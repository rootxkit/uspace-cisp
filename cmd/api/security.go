package main

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"time"

	coreauth "github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-cisp/internal/auth"
	"github.com/rootxkit/uspace-cisp/internal/config"
	"github.com/rootxkit/uspace-cisp/internal/httpapi"
	"github.com/rootxkit/uspace-cisp/internal/jws"
	"github.com/rootxkit/uspace-cisp/internal/obs"
)

// jwksRetryInterval is how often an issuer or publisher whose JWKS was
// unreachable at start is asked again: core's rate limit for JWKS
// fetches, so the retry never fetches more often than core would.
const jwksRetryInterval = coreauth.DefaultMinRefreshInterval

// security is the api's authentication: the machine token verifier, the
// guard, the publishers' signature verifiers and the signing key ring.
type security struct {
	machine *auth.MachineVerifier
	guard   *auth.Guard
	keys    *jws.KeyRing
	// console holds the session issuer and the TOTP sealer (WP-8).
	console consoleKeys
	// publishers holds the detached verifiers of the authority and, when
	// CISP_ANSP_JWKS_URL is set, the ANSP, for the publication routes
	// (WP-3, WP-5).
	publishers map[auth.Publisher]*auth.Reloading[jws.DetachedVerifier]
}

// startSecurity builds every verifier at start. A JWKS that is down is
// served from the disk copy when one exists (the component says "stale
// since"), and stops the start otherwise; a signing key that does not
// load stops the start.
func startSecurity(ctx context.Context, cfg *config.API, status *obs.Status, logger *slog.Logger) (*security, error) {
	jwksComp := status.Component("jwks")
	cache, err := auth.OpenJWKSCache(cfg.JWKSCacheFile, auth.JWKSCacheOptions{Component: jwksComp})
	if err != nil {
		return nil, err
	}
	consoleKeys, err := loadConsoleKeys(cfg)
	if err != nil {
		return nil, fmt.Errorf("console: %w", err)
	}
	mc := auth.MachineConfigFrom(cfg, cache, jwksComp)
	if consoleKeys.issuer != nil {
		// D10: one verifier; the console issuer is allow-listed beside the
		// ecosystem's with the session key's static key set.
		mc.Issuers = append(mc.Issuers, consoleKeys.issuer.Source())
	}
	machine, err := auth.NewMachineVerifier(ctx, mc)
	if err != nil {
		return nil, err
	}
	guard, err := auth.NewGuard(auth.GuardConfigFrom(cfg, machine, httpapi.WriteProblem, status.Component("auth"), logger))
	if err != nil {
		return nil, err
	}
	sec := &security{machine: machine, guard: guard, console: consoleKeys, publishers: map[auth.Publisher]*auth.Reloading[jws.DetachedVerifier]{}}

	pubs := []struct {
		p        auth.Publisher
		clientID string
		url      string
	}{
		{auth.PublisherAuthority, cfg.AuthorityClientID, cfg.TokenJWKSURL},
		{auth.PublisherANSP, cfg.ANSPClientID, cfg.ANSPJWKSURL},
	}
	for _, pb := range pubs {
		comp := status.Component("jwks_" + string(pb.p))
		if pb.url == "" {
			comp.SetDegraded("not configured (" + config.EnvANSPJWKSURL + "): its signed bodies are refused")
			continue
		}
		r, err := publisherVerifier(ctx, cfg, cache, comp, pb.clientID, pb.url)
		if err != nil {
			return nil, fmt.Errorf("%s signatures: %w", pb.p, err)
		}
		sec.publishers[pb.p] = r
	}

	signing := status.Component("signing")
	if cfg.SigningKeyFile == "" {
		signing.SetDegraded("not configured (" + config.EnvSigningKeyFile + "): the JWKS endpoint answers 503")
	} else {
		keys, err := jws.ReadKeyRing(cfg.SigningKeyFile, cfg.SigningKID, cfg.SigningKeyPrevFile, cfg.SigningKIDPrev)
		if err != nil {
			return nil, fmt.Errorf("signing key: %w", err)
		}
		sec.keys = keys
		logger.InfoContext(ctx, "signing keys loaded", "kids", keys.KIDs())
	}
	return sec, nil
}

func publisherVerifier(ctx context.Context, cfg *config.API, cache *auth.JWKSCache, comp *obs.Component, clientID, url string) (*auth.Reloading[jws.DetachedVerifier], error) {
	return auth.StartReloading(ctx, auth.ReloadConfig[jws.DetachedVerifier]{
		Name:      "publisher " + clientID,
		Sources:   []auth.Source{{ID: clientID, JWKSURL: url}},
		Cache:     cache,
		Component: comp,
		Refreshes: func(v *jws.DetachedVerifier) uint64 { return v.Counters().Get(coreauth.CounterJWKSRefresh) },
		Build: func(ctx context.Context, src map[string]coreauth.IssuerConfig) (*jws.DetachedVerifier, error) {
			return jws.NewDetachedVerifier(ctx, jws.KeySource{Publisher: clientID, Keys: src[clientID]},
				cfg.PublisherSignatureMaxSkew, jws.Options{MaxPayloadBytes: cfg.MaxPublicationBytes, HTTPClient: cache.Client()})
		},
	})
}

// retry asks every verifier running on a disk copy again, and writes the
// JWKS core accepted since the last tick to the disk copy, on every tick.
func (s *security) retry(ctx context.Context, tick <-chan time.Time) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
			_ = s.machine.Retry(ctx) // the outcome is the jwks component's state
			s.machine.Sync()
			for _, r := range s.publishers {
				_ = r.Retry(ctx)
				r.Sync()
			}
		}
	}
}

// routes is the middleware of every operation outside
// httpapi.PublicRoutes. The router is fail-closed: an operation added to
// api/openapi.yaml without an entry here stops the start. GET /v1/status
// takes an ecosystem token with cis.read (console sessions arrive with
// WP-8); the publications tag is httpapi.PublicationAuth's (WP-3: the
// publish scope, the authority binding, the media type and the
// authority's detached signature on PUT; the ANSP's client certificate
// on its heartbeat).
//
// The reads (WP-4) take cis.read; the public reads take no token and go
// through the per-client rate limiter (httpapi.PublicReadAuth), an
// explicit entry like every other. The restrictions (WP-5) are
// httpapi.RestrictionAuth's: the ANSP's publish scope, its client id and
// client certificate, and its detached signature verified with the
// ANSP's own JWKS on POST and PATCH; cis.read on the heads. The
// subscriptions (WP-6) take cis.read, and application/json on POST and
// PATCH (httpapi.SubscriptionAuth): any consumer of F3 is a subscriber.
func (s *security) routes(cfg *config.API, status *obs.Status, limiter *httpapi.RateLimiter) map[string]func(http.Handler) http.Handler {
	read := s.guard.RequireScopes(auth.ScopeRead)
	out := map[string]func(http.Handler) http.Handler{
		"GET /v1/status":                       read,
		"GET /v1/{dataset}":                    read,
		"HEAD /v1/{dataset}":                   read,
		"GET /v1/{dataset}/versions":           read,
		"GET /v1/{dataset}/versions/{version}": read,
		"GET /v1/changes":                      read,
	}
	maps.Copy(out, httpapi.PublicReadAuth(limiter))
	pub := httpapi.PublicationAuth{
		Guard: s.guard,
		AuthoritySignature: jws.SignatureGuard{
			Verifier:     s.verifier(auth.PublisherAuthority),
			Problems:     httpapi.WriteProblem,
			MaxBodyBytes: cfg.MaxPublicationBytes,
			Component:    status.Component("signature"),
		},
		Component: status.Component("publishers"),
	}
	maps.Copy(out, pub.Routes())
	restrictions := httpapi.RestrictionAuth{
		Guard: s.guard,
		ANSPSignature: jws.SignatureGuard{
			Verifier:     s.verifier(auth.PublisherANSP),
			Problems:     httpapi.WriteProblem,
			MaxBodyBytes: cfg.MaxRestrictionBytes,
			Component:    status.Component("signature"),
		},
	}
	maps.Copy(out, restrictions.Routes())
	maps.Copy(out, httpapi.SubscriptionAuth{Guard: s.guard}.Routes())
	return out
}

// verifier is the publisher's detached verifier in use, nil when its
// JWKS is not configured (the signature guard then answers 503).
func (s *security) verifier(p auth.Publisher) func() *jws.DetachedVerifier {
	return func() *jws.DetachedVerifier {
		r := s.publishers[p]
		if r == nil {
			return nil
		}
		return r.Current()
	}
}
