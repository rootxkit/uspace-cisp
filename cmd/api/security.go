package main

import (
	"context"
	"fmt"
	"log/slog"
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
	machine, err := auth.NewMachineVerifier(ctx, auth.MachineConfigFrom(cfg, cache, jwksComp))
	if err != nil {
		return nil, err
	}
	guard, err := auth.NewGuard(auth.GuardConfigFrom(cfg, machine, httpapi.WriteProblem, status.Component("auth"), logger))
	if err != nil {
		return nil, err
	}
	sec := &security{machine: machine, guard: guard, publishers: map[auth.Publisher]*auth.Reloading[jws.DetachedVerifier]{}}

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
		Build: func(ctx context.Context, src map[string]coreauth.IssuerConfig) (*jws.DetachedVerifier, error) {
			return jws.NewDetachedVerifier(ctx, jws.KeySource{Publisher: clientID, Keys: src[clientID]},
				cfg.PublisherSignatureMaxSkew, jws.Options{MaxPayloadBytes: cfg.MaxPublicationBytes, HTTPClient: cache.Client()})
		},
	})
}

// retry asks every verifier running on a disk copy again, on every tick.
func (s *security) retry(ctx context.Context, tick <-chan time.Time) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
			_ = s.machine.Retry(ctx) // the outcome is the jwks component's state
			for _, r := range s.publishers {
				_ = r.Retry(ctx)
			}
		}
	}
}

// routes is the middleware of every operation outside
// httpapi.PublicRoutes. The router is fail-closed: an operation added to
// api/openapi.yaml without an entry here stops the start. GET /v1/status
// takes an ecosystem token with cis.read (console sessions arrive with
// WP-8).
func (s *security) routes() map[string]func(http.Handler) http.Handler {
	return map[string]func(http.Handler) http.Handler{
		"GET /v1/status": s.guard.RequireScopes(auth.ScopeRead),
	}
}
