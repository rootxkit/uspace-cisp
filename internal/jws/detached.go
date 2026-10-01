package jws

import (
	"context"
	"errors"
	"net/http"
	"time"

	coreauth "github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"
)

// HeaderSignature carries the detached JWS of a publication body (Q8).
const HeaderSignature = "X-JWS-Signature"

// CounterRejectedEmpty counts a signature refused because the body was
// empty (the CISP's check, beside core's counters).
const CounterRejectedEmpty = "rejected_empty"

// KeySource is the publisher a DetachedVerifier verifies for: its client
// id (the sub of its bearer token) and its JWKS, by URL or, in tests and
// for the disk copy, as a static set.
type KeySource struct {
	Publisher string
	Keys      coreauth.IssuerConfig
}

// Options configure a DetachedVerifier. Zero values take core's defaults.
type Options struct {
	// MaxPayloadBytes bounds the body (the route's body cap).
	MaxPayloadBytes int64
	// HTTPClient fetches the JWKS (the JWKS cache's client in the api).
	HTTPClient *http.Client
	// MinRefreshInterval rate-limits JWKS fetches (tests shorten it).
	MinRefreshInterval time.Duration
	// Now is the clock; nil is time.Now.
	Now func() time.Time
}

// DetachedVerifier verifies X-JWS-Signature values of one publisher with
// core's detached verifier. It is safe for concurrent use.
type DetachedVerifier struct {
	publisher string
	v         *coreauth.DetachedVerifier
}

// NewDetachedVerifier builds the verifier for keys.Publisher and fetches
// its JWKS when it is a URL. iat may be at most maxSkew old and at most
// maxSkew ahead (CISP_PUBLISHER_SIGNATURE_MAX_SKEW_S).
func NewDetachedVerifier(ctx context.Context, keys KeySource, maxSkew time.Duration, opts Options) (*DetachedVerifier, error) {
	if keys.Publisher == "" {
		return nil, core.Fieldf("publisher", "empty")
	}
	if maxSkew <= 0 {
		return nil, core.Fieldf("max_skew", "must be positive")
	}
	v, err := coreauth.NewDetachedVerifier(ctx, coreauth.DetachedConfig{
		Publishers:         map[string]coreauth.IssuerConfig{keys.Publisher: keys.Keys},
		MaxAge:             maxSkew,
		MaxSkew:            maxSkew,
		MaxPayloadBytes:    opts.MaxPayloadBytes,
		JWKSCacheTTL:       jwksCacheTTL,
		MinRefreshInterval: opts.MinRefreshInterval,
		HTTPClient:         opts.HTTPClient,
		Now:                opts.Now,
	})
	if err != nil {
		return nil, err
	}
	return &DetachedVerifier{publisher: keys.Publisher, v: v}, nil
}

// jwksCacheTTL is the publishers' JWKS cache lifetime, the same 24 h as
// the token issuers' (docs/PLAN.md section 8.2).
const jwksCacheTTL = 24 * time.Hour

// Publisher is the client id this verifier verifies for.
func (d *DetachedVerifier) Publisher() string { return d.publisher }

// Verify checks that header is the publisher's detached signature over
// body. It refuses an empty body, then everything core refuses: a
// malformed header, alg other than RS256 (none and HS256 included), b64
// absent or true, crit missing b64 or naming anything else, an unknown or
// missing kid, a bad signature, iat missing or outside the skew. Every
// refusal is a *coreauth.TokenError naming the part at fault, counted.
func (d *DetachedVerifier) Verify(ctx context.Context, header string, body []byte) (coreauth.Signature, error) {
	if len(body) == 0 {
		d.v.Counters().Inc(CounterRejectedEmpty)
		return coreauth.Signature{}, &coreauth.TokenError{Counter: CounterRejectedEmpty, Claim: "body", Reason: "empty: there is nothing to verify"}
	}
	return d.v.Verify(ctx, d.publisher, header, body)
}

// Counters are core's counters of this verifier plus rejected_empty.
func (d *DetachedVerifier) Counters() *core.Counters { return d.v.Counters() }

// claimOf is the part a refusal names, "signature" when it is not a
// *coreauth.TokenError.
func claimOf(err error) (string, string) {
	var te *coreauth.TokenError
	if errors.As(err, &te) {
		return te.Claim, te.Reason
	}
	return "signature", err.Error()
}
