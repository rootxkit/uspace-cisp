package jws

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"

	coreauth "github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-cisp/internal/auth"
	"github.com/rootxkit/uspace-cisp/internal/obs"
)

// Problem slugs of RequireSignature.
const (
	// SlugSignature: the body's detached signature is missing or does not
	// verify (M28 names the slug).
	SlugSignature = "signature"
	// SlugSignatureUnavailable: no verifier is configured for the
	// publisher (its JWKS URL is not set).
	SlugSignatureUnavailable = "signature_unavailable"
	// SlugBodyTooLarge matches internal/httpapi's slug.
	SlugBodyTooLarge = "body_too_large"
)

// SignatureGuard configures RequireSignature.
type SignatureGuard struct {
	// Verifier returns the publisher's verifier in use (a Reloading's
	// Current); nil, or one returning nil, answers 503.
	Verifier func() *DetachedVerifier
	Problems auth.ProblemWriter
	// MaxBodyBytes bounds the body read (the route's cap).
	MaxBodyBytes int64
	// Component counts acceptances and refusals by core's counter names;
	// nil counts in the verifier only.
	Component *obs.Component
}

type signatureKey struct{}

// SignatureFrom is the signature RequireSignature accepted, or false.
func SignatureFrom(ctx context.Context) (coreauth.Signature, bool) {
	s, ok := ctx.Value(signatureKey{}).(coreauth.Signature)
	return s, ok
}

// RequireSignature verifies the X-JWS-Signature of the raw body before
// the handler sees a byte of it, and hands the same bytes on. It runs
// after the publisher binding: the caller's client id must be the
// verifier's publisher (the publisher is named by the bearer token,
// never by the signature header). A refusal is 403 problem+json, slug
// "signature", naming the part at fault; it is never a warning.
func (g SignatureGuard) RequireSignature() auth.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var v *DetachedVerifier
			if g.Verifier != nil {
				v = g.Verifier()
			}
			if v == nil {
				g.Problems(w, http.StatusServiceUnavailable, SlugSignatureUnavailable, "Signature verification unavailable",
					"no signing key source is configured for this publisher")
				return
			}
			c := auth.CallerFrom(r.Context())
			if c == nil || c.ClientID != v.Publisher() {
				g.count(auth.CounterRejectedPublisherBinding)
				fe := core.Fieldf("sub", "this client is not the publisher whose signature this route verifies")
				g.Problems(w, http.StatusForbidden, auth.SlugNotAPublisher, "Not a publisher", fe.Error(), fe)
				return
			}
			body, err := io.ReadAll(io.LimitReader(r.Body, g.MaxBodyBytes+1))
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) || int64(len(body)) > g.MaxBodyBytes {
				g.Problems(w, http.StatusRequestEntityTooLarge, SlugBodyTooLarge, "Request body too large",
					"the body is larger than this route accepts")
				return
			}
			if err != nil {
				fe := core.Fieldf("body", "could not be read: %v", err)
				g.Problems(w, http.StatusBadRequest, "bad_request", "Bad request", fe.Error(), fe)
				return
			}
			sig, err := v.Verify(r.Context(), r.Header.Get(HeaderSignature), body)
			if err != nil {
				counter := coreauth.CounterRejectedMalformed
				var te *coreauth.TokenError
				if errors.As(err, &te) {
					counter = te.Counter
				}
				g.count(counter)
				claim, reason := claimOf(err)
				fe := core.Fieldf(claim, "%s", reason)
				g.Problems(w, http.StatusForbidden, SlugSignature, "Signature refused", HeaderSignature+": "+fe.Error(), fe)
				return
			}
			g.count(coreauth.CounterAccepted)
			r.Body = io.NopCloser(bytes.NewReader(body))
			r.ContentLength = int64(len(body))
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), signatureKey{}, sig)))
		})
	}
}

func (g SignatureGuard) count(name string) {
	if g.Component != nil {
		g.Component.Counter("signature_"+name, "Publisher body signatures by outcome ("+name+").").Inc()
	}
}
