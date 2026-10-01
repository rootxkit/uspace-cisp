package httpapi

import (
	"context"
	"net/http"
	"strings"

	"github.com/rootxkit/uspace-cisp/internal/httpapi/gen"
	"github.com/rootxkit/uspace-cisp/internal/jws"
)

// JWKSCacheControl is the Cache-Control of GET /.well-known/jwks.json:
// verifiers cache an hour, inside the rotation overlap of two keys.
const JWKSCacheControl = "public, max-age=3600"

// SlugKeysUnavailable answers the JWKS request when no signing key is
// configured.
const SlugKeysUnavailable = "keys_unavailable"

// GetJWKS serves the signing key ring's JWKS bytes with its ETag, 304 when
// If-None-Match names that ETag, 503 when no signing key is configured.
func (s *Server) GetJWKS(_ context.Context, req gen.GetJWKSRequestObject) (gen.GetJWKSResponseObject, error) {
	if s.Keys == nil {
		return gen.GetJWKS503ApplicationProblemPlusJSONResponse{ProblemApplicationProblemPlusJSONResponse: gen.ProblemApplicationProblemPlusJSONResponse(
			NewProblem(http.StatusServiceUnavailable, SlugKeysUnavailable, "Signing keys unavailable",
				"no signing key is configured (CISP_SIGNING_KEY_FILE)", ""))}, nil
	}
	etag, cc := s.Keys.ETag(), JWKSCacheControl
	if req.Params.IfNoneMatch != nil && etagMatches(*req.Params.IfNoneMatch, etag) {
		return gen.GetJWKS304Response{Headers: gen.GetJWKS304ResponseHeaders{CacheControl: &cc, ETag: &etag}}, nil
	}
	return jwksResponse{keys: s.Keys}, nil
}

// jwksResponse writes the ring's cached bytes as they are, so the body is
// exactly the bytes its ETag was computed from.
type jwksResponse struct{ keys *jws.KeyRing }

// VisitGetJWKSResponse implements gen.GetJWKSResponseObject.
func (r jwksResponse) VisitGetJWKSResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", JWKSCacheControl)
	w.Header().Set("ETag", r.keys.ETag())
	w.WriteHeader(http.StatusOK)
	_, err := w.Write(r.keys.JWKS())
	return err
}

// etagMatches applies If-None-Match (RFC 9110 section 13.1.2): "*" or a
// list of entity tags compared weakly.
func etagMatches(header, etag string) bool {
	for _, t := range strings.Split(header, ",") {
		t = strings.TrimSpace(t)
		if t == "*" || strings.TrimPrefix(t, "W/") == strings.TrimPrefix(etag, "W/") {
			return true
		}
	}
	return false
}
