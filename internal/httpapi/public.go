package httpapi

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-cisp/internal/httpapi/gen"
	"github.com/rootxkit/uspace-cisp/internal/publication"
)

// The public read (docs/PLAN.md section 6.4): /public/v1/{dataset},
// the same reads as /v1/{dataset} without a token, without
// since_version, with the USSP list projected and a per-client rate
// limit.
const (
	publicGetRoute   = "GET /public/v1/{dataset}"
	publicHeadRoute  = "HEAD /public/v1/{dataset}"
	publicPathPrefix = "/public/v1/"
)

// PublicRoutes of the read are not in PublicRoutes (the operations
// served with no entry at all): their entry is PublicReadAuth, an
// explicit no-token chain with the rate limit, so the fail-closed check
// still covers them.

// usspPrivateMembers are left out of every USSP on the public read
// (section 15 Q10, the demo default until GCAA decides).
var usspPrivateMembers = []string{"base_url", "certificate_id"}

// projectUsspList is the public form of a stored USSP list snapshot
// (gzip): every USSP without usspPrivateMembers, the rest as stored, in
// canonical JSON.
func projectUsspList(gz []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	list, ok := doc["ussps"].([]any)
	if !ok {
		return nil, errors.New("the stored USSP list has no ussps array")
	}
	for _, u := range list {
		m, ok := u.(map[string]any)
		if !ok {
			return nil, errors.New("the stored USSP list holds a USSP that is not an object")
		}
		for _, k := range usspPrivateMembers {
			delete(m, k)
		}
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	return publication.Canonical(out)
}

// GetPublicDataset is the public read of a dataset (WP-4).
func (s *Server) GetPublicDataset(ctx context.Context, req gen.GetPublicDatasetRequestObject) (gen.GetPublicDatasetResponseObject, error) {
	if s.Reads == nil {
		return readsUnavailable(ctx), nil
	}
	p := req.Params
	return s.Reads.read(ctx, publication.Dataset(req.Dataset), readQuery{
		bbox: p.Bbox, at: p.At, appliesAt: p.AppliesAt,
		ifNoneMatch: p.IfNoneMatch, acceptEncoding: p.AcceptEncoding, public: true,
	})
}

// HeadPublicDataset is the headers of the public read (WP-4).
func (s *Server) HeadPublicDataset(ctx context.Context, req gen.HeadPublicDatasetRequestObject) (gen.HeadPublicDatasetResponseObject, error) {
	if s.Reads == nil {
		return readsUnavailable(ctx), nil
	}
	return s.Reads.read(ctx, publication.Dataset(req.Dataset), readQuery{ifNoneMatch: req.Params.IfNoneMatch, head: true, public: true})
}

// NotModified reports whether a public read would be answered 304: its
// If-None-Match names the current version of the dataset in its path,
// as this instance's cache holds it. The rate limiter counts such a
// request at the cheap rate. It never reads the database beyond the
// cache.
func (r *Reads) NotModified(req *http.Request) bool {
	inm := req.Header.Get("If-None-Match")
	if inm == "" || r == nil || r.Cache == nil {
		return false
	}
	rest, ok := strings.CutPrefix(req.URL.Path, publicPathPrefix)
	if !ok {
		return false
	}
	ds := publication.Dataset(rest)
	if !ds.Valid() {
		return false
	}
	v, err := r.Cache.CurrentVersion(req.Context(), ds)
	return err == nil && v > 0 && etagMatches(inm, publication.ETag(ds, v))
}

// PublicReadAuth is the route middleware of the two public operations:
// no token, the per-client rate limit, then since_version refused (it is
// not served on the public subset).
func PublicReadAuth(limiter *RateLimiter) map[string]func(http.Handler) http.Handler {
	chain := func(next http.Handler) http.Handler {
		return limiter.Middleware(refuseSinceVersion(next))
	}
	return map[string]func(http.Handler) http.Handler{publicGetRoute: chain, publicHeadRoute: chain}
}

// refuseSinceVersion answers a public read that asks for a delta with
// 400: the delta, the versions and the change feed are for subscribers
// with cis.read.
func refuseSinceVersion(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has(filterSinceVersion) {
			fe := core.Fieldf(filterSinceVersion, "is not served on the public read; deltas are served at /v1/{dataset} with cis.read")
			WriteProblem(w, http.StatusBadRequest, SlugFilterNotApplicable, "Bad request", fe.Error(), fe)
			return
		}
		next.ServeHTTP(w, r)
	})
}
