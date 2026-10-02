package httpapi

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/jackc/pgx/v5/pgconn"
	coreauth "github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/vectors"

	"github.com/rootxkit/uspace-cisp/internal/auth"
	"github.com/rootxkit/uspace-cisp/internal/authtest"
	"github.com/rootxkit/uspace-cisp/internal/config"
	"github.com/rootxkit/uspace-cisp/internal/httpapi/gen"
	"github.com/rootxkit/uspace-cisp/internal/jws"
	"github.com/rootxkit/uspace-cisp/internal/obs"
	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/store"
)

// The client ids and keys of the publication tests.
const (
	authorityID   = "authority-01"
	anspID        = "ansp-01"
	usspID        = "ussp-GEO1-01"
	anspSubject   = "CN=ansp-01,O=Sakaeronavigatsia"
	tokenIssuer   = "https://authority.example.test/"
	tokenAudience = "uspace-cisp.example.test"
	publisherKID  = "authority-sig-1"
)

// kin-openapi decodes application/json; a publication may also be
// application/geo+json (RFC 7946), the same JSON.
func init() {
	openapi3filter.RegisterBodyDecoder("application/geo+json", openapi3filter.JSONBodyDecoder)
}

// fakeStore is PublicationStore in memory, with PublishTx's contract:
// the version check under the lock, the diff, unchanged, the D8 index
// (the same *pgconn.PgError the database raises), and the snapshot
// signed with the signer.
type fakeStore struct {
	mu       sync.Mutex
	version  map[publication.Dataset]int64
	current  map[publication.Dataset][]publication.FeatureRow
	bodies   map[publication.Dataset]map[int64][]byte
	versions []store.Version
	attempts []store.Attempt
	beats    map[string]store.Heartbeat
	signed   int
	down     bool
	failWith error // returned by PublishTx when set
	// beforePublish runs inside PublishTx with the lock held, before the
	// version check (a publication that won the race).
	beforePublish func(*fakeStore)
	// rowsGiven says whether the last PublishTx was handed its rows.
	rowsGiven bool
	attemptFn func(store.Attempt) error
	// What the reads need (WP-4): the signed snapshot, the rows and the
	// head of every version, the change feed and the publishers.
	snaps      map[publication.Dataset]map[int64]store.Snapshot
	rowsAt     map[publication.Dataset]map[int64][]publication.FeatureRow
	heads      map[publication.Dataset]map[int64]store.StoredPublication
	updated    map[publication.Dataset]time.Time
	changes    []publication.Change
	publishers []store.Publisher
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		version: map[publication.Dataset]int64{},
		current: map[publication.Dataset][]publication.FeatureRow{},
		bodies:  map[publication.Dataset]map[int64][]byte{},
		beats:   map[string]store.Heartbeat{},
		snaps:   map[publication.Dataset]map[int64]store.Snapshot{},
		rowsAt:  map[publication.Dataset]map[int64][]publication.FeatureRow{},
		heads:   map[publication.Dataset]map[int64]store.StoredPublication{},
		updated: map[publication.Dataset]time.Time{},
	}
}

// errFakeDown is what an unreachable database returns: a network error.
var errFakeDown = fmt.Errorf("begin: %w", &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED})

func (f *fakeStore) CurrentVersion(_ context.Context, ds publication.Dataset) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return 0, errFakeDown
	}
	return f.version[ds], nil
}

func (f *fakeStore) Reserved(_ context.Context, ds publication.Dataset, ids []string) (map[string]publication.Dataset, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]publication.Dataset{}
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	for other, rows := range f.current {
		if other == ds || other == publication.DatasetUSSPList {
			continue
		}
		for i := range rows {
			if want[rows[i].ID] {
				out[rows[i].ID] = other
			}
		}
	}
	return out, nil
}

func (f *fakeStore) PublishTx(ctx context.Context, in store.PublishInput, signer store.Signer) (store.PublishResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return store.PublishResult{}, errFakeDown
	}
	if f.failWith != nil {
		return store.PublishResult{}, f.failWith
	}
	if f.beforePublish != nil {
		f.beforePublish(f)
	}
	current := f.version[in.Dataset]
	if in.ExpectedVersion != nil && *in.ExpectedVersion != current {
		return store.PublishResult{Version: current, ETag: publication.ETag(in.Dataset, current)}, store.ErrVersionMismatch
	}
	f.rowsGiven = in.Rows != nil
	var next []publication.FeatureRow
	if in.Rows != nil {
		next = in.Rows
	} else if in.Collection != nil {
		rows, err := publication.Rows(in.Collection)
		if err != nil {
			return store.PublishResult{}, err
		}
		next = rows
	}
	diff := publication.DiffRows(f.current[in.Dataset], next)
	if current >= 1 {
		unchanged := diff.Empty()
		if in.Collection == nil {
			a, _ := publication.UsspListCanonical(f.bodies[in.Dataset][current])
			b, _ := publication.UsspListCanonical(in.Body)
			unchanged = bytes.Equal(a, b)
		}
		if unchanged {
			return store.PublishResult{Version: current, ETag: publication.ETag(in.Dataset, current), Diff: diff}, store.ErrUnchanged
		}
	}
	for other, rows := range f.current {
		if other == in.Dataset || other == publication.DatasetUSSPList || in.Dataset == publication.DatasetUSSPList {
			continue
		}
		for i := range rows {
			for k := range next {
				if rows[i].ID == next[k].ID {
					return store.PublishResult{}, fmt.Errorf("fill features_current: %w", &pgconn.PgError{Code: "23505", ConstraintName: "features_current_cross_dataset_uq"})
				}
			}
		}
	}
	version := current + 1
	snap, err := fakeSnapshot(ctx, in, version, signer)
	if err != nil {
		return store.PublishResult{}, err
	}
	f.signed++
	f.version[in.Dataset] = version
	f.current[in.Dataset] = next
	if f.bodies[in.Dataset] == nil {
		f.bodies[in.Dataset] = map[int64][]byte{}
	}
	f.bodies[in.Dataset][version] = append([]byte{}, in.Body...)
	sum := sha256.Sum256(in.Body)
	f.versions = append(f.versions, store.Version{
		ID: fmt.Sprintf("PUB%d", len(f.versions)), Dataset: in.Dataset, Version: version, PublisherClientID: in.PublisherClientID,
		ReceivedAt: in.ReceivedAt, BodySHA256: sum[:], Bytes: int64(len(in.Body)), ContentType: in.ContentType,
		SignatureKID: in.SignatureKID, FeatureCount: len(next), Added: len(diff.Added), Changed: len(diff.Changed),
		Removed: len(diff.Removed), Warnings: in.Warnings, Reason: in.Reason,
	})
	f.record(in, version, next, diff, snap, sum[:])
	return store.PublishResult{PublicationID: fmt.Sprintf("PUB%d", len(f.versions)-1), Version: version, ETag: publication.ETag(in.Dataset, version), Diff: diff}, nil
}

func (f *fakeStore) InsertAttempt(_ context.Context, a store.Attempt) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.attemptFn != nil {
		if err := f.attemptFn(a); err != nil {
			return "", err
		}
	}
	a.ID = fmt.Sprintf("ATT%03d", len(f.attempts))
	f.attempts = append(f.attempts, a)
	return a.ID, nil
}

func (f *fakeStore) Versions(_ context.Context, ds publication.Dataset, before int64, limit int) ([]store.Version, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return nil, errFakeDown
	}
	var out []store.Version
	for i := range f.versions {
		if v := &f.versions[i]; v.Dataset == ds && (before == 0 || v.Version < before) {
			out = append(out, *v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version > out[j].Version })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (f *fakeStore) RefusedAttempts(_ context.Context, ds publication.Dataset, publisher string, since time.Time, limit int) ([]store.Attempt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return nil, errFakeDown
	}
	var out []store.Attempt
	for i := len(f.attempts) - 1; i >= 0; i-- {
		a := f.attempts[i]
		if a.Dataset == ds && a.PublisherClientID == publisher && a.Outcome == store.OutcomeRefused && a.ReceivedAt.After(since) && len(out) < limit {
			out = append(out, a)
		}
	}
	return out, nil
}

func (f *fakeStore) RecordHeartbeat(_ context.Context, h store.Heartbeat) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return errFakeDown
	}
	f.beats[h.ClientID] = h
	return nil
}

func (f *fakeStore) refused() []store.Attempt {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []store.Attempt
	for i := range f.attempts {
		if f.attempts[i].Outcome == store.OutcomeRefused {
			out = append(out, f.attempts[i])
		}
	}
	return out
}

// pubHarness is the api's router with the real guard, the authority's
// signature verifier and the publication handlers on a store.
type pubHarness struct {
	t      testing.TB
	h      http.Handler
	store  PublicationStore
	fake   *fakeStore
	iss    *coreauth.Issuer
	signer *rsa.PrivateKey
	status *obs.Status
	logs   *bytes.Buffer
	now    time.Time
	pubs   *Publications
	// The reads (WP-4) when the store serves them: the snapshot cache,
	// the handlers, the key ring that signs, the public rate limiter.
	reads   *Reads
	cache   *store.SnapshotCache
	ring    *jws.KeyRing
	limiter *RateLimiter
}

type harnessOption func(*Publications, *Server)

// newPubHarness builds the harness on st (nil: a fresh fake store).
func newPubHarness(t testing.TB, st PublicationStore, opts ...harnessOption) *pubHarness {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	iss, err := coreauth.NewIssuer(tokenIssuer, authtest.Key(t, "issuer", 2048), "tok-1")
	if err != nil {
		t.Fatal(err)
	}
	mv, err := auth.NewMachineVerifier(ctx, auth.MachineConfig{
		Issuers:   []auth.Source{{ID: tokenIssuer, Keys: iss.JWKS()}},
		Audiences: []string{tokenAudience},
	})
	if err != nil {
		t.Fatal(err)
	}
	status := obs.NewStatus("api", nil, now)
	g, err := auth.NewGuard(auth.GuardConfig{
		Verifier: mv, Problems: WriteProblem, AuthorityClientID: authorityID, ANSPClientID: anspID,
		MTLSMode: config.MTLSRequired, ANSPMTLSSubject: anspSubject, Component: status.Component("auth"),
	})
	if err != nil {
		t.Fatal(err)
	}
	key := authtest.Key(t, "authority-signing", 3072)
	set := authtest.PublicSet(t, map[string]*rsa.PrivateKey{publisherKID: key})
	const maxBytes = 32 << 20
	dv, err := jws.NewDetachedVerifier(ctx, jws.KeySource{Publisher: authorityID, Keys: coreauth.IssuerConfig{Keys: set}},
		5*time.Minute, jws.Options{MaxPayloadBytes: maxBytes})
	if err != nil {
		t.Fatal(err)
	}
	pa := PublicationAuth{
		Guard: g,
		AuthoritySignature: jws.SignatureGuard{
			Verifier: func() *jws.DetachedVerifier { return dv }, Problems: WriteProblem,
			MaxBodyBytes: maxBytes, Component: status.Component("signature"),
		},
		Component: status.Component("publishers"),
	}
	routes := pa.Routes()
	routes["GET /v1/status"] = g.RequireScopes(auth.ScopeRead)
	h := &pubHarness{t: t, iss: iss, signer: key, status: status, now: now}
	if st == nil {
		h.fake = newFakeStore()
		st = h.fake
	}
	h.store = st
	h.logs = &bytes.Buffer{}
	logger := obs.NewLogger(h.logs, "api", slog.LevelInfo)
	h.ring = keyRing(t)
	h.pubs = &Publications{
		Logger: logger,
		Store:  st, Signer: KeyRingSigner{Keys: h.ring}, MaxPublicationBytes: maxBytes,
		AuthorityClientID: authorityID, ANSPClientID: anspID, Status: status,
	}
	server := &Server{Publications: h.pubs, Status: &StatusReport{
		Configured: []ConfiguredPublisher{{ClientID: authorityID, Kind: "authority"}, {ClientID: anspID, Kind: "ansp"}},
		Registry:   status, MTLSMode: config.MTLSRequired,
	}}
	h.withReads(st, server, status, logger)
	read := g.RequireScopes(auth.ScopeRead)
	for _, op := range []string{"GET /v1/{dataset}", "HEAD /v1/{dataset}", "GET /v1/{dataset}/versions", "GET /v1/{dataset}/versions/{version}", "GET /v1/changes"} {
		routes[op] = read
	}
	maps.Copy(routes, PublicReadAuth(h.limiter))
	for _, o := range opts {
		o(h.pubs, server)
	}
	router, err := NewRouter(server, Options{
		Logger: logger, Status: status, RouteMiddleware: routes,
		RouteBodyCaps: map[string]int64{PublicationRoute: maxBytes}, HandlerTimeout: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.h = router
	return h
}

func (h *pubHarness) token(sub string, scopes ...string) string {
	h.t.Helper()
	tok, err := h.iss.Issue(sub, tokenAudience, scopes, time.Minute, time.Now())
	if err != nil {
		h.t.Fatal(err)
	}
	return tok
}

// authorityToken has the three F1 publish scopes and cis.read.
func (h *pubHarness) authorityToken() string {
	return h.token(authorityID, auth.ScopePublishZones, auth.ScopePublishUSpace, auth.ScopePublishUSSPList, auth.ScopeRead)
}

func (h *pubHarness) sign(body []byte) string {
	h.t.Helper()
	s, err := coreauth.SignDetached(coreauth.SigningKey{KID: publisherKID, Key: h.signer}, body, time.Now())
	if err != nil {
		h.t.Fatal(err)
	}
	return s
}

// putReq is a signed PUT by the authority with If-Match etag.
func (h *pubHarness) putReq(ds string, body []byte, etag string) *http.Request {
	h.t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/v1/publications/"+ds, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+h.authorityToken())
	req.Header.Set("Content-Type", "application/geo+json")
	req.Header.Set(jws.HeaderSignature, h.sign(body))
	if etag != "" {
		req.Header.Set("If-Match", etag)
	}
	return req
}

func (h *pubHarness) do(req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)
	return rec
}

// put sends a signed PUT with the current ETag and returns the answer,
// conformance checked.
func (h *pubHarness) put(ds string, body []byte) *httptest.ResponseRecorder {
	h.t.Helper()
	cur, err := h.store.CurrentVersion(context.Background(), publication.Dataset(ds))
	if err != nil {
		h.t.Fatal(err)
	}
	req := h.putReq(ds, body, publication.ETag(publication.Dataset(ds), cur))
	rec := h.do(req)
	conformPut(h.t, req, body, rec)
	return rec
}

func (h *pubHarness) get(path, token string) *httptest.ResponseRecorder {
	h.t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, http.NoBody)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := h.do(req)
	conform(h.t, req, rec)
	return rec
}

func (h *pubHarness) counter(component, name string) uint64 {
	return h.status.Component(component).Counter(name, "").Value()
}

// conformPut checks a PUT against the spec with a fresh copy of the body
// (the handler consumed the request's).
func conformPut(t testing.TB, req *http.Request, body []byte, rec *httptest.ResponseRecorder) {
	t.Helper()
	clone := req.Clone(context.Background())
	clone.Body = io.NopCloser(bytes.NewReader(body))
	conform(t, clone, rec)
}

// conformResponse checks only the response: for a request the spec
// itself refuses (past a maxItems), whose refusal must still be
// described.
func conformResponse(t testing.TB, req *http.Request, rec *httptest.ResponseRecorder) {
	t.Helper()
	route, params, err := spec(t).FindRoute(req)
	if err != nil {
		t.Fatalf("not in api/openapi.yaml: %v", err)
	}
	opts := &openapi3filter.Options{AuthenticationFunc: openapi3filter.NoopAuthenticationFunc, IncludeResponseStatus: true}
	in := &openapi3filter.RequestValidationInput{Request: req, PathParams: params, Route: route, Options: opts}
	out := &openapi3filter.ResponseValidationInput{
		RequestValidationInput: in, Status: rec.Code, Header: rec.Header(),
		Body: io.NopCloser(bytes.NewReader(rec.Body.Bytes())), Options: opts,
	}
	if err := openapi3filter.ValidateResponse(context.Background(), out); err != nil {
		t.Errorf("response %d does not conform: %v\n%s", rec.Code, err, rec.Body.String())
	}
}

// --- documents -----------------------------------------------------------

type doc = map[string]any

func vectorDoc(t testing.TB, name string) doc {
	t.Helper()
	f := vectors.Load(t, "ed318_roundtrip.json")
	for _, c := range f.Cases {
		if c.Name != name {
			continue
		}
		var in struct {
			Document doc `json:"document"`
		}
		if err := json.Unmarshal(c.Input, &in); err != nil {
			t.Fatal(err)
		}
		return in.Document
	}
	t.Fatalf("no case %s", name)
	return nil
}

func feats(d doc) []any       { return d["features"].([]any) }
func fprops(d doc, i int) doc { return feats(d)[i].(doc)["properties"].(doc) }

func jsonBytes(t testing.TB, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// zonesBody is the vector collection as a zones publication: the
// USPACE feature left out and DAR taken from TSD001's reasons.
func zonesDoc(t testing.TB) doc {
	t.Helper()
	d := vectorDoc(t, "accept-authority-collection")
	d["features"] = feats(d)[1:]
	fprops(d, 0)["reason"] = []any{"EMERGENCY"}
	return d
}

// withRequirements gives every USPACE feature of d the requirements
// block, made of the members the vector carries flat beside it.
func withRequirements(d doc) doc {
	for i := range feats(d) {
		p := fprops(d, i)
		if p["type"] != "USPACE" {
			continue
		}
		ext, _ := p["extendedProperties"].(doc)
		if ext == nil {
			ext = doc{}
			p["extendedProperties"] = ext
		}
		block := doc{}
		for _, k := range []string{"uas_requirements", "service_performance", "operational_conditions", "airspace_constraints", "services_required", "adjacent"} {
			if v, ok := ext[k]; ok {
				block[k] = v
			}
		}
		if len(block) < 6 {
			block = doc{
				"uas_requirements": doc{}, "operational_conditions": doc{}, "airspace_constraints": doc{},
				"service_performance": doc{"nid_update_hz": 1, "ti_update_hz": 1, "cis_latency_s": 5},
				"services_required":   []any{"NID", "GEO", "FA", "TI"}, "adjacent": []any{},
			}
		}
		ext["uspace_requirements"] = block
	}
	return d
}

func uspaceDoc(t testing.TB) doc {
	t.Helper()
	d := vectorDoc(t, "accept-authority-collection")
	d["features"] = feats(d)[:1]
	return withRequirements(d)
}

func usspListBody(t testing.TB) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "schemas", "cis", "ussp_list", "examples", "lab.json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func problemFields(p gen.Problem) []string {
	var out []string
	if p.Errors != nil {
		for _, e := range *p.Errors {
			out = append(out, e.Field+": "+e.Reason)
		}
	}
	return out
}

// hasProblem reports whether a problem names field with phrase.
func hasProblem(p gen.Problem, field, phrase string) bool {
	if p.Errors == nil {
		return false
	}
	for _, e := range *p.Errors {
		if e.Field == field && strings.Contains(e.Reason, phrase) {
			return true
		}
	}
	return false
}

// syntheticZones is an ED-318 collection of n PROHIBITED zones, each a
// polygon of vertices positions on a grid around Tbilisi, padded with
// message texts to at least minBytes in all.
func syntheticZones(t testing.TB, n, vertices, minBytes int) []byte {
	t.Helper()
	const latDeg, lonDeg, stepDeg, radiusDeg = 41.60, 44.65, 0.004, 0.0015
	cols := int(math.Ceil(math.Sqrt(float64(n))))
	pad := strings.Repeat("Synthetic load zone for the 5000-zone publication budget. ", 4)[:200]
	feature := func(i, texts int) map[string]any {
		cLat, cLon := latDeg+float64(i/cols)*stepDeg, lonDeg+float64(i%cols)*stepDeg
		ring := make([]any, 0, vertices+1)
		for k := range vertices {
			a := 2 * math.Pi * float64(k) / float64(vertices)
			ring = append(ring, []any{math.Round((cLon+radiusDeg*math.Cos(a))*1e7) / 1e7, math.Round((cLat+radiusDeg*math.Sin(a))*1e7) / 1e7})
		}
		ring = append(ring, ring[0])
		msgs := make([]any, texts)
		for k := range msgs {
			msgs[k] = map[string]any{"lang": "en-GB", "text": pad}
		}
		id := fmt.Sprintf("Z%04d", i)
		return map[string]any{
			"type": "Feature", "id": id,
			"geometry": map[string]any{
				"type": "Polygon", "coordinates": []any{ring},
				"layer": map[string]any{"lower": 0, "lowerReference": "AGL", "upper": 120, "upperReference": "AGL", "uom": "m"},
			},
			"properties": map[string]any{
				"identifier": id, "country": "GEO", "type": "PROHIBITED", "variant": "COMMON", "reason": []any{"SENSITIVE"},
				"name":          []any{map[string]any{"lang": "en-GB", "text": "Synthetic zone " + id}},
				"message":       msgs,
				"zoneAuthority": []any{map[string]any{"name": []any{map[string]any{"lang": "en-GB", "text": "Test authority"}}, "purpose": "AUTHORIZATION"}},
			},
		}
	}
	one, _ := json.Marshal(feature(0, 0))
	perText := len(`{"lang":"en-GB","text":""},`) + len(pad)
	texts := max(0, (minBytes/n-len(one))/perText+1)
	fs := make([]any, n)
	for i := range fs {
		fs[i] = feature(i, texts)
	}
	body, err := json.Marshal(map[string]any{"type": "FeatureCollection", "features": fs})
	if err != nil {
		t.Fatal(err)
	}
	if len(body) < minBytes {
		t.Fatalf("synthetic body is %d bytes, under %d", len(body), minBytes)
	}
	return body
}
