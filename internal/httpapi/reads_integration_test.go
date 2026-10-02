//go:build integration

// Integration tests of the reads (WP-4) on PostgreSQL + PostGIS: the
// filters on the real prefilter, the delta from the features rows, the
// verbatim versions and their integrity check, the change feed and the
// status from the tables, the geodesy vectors on &&, the degraded
// serving with the database taken away for real, and the bbox budget.
package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/store"
)

// freshZones publishes readZones on PostgreSQL after emptying zones, and
// returns the version.
func freshZones(t *testing.T, h *pubHarness) int64 {
	t.Helper()
	if rec := h.put("zones", []byte(emptyCollection)); rec.Code != 201 && rec.Code != 200 {
		t.Fatalf("empty = %d %s", rec.Code, rec.Body.String())
	}
	rec := h.put("zones", jsonBytes(t, readZones(t)))
	if rec.Code != 201 {
		t.Fatalf("PUT = %d %s", rec.Code, rec.Body.String())
	}
	return decodeResultTB(t, rec).Version
}

// Every read on PostgreSQL: the snapshot (signed, equal to the stored
// snapshot), HEAD, bbox in and out on the GiST prefilter, at and
// applies_at, since_version from the features rows, the verbatim
// version, the change feed and the status.
func TestReadsOnPostgres(t *testing.T) {
	ctx := context.Background()
	st, _ := pgStore(t)
	h := newPubHarness(t, st)
	v := freshZones(t, h)
	etag := publication.ETag(publication.DatasetZones, v)

	rec := h.read(http.MethodGet, "/v1/zones")
	snap, err := st.Snapshot(ctx, publication.DatasetZones, v)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Code != 200 || !bytes.Equal(rec.Body.Bytes(), inflate(t, snap.BodyGz)) || rec.Header().Get("ETag") != etag {
		t.Fatalf("GET = %d %s", rec.Code, rec.Header().Get("ETag"))
	}
	verifyCISP(t, rec.Header().Get(HeaderSignature), rec.Body.Bytes())
	if lm := rec.Header().Get("Last-Modified"); lm != snap.ReceivedAt.UTC().Format(http.TimeFormat) {
		t.Errorf("Last-Modified %q, received_at %v", lm, snap.ReceivedAt)
	}
	if head := h.read(http.MethodHead, "/v1/zones", "If-None-Match", etag); head.Code != 304 {
		t.Errorf("HEAD If-None-Match = %d", head.Code)
	}

	_, in := collection(t, h.read(http.MethodGet, "/v1/zones?bbox=44.79,41.69,44.83,41.725"))
	_, out := collection(t, h.read(http.MethodGet, "/v1/zones?bbox=0,0,1,1"))
	if strings.Join(ids(in), ",") != "TSR001" || len(out) != 0 {
		t.Errorf("bbox on PostGIS: in %v out %v", ids(in), ids(out))
	}
	_, at := collection(t, h.read(http.MethodGet, "/v1/zones?at="+url.QueryEscape(winterMonday)))
	if strings.Join(ids(at), ",") != "TSP001,TSR001" || annotation(at["TSP001"]) != "unknown" {
		t.Errorf("at on PostgreSQL %v", ids(at))
	}
	_, ann := collection(t, h.read(http.MethodGet, "/v1/zones?applies_at="+url.QueryEscape(winterMonday)))
	if annotation(ann["TSR001"]) != "applies" || annotation(ann["TSC001"]) != "not_applicable" || annotation(ann["TSP001"]) != "unknown" {
		t.Errorf("applies_at on PostgreSQL %v", ann)
	}

	// A second version: TSC001 changed, TSP001 removed.
	d := readZones(t)
	fprops(d, 1)["name"] = []any{doc{"lang": "en-GB", "text": "Renamed " + time.Now().Format(time.RFC3339Nano)}}
	d["features"] = feats(d)[:2]
	if rec := h.put("zones", jsonBytes(t, d)); rec.Code != 201 {
		t.Fatalf("v+1 = %d %s", rec.Code, rec.Body.String())
	}
	var delta struct {
		From    int64 `json:"from_version"`
		To      int64 `json:"to_version"`
		Added   doc   `json:"added"`
		Changed doc   `json:"changed"`
		Removed []string
	}
	drec := h.read(http.MethodGet, "/v1/zones?since_version="+vtoa(v))
	if err := json.Unmarshal(drec.Body.Bytes(), &delta); err != nil || drec.Code != 200 {
		t.Fatalf("delta = %d %s", drec.Code, drec.Body.String())
	}
	if delta.To != v+1 || len(feats(delta.Added)) != 0 || len(feats(delta.Changed)) != 1 || strings.Join(delta.Removed, ",") != "TSP001" {
		t.Errorf("delta %+v", delta)
	}
	if ch := feats(delta.Changed)[0].(doc)["properties"].(doc); ch["identifier"] != "TSC001" {
		t.Errorf("changed %v", ch["identifier"])
	}
	empty := h.read(http.MethodGet, "/v1/zones?since_version="+vtoa(v+1))
	if !strings.Contains(empty.Body.String(), `"removed":[]`) {
		t.Errorf("delta from current: %s", empty.Body.String())
	}

	body := h.read(http.MethodGet, "/v1/zones/versions/"+vtoa(v))
	pub, err := st.Publication(ctx, publication.DatasetZones, v)
	if err != nil || body.Code != 200 || !bytes.Equal(body.Body.Bytes(), pub.Body) || body.Header().Get(HeaderPublisherSig) != *pub.PublisherSignature {
		t.Errorf("version body = %d %v", body.Code, err)
	}
	verifyCISP(t, body.Header().Get(HeaderSignature), pub.Body)

	changes := h.read(http.MethodGet, "/v1/changes?dataset=zones&since=0&limit=500")
	if !strings.Contains(changes.Body.String(), `"etag":"\"zones:`+vtoa(v+1)+`\""`) {
		t.Errorf("the change feed lacks the version: %s", changes.Body.String()[:min(changes.Body.Len(), 400)])
	}
	status := h.read(http.MethodGet, "/v1/status")
	if !strings.Contains(status.Body.String(), `"etag":"\"zones:`+vtoa(v+1)+`\""`) {
		t.Errorf("status: %s", status.Body.String())
	}
	t.Logf("status on PostgreSQL: %s", strings.TrimSpace(status.Body.String()))
}

// The in_polygon and in_circle cases on PostGIS's && over the stored
// shapes (a circle is its ST_Buffer on geography).
func TestVectorsGeodesyStore(t *testing.T) {
	st, _ := pgStore(t)
	h := newPubHarness(t, st)
	if rec := h.put("zones", []byte(emptyCollection)); rec.Code != 201 && rec.Code != 200 {
		t.Fatal(rec.Code)
	}
	if n := runGeodesyVectors(t, h); n != 7 {
		t.Errorf("%d containment cases ran, want 7", n)
	}
}

// T7 on PostgreSQL: a publications.body altered behind the api's back
// (as the table's owner lifts its own insert-only revoke for the test)
// is 500 integrity and an error line; the snapshot read is unaffected;
// the body is put back and the revoke restored.
func TestReadVersionIntegrityOnPostgres(t *testing.T) {
	ctx := context.Background()
	st, pool := pgStore(t)
	h := newPubHarness(t, st)
	v := freshZones(t, h)
	// setBody rewrites the version's body with the owner's UPDATE
	// granted for one transaction and revoked again before it commits.
	setBody := func(body []byte) {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		for _, q := range []string{
			"GRANT UPDATE ON publications TO CURRENT_USER",
			"UPDATE publications SET body = $3 WHERE dataset = $1 AND version = $2",
			"REVOKE UPDATE ON publications FROM CURRENT_USER",
		} {
			var err error
			if strings.HasPrefix(q, "UPDATE") {
				_, err = tx.Exec(ctx, q, string(publication.DatasetZones), v, body)
			} else {
				_, err = tx.Exec(ctx, q)
			}
			if err != nil {
				t.Fatalf("%s: %v", q, err)
			}
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	pub, err := st.Publication(ctx, publication.DatasetZones, v)
	if err != nil {
		t.Fatal(err)
	}
	corrupt := append([]byte{}, pub.Body...)
	corrupt[20] ^= 0x01
	setBody(corrupt)
	t.Cleanup(func() { setBody(pub.Body) })
	rec := h.read(http.MethodGet, "/v1/zones/versions/"+vtoa(v))
	if p := decodeProblem(t, rec); rec.Code != 500 || p.Type != ProblemTypeBase+SlugIntegrity {
		t.Fatalf("tampered = %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(h.logs.String(), "publication body integrity check failed") {
		t.Error("no error line")
	}
	t.Logf("tampered version: %d %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	if snap := h.read(http.MethodGet, "/v1/zones"); snap.Code != 200 {
		t.Errorf("snapshot = %d", snap.Code)
	}
}

// proxy is a TCP proxy in front of PostgreSQL that the test stops and
// starts, so the database goes away for real (E-02).
type proxy struct {
	t      *testing.T
	target string
	addr   string
	mu     sync.Mutex
	ln     net.Listener
	conns  map[net.Conn]bool
}

func newProxy(t *testing.T, target string) *proxy {
	p := &proxy{t: t, target: target, conns: map[net.Conn]bool{}}
	p.start("127.0.0.1:0")
	t.Cleanup(p.stop)
	return p
}

func (p *proxy) start(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		p.t.Fatal(err)
	}
	p.mu.Lock()
	p.ln, p.addr = ln, ln.Addr().String()
	p.mu.Unlock()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			up, err := net.Dial("tcp", p.target)
			if err != nil {
				_ = c.Close()
				continue
			}
			p.mu.Lock()
			p.conns[c], p.conns[up] = true, true
			p.mu.Unlock()
			go func() { _, _ = io.Copy(up, c); _ = up.Close() }()
			go func() { _, _ = io.Copy(c, up); _ = c.Close() }()
		}
	}()
}

func (p *proxy) stop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ln != nil {
		_ = p.ln.Close()
		p.ln = nil
	}
	for c := range p.conns {
		_ = c.Close()
	}
	p.conns = map[net.Conn]bool{}
}

// E-02 for real: PostgreSQL behind a proxy that the test stops. The
// cache cannot refresh; an unfiltered read serves the held snapshot with
// X-CIS-Stale, X-CIS-Age-S and Cache-Control no-store; a filtered read
// is 503 cis_stale with Retry-After. The proxy back, the next refresh
// clears both.
func TestReadDegradedOnPostgres(t *testing.T) {
	ctx := context.Background()
	u, err := url.Parse(os.Getenv("CISP_TEST_DATABASE_URL"))
	if err != nil || u.Host == "" {
		t.Fatalf("CISP_TEST_DATABASE_URL: %v", err)
	}
	pgStore(t) // migrated
	px := newProxy(t, u.Host)
	u.Host = px.addr
	pool, err := store.OpenPool(ctx, store.PoolConfig{URL: u.String(), ApplicationName: "uspace-cisp-test-proxy", MaxConns: 2})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	h := newPubHarness(t, store.New(pool, store.Options{}))
	freshZones(t, h)
	if rec := h.read(http.MethodGet, "/v1/zones"); rec.Code != 200 || rec.Header().Get(HeaderStale) != "" {
		t.Fatalf("healthy = %d %v", rec.Code, rec.Header())
	}

	px.stop()
	if err := h.cache.Refresh(ctx); err == nil {
		t.Fatal("refresh succeeded with the database away")
	}
	stale := h.read(http.MethodGet, "/v1/zones")
	if stale.Code != 200 || stale.Header().Get(HeaderStale) != "true" || stale.Header().Get("Cache-Control") != "no-store" || stale.Header().Get(HeaderAgeS) == "" {
		t.Errorf("database away, unfiltered = %d %v", stale.Code, stale.Header())
	}
	t.Logf("database away: GET /v1/zones %d X-CIS-Stale=%s X-CIS-Age-S=%s Cache-Control=%s",
		stale.Code, stale.Header().Get(HeaderStale), stale.Header().Get(HeaderAgeS), stale.Header().Get("Cache-Control"))
	filtered := h.read(http.MethodGet, "/v1/zones?bbox=44.79,41.69,44.83,41.725")
	if p := decodeProblem(t, filtered); filtered.Code != 503 || p.Type != ProblemTypeBase+SlugCISStale || filtered.Header().Get("Retry-After") != "5" {
		t.Errorf("database away, filtered = %d %s", filtered.Code, filtered.Body.String())
	}
	t.Logf("database away: GET /v1/zones?bbox= %d Retry-After=%s %s", filtered.Code, filtered.Header().Get("Retry-After"), strings.TrimSpace(filtered.Body.String()))

	px.start(px.addr)
	deadline := time.Now().Add(10 * time.Second)
	for h.cache.Refresh(ctx) != nil {
		if time.Now().After(deadline) {
			t.Fatal("the cache did not refresh with the database back")
		}
		time.Sleep(50 * time.Millisecond)
	}
	back := h.read(http.MethodGet, "/v1/zones")
	if back.Header().Get(HeaderStale) != "" || back.Header().Get(HeaderAgeS) != "" || back.Header().Get("Cache-Control") != "public, max-age=60" {
		t.Errorf("database back: %v", back.Header())
	}
	if rec := h.read(http.MethodGet, "/v1/zones?bbox=44.79,41.69,44.83,41.725"); rec.Code != 200 {
		t.Errorf("database back, filtered = %d", rec.Code)
	}
	t.Logf("database back: GET /v1/zones %d, no X-CIS-Stale, Cache-Control=%s", back.Code, back.Header().Get("Cache-Control"))
}

// The bbox budget on PostGIS (docs/PLAN.md section 9: 100 ms p99 with
// 5 000 features): 50 reads of a box with about 50 hits; the p99 is
// logged and the test fails above 1 s (a CI runner is not the droplet).
func TestReadBBoxBudgetOnPostgres(t *testing.T) {
	st, _ := pgStore(t)
	h := newPubHarness(t, st)
	if rec := h.put("zones", []byte(emptyCollection)); rec.Code != 201 && rec.Code != 200 {
		t.Fatal(rec.Code)
	}
	if rec := h.put("zones", syntheticZones(t, 5000, 20, 1)); rec.Code != 201 {
		t.Fatalf("PUT = %d", rec.Code)
	}
	t.Cleanup(func() { h.put("zones", []byte(emptyCollection)) })
	var took []time.Duration
	hits := 0
	for range 50 {
		start := time.Now()
		rec := h.read(http.MethodGet, bboxAbout50)
		took = append(took, time.Since(start))
		_, byID := collection(t, rec)
		hits = len(byID)
	}
	sort.Slice(took, func(i, j int) bool { return took[i] < took[j] })
	p99 := took[len(took)-1]
	t.Logf("GET /v1/zones?bbox= over 5000 zones, %d hits: p50 %s, p99 %s (budget 100 ms)", hits, took[len(took)/2].Round(time.Millisecond/10), p99.Round(time.Millisecond/10))
	if hits < 30 || hits > 80 {
		t.Errorf("%d hits, expected about 50", hits)
	}
	if p99 > time.Second {
		t.Errorf("p99 %s over 1 s", p99)
	}
}

func vtoa(v int64) string { return strconv.FormatInt(v, 10) }
