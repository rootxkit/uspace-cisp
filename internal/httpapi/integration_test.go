//go:build integration

// Integration tests of the publication intake on PostgreSQL + PostGIS
// (make dev-deps, or the CI services): the vectors through PUT into the
// real store, the 5 000-zone budget, and what is read back from the
// tables. A missing address fails the test: a suite that skips proves
// nothing.
package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rootxkit/uspace-cisp/internal/auth"
	"github.com/rootxkit/uspace-cisp/internal/httpapi/gen"
	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/store"
	"github.com/rootxkit/uspace-cisp/internal/store/relational"
)

// pgStore is the store on the migrated test database.
func pgStore(t *testing.T) (*store.Store, *pgxpool.Pool) {
	t.Helper()
	url := os.Getenv("CISP_TEST_DATABASE_URL")
	if url == "" {
		t.Fatal("CISP_TEST_DATABASE_URL is not set; run make dev-deps (see the Makefile's integration target)")
	}
	ctx := context.Background()
	pool, err := store.OpenPool(ctx, store.PoolConfig{URL: url, ApplicationName: "uspace-cisp-test", MaxConns: 4, StatementTimeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	db := store.OpenSQL(pool)
	defer func() { _ = db.Close() }()
	if _, err := store.Up(ctx, db, store.TreeRelational); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return store.New(pool, store.Options{}), pool
}

func pgBody(pool *pgxpool.Pool) storedBody {
	return func(t *testing.T, ds publication.Dataset, v int64) []byte {
		t.Helper()
		p, err := relational.New(pool).GetPublication(context.Background(), relational.GetPublicationParams{Dataset: string(ds), Version: v})
		if err != nil {
			t.Fatalf("%s version %d: %v", ds, v, err)
		}
		return p.Body
	}
}

// The 22 ed318_roundtrip cases through PUT into PostgreSQL; the stored
// body of every accepted version equals the bytes sent.
func TestVectorsED318RoundtripStore(t *testing.T) {
	ran := runED318Vectors(t, func(t *testing.T) (*pubHarness, storedBody) {
		st, pool := pgStore(t)
		return newPubHarness(t, st), pgBody(pool)
	})
	t.Logf("%d ed318_roundtrip cases ran through PUT into PostgreSQL", ran)
}

// On PostgreSQL: accepted, re-PUT unchanged, one feature changed; a
// refusal recorded and read back by the publisher; the warning read back
// from the history; an identifier another dataset holds refused; the
// heartbeat read back from publishers; and the refusal counter in the
// status line.
func TestIntakeOnPostgres(t *testing.T) {
	ctx := context.Background()
	st, _ := pgStore(t)
	h := newPubHarness(t, st)

	// Start from an empty zones dataset, whatever earlier tests left.
	if rec := h.put("zones", []byte(emptyCollection)); rec.Code != 201 && rec.Code != 200 {
		t.Fatalf("empty = %d %s", rec.Code, rec.Body.String())
	}
	d := zonesDoc(t)
	delete(fprops(d, 0)["limitedApplicability"].([]any)[0].(doc), "endDateTime") // the warning
	rec := h.put("zones", jsonBytes(t, d))
	r := decodeResult(t, rec)
	if rec.Code != 201 || *r.AddedCount != 4 || len(*r.Warnings) != 1 {
		t.Fatalf("PUT = %d %s", rec.Code, rec.Body.String())
	}
	if again := h.put("zones", jsonBytes(t, d)); again.Code != 200 || !strings.Contains(again.Body.String(), `"unchanged":true`) {
		t.Fatalf("re-PUT = %d %s", again.Code, again.Body.String())
	}
	fprops(d, 1)["restrictionConditions"] = "changed " + time.Now().Format(time.RFC3339Nano)
	rec = h.put("zones", jsonBytes(t, d))
	if r2 := decodeResult(t, rec); rec.Code != 201 || r2.Version != r.Version+1 || !reflect.DeepEqual(*r2.Changed, []string{"TSR001"}) {
		t.Fatalf("changed = %d %s", rec.Code, rec.Body.String())
	}

	// The warning, read back from the history.
	var list gen.PublicationVersionList
	_ = json.Unmarshal(h.get("/v1/publications/zones?limit=1", h.authorityToken()).Body.Bytes(), &list)
	if len(list.Versions) != 1 || len(list.Versions[0].Warnings) != 1 || !strings.Contains(list.Versions[0].Warnings[0].Reason, "TSD001") {
		t.Fatalf("history %+v", list)
	}
	t.Logf("warning read back from PostgreSQL: %s: %s", list.Versions[0].Warnings[0].Field, list.Versions[0].Warnings[0].Reason)

	// A refusal, recorded and read back; and counted in the status line.
	bad := zonesDoc(t)
	fprops(bad, 2)["type"] = "USPACE"
	since := time.Now().Add(-time.Millisecond).UTC().Format(time.RFC3339Nano)
	if rec := h.put("zones", jsonBytes(t, bad)); rec.Code != 400 {
		t.Fatalf("refusal = %d", rec.Code)
	}
	var attempts gen.PublicationAttemptList
	_ = json.Unmarshal(h.get("/v1/publications/zones/attempts?since="+since, h.authorityToken()).Body.Bytes(), &attempts)
	if len(attempts.Attempts) != 1 || attempts.Attempts[0].Problems[0].Field != "features[2].properties.type" {
		t.Fatalf("attempts %+v", attempts)
	}
	var line bytes.Buffer
	h.status.Log(ctx, slog.New(slog.NewJSONHandler(&line, nil)), time.Now())
	if !strings.Contains(line.String(), `"publications_refused":1`) || !strings.Contains(line.String(), `"zones":{"publications_accepted":`) {
		t.Errorf("status line: %s", line.String())
	}
	t.Logf("status line: %s", strings.TrimSpace(line.String()))

	// D8: zones holds TSN001; uspace_airspace may not.
	u := uspaceDoc(t)
	fprops(u, 0)["identifier"] = "TSN001"
	rec = h.put("uspace_airspace", jsonBytes(t, u))
	if p := decodeProblem(t, rec); rec.Code != 400 || !hasProblem(p, "features[0].properties.identifier", "held by the current version of zones") {
		t.Fatalf("reserved = %d %s", rec.Code, rec.Body.String())
	}

	// The heartbeat, read back from publishers.
	sentAt := time.Now().UTC().Truncate(time.Second)
	body := fmt.Sprintf(`{"sent_at":%q,"active_refs":["ref-a"]}`, sentAt.Format(time.RFC3339))
	_, hb := h.heartbeat(h.token(anspID, auth.ScopePublishRestrictions), body, func(r *http.Request) { r.Header.Set(auth.HeaderClientCertSubject, anspSubject) })
	if hb.Code != 204 {
		t.Fatalf("heartbeat = %d %s", hb.Code, hb.Body.String())
	}
	p, err := st.Publisher(ctx, anspID)
	if err != nil || p.Kind != "ansp" || !p.LastHeartbeatSentAt.Equal(sentAt) || !reflect.DeepEqual(p.ActiveRefs, []string{"ref-a"}) {
		t.Fatalf("publishers row %+v %v", p, err)
	}
	if _, hb = h.heartbeat(h.token(authorityID, auth.ScopePublishZones), `{"sent_at":"2026-10-02T10:00:00Z"}`); hb.Code != 204 {
		t.Fatalf("authority heartbeat = %d", hb.Code)
	}
	if p, err := st.Publisher(ctx, authorityID); err != nil || p.ActiveRefs != nil || p.Kind != "authority" {
		t.Errorf("authority row %+v %v", p, err)
	}
}

// The database gone (E-02, for real): a pool on a port where nothing
// listens; a PUT is 503 with Retry-After, never a hang and never a 500.
func TestIntakeWithTheDatabaseGone(t *testing.T) {
	u, err := url.Parse(os.Getenv("CISP_TEST_DATABASE_URL"))
	if err != nil || u.Host == "" {
		t.Fatalf("CISP_TEST_DATABASE_URL: %v", err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	u.Host = l.Addr().String()
	_ = l.Close() // nothing listens there now
	pool, err := store.OpenPool(context.Background(), store.PoolConfig{URL: u.String(), ApplicationName: "uspace-cisp-test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	h := newPubHarness(t, store.New(pool, store.Options{}))
	rec := h.do(h.putReq("zones", jsonBytes(t, zonesDoc(t)), `"zones:0"`))
	if p := decodeProblem(t, rec); rec.Code != 503 || p.Type != ProblemTypeBase+SlugDatabaseUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("PUT = %d %s", rec.Code, rec.Body.String())
	}
	t.Logf("database gone: %d %s", rec.Code, strings.TrimSpace(rec.Body.String()))
}

// A 20 MB publication of 5 000 zones (polygons of 20 vertices around
// Tbilisi) completes under the section 9 budget; the duration is logged
// and the test fails above 30 s.
func TestPublication5000ZonesBudget(t *testing.T) {
	st, pool := pgStore(t)
	h := newPubHarness(t, st)
	body := syntheticZones(t, 5000, 20, 20_000_000)
	if rec := h.put("zones", []byte(emptyCollection)); rec.Code != 201 && rec.Code != 200 {
		t.Fatalf("empty = %d", rec.Code)
	}
	cur, _ := st.CurrentVersion(context.Background(), publication.DatasetZones)
	req := h.putReq("zones", body, publication.ETag(publication.DatasetZones, cur))
	start := time.Now()
	rec := h.do(req)
	elapsed := time.Since(start)
	if rec.Code != 201 {
		t.Fatalf("PUT = %d %s", rec.Code, rec.Body.String()[:min(rec.Body.Len(), 2000)])
	}
	r := decodeResult(t, rec)
	t.Logf("5000-zone publication: %d bytes, %d features, version %d, accepted in %s (budget 10 s p95; fails above 30 s)",
		len(body), *r.FeatureCount, r.Version, elapsed.Round(time.Millisecond))
	if elapsed > 30*time.Second {
		t.Fatalf("took %s, over 30 s", elapsed)
	}
	if *r.FeatureCount != 5000 || *r.AddedCount != 5000 || len(*r.Added) != MaxIDsPerList || r.Truncated == nil || r.Truncated.Added != 4000 {
		t.Errorf("result counts %+v", r)
	}
	if got := pgBody(pool)(t, publication.DatasetZones, r.Version); !bytes.Equal(got, body) {
		t.Error("the stored body is not the bytes received")
	}
	// Leave zones empty for the tests after this one.
	if rec := h.put("zones", []byte(emptyCollection)); rec.Code != 201 {
		t.Fatalf("empty again = %d", rec.Code)
	}
}
