package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed318"

	"github.com/rootxkit/uspace-cisp/internal/publication"
)

// fakeSource is a SnapshotSource in memory; down makes every read fail as
// an unreachable database would.
type fakeSource struct {
	mu       sync.Mutex
	current  map[publication.Dataset]int64
	snaps    map[cacheKey]Snapshot
	down     bool
	loads    int
	refreshs int
}

var errDown = errors.New("connection refused")

func (f *fakeSource) CurrentVersions(context.Context) (map[publication.Dataset]int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refreshs++
	if f.down {
		return nil, errDown
	}
	out := map[publication.Dataset]int64{}
	for k, v := range f.current {
		out[k] = v
	}
	return out, nil
}

func (f *fakeSource) Snapshot(_ context.Context, ds publication.Dataset, v int64) (Snapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.loads++
	if f.down {
		return Snapshot{}, errDown
	}
	s, ok := f.snaps[cacheKey{ds, v}]
	if !ok {
		return Snapshot{}, errors.New("no rows")
	}
	return s, nil
}

func snap(ds publication.Dataset, v int64, size int) Snapshot {
	return Snapshot{Dataset: ds, Version: v, ETag: publication.ETag(ds, v), BodyGz: make([]byte, size)}
}

func newSource() *fakeSource {
	f := &fakeSource{current: map[publication.Dataset]int64{publication.DatasetZones: 3, publication.DatasetRestrictions: 0}, snaps: map[cacheKey]Snapshot{}}
	for v := int64(1); v <= 3; v++ {
		f.snaps[cacheKey{publication.DatasetZones, v}] = snap(publication.DatasetZones, v, 100)
	}
	return f
}

func TestCacheServesCurrentAndHoldsIt(t *testing.T) {
	src := newSource()
	c := NewSnapshotCache(src, CacheConfig{})
	ctx := context.Background()
	s, err := c.Current(ctx, publication.DatasetZones)
	if err != nil || s.Version != 3 || s.ETag != `"zones:3"` {
		t.Fatalf("current %+v %v", s, err)
	}
	if _, err := c.Current(ctx, publication.DatasetZones); err != nil {
		t.Fatal(err)
	}
	if src.loads != 1 {
		t.Errorf("loaded %d times, want 1 (the second read is from memory)", src.loads)
	}
	if _, ok := c.Stale(); ok {
		t.Error("stale while the source answers")
	}
	// Never published: ErrNoVersion, not a load.
	if _, err := c.Current(ctx, publication.DatasetRestrictions); !errors.Is(err, ErrNoVersion) {
		t.Errorf("restrictions: %v", err)
	}
}

// E-02: the database goes away; the cache keeps serving what it holds and
// says since when it is stale; it recovers when the database returns.
func TestCacheDegradedServesWhatItHolds(t *testing.T) {
	src := newSource()
	now := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	c := NewSnapshotCache(src, CacheConfig{Now: func() time.Time { return now }})
	ctx := context.Background()
	if _, err := c.Current(ctx, publication.DatasetZones); err != nil {
		t.Fatal(err)
	}

	src.mu.Lock()
	src.down = true
	src.mu.Unlock()
	if err := c.Refresh(ctx); !errors.Is(err, errDown) {
		t.Fatalf("refresh with the database down: %v", err)
	}
	since, ok := c.Stale()
	if !ok || !since.Equal(now) {
		t.Fatalf("stale %v %v, want since %v", since, ok, now)
	}
	s, err := c.Current(ctx, publication.DatasetZones)
	if err != nil || s.Version != 3 {
		t.Fatalf("degraded read: %+v %v", s, err)
	}
	// A version it does not hold cannot be served.
	if _, err := c.Get(ctx, publication.DatasetZones, 1); !errors.Is(err, errDown) {
		t.Errorf("uncached version while down: %v", err)
	}
	// Staleness keeps its first time.
	now = now.Add(time.Minute)
	_ = c.Refresh(ctx)
	if since2, _ := c.Stale(); !since2.Equal(since) {
		t.Errorf("stale since moved to %v", since2)
	}
	if c.Counters().Get("snapshot_cache_refresh_failed") != 2 {
		t.Errorf("refresh failures counted %d", c.Counters().Get("snapshot_cache_refresh_failed"))
	}

	src.mu.Lock()
	src.down = false
	src.current[publication.DatasetZones] = 4
	src.snaps[cacheKey{publication.DatasetZones, 4}] = snap(publication.DatasetZones, 4, 100)
	src.mu.Unlock()
	if err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Stale(); ok {
		t.Error("still stale after a refresh succeeded")
	}
	if s, _ := c.Current(ctx, publication.DatasetZones); s.Version != 4 {
		t.Errorf("after recovery: version %d", s.Version)
	}
}

func TestCacheFirstReadWithTheDatabaseDown(t *testing.T) {
	src := newSource()
	src.down = true
	c := NewSnapshotCache(src, CacheConfig{})
	if _, err := c.Current(context.Background(), publication.DatasetZones); !errors.Is(err, errDown) {
		t.Fatalf("got %v", err)
	}
	if _, ok := c.Stale(); !ok {
		t.Error("not stale")
	}
}

// E-10: at most MaxVersionsPerDataset versions of a dataset.
func TestCacheBoundsVersionsPerDataset(t *testing.T) {
	src := newSource()
	c := NewSnapshotCache(src, CacheConfig{MaxVersionsPerDataset: 2})
	ctx := context.Background()
	for v := int64(1); v <= 2; v++ {
		if _, err := c.Get(ctx, publication.DatasetZones, v); err != nil {
			t.Fatal(err)
		}
	}
	if c.Len() != 2 || c.Counters().Get("snapshot_cache_evicted") != 0 {
		t.Fatalf("at the bound: %d held, %d evicted", c.Len(), c.Counters().Get("snapshot_cache_evicted"))
	}
	if _, err := c.Get(ctx, publication.DatasetZones, 3); err != nil {
		t.Fatal(err)
	}
	if c.Len() != 2 || c.Counters().Get("snapshot_cache_evicted") != 1 {
		t.Fatalf("past the bound: %d held, %d evicted", c.Len(), c.Counters().Get("snapshot_cache_evicted"))
	}
	loads := src.loads
	if _, err := c.Get(ctx, publication.DatasetZones, 1); err != nil || src.loads != loads+1 {
		t.Errorf("version 1 should have been evicted and reloaded")
	}
}

// E-10: at most MaxBytes; the least recently used goes, and a snapshot
// larger than the cache is served but never held.
func TestCacheBoundsBytes(t *testing.T) {
	src := newSource()
	src.current[publication.DatasetUSpaceAirspace] = 1
	src.snaps[cacheKey{publication.DatasetUSpaceAirspace, 1}] = snap(publication.DatasetUSpaceAirspace, 1, 100)
	src.snaps[cacheKey{publication.DatasetUSSPList, 1}] = snap(publication.DatasetUSSPList, 1, 5000)
	one := snap(publication.DatasetZones, 1, 100)
	c := NewSnapshotCache(src, CacheConfig{MaxBytes: 2*one.size() + 10, MaxVersionsPerDataset: 5})
	ctx := context.Background()

	mustGet := func(ds publication.Dataset, v int64) {
		t.Helper()
		if _, err := c.Get(ctx, ds, v); err != nil {
			t.Fatal(err)
		}
	}
	mustGet(publication.DatasetZones, 1)
	mustGet(publication.DatasetZones, 2)
	if c.Counters().Get("snapshot_cache_evicted") != 0 || c.Bytes() != 2*one.size() {
		t.Fatalf("within the bound: evicted %d, bytes %d", c.Counters().Get("snapshot_cache_evicted"), c.Bytes())
	}
	mustGet(publication.DatasetZones, 1) // 1 is now more recent than 2
	mustGet(publication.DatasetUSpaceAirspace, 1)
	if c.Counters().Get("snapshot_cache_evicted") != 1 || c.Len() != 2 {
		t.Fatalf("past the bound: evicted %d, held %d", c.Counters().Get("snapshot_cache_evicted"), c.Len())
	}
	loads := src.loads
	mustGet(publication.DatasetZones, 1)
	if src.loads != loads {
		t.Error("the recently used version was evicted")
	}
	mustGet(publication.DatasetZones, 2)
	if src.loads != loads+1 {
		t.Error("the least recently used version was not evicted")
	}

	big, err := c.Get(ctx, publication.DatasetUSSPList, 1)
	if err != nil || len(big.BodyGz) != 5000 {
		t.Fatalf("oversize snapshot not served: %v", err)
	}
	if c.Counters().Get("snapshot_cache_oversize") != 1 || c.Bytes() > 2*one.size()+10 {
		t.Errorf("oversize: counted %d, bytes %d", c.Counters().Get("snapshot_cache_oversize"), c.Bytes())
	}
}

func TestCacheRunRefreshesOnChange(t *testing.T) {
	src := newSource()
	c := NewSnapshotCache(src, CacheConfig{RefreshEvery: time.Hour})
	ctx, cancel := context.WithCancel(context.Background())
	changed := make(chan struct{})
	done := make(chan struct{})
	go func() { c.Run(ctx, changed); close(done) }()
	changed <- struct{}{} // accepted only after the first refresh
	changed <- struct{}{}
	cancel()
	<-done
	src.mu.Lock()
	defer src.mu.Unlock()
	if src.refreshs < 2 {
		t.Errorf("refreshed %d times", src.refreshs)
	}
}

func TestNewIDIsAULID(t *testing.T) {
	at := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	re := regexp.MustCompile(`^[0-7][0-9A-HJKMNP-TV-Z]{25}$`)
	a, b := newID(at), newID(at)
	if !re.MatchString(a) || !re.MatchString(b) || a == b {
		t.Fatalf("ids %s %s", a, b)
	}
	if a[:10] != b[:10] {
		t.Errorf("same millisecond, different time prefix: %s %s", a, b)
	}
	if later := newID(at.Add(time.Second)); later[:10] <= a[:10] {
		t.Errorf("a later id does not sort after: %s %s", later, a)
	}
	// 2026-10-02T00:00:00Z is 1790899200000 ms; the first ten characters
	// encode it (computed independently in Python).
	if a[:10] != "01M3WYJ800" {
		t.Errorf("time prefix %s", a[:10])
	}
}

func TestPolygonGeoJSONKeepsCoordinates(t *testing.T) {
	got := polygonGeoJSON([][]core.LatLon{{{LatDeg: 41.65, LonDeg: 44.7}, {LatDeg: 41.65, LonDeg: 44.95}, {LatDeg: 41.8, LonDeg: 44.95}, {LatDeg: 41.65, LonDeg: 44.7}}})
	want := `{"type":"Polygon","coordinates":[[[44.7,41.65],[44.95,41.65],[44.95,41.8],[44.7,41.65]]]}`
	if got != want {
		t.Errorf("got %s", got)
	}
	if !json.Valid([]byte(got)) {
		t.Error("not JSON")
	}
}

func TestGzipRoundTrip(t *testing.T) {
	body := []byte(strings.Repeat(`{"a":1}`, 100))
	gz, err := gzipBytes(body)
	if err != nil {
		t.Fatal(err)
	}
	back, err := gunzip(gz)
	if err != nil || !bytes.Equal(back, body) {
		t.Fatalf("round trip: %v", err)
	}
	gz2, _ := gzipBytes(body)
	if !bytes.Equal(gz, gz2) {
		t.Error("gzip is not deterministic")
	}
	if _, err := gunzip([]byte("not gzip")); err == nil {
		t.Error("garbage accepted")
	}
}

func TestParseTree(t *testing.T) {
	for _, s := range []string{"relational", "timeseries"} {
		tr, err := ParseTree(s)
		if err != nil || string(tr) != s {
			t.Errorf("%s: %v", s, err)
		}
	}
	if _, err := ParseTree("both"); err == nil {
		t.Error("an unknown tree accepted")
	}
	if TreeRelational.VersionTable() != "goose_db_version_relational" || TreeTimeseries.other() != TreeRelational {
		t.Error("version tables")
	}
	for _, tr := range []Tree{TreeRelational, TreeTimeseries} {
		if _, err := tr.files(); err != nil {
			t.Errorf("%s files: %v", tr, err)
		}
	}
	if _, err := Tree("x").files(); err == nil {
		t.Error("files of an unknown tree")
	}
}

func validInput(t *testing.T) PublishInput {
	t.Helper()
	return PublishInput{
		Dataset: publication.DatasetZones, Body: []byte(`{}`), ContentType: "application/json",
		PublisherClientID: "authority-01", Collection: &ed318.FeatureCollection{Type: "FeatureCollection"},
		Reason: publication.ReasonPublication,
	}
}

// Every refusal beside the acceptance that differs in one thing (E-01);
// validation runs before any database access.
func TestPublishInputValidation(t *testing.T) {
	if err := func() error { in := validInput(t); return in.validate() }(); err != nil {
		t.Fatalf("valid input refused: %v", err)
	}
	cases := []struct {
		field string
		edit  func(*PublishInput)
	}{
		{"dataset", func(in *PublishInput) { in.Dataset = "geo_zones" }},
		{"reason", func(in *PublishInput) { in.Reason = publication.ReasonSubscriptionTest }},
		{"body", func(in *PublishInput) { in.Body = nil }},
		{"content_type", func(in *PublishInput) { in.ContentType = "" }},
		{"publisher_client_id", func(in *PublishInput) { in.PublisherClientID = "" }},
		{"collection", func(in *PublishInput) { in.Collection = nil }},
		{"collection", func(in *PublishInput) { in.Dataset = publication.DatasetUSSPList }},
		{"warnings", func(in *PublishInput) { in.Warnings = json.RawMessage(`[`) }},
	}
	for _, c := range cases {
		in := validInput(t)
		c.edit(&in)
		var fe *core.FieldError
		if err := in.validate(); !errors.As(err, &fe) || fe.Field != c.field {
			t.Errorf("%s: got %v", c.field, err)
		}
	}
	ussp := validInput(t)
	ussp.Dataset, ussp.Collection = publication.DatasetUSSPList, nil
	if err := ussp.validate(); err != nil {
		t.Errorf("ussp_list without a collection refused: %v", err)
	}
}

func TestPublishRefusesTheNoopSignerOutsideTests(t *testing.T) {
	s := New(nil, Options{})
	if _, err := s.PublishTx(context.Background(), validInput(t), NoopSigner{}); !errors.Is(err, ErrNoopSigner) {
		t.Errorf("got %v", err)
	}
	if _, err := s.PublishTx(context.Background(), validInput(t), nil); err == nil {
		t.Error("nil signer accepted")
	}
	if sig, err := (NoopSigner{}).Sign(context.Background(), []byte("x")); sig != "" || err != nil {
		t.Error("NoopSigner signed")
	}
}

func TestEventHashChains(t *testing.T) {
	ts := time.Date(2026, 10, 2, 1, 2, 3, 456789000, time.UTC)
	a, err := EventHash(nil, ts, "client", "authority-01", "publication_accepted", "publication", "X", []byte(`{"b":1,"a":2}`))
	if err != nil || len(a) != 32 {
		t.Fatalf("%x %v", a, err)
	}
	// Key order in the payload does not matter; the previous hash does.
	a2, _ := EventHash(nil, ts, "client", "authority-01", "publication_accepted", "publication", "X", []byte(`{"a":2,"b":1}`))
	if !bytes.Equal(a, a2) {
		t.Error("payload key order changed the hash")
	}
	b, _ := EventHash(a, ts, "client", "authority-01", "publication_accepted", "publication", "X", []byte(`{"a":2,"b":1}`))
	if bytes.Equal(a, b) {
		t.Error("the previous hash does not change the hash")
	}
	if _, err := EventHash(nil, ts, "", "", "", "", "", []byte(`{`)); err == nil {
		t.Error("broken payload accepted")
	}
}

func TestOpenPoolRefusesABadURLWithoutEchoingIt(t *testing.T) {
	_, err := OpenPool(context.Background(), PoolConfig{URL: "postgres://u:secret@[::1:5432/x"})
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("got %v", err)
	}
	p, err := OpenPool(context.Background(), PoolConfig{URL: "postgres://u:p@127.0.0.1:1/x", ApplicationName: "t", MaxConns: 3, StatementTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	cfg := p.Config()
	if cfg.MaxConns != 3 || cfg.ConnConfig.RuntimeParams["application_name"] != "t" || cfg.ConnConfig.RuntimeParams["statement_timeout"] != "2000" {
		t.Errorf("config %d %v", cfg.MaxConns, cfg.ConnConfig.RuntimeParams)
	}
	d, err := OpenPool(context.Background(), PoolConfig{URL: "postgres://u:p@127.0.0.1:1/x"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if d.Config().MaxConns != DefaultRelationalMaxConns || d.Config().ConnConfig.RuntimeParams["statement_timeout"] != "10000" {
		t.Errorf("defaults %d %v", d.Config().MaxConns, d.Config().ConnConfig.RuntimeParams)
	}
}
