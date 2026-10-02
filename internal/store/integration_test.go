//go:build integration

// Integration tests of the store against real PostgreSQL + PostGIS,
// TimescaleDB and NATS (make dev-deps, or the CI services). A missing
// address fails the test: a suite that skips proves nothing.
package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rootxkit/uspace-core/ed318"
	"github.com/rootxkit/uspace-core/vectors"

	"github.com/rootxkit/uspace-cisp/internal/bus"
	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/store/relational"
	"github.com/rootxkit/uspace-cisp/internal/store/timeseries"
)

func mustEnv(t *testing.T, name string) string {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		t.Fatalf("%s is not set; run make dev-deps (see the Makefile's integration target)", name)
	}
	return v
}

func pool(t *testing.T, env string) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	p, err := OpenPool(ctx, PoolConfig{URL: mustEnv(t, env), ApplicationName: "uspace-cisp-test", MaxConns: 8})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

// migrated is a pool on the tree's database with every migration applied.
func migrated(t *testing.T, tree Tree) *pgxpool.Pool {
	t.Helper()
	env := "CISP_TEST_DATABASE_URL"
	if tree == TreeTimeseries {
		env = "CISP_TEST_TIMESERIES_URL"
	}
	p := pool(t, env)
	db := OpenSQL(p)
	defer db.Close()
	if _, err := Up(context.Background(), db, tree); err != nil {
		t.Fatalf("up: %v", err)
	}
	return p
}

func testStore(t *testing.T, opts Options) *Store {
	t.Helper()
	opts.AllowNoopSigner = true
	return New(migrated(t, TreeRelational), opts)
}

// suffix is a random 4-character base-36 tag, so that identifiers (at
// most 7 characters) never collide with an earlier run's.
func suffix(t *testing.T) string {
	t.Helper()
	const digits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	var b [4]byte
	_, _ = rand.Read(b[:])
	for i := range b {
		b[i] = digits[int(b[i])%len(digits)]
	}
	return string(b[:])
}

// base is the accepted ED-318 vector collection with identifiers made
// unique for this test: "<p><n><tag>", n = 1..5.
func base(t *testing.T, prefix string) (*ed318.FeatureCollection, []byte) {
	t.Helper()
	f := vectors.Load(t, "ed318_roundtrip.json")
	for _, c := range f.Cases {
		if c.Name != "accept-authority-collection" {
			continue
		}
		var in struct {
			Document json.RawMessage `json:"document"`
		}
		if err := json.Unmarshal(c.Input, &in); err != nil {
			t.Fatal(err)
		}
		fc, probs := ed318.Parse(in.Document, ed318.Limits{})
		if probs != nil {
			t.Fatal(probs)
		}
		tag := suffix(t)
		for i := range fc.Features {
			fc.Features[i].Properties.Identifier = prefix + string(rune('1'+i)) + tag
		}
		body, err := ed318.Export(fc)
		if err != nil {
			t.Fatal(err)
		}
		return fc, body
	}
	t.Fatal("no accept-authority-collection case")
	return nil, nil
}

func input(ds publication.Dataset, fc *ed318.FeatureCollection, body []byte) PublishInput {
	sig, kid := "eyJhbGciOiJSUzI1NiJ9..c2ln", "authority-2026"
	return PublishInput{
		Dataset: ds, Body: body, ContentType: "application/json", PublisherClientID: "authority-01",
		PublisherSignature: &sig, SignatureKID: &kid, Collection: fc, Reason: publication.ReasonPublication,
	}
}

func currentVersion(t *testing.T, s *Store, ds publication.Dataset) int64 {
	t.Helper()
	d, err := relational.New(s.pool).GetDataset(context.Background(), string(ds))
	if err != nil {
		t.Fatal(err)
	}
	return d.CurrentVersion
}

func count(t *testing.T, p *pgxpool.Pool, sql string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := p.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return n
}

func sqlState(err error) string {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return pg.Code
	}
	return ""
}

// Both trees up from empty, down to zero and up again; each ends where
// the next test expects it (migrated).
func TestMigrationTreesUpDownUp(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		tree   Tree
		env    string
		tables []string
		files  int
	}{
		{TreeRelational, "CISP_TEST_DATABASE_URL", []string{"datasets", "publications", "publication_attempts", "features", "features_current", "snapshots", "changes", "restrictions", "restriction_events", "publishers", "subscriptions", "deliveries", "accounts", "sessions", "events", "job_runs", "deliver_state"}, 9},
		{TreeTimeseries, "CISP_TEST_TIMESERIES_URL", []string{"delivery_attempts"}, 2},
	}
	for _, c := range cases {
		t.Run(string(c.tree), func(t *testing.T) {
			db := OpenSQL(pool(t, c.env))
			defer db.Close()
			if _, err := Up(ctx, db, c.tree); err != nil {
				t.Fatal(err)
			}
			down, err := DownTo(ctx, db, c.tree, 0)
			if err != nil {
				t.Fatalf("down: %v", err)
			}
			if len(down) != c.files {
				t.Errorf("rolled back %d migrations, want %d", len(down), c.files)
			}
			for _, tbl := range c.tables {
				var exists bool
				if err := db.QueryRowContext(ctx, "SELECT to_regclass($1) IS NOT NULL", tbl).Scan(&exists); err != nil || exists {
					t.Errorf("%s exists after down to 0 (%v)", tbl, err)
				}
			}
			pending, err := Pending(ctx, db, c.tree)
			if err != nil || len(pending) != c.files {
				t.Fatalf("pending after down: %v %v", pending, err)
			}
			up, err := Up(ctx, db, c.tree)
			if err != nil || len(up) != c.files {
				t.Fatalf("up again: %d applied, %v", len(up), err)
			}
			for _, tbl := range c.tables {
				var exists bool
				if err := db.QueryRowContext(ctx, "SELECT to_regclass($1) IS NOT NULL", tbl).Scan(&exists); err != nil || !exists {
					t.Errorf("%s missing after up (%v)", tbl, err)
				}
			}
			if pending, err := Pending(ctx, db, c.tree); err != nil || len(pending) != 0 {
				t.Errorf("pending after up: %v %v", pending, err)
			}
			if again, err := Up(ctx, db, c.tree); err != nil || len(again) != 0 {
				t.Errorf("a second up applied %d (%v)", len(again), err)
			}
		})
	}
}

// A tree run against the other tree's database is refused; against its
// own it runs (E-01 pair).
func TestMigrationTreeRefusesTheOtherDatabase(t *testing.T) {
	ctx := context.Background()
	rel := OpenSQL(migrated(t, TreeRelational))
	defer rel.Close()
	ts := OpenSQL(migrated(t, TreeTimeseries))
	defer ts.Close()
	if _, err := Up(ctx, ts, TreeRelational); !errors.Is(err, ErrWrongDatabase) {
		t.Errorf("relational tree on the timeseries database: %v", err)
	}
	if _, err := Pending(ctx, rel, TreeTimeseries); !errors.Is(err, ErrWrongDatabase) {
		t.Errorf("timeseries tree on the relational database: %v", err)
	}
	if _, err := Up(ctx, rel, TreeRelational); err != nil {
		t.Errorf("relational tree on its own database: %v", err)
	}
}

// 06 T7: the record is insert-only for cisp_api; a writable table beside
// it accepts the same statement (E-01 pair).
func TestAuditTablesAreInsertOnly(t *testing.T) {
	p := migrated(t, TreeRelational)
	ctx := context.Background()
	for _, stmt := range []string{
		"UPDATE publications SET reason = reason",
		"DELETE FROM publications",
		"UPDATE publication_attempts SET bytes = bytes",
		"DELETE FROM features",
		"UPDATE changes SET reason = reason",
		"DELETE FROM changes",
		"UPDATE events SET actor_id = actor_id",
		"DELETE FROM events",
		"TRUNCATE publications CASCADE",
		"UPDATE restriction_events SET actor = actor",
		"DELETE FROM restriction_events",
	} {
		tx, err := p.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(ctx, stmt)
		_ = tx.Rollback(ctx)
		if sqlState(err) != "42501" {
			t.Errorf("%s: got %v, want permission denied (42501)", stmt, err)
		}
	}
	for _, stmt := range []string{"UPDATE datasets SET updated_at = updated_at", "DELETE FROM snapshots WHERE false"} {
		tx, err := p.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(ctx, stmt)
		_ = tx.Rollback(ctx)
		if err != nil {
			t.Errorf("%s on a writable table: %v", stmt, err)
		}
	}
}

func TestPublishTxVersionsFeaturesSnapshotChangeAndAudit(t *testing.T) {
	ctx := context.Background()
	s := testStore(t, Options{})
	q := relational.New(s.pool)
	fc, body := base(t, "P")
	before := currentVersion(t, s, publication.DatasetZones)

	first, err := s.PublishTx(ctx, input(publication.DatasetZones, fc, body), NoopSigner{})
	if err != nil {
		t.Fatal(err)
	}
	if first.Version != before+1 || first.ETag != publication.ETag(publication.DatasetZones, before+1) || len(first.Diff.Added) != 5 {
		t.Fatalf("first: %+v", first)
	}

	// The same features again: no version, nothing written (D3).
	pubs := count(t, s.pool, "SELECT count(*) FROM publications WHERE dataset = 'zones'")
	again, err := s.PublishTx(ctx, input(publication.DatasetZones, fc, body), NoopSigner{})
	if !errors.Is(err, ErrUnchanged) || again.Version != first.Version {
		t.Fatalf("re-publication: %+v %v", again, err)
	}
	if n := count(t, s.pool, "SELECT count(*) FROM publications WHERE dataset = 'zones'"); n != pubs {
		t.Errorf("an unchanged publication wrote %d rows", n-pubs)
	}

	// One changed, one removed, one added beside two unchanged.
	ids := make([]string, 0, 5)
	for _, f := range fc.Features {
		ids = append(ids, f.Properties.Identifier)
	}
	next := *fc
	next.Features = slices.Clone(fc.Features[:4]) // the fifth is removed
	other := "a renamed zone"
	next.Features[2].Properties.Name = []ed318.Text{{Text: &other, Lang: "en-GB"}} // changed
	added := fc.Features[4]
	added.Properties.Identifier = "PA" + ids[0][2:]
	next.Features = append(next.Features, added)
	nextBody, _ := ed318.Export(&next)
	second, err := s.PublishTx(ctx, input(publication.DatasetZones, &next, nextBody), NoopSigner{})
	if err != nil {
		t.Fatal(err)
	}
	if second.Version != first.Version+1 {
		t.Fatalf("second version %d after %d", second.Version, first.Version)
	}
	if !slices.Equal(second.Diff.Added, []string{added.Properties.Identifier}) || !slices.Equal(second.Diff.Changed, []string{ids[2]}) || !slices.Equal(second.Diff.Removed, []string{ids[4]}) {
		t.Fatalf("diff %+v", second.Diff)
	}

	// The publication row: verbatim body, signature, counts.
	pub, err := q.GetPublication(ctx, relational.GetPublicationParams{Dataset: "zones", Version: second.Version})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(nextBody)
	if !bytes.Equal(pub.Body, nextBody) || !bytes.Equal(pub.BodySha256, sum[:]) || pub.PublisherSignature == nil || pub.FeatureCount != 5 ||
		pub.Added != 1 || pub.Changed != 1 || pub.Removed != 1 || pub.SupersedesVersion == nil || *pub.SupersedesVersion != first.Version {
		t.Errorf("publication row %+v", pub)
	}

	// The features of the version with their ops; removed carries its last form.
	feats, err := q.ListPublicationFeatures(ctx, pub.ID)
	if err != nil {
		t.Fatal(err)
	}
	ops := map[string]int{}
	for _, f := range feats {
		ops[f.Op]++
	}
	if ops["added"] != 1 || ops["changed"] != 1 || ops["removed"] != 1 || ops["unchanged"] != 3 {
		t.Errorf("ops %v", ops)
	}

	// features_current: the five current features, each equal byte for
	// byte to the published feature after canonicalisation (the buffer of
	// a circle never replaces it).
	rows, err := publication.Rows(&next)
	if err != nil {
		t.Fatal(err)
	}
	cur, err := q.ListCurrentFeatures(ctx, "zones")
	if err != nil {
		t.Fatal(err)
	}
	if len(cur) != 5 {
		t.Fatalf("features_current holds %d rows", len(cur))
	}
	for _, r := range rows {
		i := slices.IndexFunc(cur, func(c relational.ListCurrentFeaturesRow) bool { return c.FeatureID == r.ID })
		if i < 0 {
			t.Errorf("%s not current", r.ID)
			continue
		}
		got, err := publication.Canonical(cur[i].Feature)
		if err != nil || !bytes.Equal(got, r.Canonical) {
			t.Errorf("%s: stored feature differs from the published one:\n got %s\nwant %s", r.ID, got, r.Canonical)
		}
		if !bytes.Equal(cur[i].FeatureSha256, r.SHA256[:]) || cur[i].Version != second.Version {
			t.Errorf("%s: hash or version", r.ID)
		}
	}

	// The snapshot: the unfiltered body, parseable, with the cis_ members.
	snap, err := s.Snapshot(ctx, publication.DatasetZones, second.Version)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := gunzip(snap.BodyGz)
	if err != nil {
		t.Fatal(err)
	}
	if _, probs := ed318.Parse(raw, ed318.Limits{}); probs != nil {
		t.Errorf("snapshot does not parse: %v", probs)
	}
	var top map[string]json.RawMessage
	_ = json.Unmarshal(raw, &top)
	if string(top["cis_dataset"]) != `"zones"` || string(top["cis_version"]) != itoa(second.Version) || snap.ETag != second.ETag {
		t.Errorf("snapshot members %s %s %s", top["cis_dataset"], top["cis_version"], snap.ETag)
	}

	// The change record, with its box, in cursor order after the first.
	changes, err := q.ListChanges(ctx, relational.ListChangesParams{SinceID: first.Change.ID - 1, Dataset: ptr("zones"), MaxRows: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 2 || changes[0].ID != first.Change.ID || changes[1].ID != second.Change.ID || changes[1].Version != second.Version {
		t.Fatalf("changes %+v", changes)
	}
	want := second.Diff.IDs()
	if !slices.Equal(changes[1].FeatureIds, want) || !slices.Equal(changes[1].RemovedIds, []string{ids[4]}) || !changes[1].HasBbox {
		t.Errorf("change %+v", changes[1])
	}

	// The audit row, chained to the previous one.
	ev, err := q.ListEvents(ctx, relational.ListEventsParams{AfterID: 0, MaxRows: 100000})
	if err != nil {
		t.Fatal(err)
	}
	last := ev[len(ev)-1]
	if last.EventType != "publication_accepted" || last.EntityID != pub.ID || last.ActorID != "authority-01" {
		t.Errorf("last event %+v", last)
	}
	for i := 1; i < len(ev); i++ {
		if !bytes.Equal(ev[i].PrevHash, ev[i-1].Hash) {
			t.Fatalf("event %d does not chain to %d", ev[i].ID, ev[i-1].ID)
		}
		payload, _ := publication.Canonical(ev[i].Payload)
		h, err := EventHash(ev[i].PrevHash, ev[i].Ts, ev[i].ActorType, ev[i].ActorID, ev[i].EventType, ev[i].EntityType, ev[i].EntityID, payload)
		if err != nil || !bytes.Equal(h, ev[i].Hash) {
			t.Fatalf("event %d: the stored hash is not recomputable", ev[i].ID)
		}
	}
	if s.Counters().Get("bus_publish_skipped") != 2 {
		t.Errorf("bus_publish_skipped = %d, want 2 (no bus)", s.Counters().Get("bus_publish_skipped"))
	}
}

func itoa(v int64) string  { b, _ := json.Marshal(v); return string(b) }
func ptr(s string) *string { return &s }

// A failure after features_current was replaced leaves no row of the
// version anywhere; the same publication without the failure commits.
func TestPublishTxIsAtomic(t *testing.T) {
	ctx := context.Background()
	s := testStore(t, Options{})
	fc, body := base(t, "A")
	before := currentVersion(t, s, publication.DatasetZones)
	hashesBefore, err := relational.New(s.pool).CurrentFeatureHashes(ctx, "zones")
	if err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected after step 4")
	s.failAfter = func(step int) error {
		if step == stepCurrent {
			return injected
		}
		return nil
	}
	if _, err := s.PublishTx(ctx, input(publication.DatasetZones, fc, body), NoopSigner{}); !errors.Is(err, injected) {
		t.Fatalf("got %v", err)
	}
	v := before + 1
	for sql, want := range map[string]int64{
		"SELECT count(*) FROM publications WHERE dataset = 'zones' AND version = $1":     0,
		"SELECT count(*) FROM snapshots WHERE dataset = 'zones' AND version = $1":        0,
		"SELECT count(*) FROM changes WHERE dataset = 'zones' AND version = $1":          0,
		"SELECT count(*) FROM features_current WHERE dataset = 'zones' AND version = $1": 0,
	} {
		if n := count(t, s.pool, sql, v); n != want {
			t.Errorf("%s = %d after the failure", sql, n)
		}
	}
	if count(t, s.pool, "SELECT count(*) FROM features f JOIN publications p ON p.id = f.publication_id WHERE p.dataset = 'zones' AND p.version = $1", v) != 0 {
		t.Error("features of the failed version exist")
	}
	if currentVersion(t, s, publication.DatasetZones) != before {
		t.Error("the current version moved")
	}
	hashesAfter, _ := relational.New(s.pool).CurrentFeatureHashes(ctx, "zones")
	if len(hashesAfter) != len(hashesBefore) {
		t.Errorf("features_current changed: %d rows, was %d", len(hashesAfter), len(hashesBefore))
	}

	s.failAfter = nil
	res, err := s.PublishTx(ctx, input(publication.DatasetZones, fc, body), NoopSigner{})
	if err != nil || res.Version != v {
		t.Fatalf("without the failure: %+v %v", res, err)
	}
	if count(t, s.pool, "SELECT count(*) FROM features_current WHERE dataset = 'zones' AND version = $1", v) != 5 {
		t.Error("features_current not replaced")
	}
}

// Two publications of one dataset at once get versions N and N+1 and
// cursors in the same order (the advisory lock).
func TestConcurrentPublicationsSerialise(t *testing.T) {
	ctx := context.Background()
	s := testStore(t, Options{})
	before := currentVersion(t, s, publication.DatasetUSpaceAirspace)
	var wg sync.WaitGroup
	results := make([]PublishResult, 2)
	errs := make([]error, 2)
	for i := range 2 {
		fc, body := base(t, string(rune('C'+i)))
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], errs[i] = s.PublishTx(ctx, input(publication.DatasetUSpaceAirspace, fc, body), NoopSigner{})
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("publication %d: %v", i, err)
		}
	}
	slices.SortFunc(results, func(a, b PublishResult) int { return int(a.Version - b.Version) })
	if results[0].Version != before+1 || results[1].Version != before+2 {
		t.Fatalf("versions %d, %d after %d", results[0].Version, results[1].Version, before)
	}
	if results[0].Change.ID >= results[1].Change.ID {
		t.Errorf("cursor %d for version %d is not before %d for %d", results[0].Change.ID, results[0].Version, results[1].Change.ID, results[1].Version)
	}
	if currentVersion(t, s, publication.DatasetUSpaceAirspace) != before+2 {
		t.Error("current version")
	}
}

// D8: an identifier current in zones is refused in restrictions; a free
// one is accepted.
func TestCrossDatasetIdentifiersAreUnique(t *testing.T) {
	ctx := context.Background()
	s := testStore(t, Options{})
	zones, body := base(t, "X")
	if _, err := s.PublishTx(ctx, input(publication.DatasetZones, zones, body), NoopSigner{}); err != nil {
		t.Fatal(err)
	}
	taken := zones.Features[0].Properties.Identifier
	restr := &ed318.FeatureCollection{Type: "FeatureCollection", Features: []ed318.Feature{zones.Features[1]}}
	restr.Features[0].Properties.Identifier = taken
	rbody, _ := ed318.Export(restr)
	in := input(publication.DatasetRestrictions, restr, rbody)
	in.PublisherClientID = "ansp-01"
	before := currentVersion(t, s, publication.DatasetRestrictions)
	_, err := s.PublishTx(ctx, in, NoopSigner{})
	if sqlState(err) != "23505" || !strings.Contains(err.Error(), "features_current_cross_dataset_uq") {
		t.Fatalf("got %v, want the cross-dataset unique violation", err)
	}
	if currentVersion(t, s, publication.DatasetRestrictions) != before {
		t.Error("a refused publication moved the version")
	}
	restr.Features[0].Properties.Identifier = "R" + taken[1:]
	rbody, _ = ed318.Export(restr)
	in = input(publication.DatasetRestrictions, restr, rbody)
	if _, err := s.PublishTx(ctx, in, NoopSigner{}); err != nil {
		t.Fatalf("a free identifier refused: %v", err)
	}
}

// Z-11: a circle is stored as the published Point; its drawing buffer
// contains the centre and has the circle's area within 1 %.
func TestCircleGeometryIsADrawingBuffer(t *testing.T) {
	ctx := context.Background()
	s := testStore(t, Options{})
	fc, body := base(t, "G")
	if _, err := s.PublishTx(ctx, input(publication.DatasetZones, fc, body), NoopSigner{}); err != nil {
		t.Fatal(err)
	}
	circle := fc.Features[1] // TSD001: 1500 m around (44.8271, 41.7151)
	id := circle.Properties.Identifier
	var contains bool
	var areaM2 float64
	var featureType string
	if err := s.pool.QueryRow(ctx, `SELECT ST_Contains(geom, ST_SetSRID(ST_MakePoint($2, $3), 4326)),
	       ST_Area(geom::geography), feature->'geometry'->>'type'
	FROM features_current WHERE dataset = 'zones' AND feature_id = $1`, id, circle.Geometry.Center.LonDeg, circle.Geometry.Center.LatDeg).Scan(&contains, &areaM2, &featureType); err != nil {
		t.Fatal(err)
	}
	r := *circle.Geometry.RadiusM
	want := math.Pi * r * r
	if !contains {
		t.Error("the buffer does not contain the published centre")
	}
	if math.Abs(areaM2-want)/want > 0.01 {
		t.Errorf("buffer area %.0f m², pi r² %.0f m² (%.2f %%)", areaM2, want, 100*(areaM2-want)/want)
	}
	if featureType != "Point" {
		t.Errorf("the stored feature's geometry is %q; the circle must stay a Point with its radius", featureType)
	}
	// A point well outside the radius is outside (E-01 twin).
	var outside bool
	if err := s.pool.QueryRow(ctx, `SELECT ST_Contains(geom, ST_SetSRID(ST_MakePoint($2, $3), 4326)) FROM features_current WHERE dataset = 'zones' AND feature_id = $1`,
		id, circle.Geometry.Center.LonDeg, circle.Geometry.Center.LatDeg+0.02).Scan(&outside); err != nil || outside {
		t.Errorf("a point 2.2 km north is inside (%v)", err)
	}
	t.Logf("circle buffer area %.0f m², pi r² %.0f m²", areaM2, want)
}

// E-02: the cache serves after its pool is closed and reports since when
// it is stale; before that it is not stale.
func TestSnapshotCacheServesWhenTheDatabaseIsGone(t *testing.T) {
	ctx := context.Background()
	s := testStore(t, Options{})
	fc, body := base(t, "S")
	res, err := s.PublishTx(ctx, input(publication.DatasetZones, fc, body), NoopSigner{})
	if err != nil {
		t.Fatal(err)
	}
	own, err := OpenPool(ctx, PoolConfig{URL: mustEnv(t, "CISP_TEST_DATABASE_URL"), ApplicationName: "uspace-cisp-test-cache", MaxConns: 2})
	if err != nil {
		t.Fatal(err)
	}
	c := NewSnapshotCache(New(own, Options{}), CacheConfig{})
	got, err := c.Current(ctx, publication.DatasetZones)
	if err != nil || got.Version != res.Version {
		t.Fatalf("healthy: %+v %v", got, err)
	}
	if _, ok := c.Stale(); ok {
		t.Fatal("stale while the database answers")
	}
	own.Close()
	if err := c.Refresh(ctx); err == nil {
		t.Fatal("refresh succeeded on a closed pool")
	}
	since, ok := c.Stale()
	if !ok || since.IsZero() {
		t.Fatal("not stale after the pool closed")
	}
	again, err := c.Current(ctx, publication.DatasetZones)
	if err != nil || again.Version != res.Version || !bytes.Equal(again.BodyGz, got.BodyGz) {
		t.Fatalf("degraded: %+v %v", again, err)
	}
	t.Logf("stale since %s, still serving zones:%d", since.Format(time.RFC3339Nano), again.Version)
}

// The ussp_list dataset: the snapshot is the canonical list with the
// cis_* members (WP-3); the same list, also re-spaced, is unchanged;
// another is a version.
func TestPublishUSSPListByBody(t *testing.T) {
	ctx := context.Background()
	s := testStore(t, Options{})
	body := []byte(`{"schema":"cis/ussp_list/v1","issued":"2026-10-02T00:00:00Z","ussps":[],"n":"` + suffix(t) + `"}`)
	in := PublishInput{Dataset: publication.DatasetUSSPList, Body: body, ContentType: "application/json", PublisherClientID: "authority-01", Reason: publication.ReasonPublication}
	res, err := s.PublishTx(ctx, in, NoopSigner{})
	if err != nil {
		t.Fatal(err)
	}
	snap, _ := s.Snapshot(ctx, publication.DatasetUSSPList, res.Version)
	want, err := publication.UsspListSnapshot(res.Version, snap.BuiltAt, body)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := gunzip(snap.BodyGz)
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil || got["cis_version"] != float64(res.Version) || got["cis_dataset"] != "ussp_list" || got["n"] == nil {
		t.Errorf("the ussp_list snapshot %s is not the canonical list with cis_* members (%v)", raw, err)
	}
	if !bytes.Equal(raw, want) {
		t.Errorf("snapshot %s, want the canonical form %s", raw, want)
	}
	if pub, err := relational.New(s.pool).GetPublication(ctx, relational.GetPublicationParams{Dataset: string(publication.DatasetUSSPList), Version: res.Version}); err != nil || !bytes.Equal(pub.Body, body) {
		t.Errorf("the stored body is not the bytes received: %v", err)
	}
	if _, err := s.PublishTx(ctx, in, NoopSigner{}); !errors.Is(err, ErrUnchanged) {
		t.Errorf("same body: %v", err)
	}
	respaced := in
	respaced.Body = append([]byte(" \n"), body...)
	if _, err := s.PublishTx(ctx, respaced, NoopSigner{}); !errors.Is(err, ErrUnchanged) {
		t.Errorf("the same list re-spaced: %v", err)
	}
	in.Body = append(slices.Clone(body[:len(body)-1]), []byte(`,"m":1}`)...)
	if r2, err := s.PublishTx(ctx, in, NoopSigner{}); err != nil || r2.Version != res.Version+1 {
		t.Errorf("another body: %+v %v", r2, err)
	}
}

// rebuild-current: a lost features_current comes back from the body; an
// unchanged snapshot keeps its signature with no signer; a snapshot that
// must change needs one.
func TestRebuildCurrent(t *testing.T) {
	ctx := context.Background()
	s := testStore(t, Options{})
	fc, body := base(t, "B")
	res, err := s.PublishTx(ctx, input(publication.DatasetZones, fc, body), NoopSigner{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, "DELETE FROM features_current WHERE dataset = 'zones'"); err != nil {
		t.Fatal(err)
	}
	rep, err := s.RebuildCurrent(ctx, publication.DatasetZones, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Version != res.Version || rep.FeaturesBefore != 0 || rep.FeaturesAfter != 5 || rep.SnapshotRebuilt {
		t.Errorf("report %+v", rep)
	}
	if n := count(t, s.pool, "SELECT count(*) FROM features_current WHERE dataset = 'zones' AND version = $1", res.Version); n != 5 {
		t.Errorf("features_current %d rows", n)
	}

	if _, err := s.pool.Exec(ctx, "DELETE FROM snapshots WHERE dataset = 'zones' AND version = $1", res.Version); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RebuildCurrent(ctx, publication.DatasetZones, nil); !errors.Is(err, ErrNeedsSigner) {
		t.Fatalf("missing snapshot without a signer: %v", err)
	}
	rep, err = s.RebuildCurrent(ctx, publication.DatasetZones, NoopSigner{})
	if err != nil || !rep.SnapshotRebuilt {
		t.Fatalf("with a signer: %+v %v", rep, err)
	}
	if _, err := s.RebuildCurrent(ctx, publication.DatasetRestrictions, nil); err == nil {
		t.Error("restrictions rebuilt from one body")
	}
}

// The hypertable has its compression and retention policies; the
// retention is data that set-retention replaces.
func TestDeliveryAttemptsPolicies(t *testing.T) {
	ctx := context.Background()
	ts := migrated(t, TreeTimeseries)
	pol, err := Policies(ctx, ts)
	if err != nil {
		t.Fatal(err)
	}
	var compression, retention string
	for _, p := range pol {
		switch p.Proc {
		case "policy_compression":
			compression = p.Config
		case "policy_retention":
			retention = p.Config
		}
	}
	if !strings.Contains(compression, `"compress_after": "7 days"`) || !strings.Contains(retention, `"drop_after": "90 days"`) {
		t.Fatalf("policies %+v", pol)
	}
	var segment, order string
	if err := ts.QueryRow(ctx, `SELECT string_agg(attname, ',') FILTER (WHERE segmentby_column_index IS NOT NULL),
	       string_agg(attname || CASE WHEN orderby_asc THEN ' ASC' ELSE ' DESC' END, ',') FILTER (WHERE orderby_column_index IS NOT NULL)
	FROM timescaledb_information.compression_settings WHERE hypertable_name = 'delivery_attempts'`).Scan(&segment, &order); err != nil {
		t.Fatal(err)
	}
	if segment != "subscription_id" || order != "at DESC" {
		t.Errorf("compression settings segmentby %q orderby %q", segment, order)
	}
	var chunk string
	if err := ts.QueryRow(ctx, `SELECT time_interval::text FROM timescaledb_information.dimensions WHERE hypertable_name = 'delivery_attempts'`).Scan(&chunk); err != nil || chunk != "1 day" {
		t.Errorf("chunk interval %q (%v)", chunk, err)
	}

	if err := SetRetention(ctx, ts, 30); err != nil {
		t.Fatal(err)
	}
	pol, _ = Policies(ctx, ts)
	if !slices.ContainsFunc(pol, func(p Policy) bool { return p.Proc == "policy_retention" && strings.Contains(p.Config, `"30 days"`) }) {
		t.Errorf("after set-retention 30: %+v", pol)
	}
	if err := SetRetention(ctx, ts, DefaultDeliveryLogRetentionDays); err != nil {
		t.Fatal(err)
	}
	if err := SetRetention(ctx, ts, 0); err == nil {
		t.Error("0 days accepted")
	}

	// The log takes a row and gives it back.
	q := timeseries.New(ts)
	sub := "sub-" + suffix(t)
	code := int32(204)
	if err := q.InsertDeliveryAttempt(ctx, timeseries.InsertDeliveryAttemptParams{At: time.Now().UTC(), DeliveryID: "d1", SubscriptionID: sub, ChangeID: 1, Attempt: 1, StatusCode: &code, LatencyMs: 12, PayloadBytes: 300, DeliverInstance: "test"}); err != nil {
		t.Fatal(err)
	}
	got, err := q.ListDeliveryAttempts(ctx, timeseries.ListDeliveryAttemptsParams{SubscriptionID: sub, Before: time.Now().Add(time.Minute), MaxRows: 10})
	if err != nil || len(got) != 1 || *got[0].StatusCode != 204 {
		t.Errorf("delivery attempts %+v %v", got, err)
	}
}

// D6: with the broker the change is published and nothing is counted;
// without it the publication still commits and the failure is counted.
func TestPublishTxWithAndWithoutTheBroker(t *testing.T) {
	ctx := context.Background()
	up, err := bus.Connect(ctx, bus.Config{URL: mustEnv(t, "CISP_TEST_NATS_URL"), Name: "uspace-cisp-test"})
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	s := testStore(t, Options{Bus: up})
	fc, body := base(t, "N")
	res, err := s.PublishTx(ctx, input(publication.DatasetZones, fc, body), NoopSigner{})
	if err != nil {
		t.Fatal(err)
	}
	if s.Counters().Get("bus_publish_failed") != 0 {
		t.Fatalf("bus_publish_failed with the broker up: %d", s.Counters().Get("bus_publish_failed"))
	}
	// The broker stored it: a second publish of the same change is a duplicate.
	ack, err := up.PublishAck(ctx, res.Change)
	if err != nil || !ack.Duplicate {
		t.Errorf("re-publish of change %d: %+v %v", res.Change.ID, ack, err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := ln.Addr().String()
	_ = ln.Close()
	down, err := bus.Connect(ctx, bus.Config{URL: "nats://" + deadAddr, Name: "uspace-cisp-test", AckWait: 300 * time.Millisecond})
	if err != nil {
		t.Fatalf("connect with the broker down must return a handle: %v", err)
	}
	defer down.Close()
	s2 := New(s.pool, Options{Bus: down, AllowNoopSigner: true})
	fc2, body2 := base(t, "M")
	before := currentVersion(t, s2, publication.DatasetZones)
	res2, err := s2.PublishTx(ctx, input(publication.DatasetZones, fc2, body2), NoopSigner{})
	if err != nil || res2.Version != before+1 {
		t.Fatalf("publication with the broker down: %+v %v", res2, err)
	}
	if s2.Counters().Get("bus_publish_failed") != 1 {
		t.Errorf("bus_publish_failed = %d, want 1", s2.Counters().Get("bus_publish_failed"))
	}
	if n := count(t, s2.pool, "SELECT count(*) FROM changes WHERE id = $1", res2.Change.ID); n != 1 {
		t.Error("the change is not committed")
	}
}

var _ = pgx.ErrNoRows
