//go:build integration

// Integration tests of the restrictions (WP-5) on PostgreSQL + PostGIS
// and NATS: the lifecycle with its versions, change records and replays
// read back from the tables, the placement measured by PostGIS, the
// expiry with its leader lock and job run, the staleness and the
// heartbeat references from the publishers table, and the latency from
// the commit to a subscriber of the bus.
package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/rootxkit/uspace-cisp/internal/bus"
	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/restriction"
	"github.com/rootxkit/uspace-cisp/internal/store"
	"github.com/rootxkit/uspace-cisp/internal/store/relational"
)

// darID is a fresh DAR + 4 base-36 identifier: the ANSP's scheme, and
// unique across runs on the shared database (restrictions.feature_id
// names one restriction for ever).
func darID(t *testing.T) string {
	t.Helper()
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := []byte("DAR")
	for range 4 {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			t.Fatal(err)
		}
		b = append(b, alphabet[n.Int64()])
	}
	return string(b)
}

func anspRefOf(name string) string {
	return name + "-" + time.Now().UTC().Format("20060102T150405.000000000")
}

// pgRestrictions is the harness on PostgreSQL with TSU001 current.
func pgRestrictions(t *testing.T) (*pubHarness, *store.Store, time.Time) {
	t.Helper()
	st, _ := pgStore(t)
	h := newPubHarness(t, st)
	h.publishAirspace()
	t0 := time.Now().UTC().Truncate(time.Second)
	h.at(t0)
	return h, st, t0
}

// datasetVersion is datasets.current_version of restrictions, read from
// the table.
func datasetVersion(t *testing.T, st *store.Store) int64 {
	t.Helper()
	d, err := relational.New(st.Pool()).GetDataset(context.Background(), string(publication.DatasetRestrictions))
	if err != nil {
		t.Fatal(err)
	}
	return d.CurrentVersion
}

// changeAt is the change record of a version, read from the feed.
func changeAt(t *testing.T, st *store.Store, version int64) publication.Change {
	t.Helper()
	ds := publication.DatasetRestrictions
	cs, err := st.Changes(context.Background(), 0, &ds, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	for i := range cs {
		if cs[i].Version == version {
			return cs[i]
		}
	}
	t.Fatalf("no change of version %d", version)
	return publication.Change{}
}

// The lifecycle on PostgreSQL: create planned, activate, extend, end;
// each op one version with its reason in changes; every replay (with and
// without an Idempotency-Key, and with a different one) 200 and no new
// datasets.current_version; the feature served with cis_restriction by
// the WP-4 read; the ended restriction out of the current set and in
// /versions/{v}; at= inside and outside the window.
func TestRestrictionLifecycleOnPostgres(t *testing.T) {
	h, st, t0 := pgRestrictions(t)
	ref, fid := anspRefOf("NOTAM-PG"), darID(t)
	starts, ends := t0.Add(5*time.Minute), t0.Add(time.Hour)
	create := createDoc(ref, 1, "planned", fid, starts, ends)
	newEnd := ends.Add(30 * time.Minute)
	ops := []struct {
		body   doc
		reason publication.Reason
		state  restriction.State
	}{
		{create, publication.ReasonRestrictionCreated, restriction.StatePlanned},
		{doc{"op": "activate", "ansp_version": 2}, publication.ReasonRestrictionActivated, restriction.StateActive},
		{doc{"op": "extend", "ansp_version": 3, "ends_at": newEnd.Format(time.RFC3339), "feature": darDoc(fid, starts, newEnd)}, publication.ReasonRestrictionExtended, restriction.StateActive},
		{doc{"op": "end", "ansp_version": 4}, publication.ReasonRestrictionEnded, restriction.StateEnded},
	}
	var id string
	var versions []int64
	for i, op := range ops {
		before := datasetVersion(t, st)
		send := func(edit ...func(*http.Request)) *httptest.ResponseRecorder {
			if i == 0 {
				return h.postRestriction(op.body, edit...)
			}
			return h.patchRestriction(id, op.body, edit...)
		}
		rec := send()
		if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
			t.Fatalf("op %d = %d %s", i, rec.Code, rec.Body.String())
		}
		res := decodeRestriction(t, rec)
		id = res.Restriction.Id
		if res.Replay || res.Version != before+1 || datasetVersion(t, st) != before+1 || string(res.Restriction.State) != string(op.state) {
			t.Fatalf("op %d: %+v, current_version %d", i, res, datasetVersion(t, st))
		}
		if c := changeAt(t, st, res.Version); c.Reason != op.reason || !strings.Contains(strings.Join(c.FeatureIDs, ","), fid) {
			t.Errorf("op %d change %+v", i, c)
		}
		versions = append(versions, res.Version)
		// The replays: no new version, whatever the header says.
		for _, key := range []string{"", "k-a", "k-b"} {
			edit := func(*http.Request) {}
			if key != "" {
				edit = withKey(key)
			}
			again := send(edit)
			r := decodeRestriction(t, again)
			if again.Code != http.StatusOK || !r.Replay || r.Version != res.Version || datasetVersion(t, st) != res.Version {
				t.Fatalf("op %d replay %q = %d %+v", i, key, again.Code, r)
			}
		}
		if i == 2 {
			// An extend that renames the feature is a conflict.
			renamed := darDoc(fid, starts, newEnd.Add(time.Minute))
			renamed["properties"].(doc)["name"] = []any{doc{"lang": "en-GB", "text": "Renamed"}}
			c := h.patchRestriction(id, doc{"op": "extend", "ansp_version": 9, "ends_at": newEnd.Add(time.Minute).Format(time.RFC3339), "feature": renamed})
			if c.Code != http.StatusConflict || datasetVersion(t, st) != res.Version {
				t.Fatalf("renamed extend = %d %s", c.Code, c.Body.String())
			}
		}
		// The same version with another body is 409, never a replay.
		other := doc{"op": "cancel", "ansp_version": op.body["ansp_version"]}
		if conflict := h.patchRestriction(id, other); conflict.Code != http.StatusConflict || datasetVersion(t, st) != res.Version {
			t.Fatalf("op %d with another body = %d %s", i, conflict.Code, conflict.Body.String())
		}
		if i == 1 {
			_, served := h.servedRestrictions("")
			if m := served[fid]; m.State != restriction.StateActive || m.ID != id || m.AnspVersion != 2 {
				t.Errorf("served while active: %+v", m)
			}
			_, in := collection(t, h.read(http.MethodGet, "/v1/restrictions?at="+url.QueryEscape(starts.Add(time.Minute).Format(time.RFC3339))))
			_, out := collection(t, h.read(http.MethodGet, "/v1/restrictions?at="+url.QueryEscape(newEnd.Add(time.Minute).Format(time.RFC3339))))
			if _, ok := in[fid]; !ok {
				t.Errorf("at inside the window: %v", ids(in))
			}
			if _, ok := out[fid]; ok {
				t.Errorf("at outside the window: %v", ids(out))
			}
		}
	}
	if _, served := h.servedRestrictions(""); served[fid].ID != "" {
		t.Error("the ended restriction is still current")
	}
	extended := h.read(http.MethodGet, "/v1/restrictions/versions/"+i64toa(versions[2]))
	if extended.Code != http.StatusOK || !strings.Contains(extended.Body.String(), newEnd.Format(time.RFC3339)) {
		t.Errorf("version %d = %d %s", versions[2], extended.Code, extended.Body.String())
	}
	head, err := st.Restriction(context.Background(), id, false)
	if err != nil || len(head.Events) != 4 || head.EndedBy == nil || *head.EndedBy != restriction.EndedByANSP || !head.EndsAt.Equal(newEnd) {
		t.Fatalf("head %+v %v", head, err)
	}
	for i, e := range head.Events {
		if e.PublicationID == nil || e.AnspVersion != int64(i+1) {
			t.Errorf("event %d %+v", i, e)
		}
	}
	// restriction_events is insert-only (migration 0008).
	_, err = st.Pool().Exec(context.Background(), "UPDATE restriction_events SET actor = 'x' WHERE restriction_id = $1", id)
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("restriction_events updated: %v", err)
	}
	t.Logf("restrictions on PostgreSQL: %s versions %v", fid, versions)
}

// PostGIS measures the placement: outside the airspace, an unknown
// airspace and over 10 000 km2 are refused beside the accepted DAR + 4
// identifier; an 8-character identifier is refused by the parse.
func TestRestrictionPlacementOnPostgres(t *testing.T) {
	h, _, t0 := pgRestrictions(t)
	starts, ends := t0, t0.Add(time.Hour)
	poly := func(minLon, minLat, maxLon, maxLat float64) []any {
		return []any{[]any{[]any{minLon, minLat}, []any{maxLon, minLat}, []any{maxLon, maxLat}, []any{minLon, maxLat}, []any{minLon, minLat}}}
	}
	cases := []struct {
		name   string
		edit   func(d doc)
		field  string
		phrase string
	}{
		{"inside TSU001", func(doc) {}, "", ""},
		{"outside TSU001", func(d doc) { d["feature"].(doc)["geometry"].(doc)["coordinates"] = poly(46.0, 42.0, 46.1, 42.1) }, "uspace_airspace_id", "entirely outside"},
		{"an unknown airspace", func(d doc) { d["uspace_airspace_id"] = "TSU9" }, "uspace_airspace_id", "not a feature of the current uspace_airspace"},
		// About 1.5 x 0.9 degrees at 41.7 N: about 15 000 km2, overlapping TSU001.
		{"over 10 000 km2", func(d doc) { d["feature"].(doc)["geometry"].(doc)["coordinates"] = poly(44.0, 41.0, 45.5, 41.9) }, "feature.geometry", "CstrMaxAreaKm2"},
		{"just under 10 000 km2", func(d doc) { d["feature"].(doc)["geometry"].(doc)["coordinates"] = poly(44.0, 41.0, 45.0, 41.85) }, "", ""},
		{"a circle reaching into TSU001", func(d doc) {
			d["feature"].(doc)["geometry"] = doc{"type": "Point", "coordinates": []any{44.69, 41.70}, "extent": doc{"subType": "Circle", "radius": 2000},
				"layer": doc{"lower": 0, "lowerReference": "AGL", "upper": 120, "upperReference": "AGL", "uom": "m"}}
		}, "", ""},
		{"an 8-character identifier", func(d doc) { d["feature"].(doc)["properties"].(doc)["identifier"] = "DAR1A2BC" }, "feature.properties.identifier", ""},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := createDoc(anspRefOf("NOTAM-PL")+"-"+i64toa(int64(i)), 1, "active", darID(t), starts, ends)
			c.edit(d)
			if c.field == "" {
				rec := h.postRestriction(d)
				if rec.Code != http.StatusCreated {
					t.Fatalf("= %d %s", rec.Code, rec.Body.String())
				}
				id := decodeRestriction(t, rec).Restriction.Id
				if end := h.patchRestriction(id, doc{"op": "end", "ansp_version": 2}); end.Code != http.StatusOK {
					t.Fatalf("end = %d", end.Code)
				}
				return
			}
			rec := h.postRestrictionRaw(d)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("= %d %s", rec.Code, rec.Body.String())
			}
			p := decodeProblem(t, rec)
			found := false
			for _, e := range *p.Errors {
				found = found || (strings.HasPrefix(e.Field, c.field) && strings.Contains(e.Reason, c.phrase))
			}
			if !found {
				t.Errorf("problems %+v", *p.Errors)
			}
		})
	}
}

// The expiry on PostgreSQL, judged on the database's clock (E-01 both
// ways): with this process's clock an hour late, an active restriction
// whose ends_at the database has passed is ended by the next tick
// (ended_by expiry, a restriction_expired version, job_runs at the
// database's now()); with the process clock two hours early, one whose
// ends_at the database has not reached stays active. A second replica
// asking for the lock while the first holds it skips the run.
func TestRestrictionExpiryOnPostgres(t *testing.T) {
	ctx := context.Background()
	h, st, _ := pgRestrictions(t)
	dbNow := func() time.Time {
		t.Helper()
		var now time.Time
		if err := st.Pool().QueryRow(ctx, "SELECT now()").Scan(&now); err != nil {
			t.Fatal(err)
		}
		return now.UTC().Truncate(time.Second)
	}
	db := dbNow()
	late := db.Add(-time.Hour)

	// Created while the process clock is an hour late, it ended 10 s ago
	// on the database's clock.
	h.processAt(late)
	gone := darID(t)
	rec := h.postRestriction(createDoc(anspRefOf("NOTAM-EXP"), 1, "active", gone, late, db.Add(-10*time.Second)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", rec.Code, rec.Body.String())
	}
	goneID := decodeRestriction(t, rec).Restriction.Id
	// One that ends in an hour, while the process clock runs two hours
	// early.
	h.processAt(db)
	stays := darID(t)
	rec = h.postRestriction(createDoc(anspRefOf("NOTAM-STAY"), 1, "active", stays, db, db.Add(time.Hour)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", rec.Code, rec.Body.String())
	}
	staysID := decodeRestriction(t, rec).Restriction.Id

	before := datasetVersion(t, st)
	h.processAt(late)
	n, ran, err := h.rs.ExpireTick(ctx)
	if err != nil || !ran || n < 1 {
		t.Fatalf("tick with a late process clock: %d %v %v", n, ran, err)
	}
	head, err := st.Restriction(ctx, goneID, false)
	if err != nil || head.State != restriction.StateEnded || head.EndedBy == nil || *head.EndedBy != restriction.EndedByExpiry {
		t.Fatalf("head %+v %v", head.Head, err)
	}
	last := head.Events[len(head.Events)-1]
	if last.Op != restriction.OpExpire || last.Actor != store.SystemActor || last.PublicationID == nil {
		t.Errorf("event %+v", last)
	}
	pub, err := relational.New(st.Pool()).GetPublication(ctx, relational.GetPublicationParams{Dataset: "restrictions", Version: datasetVersion(t, st)})
	if err != nil || pub.Reason != string(publication.ReasonRestrictionExpired) || pub.PublisherSignature != nil || pub.PublisherClientID != store.SystemPublisher {
		t.Errorf("expiry publication %+v %v", pub.Reason, err)
	}
	if datasetVersion(t, st) < before+1 {
		t.Errorf("no version: %d", datasetVersion(t, st))
	}
	run, err := st.LastJobRun(ctx, JobRestrictionExpiry)
	if err != nil || run.RanAt.Sub(db).Abs() > time.Minute || run.Age > time.Minute || run.Instance != "test/1" || run.Count < 1 {
		t.Errorf("job run %+v %v (database now %v, process clock %v)", run, err, db, late)
	}

	h.processAt(db.Add(2 * time.Hour))
	if _, _, err := h.rs.ExpireTick(ctx); err != nil {
		t.Fatal(err)
	}
	if head, _ := st.Restriction(ctx, staysID, false); head.State != restriction.StateActive {
		t.Errorf("an early process clock ended a restriction before its ends_at: %s", head.State)
	}
	if end := h.patchRestriction(staysID, doc{"op": "end", "ansp_version": 2}); end.Code != http.StatusOK {
		t.Fatalf("end = %d", end.Code)
	}

	// The leader lock: a second replica inside the first's run skips.
	ran, err = st.RunJob(ctx, "wp5_lock_test", "a", func(ctx context.Context, _ time.Time) (int, error) {
		inner, err := st.RunJob(ctx, "wp5_lock_test", "b", func(context.Context, time.Time) (int, error) { return 0, nil })
		if err != nil || inner {
			t.Errorf("the second replica ran: %v %v", inner, err)
		}
		return 0, nil
	})
	if err != nil || !ran {
		t.Errorf("the first replica: %v %v", ran, err)
	}
	t.Logf("expired %s on PostgreSQL by the database's clock (process clock an hour late): %d this tick, job run %+v", gone, n, run)
}

// Staleness and the heartbeat references from the publishers table:
// never heard is stale; a heartbeat clears it; 61 s later it is stale
// with since; the declared refs disagreeing with the active heads show in
// the status; no version is made.
func TestRestrictionStalenessOnPostgres(t *testing.T) {
	h, st, t0 := pgRestrictions(t)
	ref := anspRefOf("NOTAM-ST")
	if rec := h.postRestriction(createDoc(ref, 1, "active", darID(t), t0, t0.Add(time.Hour))); rec.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", rec.Code, rec.Body.String())
	}
	v := datasetVersion(t, st)
	h.pubs.Now = func() time.Time { return t0 }
	body := `{"sent_at":"` + t0.Format(time.RFC3339) + `","active_refs":["` + ref + `","NOTAM-GHOST"]}`
	if _, rec := h.heartbeat(h.anspToken(), body, func(r *http.Request) { r.Header.Set("X-Client-Cert-Subject", anspSubject) }); rec.Code != http.StatusNoContent {
		t.Fatalf("heartbeat = %d %s", rec.Code, rec.Body.String())
	}
	if stale, _, err := h.rs.ANSPStale(context.Background()); err != nil || stale {
		t.Errorf("just heard: %v %v", stale, err)
	}
	h.at(t0.Add(61 * time.Second))
	stale, since, err := h.rs.ANSPStale(context.Background())
	if err != nil || !stale || since == nil || !since.Equal(t0.Add(60*time.Second)) {
		t.Errorf("61 s: %v %v %v", stale, since, err)
	}
	status := h.read(http.MethodGet, "/v1/status")
	var s struct {
		Restrictions restrictionStatusJSON `json:"restrictions"`
	}
	if err := json.Unmarshal(status.Body.Bytes(), &s); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(s.Restrictions.Unknown, ","), "NOTAM-GHOST") || s.Restrictions.StaleSince == nil {
		t.Errorf("status %s", status.Body.String())
	}
	if datasetVersion(t, st) != v {
		t.Error("staleness made a version")
	}
}

type restrictionStatusJSON struct {
	Active     int64      `json:"active"`
	StaleSince *time.Time `json:"ansp_stale_since"`
	Unknown    []string   `json:"heartbeat_ref_unknown"`
	Missing    []string   `json:"heartbeat_ref_missing"`
}

// The CIS side of C5: an active restriction POSTed, its change received
// by a subscriber of the bus; the receipt time minus changes.at is
// printed and held under 2 s (the 1 s target is reported as measured,
// not asserted on a shared runner; E-04). The webhook leg is deliver's
// (WP-6) and is measured by its e2e test.
func TestRestrictionLatencyToBus(t *testing.T) {
	natsURL := os.Getenv("CISP_TEST_NATS_URL")
	if natsURL == "" {
		t.Fatal("CISP_TEST_NATS_URL is not set; run make dev-deps")
	}
	ctx := context.Background()
	b, err := bus.Connect(ctx, bus.Config{URL: natsURL, Name: "uspace-cisp-test-wp5", PublicBaseURL: "https://cisp.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	deadline := time.Now().Add(5 * time.Second)
	for !b.Conn().IsConnected() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if err := b.EnsureStream(ctx); err != nil {
		t.Fatal(err)
	}
	received := make(chan *nats.Msg, 16)
	sub, err := b.Conn().ChanSubscribe(bus.SubjectPrefix+string(publication.DatasetRestrictions), received)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })

	_, pool := pgStore(t)
	st := store.New(pool, store.Options{Bus: b})
	h := newPubHarness(t, st)
	h.publishAirspace()
	t0 := time.Now().UTC().Truncate(time.Second)
	h.at(t0)
	rec := h.postRestriction(createDoc(anspRefOf("NOTAM-LAT"), 1, "active", darID(t), t0, t0.Add(time.Hour)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", rec.Code, rec.Body.String())
	}
	version := decodeRestriction(t, rec).Version
	for {
		select {
		case m := <-received:
			at := time.Now().UTC()
			var c bus.ChangeMessage
			if err := json.Unmarshal(m.Data, &c); err != nil {
				t.Fatal(err)
			}
			if c.Version != version {
				continue
			}
			latency := at.Sub(c.At)
			t.Logf("restriction change on the bus: version %d reason %s, receipt minus changes.at = %v", c.Version, c.Reason, latency)
			if c.Reason != string(publication.ReasonRestrictionActivated) || latency >= 2*time.Second {
				t.Errorf("reason %s latency %v", c.Reason, latency)
			}
			return
		case <-time.After(5 * time.Second):
			t.Fatal("no change on the bus within 5 s")
		}
	}
}
