//go:build integration

package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"math"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed318"

	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/restriction"
)

// The restriction heads on PostgreSQL (WP-5) at the store's boundary:
// each lifecycle op writes the head, its event and one version of the
// restrictions dataset together or not at all; a replay writes nothing;
// the reads by id, ansp_ref, identifier and filter; the expiry's
// candidates and the leader-elected job run.

// storedFeatures parses the current features Decide is handed.
func storedFeatures(t *testing.T, current []StoredFeature) []ed318.Feature {
	t.Helper()
	if len(current) == 0 {
		return nil
	}
	var b bytes.Buffer
	b.WriteString(`{"type":"FeatureCollection","features":[`)
	for i, f := range current {
		if i > 0 {
			b.WriteByte(',')
		}
		b.Write(f.Feature)
	}
	b.WriteString(`]}`)
	fc, probs := ed318.Parse(b.Bytes(), ed318.Limits{})
	if probs != nil {
		t.Fatalf("stored restrictions do not parse: %v", probs)
	}
	return fc.Features
}

func TestRestrictionHeadsOnPostgres(t *testing.T) {
	ctx := context.Background()
	s := testStore(t, Options{})
	fc, _ := base(t, "R")
	feature := fc.Features[0]
	fid := feature.Properties.Identifier
	ref := "NOTAM-ST-" + suffix(t) + suffix(t)
	t0 := time.Now().UTC().Truncate(time.Second)
	starts, ends := t0.Add(-time.Minute), t0.Add(time.Hour)
	id := NewID(t0)

	type opResult struct {
		res RestrictionResult
		err error
	}
	apply := func(w RestrictionWrite) opResult {
		t.Helper()
		if w.Body == nil {
			w.Body = []byte(`{"op":"` + suffix(t) + `"}`)
		}
		if w.ContentType == "" {
			w.ContentType = "application/json"
		}
		if w.PublisherClientID == "" {
			w.PublisherClientID = "ansp-01"
		}
		w.ReceivedAt = t0
		res, err := s.ApplyRestriction(ctx, w, NoopSigner{})
		return opResult{res, err}
	}
	decideWith := func(op restriction.Op, reason publication.Reason, next func(h *restriction.Head) restriction.Head, published *ed318.Feature) func(*restriction.Head, []StoredFeature) (RestrictionDecision, error) {
		return func(h *restriction.Head, current []StoredFeature) (RestrictionDecision, error) {
			n := next(h)
			set, err := restriction.CurrentSet(storedFeatures(t, current), n, published)
			if err != nil {
				return RestrictionDecision{}, err
			}
			return RestrictionDecision{Head: n, Op: op, Reason: reason, Collection: set}, nil
		}
	}
	events := func() int64 {
		return count(t, s.pool, `SELECT count(*) FROM restriction_events WHERE restriction_id = $1`, id)
	}

	// Create, planned.
	var sawNil bool
	before := currentVersion(t, s, publication.DatasetRestrictions)
	created := apply(RestrictionWrite{AnspRef: ref, Decide: decideWith(restriction.OpCreate, publication.ReasonRestrictionCreated, func(h *restriction.Head) restriction.Head {
		sawNil = h == nil
		return restriction.Head{ID: id, AnspRef: ref, AnspVersion: 1, UspaceAirspaceID: "TSU001", FeatureID: fid,
			State: restriction.StatePlanned, StartsAt: starts, EndsAt: ends, BodySHA256: sha256.Sum256([]byte("create"))}
	}, &feature)})
	if created.err != nil {
		t.Fatal(created.err)
	}
	if !sawNil {
		t.Error("a create's Decide was handed a stored head")
	}
	if r := created.res; r.Replay || r.Version != before+1 || r.PublicationID == "" || r.Reason != publication.ReasonRestrictionCreated ||
		r.Change.Reason != publication.ReasonRestrictionCreated || !slices.Contains(r.Change.FeatureIDs, fid) || r.ETag != publication.ETag(publication.DatasetRestrictions, r.Version) {
		t.Fatalf("create %+v", r)
	}

	// The reads: by id, by ansp_ref, by identifier; none by each.
	rec, err := s.Restriction(ctx, id, false)
	if err != nil || rec.State != restriction.StatePlanned || rec.AnspRef != ref || len(rec.Events) != 1 || rec.Events[0].Op != restriction.OpCreate ||
		rec.Events[0].Actor != "ansp-01" || rec.Events[0].PublicationID == nil || *rec.Events[0].PublicationID != created.res.PublicationID ||
		rec.LastPublisherClientID != "ansp-01" || !rec.StartsAt.Equal(starts) || !rec.EndsAt.Equal(ends) || rec.BodySHA256 != sha256.Sum256([]byte("create")) {
		t.Fatalf("by id %+v %v", rec, err)
	}
	if rec, err := s.Restriction(ctx, ref, true); err != nil || rec.ID != id || len(rec.Events) != 1 {
		t.Errorf("by ansp_ref %+v %v", rec, err)
	}
	if rec, err := s.RestrictionByFeatureID(ctx, fid); err != nil || rec.ID != id {
		t.Errorf("by identifier %+v %v", rec, err)
	}
	if _, err := s.Restriction(ctx, "01NOSUCHRESTRICTION000000", false); !errors.Is(err, ErrNotFound) {
		t.Errorf("no id: %v", err)
	}
	if _, err := s.Restriction(ctx, ref+"-none", true); !errors.Is(err, ErrNotFound) {
		t.Errorf("no ansp_ref: %v", err)
	}
	if _, err := s.RestrictionByFeatureID(ctx, "ZZ"+suffix(t)); !errors.Is(err, ErrNotFound) {
		t.Errorf("no identifier: %v", err)
	}

	// Activate, addressed by ansp_ref, through the lifecycle's rule.
	activated := apply(RestrictionWrite{AnspRef: ref, Decide: decideWith(restriction.OpActivate, publication.ReasonRestrictionActivated, func(h *restriction.Head) restriction.Head {
		if h == nil || h.ID != id {
			t.Fatalf("activate handed %+v", h)
		}
		n, reason, err := restriction.Transition(*h, restriction.Request{Op: restriction.OpActivate, AnspVersion: 2, BodySHA256: sha256.Sum256([]byte("activate")), Now: t0})
		if err != nil || reason != publication.ReasonRestrictionActivated {
			t.Fatalf("transition %v %v", reason, err)
		}
		return n
	}, nil)})
	if activated.err != nil || activated.res.Version != before+2 || activated.res.Head.State != restriction.StateActive {
		t.Fatalf("activate %+v %v", activated.res, activated.err)
	}

	// A replay: Decide names no reason; nothing is written and the
	// current version comes back.
	n := events()
	replay := apply(RestrictionWrite{ID: id, Decide: func(h *restriction.Head, _ []StoredFeature) (RestrictionDecision, error) {
		return RestrictionDecision{Head: *h}, nil
	}})
	if replay.err != nil || !replay.res.Replay || replay.res.Version != before+2 || replay.res.Head.AnspVersion != 2 ||
		replay.res.ETag != publication.ETag(publication.DatasetRestrictions, before+2) {
		t.Errorf("replay %+v %v", replay.res, replay.err)
	}
	if v := currentVersion(t, s, publication.DatasetRestrictions); v != before+2 || events() != n {
		t.Errorf("a replay wrote: version %d, events %d -> %d", v, n, events())
	}

	// Refusals, each writing nothing: Decide's own error as it is, no
	// Decide, no name, and an op that leaves the dataset as it is (a
	// fault: the head it wrote is rolled back with the version).
	sentinel := errors.New("the request conflicts")
	if r := apply(RestrictionWrite{ID: id, Decide: func(*restriction.Head, []StoredFeature) (RestrictionDecision, error) {
		return RestrictionDecision{}, sentinel
	}}); !errors.Is(r.err, sentinel) {
		t.Errorf("Decide's error: %v", r.err)
	}
	if r := apply(RestrictionWrite{ID: id}); r.err == nil {
		t.Error("no Decide was accepted")
	}
	var fe *core.FieldError
	if r := apply(RestrictionWrite{Decide: func(*restriction.Head, []StoredFeature) (RestrictionDecision, error) {
		t.Error("Decide ran for a write that names no restriction")
		return RestrictionDecision{}, nil
	}}); !errors.As(r.err, &fe) {
		t.Errorf("no id and no ansp_ref: %v", r.err)
	}
	unchanged := apply(RestrictionWrite{ID: id, Decide: func(h *restriction.Head, current []StoredFeature) (RestrictionDecision, error) {
		next := *h
		next.AnspVersion = 9
		return RestrictionDecision{Head: next, Op: restriction.OpActivate, Reason: publication.ReasonRestrictionActivated,
			Collection: &ed318.FeatureCollection{Type: "FeatureCollection", Features: storedFeatures(t, current)}}, nil
	}})
	if !errors.Is(unchanged.err, ErrUnchanged) {
		t.Errorf("an op that changes nothing: %v", unchanged.err)
	}
	if rec, _ := s.Restriction(ctx, id, false); rec.AnspVersion != 2 || len(rec.Events) != 2 {
		t.Errorf("the refused writes left ansp_version %d, %d events", rec.AnspVersion, len(rec.Events))
	}
	if v := currentVersion(t, s, publication.DatasetRestrictions); v != before+2 {
		t.Errorf("the refused writes moved the version to %d", v)
	}

	// The filters, each beside the one that leaves the head out.
	active, ended, airspace, other := restriction.StateActive, restriction.StateEnded, "TSU001", "TSU-NONE"
	inside, afterEnd := t0, ends.Add(time.Second)
	has := func(f RestrictionFilter) bool {
		t.Helper()
		f.Limit = 1 << 16
		list, err := s.Restrictions(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range list {
			if r.ID == id {
				if len(r.Events) != 2 {
					t.Errorf("listed with %d events", len(r.Events))
				}
				return true
			}
		}
		return false
	}
	for _, c := range []struct {
		name string
		f    RestrictionFilter
		want bool
	}{
		{"active", RestrictionFilter{State: &active}, true},
		{"ended", RestrictionFilter{State: &ended}, false},
		{"its airspace", RestrictionFilter{Airspace: &airspace}, true},
		{"another airspace", RestrictionFilter{Airspace: &other}, false},
		{"inside its window", RestrictionFilter{At: &inside}, true},
		{"after its window", RestrictionFilter{At: &afterEnd}, false},
	} {
		if got := has(c.f); got != c.want {
			t.Errorf("%s: listed %v, want %v", c.name, got, c.want)
		}
	}
	if empty, err := s.Restrictions(ctx, RestrictionFilter{Airspace: &other, Limit: 10}); err != nil || len(empty) != 0 {
		t.Errorf("no head: %+v %v", empty, err)
	}
	refs, err := s.ActiveRestrictionRefs(ctx)
	if err != nil || !slices.Contains(refs, ref) || !slices.IsSorted(refs) {
		t.Errorf("active refs %v %v", refs, err)
	}
	if nActive, err := s.CountActiveRestrictions(ctx); err != nil || nActive != int64(len(refs)) {
		t.Errorf("active count %d, refs %d (%v)", nActive, len(refs), err)
	}

	// The expiry's candidates: past ends_at only.
	if ids, _ := s.ExpiredRestrictions(ctx, ends.Add(-time.Second), 1<<16); slices.Contains(ids, id) {
		t.Error("a candidate before its ends_at")
	}
	ids, err := s.ExpiredRestrictions(ctx, ends, 1<<16)
	if err != nil || !slices.Contains(ids, id) {
		t.Fatalf("not a candidate at its ends_at: %v %v", ids, err)
	}

	// The expiry, as the CISP: actor system, the head out of the set.
	expired := apply(RestrictionWrite{ID: id, PublisherClientID: SystemPublisher, Actor: SystemActor,
		Decide: decideWith(restriction.OpExpire, publication.ReasonRestrictionExpired, func(h *restriction.Head) restriction.Head {
			n, ok := restriction.Expire(*h, ends)
			if !ok {
				t.Fatalf("Expire refused %+v", h)
			}
			return n
		}, nil)})
	if expired.err != nil || expired.res.Head.State != restriction.StateEnded || slices.Contains(expired.res.Change.RemovedIDs, fid) == false {
		t.Fatalf("expire %+v %v", expired.res, expired.err)
	}
	rec, _ = s.Restriction(ctx, id, false)
	if last := rec.Events[len(rec.Events)-1]; last.Op != restriction.OpExpire || last.Actor != SystemActor || rec.EndedBy == nil || *rec.EndedBy != restriction.EndedByExpiry {
		t.Errorf("expired head %+v, last event %+v", rec.Head, last)
	}
	if n := count(t, s.pool, `SELECT count(*) FROM events WHERE actor_type = 'system' AND actor_id = $1 AND entity_id = $2`, SystemActor, expired.res.PublicationID); n != 1 {
		t.Errorf("the expiry's audit row as the system: %d", n)
	}
	if ids, _ := s.ExpiredRestrictions(ctx, ends.Add(time.Hour), 1<<16); slices.Contains(ids, id) {
		t.Error("an ended head is still a candidate")
	}
	if refs, _ := s.ActiveRestrictionRefs(ctx); slices.Contains(refs, ref) {
		t.Error("an ended head is still active")
	}

	// The identifier names one restriction for ever: a second head with
	// it is refused by the backstop, and nothing of it is written.
	second := NewID(t0.Add(time.Second))
	taken := apply(RestrictionWrite{AnspRef: ref + "-2", Decide: decideWith(restriction.OpCreate, publication.ReasonRestrictionCreated, func(*restriction.Head) restriction.Head {
		return restriction.Head{ID: second, AnspRef: ref + "-2", AnspVersion: 1, UspaceAirspaceID: "TSU001", FeatureID: fid,
			State: restriction.StatePlanned, StartsAt: starts, EndsAt: ends}
	}, &feature)})
	if !IsRestrictionIdentifierTaken(taken.err) {
		t.Errorf("a second head with %s: %v", fid, taken.err)
	}
	if IsRestrictionIdentifierTaken(sentinel) || IsRestrictionIdentifierTaken(ErrUnchanged) {
		t.Error("another error read as the identifier backstop")
	}
	if _, err := s.Restriction(ctx, second, false); !errors.Is(err, ErrNotFound) {
		t.Errorf("the refused head was written: %v", err)
	}
}

// The placement of an outline (WP-5, measured by PostGIS on geography):
// over the current U-space airspace it names, a circle's area, an
// airspace that is not current, and an outline with no part.
func TestRestrictionPlacementOnPostgres(t *testing.T) {
	ctx := context.Background()
	s := testStore(t, Options{})
	fc, body := base(t, "U")
	if _, err := s.PublishTx(ctx, input(publication.DatasetUSpaceAirspace, fc, body), NoopSigner{}); err != nil {
		t.Fatal(err)
	}
	rows, err := publication.Rows(fc)
	if err != nil {
		t.Fatal(err)
	}
	var polygon []publication.GeomPart
	for _, r := range rows {
		for _, g := range r.Geom {
			if !g.Circle() && polygon == nil {
				polygon = []publication.GeomPart{g}
			}
		}
	}
	if polygon == nil {
		t.Fatal("the vector collection has no polygon part")
	}
	airspace := rows[0].ID
	for _, r := range rows {
		if slices.ContainsFunc(r.Geom, func(g publication.GeomPart) bool { return !g.Circle() }) {
			airspace = r.ID
			break
		}
	}
	p, err := s.RestrictionPlacement(ctx, airspace, polygon)
	if err != nil || !p.AirspaceCurrent || !p.Intersects || p.AreaM2 <= 0 {
		t.Errorf("its own outline over %s: %+v %v", airspace, p, err)
	}
	if p, err := s.RestrictionPlacement(ctx, "NOSUCH", polygon); err != nil || p.AirspaceCurrent || p.Intersects || p.AreaM2 <= 0 {
		t.Errorf("over an airspace that is not current: %+v %v", p, err)
	}
	// A circle far from any airspace: its area is the buffer's, within
	// the drawing's 1 %, and it intersects nothing.
	r := 1000.0
	far := publication.GeomPart{Center: &core.LatLon{LatDeg: -60, LonDeg: -150}, RadiusM: &r}
	p, err = s.RestrictionPlacement(ctx, airspace, []publication.GeomPart{far})
	if want := math.Pi * r * r; err != nil || !p.AirspaceCurrent || p.Intersects || math.Abs(p.AreaM2-want)/want > 0.01 {
		t.Errorf("a circle: %+v %v, want an area of %.0f m2", p, err, want)
	}
	var fe *core.FieldError
	if _, err := s.RestrictionPlacement(ctx, airspace, nil); !errors.As(err, &fe) || !strings.Contains(err.Error(), "no part") {
		t.Errorf("no part: %v", err)
	}
}

// The publishers' declared active references (the ANSP's heartbeat, the
// staleness check reads them): a list, none declared (nil), and an empty
// list, which is a declaration that nothing is active (not nil).
func TestPublishersRefsOnPostgres(t *testing.T) {
	ctx := context.Background()
	s := testStore(t, Options{})
	id := "ansp-refs-" + suffix(t)
	recv := time.Now().UTC().Truncate(time.Microsecond)
	refsOf := func() (PublisherRefs, bool) {
		t.Helper()
		all, err := s.PublishersRefs(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range all {
			if p.ClientID == id {
				return p, true
			}
		}
		return PublisherRefs{}, false
	}
	if _, ok := refsOf(); ok {
		t.Fatal("a publisher before its first heartbeat")
	}
	for _, c := range []struct {
		name string
		refs []string
		want []string
	}{
		{"two refs", []string{"R-1", "R-2"}, []string{"R-1", "R-2"}},
		{"none declared", nil, nil},
		{"an empty list", []string{}, []string{}},
	} {
		recv = recv.Add(time.Second)
		if err := s.RecordHeartbeat(ctx, Heartbeat{ClientID: id, Kind: "ansp", ReceivedAt: recv, SentAt: recv, ActiveRefs: c.refs}); err != nil {
			t.Fatal(err)
		}
		p, ok := refsOf()
		if !ok || p.Kind != "ansp" || p.LastHeartbeatAt == nil || !p.LastHeartbeatAt.Equal(recv) || p.StaleAfterS <= 0 ||
			(p.ActiveRefs == nil) != (c.want == nil) || !slices.Equal(p.ActiveRefs, c.want) {
			t.Errorf("%s: %+v", c.name, p)
		}
	}
}

// The leader-elected job: one replica runs it with the database's clock
// and records the run; a second replica, while the first holds the lock,
// skips; fn's error records nothing; before the first run there is none.
func TestRunJobOnPostgres(t *testing.T) {
	ctx := context.Background()
	s := testStore(t, Options{})
	name := "st-job-" + strings.ToLower(suffix(t))
	if _, err := s.LastJobRun(ctx, name); !errors.Is(err, ErrNotFound) {
		t.Fatalf("before the first run: %v", err)
	}
	failed := errors.New("the job failed")
	if ran, err := s.RunJob(ctx, name, "replica-a", func(context.Context, time.Time) (int, error) { return 0, failed }); ran || !errors.Is(err, failed) {
		t.Errorf("a failing run: %v %v", ran, err)
	}
	if _, err := s.LastJobRun(ctx, name); !errors.Is(err, ErrNotFound) {
		t.Errorf("a failing run was recorded: %v", err)
	}

	inside := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	var clock time.Time
	go func() {
		_, err := s.RunJob(ctx, name, "replica-a", func(_ context.Context, now time.Time) (int, error) {
			clock = now
			close(inside)
			<-release
			return 7, nil
		})
		done <- err
	}()
	<-inside
	other := New(s.pool, Options{AllowNoopSigner: true})
	ran, err := other.RunJob(ctx, name, "replica-b", func(context.Context, time.Time) (int, error) {
		t.Error("the second replica ran the job while the first held it")
		return 0, nil
	})
	if err != nil || ran {
		t.Errorf("the second replica: ran %v, %v", ran, err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	run, err := s.LastJobRun(ctx, name)
	if err != nil || run.Instance != "replica-a" || run.Count != 7 || run.Age < 0 || run.Age > time.Minute || clock.IsZero() || clock.Location() != time.UTC {
		t.Errorf("the recorded run %+v (clock %v) %v", run, clock, err)
	}
	if ran, err := other.RunJob(ctx, name, "replica-b", func(context.Context, time.Time) (int, error) { return 1, nil }); err != nil || !ran {
		t.Errorf("the second replica once the lock is free: %v %v", ran, err)
	}
	if run, _ := s.LastJobRun(ctx, name); run.Instance != "replica-b" || run.Count != 1 {
		t.Errorf("the second run %+v", run)
	}
}
