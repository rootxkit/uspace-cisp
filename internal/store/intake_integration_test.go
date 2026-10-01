//go:build integration

package store

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/ed318"

	"github.com/rootxkit/uspace-cisp/internal/publication"
)

// If-Match under the lock: the expected version publishes, any other is
// ErrVersionMismatch with the current version and writes nothing.
func TestPublishTxExpectedVersion(t *testing.T) {
	ctx := context.Background()
	s := testStore(t, Options{})
	fc, body := base(t, "E")
	current := currentVersion(t, s, publication.DatasetZones)
	stale := current - 1
	in := input(publication.DatasetZones, fc, body)
	in.ExpectedVersion = &stale
	res, err := s.PublishTx(ctx, in, NoopSigner{})
	if !errors.Is(err, ErrVersionMismatch) || res.Version != current || res.ETag != publication.ETag(publication.DatasetZones, current) {
		t.Fatalf("stale: %+v %v", res, err)
	}
	if currentVersion(t, s, publication.DatasetZones) != current {
		t.Fatal("a mismatched publication moved the version")
	}
	in.ExpectedVersion = &current
	if res, err := s.PublishTx(ctx, in, NoopSigner{}); err != nil || res.Version != current+1 {
		t.Fatalf("current: %+v %v", res, err)
	}
	if got, err := s.CurrentVersion(ctx, publication.DatasetZones); err != nil || got != current+1 {
		t.Errorf("CurrentVersion = %d %v", got, err)
	}
	if _, err := s.CurrentVersion(ctx, "nothing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("an unknown dataset: %v", err)
	}
}

// D8 lookup: an identifier current in zones is reserved for the other
// datasets and not for zones itself; and the backstop is recognised.
func TestReservedAndTheIdentifierBackstop(t *testing.T) {
	ctx := context.Background()
	s := testStore(t, Options{})
	fc, body := base(t, "V")
	if _, err := s.PublishTx(ctx, input(publication.DatasetZones, fc, body), NoopSigner{}); err != nil {
		t.Fatal(err)
	}
	taken := fc.Features[2].Properties.Identifier
	free := "F" + taken[1:]
	got, err := s.Reserved(ctx, publication.DatasetUSpaceAirspace, []string{taken, free})
	if err != nil || !reflect.DeepEqual(got, map[string]publication.Dataset{taken: publication.DatasetZones}) {
		t.Fatalf("Reserved = %v %v", got, err)
	}
	if got, err := s.Reserved(ctx, publication.DatasetZones, []string{taken}); err != nil || len(got) != 0 {
		t.Errorf("own dataset reserved: %v %v", got, err)
	}
	if got, err := s.Reserved(ctx, publication.DatasetZones, nil); err != nil || len(got) != 0 {
		t.Errorf("no ids: %v %v", got, err)
	}
	// The backstop: bypass the lookup and the unique index refuses.
	clash := &ed318.FeatureCollection{Type: "FeatureCollection", Features: []ed318.Feature{fc.Features[2]}}
	cbody, _ := ed318.Export(clash)
	_, err = s.PublishTx(ctx, input(publication.DatasetUSpaceAirspace, clash, cbody), NoopSigner{})
	if !IsIdentifierConflict(err) {
		t.Fatalf("got %v, want the D8 conflict", err)
	}
}

// Attempts: refused ones are read back by their publisher with their
// problems and truncated count, after since; accepted ones and other
// publishers' are not.
func TestAttemptsReadBack(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	s := testStore(t, Options{Now: func() time.Time { return now }})
	me := "authority-" + suffix(t)
	pubID := "01JPUBLICATION0000000000" + suffix(t)[:2]
	rows := []Attempt{
		{Dataset: publication.DatasetZones, PublisherClientID: me, ReceivedAt: now.Add(-2 * time.Minute), Outcome: OutcomeRefused,
			Problems: []AttemptProblem{{Field: "features[0].properties.type", Reason: "USPACE: ..."}}, Truncated: 3, Bytes: 10, BodySHA256: make([]byte, 32)},
		{Dataset: publication.DatasetZones, PublisherClientID: me, ReceivedAt: now.Add(-time.Minute), Outcome: OutcomeRefused, Bytes: 5},
		{Dataset: publication.DatasetZones, PublisherClientID: me, ReceivedAt: now, Outcome: OutcomeAccepted, PublicationID: &pubID, Bytes: 7},
		{Dataset: publication.DatasetZones, PublisherClientID: "other-" + suffix(t), ReceivedAt: now, Outcome: OutcomeRefused, Bytes: 1},
		{Dataset: publication.DatasetUSSPList, PublisherClientID: me, ReceivedAt: now, Outcome: OutcomeRefused, Bytes: 1},
	}
	for _, a := range rows {
		if id, err := s.InsertAttempt(ctx, a); err != nil || len(id) != 26 {
			t.Fatalf("insert: %q %v", id, err)
		}
	}
	got, err := s.RefusedAttempts(ctx, publication.DatasetZones, me, time.Time{}, 10)
	if err != nil || len(got) != 2 {
		t.Fatalf("attempts %+v %v", got, err)
	}
	if got[0].Bytes != 5 || got[1].Truncated != 3 || got[1].Problems[0].Field != "features[0].properties.type" || len(got[1].BodySHA256) != 32 {
		t.Errorf("read back %+v", got)
	}
	if got[0].Problems == nil || len(got[0].Problems) != 0 {
		t.Errorf("a refusal without problems reads back as %v", got[0].Problems)
	}
	since, err := s.RefusedAttempts(ctx, publication.DatasetZones, me, now.Add(-90*time.Second), 10)
	if err != nil || len(since) != 1 || since[0].Bytes != 5 {
		t.Errorf("since: %+v %v", since, err)
	}
	if one, _ := s.RefusedAttempts(ctx, publication.DatasetZones, me, time.Time{}, 1); len(one) != 1 {
		t.Errorf("limit 1: %d", len(one))
	}
	// A zero ReceivedAt is the store's clock.
	if _, err := s.InsertAttempt(ctx, Attempt{Dataset: publication.DatasetUSpaceAirspace, PublisherClientID: me, Outcome: OutcomeRefused}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.RefusedAttempts(ctx, publication.DatasetUSpaceAirspace, me, now.Add(-time.Second), 5); len(got) != 1 || !got[0].ReceivedAt.Equal(now) {
		t.Errorf("clock: %+v", got)
	}
}

// The history: newest first, warnings and body size read back, before
// pages.
func TestVersionsReadBack(t *testing.T) {
	ctx := context.Background()
	s := testStore(t, Options{})
	fc, body := base(t, "H")
	in := input(publication.DatasetZones, fc, body)
	in.Warnings = json.RawMessage(`[{"field":"features[1].properties.limitedApplicability[0]","reason":"open"}]`)
	res, err := s.PublishTx(ctx, in, NoopSigner{})
	if err != nil {
		t.Fatal(err)
	}
	vs, err := s.Versions(ctx, publication.DatasetZones, 0, 2)
	if err != nil || len(vs) == 0 {
		t.Fatalf("versions %v %v", vs, err)
	}
	v := vs[0]
	if v.Version != res.Version || v.Bytes != int64(len(body)) || v.FeatureCount != len(fc.Features) || v.Reason != publication.ReasonPublication {
		t.Errorf("version %+v", v)
	}
	var ws []map[string]string
	if err := json.Unmarshal(v.Warnings, &ws); err != nil || len(ws) != 1 || ws[0]["reason"] != "open" {
		t.Errorf("warnings %s %v", v.Warnings, err)
	}
	if v.SignatureKID == nil || *v.SignatureKID != "authority-2026" || v.ContentType != "application/json" {
		t.Errorf("signature kid %v content type %s", v.SignatureKID, v.ContentType)
	}
	below, err := s.Versions(ctx, publication.DatasetZones, res.Version, 5)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range below {
		if b.Version >= res.Version {
			t.Errorf("before %d returned %d", res.Version, b.Version)
		}
	}
}

// The heartbeat: with and without active_refs, read back; the second
// replaces the first.
func TestHeartbeatReadBack(t *testing.T) {
	ctx := context.Background()
	s := testStore(t, Options{})
	id := "ansp-" + suffix(t)
	if _, err := s.Publisher(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("before any heartbeat: %v", err)
	}
	recv := time.Date(2026, 10, 2, 10, 0, 15, 0, time.UTC)
	sent := recv.Add(-200 * time.Millisecond)
	if err := s.RecordHeartbeat(ctx, Heartbeat{ClientID: id, Kind: "ansp", ReceivedAt: recv, SentAt: sent, ActiveRefs: []string{"R-1", "R-2"}}); err != nil {
		t.Fatal(err)
	}
	p, err := s.Publisher(ctx, id)
	if err != nil || p.Kind != "ansp" || !p.LastHeartbeatAt.Equal(recv) || !p.LastHeartbeatSentAt.Equal(sent) || !reflect.DeepEqual(p.ActiveRefs, []string{"R-1", "R-2"}) || p.StaleAfterS != 60 {
		t.Fatalf("read back %+v %v", p, err)
	}
	if err := s.RecordHeartbeat(ctx, Heartbeat{ClientID: id, Kind: "ansp", ReceivedAt: recv.Add(15 * time.Second), SentAt: sent.Add(15 * time.Second)}); err != nil {
		t.Fatal(err)
	}
	p, err = s.Publisher(ctx, id)
	if err != nil || p.ActiveRefs != nil || !p.LastHeartbeatAt.Equal(recv.Add(15*time.Second)) {
		t.Errorf("second heartbeat %+v %v", p, err)
	}
	if err := s.RecordHeartbeat(ctx, Heartbeat{ClientID: id, Kind: "ansp", ReceivedAt: recv, SentAt: sent, ActiveRefs: []string{}}); err != nil {
		t.Fatal(err)
	}
	if p, _ := s.Publisher(ctx, id); p.ActiveRefs == nil || len(p.ActiveRefs) != 0 {
		t.Errorf("an empty list read back as %v", p.ActiveRefs)
	}
}
