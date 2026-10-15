//go:build integration

package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/restriction"
)

// An outage is never an absence (E-02): with the database gone, every
// read and write of the store returns an error, and none of them reads
// as "no such row" (ErrNotFound, pgx.ErrNoRows), which a caller would
// act on: a missing watermark rescans from 0, a missing session reads
// as revoked, a missing restriction is created. The pools are real
// ones, closed; the same calls on the live pools answer first, so the
// closed pool is what fails below, not the calls.
func TestAnOutageIsNotAnAbsence(t *testing.T) {
	ctx := context.Background()
	live := New(migrated(t, TreeRelational), Options{AllowNoopSigner: true})
	liveLog := NewDeliveryLog(migrated(t, TreeTimeseries))
	closed := func(env string) *DeliveryLog {
		p, err := OpenPool(ctx, PoolConfig{URL: mustEnv(t, env), ApplicationName: "uspace-cisp-test"})
		if err != nil {
			t.Fatal(err)
		}
		p.Close()
		return NewDeliveryLog(p)
	}
	gone := New(closed("CISP_TEST_DATABASE_URL").pool, Options{AllowNoopSigner: true})
	goneLog := closed("CISP_TEST_TIMESERIES_URL")

	now := time.Now().UTC()
	ds := publication.DatasetZones
	e := Event{TS: now, ActorType: ActorSystem, ActorID: "it", EventType: "it", EntityType: "it", EntityID: "it"}
	r := 10.0
	circle := []publication.GeomPart{{Center: &core.LatLon{LatDeg: 41.7, LonDeg: 44.8}, RadiusM: &r}}
	v := int64(1)

	type call func(s *Store, l *DeliveryLog) error
	calls := map[string]call{
		"CurrentVersions": func(s *Store, _ *DeliveryLog) error { _, err := s.CurrentVersions(ctx); return err },
		"CurrentStates":   func(s *Store, _ *DeliveryLog) error { _, err := s.CurrentStates(ctx); return err },
		"CurrentVersion":  func(s *Store, _ *DeliveryLog) error { _, err := s.CurrentVersion(ctx, ds); return err },
		"Reserved":        func(s *Store, _ *DeliveryLog) error { _, err := s.Reserved(ctx, ds, []string{"A"}); return err },
		"RefusedAttempts": func(s *Store, _ *DeliveryLog) error { _, err := s.RefusedAttempts(ctx, ds, "p", now, 10); return err },
		"Versions":        func(s *Store, _ *DeliveryLog) error { _, err := s.Versions(ctx, ds, 0, 10); return err },
		"ReadCurrent":     func(s *Store, _ *DeliveryLog) error { _, err := s.ReadCurrent(ctx, ds, nil); return err },
		"Changes":         func(s *Store, _ *DeliveryLog) error { _, err := s.Changes(ctx, 0, nil, 10); return err },
		"Publishers":      func(s *Store, _ *DeliveryLog) error { _, err := s.Publishers(ctx); return err },
		"PublishersRefs":  func(s *Store, _ *DeliveryLog) error { _, err := s.PublishersRefs(ctx); return err },
		"DatabaseNow":     func(s *Store, _ *DeliveryLog) error { _, err := s.DatabaseNow(ctx); return err },
		"Accounts":        func(s *Store, _ *DeliveryLog) error { _, err := s.Accounts(ctx, 10); return err },
		"RevokedSessions": func(s *Store, _ *DeliveryLog) error { _, err := s.RevokedSessions(ctx, 10); return err },
		"TouchSession":    func(s *Store, _ *DeliveryLog) error { _, err := s.TouchSession(ctx, "j", time.Minute); return err },
		"AuditEvents":     func(s *Store, _ *DeliveryLog) error { _, err := s.AuditEvents(ctx, AuditFilter{Limit: 10}); return err },
		"FeatureChanges":  func(s *Store, _ *DeliveryLog) error { _, err := s.FeatureChanges(ctx, "p", "q", 10); return err },
		"AllSubscriptions": func(s *Store, _ *DeliveryLog) error {
			_, _, err := s.AllSubscriptions(ctx, SubscriptionFilter{Limit: 10})
			return err
		},
		"ClientSubscriptions": func(s *Store, _ *DeliveryLog) error { _, err := s.ClientSubscriptions(ctx, "c", 10); return err },
		"SubscriptionDeliveries": func(s *Store, _ *DeliveryLog) error {
			_, err := s.SubscriptionDeliveries(ctx, "s", now, 10)
			return err
		},
		"ReceivingSubscriptions": func(s *Store, _ *DeliveryLog) error { _, err := s.ReceivingSubscriptions(ctx); return err },
		"Watermark":              func(s *Store, _ *DeliveryLog) error { _, err := s.Watermark(ctx, "outage-it"); return err },
		"ScanChanges":            func(s *Store, _ *DeliveryLog) error { _, err := s.ScanChanges(ctx, 0, now, 10); return err },
		"ChangesByID":            func(s *Store, _ *DeliveryLog) error { _, err := s.ChangesByID(ctx, []int64{1}); return err },
		"DatasetVersions":        func(s *Store, _ *DeliveryLog) error { _, err := s.DatasetVersions(ctx); return err },
		"SuspendSubscription": func(s *Store, _ *DeliveryLog) error {
			_, err := s.SuspendSubscription(ctx, "outage-it", "r")
			return err
		},
		"DeliveryQueue": func(s *Store, _ *DeliveryLog) error { _, err := s.DeliveryQueue(ctx, now); return err },
		"Restrictions": func(s *Store, _ *DeliveryLog) error {
			_, err := s.Restrictions(ctx, RestrictionFilter{Limit: 10})
			return err
		},
		"ExpiredRestrictions":   func(s *Store, _ *DeliveryLog) error { _, err := s.ExpiredRestrictions(ctx, now, 10); return err },
		"ActiveRestrictionRefs": func(s *Store, _ *DeliveryLog) error { _, err := s.ActiveRestrictionRefs(ctx); return err },
		"CountActiveRestrictions": func(s *Store, _ *DeliveryLog) error {
			_, err := s.CountActiveRestrictions(ctx)
			return err
		},
		"RestrictionPlacement": func(s *Store, _ *DeliveryLog) error { _, err := s.RestrictionPlacement(ctx, "U", circle); return err },
		"AttemptsOf":           func(_ *Store, l *DeliveryLog) error { _, err := l.AttemptsOf(ctx, "s", []string{"d"}); return err },
		"ConsoleSummary":       func(s *Store, _ *DeliveryLog) error { _, err := s.ConsoleSummary(ctx, time.Hour); return err },
		"Latency":              func(_ *Store, l *DeliveryLog) error { _, err := l.Latency(ctx, time.Hour, 10); return err },
	}
	for name, c := range calls {
		if err := c(live, liveLog); err != nil {
			t.Errorf("%s on the live database: %v", name, err)
		}
	}

	// The calls that need a row (or write one) are only made with the
	// database gone: what they would answer live is the other tests'.
	writes := map[string]call{
		"Snapshot":  func(s *Store, _ *DeliveryLog) error { _, err := s.Snapshot(ctx, ds, 1); return err },
		"Publisher": func(s *Store, _ *DeliveryLog) error { _, err := s.Publisher(ctx, "p"); return err },
		"RecordHeartbeat": func(s *Store, _ *DeliveryLog) error {
			return s.RecordHeartbeat(ctx, Heartbeat{ClientID: "p", Kind: "ansp", ReceivedAt: now, SentAt: now})
		},
		"ReadDelta":      func(s *Store, _ *DeliveryLog) error { _, err := s.ReadDelta(ctx, ds, 1, 10); return err },
		"Publication":    func(s *Store, _ *DeliveryLog) error { _, err := s.Publication(ctx, ds, 1); return err },
		"Account":        func(s *Store, _ *DeliveryLog) error { _, err := s.Account(ctx, "a"); return err },
		"Session":        func(s *Store, _ *DeliveryLog) error { _, err := s.Session(ctx, "j"); return err },
		"SessionRevoked": func(s *Store, _ *DeliveryLog) error { _, err := s.SessionRevoked(ctx, "j"); return err },
		"EventsInRange": func(s *Store, _ *DeliveryLog) error {
			_, err := s.EventsInRange(ctx, now, now, func([]byte, AuditRow) error { return nil })
			return err
		},
		"PublicationByID": func(s *Store, _ *DeliveryLog) error { _, err := s.PublicationByID(ctx, "p"); return err },
		"PreviousPublication": func(s *Store, _ *DeliveryLog) error {
			_, err := s.PreviousPublication(ctx, PublicationHead{Dataset: ds, SupersedesVersion: &v})
			return err
		},
		"Subscription":           func(s *Store, _ *DeliveryLog) error { _, err := s.Subscription(ctx, "s"); return err },
		"LatestPing":             func(s *Store, _ *DeliveryLog) error { _, err := s.LatestPing(ctx, "s"); return err },
		"AdvanceWatermark":       func(s *Store, _ *DeliveryLog) error { return s.AdvanceWatermark(ctx, "w", 1, now) },
		"Restriction":            func(s *Store, _ *DeliveryLog) error { _, err := s.Restriction(ctx, "r", false); return err },
		"RestrictionByFeatureID": func(s *Store, _ *DeliveryLog) error { _, err := s.RestrictionByFeatureID(ctx, "F"); return err },
		"LastJobRun":             func(s *Store, _ *DeliveryLog) error { _, err := s.LastJobRun(ctx, "j"); return err },
		"RunJob": func(s *Store, _ *DeliveryLog) error {
			_, err := s.RunJob(ctx, "j", "i", func(context.Context, time.Time) (int, error) { return 0, nil })
			return err
		},
		"EnsureEventPartitions": func(s *Store, _ *DeliveryLog) error { _, err := s.EnsureEventPartitions(ctx, 1); return err },
		"InsertChangeDeliveries": func(s *Store, _ *DeliveryLog) error {
			_, err := s.InsertChangeDeliveries(ctx, 1, []string{"s"}, now)
			return err
		},
		"ClaimDeliveries": func(s *Store, _ *DeliveryLog) error { _, err := s.ClaimDeliveries(ctx, now, now, 1, 1); return err },
		"FinishDelivered": func(s *Store, _ *DeliveryLog) error { _, err := s.FinishDelivered(ctx, "d", "s", now, 200); return err },
		"FinishFailed": func(s *Store, _ *DeliveryLog) error {
			_, err := s.FinishFailed(ctx, FailedAttempt{DeliveryID: "d", SubscriptionID: "s", At: now})
			return err
		},
		"RequeueDelivery":    func(s *Store, _ *DeliveryLog) error { _, err := s.RequeueDelivery(ctx, "s", "d", now, e); return err },
		"DeleteSubscription": func(s *Store, _ *DeliveryLog) error { _, err := s.DeleteSubscription(ctx, "s", e); return err },
		"Republish":          func(s *Store, _ *DeliveryLog) error { _, err := s.Republish(ctx, "p", e); return err },
		"RevokeSession":      func(s *Store, _ *DeliveryLog) error { _, err := s.RevokeSession(ctx, "j", e); return err },
		"Record": func(_ *Store, l *DeliveryLog) error {
			return l.Record(ctx, DeliveryAttempt{At: now, DeliveryID: "d", SubscriptionID: "s"})
		},
		"ApplyRestriction": func(s *Store, _ *DeliveryLog) error {
			_, err := s.ApplyRestriction(ctx, RestrictionWrite{ID: "r", Body: []byte("{}"), ContentType: "application/json", PublisherClientID: "a",
				Decide: func(*restriction.Head, []StoredFeature) (RestrictionDecision, error) {
					return RestrictionDecision{}, nil
				}}, NoopSigner{})
			return err
		},
	}
	for name, c := range writes {
		calls[name] = c
	}
	for name, c := range calls {
		err := c(gone, goneLog)
		switch {
		case err == nil:
			t.Errorf("%s: no error with the database gone", name)
		case errors.Is(err, ErrNotFound), errors.Is(err, pgx.ErrNoRows):
			t.Errorf("%s: the outage read as an absence: %v", name, err)
		}
	}
}
