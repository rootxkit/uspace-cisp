//go:build integration

package store

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rootxkit/uspace-core/geodesy"

	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/subscription"
)

// The subscriptions and the delivery queue on PostgreSQL (WP-6, WP-7,
// WP-8): what the api writes for a subscription, what deliver claims and
// finishes as cisp_deliver, and the console's audited actions, each
// refusal beside the acceptance that differs in one thing (E-01).

// resetSubscriptions deletes (a status, never a row) every subscription
// an earlier test or run left receiving: the queue is then this test's.
func resetSubscriptions(t *testing.T, s *Store) {
	t.Helper()
	if _, err := s.pool.Exec(context.Background(), `UPDATE subscriptions SET status = 'deleted' WHERE status <> 'deleted'`); err != nil {
		t.Fatal(err)
	}
}

// onDatabase is url with its database name replaced.
func onDatabase(url, from, to string) string {
	return strings.Replace(url, "/"+from+"?", "/"+to+"?", 1)
}

// deliverPool is the relational database as cisp_deliver: the role, and
// so the grants, deliver runs with.
func deliverPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := onDatabase(mustEnv(t, "CISP_TEST_TIMESERIES_URL"), "cisp_ts", "cisp")
	p, err := OpenPool(context.Background(), PoolConfig{URL: url, ApplicationName: "uspace-cisp-test", MaxConns: 4})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

// subscribe creates a pending subscription of client with its ping, as
// the api does, created at.
func subscribe(t *testing.T, s *Store, client string, at time.Time, box *geodesy.BBox, ds ...publication.Dataset) (SubscriptionRecord, string) {
	t.Helper()
	if len(ds) == 0 {
		ds = []publication.Dataset{publication.DatasetZones}
	}
	rec := SubscriptionRecord{
		Subscription: subscription.Subscription{ID: NewID(at), ClientID: client, CallbackURL: "https://ussp.example.test/hook/" + suffix(t),
			Datasets: ds, BBox: box, Status: subscription.PendingVerification},
		CreatedAt: at,
	}
	ping := NewID(at)
	err := s.CreateSubscription(context.Background(), NewSubscription{Record: rec, PingID: ping, MaxPerClient: 100, Event: subEvent(client, "subscription_created", rec.ID, at)})
	if err != nil {
		t.Fatal(err)
	}
	return rec, ping
}

func subEvent(actor, typ, id string, at time.Time) Event {
	return Event{TS: at, ActorType: ActorClient, ActorID: actor, EventType: typ, EntityType: "subscription", EntityID: id}
}

func setStatus(t *testing.T, s *Store, id string, st subscription.Status) {
	t.Helper()
	if _, err := s.pool.Exec(context.Background(), `UPDATE subscriptions SET status = $2 WHERE id = $1`, id, string(st)); err != nil {
		t.Fatal(err)
	}
}

// The api's side: the per-client limit counted under the client's lock
// (deleted ones not counted), the record read back with and without a
// box, the PATCH with and without a new ping, the soft delete expiring
// the open deliveries (and saying how many in its audit row), the
// deliveries by time, and the requeue refused for an unknown delivery,
// another subscription's, and one in flight.
func TestSubscriptionsOnPostgres(t *testing.T) {
	ctx := context.Background()
	s := testStore(t, Options{})
	resetSubscriptions(t, s)
	client := "ussp-st-" + strings.ToLower(suffix(t))
	t0 := time.Now().UTC().Add(-10 * time.Minute).Truncate(time.Microsecond)
	box := &geodesy.BBox{MinLon: 44.7, MinLat: 41.6, MaxLon: 44.9, MaxLat: 41.8}

	newSub := func(at time.Time, b *geodesy.BBox, limit int) (SubscriptionRecord, string, error) {
		rec := SubscriptionRecord{
			Subscription: subscription.Subscription{ID: NewID(at), ClientID: client, CallbackURL: "https://ussp.example.test/hook",
				Datasets: []publication.Dataset{publication.DatasetZones, publication.DatasetRestrictions}, BBox: b, Status: subscription.PendingVerification},
			CreatedAt: at,
		}
		ping := NewID(at)
		return rec, ping, s.CreateSubscription(ctx, NewSubscription{Record: rec, PingID: ping, MaxPerClient: limit, Event: subEvent(client, "subscription_created", rec.ID, at)})
	}
	a, pingA, err := newSub(t0, box, 2)
	if err != nil {
		t.Fatal(err)
	}
	b, pingB, err := newSub(t0.Add(time.Second), nil, 2)
	if err != nil {
		t.Fatal(err)
	}
	c, _, err := newSub(t0.Add(2*time.Second), nil, 2)
	if !errors.Is(err, ErrSubscriptionLimit) {
		t.Fatalf("a third subscription at a limit of 2: %v", err)
	}
	if n := count(t, s.pool, `SELECT count(*) FROM subscriptions WHERE id = $1`, c.ID); n != 0 {
		t.Errorf("the refused subscription was written (%d)", n)
	}
	if n := count(t, s.pool, `SELECT count(*) FROM events WHERE entity_id = $1`, c.ID); n != 0 {
		t.Errorf("the refused subscription was audited (%d)", n)
	}

	got, err := s.Subscription(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.BBox == nil || *got.BBox != *box || got.Status != subscription.PendingVerification || !slices.Equal(got.Datasets, a.Datasets) ||
		got.ClientID != client || !got.CreatedAt.Equal(t0) || got.VerifiedAt != nil || got.ConsecutiveFailures != 0 {
		t.Errorf("subscription a %+v", got)
	}
	if got, err := s.Subscription(ctx, b.ID); err != nil || got.BBox != nil {
		t.Errorf("subscription b without a box: %+v %v", got.BBox, err)
	}
	if _, err := s.Subscription(ctx, "01NOSUCHSUBSCRIPTION00000"); !errors.Is(err, ErrNotFound) {
		t.Errorf("no subscription: %v", err)
	}
	list, err := s.ClientSubscriptions(ctx, client, 10)
	if err != nil || len(list) != 2 || list[0].ID != a.ID || list[1].ID != b.ID {
		t.Fatalf("client subscriptions %+v %v", list, err)
	}
	if list, _ := s.ClientSubscriptions(ctx, client, 1); len(list) != 1 {
		t.Errorf("limit 1: %d", len(list))
	}

	ping, err := s.LatestPing(ctx, a.ID)
	if err != nil || ping.ID != pingA || ping.State != DeliveryQueued || ping.Reason != publication.ReasonSubscriptionTest || ping.ChangeID != nil {
		t.Errorf("ping of a %+v %v", ping, err)
	}
	if _, err := s.LatestPing(ctx, "01NOSUCHSUBSCRIPTION00000"); !errors.Is(err, ErrNotFound) {
		t.Errorf("no ping: %v", err)
	}

	// PATCH: a new callback with a new ping, the box dropped; b without
	// one keeps its ping.
	upd := a
	upd.CallbackURL, upd.BBox = "https://ussp.example.test/hook/v2", nil
	ping2 := NewID(t0.Add(time.Minute))
	if err := s.UpdateSubscription(ctx, SubscriptionUpdate{Record: upd, PingID: ping2, Event: subEvent(client, "subscription_updated", a.ID, t0.Add(time.Minute))}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Subscription(ctx, a.ID); got.CallbackURL != upd.CallbackURL || got.BBox != nil {
		t.Errorf("patched a %+v", got)
	}
	if p, _ := s.LatestPing(ctx, a.ID); p.ID != ping2 {
		t.Errorf("a's latest ping %s, want the new %s", p.ID, ping2)
	}
	updB := b
	updB.Datasets = []publication.Dataset{publication.DatasetUSSPList}
	if err := s.UpdateSubscription(ctx, SubscriptionUpdate{Record: updB, Event: subEvent(client, "subscription_updated", b.ID, t0.Add(time.Minute))}); err != nil {
		t.Fatal(err)
	}
	if p, _ := s.LatestPing(ctx, b.ID); p.ID != pingB {
		t.Errorf("b's latest ping %s, want its first %s", p.ID, pingB)
	}

	ds, err := s.SubscriptionDeliveries(ctx, a.ID, t0, 10)
	if err != nil || len(ds) != 2 || ds[0].ID != ping2 || ds[1].ID != pingA {
		t.Errorf("a's deliveries newest first %+v %v", ds, err)
	}
	if ds, _ := s.SubscriptionDeliveries(ctx, a.ID, t0.Add(30*time.Second), 10); len(ds) != 1 || ds[0].ID != ping2 {
		t.Errorf("a's deliveries since the PATCH %+v", ds)
	}

	// Requeue: the presence, then each refusal, none audited.
	if _, err := s.pool.Exec(ctx, `UPDATE deliveries SET state = 'failed', next_retry_at = $2 WHERE id = $1`, pingA, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	now := t0.Add(2 * time.Minute)
	rq, err := s.RequeueDelivery(ctx, a.ID, pingA, now, subEvent(client, "delivery_retry", pingA, now))
	if err != nil || rq.State != DeliveryQueued || rq.NextRetryAt == nil || !rq.NextRetryAt.Equal(now) {
		t.Errorf("requeue %+v %v", rq, err)
	}
	events := count(t, s.pool, `SELECT count(*) FROM events WHERE event_type = 'delivery_retry' AND actor_id = $1`, client)
	if events != 1 {
		t.Errorf("requeue audit rows %d", events)
	}
	if _, err := s.RequeueDelivery(ctx, a.ID, "01NOSUCHDELIVERY000000000", now, subEvent(client, "delivery_retry", "x", now)); !errors.Is(err, ErrNotFound) {
		t.Errorf("no delivery: %v", err)
	}
	if _, err := s.RequeueDelivery(ctx, b.ID, pingA, now, subEvent(client, "delivery_retry", pingA, now)); !errors.Is(err, ErrNotFound) {
		t.Errorf("another subscription's delivery: %v", err)
	}
	if _, err := s.pool.Exec(ctx, `UPDATE deliveries SET state = 'delivering' WHERE id = $1`, pingA); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RequeueDelivery(ctx, a.ID, pingA, now, subEvent(client, "delivery_retry", pingA, now)); !errors.Is(err, ErrDeliveryInFlight) {
		t.Errorf("a delivery in flight: %v", err)
	}
	if n := count(t, s.pool, `SELECT count(*) FROM events WHERE event_type = 'delivery_retry' AND actor_id = $1`, client); n != events {
		t.Errorf("a refused requeue was audited (%d)", n-events)
	}

	// The soft delete: b's open ping expires (a state), the row stays,
	// and the limit has room again.
	expired, err := s.DeleteSubscription(ctx, b.ID, subEvent(client, "subscription_deleted", b.ID, now))
	if err != nil || expired != 1 {
		t.Fatalf("delete b: %d expired, %v", expired, err)
	}
	if got, _ := s.Subscription(ctx, b.ID); got.Status != subscription.Deleted {
		t.Errorf("deleted b is %s", got.Status)
	}
	if p, _ := s.LatestPing(ctx, b.ID); p.State != DeliveryExpired {
		t.Errorf("b's ping is %s, want expired", p.State)
	}
	if n := count(t, s.pool, `SELECT count(*) FROM events WHERE entity_id = $1 AND event_type = 'subscription_deleted' AND payload->>'deliveries_expired' = '1'`, b.ID); n != 1 {
		t.Errorf("the delete's audit row with deliveries_expired: %d", n)
	}
	if list, _ := s.ClientSubscriptions(ctx, client, 10); len(list) != 1 || list[0].ID != a.ID {
		t.Errorf("after the delete %+v", list)
	}
	if _, _, err := newSub(t0.Add(3*time.Second), nil, 2); err != nil {
		t.Errorf("a second subscription once b is deleted: %v", err)
	}
}

// The console's view and actions: every subscription with its delivery
// counts per state, the status filter (deleted ones only when asked),
// suspend and resume with their audit rows, each refused on the wrong
// status, a deleted subscription and none.
func TestConsoleSubscriptionsOnPostgres(t *testing.T) {
	ctx := context.Background()
	s := testStore(t, Options{})
	resetSubscriptions(t, s)
	client := "ussp-cs-" + strings.ToLower(suffix(t))
	t0 := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	a, pingA := subscribe(t, s, client, t0, nil)
	gone, _ := subscribe(t, s, client, t0.Add(time.Second), nil)
	if _, err := s.DeleteSubscription(ctx, gone.ID, subEvent(client, "subscription_deleted", gone.ID, t0)); err != nil {
		t.Fatal(err)
	}

	subs, sums, err := s.AllSubscriptions(ctx, SubscriptionFilter{Limit: 100})
	if err != nil || len(subs) != 1 || subs[0].ID != a.ID || sums[a.ID][DeliveryQueued] != 1 {
		t.Fatalf("receiving subscriptions %+v %v %v", subs, sums, err)
	}
	if subs, sums, _ := s.AllSubscriptions(ctx, SubscriptionFilter{IncludeDeleted: true, AfterID: a.ID, Limit: 100}); len(subs) == 0 ||
		!slices.ContainsFunc(subs, func(r SubscriptionRecord) bool { return r.ID == gone.ID }) || sums[gone.ID][DeliveryExpired] != 1 {
		t.Errorf("with the deleted ones after a %+v %v", subs, sums)
	}
	suspended := string(subscription.Suspended)
	if subs, sums, err := s.AllSubscriptions(ctx, SubscriptionFilter{Status: &suspended, Limit: 100}); err != nil || len(subs) != 0 || len(sums) != 0 {
		t.Errorf("suspended before any suspension %+v %v", subs, err)
	}

	console := func(typ, id string) Event {
		return Event{TS: time.Now().UTC(), ActorType: ActorAccount, ActorID: "acc-" + client, EventType: typ, EntityType: "subscription", EntityID: id}
	}
	audited := func() int64 {
		return count(t, s.pool, `SELECT count(*) FROM events WHERE actor_id = $1`, "acc-"+client)
	}
	if err := s.ResumeSubscriptionAudited(ctx, a.ID, NewID(t0), console("console_resume", a.ID)); !errors.Is(err, ErrSubscriptionState) {
		t.Errorf("resume a pending subscription: %v", err)
	}
	if err := s.SuspendSubscriptionAudited(ctx, a.ID, "the operator asked", console("console_suspend", a.ID)); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Subscription(ctx, a.ID); got.Status != subscription.Suspended || got.SuspendedReason == nil || *got.SuspendedReason != "the operator asked" {
		t.Errorf("suspended a %+v", got)
	}
	if subs, _, _ := s.AllSubscriptions(ctx, SubscriptionFilter{Status: &suspended, Limit: 100}); len(subs) != 1 || subs[0].ID != a.ID {
		t.Errorf("suspended filter %+v", subs)
	}
	if err := s.SuspendSubscriptionAudited(ctx, a.ID, "again", console("console_suspend", a.ID)); !errors.Is(err, ErrSubscriptionState) {
		t.Errorf("suspend a suspended subscription: %v", err)
	}
	ping := NewID(time.Now())
	if err := s.ResumeSubscriptionAudited(ctx, a.ID, ping, console("console_resume", a.ID)); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Subscription(ctx, a.ID); got.Status != subscription.PendingVerification {
		t.Errorf("resumed a is %s", got.Status)
	}
	if p, _ := s.LatestPing(ctx, a.ID); p.ID != ping || p.ID == pingA {
		t.Errorf("resume's ping %s, want %s", p.ID, ping)
	}
	if n := audited(); n != 2 {
		t.Errorf("audit rows %d, want the suspend and the resume", n)
	}
	for _, id := range []string{gone.ID, "01NOSUCHSUBSCRIPTION00000"} {
		if err := s.SuspendSubscriptionAudited(ctx, id, "x", console("console_suspend", id)); !errors.Is(err, ErrNotFound) {
			t.Errorf("suspend %s: %v", id, err)
		}
		if err := s.ResumeSubscriptionAudited(ctx, id, NewID(t0), console("console_resume", id)); !errors.Is(err, ErrNotFound) {
			t.Errorf("resume %s: %v", id, err)
		}
	}
	if n := audited(); n != 2 {
		t.Errorf("a refused console action was audited (%d rows)", n)
	}
}

// deliver's side as cisp_deliver: the receiving subscriptions, the
// change feed read by cursor and by id, one delivery per change and
// subscription however often it is queued, the watermark that never goes
// down, the claim with its per-subscription bound and its lease, the 2xx
// that verifies a pending subscription, the failure run (and the
// payload's failure that leaves it alone), the suspension, the queue
// numbers, and the attempt log on the timeseries database.
func TestDeliverQueueOnPostgres(t *testing.T) {
	ctx := context.Background()
	api := testStore(t, Options{})
	d := New(deliverPool(t), Options{})
	resetSubscriptions(t, api)
	client := "ussp-dq-" + strings.ToLower(suffix(t))
	t0 := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)

	active, pingActive := subscribe(t, api, client, t0, nil)
	setStatus(t, api, active.ID, subscription.Active)
	pending, pingPending := subscribe(t, api, client, t0.Add(time.Second), nil)
	held, pingHeld := subscribe(t, api, client, t0.Add(2*time.Second), nil)
	setStatus(t, api, held.ID, subscription.Suspended)

	// The queue: the two receiving pings due since t0, the suspended
	// subscription's not counted.
	q, err := d.DeliveryQueue(ctx, t0.Add(time.Minute))
	if err != nil || q.Queued != 2 || q.Due != 2 || q.Delivering != 0 || q.Suspended != 1 ||
		q.OldestDueAge < 59*time.Second || q.OldestDueAge > 61*time.Second {
		t.Errorf("queue at t0+1m %+v %v", q, err)
	}
	if q, _ := d.DeliveryQueue(ctx, t0.Add(-time.Minute)); q.Queued != 2 || q.Due != 0 || q.OldestDueAge != 0 {
		t.Errorf("queue before anything is due %+v", q)
	}

	recv, err := d.ReceivingSubscriptions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, len(recv))
	for _, r := range recv {
		ids = append(ids, r.ID)
	}
	slices.Sort(ids)
	if want := []string{active.ID, pending.ID}; !slices.Equal(ids, want) {
		t.Errorf("receiving %v, want %v (the suspended one left out)", ids, want)
	}

	// A real change, with its box, through the publication transaction.
	fc, body := base(t, "Q")
	res, err := api.PublishTx(ctx, input(publication.DatasetZones, fc, body), NoopSigner{})
	if err != nil {
		t.Fatal(err)
	}
	cid := res.Change.ID
	byID, err := d.ChangesByID(ctx, []int64{cid, cid + 1_000_000_000})
	if err != nil || len(byID) != 1 || byID[cid].Version != res.Version || byID[cid].BBox == nil || *byID[cid].BBox != *res.Change.BBox {
		t.Errorf("changes by id %+v %v", byID, err)
	}
	if empty, err := d.ChangesByID(ctx, nil); err != nil || len(empty) != 0 {
		t.Errorf("no ids %v %v", empty, err)
	}
	scan, err := d.ScanChanges(ctx, cid-1, time.Now().Add(time.Minute), 10)
	if err != nil || len(scan) == 0 || scan[0].ID != cid || scan[0].Reason != publication.ReasonPublication || !slices.Equal(scan[0].FeatureIDs, res.Change.FeatureIDs) {
		t.Errorf("scan from the cursor %+v %v", scan, err)
	}
	if scan, _ := d.ScanChanges(ctx, cid-1, res.Change.At, 10); slices.ContainsFunc(scan, func(c publication.Change) bool { return c.ID == cid }) {
		t.Errorf("the scan's before bound is exclusive, yet it returned change %d", cid)
	}
	versions, err := d.DatasetVersions(ctx)
	if err != nil || versions[publication.DatasetZones] != res.Version {
		t.Errorf("dataset versions %v %v, want zones %d", versions, err, res.Version)
	}

	now := t0.Add(2 * time.Minute)
	n, err := d.InsertChangeDeliveries(ctx, cid, []string{active.ID, pending.ID}, now)
	if err != nil || n != 2 {
		t.Fatalf("queue the change: %d %v", n, err)
	}
	if n, err := d.InsertChangeDeliveries(ctx, cid, []string{active.ID, pending.ID}, now); err != nil || n != 0 {
		t.Errorf("the same change again wrote %d (%v)", n, err)
	}
	if n, err := d.InsertChangeDeliveries(ctx, cid, nil, now); err != nil || n != 0 {
		t.Errorf("no subscriptions: %d %v", n, err)
	}

	mark := "st-" + suffix(t)
	if w, err := d.Watermark(ctx, mark); err != nil || w != 0 {
		t.Errorf("first watermark %d %v", w, err)
	}
	for _, step := range []struct{ to, want int64 }{{10, 10}, {5, 10}, {12, 12}} {
		if err := d.AdvanceWatermark(ctx, mark, step.to, now); err != nil {
			t.Fatal(err)
		}
		if w, _ := d.Watermark(ctx, mark); w != step.want {
			t.Errorf("advance to %d: %d, want %d", step.to, w, step.want)
		}
	}

	// The claim: one per subscription with a bound of 1 (0 is 1), the
	// oldest due first; nothing more while the leases live; a limit of 0
	// claims nothing; the leases run out and every row is due again.
	lease := now.Add(time.Minute)
	if c, err := d.ClaimDeliveries(ctx, now, lease, 0, 1); err != nil || c != nil {
		t.Errorf("limit 0 claimed %+v %v", c, err)
	}
	claims, err := d.ClaimDeliveries(ctx, now, lease, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Claim{}
	for _, c := range claims {
		got[c.SubscriptionID] = c
	}
	if len(claims) != 2 || got[active.ID].DeliveryID != pingActive || got[pending.ID].DeliveryID != pingPending ||
		got[active.ID].ChangeID != nil || !got[active.ID].LeaseUntil.Equal(lease) || got[pending.ID].SubscriptionStatus != subscription.PendingVerification {
		t.Fatalf("first claim %+v", claims)
	}
	if again, _ := d.ClaimDeliveries(ctx, now, lease, 10, 1); len(again) != 0 {
		t.Errorf("claimed %d under live leases at a bound of 1", len(again))
	}
	if q, _ := d.DeliveryQueue(ctx, now); q.Delivering != 2 || q.Queued != 2 {
		t.Errorf("queue while claimed %+v", q)
	}
	after := lease.Add(time.Second)
	all, err := d.ClaimDeliveries(ctx, after, after.Add(time.Minute), 10, 5)
	if err != nil || len(all) != 4 {
		t.Fatalf("after the leases ran out: %d %v", len(all), err)
	}
	for _, c := range all {
		if c.SubscriptionID == held.ID || c.DeliveryID == pingHeld {
			t.Errorf("claimed the suspended subscription's %s", c.DeliveryID)
		}
	}
	changeDelivery := map[string]string{}
	for _, c := range all {
		if c.ChangeID != nil && *c.ChangeID == cid {
			changeDelivery[c.SubscriptionID] = c.DeliveryID
		}
	}
	at := after.Add(time.Second)

	// The 2xx: the pending subscription's ping verifies it; the active
	// one's is a success that verifies nothing.
	dv, err := d.FinishDelivered(ctx, pingPending, pending.ID, at, 204)
	if err != nil || !dv.Verified || dv.Attempts != 1 {
		t.Errorf("pending's ping delivered %+v %v", dv, err)
	}
	if s, _ := api.Subscription(ctx, pending.ID); s.Status != subscription.Active || s.VerifiedAt == nil || s.LastSuccessAt == nil {
		t.Errorf("verified subscription %+v", s)
	}
	if dv, err := d.FinishDelivered(ctx, pingActive, active.ID, at, 200); err != nil || dv.Verified {
		t.Errorf("active's ping delivered %+v %v", dv, err)
	}

	// The failure run: failed and due again, then expired; failing_since
	// stays the first failure's.
	code := 503
	retry := at.Add(time.Minute)
	f, err := d.FinishFailed(ctx, FailedAttempt{DeliveryID: changeDelivery[pending.ID], SubscriptionID: pending.ID, At: at, StatusCode: &code, Error: "503", NextRetryAt: &retry})
	if err != nil || f.State != DeliveryFailed || f.Attempts != 1 || f.ConsecutiveFailures != 1 || !f.FailingSince.Equal(at) || f.SubscriptionStatus != subscription.Active {
		t.Errorf("first failure %+v %v", f, err)
	}
	f, err = d.FinishFailed(ctx, FailedAttempt{DeliveryID: changeDelivery[pending.ID], SubscriptionID: pending.ID, At: at.Add(time.Minute), Error: "connection refused", Expire: true})
	if err != nil || f.State != DeliveryExpired || f.Attempts != 2 || f.ConsecutiveFailures != 2 || !f.FailingSince.Equal(at) {
		t.Errorf("second failure %+v %v", f, err)
	}
	// The payload's failure: expired, the subscriber's run untouched.
	f, err = d.FinishFailed(ctx, FailedAttempt{DeliveryID: changeDelivery[active.ID], SubscriptionID: active.ID, At: at, Error: "payload over the bound", Payload: true})
	if err != nil || f.State != DeliveryExpired || f.ConsecutiveFailures != 0 {
		t.Errorf("payload failure %+v %v", f, err)
	}
	if s, _ := api.Subscription(ctx, active.ID); s.ConsecutiveFailures != 0 || s.FailingSince != nil {
		t.Errorf("a payload failure counted against the subscriber %+v", s)
	}
	if s, _ := api.Subscription(ctx, pending.ID); s.ConsecutiveFailures != 2 {
		t.Errorf("pending's run %d", s.ConsecutiveFailures)
	}

	// Suspension: only an active subscription.
	if ok, err := d.SuspendSubscription(ctx, pending.ID, "failing"); err != nil || !ok {
		t.Errorf("suspend an active subscription: %v %v", ok, err)
	}
	if ok, _ := d.SuspendSubscription(ctx, pending.ID, "failing"); ok {
		t.Error("suspended a suspended subscription again")
	}
	other, _ := subscribe(t, api, client, t0, nil)
	if ok, _ := d.SuspendSubscription(ctx, other.ID, "failing"); ok {
		t.Error("suspended a pending subscription")
	}

	// The attempt log: written as deliver, read back as the api.
	tsDeliver := migrated(t, TreeTimeseries)
	tsAPIURL := onDatabase(mustEnv(t, "CISP_TEST_DATABASE_URL"), "cisp", "cisp_ts")
	readPool, err := OpenPool(ctx, PoolConfig{URL: tsAPIURL, ApplicationName: "uspace-cisp-test", MaxConns: 2})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(readPool.Close)
	w, r := NewDeliveryLog(tsDeliver), NewDeliveryLog(readPool)
	attempts := []DeliveryAttempt{
		{At: at, DeliveryID: changeDelivery[pending.ID], SubscriptionID: pending.ID, ChangeID: cid, Attempt: 1, StatusCode: &code, LatencyMs: 12, PayloadBytes: 900, Instance: "deliver-it"},
		{At: at.Add(time.Minute), DeliveryID: changeDelivery[pending.ID], SubscriptionID: pending.ID, ChangeID: cid, Attempt: 2, Error: ptr("connection refused"), LatencyMs: 3000, PayloadBytes: 900, Instance: "deliver-it"},
		{At: at, DeliveryID: pingPending, SubscriptionID: pending.ID, ChangeID: PingChangeID, Attempt: 1, StatusCode: intRef(204), LatencyMs: 5, Instance: "deliver-it"},
	}
	for _, a := range attempts {
		if err := w.Record(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	log, err := r.AttemptsOf(ctx, pending.ID, []string{changeDelivery[pending.ID]})
	if err != nil || len(log) != 2 || log[0].Attempt != 1 || log[1].Attempt != 2 || log[0].StatusCode == nil || *log[0].StatusCode != 503 ||
		log[1].StatusCode != nil || log[1].Error == nil || log[0].Instance != "deliver-it" || !log[0].At.Equal(at) {
		t.Errorf("attempt log %+v %v", log, err)
	}
	if log, _ := r.AttemptsOf(ctx, active.ID, []string{changeDelivery[pending.ID]}); len(log) != 0 {
		t.Errorf("another subscription's attempts: %+v", log)
	}
	if err := r.Record(ctx, attempts[0]); err == nil {
		t.Error("the api's read-only role wrote an attempt")
	}
}

func intRef(v int) *int { return &v }
