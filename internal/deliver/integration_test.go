//go:build integration

// Integration tests of deliver on PostgreSQL + PostGIS, TimescaleDB and
// NATS JetStream (make dev-deps, or the CI services). deliver connects
// as cisp_deliver, as it does in production, so every grant it needs is
// exercised; the api's side (subscriptions, the change rows) is written
// as cisp_api. A missing address fails the test: a suite that skips
// proves nothing.
package deliver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rootxkit/uspace-cisp/internal/bus"
	"github.com/rootxkit/uspace-cisp/internal/obs"
	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/store"
	"github.com/rootxkit/uspace-cisp/internal/subscription"
)

func envURL(t *testing.T, name string) string {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		t.Fatalf("%s is not set; run make dev-deps (see the Makefile's integration target)", name)
	}
	return v
}

func openPool(t *testing.T, url string) *pgxpool.Pool {
	t.Helper()
	p, err := store.OpenPool(context.Background(), store.PoolConfig{URL: url, ApplicationName: "uspace-cisp-test", MaxConns: 8})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

// onDatabase is url with its database name replaced.
func onDatabase(url, from, to string) string {
	return strings.Replace(url, "/"+from+"?", "/"+to+"?", 1)
}

type pg struct {
	api       *pgxpool.Pool // cisp as cisp_api
	apiStore  *store.Store
	deliver   *pgxpool.Pool // cisp as cisp_deliver
	ts        *pgxpool.Pool // cisp_ts as cisp_deliver
	tsReadAPI *pgxpool.Pool // cisp_ts as cisp_api (the api's read-only role)
}

func setup(t *testing.T) *pg {
	t.Helper()
	ctx := context.Background()
	dbURL, tsURL := envURL(t, "CISP_TEST_DATABASE_URL"), envURL(t, "CISP_TEST_TIMESERIES_URL")
	p := &pg{api: openPool(t, dbURL), ts: openPool(t, tsURL)}
	for _, m := range []struct {
		pool *pgxpool.Pool
		tree store.Tree
	}{{p.api, store.TreeRelational}, {p.ts, store.TreeTimeseries}} {
		db := store.OpenSQL(m.pool)
		if _, err := store.Up(ctx, db, m.tree); err != nil {
			t.Fatalf("migrate %s: %v", m.tree, err)
		}
		_ = db.Close()
	}
	p.deliver = openPool(t, onDatabase(tsURL, "cisp_ts", "cisp"))
	p.tsReadAPI = openPool(t, onDatabase(dbURL, "cisp", "cisp_ts"))
	p.apiStore = store.New(p.api, store.Options{})
	// Earlier runs' subscriptions are not this test's.
	if _, err := p.api.Exec(ctx, `UPDATE subscriptions SET status = 'deleted' WHERE status <> 'deleted'`); err != nil {
		t.Fatal(err)
	}
	return p
}

// change writes a changes row as the api's transaction would, without a
// bus: the scan's case. Its version is far above any a publication
// test makes, so a test that finds a change by dataset and version
// never finds this one.
func (p *pg) change(t *testing.T, ds publication.Dataset, at time.Time) publication.Change {
	t.Helper()
	const version = 1_000_000_000
	var id int64
	err := p.api.QueryRow(context.Background(),
		`INSERT INTO changes (dataset, version, feature_ids, removed_ids, reason, at)
		 VALUES ($1, $2, ARRAY['ZT1'], ARRAY[]::text[], 'publication', $3) RETURNING id`, string(ds), version, at).Scan(&id)
	if err != nil {
		t.Fatal(err)
	}
	return publication.Change{ID: id, Dataset: ds, Version: version, FeatureIDs: []string{"ZT1"}, RemovedIDs: []string{},
		Reason: publication.ReasonPublication, At: at.UTC()}
}

// subscribe registers callback as the api does (pending, with its ping);
// active marks it verified and its ping delivered.
func (p *pg) subscribe(t *testing.T, callback string, active bool, ds ...publication.Dataset) store.SubscriptionRecord {
	t.Helper()
	if len(ds) == 0 {
		ds = []publication.Dataset{publication.DatasetZones}
	}
	ctx := context.Background()
	now := time.Now().UTC().Add(-time.Minute)
	rec := store.SubscriptionRecord{
		Subscription: subscription.Subscription{ID: store.NewID(now), ClientID: "ussp-it-01", CallbackURL: callback, Datasets: ds,
			Status: subscription.PendingVerification},
		CreatedAt: now,
	}
	err := p.apiStore.CreateSubscription(ctx, store.NewSubscription{Record: rec, PingID: store.NewID(now), MaxPerClient: 1000,
		Event: store.Event{TS: now, ActorType: store.ActorClient, ActorID: "ussp-it-01", EventType: "subscription_created",
			EntityType: "subscription", EntityID: rec.ID}})
	if err != nil {
		t.Fatal(err)
	}
	if active {
		if _, err := p.api.Exec(ctx, `UPDATE subscriptions SET status = 'active', verified_at = now() WHERE id = $1`, rec.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := p.api.Exec(ctx, `UPDATE deliveries SET state = 'delivered', next_retry_at = NULL WHERE subscription_id = $1`, rec.ID); err != nil {
			t.Fatal(err)
		}
		rec.Status = subscription.Active
	}
	return rec
}

func (p *pg) rows(t *testing.T, change int64) map[string]string {
	t.Helper()
	rows, err := p.api.Query(context.Background(), `SELECT subscription_id, state FROM deliveries WHERE change_id = $1`, change)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var s, st string
		if err := rows.Scan(&s, &st); err != nil {
			t.Fatal(err)
		}
		out[s] = st
	}
	return out
}

func (p *pg) service(t *testing.T, instance string, mutate func(*Config)) (*Service, *obs.Status) {
	t.Helper()
	ring, _ := keyRing(t, "cisp-it")
	status := obs.NewStatus("deliver", nil, time.Now())
	cfg := Config{
		Instance: instance, IssuerURL: testIssuer, PublicBaseURL: "https://uspace-cisp.example.test",
		Policy: subscription.URLPolicy{AllowPrivate: true, AllowInsecure: true},
	}
	if mutate != nil {
		mutate(&cfg)
	}
	s, err := New(cfg, store.New(p.deliver, store.Options{}), store.NewDeliveryLog(p.ts), ring, Options{Status: status})
	if err != nil {
		t.Fatal(err)
	}
	return s, status
}

// countingReceiver counts deliveries by jti (the delivery id header) and
// answers codes in turn.
type countingReceiver struct {
	srv   *httptest.Server
	mu    sync.Mutex
	byID  map[string]int
	codes []int
	n     int
}

func newCounting(t *testing.T, codes ...int) *countingReceiver {
	t.Helper()
	if len(codes) == 0 {
		codes = []int{http.StatusNoContent}
	}
	r := &countingReceiver{byID: map[string]int{}, codes: codes}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.byID[req.Header.Get(HeaderDeliveryID)]++
		code := r.codes[min(r.n, len(r.codes)-1)]
		r.n++
		r.mu.Unlock()
		w.WriteHeader(code)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *countingReceiver) snapshot() map[string]int {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]int, len(r.byID))
	for k, v := range r.byID {
		out[k] = v
	}
	return out
}

func eventually(t *testing.T, within time.Duration, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("not within %s: %s", within, what)
}

func connectBus(t *testing.T) *bus.Bus {
	t.Helper()
	b, err := bus.Connect(context.Background(), bus.Config{URL: envURL(t, "CISP_TEST_NATS_URL"), Name: "uspace-cisp-test", PublicBaseURL: "https://uspace-cisp.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	eventually(t, 5*time.Second, "nats connected", func() bool { ok, _ := b.Status(); return ok })
	return b
}

// Through JetStream: one row per matching subscription, written before
// the ack; the same Nats-Msg-Id published twice is stored once, and the
// same change under another message id writes nothing more (B-05).
func TestIntakeFromJetStream(t *testing.T) {
	p := setup(t)
	ctx := context.Background()
	b := connectBus(t)
	name := fmt.Sprintf("deliver-it-%d", time.Now().UnixNano())
	c, err := b.DurableConsumer(ctx, bus.ConsumerConfig{Name: name})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.DeleteConsumer(context.Background(), name) })
	r := newCounting(t)
	z1 := p.subscribe(t, r.srv.URL+"/a", true, publication.DatasetZones)
	z2 := p.subscribe(t, r.srv.URL+"/b", false, publication.DatasetZones, publication.DatasetRestrictions)
	other := p.subscribe(t, r.srv.URL+"/c", true, publication.DatasetUSSPList)
	svc, status := p.service(t, "it-intake", nil)
	// The cursor is the Nats-Msg-Id; a suite that migrated the tables
	// down and up restarts it at 1, and an id the stream saw within its
	// two-minute window would read as a duplicate. Move it past them.
	if _, err := p.api.Exec(ctx, `SELECT setval(pg_get_serial_sequence('changes', 'id'),
		GREATEST((SELECT COALESCE(max(id), 0) FROM changes), $1::bigint))`, time.Now().UnixMilli()*1000); err != nil {
		t.Fatal(err)
	}
	ch := p.change(t, publication.DatasetZones, time.Now())

	first, err := b.PublishAck(ctx, ch)
	if err != nil {
		t.Fatal(err)
	}
	again, err := b.PublishAck(ctx, ch)
	if err != nil || !again.Duplicate || first.Duplicate {
		t.Fatalf("dedupe: first %+v again %+v %v", first, again, err)
	}
	body, _ := json.Marshal(bus.MessageOf(ch, "https://uspace-cisp.example.test"))
	if _, err := b.PublishRaw(ctx, ch.Dataset, fmt.Sprintf("%d-again", ch.ID), body); err != nil {
		t.Fatal(err)
	}
	handled := 0
	deadline := time.Now().Add(10 * time.Second)
	for handled < 2 && time.Now().Before(deadline) {
		err := c.Fetch(ctx, 10, 500*time.Millisecond, func(m bus.Msg) {
			pc, err := bus.ParseChange(m.Data())
			if err != nil || pc.ID != ch.ID {
				_ = m.Ack()
				return
			}
			svc.Handle(ctx, m, bus.DefaultMaxDeliver)
			handled++
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if handled != 2 {
		t.Fatalf("handled %d messages of the change, want 2 (the duplicate id stored once, the other id once)", handled)
	}
	got := p.rows(t, ch.ID)
	if len(got) != 2 || got[z1.ID] != store.DeliveryQueued || got[z2.ID] != store.DeliveryQueued || got[other.ID] != "" {
		t.Errorf("rows %v", got)
	}
	if n := status.Component(Component).Counter(CounterIntakeDeliveries, "").Value(); n != 2 {
		t.Errorf("deliveries_from_bus %d, want 2", n)
	}
}

// A change that never reached NATS is found by the scan, its rows
// written and counted (D6, E-02); the watermark settles past it.
func TestScanFindsAChangeTheBusLost(t *testing.T) {
	p := setup(t)
	ctx := context.Background()
	r := newCounting(t)
	sub := p.subscribe(t, r.srv.URL+"/a", true)
	svc, status := p.service(t, "it-scan", func(c *Config) { c.ScanSettle = time.Millisecond })
	ch := p.change(t, publication.DatasetZones, time.Now().Add(-5*time.Second))
	n, err := svc.Scan(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n < 1 || p.rows(t, ch.ID)[sub.ID] != store.DeliveryQueued {
		t.Fatalf("scan wrote %d; rows %v", n, p.rows(t, ch.ID))
	}
	if got := status.Component(Component).Counter(CounterScanDeliveries, "").Value(); got != uint64(n) {
		t.Errorf("deliveries_from_scan %d, want %d", got, n)
	}
	w, err := store.New(p.deliver, store.Options{}).Watermark(ctx, WatermarkName)
	if err != nil || w < ch.ID {
		t.Errorf("watermark %d %v, want at least %d", w, err, ch.ID)
	}
	if n, err := svc.Scan(ctx); err != nil || n != 0 {
		t.Errorf("second scan wrote %d %v", n, err)
	}
	// And the sender delivers it.
	svc.Dispatch(ctx)
	svc.Wait()
	if p.rows(t, ch.ID)[sub.ID] != store.DeliveryDelivered {
		t.Errorf("not delivered: %v", p.rows(t, ch.ID))
	}
}

// Two instances share the queue: every delivery arrives exactly once
// (SKIP LOCKED); then a "killed" instance's leased rows are delivered by
// the survivor once the lease runs out: nothing lost, nothing twice.
func TestTwoInstancesAndAKilledOne(t *testing.T) {
	p := setup(t)
	ctx := context.Background()
	r := newCounting(t)
	sub := p.subscribe(t, r.srv.URL+"/a", true)
	_ = sub
	const n = 40
	var ids []int64
	for range n {
		ch := p.change(t, publication.DatasetZones, time.Now())
		ids = append(ids, ch.ID)
	}
	a, _ := p.service(t, "it-a", func(c *Config) { c.MaxInFlight = 8 })
	b, _ := p.service(t, "it-b", func(c *Config) { c.MaxInFlight = 8 })
	for _, id := range ids {
		if _, err := a.Intake(ctx, publication.Change{ID: id, Dataset: publication.DatasetZones, At: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	runCtx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	for _, s := range []*Service{a, b} {
		wg.Add(1)
		go func() { defer wg.Done(); s.RunSender(runCtx) }()
		s.Wake()
	}
	eventually(t, 20*time.Second, "40 deliveries", func() bool { return len(r.snapshot()) >= n })
	cancel()
	wg.Wait()
	for id, count := range r.snapshot() {
		if count != 1 {
			t.Errorf("delivery %s received %d times", id, count)
		}
	}
	for _, id := range ids {
		if st := p.rows(t, id)[sub.ID]; st != store.DeliveryDelivered {
			t.Errorf("change %d: %s", id, st)
		}
	}

	// A process killed mid-batch: its claims stay delivering under a
	// lease; the survivor sends them once the lease runs out.
	var more []int64
	for range 5 {
		ch := p.change(t, publication.DatasetZones, time.Now())
		more = append(more, ch.ID)
		if _, err := a.Intake(ctx, ch); err != nil {
			t.Fatal(err)
		}
	}
	killed := store.New(p.deliver, store.Options{})
	now := time.Now().UTC()
	claims, err := killed.ClaimDeliveries(ctx, now, now.Add(time.Second), 100, 100)
	if err != nil || len(claims) != 5 {
		t.Fatalf("killed instance claimed %d %v", len(claims), err)
	}
	if got, _ := b.Dispatch(ctx); got != 0 {
		t.Fatalf("claimed %d rows another instance holds", got)
	}
	time.Sleep(1100 * time.Millisecond) // the lease, 1 s
	b.Dispatch(ctx)
	b.Wait()
	for _, id := range more {
		if st := p.rows(t, id)[sub.ID]; st != store.DeliveryDelivered {
			t.Errorf("change %d after the killed instance: %s", id, st)
		}
	}
	if total := len(r.snapshot()); total != n+5 {
		t.Errorf("%d distinct deliveries received, want %d", total, n+5)
	}
	for id, count := range r.snapshot() {
		if count != 1 {
			t.Errorf("delivery %s received %d times", id, count)
		}
	}
}

// The ping: a 2xx activates the subscription; a 500 leaves it pending
// with the status and error on its latest ping (what GET shows).
func TestPingOnPostgres(t *testing.T) {
	p := setup(t)
	ctx := context.Background()
	ok, bad := newCounting(t, http.StatusNoContent), newCounting(t, http.StatusInternalServerError)
	good := p.subscribe(t, ok.srv.URL+"/hook", false)
	failing := p.subscribe(t, bad.srv.URL+"/hook", false)
	svc, _ := p.service(t, "it-ping", nil)
	svc.Dispatch(ctx)
	svc.Wait()
	g, err := p.apiStore.Subscription(ctx, good.ID)
	if err != nil || g.Status != subscription.Active || g.VerifiedAt == nil || g.LastSuccessAt == nil {
		t.Errorf("good subscription %+v %v", g, err)
	}
	f, err := p.apiStore.Subscription(ctx, failing.ID)
	if err != nil || f.Status != subscription.PendingVerification || f.ConsecutiveFailures != 1 || f.FailingSince == nil {
		t.Errorf("failing subscription %+v %v", f, err)
	}
	ping, err := p.apiStore.LatestPing(ctx, failing.ID)
	if err != nil || ping.State != store.DeliveryFailed || ping.LastStatusCode == nil || *ping.LastStatusCode != 500 ||
		ping.LastError == nil || *ping.LastError != "status 500" || ping.NextRetryAt == nil {
		t.Errorf("failing ping %+v %v", ping, err)
	}
	// The attempts are in the delivery log, read through the api's role.
	attempts, err := store.NewDeliveryLog(p.tsReadAPI).AttemptsOf(ctx, failing.ID, []string{ping.ID})
	if err != nil || len(attempts) != 1 || attempts[0].ChangeID != store.PingChangeID || *attempts[0].StatusCode != 500 || attempts[0].Instance != "it-ping" {
		t.Errorf("attempts %+v %v", attempts, err)
	}
}

// The retry schedule against a subscriber that fails twice: three
// attempts, the gaps at least the doubling delays, all logged.
func TestRetryScheduleOnPostgres(t *testing.T) {
	p := setup(t)
	ctx := context.Background()
	r := newCounting(t, http.StatusInternalServerError, http.StatusBadGateway, http.StatusOK)
	sub := p.subscribe(t, r.srv.URL+"/hook", true)
	ch := p.change(t, publication.DatasetZones, time.Now())
	retry := subscription.Retry{Base: 100 * time.Millisecond, Max: time.Second, Window: time.Hour}
	svc, _ := p.service(t, "it-retry", func(c *Config) { c.Retry = retry })
	if _, err := svc.Intake(ctx, ch); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "delivered after two failures", func() bool {
		svc.Dispatch(ctx)
		svc.Wait()
		return p.rows(t, ch.ID)[sub.ID] == store.DeliveryDelivered
	})
	var did string
	if err := p.api.QueryRow(ctx, `SELECT id FROM deliveries WHERE change_id = $1`, ch.ID).Scan(&did); err != nil {
		t.Fatal(err)
	}
	attempts, err := store.NewDeliveryLog(p.tsReadAPI).AttemptsOf(ctx, sub.ID, []string{did})
	if err != nil || len(attempts) != 3 {
		t.Fatalf("attempts %+v %v", attempts, err)
	}
	for i, want := range []int{500, 502, 200} {
		if attempts[i].Attempt != i+1 || attempts[i].StatusCode == nil || *attempts[i].StatusCode != want {
			t.Errorf("attempt %d: %+v", i+1, attempts[i])
		}
	}
	if gap := attempts[1].At.Sub(attempts[0].At); gap < 90*time.Millisecond {
		t.Errorf("first retry after %s, want at least 100 ms -10 %%", gap)
	}
	if gap := attempts[2].At.Sub(attempts[1].At); gap < 180*time.Millisecond {
		t.Errorf("second retry after %s, want at least 200 ms -10 %%", gap)
	}
	t.Logf("retries after %s and %s", attempts[1].At.Sub(attempts[0].At), attempts[2].At.Sub(attempts[1].At))
}

// The queue as the status line reads it, on the real query: the healthy
// "0 queued, 0 due" with nothing waiting (E-02).
func TestQueueStatsOnPostgres(t *testing.T) {
	p := setup(t)
	svc, status := p.service(t, "it-queue", nil)
	svc.Probe(context.Background())
	comp := status.Component(Component)
	if comp.DegradedReason() != "" {
		t.Fatalf("degraded: %s", comp.DegradedReason())
	}
	if q := comp.Gauge(GaugeQueued, "").Value(); q != 0 {
		t.Errorf("queued %v with every subscription deleted", q)
	}
}

// The per-subscription cap on the real claim: a slow subscriber with ten
// due deliveries holds three rows, the other subscriber's delivery goes
// in the same pass, and a second instance claims none of the slow one's
// while its three leases are live (the cap counts every instance).
func TestPerSubscriptionCapOnPostgres(t *testing.T) {
	p := setup(t)
	ctx := context.Background()
	release := make(chan struct{})
	slowSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(slowSrv.Close)
	fast := newCounting(t)
	slow := p.subscribe(t, slowSrv.URL+"/hook", true)
	p.subscribe(t, fast.srv.URL+"/hook", true, publication.DatasetRestrictions)
	cfg := func(c *Config) { c.MaxInFlight = 8; c.MaxPerSubscription = 3 }
	a, _ := p.service(t, "it-cap-a", cfg)
	b, _ := p.service(t, "it-cap-b", cfg)
	for range 10 {
		if _, err := a.Intake(ctx, p.change(t, publication.DatasetZones, time.Now())); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := a.Intake(ctx, p.change(t, publication.DatasetRestrictions, time.Now())); err != nil {
		t.Fatal(err)
	}
	if n, err := a.Dispatch(ctx); err != nil || n != 4 {
		t.Fatalf("claimed %d %v, want 3 of the slow subscriber and 1 of the other", n, err)
	}
	eventually(t, 5*time.Second, "the other subscriber served beside the slow one", func() bool { return len(fast.snapshot()) == 1 })
	if n, err := b.Dispatch(ctx); err != nil || n != 0 {
		t.Errorf("a second instance claimed %d %v of a subscriber at its cap", n, err)
	}
	var delivering int
	if err := p.api.QueryRow(ctx, `SELECT count(*) FROM deliveries WHERE subscription_id = $1 AND state = 'delivering'`, slow.ID).Scan(&delivering); err != nil || delivering != 3 {
		t.Errorf("slow subscriber delivering %d (%v), want 3", delivering, err)
	}
	close(release)
	a.Wait()
}

// On the real store: a webhook over MaxTokenBytes expires without a
// POST and leaves the subscription's failure run where it was (49 stay
// 49, still active); the twin inside the bound answered 502 makes it 50
// and suspends the subscription (E-01).
func TestPayloadTooLargeOnPostgres(t *testing.T) {
	for _, tc := range []struct {
		name     string
		maxBytes int
		code     int
		large    bool
	}{
		{"over the bound", 600, http.StatusNoContent, true},
		{"inside the bound, 502", 0, http.StatusBadGateway, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := setup(t)
			ctx := context.Background()
			r := newCounting(t, tc.code)
			sub := p.subscribe(t, r.srv.URL+"/hook", true)
			if _, err := p.api.Exec(ctx, `UPDATE subscriptions SET consecutive_failures = 49, failing_since = now() - interval '2 hours' WHERE id = $1`, sub.ID); err != nil {
				t.Fatal(err)
			}
			ch := p.change(t, publication.DatasetZones, time.Now())
			svc, status := p.service(t, "it-payload", func(c *Config) { c.MaxTokenBytes = tc.maxBytes })
			if _, err := svc.Intake(ctx, ch); err != nil {
				t.Fatal(err)
			}
			if _, err := svc.Dispatch(ctx); err != nil {
				t.Fatal(err)
			}
			svc.Wait()
			var failures int
			var subStatus, lastError string
			if err := p.api.QueryRow(ctx, `SELECT s.consecutive_failures, s.status, COALESCE(d.last_error, '')
				FROM subscriptions s JOIN deliveries d ON d.subscription_id = s.id WHERE s.id = $1 AND d.change_id = $2`,
				sub.ID, ch.ID).Scan(&failures, &subStatus, &lastError); err != nil {
				t.Fatal(err)
			}
			state := p.rows(t, ch.ID)[sub.ID]
			posted := len(r.snapshot())
			tooLarge := status.Component(Component).Counter(CounterPayloadTooLarge, "").Value()
			if !tc.large {
				if posted != 1 || failures != 50 || subStatus != string(subscription.Suspended) || state != store.DeliveryFailed || tooLarge != 0 {
					t.Errorf("posted %d, failures %d, status %s, delivery %s, too large %d", posted, failures, subStatus, state, tooLarge)
				}
				return
			}
			if posted != 0 || state != store.DeliveryExpired || !strings.Contains(lastError, "over the 600-byte bound") {
				t.Errorf("posted %d, delivery %s, last error %q", posted, state, lastError)
			}
			if failures != 49 || subStatus != string(subscription.Active) || tooLarge != 1 {
				t.Errorf("failures %d, status %s, too large %d: the payload's failure counted against the subscriber", failures, subStatus, tooLarge)
			}
		})
	}
}
