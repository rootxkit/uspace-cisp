//go:build integration

package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/subscription"
)

// The console overview's figures on PostgreSQL (docs/PLAN.md section 15
// Q52). The databases are shared with the other tests, so every count is
// read before and after this test's own rows and compared by difference;
// each row that must not count has a twin that must, differing in one
// thing (E-01): the state, or the last attempt's time against the
// window.
func TestConsoleSummaryOnPostgres(t *testing.T) {
	ctx := context.Background()
	s := testStore(t, Options{})
	resetSubscriptions(t, s)
	before, err := s.ConsoleSummary(ctx, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if before.Now.IsZero() || before.Now.Location() != time.UTC {
		t.Errorf("now %v: want the database's clock in UTC", before.Now)
	}

	client := "ussp-sum-" + strings.ToLower(suffix(t))
	t0 := time.Now().UTC().Add(-time.Minute)
	pings := map[string]string{}
	for i, st := range []subscription.Status{subscription.Active, subscription.Active, subscription.Suspended, subscription.PendingVerification, subscription.Deleted} {
		rec, ping := subscribe(t, s, client, t0.Add(time.Duration(i)*time.Second), nil)
		setStatus(t, s, rec.ID, st)
		pings[[]string{"failed-in", "failed-out", "expired-in", "delivered-in", "queued"}[i]] = ping
	}
	// The pings become the deliveries: failed an hour ago (counted), failed
	// 25 h ago (outside the window), expired an hour ago (counted as
	// expired), delivered an hour ago (not a failure); the last stays
	// queued with no attempt.
	for key, set := range map[string]string{
		"failed-in":    `state = 'failed', last_attempt_at = now() - interval '1 hour'`,
		"failed-out":   `state = 'failed', last_attempt_at = now() - interval '25 hours'`,
		"expired-in":   `state = 'expired', last_attempt_at = now() - interval '1 hour'`,
		"delivered-in": `state = 'delivered', last_attempt_at = now() - interval '1 hour'`,
	} {
		if _, err := s.pool.Exec(ctx, `UPDATE deliveries SET `+set+` WHERE id = $1`, pings[key]); err != nil {
			t.Fatal(err)
		}
	}

	after, err := s.ConsoleSummary(ctx, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for st, want := range map[string]int64{"active": 2, "suspended": 1, "pending_verification": 1, "deleted": 1} {
		if d := after.Subscriptions[st] - before.Subscriptions[st]; d != want {
			t.Errorf("subscriptions %s: +%d, want +%d", st, d, want)
		}
	}
	if d := after.FailedDeliveries - before.FailedDeliveries; d != 1 {
		t.Errorf("failed deliveries in 24 h: +%d, want +1 (the one 25 h ago is outside)", d)
	}
	if d := after.ExpiredDeliveries - before.ExpiredDeliveries; d != 1 {
		t.Errorf("expired deliveries in 24 h: +%d, want +1", d)
	}
	// The window is the argument: 26 h takes the older failure in too.
	wide, err := s.ConsoleSummary(ctx, 26*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if wide.FailedDeliveries < after.FailedDeliveries+1 {
		t.Errorf("failed in 26 h %d, in 24 h %d: the 25 h failure is not counted in the wider window", wide.FailedDeliveries, after.FailedDeliveries)
	}

	// The USSP list: the entries of the current version, by version.
	publish := func(entries int) PublishResult {
		t.Helper()
		var list []string
		for i := range entries {
			list = append(list, `{"ussp_id":"U`+string(rune('A'+i))+`","status":"operating"}`)
		}
		body := []byte(`{"schema":"cis/ussp_list/v1","issued":"2026-10-02T00:00:00Z","ussps":[` + strings.Join(list, ",") + `],"n":"` + suffix(t) + `"}`)
		res, err := s.PublishTx(ctx, PublishInput{Dataset: publication.DatasetUSSPList, Body: body, ContentType: "application/json",
			PublisherClientID: "authority-01", Reason: publication.ReasonPublication}, NoopSigner{})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	for _, n := range []int{3, 0} {
		res := publish(n)
		got, err := s.ConsoleSummary(ctx, 24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if got.UsspListVersion != res.Version || got.Ussps != int64(n) {
			t.Errorf("ussp_list v%d with %d entries: summary v%d with %d", res.Version, n, got.UsspListVersion, got.Ussps)
		}
	}
}

// The failed-deliveries count reads the partial index of migration 0015,
// never the whole of deliveries: with sequential scans priced out, the
// plan of the very query the store runs names the index.
func TestConsoleFailedDeliveriesUsesItsIndex(t *testing.T) {
	ctx := context.Background()
	s := testStore(t, Options{})
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SET LOCAL enable_seqscan = off`); err != nil {
		t.Fatal(err)
	}
	rows, err := tx.Query(ctx, `EXPLAIN SELECT count(*) FILTER (WHERE state = 'failed')::bigint, count(*) FILTER (WHERE state = 'expired')::bigint, now()
		FROM deliveries WHERE state IN ('failed', 'expired') AND last_attempt_at >= now() - make_interval(secs => $1::float8)`, 86400.0)
	if err != nil {
		t.Fatal(err)
	}
	var plan []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, line)
	}
	rows.Close()
	joined := strings.Join(plan, "\n")
	if !strings.Contains(joined, "deliveries_failed_recent_idx") || strings.Contains(joined, "Seq Scan on deliveries") {
		t.Errorf("the failed-deliveries count does not read deliveries_failed_recent_idx:\n%s", joined)
	}
	t.Logf("plan:\n%s", joined)
}

// The delivery latency over the newest attempts of the window, bounded:
// with more attempts than the bound, the oldest are left out of the
// percentiles (E-10); an attempt older than the window is not counted
// and a recent one is (E-01).
func TestDeliveryLatencyOnPostgres(t *testing.T) {
	ctx := context.Background()
	writer := NewDeliveryLog(migrated(t, TreeTimeseries))
	// Read as the api reads it: cisp_ts as cisp_api, the read-only role.
	asAPI, err := OpenPool(ctx, PoolConfig{URL: onDatabase(mustEnv(t, "CISP_TEST_DATABASE_URL"), "cisp", "cisp_ts"), ApplicationName: "uspace-cisp-test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(asAPI.Close)
	reader := NewDeliveryLog(asAPI)
	sub := "SUB-LAT-" + suffix(t)
	record := func(at time.Time, latencyMs int) {
		t.Helper()
		if err := writer.Record(ctx, DeliveryAttempt{At: at, DeliveryID: "DEL-" + suffix(t), SubscriptionID: sub, ChangeID: 1, Attempt: 1,
			LatencyMs: latencyMs, PayloadBytes: 10, Instance: "it"}); err != nil {
			t.Fatal(err)
		}
	}
	// The newest of the log, ahead of every other test's attempt: three
	// slow ones, then twenty newer at 10, 20, ..., 200 ms.
	future := time.Now().UTC().Add(time.Minute)
	for i := range 3 {
		record(future.Add(time.Duration(i)*time.Millisecond), 99_999)
	}
	for i := range 20 {
		record(future.Add(time.Second+time.Duration(i)*time.Millisecond), 10*(i+1))
	}
	bounded, err := reader.Latency(ctx, time.Hour, 20)
	if err != nil {
		t.Fatal(err)
	}
	if bounded.Attempts != 20 || bounded.P50Ms == nil || *bounded.P50Ms != 100 || bounded.P95Ms == nil || *bounded.P95Ms != 190 {
		t.Errorf("the newest 20: %+v p50 %v p95 %v, want 20 attempts, p50 100, p95 190", bounded, deref(bounded.P50Ms), deref(bounded.P95Ms))
	}
	past, err := reader.Latency(ctx, time.Hour, 23)
	if err != nil {
		t.Fatal(err)
	}
	if past.Attempts != 23 || deref(past.P50Ms) != 120 || deref(past.P95Ms) != 99_999 {
		t.Errorf("the newest 23: %d attempts, p50 %d, p95 %d; want 23, 120, 99999", past.Attempts, deref(past.P50Ms), deref(past.P95Ms))
	}
	if past.Now.IsZero() || past.Now.Location() != time.UTC {
		t.Errorf("now %v: want the database's clock in UTC", past.Now)
	}

	all := func() int64 {
		t.Helper()
		l, err := reader.Latency(ctx, time.Hour, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		return l.Attempts
	}
	n := all()
	record(time.Now().UTC().Add(-2*time.Hour), 5)
	if m := all(); m != n {
		t.Errorf("an attempt two hours old changed the hour's count %d -> %d", n, m)
	}
	record(time.Now().UTC().Add(-time.Minute), 5)
	if m := all(); m != n+1 {
		t.Errorf("an attempt a minute old: count %d -> %d, want +1", n, m)
	}
}

// An empty window has a count of zero and no percentiles, never zeros
// read as a latency (E-02). The log is shared with the other tests, so
// the empty window is one that starts an hour ahead of the database's
// clock: no attempt is logged there.
func TestDeliveryLatencyEmptyWindow(t *testing.T) {
	ctx := context.Background()
	l := NewDeliveryLog(migrated(t, TreeTimeseries))
	got, err := l.Latency(ctx, -time.Hour, 10)
	if err != nil {
		t.Fatal(err)
	}
	if got.Attempts != 0 || got.P50Ms != nil || got.P95Ms != nil {
		t.Errorf("empty window: %+v", got)
	}
}

func deref(p *int) int {
	if p == nil {
		return -1
	}
	return *p
}
