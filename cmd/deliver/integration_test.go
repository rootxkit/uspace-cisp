//go:build integration

package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rootxkit/uspace-cisp/internal/authtest"
	"github.com/rootxkit/uspace-cisp/internal/jws"
	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/store"
	"github.com/rootxkit/uspace-cisp/internal/subscription"
)

// deliver never migrates the timeseries tree: with a migration pending it
// names it and exits 2; with none pending it starts (E-01 pair).
func TestRunRefusesPendingTimeseriesMigrations(t *testing.T) {
	url := os.Getenv("CISP_TEST_TIMESERIES_URL")
	if url == "" {
		t.Fatal("CISP_TEST_TIMESERIES_URL is not set; run make dev-deps")
	}
	ctx := context.Background()
	pool, err := store.OpenPool(ctx, store.PoolConfig{URL: url, ApplicationName: "uspace-cisp-test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	db := store.OpenSQL(pool)
	t.Cleanup(func() { _ = db.Close() })
	if _, err := store.DownTo(ctx, db, store.TreeTimeseries, 1); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := store.Up(context.Background(), db, store.TreeTimeseries); err != nil {
			t.Errorf("up again: %v", err)
		}
	})
	env := []string{"CISP_DELIVER_HTTP_ADDR=127.0.0.1:0", "CISP_TIMESERIES_URL=" + url}
	logs := &syncBuffer{}
	if c := run(ctx, nil, env, logs, io.Discard); c != 2 {
		t.Fatalf("exit %d with a pending migration, want 2: %s", c, logs.String())
	}
	if !strings.Contains(logs.String(), "0002_delivery_attempts.sql") {
		t.Errorf("the pending migration is not named: %s", logs.String())
	}

	if _, err := store.Up(ctx, db, store.TreeTimeseries); err != nil {
		t.Fatal(err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	logs = &syncBuffer{}
	done := make(chan int, 1)
	go func() { done <- run(runCtx, nil, env, logs, io.Discard) }()
	waitForLine(t, logs, "listening")
	cancel()
	if c := <-done; c != 0 {
		t.Errorf("exit %d: %s", c, logs.String())
	}
	if strings.Contains(logs.String(), "migrations pending") {
		t.Error("pending reported with every migration applied")
	}
}

// deliverEnv is the environment of a deliver that sends: its own role on
// the relational database, the timeseries database, a signing key, the
// issuer and the public base URL, private and plain-http callbacks
// allowed (the test's receiver is on 127.0.0.1), a 1 s status line.
func deliverEnv(t *testing.T, natsURL string) []string {
	t.Helper()
	ts := os.Getenv("CISP_TEST_TIMESERIES_URL")
	if ts == "" || os.Getenv("CISP_TEST_DATABASE_URL") == "" {
		t.Fatal("CISP_TEST_DATABASE_URL and CISP_TEST_TIMESERIES_URL must be set; run make dev-deps")
	}
	pemBytes, err := jws.EncodePrivateKeyPEM(authtest.Key(t, "deliver-cmd", 3072))
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "cisp.pem")
	if err := os.WriteFile(keyFile, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return []string{
		"CISP_DELIVER_HTTP_ADDR=127.0.0.1:0",
		"CISP_DATABASE_URL=" + strings.Replace(ts, "/cisp_ts?", "/cisp?", 1),
		"CISP_TIMESERIES_URL=" + ts,
		"CISP_NATS_URL=" + natsURL,
		"CISP_SIGNING_KEY_FILE=" + keyFile, "CISP_SIGNING_KID=cisp-cmd",
		"CISP_ISSUER_URL=https://uspace-cisp.example.test", "CISP_PUBLIC_BASE_URL=https://uspace-cisp.example.test",
		"CISP_ALLOW_PRIVATE_CALLBACKS=true", "CISP_ALLOW_INSECURE_CALLBACKS=true",
		"CISP_STATUS_INTERVAL_S=1",
	}
}

// statusSummary waits for a status line written from now on whose
// deliver summary starts with prefix and returns the line.
func statusSummary(t *testing.T, logs *syncBuffer, prefix string, within time.Duration) map[string]any {
	t.Helper()
	from := len(logs.String())
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		for _, m := range logLines(logs.String()[from:]) {
			if m["msg"] != "status" {
				continue
			}
			d, _ := m["deliver"].(map[string]any)
			if s, _ := d["summary"].(string); strings.HasPrefix(s, prefix) {
				return m
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no status line with summary %q in: %s", prefix, logs.String())
	return nil
}

// The whole process with the broker absent for real (nothing listens on
// its address): a change committed without a publish is found by the
// scan within its 10 s, counted deliveries_from_scan, and delivered; the
// status line reads "0 queued, 0 due" before and after (E-02). Stopped,
// it exits 0.
func TestDeliverWithoutTheBrokerOnPostgres(t *testing.T) {
	ctx := context.Background()
	apiPool, err := store.OpenPool(ctx, store.PoolConfig{URL: os.Getenv("CISP_TEST_DATABASE_URL"), ApplicationName: "uspace-cisp-test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(apiPool.Close)
	db := store.OpenSQL(apiPool)
	if _, err := store.Up(ctx, db, store.TreeRelational); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	if _, err := apiPool.Exec(ctx, `UPDATE subscriptions SET status = 'deleted' WHERE status <> 'deleted'`); err != nil {
		t.Fatal(err)
	}
	var got sync.Map
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Store(r.Header.Get("X-CIS-Delivery-Id"), true)
		hits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	logs := &syncBuffer{}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan int, 1)
	go func() { done <- run(runCtx, nil, deliverEnv(t, "nats://127.0.0.1:1"), logs, io.Discard) }()
	waitForLine(t, logs, "delivering")
	line := statusSummary(t, logs, "0 queued, 0 due", 10*time.Second)
	if nats, _ := line["nats"].(map[string]any); nats["degraded"] == nil {
		t.Errorf("the broker's absence is not in the status line: %v", line)
	}
	t.Logf("healthy line: %v", line["deliver"])

	// A subscription (active) and a change committed with no publish.
	st := store.New(apiPool, store.Options{})
	now := time.Now().UTC().Add(-time.Second)
	sub := store.SubscriptionRecord{Subscription: subscription.Subscription{ID: store.NewID(now), ClientID: "ussp-cmd-01",
		CallbackURL: srv.URL + "/v1/cis/notifications", Datasets: []publication.Dataset{publication.DatasetZones},
		Status: subscription.PendingVerification}, CreatedAt: now}
	if err := st.CreateSubscription(ctx, store.NewSubscription{Record: sub, PingID: store.NewID(now), MaxPerClient: 100,
		Event: store.Event{TS: now, ActorType: store.ActorClient, ActorID: "ussp-cmd-01", EventType: "subscription_created", EntityType: "subscription", EntityID: sub.ID}}); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "the ping", func() bool { return hits.Load() == 1 })
	var change int64
	if err := apiPool.QueryRow(ctx, `INSERT INTO changes (dataset, version, feature_ids, removed_ids, reason, at)
		VALUES ('zones', 1, ARRAY['ZC1'], ARRAY[]::text[], 'publication', now()) RETURNING id`).Scan(&change); err != nil {
		t.Fatal(err)
	}
	committed := time.Now()
	eventually(t, 15*time.Second, "the change delivered by the scan", func() bool { return hits.Load() == 2 })
	t.Logf("delivered by the scan %s after the commit", time.Since(committed).Round(time.Millisecond))
	// The receiver answers before deliver records the 2xx.
	eventually(t, 5*time.Second, "the delivery recorded delivered", func() bool {
		var state string
		err := apiPool.QueryRow(ctx, `SELECT state FROM deliveries WHERE change_id = $1 AND subscription_id = $2`, change, sub.ID).Scan(&state)
		return err == nil && state == "delivered"
	})
	line = statusSummary(t, logs, "0 queued, 0 due", 5*time.Second)
	// A status line counts what happened since the previous one (WP-7):
	// the lines since the start add up to the totals.
	if scan, delivered := sumCounter(logs, "deliver", "deliveries_from_scan"), sumCounter(logs, "deliver", "deliveries_delivered"); scan == 0 || delivered < 2 {
		t.Errorf("counters not in the lines: from_scan %v, delivered %v; last %v", scan, delivered, line["deliver"])
	} else {
		t.Logf("after the scan: from_scan %v, delivered %v; last line %v", scan, delivered, line["deliver"])
	}

	cancel()
	select {
	case c := <-done:
		if c != 0 {
			t.Errorf("exit %d: %s", c, logs.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("deliver did not stop")
	}
	waitForLine(t, logs, "stopped")
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

// sumCounter adds a component's counter over every status line so far.
func sumCounter(logs *syncBuffer, component, name string) float64 {
	total := 0.0
	for _, l := range strings.Split(logs.String(), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) != nil || m["msg"] != "status" {
			continue
		}
		if c, ok := m[component].(map[string]any); ok {
			if v, ok := c[name].(float64); ok {
				total += v
			}
		}
	}
	return total
}
