//go:build integration

package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rootxkit/uspace-cisp/internal/bus"
	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/store"
	"github.com/rootxkit/uspace-cisp/internal/subscription"
)

// The pair of TestDeliverWithoutTheBrokerOnPostgres: the whole process
// with the broker there. The connection and the durable consumer report
// healthy in the status line (no degraded reason), and a change published to the bus by the
// publication transaction is queued from the bus (deliveries_from_bus)
// and delivered well inside the scan's 10 s.
func TestDeliverWithTheBrokerOnPostgres(t *testing.T) {
	ctx := context.Background()
	natsURL := os.Getenv("CISP_TEST_NATS_URL")
	if natsURL == "" {
		t.Fatal("CISP_TEST_NATS_URL is not set; run make dev-deps")
	}
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
	b, err := bus.Connect(ctx, bus.Config{URL: natsURL, Name: "uspace-cisp-test", PublicBaseURL: "https://uspace-cisp.example.test", ConnectTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	logs := &syncBuffer{}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan int, 1)
	go func() { done <- run(runCtx, nil, deliverEnv(t, natsURL), logs, io.Discard) }()
	// A failure below still stops this instance before the next test
	// starts its own.
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
		}
	})
	waitForLine(t, logs, "delivering")
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("deliver's log: %s", logs.String())
		}
	})
	eventually(t, 15*time.Second, "the broker and the consumer healthy in a status line", func() bool {
		for _, m := range logLines(logs.String()) {
			if m["msg"] != "status" {
				continue
			}
			nats, _ := m["nats"].(map[string]any)
			intake, _ := m["intake"].(map[string]any)
			// A healthy component with nothing to count is left out of
			// the line; a degraded one never is.
			if nats != nil && nats["degraded"] == nil && intake["degraded"] == nil {
				return true
			}
		}
		return false
	})
	if l := waitForLine(t, logs, "nats connected"); l["level"] != "INFO" {
		t.Errorf("connected line %v", l)
	}

	st := store.New(apiPool, store.Options{Bus: b, AllowNoopSigner: true})
	now := time.Now().UTC().Add(-time.Second)
	sub := store.SubscriptionRecord{Subscription: subscription.Subscription{ID: store.NewID(now), ClientID: "ussp-cmd-bus",
		CallbackURL: srv.URL + "/v1/cis/notifications", Datasets: []publication.Dataset{publication.DatasetUSSPList},
		Status: subscription.PendingVerification}, CreatedAt: now}
	if err := st.CreateSubscription(ctx, store.NewSubscription{Record: sub, PingID: store.NewID(now), MaxPerClient: 100,
		Event: store.Event{TS: now, ActorType: store.ActorClient, ActorID: "ussp-cmd-bus", EventType: "subscription_created", EntityType: "subscription", EntityID: sub.ID}}); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "the ping", func() bool { return hits.Load() == 1 })

	body := []byte(`{"schema":"cis/ussp_list/v1","issued":"2026-10-14T00:00:00Z","ussps":[],"n":"` + store.NewID(time.Now()) + `"}`)
	res, err := st.PublishTx(ctx, store.PublishInput{Dataset: publication.DatasetUSSPList, Body: body, ContentType: "application/json",
		PublisherClientID: "authority-01", Reason: publication.ReasonPublication}, store.NoopSigner{})
	if err != nil {
		t.Fatal(err)
	}
	committed := time.Now()
	eventually(t, 5*time.Second, "the change delivered from the bus", func() bool { return hits.Load() == 2 })
	t.Logf("change %d delivered %s after the commit", res.Change.ID, time.Since(committed).Round(time.Millisecond))
	eventually(t, 5*time.Second, "deliveries_from_bus in a status line", func() bool {
		return sumCounter(logs, "deliver", "deliveries_from_bus") >= 1
	})

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
