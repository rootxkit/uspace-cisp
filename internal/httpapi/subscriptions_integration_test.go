//go:build integration

package httpapi

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-cisp/internal/httpapi/gen"
	"github.com/rootxkit/uspace-cisp/internal/store"
)

// The subscriptions tag on PostgreSQL: create with its ping and audit
// row, the per-client limit under the client's lock, PATCH re-verifying
// a new callback, the deliveries list joined with the delivery log read
// through the api's read-only role on the timeseries database, retry,
// and delete expiring the open deliveries.
func TestSubscriptionsOnPostgres(t *testing.T) {
	st, pool := pgStore(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `UPDATE subscriptions SET status = 'deleted' WHERE client_id LIKE 'ussp-pg-%'`); err != nil {
		t.Fatal(err)
	}
	h := newPubHarness(t, st)
	tsURL := os.Getenv("CISP_TEST_TIMESERIES_URL")
	dbURL := os.Getenv("CISP_TEST_DATABASE_URL")
	if tsURL == "" || dbURL == "" {
		t.Fatal("CISP_TEST_TIMESERIES_URL and CISP_TEST_DATABASE_URL must be set")
	}
	// The api reads cisp_ts as cisp_api (deploy/postgres/init.sql grants
	// it SELECT); deliver writes it as cisp_deliver.
	readTS, err := store.OpenPool(ctx, store.PoolConfig{URL: strings.Replace(dbURL, "/cisp?", "/cisp_ts?", 1), ApplicationName: "uspace-cisp-test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(readTS.Close)
	writeTS, err := store.OpenPool(ctx, store.PoolConfig{URL: tsURL, ApplicationName: "uspace-cisp-test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(writeTS.Close)
	h.subs.Log = store.NewDeliveryLog(readTS)
	client := "ussp-pg-" + strings.ToLower(store.NewID(time.Now())[20:])

	var events int64
	countEvents := func() int64 {
		var n int64
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM events WHERE actor_id = $1`, client).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	s := h.createSub(t, client, validSub())
	if s.Verification == nil || s.Status != "pending_verification" {
		t.Fatalf("created %+v", s)
	}
	if events = countEvents(); events != 1 {
		t.Errorf("%d audit rows after create", events)
	}
	got := decodeJSON[gen.Subscription](t, h.subDo(t, h.subReq(http.MethodGet, "/v1/subscriptions/"+s.Id, client, nil)))
	if got.Verification == nil || got.Verification.Id != s.Verification.Id || got.Bbox == nil || (*got.Bbox)[0] != 44.7 {
		t.Errorf("read back %+v", got)
	}

	// The limit (3 in the harness), under the client's lock.
	h.createSub(t, client, validSub())
	h.createSub(t, client, validSub())
	if rec := h.subDo(t, h.subReq(http.MethodPost, "/v1/subscriptions", client, validSub())); rec.Code != http.StatusConflict {
		t.Fatalf("4th = %d %s", rec.Code, rec.Body.String())
	}
	if l := decodeJSON[gen.SubscriptionList](t, h.subDo(t, h.subReq(http.MethodGet, "/v1/subscriptions", client, nil))); len(l.Subscriptions) != 3 {
		t.Errorf("listed %d", len(l.Subscriptions))
	}

	// A new callback: pending again, a second ping.
	patched := decodeJSON[gen.Subscription](t, h.subDo(t, h.subReq(http.MethodPatch, "/v1/subscriptions/"+s.Id, client,
		map[string]any{"callback_url": "https://other.example.ge/hook", "bbox": []float64{}})))
	if patched.Verification == nil || patched.Verification.Id == s.Verification.Id || patched.Bbox != nil {
		t.Errorf("patched %+v", patched)
	}

	// The deliveries list with the log.
	code := 500
	msg := "status 500"
	if err := store.NewDeliveryLog(writeTS).Record(ctx, store.DeliveryAttempt{
		At: time.Now().UTC(), DeliveryID: s.Verification.Id, SubscriptionID: s.Id, ChangeID: store.PingChangeID, Attempt: 1,
		StatusCode: &code, Error: &msg, LatencyMs: 3, PayloadBytes: 1200, Instance: "it",
	}); err != nil {
		t.Fatal(err)
	}
	list := decodeJSON[gen.DeliveryList](t, h.subDo(t, h.subReq(http.MethodGet, "/v1/subscriptions/"+s.Id+"/deliveries", client, nil)))
	if list.Log != "complete" || len(list.Deliveries) != 2 {
		t.Fatalf("deliveries %+v", list)
	}
	var logged int
	for _, d := range list.Deliveries {
		if d.Reason != "subscription_test" || d.Log == nil {
			t.Errorf("delivery %+v", d)
			continue
		}
		logged += len(*d.Log)
	}
	if logged != 1 {
		t.Errorf("%d logged attempts listed, want 1", logged)
	}

	// Retry, then delete: the open pings expire.
	rec := h.subDo(t, h.subReq(http.MethodPost, "/v1/subscriptions/"+s.Id+"/deliveries/"+s.Verification.Id+"/retry", client, nil))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("retry = %d %s", rec.Code, rec.Body.String())
	}
	if rec := h.subDo(t, h.subReq(http.MethodDelete, "/v1/subscriptions/"+s.Id, client, nil)); rec.Code != http.StatusOK {
		t.Fatalf("delete = %d", rec.Code)
	}
	var open int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM deliveries WHERE subscription_id = $1 AND state <> 'expired'`, s.Id).Scan(&open); err != nil || open != 0 {
		t.Errorf("%d open deliveries after delete (%v)", open, err)
	}
	if n := countEvents(); n != events+5 {
		t.Errorf("%d audit rows, want %d (2 creates, patch, retry, delete)", n, events+5)
	}
	if rec := h.subDo(t, h.subReq(http.MethodGet, "/v1/subscriptions/"+s.Id, client, nil)); rec.Code != http.StatusNotFound {
		t.Errorf("deleted = %d", rec.Code)
	}
}
