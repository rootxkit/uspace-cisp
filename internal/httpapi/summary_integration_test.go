//go:build integration

package httpapi

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-cisp/internal/auth"
	"github.com/rootxkit/uspace-cisp/internal/httpapi/gen"
	"github.com/rootxkit/uspace-cisp/internal/store"
)

// GET /v1/console/summary on PostgreSQL and TimescaleDB, the log read
// as the api reads it (cisp_ts as cisp_api). The databases are shared,
// so the figures are compared before and after this test's own rows:
// a new pending subscription, its ping failed an hour ago, and one
// logged attempt. A viewer gets the counts, a machine token 403, no
// session 401.
func TestConsoleSummaryOnPostgres(t *testing.T) {
	st, pool := pgStore(t)
	ctx := context.Background()
	h := newPubHarness(t, st)
	dbURL, tsURL := os.Getenv("CISP_TEST_DATABASE_URL"), os.Getenv("CISP_TEST_TIMESERIES_URL")
	if dbURL == "" || tsURL == "" {
		t.Fatal("CISP_TEST_TIMESERIES_URL and CISP_TEST_DATABASE_URL must be set")
	}
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
	h.console.Latency = store.NewDeliveryLog(readTS)
	tok, _ := h.consoleToken(t, auth.RoleViewer)
	summary := func() gen.ConsoleSummary {
		t.Helper()
		rec := h.consoleDo(t, h.consoleReq(http.MethodGet, summaryPath, tok, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("summary: %d %s", rec.Code, rec.Body.String())
		}
		return decodeJSON[gen.ConsoleSummary](t, rec)
	}

	before := summary()
	client := "ussp-sum-" + strings.ToLower(store.NewID(time.Now())[20:])
	sub := h.createSub(t, client, validSub())
	if _, err := pool.Exec(ctx, `UPDATE deliveries SET state = 'failed', last_attempt_at = now() - interval '1 hour' WHERE id = $1`, sub.Verification.Id); err != nil {
		t.Fatal(err)
	}
	if err := store.NewDeliveryLog(writeTS).Record(ctx, store.DeliveryAttempt{At: time.Now().UTC(), DeliveryID: sub.Verification.Id,
		SubscriptionID: sub.Id, ChangeID: store.PingChangeID, Attempt: 1, LatencyMs: 12, PayloadBytes: 100, Instance: "it"}); err != nil {
		t.Fatal(err)
	}
	after := summary()
	if d := after.Subscriptions.PendingVerification - before.Subscriptions.PendingVerification; d != 1 {
		t.Errorf("pending subscriptions +%d, want +1", d)
	}
	if d := after.FailedDeliveries.Failed - before.FailedDeliveries.Failed; d != 1 {
		t.Errorf("failed deliveries +%d, want +1", d)
	}
	l := after.DeliveryLatency
	if l.Log != gen.ConsoleSummaryDeliveryLatencyLogComplete || l.Attempts < 1 || l.P50Ms == nil || l.P95Ms == nil || *l.P95Ms < *l.P50Ms {
		t.Errorf("latency %+v", l)
	}
	if strings.Contains(h.consoleDo(t, h.consoleReq(http.MethodGet, summaryPath, tok, nil)).Body.String(), client) {
		t.Error("the summary names the client")
	}
	if rec := h.consoleDo(t, h.consoleReq(http.MethodGet, summaryPath, h.token(client, auth.ScopeRead), nil)); rec.Code != http.StatusForbidden {
		t.Errorf("machine token: %d %s", rec.Code, rec.Body.String())
	}
	if rec := h.consoleDo(t, h.consoleReq(http.MethodGet, summaryPath, "", nil)); rec.Code != http.StatusUnauthorized {
		t.Errorf("no session: %d %s", rec.Code, rec.Body.String())
	}
}
