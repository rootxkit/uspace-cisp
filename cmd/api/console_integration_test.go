//go:build integration

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-cisp/internal/auth"
	"github.com/rootxkit/uspace-cisp/internal/console"
	"github.com/rootxkit/uspace-cisp/internal/store"
)

type noSigner struct{}

func (noSigner) Issue(string, string, string, time.Time, time.Time) (string, error) {
	return "", nil
}

// The api with its console on PostgreSQL, as a process: an admin made
// as cispctl makes it, a TOTP login, GET /v1/console/me, a machine
// token refused on the console and the session refused on the machine
// status, logout and the session refused after it.
func TestRunConsoleOnPostgres(t *testing.T) {
	dbURL := os.Getenv("CISP_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Fatal("CISP_TEST_DATABASE_URL is not set; run make dev-deps")
	}
	ctx := context.Background()
	pool, err := store.OpenPool(ctx, store.PoolConfig{URL: dbURL, ApplicationName: "uspace-cisp-test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	db := store.OpenSQL(pool)
	if _, err := store.Up(ctx, db, store.TreeRelational); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	sealer, err := console.NewSealer(k32())
	if err != nil {
		t.Fatal(err)
	}
	acc, err := console.NewAccounts(console.Config{Store: store.New(pool, store.Options{}), Sessions: noSigner{}, Sealer: sealer})
	if err != nil {
		t.Fatal(err)
	}
	name := "it-admin-" + strings.ToLower(store.NewID(time.Now())[20:])
	created, err := acc.Create(ctx, console.Actor{ID: "cispctl", Role: "operator", Type: store.ActorSystem}, name, auth.RoleAdmin, false)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(created.TOTPURL)
	code, err := auth.TOTPCode(u.Query().Get("secret"), time.Now())
	if err != nil {
		t.Fatal(err)
	}

	a := newAuthRig(t)
	r := startRun(t, a.env("CISP_HTTP_ADDR=127.0.0.1:0", "CISP_DATABASE_URL="+dbURL,
		"CISP_SESSION_KEY_FILE="+sessionKeyFile(t, 3072), "CISP_CONSOLE_ISSUER=https://uspace-cisp.example.test/console",
		"CISP_SECRETS_KEY_FILE="+secretsKeyFile(t)))
	waitForLine(t, r.logs, "console ready")
	status, body := do(t, http.MethodPost, r.base+"/v1/console/session", "", map[string]any{"username": name, "password": created.Password, "totp": code})
	if status != http.StatusCreated {
		t.Fatalf("login = %d %s", status, body)
	}
	var s struct {
		Token     string
		ExpiresAt time.Time `json:"expires_at"`
	}
	_ = json.Unmarshal([]byte(body), &s)
	t.Logf("POST /v1/console/session = %d (token %d bytes, expires_at %s)", status, len(s.Token), s.ExpiresAt.Format(time.RFC3339))
	status, body = do(t, http.MethodGet, r.base+"/v1/console/me", s.Token, nil)
	if status != http.StatusOK || !strings.Contains(body, `"username":"`+name+`"`) || !strings.Contains(body, `"role":"admin"`) {
		t.Fatalf("me = %d %s", status, body)
	}
	t.Logf("GET /v1/console/me = %d %s", status, strings.TrimSpace(body))
	if status, _ := do(t, http.MethodGet, r.base+"/v1/console/me", a.token(t, "cis.read"), nil); status != http.StatusForbidden {
		t.Errorf("a machine token on the console: %d", status)
	}
	if status, _ := do(t, http.MethodGet, r.base+"/v1/status", s.Token, nil); status != http.StatusForbidden {
		t.Errorf("a console session on the machine status: %d", status)
	}
	if status, _ := do(t, http.MethodDelete, r.base+"/v1/console/session", s.Token, nil); status != http.StatusNoContent {
		t.Errorf("logout: %d", status)
	}
	if status, body := do(t, http.MethodGet, r.base+"/v1/console/me", s.Token, nil); status != http.StatusUnauthorized || !strings.Contains(body, "session_revoked") {
		t.Errorf("after logout: %d %s", status, body)
	}
	if c := r.stop(t); c != 0 {
		t.Errorf("exit %d", c)
	}
}

// The api as a process with the console and the delivery log
// (CISP_TIMESERIES_URL, read as cisp_api): GET /v1/console/summary for a
// viewer is 200 with every figure and the latency read from the log;
// without a session 401, with a machine token 403.
func TestRunConsoleSummaryOnPostgres(t *testing.T) {
	dbURL, tsURL := os.Getenv("CISP_TEST_DATABASE_URL"), os.Getenv("CISP_TEST_TIMESERIES_URL")
	if dbURL == "" || tsURL == "" {
		t.Fatal("CISP_TEST_DATABASE_URL and CISP_TEST_TIMESERIES_URL must be set; run make dev-deps")
	}
	ctx := context.Background()
	open := func(u string, tree store.Tree) *store.DeliveryLog {
		p, err := store.OpenPool(ctx, store.PoolConfig{URL: u, ApplicationName: "uspace-cisp-test"})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(p.Close)
		db := store.OpenSQL(p)
		defer func() { _ = db.Close() }()
		if _, err := store.Up(ctx, db, tree); err != nil {
			t.Fatal(err)
		}
		return store.NewDeliveryLog(p)
	}
	_ = open(dbURL, store.TreeRelational)
	if err := open(tsURL, store.TreeTimeseries).Record(ctx, store.DeliveryAttempt{At: time.Now().UTC(), DeliveryID: "DEL-SUM-IT",
		SubscriptionID: "SUB-SUM-IT", ChangeID: 1, Attempt: 1, LatencyMs: 7, PayloadBytes: 10, Instance: "it"}); err != nil {
		t.Fatal(err)
	}
	pool, err := store.OpenPool(ctx, store.PoolConfig{URL: dbURL, ApplicationName: "uspace-cisp-test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	sealer, err := console.NewSealer(k32())
	if err != nil {
		t.Fatal(err)
	}
	acc, err := console.NewAccounts(console.Config{Store: store.New(pool, store.Options{}), Sessions: noSigner{}, Sealer: sealer})
	if err != nil {
		t.Fatal(err)
	}
	name := "it-viewer-" + strings.ToLower(store.NewID(time.Now())[20:])
	created, err := acc.Create(ctx, console.Actor{ID: "cispctl", Role: "operator", Type: store.ActorSystem}, name, auth.RoleViewer, false)
	if err != nil {
		t.Fatal(err)
	}

	a := newAuthRig(t)
	apiTS := strings.Replace(dbURL, "/cisp?", "/cisp_ts?", 1)
	r := startRun(t, a.env("CISP_HTTP_ADDR=127.0.0.1:0", "CISP_DATABASE_URL="+dbURL, "CISP_TIMESERIES_URL="+apiTS,
		"CISP_SESSION_KEY_FILE="+sessionKeyFile(t, 3072), "CISP_CONSOLE_ISSUER=https://uspace-cisp.example.test/console",
		"CISP_SECRETS_KEY_FILE="+secretsKeyFile(t)))
	waitForLine(t, r.logs, "console ready")
	status, body := do(t, http.MethodPost, r.base+"/v1/console/session", "", map[string]any{"username": name, "password": created.Password})
	if status != http.StatusCreated {
		t.Fatalf("login = %d %s", status, body)
	}
	var s struct{ Token string }
	_ = json.Unmarshal([]byte(body), &s)

	status, body = do(t, http.MethodGet, r.base+"/v1/console/summary", s.Token, nil)
	var sum struct {
		Subscriptions    map[string]int64 `json:"subscriptions"`
		FailedDeliveries struct {
			WindowS int `json:"window_s"`
		} `json:"failed_deliveries"`
		Ussps           map[string]int64 `json:"ussps"`
		DeliveryLatency struct {
			Log      string `json:"log"`
			Attempts int64  `json:"attempts"`
			P50Ms    *int   `json:"p50_ms"`
		} `json:"delivery_latency"`
	}
	if err := json.Unmarshal([]byte(body), &sum); err != nil || status != http.StatusOK {
		t.Fatalf("summary = %d %s (%v)", status, body, err)
	}
	t.Logf("GET /v1/console/summary = %d %s", status, strings.TrimSpace(body))
	if len(sum.Subscriptions) != 4 || sum.FailedDeliveries.WindowS != 86400 || len(sum.Ussps) != 2 ||
		sum.DeliveryLatency.Log != "complete" || sum.DeliveryLatency.Attempts < 1 || sum.DeliveryLatency.P50Ms == nil {
		t.Errorf("summary %+v", sum)
	}
	if status, body := do(t, http.MethodGet, r.base+"/v1/console/summary", "", nil); status != http.StatusUnauthorized || strings.Contains(body, "delivery_latency") {
		t.Errorf("no session: %d %s", status, body)
	}
	if status, body := do(t, http.MethodGet, r.base+"/v1/console/summary", a.token(t, "cis.read"), nil); status != http.StatusForbidden || strings.Contains(body, "delivery_latency") {
		t.Errorf("a machine token: %d %s", status, body)
	}
	if c := r.stop(t); c != 0 {
		t.Errorf("exit %d", c)
	}
}
