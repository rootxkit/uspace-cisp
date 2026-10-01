//go:build integration

package main

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/rootxkit/uspace-cisp/internal/store"
)

// The api never migrates: with a migration pending it names it and
// exits 2; with none pending it starts and /readyz is ready on the
// database and the migrations (E-01 pair).
func TestRunRefusesPendingMigrations(t *testing.T) {
	url := os.Getenv("CISP_TEST_DATABASE_URL")
	if url == "" {
		t.Fatal("CISP_TEST_DATABASE_URL is not set; run make dev-deps")
	}
	ctx := context.Background()
	pool, err := store.OpenPool(ctx, store.PoolConfig{URL: url, ApplicationName: "uspace-cisp-test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	db := store.OpenSQL(pool)
	t.Cleanup(func() { _ = db.Close() })
	if _, err := store.Up(ctx, db, store.TreeRelational); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DownTo(ctx, db, store.TreeRelational, 5); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := store.Up(context.Background(), db, store.TreeRelational); err != nil {
			t.Errorf("up again: %v", err)
		}
	})

	env := []string{"CISP_HTTP_ADDR=127.0.0.1:0", "CISP_DATABASE_URL=" + url}
	logs := &syncBuffer{}
	if c := run(ctx, nil, env, logs, io.Discard); c != 2 {
		t.Fatalf("exit %d with a pending migration, want 2: %s", c, logs.String())
	}
	if !strings.Contains(logs.String(), "migrations pending") || !strings.Contains(logs.String(), "0006_events.sql") {
		t.Errorf("the pending migration is not named: %s", logs.String())
	}

	if _, err := store.Up(ctx, db, store.TreeRelational); err != nil {
		t.Fatal(err)
	}
	r := startRun(t, env)
	code, body := get(t, r.base+"/readyz")
	if !strings.Contains(body, `"database":"ok"`) || !strings.Contains(body, `"migrations":"ok"`) {
		t.Errorf("readyz = %d %s", code, body)
	}
	t.Logf("readyz = %d %s", code, body)
	if c := r.stop(t); c != 0 {
		t.Errorf("exit %d", c)
	}
}
