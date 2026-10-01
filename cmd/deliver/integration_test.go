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
