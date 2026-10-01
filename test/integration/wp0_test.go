//go:build integration

// Package integration runs against real PostgreSQL + PostGIS,
// TimescaleDB and NATS JetStream (make dev-deps, or the CI services).
// A missing address fails the test: a suite that skips proves nothing,
// and make integration fails when zero tests ran.
package integration

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib" // database/sql driver "pgx" for goose
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/pressly/goose/v3"
)

func mustEnv(t *testing.T, name string) string {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		t.Fatalf("%s is not set; run make dev-deps and export it (see the Makefile's integration target)", name)
	}
	return v
}

func connect(t *testing.T, url string) *pgx.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn
}

func TestRelationalAcceptsPostGIS(t *testing.T) {
	conn := connect(t, mustEnv(t, "CISP_TEST_DATABASE_URL"))
	ctx := context.Background()
	if _, err := conn.Exec(ctx, "CREATE EXTENSION IF NOT EXISTS postgis"); err != nil {
		t.Fatalf("create extension postgis: %v", err)
	}
	var version string
	if err := conn.QueryRow(ctx, "SELECT postgis_lib_version()").Scan(&version); err != nil {
		t.Fatalf("postgis_lib_version: %v", err)
	}
	t.Logf("postgis %s", version)
}

func TestTimeseriesAcceptsTimescaleDB(t *testing.T) {
	conn := connect(t, mustEnv(t, "CISP_TEST_TIMESERIES_URL"))
	ctx := context.Background()
	if _, err := conn.Exec(ctx, "CREATE EXTENSION IF NOT EXISTS timescaledb"); err != nil {
		t.Fatalf("create extension timescaledb: %v", err)
	}
	var version string
	if err := conn.QueryRow(ctx, "SELECT extversion FROM pg_extension WHERE extname = 'timescaledb'").Scan(&version); err != nil {
		t.Fatalf("timescaledb version: %v", err)
	}
	t.Logf("timescaledb %s", version)
}

// The migration files apply up and down through goose with the version
// table each tree is named for (docs/PLAN.md D11). WP-1 owns the runner;
// this proves the WP-0 files are valid goose SQL.
func TestMigrationTreesUpAndDown(t *testing.T) {
	cases := []struct {
		tree, env, table string
		check            string
		want             int
	}{
		{"relational", "CISP_TEST_DATABASE_URL", "goose_db_version_relational", "SELECT count(*) FROM datasets", 4},
		{"timeseries", "CISP_TEST_TIMESERIES_URL", "goose_db_version_timeseries", "SELECT count(*) FROM pg_extension WHERE extname = 'timescaledb'", 1},
	}
	for _, c := range cases {
		t.Run(c.tree, func(t *testing.T) {
			db, err := sql.Open("pgx", mustEnv(t, c.env))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			dir := filepath.Join("..", "..", "migrations", c.tree)
			p, err := goose.NewProvider(goose.DialectPostgres, db, os.DirFS(dir), goose.WithTableName(c.table))
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			if _, err := p.Up(ctx); err != nil {
				t.Fatalf("up: %v", err)
			}
			var n int
			if err := db.QueryRowContext(ctx, c.check).Scan(&n); err != nil || n != c.want {
				t.Fatalf("after up: %q = %d (%v), want %d", c.check, n, err, c.want)
			}
			var applied int
			if err := db.QueryRowContext(ctx, "SELECT count(*) FROM "+c.table+" WHERE version_id = 1 AND is_applied").Scan(&applied); err != nil || applied != 1 {
				t.Fatalf("version table %s: %d (%v)", c.table, applied, err)
			}
			if _, err := p.DownTo(ctx, 0); err != nil {
				t.Fatalf("down: %v", err)
			}
			if c.tree == "relational" {
				var exists bool
				if err := db.QueryRowContext(ctx, "SELECT to_regclass('datasets') IS NOT NULL").Scan(&exists); err != nil || exists {
					t.Errorf("datasets still exists after down (%v)", err)
				}
			}
			// Leave the database as the next run expects it: migrated.
			if _, err := p.Up(ctx); err != nil {
				t.Fatalf("up again: %v", err)
			}
		})
	}
}

func TestNATSAnswersJetStream(t *testing.T) {
	nc, err := nats.Connect(mustEnv(t, "CISP_TEST_NATS_URL"), nats.Timeout(5*time.Second))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer nc.Close()
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	info, err := js.AccountInfo(ctx)
	if err != nil {
		t.Fatalf("JetStream account info (is nats running with -js?): %v", err)
	}
	t.Logf("jetstream: %d streams, %d bytes of storage used", info.Streams, info.Store)
}
