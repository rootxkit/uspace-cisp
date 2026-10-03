//go:build integration

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rootxkit/uspace-cisp/internal/store"
)

// backupEnv is the PostgreSQL container of the integration database
// (pg_dump and pg_restore run inside it, the server's own version) and
// a superuser URL for the scratch databases.
func backupEnv(t *testing.T) (container, admin string) {
	t.Helper()
	container, admin = os.Getenv("CISP_TEST_PG_CONTAINER"), os.Getenv("CISP_TEST_ADMIN_URL")
	if container == "" || admin == "" {
		t.Fatal("CISP_TEST_PG_CONTAINER and CISP_TEST_ADMIN_URL must be set (make integration sets them for make dev-deps; CI for its service)")
	}
	return container, admin
}

// The weekly restore test on a good dump (ok, with what it counted), on
// the same dump restored and then tampered (an events row, a dataset's
// current_version: each named), and on a dump whose bytes are corrupted
// (it does not restore). Every scratch database is dropped.
func TestVerifyBackup(t *testing.T) {
	container, admin := backupEnv(t)
	env := append(testEnv(t), "CISP_SECRETS_KEY_FILE="+secretsKeyFile(t))
	dbPool(t)
	// At least one events row, so the chain check has something to check.
	if code, _, errOut := runCtl([]string{"create-account", "--username", "bak-" + strings.ToLower(store.NewID(time.Now())[20:]), "--role", "viewer"}, env); code != exitOK {
		t.Fatalf("create-account: %s", errOut)
	}
	dir := t.TempDir()
	dump, err := exec.Command("docker", "exec", container, "pg_dump", "-Fc", "-U", "postgres", "cisp").Output()
	if err != nil {
		t.Fatalf("pg_dump in %s: %v", container, err)
	}
	good := filepath.Join(dir, "cisp-20261003T020000Z.dump")
	if err := os.WriteFile(good, dump, 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"verify-backup", "--dump", dir, "--pg-restore", "docker exec -i " + container + " pg_restore", "--restore-host", "127.0.0.1:5432"}
	benv := []string{EnvBackupAdminURL + "=" + admin}

	code, out, errOut := runCtl(args, benv)
	t.Logf("good dump:\n%s%s", out, errOut)
	for _, want := range []string{"verify-backup: current versions ", "the hash chain is intact", "verify-backup: ok", "dropped"} {
		if code != exitOK || !strings.Contains(out, want) {
			t.Fatalf("good dump = %d, want %q in %q %q", code, want, out, errOut)
		}
	}

	for _, c := range []struct {
		name, sql, want string
	}{
		{"an events row", "UPDATE events SET entity_id = 'tampered' WHERE id = (SELECT max(id) FROM events)", "events hash chain broken"},
		{"a current_version", "UPDATE datasets SET current_version = current_version + 1 WHERE name = 'ussp_list'", "dataset ussp_list: current_version"},
	} {
		t.Run("tampered "+c.name, func(t *testing.T) {
			afterRestore = func(ctx context.Context, p *pgxpool.Pool) error {
				_, err := p.Exec(ctx, c.sql)
				return err
			}
			defer func() { afterRestore = nil }()
			code, out, errOut := runCtl(args, benv)
			t.Logf("%s", out)
			if code != exitFailed || !strings.Contains(out, "FAILED: "+c.want) || !strings.Contains(out, "dropped") {
				t.Fatalf("= %d %q %q, want FAILED: %s", code, out, errOut, c.want)
			}
		})
	}

	t.Run("corrupted bytes", func(t *testing.T) {
		bad := append([]byte{}, dump...)
		for i := len(bad) / 3; i < len(bad)/3+512 && i < len(bad); i++ {
			bad[i] ^= 0x5a
		}
		// A newer name: the newest dump of the directory is the one checked.
		if err := os.WriteFile(filepath.Join(dir, "cisp-20261004T020000Z.dump"), bad, 0o600); err != nil {
			t.Fatal(err)
		}
		code, out, errOut := runCtl(args, benv)
		t.Logf("%s%s", out, errOut)
		if code != exitFailed || !strings.Contains(out, "cisp-20261004T020000Z.dump") || !strings.Contains(out, "FAILED: the dump does not restore") {
			t.Fatalf("= %d %q %q", code, out, errOut)
		}
	})

	p, err := pgxpool.New(context.Background(), admin)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	var left int
	if err := p.QueryRow(context.Background(), "SELECT count(*) FROM pg_database WHERE datname LIKE 'cisp_verify_%'").Scan(&left); err != nil || left != 0 {
		t.Errorf("%d scratch databases left (%v)", left, err)
	}
}
