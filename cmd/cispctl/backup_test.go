package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The refusals before anything connects, each naming what is wrong.
func TestVerifyBackupRefusesBeforeConnecting(t *testing.T) {
	dir := t.TempDir()
	admin := EnvBackupAdminURL + "=postgres://u:p@127.0.0.1:1/postgres?connect_timeout=1"
	cases := []struct {
		name string
		args []string
		env  []string
		code int
		want string
	}{
		{"no dump", []string{"verify-backup"}, []string{admin}, exitUsage, "usage"},
		{"an argument", []string{"verify-backup", "--dump", dir, "extra"}, []string{admin}, exitUsage, "usage"},
		{"no admin URL", []string{"verify-backup", "--dump", dir}, nil, exitConfig, EnvBackupAdminURL + " is not set"},
		{"no dump in the directory", []string{"verify-backup", "--dump", dir}, []string{admin}, exitFailed, "the backup job has not written one"},
		{"no such dump", []string{"verify-backup", "--dump", filepath.Join(dir, "none.dump")}, []string{admin}, exitFailed, "none.dump"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, out, errOut := runCtl(c.args, c.env)
			if code != c.code || !strings.Contains(out+errOut, c.want) {
				t.Fatalf("= %d %q %q, want %d %q", code, out, errOut, c.code, c.want)
			}
		})
	}
	// The twin: with a dump present the command gets as far as the
	// database, and says it cannot create the scratch one.
	if err := os.WriteFile(filepath.Join(dir, "cisp-20261003T020000Z.dump"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := runCtl([]string{"verify-backup", "--dump", dir}, []string{admin})
	if code != exitFailed || !strings.Contains(out, "cisp-20261003T020000Z.dump") || !strings.Contains(errOut, "create cisp_verify_") {
		t.Fatalf("with a dump = %d %q %q", code, out, errOut)
	}
}

// The newest dump of a directory by name; a file is itself.
func TestLatestDump(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"cisp-20261001T020000Z.dump", "cisp-20261003T020000Z.dump", "cisp-20261002T020000Z.dump", "cisp_ts-20261009T020000Z.dump", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(dir, n), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := latestDump(dir)
	if err != nil || filepath.Base(got) != "cisp-20261003T020000Z.dump" {
		t.Fatalf("latest = %q %v", got, err)
	}
	file := filepath.Join(dir, "cisp-20261001T020000Z.dump")
	if got, err := latestDump(file); err != nil || got != file {
		t.Fatalf("file = %q %v", got, err)
	}
}

func TestScratchURLs(t *testing.T) {
	own, restore, err := scratchURLs("postgres://admin:pw@127.0.0.1:15432/postgres?sslmode=disable", "cisp_verify_1", "127.0.0.1:5432")
	if err != nil || own != "postgres://admin:pw@127.0.0.1:15432/cisp_verify_1?sslmode=disable" ||
		restore != "postgres://admin:pw@127.0.0.1:5432/cisp_verify_1?sslmode=disable" {
		t.Fatalf("= %q %q %v", own, restore, err)
	}
	own, restore, _ = scratchURLs("postgres://admin@db/postgres", "x", "")
	if own != restore {
		t.Errorf("without --restore-host: %q %q", own, restore)
	}
	for _, bad := range []string{"mysql://db/x", "postgres:///x", "::"} {
		if _, _, err := scratchURLs(bad, "x", ""); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
