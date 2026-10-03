package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rootxkit/uspace-cisp/internal/console"
	"github.com/rootxkit/uspace-cisp/internal/store"
)

// EnvBackupAdminURL names the variable holding the URL of a PostgreSQL
// role that may create and drop databases, for verify-backup's scratch
// database. Not a CISP_* variable: no process reads it, and it is never
// in deploy/.env.
const EnvBackupAdminURL = "VERIFY_BACKUP_ADMIN_URL"

// dumpGlob matches the relational dumps deploy/backup/backup.sh writes
// (cisp-<UTC stamp>.dump, pg_dump -Fc); the timeseries ones are
// cisp_ts-<UTC stamp>.dump and never match.
const dumpGlob = "cisp-*.dump"

// afterRestore runs between the restore and the checks; tests set it to
// tamper with the restored copy.
var afterRestore func(ctx context.Context, scratch *pgxpool.Pool) error

// verifyBackup is the weekly restore test (docs/RUNBOOKS/backup-restore.md,
// predecessor S-22, S-23): it restores the latest relational dump into a
// scratch database with pg_restore and checks what a restore must keep:
// every dataset's current_version is its newest publication, every
// publication's body still has its body_sha256, and the events hash
// chain is intact. The scratch database is dropped afterwards, whatever
// happened.
func verifyBackup(ctx context.Context, args, environ []string, stdout, stderr io.Writer, now time.Time) int {
	fs := flag.NewFlagSet("verify-backup", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dump := fs.String("dump", "", "a relational dump (pg_dump -Fc) or a directory of them (the newest "+dumpGlob+" by name)")
	pgRestore := fs.String("pg-restore", "pg_restore", "the pg_restore command (split on spaces, e.g. \"docker exec -i pg pg_restore\")")
	restoreHost := fs.String("restore-host", "", "host:port where pg_restore reaches the server (default: the admin URL's)")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *dump == "" || strings.TrimSpace(*pgRestore) == "" {
		_, _ = fmt.Fprint(stderr, usage)
		return exitUsage
	}
	adminURL := lookupEnv(environ, EnvBackupAdminURL)
	if adminURL == "" {
		_, _ = fmt.Fprintf(stderr, "cispctl: verify-backup: %s is not set (a role that may create databases)\n", EnvBackupAdminURL)
		return exitConfig
	}
	file, err := latestDump(*dump)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "cispctl: verify-backup: %v\n", err)
		return exitFailed
	}
	info, err := os.Stat(file)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "cispctl: verify-backup: %v\n", err)
		return exitFailed
	}
	_, _ = fmt.Fprintf(stdout, "verify-backup: dump %s (%d bytes, written %s)\n", file, info.Size(), info.ModTime().UTC().Format(time.RFC3339))

	admin, err := pgxpool.New(ctx, adminURL)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "cispctl: verify-backup: %s: %v\n", EnvBackupAdminURL, err)
		return exitConfig
	}
	defer admin.Close()
	scratch := fmt.Sprintf("cisp_verify_%d", now.UnixNano())
	ident := pgx.Identifier{scratch}.Sanitize() //nolint:misspell // pgx's method name
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+ident); err != nil {
		_, _ = fmt.Fprintf(stderr, "cispctl: verify-backup: create %s: %v\n", scratch, err)
		return exitFailed
	}
	defer func() {
		// A fresh context: the drop must run even when ctx is done.
		dctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := admin.Exec(dctx, "DROP DATABASE IF EXISTS "+ident+" WITH (FORCE)"); err != nil {
			_, _ = fmt.Fprintf(stderr, "cispctl: verify-backup: drop %s: %v (drop it by hand)\n", scratch, err)
			return
		}
		_, _ = fmt.Fprintf(stdout, "verify-backup: scratch database %s dropped\n", scratch)
	}()
	scratchURL, restoreURL, err := scratchURLs(adminURL, scratch, *restoreHost)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "cispctl: verify-backup: %v\n", err)
		return exitConfig
	}
	if err := restore(ctx, strings.Fields(*pgRestore), restoreURL, file, stderr); err != nil {
		_, _ = fmt.Fprintf(stdout, "verify-backup: FAILED: the dump does not restore: %v\n", err)
		return exitFailed
	}
	_, _ = fmt.Fprintf(stdout, "verify-backup: restored into %s\n", scratch)
	pool, err := pgxpool.New(ctx, scratchURL)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "cispctl: verify-backup: %v\n", err)
		return exitFailed
	}
	defer pool.Close()
	if afterRestore != nil {
		if err := afterRestore(ctx, pool); err != nil {
			_, _ = fmt.Fprintf(stderr, "cispctl: verify-backup: %v\n", err)
			return exitFailed
		}
	}
	problems, err := verifyRestored(ctx, pool, now, stdout)
	pool.Close()
	switch {
	case err != nil:
		_, _ = fmt.Fprintf(stderr, "cispctl: verify-backup: %v\n", err)
		return exitFailed
	case len(problems) > 0:
		for _, p := range problems {
			_, _ = fmt.Fprintf(stdout, "verify-backup: FAILED: %s\n", p)
		}
		return exitFailed
	}
	_, _ = fmt.Fprintln(stdout, "verify-backup: ok")
	return exitOK
}

func lookupEnv(environ []string, name string) string {
	v := ""
	for _, kv := range environ {
		if k, val, ok := strings.Cut(kv, "="); ok && k == name {
			v = val
		}
	}
	return v
}

// latestDump is path itself, or the newest cisp-*.dump in it by name (the
// names carry a UTC stamp, so the order of names is the order of time).
func latestDump(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return path, nil
	}
	matches, err := filepath.Glob(filepath.Join(path, dumpGlob))
	if err != nil {
		return "", err
	}
	if len(matches) == 0 {
		return "", fmt.Errorf("no %s in %s: the backup job has not written one", dumpGlob, path)
	}
	sort.Strings(matches)
	return matches[len(matches)-1], nil
}

// scratchURLs are the admin URL pointed at the scratch database, and
// the same with restoreHost as its host:port for pg_restore.
func scratchURLs(adminURL, scratch, restoreHost string) (string, string, error) {
	u, err := url.Parse(adminURL)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Host == "" {
		return "", "", fmt.Errorf("%s must be a postgres:// URL with a host", EnvBackupAdminURL)
	}
	u.Path = "/" + scratch
	own := u.String()
	if restoreHost != "" {
		u.Host = restoreHost
	}
	return own, u.String(), nil
}

// restore runs pg_restore with the dump on stdin into dbURL: no owners
// or privileges (the scratch database is the admin's), stop at the
// first error.
func restore(ctx context.Context, cmdline []string, dbURL, file string, stderr io.Writer) error {
	f, err := os.Open(file) //nolint:gosec // the operator names the dump
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	args := append(append([]string{}, cmdline[1:]...), "--no-owner", "--no-privileges", "--exit-on-error", "--dbname", dbURL)
	cmd := exec.CommandContext(ctx, cmdline[0], args...) //nolint:gosec // the operator's pg_restore
	cmd.Stdin = f
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		_, _ = fmt.Fprintf(stderr, "%s", tailLines(out.String(), 20))
		return fmt.Errorf("%s: %w", cmdline[0], err)
	}
	return nil
}

func tailLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	if len(lines) == 1 && lines[0] == "" {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}

// verifyRestored checks a restored relational database and returns what
// is wrong (nothing: intact). It prints what it counted.
func verifyRestored(ctx context.Context, pool *pgxpool.Pool, now time.Time, stdout io.Writer) ([]string, error) {
	var problems []string
	rows, err := pool.Query(ctx, `SELECT d.name, d.current_version, coalesce(max(p.version), 0)
		FROM datasets d LEFT JOIN publications p ON p.dataset = d.name
		GROUP BY d.name, d.current_version ORDER BY d.name`)
	if err != nil {
		return nil, fmt.Errorf("datasets: %w", err)
	}
	var summary []string
	for rows.Next() {
		var name string
		var current, newest int64
		if err := rows.Scan(&name, &current, &newest); err != nil {
			rows.Close()
			return nil, err
		}
		summary = append(summary, fmt.Sprintf("%s:%d", name, current))
		if current != newest {
			problems = append(problems, fmt.Sprintf("dataset %s: current_version %d, but its newest publication is version %d", name, current, newest))
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(summary) == 0 {
		problems = append(problems, "no datasets rows: this is not a migrated CISP database")
	}
	_, _ = fmt.Fprintf(stdout, "verify-backup: current versions %s\n", strings.Join(summary, ", "))

	var total, bad int64
	var firstBad *string
	if err := pool.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE sha256(body) <> body_sha256),
		min(dataset || ':' || version) FILTER (WHERE sha256(body) <> body_sha256) FROM publications`).Scan(&total, &bad, &firstBad); err != nil {
		return nil, fmt.Errorf("publications: %w", err)
	}
	_, _ = fmt.Fprintf(stdout, "verify-backup: %d publications, %d whose body no longer matches body_sha256\n", total, bad)
	if bad > 0 {
		problems = append(problems, fmt.Sprintf("%d publications whose body does not match body_sha256 (first %s)", bad, deref(firstBad)))
	}

	n, err := store.New(pool, store.Options{}).EventsInRange(ctx, time.Unix(0, 0).UTC(), now.Add(time.Hour), console.CheckRow)
	var br *console.ChainBreakError
	switch {
	case errors.As(err, &br):
		problems = append(problems, fmt.Sprintf("events hash chain broken: %v (%d rows verified before it)", br, n))
	case err != nil:
		return nil, fmt.Errorf("events: %w", err)
	default:
		_, _ = fmt.Fprintf(stdout, "verify-backup: %d events, the hash chain is intact\n", n)
	}
	return problems, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
