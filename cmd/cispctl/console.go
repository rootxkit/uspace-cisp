package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/rootxkit/uspace-cisp/internal/config"
	"github.com/rootxkit/uspace-cisp/internal/console"
	"github.com/rootxkit/uspace-cisp/internal/jws"
	"github.com/rootxkit/uspace-cisp/internal/store"
)

// The console's operations commands (WP-8): the first admin of a fresh
// deployment, the audit export and its verification, and the monthly
// partitions of events.

// cispctlActor is the events actor of what cispctl writes.
var cispctlActor = console.Actor{ID: "cispctl", Role: "operator", Type: store.ActorSystem}

// noSessions refuses to sign: cispctl creates accounts, it never logs in.
type noSessions struct{}

func (noSessions) Issue(string, string, string, time.Time, time.Time) (string, error) {
	return "", errors.New("cispctl issues no sessions")
}

func createAccount(ctx context.Context, args, environ []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("create-account", flag.ContinueOnError)
	fs.SetOutput(stderr)
	username := fs.String("username", "", "the account's username (lower case, 3-64 of a-z 0-9 . _ -)")
	role := fs.String("role", "", "viewer, publisher_admin or admin")
	mfa := fs.Bool("mfa", false, "require TOTP (always on for admin)")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *username == "" || *role == "" {
		_, _ = fmt.Fprint(stderr, usage)
		return exitUsage
	}
	cfg, err := config.LoadCtl(environ)
	if printProblems(stderr, "cispctl", err) {
		return exitConfig
	}
	sealer, err := console.LoadSealer(cfg.SecretsKeyFile)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "cispctl: %v\n", err)
		return exitConfig
	}
	pool, code := openTree(ctx, store.TreeRelational, environ, stderr)
	if code != exitOK {
		return code
	}
	defer pool.Close()
	acc, err := console.NewAccounts(console.Config{Store: store.New(pool, store.Options{}), Sessions: noSessions{}, Sealer: sealer})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "cispctl: %v\n", err)
		return exitFailed
	}
	created, err := acc.Create(ctx, cispctlActor, *username, *role, *mfa)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "cispctl: create-account: %v\n", err)
		return exitFailed
	}
	a := created.Account
	_, _ = fmt.Fprintf(stdout, "account %s created: id %s, role %s, mfa_required %v\n", a.Username, a.ID, a.Role, a.MFARequired)
	_, _ = fmt.Fprintf(stdout, "one-time password (shown once): %s\n", created.Password)
	if created.TOTPURL != "" {
		_, _ = fmt.Fprintf(stdout, "TOTP (enrol it in an authenticator now; shown once): %s\n", created.TOTPURL)
	}
	return exitOK
}

// rangeFlags are --from and --to (RFC 3339; the defaults are the
// beginning of time and now).
type rangeFlags struct{ from, to *string }

func addRange(fs *flag.FlagSet) rangeFlags {
	return rangeFlags{
		from: fs.String("from", "1970-01-01T00:00:00Z", "the first ts included (RFC 3339)"),
		to:   fs.String("to", "", "the first ts excluded (RFC 3339; default now)"),
	}
}

func (r rangeFlags) parse(now time.Time) (time.Time, time.Time, error) {
	f, err := time.Parse(time.RFC3339, *r.from)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("--from: %w", err)
	}
	t := now
	if *r.to != "" {
		if t, err = time.Parse(time.RFC3339, *r.to); err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("--to: %w", err)
		}
	}
	if !f.Before(t) {
		return time.Time{}, time.Time{}, errors.New("--from must be before --to")
	}
	return f.UTC(), t.UTC(), nil
}

func verifyAudit(ctx context.Context, args, environ []string, stdout, stderr io.Writer, now time.Time) int {
	fs := flag.NewFlagSet("verify-audit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	rf := addRange(fs)
	err := fs.Parse(args)
	if err == nil && fs.NArg() != 0 {
		err = fmt.Errorf("unexpected arguments %v", fs.Args())
	}
	var from, to time.Time
	if err == nil {
		from, to, err = rf.parse(now)
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "cispctl: verify-audit: %v\n%s", err, usage)
		return exitUsage
	}
	pool, code := openTree(ctx, store.TreeRelational, environ, stderr)
	if code != exitOK {
		return code
	}
	defer pool.Close()
	var first, last int64
	n, err := store.New(pool, store.Options{}).EventsInRange(ctx, from, to, func(prev []byte, r store.AuditRow) error {
		if first == 0 {
			first = r.ID
		}
		last = r.ID
		return console.CheckRow(prev, r)
	})
	var br *console.ChainBreakError
	switch {
	case errors.As(err, &br):
		_, _ = fmt.Fprintf(stdout, "verify-audit: BROKEN: %v (%d rows verified before it)\n", br, n)
		return exitFailed
	case err != nil:
		_, _ = fmt.Fprintf(stderr, "cispctl: verify-audit: %v\n", err)
		return exitFailed
	case n == 0:
		_, _ = fmt.Fprintf(stdout, "verify-audit: 0 rows from %s to %s; nothing to verify\n", from.Format(time.RFC3339), to.Format(time.RFC3339))
		return exitOK
	}
	_, _ = fmt.Fprintf(stdout, "verify-audit: %d rows verified (ids %d..%d, %s to %s); the hash chain is intact\n",
		n, first, last, from.Format(time.RFC3339), to.Format(time.RFC3339))
	return exitOK
}

func exportAudit(ctx context.Context, args, environ []string, stdout, stderr io.Writer, now time.Time) int {
	fs := flag.NewFlagSet("export-audit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "", "the JSON-lines file to write (must not exist); the signature is written beside it as <out>.jws")
	rf := addRange(fs)
	err := fs.Parse(args)
	if err == nil && fs.NArg() != 0 {
		err = fmt.Errorf("unexpected arguments %v", fs.Args())
	}
	var from, to time.Time
	if err == nil {
		from, to, err = rf.parse(now)
	}
	if err != nil || *out == "" {
		if err == nil {
			err = errors.New("--out is required")
		}
		_, _ = fmt.Fprintf(stderr, "cispctl: export-audit: %v\n%s", err, usage)
		return exitUsage
	}
	cfg, err := config.LoadCtl(environ)
	if printProblems(stderr, "cispctl", err) {
		return exitConfig
	}
	if cfg.SigningKeyFile == "" {
		_, _ = fmt.Fprintf(stderr, "cispctl: export-audit: %s is not set: the export is signed with the CISP's key ring\n", config.EnvSigningKeyFile)
		return exitConfig
	}
	keys, err := jws.ReadKeyRing(cfg.SigningKeyFile, cfg.SigningKID, cfg.SigningKeyPrevFile, cfg.SigningKIDPrev)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "cispctl: export-audit: signing key: %v\n", err)
		return exitConfig
	}
	pool, code := openTree(ctx, store.TreeRelational, environ, stderr)
	if code != exitOK {
		return code
	}
	defer pool.Close()
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "cispctl: export-audit: %v\n", err)
		return exitFailed
	}
	w := bufio.NewWriter(f)
	n, err := store.New(pool, store.Options{}).EventsInRange(ctx, from, to, func(_ []byte, r store.AuditRow) error {
		line, err := console.ExportLine(r)
		if err != nil {
			return err
		}
		_, err = w.Write(line)
		return err
	})
	if err == nil {
		err = w.Flush()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "cispctl: export-audit: %v; %s is incomplete\n", err, *out)
		return exitFailed
	}
	body, err := os.ReadFile(*out)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "cispctl: export-audit: %v\n", err)
		return exitFailed
	}
	sig, err := keys.SignDetached(body, now)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "cispctl: export-audit: sign: %v\n", err)
		return exitFailed
	}
	if err := os.WriteFile(*out+".jws", []byte(sig+"\n"), 0o600); err != nil { //nolint:gosec // G703: the path is the operator's own --out
		_, _ = fmt.Fprintf(stderr, "cispctl: export-audit: %v\n", err)
		return exitFailed
	}
	_, _ = fmt.Fprintf(stdout, "export-audit: %d rows (%s to %s) written to %s; detached JWS (kid %s) in %s.jws\n",
		n, from.Format(time.RFC3339), to.Format(time.RFC3339), *out, keys.ActiveKID(), *out)
	return exitOK
}

func partitions(ctx context.Context, args, environ []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("partitions", flag.ContinueOnError)
	fs.SetOutput(stderr)
	months := fs.Int("ensure-months", 3, "create the events partitions from this month through this many months ahead")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *months < 0 || *months > 120 {
		_, _ = fmt.Fprint(stderr, usage)
		return exitUsage
	}
	pool, code := openTree(ctx, store.TreeRelational, environ, stderr)
	if code != exitOK {
		return code
	}
	defer pool.Close()
	created, err := store.New(pool, store.Options{}).EnsureEventPartitions(ctx, *months)
	for _, c := range created {
		_, _ = fmt.Fprintf(stdout, "partitions: created %s\n", c)
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "cispctl: partitions: %v\n", err)
		return exitFailed
	}
	if len(created) == 0 {
		_, _ = fmt.Fprintf(stdout, "partitions: every partition through %d months ahead exists\n", *months)
	}
	return exitOK
}
