// Command cispctl is the CISP's operations tool: the version, the
// configuration check, the migrations of the two trees, the rebuild of
// the materialised current version, the delivery log's retention, the
// signing key rotation, the console's accounts, audit export and
// verification and events partitions (WP-8), the offline ED-269 mapping
// (WP-12), and two dev helpers that sign a body and verify a detached
// signature with a local key.
// It is never long-running and never on the request path.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rootxkit/uspace-cisp/internal/config"
	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/store"
)

// version is set at build time: -ldflags "-X main.version=<tag or sha>".
var version = "dev"

// Exit codes.
const (
	exitOK     = 0
	exitFailed = 1
	exitUsage  = 2
	exitConfig = 3
)

const usage = `usage: cispctl <command>

commands:
  version         print the version
  config check    load and validate the api, deliver and cispctl
                  configuration from the CISP_* environment; print every
                  problem, or the redacted effective values
  migrate relational|timeseries [--down-to N]
                  apply the tree's pending migrations (or roll back to
                  version N) and print the applied versions
  migrate all     apply both trees, relational first (the compose
                  migrate service)
  migrate status relational|timeseries
                  print every migration of the tree and whether it is applied
  rebuild-current --dataset zones|uspace_airspace|ussp_list
                  rebuild features_current and the current snapshot from
                  the current publication's body; print counts before and after
  set-retention --days N
                  replace the delivery log's retention policy (default 90)
  rotate-key [--out local/] [--kid K] [--force]
                  generate an RSA-3072 signing key, write signing-<kid>.pem
                  (0600) and print the CISP_SIGNING_* lines to set; refuses
                  a directory outside local/ unless --force
  create-account --username U --role viewer|publisher_admin|admin [--mfa]
                  create a console account (the first admin of a fresh
                  deployment); print its one-time password and, with MFA
                  (always for admin), the otpauth URL, each once
  export-audit --out FILE [--from T] [--to T]
                  write the events rows of [from, to) with their chain
                  hashes as JSON lines, and a detached JWS of the file by
                  the CISP's signing key to FILE.jws
  verify-audit [--from T] [--to T]
                  recompute the events hash chain over [from, to); exit 0
                  with the count verified, 1 naming the first row that
                  breaks it
  verify-backup --dump FILE|DIR [--pg-restore CMD] [--restore-host H:P]
                  restore the newest relational dump into a scratch
                  database (VERIFY_BACKUP_ADMIN_URL: a role that may
                  create databases), check every current_version, every
                  body hash and the events chain, drop it; exit 1 naming
                  what is wrong
  partitions [--ensure-months N]
                  create the monthly events partitions from this month
                  through N months ahead (default 3; run monthly)
  ed269 convert --to ed318|ed269 [--lang ka] [--max-bytes N] < in > out
                  map one document offline through uspace-core's mapping:
                  --to ed318 reads ED-269 strictly and maps it, --to ed269
                  exports ED-318; problems on stderr and exit 1
  sign --key FILE --kid K < body
                  print the X-JWS-Signature value of the body (dev helper)
  verify-signature --key FILE --kid K --sig SIG < body
                  verify a detached signature with the public half of a
                  local key through the api's verifier (dev helper)
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := runIO(ctx, os.Args[1:], os.Environ(), os.Stdin, os.Stdout, os.Stderr, time.Now())
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args, environ []string, stdout, stderr io.Writer) int {
	return runIO(ctx, args, environ, strings.NewReader(""), stdout, stderr, time.Now())
}

func runIO(ctx context.Context, args, environ []string, stdin io.Reader, stdout, stderr io.Writer, now time.Time) int {
	switch {
	case len(args) >= 1 && args[0] == "rotate-key":
		return rotateKey(args[1:], environ, stdout, stderr, now)
	case len(args) >= 1 && args[0] == "sign":
		return sign(args[1:], stdin, stdout, stderr, now)
	case len(args) >= 1 && args[0] == "verify-signature":
		return verifySignature(ctx, args[1:], stdin, stdout, stderr, now)
	case len(args) == 1 && args[0] == "version":
		_, _ = fmt.Fprintln(stdout, version)
		return exitOK
	case len(args) == 2 && args[0] == "config" && args[1] == "check":
		return configCheck(environ, stdout, stderr)
	case len(args) == 3 && args[0] == "migrate" && args[1] == "status":
		return migrateStatus(ctx, args[2], environ, stdout, stderr)
	case len(args) == 2 && args[0] == "migrate" && args[1] == "all":
		return migrateAll(ctx, environ, stdout, stderr)
	case len(args) >= 2 && args[0] == "migrate":
		return migrate(ctx, args[1:], environ, stdout, stderr)
	case len(args) >= 1 && args[0] == "rebuild-current":
		return rebuildCurrent(ctx, args[1:], environ, stdout, stderr)
	case len(args) >= 1 && args[0] == "set-retention":
		return setRetention(ctx, args[1:], environ, stdout, stderr)
	case len(args) >= 1 && args[0] == "create-account":
		return createAccount(ctx, args[1:], environ, stdout, stderr)
	case len(args) >= 1 && args[0] == "verify-audit":
		return verifyAudit(ctx, args[1:], environ, stdout, stderr, now)
	case len(args) >= 1 && args[0] == "verify-backup":
		return verifyBackup(ctx, args[1:], environ, stdout, stderr, now)
	case len(args) >= 1 && args[0] == "export-audit":
		return exportAudit(ctx, args[1:], environ, stdout, stderr, now)
	case len(args) >= 1 && args[0] == "partitions":
		return partitions(ctx, args[1:], environ, stdout, stderr)
	case len(args) >= 1 && args[0] == "ed269":
		return ed269Convert(args[1:], stdin, stdout, stderr)
	default:
		_, _ = fmt.Fprint(stderr, usage)
		return exitUsage
	}
}

type redactor interface {
	Redacted() map[string]string
}

func configCheck(environ []string, stdout, stderr io.Writer) int {
	api, errAPI := config.LoadAPI(environ)
	deliver, errDeliver := config.LoadDeliver(environ)
	ctl, errCtl := config.LoadCtl(environ)

	failed := printProblems(stderr, "api", errAPI)
	failed = printProblems(stderr, "deliver", errDeliver) || failed
	failed = printProblems(stderr, "cispctl", errCtl) || failed
	if failed {
		return exitConfig
	}

	merged := map[string]string{}
	for _, r := range []redactor{api, deliver, ctl} {
		for k, v := range r.Redacted() {
			merged[k] = v
		}
	}
	names := make([]string, 0, len(merged))
	for k := range merged {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		_, _ = fmt.Fprintf(stdout, "%s=%s\n", k, merged[k])
	}
	_, _ = fmt.Fprintln(stdout, "config check: ok")
	return exitOK
}

// printProblems writes every problem of err, prefixed by the process,
// and reports whether there was any.
func printProblems(stderr io.Writer, process string, err error) bool {
	if err == nil {
		return false
	}
	var probs config.FieldErrors
	if errors.As(err, &probs) {
		for _, p := range probs {
			_, _ = fmt.Fprintf(stderr, "%s: %s: %s\n", process, p.Field, p.Reason)
		}
		return true
	}
	_, _ = fmt.Fprintf(stderr, "%s: %v\n", process, err)
	return true
}

// openTree loads the configuration and opens the pool of the tree's
// database. The returned code is non-zero when it could not.
func openTree(ctx context.Context, tree store.Tree, environ []string, stderr io.Writer) (*pgxpool.Pool, int) {
	cfg, err := config.LoadCtl(environ)
	if printProblems(stderr, "cispctl", err) {
		return nil, exitConfig
	}
	url, name, maxConns := cfg.DatabaseURL, config.EnvDatabaseURL, cfg.DatabaseMaxConns
	if tree == store.TreeTimeseries {
		url, name, maxConns = cfg.TimeseriesURL, config.EnvTimeseriesURL, cfg.TimeseriesMaxConns
	}
	if url == "" {
		_, _ = fmt.Fprintf(stderr, "cispctl: %s is not set\n", name)
		return nil, exitConfig
	}
	pool, err := store.OpenPool(ctx, store.PoolConfig{URL: url, ApplicationName: "uspace-cisp-cispctl", MaxConns: int32(maxConns)})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "cispctl: %v\n", err)
		return nil, exitConfig
	}
	return pool, exitOK
}

func migrate(ctx context.Context, args, environ []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return exitUsage
	}
	tree, err := store.ParseTree(args[0])
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "cispctl: %v\n%s", err, usage)
		return exitUsage
	}
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	downTo := fs.Int64("down-to", -1, "roll back to this version (0 is empty)")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return exitUsage
	}
	pool, code := openTree(ctx, tree, environ, stderr)
	if code != exitOK {
		return code
	}
	defer pool.Close()
	db := store.OpenSQL(pool)
	defer func() { _ = db.Close() }()

	var results []store.MigrationResult
	verb := "applied"
	if *downTo >= 0 {
		verb = "rolled back"
		results, err = store.DownTo(ctx, db, tree, *downTo)
	} else {
		results, err = store.Up(ctx, db, tree)
	}
	for _, r := range results {
		_, _ = fmt.Fprintf(stdout, "%s: %s %s (%d ms)\n", tree, verb, r.File, r.Duration.Milliseconds())
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "cispctl: %v\n", err)
		return exitFailed
	}
	st, err := store.Status(ctx, db, tree)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "cispctl: %v\n", err)
		return exitFailed
	}
	var applied, pending []string
	for _, s := range st {
		if s.Applied {
			applied = append(applied, strconv.FormatInt(s.Version, 10))
		} else {
			pending = append(pending, s.File)
		}
	}
	if len(applied) == 0 {
		applied = []string{"none"}
	}
	line := fmt.Sprintf("%s: applied versions %s", tree, strings.Join(applied, ", "))
	if len(pending) == 0 {
		line += "; nothing pending"
	} else {
		line += "; pending " + strings.Join(pending, ", ")
	}
	_, _ = fmt.Fprintln(stdout, line)
	return exitOK
}

// migrateAll applies both trees, relational first, and stops at the
// first that fails: the one-shot compose service (deploy/compose.yml),
// which has no shell to run two commands.
func migrateAll(ctx context.Context, environ []string, stdout, stderr io.Writer) int {
	for _, tree := range []string{"relational", "timeseries"} {
		if code := migrate(ctx, []string{tree}, environ, stdout, stderr); code != exitOK {
			return code
		}
	}
	return exitOK
}

func migrateStatus(ctx context.Context, name string, environ []string, stdout, stderr io.Writer) int {
	tree, err := store.ParseTree(name)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "cispctl: %v\n%s", err, usage)
		return exitUsage
	}
	pool, code := openTree(ctx, tree, environ, stderr)
	if code != exitOK {
		return code
	}
	defer pool.Close()
	db := store.OpenSQL(pool)
	defer func() { _ = db.Close() }()
	st, err := store.Status(ctx, db, tree)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "cispctl: %v\n", err)
		return exitFailed
	}
	for _, s := range st {
		state := "pending"
		if s.Applied {
			state = "applied " + s.AppliedAt.UTC().Format("2006-01-02T15:04:05Z")
		}
		_, _ = fmt.Fprintf(stdout, "%s: %s %s\n", tree, s.File, state)
	}
	return exitOK
}

func rebuildCurrent(ctx context.Context, args, environ []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("rebuild-current", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dataset := fs.String("dataset", "", "the dataset to rebuild")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *dataset == "" {
		_, _ = fmt.Fprint(stderr, usage)
		return exitUsage
	}
	ds := publication.Dataset(*dataset)
	if !ds.Valid() {
		_, _ = fmt.Fprintf(stderr, "cispctl: %q is not a dataset\n", *dataset)
		return exitUsage
	}
	pool, code := openTree(ctx, store.TreeRelational, environ, stderr)
	if code != exitOK {
		return code
	}
	defer pool.Close()
	// No signer until WP-2: a snapshot whose bytes are unchanged keeps
	// its signature, and one that changed refuses the rebuild.
	rep, err := store.New(pool, store.Options{}).RebuildCurrent(ctx, ds, nil)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "cispctl: %s: %v; nothing was changed\n", ds, err)
		return exitFailed
	}
	snapshot := "kept (same bytes, same signature)"
	if rep.SnapshotRebuilt {
		snapshot = "rebuilt and signed"
	}
	if rep.Version == 0 {
		snapshot = "none (never published)"
	}
	_, _ = fmt.Fprintf(stdout, "%s version %d: features_current %d rows before, %d after; snapshot %s\n",
		ds, rep.Version, rep.FeaturesBefore, rep.FeaturesAfter, snapshot)
	return exitOK
}

func setRetention(ctx context.Context, args, environ []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("set-retention", flag.ContinueOnError)
	fs.SetOutput(stderr)
	days := fs.Int("days", store.DefaultDeliveryLogRetentionDays, "days the delivery log is kept")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return exitUsage
	}
	if *days < 1 || *days > store.MaxDeliveryLogRetentionDays {
		_, _ = fmt.Fprintf(stderr, "cispctl: --days %d is outside 1..%d\n", *days, store.MaxDeliveryLogRetentionDays)
		return exitUsage
	}
	pool, code := openTree(ctx, store.TreeTimeseries, environ, stderr)
	if code != exitOK {
		return code
	}
	defer pool.Close()
	if err := store.SetRetention(ctx, pool, *days); err != nil {
		_, _ = fmt.Fprintf(stderr, "cispctl: %v\n", err)
		return exitFailed
	}
	policies, err := store.Policies(ctx, pool)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "cispctl: %v\n", err)
		return exitFailed
	}
	for _, p := range policies {
		_, _ = fmt.Fprintf(stdout, "delivery_attempts: job %d %s %s\n", p.JobID, p.Proc, p.Config)
	}
	return exitOK
}
