// Command api is the CISP's HTTP API process: the routes of
// api/openapi.yaml, /healthz, /readyz and /metrics. It stops cleanly on
// SIGTERM or interrupt: in-flight requests finish within
// CISP_SHUTDOWN_TIMEOUT_S, then the listener and the clients close.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/rootxkit/uspace-cisp/internal/auth"
	"github.com/rootxkit/uspace-cisp/internal/config"
	"github.com/rootxkit/uspace-cisp/internal/httpapi"
	"github.com/rootxkit/uspace-cisp/internal/obs"
	"github.com/rootxkit/uspace-cisp/internal/store"
)

const process = "api"

// version is set at build time: -ldflags "-X main.version=<tag or sha>".
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Environ(), os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

// run is the whole process; it returns the exit code. ctx ending is the
// stop signal.
func run(ctx context.Context, args, environ []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(process, flag.ContinueOnError)
	fs.SetOutput(stderr)
	probe := fs.String("probe", "", "GET this path on the local listener (CISP_HTTP_ADDR) and exit 0 on 200, 1 otherwise; the container health check")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	level := new(slog.LevelVar)
	logger := obs.NewLogger(stdout, process, level)

	cfg, err := config.LoadAPI(environ)
	if err != nil {
		logConfigProblems(ctx, logger, err)
		return 2
	}
	level.Set(cfg.Level())

	if *probe != "" {
		return httpapi.Probe(ctx, cfg.HTTPAddr, *probe, stderr)
	}
	return serve(ctx, cfg, logger)
}

func logConfigProblems(ctx context.Context, logger *slog.Logger, err error) {
	var probs config.FieldErrors
	if errors.As(err, &probs) {
		for _, p := range probs {
			logger.ErrorContext(ctx, "configuration refused", "variable", p.Field, "reason", p.Reason)
		}
		return
	}
	logger.ErrorContext(ctx, "configuration refused", "error", err.Error())
}

func serve(ctx context.Context, cfg *config.API, logger *slog.Logger) int {
	logger.InfoContext(ctx, "starting", "version", version, "config", cfg.Redacted())

	reg := obs.NewRegistry()
	status := obs.NewStatus(process, reg, time.Now())
	// A disabled safeguard is shown at error level every period
	// (CLAUDE.md hard rule 4).
	auth.ReportMTLS(status.Component("mtls"), cfg.MTLSMode)

	sec, err := startSecurity(ctx, cfg, status, logger)
	if err != nil {
		logger.ErrorContext(ctx, "authentication refused", "error", err.Error())
		return 1
	}
	retry := time.NewTicker(jwksRetryInterval)
	defer retry.Stop()
	go sec.retry(ctx, retry.C)

	tp, shutdownTracer, err := obs.NewTracerProvider(ctx, cfg.OTelEndpoint, process, version)
	if err != nil {
		logger.ErrorContext(ctx, "tracing refused", "error", err.Error())
		return 1
	}

	ready := httpapi.Readiness{}
	dbComp := status.Component("database")
	migComp := status.Component("migrations")
	var pool *pgxpool.Pool
	if cfg.DatabaseURL == "" {
		dbComp.SetDegraded(httpapi.CheckNotConfigured)
		migComp.SetDegraded(httpapi.CheckNotConfigured)
	} else {
		pool, err = store.OpenPool(ctx, store.PoolConfig{
			URL: cfg.DatabaseURL, ApplicationName: "uspace-cisp-" + process, MaxConns: int32(cfg.DatabaseMaxConns),
		})
		if err != nil {
			logger.ErrorContext(ctx, "database pool refused", "error", err.Error())
			return 1
		}
		defer pool.Close()
		// The api never migrates (docs/PLAN.md section 5.3): pending
		// migrations stop the start; an unreachable database does not,
		// and readiness keeps asking.
		if code, stop := refusePending(ctx, pool, store.TreeRelational, logger); stop {
			return code
		}
		ready.Database = databaseCheck(pool)
		ready.Migrations = migrationsCheck(pool, store.TreeRelational)
		status.AddProbe(func(ctx context.Context) {
			if state, ok := ready.Database(ctx); ok {
				dbComp.SetHealthy()
			} else {
				dbComp.SetDegraded(state)
			}
			if state, ok := ready.Migrations(ctx); ok {
				migComp.SetHealthy()
			} else {
				migComp.SetDegraded(state)
			}
		})
	}

	natsComp := status.Component("nats")
	var nc *nats.Conn
	if cfg.NATSURL == "" {
		natsComp.SetDegraded(httpapi.CheckNotConfigured)
	} else {
		nc, err = connectNATS(cfg, logger, natsComp)
		if err != nil {
			logger.ErrorContext(ctx, "nats refused", "error", err.Error())
			return 1
		}
		ready.NATS = natsCheck(nc)
	}

	router, err := httpapi.NewRouter(&httpapi.Server{Ready: ready, Keys: sec.keys}, httpapi.Options{
		Logger:          logger,
		Status:          status,
		Registerer:      reg,
		Tracer:          tp,
		HandlerTimeout:  cfg.HandlerTimeout,
		MaxBodyBytes:    cfg.MaxBodyBytes,
		RouteMiddleware: sec.routes(),
	})
	if err != nil {
		logger.ErrorContext(ctx, "routes refused", "error", err.Error())
		return 1
	}
	top := http.NewServeMux()
	top.Handle("GET /metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	top.Handle("/", router)

	code := httpapi.Serve(ctx, httpapi.ServeOptions{Addr: cfg.HTTPAddr, ShutdownTimeout: cfg.ShutdownTimeout, StatusInterval: cfg.StatusInterval}, top, status, logger)

	if nc != nil {
		nc.Close()
	}
	flushCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := shutdownTracer(flushCtx); err != nil {
		logger.Warn("tracer shutdown", "error", err.Error())
	}
	logger.Info("stopped")
	return code
}

// refusePending lists the tree's pending migrations and, when there are
// any, logs them and says to stop with exit 2. A database it cannot ask
// is logged and the start continues: readiness reports it.
func refusePending(ctx context.Context, pool *pgxpool.Pool, tree store.Tree, logger *slog.Logger) (int, bool) {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	db := store.OpenSQL(pool)
	defer func() { _ = db.Close() }()
	pending, err := store.Pending(cctx, db, tree)
	if err != nil {
		logger.WarnContext(ctx, "migrations not checked at start", "tree", string(tree), "error", err.Error())
		return 0, false
	}
	if len(pending) > 0 {
		logger.ErrorContext(ctx, "migrations pending; run cispctl migrate "+string(tree)+" first", "tree", string(tree), "pending", pending)
		return 2, true
	}
	return 0, false
}

func migrationsCheck(pool *pgxpool.Pool, tree store.Tree) httpapi.Check {
	return func(ctx context.Context) (string, bool) {
		ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		db := store.OpenSQL(pool)
		defer func() { _ = db.Close() }()
		pending, err := store.Pending(ctx, db, tree)
		switch {
		case err != nil:
			return "unknown: " + err.Error(), false
		case len(pending) > 0:
			return "pending: " + strings.Join(pending, ", "), false
		}
		return httpapi.CheckOK, true
	}
}

func databaseCheck(pool *pgxpool.Pool) httpapi.Check {
	return func(ctx context.Context) (string, bool) {
		ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		if err := pool.Ping(ctx); err != nil {
			return "unreachable: " + err.Error(), false
		}
		return httpapi.CheckOK, true
	}
}

// connectNATS connects without ever giving up (LESSONS B-08): the first
// connect does not block when the broker is down, reconnects are
// unlimited, and the component's degraded state follows the connection.
func connectNATS(cfg *config.API, logger *slog.Logger, comp *obs.Component) (*nats.Conn, error) {
	comp.SetDegraded("connecting")
	opts := []nats.Option{
		nats.Name("uspace-cisp-" + process),
		nats.MaxReconnects(-1),
		nats.RetryOnFailedConnect(true),
		nats.ReconnectWait(2 * time.Second),
		nats.ConnectHandler(func(*nats.Conn) { comp.SetHealthy(); logger.Info("nats connected") }),
		nats.ReconnectHandler(func(*nats.Conn) { comp.SetHealthy(); logger.Info("nats reconnected") }),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			reason := "disconnected"
			if err != nil {
				reason += ": " + err.Error()
			}
			comp.SetDegraded(reason)
			logger.Warn("nats disconnected", "reason", reason)
		}),
	}
	if cfg.NATSCredsFile != "" {
		opts = append(opts, nats.UserCredentials(cfg.NATSCredsFile))
	}
	nc, err := nats.Connect(cfg.NATSURL, opts...)
	if err != nil {
		return nil, fmt.Errorf("nats connect: %w", err)
	}
	if nc.IsConnected() {
		comp.SetHealthy()
	}
	return nc, nil
}

func natsCheck(nc *nats.Conn) httpapi.Check {
	return func(context.Context) (string, bool) {
		if nc.IsConnected() {
			return httpapi.CheckOK, true
		}
		return "disconnected: " + strings.ToLower(nc.Status().String()), false
	}
}
