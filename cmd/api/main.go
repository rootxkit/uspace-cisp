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

	"github.com/rootxkit/uspace-cisp/internal/config"
	"github.com/rootxkit/uspace-cisp/internal/httpapi"
	"github.com/rootxkit/uspace-cisp/internal/obs"
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
	if cfg.MTLSMode == config.MTLSOff {
		// A disabled safeguard is shown at error level every period
		// (CLAUDE.md hard rule 4).
		status.Component("mtls").SetDegraded("CISP_MTLS_MODE=off: the ANSP's client certificate is not checked")
	}

	tp, shutdownTracer, err := obs.NewTracerProvider(ctx, cfg.OTelEndpoint, process, version)
	if err != nil {
		logger.ErrorContext(ctx, "tracing refused", "error", err.Error())
		return 1
	}

	// Until WP-1 ships the goose runner nothing can say the migrations
	// are current, so /readyz is not ready and the status line says why.
	ready := httpapi.Readiness{
		Migrations: func(context.Context) (string, bool) { return httpapi.MigrationsPendingWP1, false },
	}
	status.Component("migrations").SetDegraded(httpapi.MigrationsPendingWP1)

	dbComp := status.Component("database")
	var pool *pgxpool.Pool
	if cfg.DatabaseURL == "" {
		dbComp.SetDegraded(httpapi.CheckNotConfigured)
	} else {
		pool, err = pgxpool.New(ctx, cfg.DatabaseURL)
		if err != nil {
			logger.ErrorContext(ctx, "database pool refused", "error", err.Error())
			return 1
		}
		ready.Database = databaseCheck(pool)
		status.AddProbe(func(ctx context.Context) {
			if state, ok := ready.Database(ctx); ok {
				dbComp.SetHealthy()
			} else {
				dbComp.SetDegraded(state)
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

	router := httpapi.NewRouter(&httpapi.Server{Ready: ready}, httpapi.Options{
		Logger:         logger,
		Status:         status,
		Registerer:     reg,
		Tracer:         tp,
		HandlerTimeout: cfg.HandlerTimeout,
		MaxBodyBytes:   cfg.MaxBodyBytes,
	})
	top := http.NewServeMux()
	top.Handle("GET /metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	top.Handle("/", router)

	code := httpapi.Serve(ctx, httpapi.ServeOptions{Addr: cfg.HTTPAddr, ShutdownTimeout: cfg.ShutdownTimeout, StatusInterval: cfg.StatusInterval}, top, status, logger)

	if nc != nil {
		nc.Close()
	}
	if pool != nil {
		pool.Close()
	}
	flushCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := shutdownTracer(flushCtx); err != nil {
		logger.Warn("tracer shutdown", "error", err.Error())
	}
	logger.Info("stopped")
	return code
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
