// Command deliver is the CISP's webhook fan-out process. Until WP-6 it
// runs idle: it serves /healthz and /metrics on its internal listener
// (CISP_DELIVER_HTTP_ADDR) and prints the status line every
// CISP_STATUS_INTERVAL_S. It stops cleanly on SIGTERM or interrupt.
package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/rootxkit/uspace-cisp/internal/config"
	"github.com/rootxkit/uspace-cisp/internal/httpapi"
	"github.com/rootxkit/uspace-cisp/internal/obs"
	"github.com/rootxkit/uspace-cisp/internal/store"
)

const process = "deliver"

// version is set at build time: -ldflags "-X main.version=<tag or sha>".
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Environ(), os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args, environ []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(process, flag.ContinueOnError)
	fs.SetOutput(stderr)
	probe := fs.String("probe", "", "GET this path on the local listener (CISP_DELIVER_HTTP_ADDR) and exit 0 on 200, 1 otherwise; the container health check")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	level := new(slog.LevelVar)
	logger := obs.NewLogger(stdout, process, level)

	cfg, err := config.LoadDeliver(environ)
	if err != nil {
		var probs config.FieldErrors
		if errors.As(err, &probs) {
			for _, p := range probs {
				logger.ErrorContext(ctx, "configuration refused", "variable", p.Field, "reason", p.Reason)
			}
		}
		return 2
	}
	level.Set(cfg.Level())
	if *probe != "" {
		return httpapi.Probe(ctx, cfg.HTTPAddr, *probe, stderr)
	}
	logger.InfoContext(ctx, "starting", "version", version, "config", cfg.Redacted())

	// deliver is the only writer of the timeseries tree and never
	// migrates it (docs/PLAN.md section 5.3): pending migrations stop the
	// start with exit 2; a database it cannot ask is logged and the start
	// continues.
	if cfg.TimeseriesURL != "" {
		pool, err := store.OpenPool(ctx, store.PoolConfig{
			URL: cfg.TimeseriesURL, ApplicationName: "uspace-cisp-" + process, MaxConns: int32(cfg.TimeseriesMaxConns),
		})
		if err != nil {
			logger.ErrorContext(ctx, "timeseries pool refused", "error", err.Error())
			return 1
		}
		defer pool.Close()
		if pending, err := pendingTimeseries(ctx, pool); err != nil {
			logger.WarnContext(ctx, "migrations not checked at start", "tree", string(store.TreeTimeseries), "error", err.Error())
		} else if len(pending) > 0 {
			logger.ErrorContext(ctx, "migrations pending; run cispctl migrate timeseries first", "tree", string(store.TreeTimeseries), "pending", pending)
			return 2
		}
	}

	reg := obs.NewRegistry()
	status := obs.NewStatus(process, reg, time.Now())
	// Nothing is delivered until WP-6; the gauge says so in every status
	// line rather than leaving the process silent.
	status.Component("deliver").Gauge("deliveries_in_flight", "Webhook deliveries in flight.").Set(0)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"ok"}`+"\n")
	})
	mux.Handle("GET /metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	h := httpapi.Wrap(mux, httpapi.Options{Logger: logger, Status: status, Registerer: reg})

	code := httpapi.Serve(ctx, httpapi.ServeOptions{
		Addr:            cfg.HTTPAddr,
		ShutdownTimeout: cfg.ShutdownTimeout,
		StatusInterval:  cfg.StatusInterval,
	}, h, status, logger)
	logger.Info("stopped")
	return code
}

func pendingTimeseries(ctx context.Context, pool *pgxpool.Pool) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	db := store.OpenSQL(pool)
	defer func() { _ = db.Close() }()
	return store.Pending(ctx, db, store.TreeTimeseries)
}
