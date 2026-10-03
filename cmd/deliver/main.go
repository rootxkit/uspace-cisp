// Command deliver is the CISP's webhook fan-out process (docs/PLAN.md
// sections 2 and 6.5, internal/deliver): it reads committed changes from
// the durable JetStream consumer "deliver" and from its reconciliation
// scan of the changes table, queues one delivery per matching
// subscription, and POSTs each as a signed compact JWS within 1 s,
// retrying for 24 h. It serves /healthz and /metrics on its internal
// listener (CISP_DELIVER_HTTP_ADDR) and prints the status line every
// CISP_STATUS_INTERVAL_S, the queue included ("0 queued, 0 due").
//
// Without CISP_DATABASE_URL it runs idle and says so. On SIGTERM or
// interrupt it stops claiming, hands back the messages it fetched and
// has not handled, waits at most 5 s for the attempts in flight (a
// delivery still delivering after that is due again once its lease runs
// out, on any instance), and exits 0.
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
	"regexp"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/rootxkit/uspace-cisp/internal/bus"
	"github.com/rootxkit/uspace-cisp/internal/config"
	"github.com/rootxkit/uspace-cisp/internal/deliver"
	"github.com/rootxkit/uspace-cisp/internal/httpapi"
	"github.com/rootxkit/uspace-cisp/internal/jws"
	"github.com/rootxkit/uspace-cisp/internal/obs"
	"github.com/rootxkit/uspace-cisp/internal/store"
	"github.com/rootxkit/uspace-cisp/internal/subscription"
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

	reg := obs.NewRegistry()
	status := obs.NewStatus(process, reg, time.Now())
	status.CheckCatalogue()
	tp, shutdownTracer, err := obs.NewTracerProvider(ctx, cfg.OTelEndpoint, process, version)
	if err != nil {
		logger.ErrorContext(ctx, "tracing refused", "error", err.Error())
		return 1
	}
	defer func() {
		flushCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cfg.ShutdownTimeout)
		defer cancel()
		if err := shutdownTracer(flushCtx); err != nil {
			logger.Warn("tracer shutdown", "error", err.Error())
		}
	}()
	spans := obs.NewSpans(tp, cfg.OTelEndpoint != "")

	// deliver is the only writer of the timeseries tree and never
	// migrates it (docs/PLAN.md section 5.3): pending migrations stop the
	// start with exit 2; a database it cannot ask is logged and the start
	// continues.
	var tsPool *pgxpool.Pool
	if cfg.TimeseriesURL != "" {
		tsPool, err = store.OpenPool(ctx, store.PoolConfig{
			URL: cfg.TimeseriesURL, ApplicationName: "uspace-cisp-" + process, MaxConns: int32(cfg.TimeseriesMaxConns),
		})
		if err != nil {
			logger.ErrorContext(ctx, "timeseries pool refused", "error", err.Error())
			return 1
		}
		defer tsPool.Close()
		if pending, err := pendingTimeseries(ctx, tsPool); err != nil {
			logger.WarnContext(ctx, "migrations not checked at start", "tree", string(store.TreeTimeseries), "error", err.Error())
		} else if len(pending) > 0 {
			logger.ErrorContext(ctx, "migrations pending; run cispctl migrate timeseries first", "tree", string(store.TreeTimeseries), "pending", pending)
			return 2
		}
	}

	var workers sync.WaitGroup
	workCtx, stopWork := context.WithCancel(ctx)
	defer stopWork()
	var changes *bus.Bus
	var pool *pgxpool.Pool
	if cfg.DatabaseURL == "" {
		// Nothing can be queued or sent without the database; the status
		// line says so rather than leaving the process silent.
		comp := status.Component(deliver.Component)
		comp.Gauge(deliver.GaugeInFlight, "Webhook deliveries in flight.").Set(0)
		comp.SetSummary("idle: no database (" + config.EnvDatabaseURL + "); nothing is delivered")
	} else {
		changes, pool, err = start(workCtx, cfg, tsPool, status, reg, spans, logger, &workers)
		if err != nil {
			logger.ErrorContext(ctx, "deliver refused", "error", err.Error())
			return 1
		}
	}

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
	stopWork()
	workers.Wait()
	if changes != nil {
		changes.Close()
	}
	if pool != nil {
		pool.Close()
	}
	logger.Info("stopped")
	return code
}

// start opens the relational database, the signing key, the delivery
// log and the bus, and runs the sender, the scan and the consumer until
// ctx ends. The caller closes the bus and the pool once workers is done.
func start(ctx context.Context, cfg *config.Deliver, tsPool *pgxpool.Pool, status *obs.Status, reg prometheus.Registerer,
	spans obs.Spans, logger *slog.Logger, workers *sync.WaitGroup,
) (*bus.Bus, *pgxpool.Pool, error) {
	pool, err := store.OpenPool(ctx, store.PoolConfig{
		URL: cfg.DatabaseURL, ApplicationName: "uspace-cisp-" + process, MaxConns: int32(cfg.DatabaseMaxConns),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("database pool: %w", err)
	}
	keys, err := jws.ReadKeyRing(cfg.SigningKeyFile, cfg.SigningKID, "", "")
	if err != nil {
		pool.Close()
		return nil, nil, fmt.Errorf("signing key: %w", err)
	}
	logger.InfoContext(ctx, "signing key loaded", "kid", keys.ActiveKID())
	var attempts deliver.AttemptLog
	if tsPool != nil {
		attempts = store.NewDeliveryLog(tsPool)
	} else {
		status.Component("delivery_log").SetDegraded("not configured (" + config.EnvTimeseriesURL + "): attempts are not logged")
	}

	natsComp := status.Component("nats")
	var changes *bus.Bus
	brokerState := func() string { return "not configured" }
	if cfg.NATSURL == "" {
		natsComp.SetDegraded("not configured (" + config.EnvNATSURL + "): the scan alone queues deliveries, every 10 s")
	} else {
		natsComp.SetDegraded("connecting")
		slow := natsComp.Counter("nats_slow_consumer", "NATS slow-consumer errors on this process's subscriptions (messages dropped by the client).")
		changes, err = bus.Connect(ctx, bus.Config{
			URL: cfg.NATSURL, CredsFile: cfg.NATSCredsFile, Name: "uspace-cisp-" + process, PublicBaseURL: cfg.PublicBaseURL,
			ConnectTimeout: cfg.NATSConnectTimeout,
			OnSlowConsumer: func(err error) {
				slow.Inc()
				if ok, held := obs.Once("nats: slow consumer", time.Minute); ok {
					logger.Warn("nats slow consumer", "error", err.Error(), "also_since_last_line", held)
				}
			},
			OnState: func(connected bool, state string) {
				if connected {
					natsComp.SetHealthy()
					logger.Info("nats " + state)
					return
				}
				natsComp.SetDegraded(state + ": the scan queues deliveries meanwhile")
				logger.Warn("nats disconnected", "reason", state)
			},
		})
		if err != nil {
			pool.Close()
			return nil, nil, fmt.Errorf("nats: %w", err)
		}
		brokerState = func() string { _, s := changes.Status(); return s }
	}

	st := store.New(pool, store.Options{Logger: logger})
	status.AddProbe(obs.MirrorCounters(status.Component("store"), st.Counters(), "Store", "bus_publish_failed", "bus_publish_skipped", "change_bbox_unavailable"))
	instance := instanceName()
	svc, err := deliver.New(deliver.Config{
		Instance: instance, IssuerURL: cfg.IssuerURL, PublicBaseURL: cfg.PublicBaseURL, Version: version,
		Policy:        subscription.URLPolicy{AllowPrivate: cfg.AllowPrivateCallbacks, AllowInsecure: cfg.AllowInsecureCallbacks},
		MaxTokenBytes: int(cfg.WebhookMaxTokenBytes),
	}, st, attempts, keys, deliver.Options{
		Status: status, Registerer: reg, Logger: logger, BusState: brokerState, Spans: spans,
	})
	if err != nil {
		pool.Close()
		if changes != nil {
			changes.Close()
		}
		return nil, nil, err
	}
	if cfg.AllowPrivateCallbacks || cfg.AllowInsecureCallbacks {
		// A relaxed SSRF guard is a lab setting; it is never quiet.
		status.Component("callback_policy").SetWarning(fmt.Sprintf("%s=%t %s=%t: callbacks may reach private addresses or plain http (lab only)",
			config.EnvAllowPrivateCallbacks, cfg.AllowPrivateCallbacks, config.EnvAllowInsecureCallbacks, cfg.AllowInsecureCallbacks))
	}
	status.AddProbe(svc.Probe)

	workers.Add(3)
	go func() {
		defer workers.Done()
		svc.RunSender(ctx)
	}()
	go func() {
		defer workers.Done()
		tick := time.NewTicker(svc.ScanInterval())
		defer tick.Stop()
		svc.RunScan(ctx, tick.C)
	}()
	go func() {
		defer workers.Done()
		if changes == nil {
			return
		}
		intake := status.Component("intake")
		svc.RunConsumer(ctx, deliver.ConsumerOptions{
			Open: func(ctx context.Context) (deliver.Fetcher, error) {
				return changes.DurableConsumer(ctx, bus.ConsumerConfig{})
			},
			OnState: func(problem string) {
				if problem == "" {
					intake.SetHealthy()
					return
				}
				intake.SetDegraded(problem)
			},
		})
	}()
	logger.InfoContext(ctx, "delivering", "instance", instance)
	return changes, pool, nil
}

var notInstance = regexp.MustCompile(`[^A-Za-z0-9._-]`)

// instanceName is this host and process, as an instance name: the
// producer of its webhooks (cisp/deliver-<instance>) and the instance of
// its delivery log rows.
func instanceName() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "host"
	}
	name := notInstance.ReplaceAllString(host, "-") + "-" + strconv.Itoa(os.Getpid())
	if len(name) > 64 {
		name = name[len(name)-64:]
	}
	return name
}

func pendingTimeseries(ctx context.Context, pool *pgxpool.Pool) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	db := store.OpenSQL(pool)
	defer func() { _ = db.Close() }()
	return store.Pending(ctx, db, store.TreeTimeseries)
}
