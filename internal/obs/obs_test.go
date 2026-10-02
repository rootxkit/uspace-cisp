package obs

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

var t0 = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

func lines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("not JSON: %q: %v", l, err)
		}
		out = append(out, m)
	}
	return out
}

func TestLoggerCarriesProcessAndRequestID(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, "api", slog.LevelInfo)
	logger.InfoContext(WithRequestID(context.Background(), "req-1"), "with id")
	logger.Info("without id")
	logger.With("k", "v").WithGroup("g").InfoContext(WithRequestID(context.Background(), "req-2"), "grouped", "x", 1)
	logger.Debug("below the level")

	got := lines(t, &buf)
	if len(got) != 3 {
		t.Fatalf("got %d lines, want 3: %s", len(got), buf.String())
	}
	if got[0]["process"] != "api" || got[0]["request_id"] != "req-1" {
		t.Errorf("line 0 = %v", got[0])
	}
	if _, ok := got[1]["request_id"]; ok {
		t.Errorf("line 1 has a request id: %v", got[1])
	}
	if got[2]["k"] != "v" {
		t.Errorf("line 2 lost With attrs: %v", got[2])
	}
	if RequestID(context.Background()) != "" {
		t.Error("empty context has a request id")
	}
}

// E-02: the healthy status line is read back at info, then a component
// degrades and the same line is read back at error with the reason.
func TestStatusLineInfoThenError(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, "api", slog.LevelInfo)
	reg := prometheus.NewRegistry()
	s := NewStatus("api", reg, t0)
	httpC := s.Component("http")
	panics := httpC.Counter("handler_panics", "Handler panics.")
	panics.Add(2)
	panics.Inc()
	s.Component("deliver").Gauge("deliveries_in_flight", "In flight.").Set(4)

	s.Log(context.Background(), logger, t0.Add(90*time.Second))
	if s.Degraded() {
		t.Fatal("Degraded with every component healthy")
	}
	s.Component("nats").SetDegraded("disconnected: connection refused")
	if !s.Degraded() {
		t.Fatal("not Degraded with nats degraded")
	}
	s.Log(context.Background(), logger, t0.Add(120*time.Second))

	got := lines(t, &buf)
	if len(got) != 2 {
		t.Fatalf("got %d lines: %s", len(got), buf.String())
	}
	healthy, degraded := got[0], got[1]
	if healthy["level"] != "INFO" || healthy["msg"] != "status" || healthy["uptime_s"] != float64(90) {
		t.Errorf("healthy line = %v", healthy)
	}
	if _, ok := healthy["degraded"]; ok {
		t.Errorf("healthy line names degraded components: %v", healthy)
	}
	if h, _ := healthy["http"].(map[string]any); h["handler_panics"] != float64(3) {
		t.Errorf("http group = %v", healthy["http"])
	}
	if d, _ := healthy["deliver"].(map[string]any); d["deliveries_in_flight"] != float64(4) {
		t.Errorf("deliver group = %v", healthy["deliver"])
	}
	if degraded["level"] != "ERROR" {
		t.Errorf("degraded line level = %v", degraded["level"])
	}
	if n, _ := degraded["nats"].(map[string]any); n["degraded"] != "disconnected: connection refused" {
		t.Errorf("nats group = %v", degraded["nats"])
	}
	if list, _ := degraded["degraded"].([]any); len(list) != 1 || list[0] != "nats" {
		t.Errorf("degraded list = %v", degraded["degraded"])
	}

	// Back to healthy: the next line is info again.
	s.Component("nats").SetHealthy()
	buf.Reset()
	s.Log(context.Background(), logger, t0)
	if got := lines(t, &buf); got[0]["level"] != "INFO" {
		t.Errorf("after recovery level = %v", got[0]["level"])
	}

	// The counter and the gauge are Prometheus metrics too.
	if v := testutil.ToFloat64(panics.prom); v != 3 {
		t.Errorf("prometheus counter = %v", v)
	}
	if n, err := testutil.GatherAndCount(reg, "cisp_handler_panics_total", "cisp_deliveries_in_flight"); err != nil || n != 2 {
		t.Errorf("gathered %d series, err %v", n, err)
	}
}

func TestComponentReturnsTheSameMetrics(t *testing.T) {
	s := NewStatus("api", prometheus.NewRegistry(), t0)
	c := s.Component("x")
	if c != s.Component("x") {
		t.Error("Component not memoised")
	}
	c1, c2 := c.Counter("a", "h"), c.Counter("a", "h")
	if c1 != c2 {
		t.Error("Counter not memoised")
	}
	g1, g2 := c.Gauge("b", "h"), c.Gauge("b", "h")
	if g1 != g2 {
		t.Error("Gauge not memoised")
	}
	// The same counter name on two components is one metric with two
	// label values, not a registration failure.
	s.Component("y").Counter("a", "h").Inc()
	if s.Degraded() {
		t.Error("a shared metric name degraded the status")
	}
}

// A metric that cannot be registered is not silent: the status degrades
// and the line names it.
func TestMetricRegistrationFailureIsVisible(t *testing.T) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(prometheus.NewCounter(prometheus.CounterOpts{Name: "cisp_taken_total", Help: "x"}))
	reg.MustRegister(prometheus.NewGauge(prometheus.GaugeOpts{Name: "cisp_level", Help: "x"}))
	s := NewStatus("api", reg, t0)
	s.Component("c").Counter("taken", "h").Inc()
	s.Component("c").Gauge("level", "h").Set(1)
	s.Component("c").Counter("Bad-Name", "h")
	s.Component("c").Gauge("Bad-Gauge", "h")
	if !s.Degraded() {
		t.Fatal("registration failures did not degrade the status")
	}
	var buf bytes.Buffer
	s.Log(context.Background(), NewLogger(&buf, "api", slog.LevelInfo), t0)
	got := lines(t, &buf)[0]
	if got["level"] != "ERROR" {
		t.Errorf("level = %v", got["level"])
	}
	errs, _ := got["metric_register_errors"].([]any)
	if len(errs) != 4 {
		t.Errorf("metric_register_errors = %v", got["metric_register_errors"])
	}
}

func TestStatusWithoutRegistry(t *testing.T) {
	s := NewStatus("cispctl", nil, t0)
	s.Component("c").Counter("n", "h").Inc()
	s.Component("c").Gauge("g", "h").Set(2)
	if s.Degraded() {
		t.Error("Degraded without a registry")
	}
}

func TestProbesRunBeforeTheLine(t *testing.T) {
	s := NewStatus("api", nil, t0)
	db := s.Component("database")
	s.AddProbe(func(context.Context) { db.SetDegraded("unreachable: refused") })
	var buf bytes.Buffer
	s.Log(context.Background(), NewLogger(&buf, "api", slog.LevelInfo), t0)
	if got := lines(t, &buf)[0]; got["level"] != "ERROR" {
		t.Errorf("probe result not in the line: %v", got)
	}
}

func TestRunLogsOnEveryTickAndStops(t *testing.T) {
	s := NewStatus("deliver", nil, t0)
	var buf bytes.Buffer
	logger := NewLogger(&buf, "deliver", slog.LevelInfo)
	tick := make(chan time.Time)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx, logger, tick); close(done) }()
	tick <- t0.Add(time.Second)
	tick <- t0.Add(2 * time.Second)
	cancel()
	<-done
	if n := len(lines(t, &buf)); n != 2 {
		t.Errorf("got %d status lines, want 2", n)
	}
}

func TestNewRegistryHasRuntimeCollectors(t *testing.T) {
	mfs, err := NewRegistry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	var goSeen bool
	for _, mf := range mfs {
		if strings.HasPrefix(mf.GetName(), "go_") {
			goSeen = true
		}
	}
	if !goSeen {
		t.Error("no go_ metrics")
	}
}

// Without CISP_OTEL_ENDPOINT the provider is a no-op; with it, an SDK
// provider exporting over OTLP/HTTP.
func TestTracerProviderWithoutEndpoint(t *testing.T) {
	tp, shutdown, err := NewTracerProvider(context.Background(), "", "api", "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := tp.(noop.TracerProvider); !ok {
		t.Errorf("provider = %T, want noop.TracerProvider", tp)
	}
	if err := shutdown(context.Background()); err != nil {
		t.Error(err)
	}
}

func TestTracerProviderWithEndpoint(t *testing.T) {
	tp, shutdown, err := NewTracerProvider(context.Background(), "http://127.0.0.1:1/v1/traces", "api", "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := tp.(*sdktrace.TracerProvider); !ok {
		t.Errorf("provider = %T, want *sdktrace.TracerProvider", tp)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_ = shutdown(ctx) // nothing listens; only that it returns matters
}

// A degraded component keeps the instant it went degraded while it stays
// degraded, whatever the reason becomes; healthy clears it (E-01: the
// healthy component beside the degraded one).
func TestDegradationsKeepTheirSince(t *testing.T) {
	s := NewStatus("api", nil, time.Now())
	s.Component("nats").SetHealthy()
	db := s.Component("database")
	before := time.Now().UTC()
	db.SetDegraded("unreachable: dial")
	reason, since := db.DegradedSince()
	if reason != "unreachable: dial" || since.Before(before.Add(-time.Second)) || since.After(time.Now().UTC()) {
		t.Fatalf("since %v reason %q", since, reason)
	}
	db.SetDegraded("unreachable: timeout")
	if _, again := db.DegradedSince(); !again.Equal(since) {
		t.Errorf("since moved from %v to %v", since, again)
	}
	got := s.Degradations()
	if len(got) != 1 || got[0].Component != "database" || got[0].Reason != "unreachable: timeout" || !got[0].Since.Equal(since) {
		t.Errorf("degradations %+v", got)
	}
	db.SetHealthy()
	if reason, since := db.DegradedSince(); reason != "" || !since.IsZero() {
		t.Errorf("healthy: %q %v", reason, since)
	}
	if got := s.Degradations(); len(got) != 0 {
		t.Errorf("healthy: %+v", got)
	}
}

// A warning raises the line to warning level, never to error; a degraded
// component beside it still makes the line error; cleared, the line is
// info again (E-01, E-02: each level read back).
func TestStatusLineWarning(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, "api", slog.LevelInfo)
	s := NewStatus("api", nil, t0)
	ansp := s.Component("ansp")
	ansp.SetWarning("ansp-01 stale since 2026-10-02T12:00:00Z")
	if ansp.Warning() == "" || s.Degraded() {
		t.Fatalf("warning %q, degraded %v", ansp.Warning(), s.Degraded())
	}
	s.Log(context.Background(), logger, t0)
	s.Component("database").SetDegraded("unreachable")
	s.Log(context.Background(), logger, t0)
	s.Component("database").SetHealthy()
	ansp.SetWarning("")
	s.Log(context.Background(), logger, t0)

	got := lines(t, &buf)
	if len(got) != 3 {
		t.Fatalf("got %d lines", len(got))
	}
	if got[0]["level"] != "WARN" {
		t.Errorf("warned line level = %v", got[0]["level"])
	}
	if a, _ := got[0]["ansp"].(map[string]any); a["warning"] != "ansp-01 stale since 2026-10-02T12:00:00Z" {
		t.Errorf("ansp group = %v", got[0]["ansp"])
	}
	if list, _ := got[0]["warnings"].([]any); len(list) != 1 || list[0] != "ansp" {
		t.Errorf("warnings = %v", got[0]["warnings"])
	}
	if _, ok := got[0]["degraded"]; ok {
		t.Errorf("a warning is listed as degraded: %v", got[0])
	}
	if got[1]["level"] != "ERROR" {
		t.Errorf("warned and degraded line level = %v", got[1]["level"])
	}
	if got[2]["level"] != "INFO" {
		t.Errorf("cleared line level = %v", got[2]["level"])
	}
}
