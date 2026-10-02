package obs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/rootxkit/uspace-core/core"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace/noop"
)

// CheckCatalogue: a catalogued name registers quietly; one outside the
// catalogue is still counted, and the status line warns and names it
// (E-01 pair). Without CheckCatalogue nothing is judged.
func TestCheckCatalogue(t *testing.T) {
	s := NewStatus("api", prometheus.NewRegistry(), time.Now())
	s.CheckCatalogue()
	s.Component("stream").Counter("stream_changes", "h").Inc()
	var buf bytes.Buffer
	logger := NewLogger(&buf, "api", slog.LevelInfo)
	s.Log(context.Background(), logger, time.Now())
	if got := lines(t, &buf)[0]; got["level"] != "INFO" || got["metrics_uncatalogued"] != nil {
		t.Errorf("a catalogued metric: %v", got)
	}
	buf.Reset()
	c := s.Component("x").Counter("made_up", "h")
	c.Inc()
	s.Log(context.Background(), logger, time.Now())
	got := lines(t, &buf)[0]
	if got["level"] != "WARN" || !strings.Contains(buf.String(), "cisp_made_up_total") || c.Value() != 1 {
		t.Errorf("an uncatalogued metric: %v", got)
	}
	if u := s.Uncatalogued(); len(u) != 1 || u[0] != "cisp_made_up_total" {
		t.Errorf("Uncatalogued = %v", u)
	}
	s.Component("y").Gauge("made_up_gauge", "h").Set(1)
	if u := s.Uncatalogued(); len(u) != 2 || u[1] != "cisp_made_up_gauge" {
		t.Errorf("Uncatalogued = %v", u)
	}

	off := NewStatus("api", nil, time.Now())
	off.Component("x").Counter("made_up", "h")
	if len(off.Uncatalogued()) != 0 {
		t.Error("judged without CheckCatalogue")
	}
}

// The status line's counters are the count since the previous line;
// Prometheus keeps the total. The first line, and only it, says start.
func TestStatusLineCountsSinceTheLastLine(t *testing.T) {
	reg := prometheus.NewRegistry()
	s := NewStatus("api", reg, time.Now())
	c := s.Component("stream").Counter("stream_changes", "h")
	var buf bytes.Buffer
	logger := NewLogger(&buf, "api", slog.LevelInfo)
	c.Add(3)
	s.Log(context.Background(), logger, time.Now())
	s.Log(context.Background(), logger, time.Now())
	c.Add(2)
	s.Log(context.Background(), logger, time.Now())
	got := lines(t, &buf)
	var seen []float64
	for _, l := range got {
		seen = append(seen, l["stream"].(map[string]any)["stream_changes"].(float64))
	}
	if len(seen) != 3 || seen[0] != 3 || seen[1] != 0 || seen[2] != 2 {
		t.Errorf("since-last counts %v, want [3 0 2]", seen)
	}
	if got[0]["start"] != true || got[1]["start"] != nil || got[2]["start"] != nil {
		t.Errorf("start flags %v %v %v", got[0]["start"], got[1]["start"], got[2]["start"])
	}
	if c.Value() != 5 || testutil.ToFloat64(s.counterFor("stream_changes", "h", "stream")) != 5 {
		t.Errorf("total %d", c.Value())
	}
}

// MirrorCounters copies what a core.Counters counted since the previous
// probe into the component's counters; a count that has not moved adds
// nothing but is registered (and so shown).
func TestMirrorCounters(t *testing.T) {
	s := NewStatus("api", prometheus.NewRegistry(), time.Now())
	src := &core.Counters{}
	probe := MirrorCounters(s.Component("store"), src, "Store", "bus_publish_failed", "bus_publish_skipped")
	probe(context.Background())
	comp := s.Component("store")
	if comp.Counter("bus_publish_failed", "").Value() != 0 {
		t.Error("counted before anything happened")
	}
	src.Inc("bus_publish_failed")
	src.Inc("bus_publish_failed")
	probe(context.Background())
	src.Inc("bus_publish_failed")
	src.Inc("bus_publish_skipped")
	probe(context.Background())
	probe(context.Background())
	if a, b := comp.Counter("bus_publish_failed", "").Value(), comp.Counter("bus_publish_skipped", "").Value(); a != 3 || b != 1 {
		t.Errorf("mirrored %d and %d, want 3 and 1", a, b)
	}
}

// Once: the first line goes through, the next within the interval is
// held and counted, the one after the interval goes through with the
// count. The key set is bounded (E-10): past it the least recently used
// is forgotten, and comes back as a first line.
// onceRuns makes the package Once's key unique per run of TestThrottle.
var onceRuns atomic.Int64

func TestThrottle(t *testing.T) {
	now := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	th := NewThrottle(2, clock)
	if ok, n := th.Once("a", time.Minute); !ok || n != 0 {
		t.Errorf("first = %v %d", ok, n)
	}
	for range 3 {
		if ok, _ := th.Once("a", time.Minute); ok {
			t.Error("a line within the interval went through")
		}
	}
	advance(time.Minute)
	if ok, n := th.Once("a", time.Minute); !ok || n != 3 {
		t.Errorf("after the interval = %v %d, want true 3", ok, n)
	}
	th.Once("b", time.Minute)
	th.Once("c", time.Minute) // evicts a, the least recently used
	if th.Len() != 2 {
		t.Errorf("keys = %d, bound 2", th.Len())
	}
	if ok, _ := th.Once("a", time.Minute); !ok {
		t.Error("a forgotten key was held back")
	}
	// The package Once is process-wide and outlives a run under
	// -count=N, so each run takes a key no earlier run has used.
	key := fmt.Sprintf("obs-test-%s-%d", t.Name(), onceRuns.Add(1))
	if ok, _ := Once(key, time.Hour); !ok {
		t.Error("the package Once held back a first line")
	}
	if ok, _ := Once(key, time.Hour); ok {
		t.Error("the package Once let a second line through within the interval")
	}
	if NewThrottle(0, nil).maxKeys != DefaultThrottleKeys {
		t.Error("default bound")
	}
}

// Tracing off: a span under a non-recording context starts nothing and
// allocates nothing; the attribute helpers do nothing.
func TestSpansOffAllocateNothing(t *testing.T) {
	ctx := context.Background()
	boom := errors.New("x")
	allocs := testing.AllocsPerRun(200, func() {
		c, span := StartSpan(ctx, SpanValidate)
		SetChangeID(span, 42)
		SetString(span, "k", "v")
		SetError(span, boom)
		EndAt(span, time.Time{})
		span.End()
		_ = c
	})
	if allocs != 0 {
		t.Errorf("the no-op span path allocates %.0f per call", allocs)
	}
	off := NewSpans(noop.NewTracerProvider(), false)
	allocs = testing.AllocsPerRun(200, func() {
		_, span := off.StartAt(ctx, SpanDelivery, time.Time{})
		span.End()
	})
	if allocs != 0 {
		t.Errorf("Spans off allocates %.0f per call", allocs)
	}
	if NewSpans(nil, true).root != nil {
		t.Error("a nil provider started spans")
	}
}

// Tracing on: a child under a recording server span carries the change
// id; Spans with a root tracer start the delivery's root span at the
// claim's time with its children (E-01 pair with the test above).
func TestSpansOnRecord(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	defer func() { _ = tp.Shutdown(context.Background()) }()

	ctx, server := tp.Tracer("test").Start(context.Background(), "PUT /v1/publications/{dataset}")
	_, child := StartSpan(ctx, SpanPublishTx)
	SetChangeID(child, 42)
	SetError(child, errors.New("boom"))
	child.End()
	server.End()

	spans := NewSpans(tp, true)
	claimAt := time.Now().Add(-time.Second)
	dctx, root := spans.StartAt(context.Background(), SpanDelivery, claimAt)
	_, claim := spans.StartAt(dctx, SpanClaim, claimAt)
	EndAt(claim, claimAt.Add(10*time.Millisecond))
	_, post := spans.Start(dctx, SpanPost)
	SetString(post, "cisp.delivery_result", "2xx")
	post.End()
	root.End()

	ended := rec.Ended()
	byName := map[string]sdktrace.ReadOnlySpan{}
	for _, s := range ended {
		byName[s.Name()] = s
	}
	tx := byName[SpanPublishTx]
	if tx == nil || tx.Parent().SpanID() != server.SpanContext().SpanID() || len(tx.Events()) != 1 {
		t.Fatalf("publish_tx span %v", tx)
	}
	found := false
	for _, a := range tx.Attributes() {
		if string(a.Key) == AttrChangeID && a.Value.AsInt64() == 42 {
			found = true
		}
	}
	if !found {
		t.Errorf("no change id on publish_tx: %v", tx.Attributes())
	}
	d, c := byName[SpanDelivery], byName[SpanClaim]
	if d == nil || c == nil || !d.StartTime().Equal(claimAt) || c.Parent().SpanID() != d.SpanContext().SpanID() ||
		!c.EndTime().Equal(claimAt.Add(10*time.Millisecond)) || byName[SpanPost].Parent().SpanID() != d.SpanContext().SpanID() {
		t.Errorf("delivery spans: %v %v", d, c)
	}
}
