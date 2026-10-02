package obs

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// TracerName is the instrumentation name of the CISP's own spans.
const TracerName = "github.com/rootxkit/uspace-cisp"

// Span names of the publication and delivery paths (WP-7).
const (
	SpanValidate   = "validate"
	SpanPublishTx  = "publish_tx"
	SpanBusPublish = "bus_publish"
	SpanDelivery   = "delivery_attempt"
	SpanClaim      = "claim"
	SpanSign       = "sign"
	SpanPost       = "post"
)

// AttrChangeID is the change cursor on the spans that know it.
const AttrChangeID = "cisp.change_id"

// Spans starts the CISP's spans. The zero value starts a child only
// under a recording parent span in the context (the HTTP server span
// otelhttp starts when CISP_OTEL_ENDPOINT is set), and otherwise returns
// the context and its non-recording span unchanged: the path with
// tracing off allocates nothing. Root starts a root span from its own
// tracer when no recording parent exists (deliver, which has no server
// span).
type Spans struct {
	root trace.Tracer
}

// NewSpans returns Spans that start root spans from tp when enabled
// (CISP_OTEL_ENDPOINT set) and behaves as the zero value otherwise.
func NewSpans(tp trace.TracerProvider, enabled bool) Spans {
	if !enabled || tp == nil {
		return Spans{}
	}
	return Spans{root: tp.Tracer(TracerName)}
}

// Start starts name under the context's recording span (or as a root
// span when s has a tracer); with nothing recording it returns ctx and
// the context's span, allocating nothing. End the span either way.
func (s Spans) Start(ctx context.Context, name string) (context.Context, trace.Span) {
	parent := trace.SpanFromContext(ctx)
	if parent.IsRecording() {
		return parent.TracerProvider().Tracer(TracerName).Start(ctx, name)
	}
	if s.root != nil {
		return s.root.Start(ctx, name)
	}
	return ctx, parent
}

// StartAt is Start with the span's start time given (a span opened
// for work that began before it was known to be worth a span).
func (s Spans) StartAt(ctx context.Context, name string, start time.Time) (context.Context, trace.Span) {
	parent := trace.SpanFromContext(ctx)
	if parent.IsRecording() {
		return parent.TracerProvider().Tracer(TracerName).Start(ctx, name, trace.WithTimestamp(start))
	}
	if s.root != nil {
		return s.root.Start(ctx, name, trace.WithTimestamp(start))
	}
	return ctx, parent
}

// EndAt ends span at end when it records (and allocates nothing when
// it does not).
func EndAt(span trace.Span, end time.Time) {
	if span.IsRecording() {
		span.End(trace.WithTimestamp(end))
	}
}

// SetString puts a string attribute on span when it records.
func SetString(span trace.Span, key, value string) {
	if span.IsRecording() {
		span.SetAttributes(attribute.String(key, value))
	}
}

// StartSpan is the zero Spans' Start: a child of the context's recording
// span, or nothing.
func StartSpan(ctx context.Context, name string) (context.Context, trace.Span) {
	return Spans{}.Start(ctx, name)
}

// SetChangeID puts the change cursor on span when it records.
func SetChangeID(span trace.Span, id int64) {
	if span.IsRecording() {
		span.SetAttributes(attribute.Int64(AttrChangeID, id))
	}
}

// SetError marks span failed with err when it records and err is set.
func SetError(span trace.Span, err error) {
	if err != nil && span.IsRecording() {
		span.RecordError(err)
	}
}
