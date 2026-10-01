// Package obs is the observability base of every process: the JSON
// slog logger with the process name and the request id, the Prometheus
// registry, the Status that components count into and that prints the
// periodic status line, and the OpenTelemetry tracer provider.
package obs

import (
	"context"
	"io"
	"log/slog"
)

type requestIDKey struct{}

// WithRequestID returns ctx carrying the request id; every log record
// written with that context carries it as request_id.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

// RequestID is the request id carried by ctx, or "".
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// NewLogger returns a JSON logger writing to w at level, with the
// process name on every record and request_id on every record whose
// context carries one.
func NewLogger(w io.Writer, process string, level slog.Leveler) *slog.Logger {
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level})
	return slog.New(contextHandler{h}).With("process", process)
}

type contextHandler struct{ slog.Handler }

// Handle adds request_id from the context, then writes the record.
func (h contextHandler) Handle(ctx context.Context, r slog.Record) error {
	if id := RequestID(ctx); id != "" {
		r.AddAttrs(slog.String("request_id", id))
	}
	return h.Handler.Handle(ctx, r)
}

// WithAttrs keeps the context handler around the derived handler.
func (h contextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return contextHandler{h.Handler.WithAttrs(attrs)}
}

// WithGroup keeps the context handler around the derived handler.
func (h contextHandler) WithGroup(name string) slog.Handler {
	return contextHandler{h.Handler.WithGroup(name)}
}
