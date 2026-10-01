package obs

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// NewTracerProvider returns the OTLP/HTTP exporting provider when
// endpoint (CISP_OTEL_ENDPOINT, a URL) is set, and a no-op provider when
// it is empty. The returned function flushes and stops the provider.
func NewTracerProvider(ctx context.Context, endpoint, process, version string) (trace.TracerProvider, func(context.Context) error, error) {
	if endpoint == "" {
		return noop.NewTracerProvider(), func(context.Context) error { return nil }, nil
	}
	exp, err := otlptracehttp.New(ctx, otlptracehttp.WithEndpointURL(endpoint))
	if err != nil {
		return nil, nil, fmt.Errorf("otlp exporter: %w", err)
	}
	res := resource.NewSchemaless(
		attribute.String("service.name", "uspace-cisp-"+process),
		attribute.String("service.version", version),
	)
	tp := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exp), sdktrace.WithResource(res))
	return tp, tp.Shutdown, nil
}
