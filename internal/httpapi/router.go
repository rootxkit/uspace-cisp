// Package httpapi is the HTTP surface of cmd/api: the net/http ServeMux
// with the routes generated from api/openapi.yaml, the middleware chain
// (request id, access log, recover, tracing, body cap, handler deadline)
// and problem+json errors.
package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/rootxkit/uspace-cisp/internal/httpapi/gen"
	"github.com/rootxkit/uspace-cisp/internal/obs"
)

// DefaultMaxBodyBytes is the body cap of a route that does not raise it.
const DefaultMaxBodyBytes = 64 << 10

// DefaultHandlerTimeout is the handler deadline when none is configured.
const DefaultHandlerTimeout = 10 * time.Second

// Options configure the router.
type Options struct {
	Logger *slog.Logger
	Status *obs.Status
	// Registerer receives cisp_http_request_seconds; nil: not exported.
	Registerer prometheus.Registerer
	// Tracer is the tracer provider; nil: a no-op provider.
	Tracer trace.TracerProvider
	// HandlerTimeout is the per-request deadline (CISP_HANDLER_TIMEOUT_S).
	HandlerTimeout time.Duration
	// MaxBodyBytes is the default body cap (CISP_MAX_BODY_BYTES).
	MaxBodyBytes int64
	// RouteBodyCaps raises (or lowers) the cap of a route, keyed by its
	// ServeMux pattern ("PUT /v1/publications/{dataset}").
	RouteBodyCaps map[string]int64
	// Now is the clock for durations; nil: time.Now.
	Now func() time.Time
}

// NewRouter registers the generated routes of api/openapi.yaml on a
// ServeMux, answers unmatched paths and methods with problem+json, and
// wraps the result in the middleware chain.
func NewRouter(server gen.StrictServerInterface, opts Options) http.Handler {
	mux := http.NewServeMux()
	strict := gen.NewStrictHandlerWithOptions(server, nil, gen.StrictHTTPServerOptions{
		RequestErrorHandlerFunc:  requestError,
		ResponseErrorHandlerFunc: responseError(opts.Logger),
	})
	gen.HandlerWithOptions(strict, gen.StdHTTPServerOptions{
		BaseRouter:       mux,
		ErrorHandlerFunc: requestError,
	})
	return Wrap(mux, opts)
}

// Wrap puts the middleware chain around mux. Exported for the processes
// that serve a plain mux (deliver's /healthz and /metrics).
func Wrap(mux *http.ServeMux, opts Options) http.Handler {
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if opts.Status == nil {
		opts.Status = obs.NewStatus("test", nil, time.Now())
	}
	if opts.Tracer == nil {
		opts.Tracer = noop.NewTracerProvider()
	}
	if opts.HandlerTimeout <= 0 {
		opts.HandlerTimeout = DefaultHandlerTimeout
	}
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	hist := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "cisp_http_request_seconds",
		Help:    "HTTP request duration by route and status.",
		Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
	}, []string{"route", "code"})
	if opts.Registerer != nil {
		var already prometheus.AlreadyRegisteredError
		if err := opts.Registerer.Register(hist); errors.As(err, &already) {
			if existing, ok := already.ExistingCollector.(*prometheus.HistogramVec); ok {
				hist = existing
			}
		} else if err != nil {
			opts.Status.Component("http").SetDegraded("cisp_http_request_seconds not registered: " + err.Error())
		}
	}
	panics := opts.Status.Component("http").Counter("handler_panics", "Handler panics turned into 500 responses.")

	h := unmatched(mux)
	h = deadline(h, opts.HandlerTimeout)
	h = bodyCap(h, opts.MaxBodyBytes, opts.RouteBodyCaps)
	h = tracing(h, opts.Tracer)
	h = recoverer(h, opts.Logger, panics)
	h = access(h, opts.Logger, hist, mux, opts.Now)
	return requestID(h)
}

var probeMethods = []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}

// unmatched answers a request no pattern matches with a 404 problem, and
// one whose path matches under another method with a 405 problem and
// Allow, instead of ServeMux's plain-text bodies.
func unmatched(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if routeOf(r.Context()) != "unmatched" {
			mux.ServeHTTP(w, r)
			return
		}
		var allow []string
		for _, m := range probeMethods {
			probe := r.Clone(r.Context())
			probe.Method = m
			if _, pattern := mux.Handler(probe); pattern != "" {
				allow = append(allow, m)
			}
		}
		if len(allow) > 0 {
			w.Header().Set("Allow", strings.Join(allow, ", "))
			WriteProblem(w, http.StatusMethodNotAllowed, SlugMethodNotAllowed, "Method not allowed",
				r.Method+" is not defined on this path")
			return
		}
		WriteProblem(w, http.StatusNotFound, SlugNotFound, "Not found", "no operation of api/openapi.yaml has this path")
	})
}

// requestError answers a request the generated code could not decode.
func requestError(w http.ResponseWriter, _ *http.Request, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		WriteProblem(w, http.StatusRequestEntityTooLarge, SlugBodyTooLarge, "Request body too large",
			"the body is larger than this route accepts")
		return
	}
	WriteProblem(w, http.StatusBadRequest, SlugBadRequest, "Bad request", err.Error())
}

// responseError answers a handler that returned an error: 503 when its
// deadline passed, 500 otherwise (logged, never shown to the client).
func responseError(logger *slog.Logger) func(http.ResponseWriter, *http.Request, error) {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return func(w http.ResponseWriter, r *http.Request, err error) {
		if errors.Is(err, context.DeadlineExceeded) {
			writeTimeout(w)
			return
		}
		logger.LogAttrs(r.Context(), slog.LevelError, "handler error",
			slog.String("route", routeOf(r.Context())), slog.String("error", err.Error()))
		WriteProblem(w, http.StatusInternalServerError, SlugInternal, "Internal error",
			"the handler failed; the failure is logged with this request id")
	}
}
