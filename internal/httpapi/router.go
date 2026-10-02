// Package httpapi is the HTTP surface of cmd/api: the net/http ServeMux
// with the routes generated from api/openapi.yaml, the middleware chain
// (request id, access log, recover, tracing, body cap, handler deadline)
// and problem+json errors.
package httpapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/rootxkit/uspace-cisp/internal/httpapi/gen"
	"github.com/rootxkit/uspace-cisp/internal/obs"
	"github.com/rootxkit/uspace-cisp/internal/publication"
)

// DefaultMaxBodyBytes is the body cap of a route that does not raise it.
const DefaultMaxBodyBytes = 64 << 10

// DefaultBodyReadMinBytesPerS is the slowest upload accepted when none
// is configured (CISP_BODY_READ_MIN_BYTES_PER_S).
const DefaultBodyReadMinBytesPerS = 64 << 10

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
	// BodyReadMinBytesPerS is the slowest upload accepted
	// (CISP_BODY_READ_MIN_BYTES_PER_S): a body has its route cap divided
	// by it, and at least HandlerTimeout, to arrive. The handler deadline
	// starts once it has.
	BodyReadMinBytesPerS int64
	// RouteBodyCaps raises (or lowers) the cap of a route, keyed by its
	// ServeMux pattern ("PUT /v1/publications/{dataset}").
	RouteBodyCaps map[string]int64
	// RouteMiddleware wraps the handler of a route, keyed by its ServeMux
	// pattern ("GET /v1/status"): authentication, scopes, the publisher
	// binding, the mTLS check, the body signature. It runs inside the
	// handler deadline and after the body cap. It is fail-closed: every
	// operation of api/openapi.yaml outside PublicRoutes must have an
	// entry, and NewRouter refuses a missing one (and one for a pattern
	// that is no operation, which would be a typo guarding nothing). A
	// header only an mTLS route checks is read nowhere else.
	RouteMiddleware map[string]func(http.Handler) http.Handler
	// Now is the clock for durations; nil: time.Now.
	Now func() time.Time
	// RouteAliases names a registered ServeMux pattern by the operation it
	// serves: NewRouter registers "GET /v1/{dataset}" as one pattern per
	// dataset ("GET /v1/zones", ...) and maps each back here, so the
	// route middleware, the body caps, the logs and the metrics all key
	// on the operation. Set by NewRouter.
	RouteAliases map[string]string
}

// PublicRoutes are the operations served without authentication: the
// liveness and readiness probes and the CISP's public signing keys.
// Every other operation needs an Options.RouteMiddleware entry.
var PublicRoutes = map[string]bool{
	"GET /healthz":               true,
	"GET /readyz":                true,
	"GET /.well-known/jwks.json": true,
}

// NewRouter registers the generated routes of api/openapi.yaml on a
// ServeMux, answers unmatched paths and methods with problem+json, and
// wraps the result in the middleware chain. It refuses (and the process
// does not start) when an operation outside PublicRoutes has no
// RouteMiddleware entry, or an entry names no operation.
func NewRouter(server gen.StrictServerInterface, opts Options) (http.Handler, error) {
	mux := &recordingMux{ServeMux: http.NewServeMux(), aliases: map[string]string{}}
	strict := gen.NewStrictHandlerWithOptions(server, nil, gen.StrictHTTPServerOptions{
		RequestErrorHandlerFunc:  requestError,
		ResponseErrorHandlerFunc: responseError(opts.Logger),
	})
	gen.HandlerWithOptions(strict, gen.StdHTTPServerOptions{
		BaseRouter:       mux,
		ErrorHandlerFunc: requestError,
	})
	if err := CheckRouteAuth(mux.patterns, opts.RouteMiddleware); err != nil {
		return nil, err
	}
	opts.RouteAliases = mux.aliases
	return Wrap(mux.ServeMux, opts), nil
}

// datasetFirst are the operation paths whose first segment after the
// version is the dataset. net/http's ServeMux refuses them as written:
// "GET /v1/{dataset}/versions" and "GET /v1/publications/{dataset}" both
// match /v1/publications/versions and neither is more specific, and
// "HEAD /v1/{dataset}" conflicts with "GET /v1/status" the same way. They
// are registered once per dataset instead, which also answers an unknown
// dataset with the router's 404 before any handler or authentication.
var datasetFirst = []string{"/v1/{dataset}", "/public/v1/{dataset}"}

// recordingMux records every pattern the generated code registers, and
// expands the datasetFirst ones.
type recordingMux struct {
	*http.ServeMux
	patterns []string
	// aliases maps an expanded pattern to the operation's pattern.
	aliases map[string]string
}

// HandleFunc registers and records pattern; a datasetFirst pattern is
// registered once per dataset, with the dataset set as the path value
// the generated code reads.
func (m *recordingMux) HandleFunc(pattern string, h func(http.ResponseWriter, *http.Request)) {
	m.patterns = append(m.patterns, pattern)
	method, path, _ := strings.Cut(pattern, " ")
	for _, prefix := range datasetFirst {
		if path != prefix && !strings.HasPrefix(path, prefix+"/") {
			continue
		}
		for _, ds := range publication.Datasets {
			expanded := method + " " + strings.Replace(path, "{dataset}", string(ds), 1)
			m.aliases[expanded] = pattern
			m.ServeMux.HandleFunc(expanded, func(w http.ResponseWriter, r *http.Request) {
				r.SetPathValue("dataset", string(ds))
				h(w, r)
			})
		}
		return
	}
	m.ServeMux.HandleFunc(pattern, h)
}

// CheckRouteAuth is the fail-closed rule of RouteMiddleware over the
// registered operation patterns: every one outside PublicRoutes has an
// entry, and every entry is one of them.
func CheckRouteAuth(patterns []string, byRoute map[string]func(http.Handler) http.Handler) error {
	known := make(map[string]bool, len(patterns))
	var missing, unknown []string
	for _, p := range patterns {
		known[p] = true
		if !PublicRoutes[p] && byRoute[p] == nil {
			missing = append(missing, p)
		}
	}
	for p := range byRoute {
		if !known[p] {
			unknown = append(unknown, p)
		}
	}
	sort.Strings(missing)
	sort.Strings(unknown)
	var errs []error
	if len(missing) > 0 {
		errs = append(errs, fmt.Errorf("operations without an authentication entry (refusing to serve them open): %s", strings.Join(missing, ", ")))
	}
	if len(unknown) > 0 {
		errs = append(errs, fmt.Errorf("authentication entries for no operation: %s", strings.Join(unknown, ", ")))
	}
	return errors.Join(errs...)
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
	if opts.BodyReadMinBytesPerS <= 0 {
		opts.BodyReadMinBytesPerS = DefaultBodyReadMinBytesPerS
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
	h = routeMiddleware(h, opts.RouteMiddleware)
	h = deadline(h, opts.HandlerTimeout)
	h = readBody(h, bodyReadPolicy{
		defaultCap: opts.MaxBodyBytes, caps: opts.RouteBodyCaps,
		minBytesPerS: opts.BodyReadMinBytesPerS, floor: opts.HandlerTimeout, now: opts.Now,
	})
	h = bodyCap(h, opts.MaxBodyBytes, opts.RouteBodyCaps)
	h = tracing(h, opts.Tracer)
	h = recoverer(h, opts.Logger, panics)
	h = access(h, opts.Logger, hist, mux, opts.RouteAliases, opts.Now)
	return requestID(h)
}

// routeName is the operation a matched ServeMux pattern serves.
func routeName(pattern string, aliases map[string]string) string {
	if op, ok := aliases[pattern]; ok {
		return op
	}
	return pattern
}

// routeMiddleware runs the matched route's middleware, if any.
func routeMiddleware(next http.Handler, byRoute map[string]func(http.Handler) http.Handler) http.Handler {
	if len(byRoute) == 0 {
		return next
	}
	wrapped := make(map[string]http.Handler, len(byRoute))
	for route, mw := range byRoute {
		wrapped[route] = mw(next)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h, ok := wrapped[routeOf(r.Context())]; ok {
			h.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
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
