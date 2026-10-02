package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/trace"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-cisp/internal/obs"
)

// HeaderRequestID carries the request id; it is echoed when the client
// sent a well-formed one and generated otherwise.
const HeaderRequestID = "X-Request-Id"

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

// statusWriter records the status and byte count and whether anything
// was written, for the logging, recover and deadline middlewares.
type statusWriter struct {
	http.ResponseWriter
	status  int
	bytes   int64
	written bool
}

// WriteHeader records the status and sends it once.
func (w *statusWriter) WriteHeader(code int) {
	if w.written {
		return
	}
	w.status = code
	w.written = true
	w.ResponseWriter.WriteHeader(code)
}

// Write counts the bytes, sending 200 first when no status was sent.
func (w *statusWriter) Write(b []byte) (int, error) {
	if !w.written {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return hex.EncodeToString(b[:])
}

// requestID echoes a well-formed X-Request-Id or generates one, sets it
// on the response and puts it in the context for the logger.
func requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(HeaderRequestID)
		if !requestIDPattern.MatchString(id) {
			id = newRequestID()
		}
		w.Header().Set(HeaderRequestID, id)
		next.ServeHTTP(w, r.WithContext(obs.WithRequestID(r.Context(), id)))
	})
}

type routeKey struct{}

func routeOf(ctx context.Context) string {
	route, _ := ctx.Value(routeKey{}).(string)
	return route
}

// access logs every request once, at the end, with its route, status
// and duration, and observes cisp_http_request_seconds by route.
func access(next http.Handler, logger *slog.Logger, hist *prometheus.HistogramVec, mux *http.ServeMux, aliases map[string]string, now func() time.Time) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := now()
		_, route := mux.Handler(r)
		if route == "" {
			route = "unmatched"
		}
		route = routeName(route, aliases)
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r.WithContext(context.WithValue(r.Context(), routeKey{}, route)))
		elapsed := now().Sub(start)
		hist.WithLabelValues(route, strconv.Itoa(sw.status)).Observe(elapsed.Seconds())
		level := slog.LevelInfo
		if sw.status >= http.StatusInternalServerError {
			level = slog.LevelError
		}
		logger.LogAttrs(r.Context(), level, "request",
			slog.String("method", r.Method),
			slog.String("route", route),
			slog.String("path", r.URL.Path),
			slog.Int("status", sw.status),
			slog.Int64("bytes", sw.bytes),
			slog.Int64("duration_ms", elapsed.Milliseconds()),
		)
	})
}

// recoverer turns a handler panic into a 500 problem and a count of
// handler_panics; the process keeps serving.
func recoverer(next http.Handler, logger *slog.Logger, panics *obs.Counter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw, ok := w.(*statusWriter)
		if !ok {
			sw = &statusWriter{ResponseWriter: w, status: http.StatusOK}
		}
		defer func() {
			v := recover()
			if v == nil {
				return
			}
			panics.Inc()
			logger.LogAttrs(r.Context(), slog.LevelError, "handler panic",
				slog.String("route", routeOf(r.Context())),
				slog.String("panic", fmt.Sprint(v)),
			)
			if !sw.written {
				WriteProblem(sw, http.StatusInternalServerError, SlugInternal, "Internal error", "the handler failed; the failure is logged with this request id")
			}
		}()
		next.ServeHTTP(sw, r)
	})
}

// tracing wraps the handler in an OpenTelemetry server span.
func tracing(next http.Handler, tp trace.TracerProvider) http.Handler {
	return otelhttp.NewHandler(next, "cisp.api",
		otelhttp.WithTracerProvider(tp),
		otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
			return r.Method + " " + routeOf(r.Context())
		}),
	)
}

// bodyCap refuses a declared body over the route's cap with 413 before
// the handler runs, and caps the body reader so an undeclared (chunked)
// body over the cap fails the read with *http.MaxBytesError.
func bodyCap(next http.Handler, defaultCap int64, caps map[string]int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limit := defaultCap
		if c, ok := caps[routeOf(r.Context())]; ok {
			limit = c
		}
		if r.ContentLength > limit {
			WriteProblem(w, http.StatusRequestEntityTooLarge, SlugBodyTooLarge, "Request body too large",
				"the body is larger than this route accepts",
				core.Fieldf("body", "%d bytes declared, at most %d accepted", r.ContentLength, limit))
			return
		}
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, limit)
		}
		next.ServeHTTP(w, r)
	})
}

// SlugBodyTimeout is the problem of a body that did not arrive within
// its read deadline.
const SlugBodyTimeout = "body_timeout"

// bodyReadPolicy sizes the read deadline of a request body.
type bodyReadPolicy struct {
	defaultCap   int64
	caps         map[string]int64
	minBytesPerS int64
	floor        time.Duration
	now          func() time.Time
}

// readFor is how long a body on route may take: its cap at the minimum
// rate, and never less than floor.
func (p bodyReadPolicy) readFor(route string) time.Duration {
	limit := p.defaultCap
	if c, ok := p.caps[route]; ok {
		limit = c
	}
	d := time.Duration(float64(limit) / float64(p.minBytesPerS) * float64(time.Second))
	return max(d, p.floor)
}

// readBody reads the whole (capped) body before the handler deadline
// starts, under a read deadline of its own sized to the route's cap and
// the minimum upload rate, so a large publication on a slow link is not
// cut by the handler deadline, and a stalled one is cut by its own (408
// body_timeout). The handler then reads the same bytes from memory.
func readBody(next http.Handler, p bodyReadPolicy) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body == nil || r.Body == http.NoBody {
			next.ServeHTTP(w, r)
			return
		}
		rc := http.NewResponseController(w)
		// A writer that cannot set deadlines (a test recorder) reads
		// without one; the server's connection always can.
		_ = rc.SetReadDeadline(p.now().Add(p.readFor(routeOf(r.Context()))))
		body, err := io.ReadAll(r.Body)
		_ = rc.SetReadDeadline(time.Time{})
		var tooLarge *http.MaxBytesError
		var netErr net.Error
		switch {
		case errors.As(err, &tooLarge):
			WriteProblem(w, http.StatusRequestEntityTooLarge, SlugBodyTooLarge, "Request body too large",
				"the body is larger than this route accepts")
			return
		case errors.Is(err, os.ErrDeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()):
			w.Header().Set("Connection", "close")
			WriteProblem(w, http.StatusRequestTimeout, SlugBodyTimeout, "Request body too slow",
				"the body did not arrive within its read deadline",
				core.Fieldf("body", "%d bytes arrived within %s", len(body), p.readFor(routeOf(r.Context()))))
			return
		case err != nil:
			WriteProblem(w, http.StatusBadRequest, SlugBadRequest, "Bad request", "the body could not be read",
				core.Fieldf("body", "could not be read: %v", err))
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		next.ServeHTTP(w, r)
	})
}

// deadline gives every handler a context deadline; a handler that
// returns because the deadline passed, without having answered, gets a
// 503 problem.
func deadline(next http.Handler, timeout time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		sw, ok := w.(*statusWriter)
		if !ok {
			sw = &statusWriter{ResponseWriter: w, status: http.StatusOK}
		}
		next.ServeHTTP(sw, r.WithContext(ctx))
		if !sw.written && errors.Is(ctx.Err(), context.DeadlineExceeded) {
			writeTimeout(sw)
		}
	})
}

func writeTimeout(w http.ResponseWriter) {
	WriteProblem(w, http.StatusServiceUnavailable, SlugTimeout, "Handler deadline exceeded",
		"the request did not complete within the handler deadline; retry later")
}
