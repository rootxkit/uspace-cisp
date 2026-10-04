package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/legacy"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-cisp/internal/httpapi/gen"
	"github.com/rootxkit/uspace-cisp/internal/obs"
	"github.com/rootxkit/uspace-cisp/internal/publication"
)

var (
	specOnce   sync.Once
	specRouter routers.Router
	// specDatasetFirst routes the dataset-first operations alone
	// (/v1/{dataset}..., /public/v1/{dataset}).
	specDatasetFirst routers.Router
	errSpec          error
)

// spec loads api/openapi.yaml once; every handler test validates its
// request and response against it, so the file is the contract.
func spec(t testing.TB) routers.Router {
	t.Helper()
	specOnce.Do(func() {
		loader := openapi3.NewLoader()
		doc, err := loader.LoadFromFile(filepath.Join("..", "..", "api", "openapi.yaml"))
		if err != nil {
			errSpec = err
			return
		}
		if err := doc.Validate(loader.Context); err != nil {
			errSpec = err
			return
		}
		if specRouter, errSpec = legacy.NewRouter(doc); errSpec != nil {
			return
		}
		first := *doc
		first.Paths = openapi3.NewPaths()
		for path, item := range doc.Paths.Map() {
			for _, prefix := range datasetFirst {
				if path == prefix || strings.HasPrefix(path, prefix+"/") {
					first.Paths.Set(path, item)
				}
			}
		}
		specDatasetFirst, errSpec = legacy.NewRouter(&first)
	})
	if errSpec != nil {
		t.Fatalf("api/openapi.yaml: %v", errSpec)
	}
	return specRouter
}

// findRoute finds the operation of req as the server's router does:
// the dataset-first operations are registered once per dataset (Q34), so
// for a request naming a dataset in that segment they are more specific
// than a templated path of another tag (GET /v1/restrictions/versions is
// the versions of restrictions, not the restriction "versions"). The
// spec's own router prefers literal segments and would pick the other.
func findRoute(t testing.TB, req *http.Request) (*routers.Route, map[string]string, error) {
	t.Helper()
	all := spec(t)
	if route, params, err := specDatasetFirst.FindRoute(req); err == nil && publication.Dataset(params["dataset"]).Valid() {
		return route, params, nil
	}
	return all.FindRoute(req)
}

// conform fails the test when req or the recorded response is not what
// api/openapi.yaml describes.
func conform(t testing.TB, req *http.Request, rec *httptest.ResponseRecorder) {
	t.Helper()
	if err := conformErr(t, req, rec); err != nil {
		t.Errorf("%s %s: %v\n%s", req.Method, req.URL.Path, err, rec.Body.String())
	}
}

func conformErr(t testing.TB, req *http.Request, rec *httptest.ResponseRecorder) error {
	t.Helper()
	route, params, err := findRoute(t, req)
	if err != nil {
		return fmt.Errorf("not in api/openapi.yaml: %w", err)
	}
	opts := &openapi3filter.Options{AuthenticationFunc: openapi3filter.NoopAuthenticationFunc, IncludeResponseStatus: true}
	in := &openapi3filter.RequestValidationInput{Request: req, PathParams: params, Route: route, Options: opts}
	if err := openapi3filter.ValidateRequest(context.Background(), in); err != nil {
		return fmt.Errorf("request does not conform: %w", err)
	}
	out := &openapi3filter.ResponseValidationInput{
		RequestValidationInput: in,
		Status:                 rec.Code,
		Header:                 rec.Header(),
		Body:                   io.NopCloser(bytes.NewReader(rec.Body.Bytes())),
		Options:                opts,
	}
	if err := openapi3filter.ValidateResponse(context.Background(), out); err != nil {
		return fmt.Errorf("response %d does not conform: %w", rec.Code, err)
	}
	return nil
}

// The contract check itself catches what the spec does not describe
// (E-01: the refusal beside the acceptance).
func TestConformCatchesDeviations(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", http.NoBody)
	cases := map[string]func(*httptest.ResponseRecorder){
		"undocumented enum value": func(rec *httptest.ResponseRecorder) {
			rec.Header().Set("Content-Type", "application/json")
			rec.WriteHeader(http.StatusOK)
			_, _ = rec.WriteString(`{"status":"fine"}`)
		},
		"missing required member": func(rec *httptest.ResponseRecorder) {
			rec.Header().Set("Content-Type", "application/json")
			rec.WriteHeader(http.StatusOK)
			_, _ = rec.WriteString(`{}`)
		},
		"problem without its type": func(rec *httptest.ResponseRecorder) {
			rec.Header().Set("Content-Type", "application/problem+json")
			rec.WriteHeader(http.StatusInternalServerError)
			_, _ = rec.WriteString(`{"title":"x","status":500}`)
		},
	}
	for name, write := range cases {
		rec := httptest.NewRecorder()
		write(rec)
		if conformErr(t, req, rec) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if conformErr(t, httptest.NewRequest(http.MethodGet, "/v1/undocumented", http.NoBody), httptest.NewRecorder()) == nil {
		t.Error("an undocumented path was accepted")
	}
	rec := httptest.NewRecorder()
	rec.Header().Set("Content-Type", "application/json")
	_, _ = rec.WriteString(`{"status":"ok"}`)
	if err := conformErr(t, req, rec); err != nil {
		t.Errorf("the documented response was refused: %v", err)
	}
}

type fixture struct {
	h      http.Handler
	status *obs.Status
	logs   *bytes.Buffer
}

func newFixture(t *testing.T, server gen.StrictServerInterface, opts Options) fixture {
	t.Helper()
	logs := &bytes.Buffer{}
	opts.Logger = obs.NewLogger(logs, "api", slog.LevelInfo)
	opts.Status = obs.NewStatus("api", nil, time.Now())
	opts.Registerer = prometheus.NewRegistry()
	if opts.RouteMiddleware == nil {
		opts.RouteMiddleware = openRoutes()
	}
	h, err := NewRouter(server, opts)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{h: h, status: opts.Status, logs: logs}
}

func (f fixture) do(req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	return rec
}

func decodeProblem(t testing.TB, rec *httptest.ResponseRecorder) gen.Problem {
	t.Helper()
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("Content-Type = %q, want application/problem+json; body %s", ct, rec.Body.String())
	}
	var p gen.Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	// problem/v1 requires errors on every problem body (M28, lab C1).
	var members map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &members); err != nil {
		t.Fatal(err)
	}
	if e, ok := members["errors"]; !ok || len(e) == 0 || e[0] != '[' {
		t.Errorf("problem body without an errors array: %s", rec.Body.String())
	}
	if p.Status != rec.Code {
		t.Errorf("problem status %d, response %d", p.Status, rec.Code)
	}
	return p
}

func okCheck(context.Context) (string, bool) { return CheckOK, true }

func TestHealthz(t *testing.T) {
	f := newFixture(t, &Server{}, Options{})
	req := httptest.NewRequest(http.MethodGet, "/healthz", http.NoBody)
	rec := f.do(req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"ok"`) {
		t.Fatalf("GET /healthz = %d %s", rec.Code, rec.Body.String())
	}
	conform(t, req, rec)
}

func TestRequestIDEchoedOrGenerated(t *testing.T) {
	f := newFixture(t, &Server{}, Options{})

	req := httptest.NewRequest(http.MethodGet, "/healthz", http.NoBody)
	req.Header.Set(HeaderRequestID, "client-chosen-42")
	if got := f.do(req).Header().Get(HeaderRequestID); got != "client-chosen-42" {
		t.Errorf("echoed id = %q", got)
	}

	gen1 := f.do(httptest.NewRequest(http.MethodGet, "/healthz", http.NoBody)).Header().Get(HeaderRequestID)
	gen2 := f.do(httptest.NewRequest(http.MethodGet, "/healthz", http.NoBody)).Header().Get(HeaderRequestID)
	if len(gen1) != 32 || gen1 == gen2 {
		t.Errorf("generated ids %q %q", gen1, gen2)
	}

	// A malformed id is not echoed (it would go into logs and headers).
	bad := httptest.NewRequest(http.MethodGet, "/healthz", http.NoBody)
	bad.Header.Set(HeaderRequestID, "evil\x01id with spaces")
	if got := f.do(bad).Header().Get(HeaderRequestID); got == bad.Header.Get(HeaderRequestID) || len(got) != 32 {
		t.Errorf("malformed id handled as %q", got)
	}

	// The access log line carries the id.
	if !strings.Contains(f.logs.String(), `"request_id":"client-chosen-42"`) {
		t.Errorf("access log without the request id: %s", f.logs.String())
	}
}

func TestReadyz(t *testing.T) {
	pending := func(context.Context) (string, bool) { return "pending: 0006_events.sql", false }
	down := func(context.Context) (string, bool) { return "unreachable: connection refused", false }
	cases := []struct {
		name       string
		ready      Readiness
		wantCode   int
		wantStatus gen.ReadinessStatus
		wantChecks [3]string
	}{
		{"all ok", Readiness{Database: okCheck, Migrations: okCheck, NATS: okCheck}, 200, gen.Ready, [3]string{"ok", "ok", "ok"}},
		{"migrations pending is not ready", Readiness{Database: okCheck, Migrations: pending, NATS: okCheck}, 503, gen.NotReady, [3]string{"ok", "pending: 0006_events.sql", "ok"}},
		{"database unreachable", Readiness{Database: down, Migrations: okCheck, NATS: okCheck}, 503, gen.NotReady, [3]string{"unreachable: connection refused", "ok", "ok"}},
		{"nats down is ready, degraded", Readiness{Database: okCheck, Migrations: okCheck, NATS: down}, 200, gen.Ready, [3]string{"ok", "ok", "unreachable: connection refused"}},
		{"nothing configured", Readiness{}, 503, gen.NotReady, [3]string{CheckNotConfigured, CheckNotConfigured, CheckNotConfigured}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, &Server{Ready: c.ready}, Options{})
			req := httptest.NewRequest(http.MethodGet, "/readyz", http.NoBody)
			rec := f.do(req)
			if rec.Code != c.wantCode {
				t.Fatalf("code = %d, want %d: %s", rec.Code, c.wantCode, rec.Body.String())
			}
			var body gen.Readiness
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			got := [3]string{body.Checks.Database, body.Checks.Migrations, body.Checks.Nats}
			if body.Status != c.wantStatus || got != c.wantChecks {
				t.Errorf("body = %+v", body)
			}
			conform(t, req, rec)
		})
	}
}

// The readiness checks run under a deadline: a hanging dependency is
// reported, not waited for.
func TestReadyzCheckDeadline(t *testing.T) {
	hang := func(ctx context.Context) (string, bool) {
		<-ctx.Done()
		return "unreachable: " + ctx.Err().Error(), false
	}
	f := newFixture(t, &Server{Ready: Readiness{Database: hang, Migrations: okCheck, Timeout: 10 * time.Millisecond}}, Options{})
	rec := f.do(httptest.NewRequest(http.MethodGet, "/readyz", http.NoBody))
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "deadline exceeded") {
		t.Errorf("readyz = %d %s", rec.Code, rec.Body.String())
	}
}

// GET /v1/status without a database: the clock, the mTLS mode and
// nothing it cannot know (E-02: the branch with the dependency absent).
func TestStatusWithoutADatabase(t *testing.T) {
	f := newFixture(t, &Server{Status: &StatusReport{MTLSMode: "off"}}, Options{})
	req := httptest.NewRequest(http.MethodGet, "/v1/status", http.NoBody)
	rec := f.do(req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d %s", rec.Code, rec.Body.String())
	}
	conform(t, req, rec)
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["mtls_mode"] != "off" || len(body["datasets"].([]any)) != 0 || len(body["publishers"].([]any)) != 0 || body["now"] == nil {
		t.Errorf("status %v", body)
	}
	// A server with no report at all still answers with the clock.
	rec = newFixture(t, &Server{}, Options{}).do(httptest.NewRequest(http.MethodGet, "/v1/status", http.NoBody))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"now"`) {
		t.Errorf("no report: %d %s", rec.Code, rec.Body.String())
	}
}

func TestUnmatchedPathsAndMethodsAreProblems(t *testing.T) {
	f := newFixture(t, &Server{}, Options{})
	rec := f.do(httptest.NewRequest(http.MethodGet, "/v1/nothing-here", http.NoBody))
	if rec.Code != http.StatusNotFound || decodeProblem(t, rec).Type != ProblemTypeBase+SlugNotFound {
		t.Errorf("unknown path = %d %s", rec.Code, rec.Body.String())
	}
	if p := decodeProblem(t, rec); p.Instance == nil || *p.Instance != rec.Header().Get(HeaderRequestID) {
		t.Errorf("instance = %v, want the request id", p.Instance)
	}

	rec = f.do(httptest.NewRequest(http.MethodDelete, "/healthz", http.NoBody))
	if rec.Code != http.StatusMethodNotAllowed || decodeProblem(t, rec).Type != ProblemTypeBase+SlugMethodNotAllowed {
		t.Errorf("wrong method = %d %s", rec.Code, rec.Body.String())
	}
	if allow := rec.Header().Get("Allow"); !strings.Contains(allow, http.MethodGet) {
		t.Errorf("Allow = %q", allow)
	}
}

type panicky struct{ Server }

func (panicky) GetStatus(context.Context, gen.GetStatusRequestObject) (gen.GetStatusResponseObject, error) {
	panic("boom: a handler bug")
}

func TestPanicBecomes500AndCounter(t *testing.T) {
	f := newFixture(t, &panicky{}, Options{})
	rec := f.do(httptest.NewRequest(http.MethodGet, "/v1/status", http.NoBody))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("code = %d", rec.Code)
	}
	if decodeProblem(t, rec).Type != ProblemTypeBase+SlugInternal {
		t.Error("wrong problem type")
	}
	if n := f.status.Component("http").Counter("handler_panics", "").Value(); n != 1 {
		t.Errorf("handler_panics = %d, want 1", n)
	}
	if !strings.Contains(f.logs.String(), "handler panic") {
		t.Error("panic not logged")
	}
	// The process keeps serving.
	if rec := f.do(httptest.NewRequest(http.MethodGet, "/healthz", http.NoBody)); rec.Code != http.StatusOK {
		t.Errorf("after a panic /healthz = %d", rec.Code)
	}
}

// A panic after the handler started answering cannot change the status;
// it is still counted.
func TestPanicAfterWriteIsCounted(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /x", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		panic("late: a handler bug after the status")
	})
	status := obs.NewStatus("api", nil, time.Now())
	h := Wrap(mux, Options{Status: status})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", http.NoBody))
	if rec.Code != http.StatusAccepted {
		t.Errorf("code = %d", rec.Code)
	}
	if status.Component("http").Counter("handler_panics", "").Value() != 1 {
		t.Error("late panic not counted")
	}
}

func bodyEcho() *http.ServeMux {
	mux := http.NewServeMux()
	read := func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			requestError(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
	mux.HandleFunc("POST /small", read)
	mux.HandleFunc("POST /large", read)
	return mux
}

// chunked hides the length, so only the capped reader can refuse it.
type chunked struct{ io.Reader }

func TestBodyCap(t *testing.T) {
	h := Wrap(bodyEcho(), Options{MaxBodyBytes: 1024, RouteBodyCaps: map[string]int64{"POST /large": 4096}})
	cases := []struct {
		name     string
		path     string
		body     io.Reader
		length   int64
		wantCode int
	}{
		{"declared under the default cap", "/small", strings.NewReader(strings.Repeat("a", 1024)), 1024, http.StatusNoContent},
		{"declared over the default cap", "/small", strings.NewReader(strings.Repeat("a", 1025)), 1025, http.StatusRequestEntityTooLarge},
		{"chunked over the default cap", "/small", chunked{strings.NewReader(strings.Repeat("a", 5000))}, -1, http.StatusRequestEntityTooLarge},
		{"chunked under the default cap", "/small", chunked{strings.NewReader("abc")}, -1, http.StatusNoContent},
		{"raised route under its cap", "/large", strings.NewReader(strings.Repeat("a", 4096)), 4096, http.StatusNoContent},
		{"raised route over its cap", "/large", strings.NewReader(strings.Repeat("a", 4097)), 4097, http.StatusRequestEntityTooLarge},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, c.path, c.body)
			req.ContentLength = c.length
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != c.wantCode {
				t.Fatalf("code = %d, want %d: %s", rec.Code, c.wantCode, rec.Body.String())
			}
			if c.wantCode == http.StatusRequestEntityTooLarge && decodeProblem(t, rec).Type != ProblemTypeBase+SlugBodyTooLarge {
				t.Error("wrong problem type")
			}
		})
	}
}

// Through the generated router: a declared body over the cap on a
// documented operation is refused before the handler runs.
func TestBodyCapOnGeneratedRoute(t *testing.T) {
	f := newFixture(t, &Server{}, Options{MaxBodyBytes: 1024})
	req := httptest.NewRequest(http.MethodGet, "/healthz", strings.NewReader(strings.Repeat("a", 2048)))
	rec := f.do(req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("code = %d", rec.Code)
	}
	p := decodeProblem(t, rec)
	if len(p.Errors) != 1 || p.Errors[0].Field != "body" {
		t.Errorf("errors = %+v", p.Errors)
	}
}

func TestRequestErrorBadRequest(t *testing.T) {
	rec := httptest.NewRecorder()
	requestError(rec, httptest.NewRequest(http.MethodGet, "/", http.NoBody), errors.New("bad parameter"))
	if rec.Code != http.StatusBadRequest || decodeProblem(t, rec).Type != ProblemTypeBase+SlugBadRequest {
		t.Errorf("= %d %s", rec.Code, rec.Body.String())
	}
}

// A handler that gives up when its deadline passes gets a 503 problem.
func TestDeadlineExceededIs503(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /slow", func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	mux.HandleFunc("GET /fast", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	h := Wrap(mux, Options{HandlerTimeout: 20 * time.Millisecond})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/slow", http.NoBody))
	if rec.Code != http.StatusServiceUnavailable || decodeProblem(t, rec).Type != ProblemTypeBase+SlugTimeout {
		t.Errorf("slow = %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/fast", http.NoBody))
	if rec.Code != http.StatusNoContent {
		t.Errorf("fast = %d", rec.Code)
	}
}

type slowStrict struct{ Server }

func (slowStrict) GetStatus(ctx context.Context, _ gen.GetStatusRequestObject) (gen.GetStatusResponseObject, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

type failingStrict struct{ Server }

func (failingStrict) GetStatus(context.Context, gen.GetStatusRequestObject) (gen.GetStatusResponseObject, error) {
	return nil, errors.New("store exploded")
}

// The generated strict handler returning the deadline error is a 503
// too; any other error is a 500 whose detail does not leak the error.
func TestStrictHandlerErrors(t *testing.T) {
	f := newFixture(t, &slowStrict{}, Options{HandlerTimeout: 20 * time.Millisecond})
	rec := f.do(httptest.NewRequest(http.MethodGet, "/v1/status", http.NoBody))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("deadline = %d %s", rec.Code, rec.Body.String())
	}

	f = newFixture(t, &failingStrict{}, Options{})
	rec = f.do(httptest.NewRequest(http.MethodGet, "/v1/status", http.NoBody))
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "exploded") {
		t.Errorf("error = %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(f.logs.String(), "store exploded") {
		t.Error("handler error not logged")
	}
}

func TestProblemErrorsCapped(t *testing.T) {
	fields := make([]*core.FieldError, MaxProblemErrors+1)
	for i := range fields {
		fields[i] = core.Fieldf("features["+string(rune('a'+i%26))+"]", "bad")
	}
	p := NewProblem(400, "x", "t", "", "", fields...)
	if len(p.Errors) != MaxProblemErrors || p.Truncated == nil || !*p.Truncated {
		t.Errorf("errors %d truncated %v", len(p.Errors), p.Truncated)
	}
	p = NewProblem(400, "x", "t", "", "", fields[:MaxProblemErrors]...)
	if len(p.Errors) != MaxProblemErrors || p.Truncated != nil {
		t.Errorf("at the cap: errors %d truncated %v", len(p.Errors), p.Truncated)
	}
	p = NewProblem(400, "x", "t", "", "", nil, core.Fieldf("a", "b"))
	if len(p.Errors) != 1 {
		t.Errorf("nil field kept: %v", p.Errors)
	}
}

// Every problem body carries errors (problem/v1, M28; lab finding C1):
// an empty array when no field is at fault, the fields when some are.
func TestProblemErrorsAlwaysPresent(t *testing.T) {
	for _, tc := range []struct {
		name   string
		fields []*core.FieldError
		want   string
	}{
		{"no field", nil, `"errors":[]`},
		{"only a nil field", []*core.FieldError{nil}, `"errors":[]`},
		{"a field", []*core.FieldError{core.Fieldf("username", "required")}, `"errors":[{"field":"username","reason":"required"}]`},
	} {
		rec := httptest.NewRecorder()
		WriteProblem(rec, http.StatusServiceUnavailable, SlugConsoleUnavailable, "Console unavailable", "off", tc.fields...)
		if !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("%s: body %s, want %s", tc.name, rec.Body.String(), tc.want)
		}
		decodeProblem(t, rec)
	}
}

func TestMetricsHistogramShared(t *testing.T) {
	reg := prometheus.NewRegistry()
	status := obs.NewStatus("api", nil, time.Now())
	_, _ = NewRouter(&Server{}, Options{Registerer: reg, Status: status, RouteMiddleware: openRoutes()})
	_, _ = NewRouter(&Server{}, Options{Registerer: reg, Status: status, RouteMiddleware: openRoutes()})
	if status.Degraded() {
		t.Error("a second router on the same registry degraded the status")
	}
}

func TestMetricsHistogramConflictIsVisible(t *testing.T) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(prometheus.NewCounter(prometheus.CounterOpts{Name: "cisp_http_request_seconds", Help: "x"}))
	status := obs.NewStatus("api", nil, time.Now())
	_, _ = NewRouter(&Server{}, Options{Registerer: reg, Status: status, RouteMiddleware: openRoutes()})
	if !status.Degraded() {
		t.Error("a histogram that could not register is silent")
	}
}
