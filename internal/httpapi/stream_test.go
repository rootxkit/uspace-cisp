package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/rootxkit/uspace-cisp/internal/obs"
	"github.com/rootxkit/uspace-cisp/internal/stream"
)

// The stream's upgrade passes the whole middleware chain (request id,
// access log, recover, tracing, body cap, deadline, the route's rate
// limiter): the connection is hijacked through every wrapper, and it
// outlives the handler deadline, which ends with the handler.
func TestStreamThroughTheRouter(t *testing.T) {
	st := obs.NewStatus("api", nil, time.Now())
	hub := stream.NewHub(stream.Config{Status: st})
	defer hub.Close()
	limiter := NewRateLimiter(RateLimiterConfig{RPM: 1, Burst: 2, Component: st.Component("ratelimit")})
	routes := openRoutes()
	for k, v := range StreamAuth(limiter) {
		routes[k] = v
	}
	h := mustRouter(t, &Server{}, Options{
		HandlerTimeout: 50 * time.Millisecond, RouteMiddleware: routes,
		RouteHandlers: map[string]http.Handler{StreamRoute: stream.NewHandler(hub, stream.HandlerConfig{Public: true, Problems: WriteProblem})},
	})
	srv := httptest.NewServer(h)
	defer srv.Close()
	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/v1/stream"

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, resp, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatalf("upgrade through the router: %v", err)
	}
	defer c.CloseNow()
	if resp.Header.Get(HeaderRequestID) == "" {
		t.Error("the upgrade has no request id")
	}
	if _, data, err := c.Read(ctx); err != nil || !strings.Contains(string(data), `"schema":"console/status/v1"`) {
		t.Fatalf("first frame %s %v", data, err)
	}
	time.Sleep(100 * time.Millisecond) // past the handler deadline (50 ms)
	hub.Tick(time.Now())
	if _, data, err := c.Read(ctx); err != nil || !strings.Contains(string(data), `"schema":"console/status/v1"`) {
		t.Fatalf("a frame after the handler deadline: %s %v", data, err)
	}

	// The upgrade is rate-limited per client (burst 2): the third is 429.
	if c2, _, err := websocket.Dial(ctx, url, nil); err == nil {
		defer c2.CloseNow()
	}
	_, resp, err = websocket.Dial(ctx, url, nil)
	if err == nil || resp == nil || resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("third upgrade: %v %v", err, resp)
	}
}

// Without a stream handler the operation answers 503 stream_unavailable
// (presence: the handler above), and a handler for no operation stops
// the router.
func TestStreamUnavailableAndUnknownHandler(t *testing.T) {
	h := mustRouter(t, &Server{}, Options{RouteMiddleware: openRoutes()})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/stream", nil))
	body, _ := io.ReadAll(rec.Body)
	var p map[string]any
	_ = json.Unmarshal(body, &p)
	if rec.Code != http.StatusServiceUnavailable || p["type"] != ProblemTypeBase+SlugStreamUnavailable {
		t.Errorf("= %d %s", rec.Code, body)
	}
	_, err := NewRouter(&Server{}, Options{RouteMiddleware: openRoutes(), RouteHandlers: map[string]http.Handler{"GET /v1/streem": http.NotFoundHandler()}})
	if err == nil || !strings.Contains(err.Error(), "GET /v1/streem") {
		t.Errorf("a handler for no operation: %v", err)
	}
}
