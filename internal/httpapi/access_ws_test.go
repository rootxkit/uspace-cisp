package httpapi

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/prometheus/client_golang/prometheus"
)

// The access log records a WebSocket upgrade as 101, not 200 (N3); a
// plain request beside it is still 200 (E-01).
func TestAccessLogsTheUpgradeAs101(t *testing.T) {
	var buf syncBuffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	hist := prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "t_seconds"}, []string{"route", "code"})
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/stream", func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		_ = c.Close(websocket.StatusNormalClosure, "")
	})
	mux.HandleFunc("GET /plain", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	srv := httptest.NewServer(access(mux, logger, hist, mux, nil, time.Now))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, resp, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/v1/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Body != nil {
		_ = resp.Body.Close()
	}
	_, _, _ = c.Read(ctx)
	_ = c.CloseNow()
	plain, err := http.Get(srv.URL + "/plain")
	if err != nil {
		t.Fatal(err)
	}
	_ = plain.Body.Close()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && strings.Count(buf.String(), `"msg":"request"`) < 2 {
		time.Sleep(10 * time.Millisecond)
	}
	var stream, other string
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		switch {
		case strings.Contains(line, `"path":"/v1/stream"`):
			stream = line
		case strings.Contains(line, `"path":"/plain"`):
			other = line
		}
	}
	if !strings.Contains(stream, `"status":101`) {
		t.Errorf("upgrade logged as %s", stream)
	}
	if !strings.Contains(other, `"status":200`) {
		t.Errorf("plain request logged as %s", other)
	}
}
