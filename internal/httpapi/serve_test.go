package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-cisp/internal/obs"
)

// syncBuffer is a log sink the server goroutines and the test share.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// listeningAddr waits for the "listening" log line and returns its addr.
func listeningAddr(t *testing.T, logs *syncBuffer) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, line := range strings.Split(logs.String(), "\n") {
			var m map[string]any
			if json.Unmarshal([]byte(line), &m) == nil && m["msg"] == "listening" {
				return m["addr"].(string)
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no listening line: %s", logs.String())
	return ""
}

type serveRun struct {
	logs   *syncBuffer
	cancel context.CancelFunc
	code   chan int
	addr   string
}

func startServe(t *testing.T, h http.Handler, shutdown time.Duration) serveRun {
	t.Helper()
	logs := &syncBuffer{}
	logger := obs.NewLogger(logs, "api", slog.LevelInfo)
	status := obs.NewStatus("api", nil, time.Now())
	ctx, cancel := context.WithCancel(context.Background())
	code := make(chan int, 1)
	go func() {
		code <- Serve(ctx, ServeOptions{Addr: "127.0.0.1:0", ShutdownTimeout: shutdown, StatusInterval: time.Hour}, h, status, logger)
	}()
	return serveRun{logs: logs, cancel: cancel, code: code, addr: listeningAddr(t, logs)}
}

func waitCode(t *testing.T, code chan int) int {
	t.Helper()
	select {
	case c := <-code:
		return c
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return within 10 s")
		return -1
	}
}

func TestServeStartsAndStopsCleanly(t *testing.T) {
	r := startServe(t, NewRouter(&Server{}, Options{}), time.Second)
	resp, err := http.Get("http://" + r.addr + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("healthz = %d", resp.StatusCode)
	}
	if !strings.Contains(r.logs.String(), `"msg":"status"`) {
		t.Error("no status line at start")
	}
	r.cancel()
	if c := waitCode(t, r.code); c != 0 {
		t.Errorf("exit code %d, want 0: %s", c, r.logs.String())
	}
	if _, err := http.Get("http://" + r.addr + "/healthz"); err == nil {
		t.Error("listener still open after stop")
	}
}

// An in-flight request finishes after the stop signal; the stop waits
// for it and is still clean.
func TestServeLetsInFlightRequestsFinish(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("GET /work", func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		w.WriteHeader(http.StatusOK)
	})
	r := startServe(t, mux, 5*time.Second)

	got := make(chan int, 1)
	go func() {
		resp, err := http.Get("http://" + r.addr + "/work")
		if err != nil {
			got <- -1
			return
		}
		_ = resp.Body.Close()
		got <- resp.StatusCode
	}()
	<-entered
	r.cancel()
	close(release)
	if c := <-got; c != http.StatusOK {
		t.Errorf("in-flight request = %d, want 200", c)
	}
	if c := waitCode(t, r.code); c != 0 {
		t.Errorf("exit code %d, want 0", c)
	}
}

// A request that outlives the shutdown timeout makes the stop unclean,
// and the exit code says so.
func TestServeShutdownTimeoutIsExit1(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /stuck", func(_ http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
	})
	r := startServe(t, mux, 20*time.Millisecond)
	go func() {
		if resp, err := http.Get("http://" + r.addr + "/stuck"); err == nil {
			_ = resp.Body.Close()
		}
	}()
	<-entered
	r.cancel()
	if c := waitCode(t, r.code); c != 1 {
		t.Errorf("exit code %d, want 1", c)
	}
	if !strings.Contains(r.logs.String(), "shutdown did not finish in time") {
		t.Error("unclean stop not logged")
	}
}

func TestServeListenFailureIsExit1(t *testing.T) {
	logs := &syncBuffer{}
	logger := obs.NewLogger(logs, "api", slog.LevelInfo)
	c := Serve(context.Background(), ServeOptions{Addr: "127.0.0.1:-1"}, http.NotFoundHandler(), obs.NewStatus("api", nil, time.Now()), logger)
	if c != 1 || !strings.Contains(logs.String(), "listen refused") {
		t.Errorf("code %d logs %s", c, logs.String())
	}
}
