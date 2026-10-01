package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

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

func logLines(s string) []map[string]any {
	var out []map[string]any
	for _, l := range strings.Split(s, "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) == nil {
			out = append(out, m)
		}
	}
	return out
}

func waitForLine(t *testing.T, logs *syncBuffer, msg string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		for _, m := range logLines(logs.String()) {
			if m["msg"] == msg {
				return m
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no %q line in: %s", msg, logs.String())
	return nil
}

func get(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func startRun(t *testing.T, env []string) (*syncBuffer, context.CancelFunc, chan int, string) {
	t.Helper()
	logs := &syncBuffer{}
	ctx, cancel := context.WithCancel(context.Background())
	code := make(chan int, 1)
	go func() { code <- run(ctx, nil, env, logs, io.Discard) }()
	addr := waitForLine(t, logs, "listening")["addr"].(string)
	return logs, cancel, code, "http://" + addr
}

func TestRunIdleLoop(t *testing.T) {
	logs, cancel, code, base := startRun(t, []string{"CISP_DELIVER_HTTP_ADDR=127.0.0.1:0"})
	if c, body := get(t, base+"/healthz"); c != 200 || !strings.Contains(body, `"ok"`) {
		t.Errorf("healthz = %d %s", c, body)
	}
	if c, body := get(t, base+"/metrics"); c != 200 || !strings.Contains(body, "cisp_deliveries_in_flight") {
		t.Errorf("metrics = %d", c)
	}
	if c, body := get(t, base+"/nothing"); c != 404 || !strings.Contains(body, "not_found") {
		t.Errorf("unknown path = %d %s", c, body)
	}
	// Idle is healthy: the status line is at info and names the gauge.
	status := waitForLine(t, logs, "status")
	d, _ := status["deliver"].(map[string]any)
	if status["level"] != "INFO" || d["deliveries_in_flight"] != float64(0) {
		t.Errorf("status = %v", status)
	}
	probeEnv := []string{"CISP_DELIVER_HTTP_ADDR=" + strings.TrimPrefix(base, "http://")}
	if c := run(context.Background(), []string{"-probe=/healthz"}, probeEnv, io.Discard, io.Discard); c != 0 {
		t.Errorf("probe /healthz exit %d, want 0", c)
	}
	if c := run(context.Background(), []string{"-probe=/missing"}, probeEnv, io.Discard, io.Discard); c != 1 {
		t.Errorf("probe /missing exit %d, want 1", c)
	}
	cancel()
	select {
	case c := <-code:
		if c != 0 {
			t.Errorf("exit %d", c)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("deliver did not stop within 10 s")
	}
	waitForLine(t, logs, "stopped")
}

func TestRunConfigRefused(t *testing.T) {
	logs := &syncBuffer{}
	if c := run(context.Background(), nil, []string{"CISP_DELIVERY_LOG_RETENTION_DAYS=0"}, logs, io.Discard); c != 2 {
		t.Errorf("exit %d, want 2", c)
	}
	if !strings.Contains(logs.String(), "CISP_DELIVERY_LOG_RETENTION_DAYS") {
		t.Errorf("problem not named: %s", logs.String())
	}
	if c := run(context.Background(), []string{"-nope"}, nil, io.Discard, io.Discard); c != 2 {
		t.Errorf("bad flag exit %d, want 2", c)
	}
}

// cleanEnv is the test's environment without any CISP_* variable, so a
// developer's shell cannot change what the binary sees.
func cleanEnv(extra ...string) []string {
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "CISP_") {
			env = append(env, kv)
		}
	}
	return append(env, extra...)
}

// buildBinary builds this command with the go tool.
func buildBinary(t *testing.T) string {
	t.Helper()
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("the go tool is not on PATH; the in-process tests cover run()")
	}
	bin := filepath.Join(t.TempDir(), "deliver")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	out, err := exec.Command(goTool, "build", "-o", bin, ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

// The binary: start on a free port, answer /healthz, stop on SIGTERM
// with exit 0 within 10 s.
func TestBinaryStopsOnSIGTERM(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SIGTERM cannot be sent to a process on windows; CI runs this on linux")
	}
	bin := buildBinary(t)
	cmd := exec.Command(bin)
	cmd.Env = cleanEnv("CISP_DELIVER_HTTP_ADDR=127.0.0.1:0")
	logs := &syncBuffer{}
	cmd.Stdout = logs
	cmd.Stderr = logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	addr := waitForLine(t, logs, "listening")["addr"].(string)
	if code, _ := get(t, "http://"+addr+"/healthz"); code != 200 {
		t.Errorf("healthz = %d", code)
	}
	start := time.Now()
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("exit: %v\n%s", err, logs.String())
		}
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("no exit within 10 s of SIGTERM")
	}
	t.Logf("stopped %v after SIGTERM", time.Since(start).Round(time.Millisecond))
}
