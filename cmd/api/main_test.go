package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
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

// closedPort is a local port nothing listens on.
func closedPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

type apiRun struct {
	logs   *syncBuffer
	cancel context.CancelFunc
	code   chan int
	base   string
}

func startRun(t *testing.T, env []string) apiRun {
	t.Helper()
	logs := &syncBuffer{}
	ctx, cancel := context.WithCancel(context.Background())
	code := make(chan int, 1)
	go func() { code <- run(ctx, nil, env, logs, io.Discard) }()
	addr := waitForLine(t, logs, "listening")["addr"].(string)
	return apiRun{logs: logs, cancel: cancel, code: code, base: "http://" + addr}
}

func (r apiRun) stop(t *testing.T) int {
	t.Helper()
	r.cancel()
	select {
	case c := <-r.code:
		return c
	case <-time.After(10 * time.Second):
		t.Fatal("api did not stop within 10 s")
		return -1
	}
}

// In-process: the WP-0 readiness without stores reports every check as
// not configured and is not ready; the status line is at error because
// the stores are missing; the stop is clean.
func TestRunWithoutStores(t *testing.T) {
	r := startRun(t, []string{"CISP_HTTP_ADDR=127.0.0.1:0"})
	if code, body := get(t, r.base+"/healthz"); code != 200 || !strings.Contains(body, `"ok"`) {
		t.Errorf("healthz = %d %s", code, body)
	}
	code, body := get(t, r.base+"/readyz")
	if code != 503 || !strings.Contains(body, `"database":"not configured"`) ||
		!strings.Contains(body, `"migrations":"not configured"`) || !strings.Contains(body, `"nats":"not configured"`) {
		t.Errorf("readyz = %d %s", code, body)
	}
	if code, body := get(t, r.base+"/metrics"); code != 200 || !strings.Contains(body, "go_goroutines") || !strings.Contains(body, "cisp_http_request_seconds") {
		t.Errorf("metrics = %d (no go_goroutines or cisp_http_request_seconds)", code)
	}
	status := waitForLine(t, r.logs, "status")
	if status["level"] != "ERROR" {
		t.Errorf("status line without stores at %v", status["level"])
	}
	if c := r.stop(t); c != 0 {
		t.Errorf("exit %d: %s", c, r.logs.String())
	}
	waitForLine(t, r.logs, "stopped")
}

// Unreachable stores are reported as such, never as ok, and the
// configured database password never reaches the log.
func TestRunWithUnreachableStores(t *testing.T) {
	const password = "never-in-the-log-7"
	r := startRun(t, []string{
		"CISP_HTTP_ADDR=127.0.0.1:0",
		"CISP_DATABASE_URL=postgres://cisp_api:" + password + "@" + closedPort(t) + "/cisp?connect_timeout=1",
		"CISP_NATS_URL=nats://" + closedPort(t),
	})
	code, body := get(t, r.base+"/readyz")
	if code != 503 || !strings.Contains(body, `"database":"unreachable`) || !strings.Contains(body, `"nats":"disconnected`) {
		t.Errorf("readyz = %d %s", code, body)
	}
	if c := r.stop(t); c != 0 {
		t.Errorf("exit %d", c)
	}
	if strings.Contains(r.logs.String(), password) {
		t.Error("the database password is in the log")
	}
}

func TestRunMTLSOffIsAnErrorEveryPeriod(t *testing.T) {
	r := startRun(t, []string{"CISP_HTTP_ADDR=127.0.0.1:0", "CISP_MTLS_MODE=off"})
	status := waitForLine(t, r.logs, "status")
	mtls, _ := status["mtls"].(map[string]any)
	if status["level"] != "ERROR" || !strings.Contains(mtls["degraded"].(string), "CISP_MTLS_MODE=off") {
		t.Errorf("status = %v", status)
	}
	r.stop(t)
}

// fakeNATS speaks just enough of the NATS client protocol (INFO, then
// PONG for every PING) for a client to connect; closing it is the broker
// going away.
type fakeNATS struct {
	ln    net.Listener
	mu    sync.Mutex
	conns []net.Conn
}

func startFakeNATS(t *testing.T, addr string) *fakeNATS {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeNATS{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			f.mu.Lock()
			f.conns = append(f.conns, c)
			f.mu.Unlock()
			go func(c net.Conn) {
				_, _ = io.WriteString(c, `INFO {"server_id":"fake","version":"2.10.0","proto":1,"max_payload":1048576}`+"\r\n")
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					if strings.Contains(string(buf[:n]), "PING") {
						_, _ = io.WriteString(c, "PONG\r\n")
					}
				}
			}(c)
		}
	}()
	return f
}

func (f *fakeNATS) close() {
	_ = f.ln.Close()
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.conns {
		_ = c.Close()
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// E-02: the bus is there (ok), is taken away (disconnected, logged), and
// comes back (reconnected, ok again); readiness reports each state.
func TestRunNATSGoneAndBack(t *testing.T) {
	broker := startFakeNATS(t, "127.0.0.1:0")
	natsAddr := broker.ln.Addr().String()
	r := startRun(t, []string{"CISP_HTTP_ADDR=127.0.0.1:0", "CISP_NATS_URL=nats://" + natsAddr})
	readyNATS := func(want string) func() bool {
		return func() bool {
			_, body := get(t, r.base+"/readyz")
			return strings.Contains(body, `"nats":"`+want)
		}
	}
	waitFor(t, "nats ok", readyNATS("ok"))

	broker.close()
	waitFor(t, "nats disconnected", readyNATS("disconnected"))
	waitForLine(t, r.logs, "nats disconnected")

	broker = startFakeNATS(t, natsAddr)
	defer broker.close()
	waitFor(t, "nats ok again", readyNATS("ok"))
	waitForLine(t, r.logs, "nats reconnected")
	if c := r.stop(t); c != 0 {
		t.Errorf("exit %d", c)
	}
}

// A store client that cannot even be built stops the start with exit 1
// and the reason, rather than serving with the dependency silently gone.
func TestRunStoreClientRefused(t *testing.T) {
	cases := map[string][]string{
		"database pool": {"CISP_HTTP_ADDR=127.0.0.1:0", "CISP_DATABASE_URL=postgres://db/cisp?pool_max_conns=many"},
		"nats":          {"CISP_HTTP_ADDR=127.0.0.1:0", "CISP_NATS_URL=nats://127.0.0.1:1", "CISP_NATS_CREDS_FILE=" + filepath.Join(t.TempDir(), "missing.creds")},
	}
	for name, env := range cases {
		t.Run(name, func(t *testing.T) {
			logs := &syncBuffer{}
			if c := run(context.Background(), nil, env, logs, io.Discard); c != 1 {
				t.Errorf("exit %d, want 1: %s", c, logs.String())
			}
			if !strings.Contains(logs.String(), "refused") {
				t.Errorf("no reason logged: %s", logs.String())
			}
		})
	}
}

func TestRunConfigRefused(t *testing.T) {
	logs := &syncBuffer{}
	if c := run(context.Background(), nil, []string{"CISP_HTTP_ADRR=:1"}, logs, io.Discard); c != 2 {
		t.Errorf("exit %d, want 2", c)
	}
	if !strings.Contains(logs.String(), "CISP_HTTP_ADRR") {
		t.Errorf("problem not named: %s", logs.String())
	}
	if c := run(context.Background(), []string{"-nope"}, nil, io.Discard, io.Discard); c != 2 {
		t.Errorf("bad flag exit %d, want 2", c)
	}
}

func TestProbe(t *testing.T) {
	r := startRun(t, []string{"CISP_HTTP_ADDR=127.0.0.1:0"})
	addr := strings.TrimPrefix(r.base, "http://")
	env := []string{"CISP_HTTP_ADDR=" + addr}
	if c := run(context.Background(), []string{"-probe=/healthz"}, env, io.Discard, io.Discard); c != 0 {
		t.Errorf("probe /healthz exit %d, want 0", c)
	}
	var stderr bytes.Buffer
	if c := run(context.Background(), []string{"-probe=/readyz"}, env, io.Discard, &stderr); c != 1 || !strings.Contains(stderr.String(), "503") {
		t.Errorf("probe /readyz exit %d (%s), want 1 with 503", c, stderr.String())
	}
	r.stop(t)
	if c := run(context.Background(), []string{"-probe=/healthz"}, []string{"CISP_HTTP_ADDR=" + closedPort(t)}, io.Discard, io.Discard); c != 1 {
		t.Errorf("probe of a closed port exit %d, want 1", c)
	}
}

func TestRunListenRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	logs := &syncBuffer{}
	if c := run(context.Background(), nil, []string{"CISP_HTTP_ADDR=" + ln.Addr().String()}, logs, io.Discard); c != 1 {
		t.Errorf("exit %d, want 1: %s", c, logs.String())
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
	bin := filepath.Join(t.TempDir(), "api")
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
	cmd.Env = cleanEnv("CISP_HTTP_ADDR=127.0.0.1:0")
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
