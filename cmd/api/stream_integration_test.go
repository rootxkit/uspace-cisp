//go:build integration

package main

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/rootxkit/uspace-cisp/internal/bus"
	"github.com/rootxkit/uspace-cisp/internal/natstest"
	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/store"
	"github.com/rootxkit/uspace-cisp/internal/stream"
)

// The WP-7 transcripts: the api with the broker absent at the start,
// and with the broker stopped during a run. The broker is a docker
// container the test creates, starts, stops and starts again
// (internal/natstest); the database is CISP_TEST_DATABASE_URL. Each
// status line and stream frame the assertions read is logged (E-04).

func migratedDatabase(t *testing.T) string {
	t.Helper()
	url := os.Getenv("CISP_TEST_DATABASE_URL")
	if url == "" {
		t.Fatal("CISP_TEST_DATABASE_URL is not set; run make dev-deps")
	}
	ctx := context.Background()
	pool, err := store.OpenPool(ctx, store.PoolConfig{URL: url, ApplicationName: "uspace-cisp-test"})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	db := store.OpenSQL(pool)
	defer func() { _ = db.Close() }()
	if _, err := store.Up(ctx, db, store.TreeRelational); err != nil {
		t.Fatal(err)
	}
	return url
}

type wsClient struct {
	t *testing.T
	c *websocket.Conn
}

func dialStream(t *testing.T, base string) wsClient {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(base, "http")+"/v1/stream", nil)
	if err != nil {
		t.Fatalf("dial the stream: %v", err)
	}
	t.Cleanup(func() { _ = c.CloseNow() })
	return wsClient{t: t, c: c}
}

// next reads frames until one satisfies match, within timeout; it logs
// the frame it returns.
func (w wsClient) next(what string, timeout time.Duration, match func(stream.Envelope) bool) stream.Envelope {
	w.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	for {
		_, data, err := w.c.Read(ctx)
		if err != nil {
			w.t.Fatalf("waiting for %s: %v", what, err)
		}
		var env stream.Envelope
		if err := json.Unmarshal(data, &env); err != nil {
			w.t.Fatalf("frame is not JSON: %s", data)
		}
		if match(env) {
			w.t.Logf("%s: %s", what, data)
			return env
		}
	}
}

func statusBody(t *testing.T, env stream.Envelope) stream.StatusBody {
	t.Helper()
	var b stream.StatusBody
	if err := json.Unmarshal(env.Body, &b); err != nil {
		t.Fatal(err)
	}
	return b
}

func isStatus(pred func(stream.StatusBody) bool) func(stream.Envelope) bool {
	return func(env stream.Envelope) bool {
		if env.Schema != stream.SchemaStatus {
			return false
		}
		var b stream.StatusBody
		return json.Unmarshal(env.Body, &b) == nil && pred(b)
	}
}

func isChange(env stream.Envelope) bool { return env.Schema == stream.SchemaChange }

// publishChange publishes a change on the broker from a connection of
// its own, as another api replica committing a change would.
func publishChange(t *testing.T, url string, id int64) {
	t.Helper()
	b, err := bus.Connect(context.Background(), bus.Config{URL: url, Name: "transcript-publisher", ConnectTimeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	c := publication.Change{ID: id, Dataset: publication.DatasetZones, Version: id, FeatureIDs: []string{"ZONE1"}, RemovedIDs: []string{},
		Reason: publication.ReasonPublication, At: time.Now().UTC()}
	deadline := time.Now().Add(30 * time.Second)
	for {
		err := b.Publish(context.Background(), c)
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("publish: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func statusLines(logs *syncBuffer) []map[string]any {
	var out []map[string]any
	for _, m := range logLines(logs.String()) {
		if m["msg"] == "status" {
			out = append(out, m)
		}
	}
	return out
}

func logStatusLines(t *testing.T, logs *syncBuffer) {
	t.Helper()
	for _, l := range strings.Split(logs.String(), "\n") {
		if strings.Contains(l, `"msg":"status"`) || strings.Contains(l, `"msg":"nats `) || strings.Contains(l, `"msg":"stream: `) {
			t.Log(l)
		}
	}
}

func streamEnv(t *testing.T, db, natsURL string) []string {
	return baseEnv(t, "CISP_HTTP_ADDR=127.0.0.1:0", "CISP_DATABASE_URL="+db, "CISP_NATS_URL="+natsURL,
		"CISP_NATS_CONNECT_TIMEOUT_S=1", "CISP_STATUS_INTERVAL_S=1", "CISP_STREAM_STATUS_INTERVAL_S=1", "CISP_STREAM_LIVE_MAX_AGE_S=3")
}

// Transcript 1: the broker absent at the start. The first status line
// says nats never connected (at error), /readyz is ready with nats not
// ok, and a stream client gets console/status/v1 with nats
// never_connected and degraded naming it. The broker starts: the
// client gets a status with resync_since, then a change.
func TestStreamTranscriptBrokerDownAtStart(t *testing.T) {
	db := migratedDatabase(t)
	broker := natstest.New(t)
	r := startRun(t, streamEnv(t, db, broker.URL()))
	defer func() {
		logStatusLines(t, r.logs)
		if c := r.stop(t); c != 0 {
			t.Errorf("exit %d", c)
		}
	}()

	first := waitForLine(t, r.logs, "status")
	natsComp, _ := first["nats"].(map[string]any)
	reason, _ := natsComp["degraded"].(string)
	if first["level"] != "ERROR" || first["start"] != true || !strings.HasPrefix(reason, "never connected") {
		t.Errorf("first status line: %v", first)
	}
	degraded, _ := first["degraded"].([]any)
	if !slices.Contains(degraded, any("nats")) || slices.Contains(degraded, any("database")) {
		t.Errorf("first status line degraded = %v", degraded)
	}
	code, body := get(t, r.base+"/readyz")
	if code != 200 || !strings.Contains(body, `"database":"ok"`) || strings.Contains(body, `"nats":"ok"`) {
		t.Errorf("readyz = %d %s (want ready, nats degraded)", code, body)
	}
	t.Logf("readyz with the broker absent: %d %s", code, body)

	ws := dialStream(t, r.base)
	env := ws.next("status with the broker absent", 10*time.Second, isStatus(func(stream.StatusBody) bool { return true }))
	b := statusBody(t, env)
	if b.NATS != "never_connected" || b.NATSSince == "" || !slices.Contains(b.Degraded, "nats") || b.ResyncSince != "" {
		t.Errorf("status with the broker absent: %+v", b)
	}

	broker.Start()
	env = ws.next("status after the broker started", 60*time.Second, isStatus(func(b stream.StatusBody) bool { return b.ResyncSince != "" }))
	if b := statusBody(t, env); b.NATS != "connected" || slices.Contains(b.Degraded, "nats") {
		t.Errorf("status after the broker started: %+v", b)
	}
	publishChange(t, broker.URL(), time.Now().UnixNano()%1e12)
	env = ws.next("change after the broker started", 30*time.Second, isChange)
	if !strings.Contains(string(env.Body), `"dataset":"zones"`) {
		t.Errorf("change frame body %s", env.Body)
	}
	waitFor(t, "a status line with nats healthy", func() bool {
		lines := statusLines(r.logs)
		last := lines[len(lines)-1]
		n, _ := last["nats"].(map[string]any)
		return n["degraded"] == nil && n["summary"] == "connected"
	})
}

// Transcript 2: the broker stopped during a run. The stream says nats
// reconnecting since the loss and degraded names it, with no change;
// the status line is at error with the time; when the broker returns
// the client gets a status with resync_since equal to the loss, then a
// change.
func TestStreamTranscriptBrokerStoppedMidRun(t *testing.T) {
	db := migratedDatabase(t)
	broker := natstest.New(t)
	broker.Start()
	r := startRun(t, streamEnv(t, db, broker.URL()))
	defer func() {
		logStatusLines(t, r.logs)
		if c := r.stop(t); c != 0 {
			t.Errorf("exit %d", c)
		}
	}()
	first := waitForLine(t, r.logs, "status")
	if n, _ := first["nats"].(map[string]any); n["summary"] != "connected" || n["degraded"] != nil {
		t.Errorf("first status line nats = %v", first["nats"])
	}
	ws := dialStream(t, r.base)
	env := ws.next("status with the broker up", 10*time.Second, isStatus(func(stream.StatusBody) bool { return true }))
	if b := statusBody(t, env); b.NATS != "connected" || slices.Contains(b.Degraded, "nats") {
		t.Errorf("status with the broker up: %+v", b)
	}

	broker.Stop()
	env = ws.next("status with the broker stopped", 30*time.Second, isStatus(func(b stream.StatusBody) bool { return b.NATS == "reconnecting" }))
	lostAt := statusBody(t, env)
	if lostAt.NATSSince == "" || !slices.Contains(lostAt.Degraded, "nats") || lostAt.DegradedSince["nats"] == "" {
		t.Errorf("status with the broker stopped: %+v", lostAt)
	}
	waitFor(t, "a status line with nats reconnecting", func() bool {
		lines := statusLines(r.logs)
		last := lines[len(lines)-1]
		n, _ := last["nats"].(map[string]any)
		reason, _ := n["degraded"].(string)
		return last["level"] == "ERROR" && strings.HasPrefix(reason, "reconnecting since ")
	})

	broker.Start()
	env = ws.next("status after the broker returned", 60*time.Second, isStatus(func(b stream.StatusBody) bool { return b.ResyncSince != "" }))
	back := statusBody(t, env)
	if back.NATS != "connected" || back.ResyncSince != lostAt.NATSSince {
		t.Errorf("status after the return: %+v (lost at %s)", back, lostAt.NATSSince)
	}
	publishChange(t, broker.URL(), time.Now().UnixNano()%1e12)
	ws.next("change after the broker returned", 30*time.Second, isChange)
}
