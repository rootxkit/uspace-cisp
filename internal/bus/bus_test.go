package bus

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/geodesy"

	"github.com/rootxkit/uspace-cisp/internal/publication"
)

func deadAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func change() publication.Change {
	return publication.Change{
		ID: 42, Dataset: publication.DatasetZones, Version: 7,
		FeatureIDs: []string{"A", "B"}, RemovedIDs: []string{"B"},
		Reason: publication.ReasonPublication,
		At:     time.Date(2026, 10, 2, 8, 0, 0, 0, time.FixedZone("x", 4*3600)),
		BBox:   &geodesy.BBox{MinLat: 41.6, MinLon: 44.7, MaxLat: 41.8, MaxLon: 44.9},
	}
}

func TestMessageIsTheChangeBody(t *testing.T) {
	b := &Bus{cfg: Config{PublicBaseURL: "https://cisp.example.test/"}}
	raw, err := json.Marshal(b.Message(change()))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schema":"cis/change/v1","msg_id":"42","producer":"uspace-cisp","dataset":"zones","version":7,"etag":"\"zones:7\"","feature_ids":["A","B"],"removed_ids":["B"],"reason":"publication","at":"2026-10-02T04:00:00Z","pull_url":"https://cisp.example.test/v1/zones?since_version=6","bbox":[44.7,41.6,44.9,41.8]}`
	if string(raw) != want {
		t.Errorf("got  %s\nwant %s", raw, want)
	}
	// The whole dataset: no bbox member; empty lists stay lists.
	c := change()
	c.BBox, c.FeatureIDs, c.RemovedIDs = nil, nil, nil
	raw, _ = json.Marshal(b.Message(c))
	if strings.Contains(string(raw), "bbox") || !strings.Contains(string(raw), `"feature_ids":[]`) || !strings.Contains(string(raw), `"removed_ids":[]`) {
		t.Errorf("whole-dataset change: %s", raw)
	}
}

func TestConnectNeedsAURL(t *testing.T) {
	if _, err := Connect(context.Background(), Config{}); err == nil {
		t.Error("no URL accepted")
	}
	if _, err := Connect(context.Background(), Config{URL: "nats://" + deadAddr(t), CredsFile: t.TempDir() + "/missing.creds"}); err == nil {
		t.Error("a missing credentials file accepted")
	}
}

// LESSONS B-08: with the broker down Connect still returns a handle,
// reports the state, and a publish fails within AckWait instead of
// hanging.
func TestBrokerDownGivesAHandleAndAFastFailure(t *testing.T) {
	var mu sync.Mutex
	var states []string
	b, err := Connect(context.Background(), Config{
		URL: "nats://" + deadAddr(t), Name: "test", AckWait: 200 * time.Millisecond, ReconnectWait: 50 * time.Millisecond,
		OnState: func(connected bool, state string) {
			mu.Lock()
			defer mu.Unlock()
			if !connected {
				states = append(states, state)
			}
		},
	})
	if err != nil {
		t.Fatalf("connect with the broker down: %v", err)
	}
	defer b.Close()
	if ok, state := b.Status(); ok || state == "" {
		t.Errorf("status %v %q", ok, state)
	}
	mu.Lock()
	if len(states) == 0 || states[0] != "connecting" {
		t.Errorf("states %v", states)
	}
	mu.Unlock()
	if b.Conn() == nil {
		t.Error("no connection handle")
	}

	start := time.Now()
	err = b.Publish(context.Background(), change())
	if err == nil {
		t.Fatal("publish succeeded with no broker")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("publish took %s, AckWait is 200 ms", d)
	}
	if err := b.Publish(context.Background(), publication.Change{Dataset: publication.DatasetZones}); err == nil || !strings.Contains(err.Error(), "cursor") {
		t.Errorf("a change without a cursor: %v", err)
	}
}

func TestStreamConfig(t *testing.T) {
	b := &Bus{}
	b.cfg.defaults()
	sc := b.StreamConfig()
	if sc.Name != "CIS_CHANGES" || len(sc.Subjects) != 1 || sc.Subjects[0] != "cis.v1.change.*" ||
		sc.MaxAge != 30*24*time.Hour || sc.MaxBytes != 1<<30 || sc.Duplicates != 2*time.Minute {
		t.Errorf("stream config %+v", sc)
	}
	if b.cfg.AckWait != 5*time.Second || b.cfg.ReconnectWait != 2*time.Second {
		t.Errorf("defaults %+v", b.cfg)
	}
}
