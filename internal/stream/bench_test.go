package stream

import (
	"context"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/rootxkit/uspace-cisp/internal/obs"
)

// discardConn takes every frame at once.
type discardConn struct{}

func (discardConn) Write(context.Context, []byte) error      { return nil }
func (discardConn) Close(websocket.StatusCode, string) error { return nil }

// BenchmarkHubFanout1000 is one change fanned out to 1 000 clients: one
// frame encoded once and queued to each (the writers drain in their
// own goroutines).
func BenchmarkHubFanout1000(b *testing.B) {
	hub := NewHub(Config{Status: obs.NewStatus("api", nil, time.Now()), Source: healthyParts, SendBuffer: 1 << 16})
	defer hub.Close()
	for range DefaultMaxClients {
		hub.reserve()
		hub.attach(discardConn{}, nil, false, nil)
	}
	m := change(1, "zones", time.Now())
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		hub.Publish(m, time.Now())
	}
}
