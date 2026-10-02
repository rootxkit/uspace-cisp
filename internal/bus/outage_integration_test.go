//go:build integration

package bus

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-cisp/internal/natstest"
	"github.com/rootxkit/uspace-cisp/internal/publication"
)

type events struct {
	mu       sync.Mutex
	changes  []ChangeMessage
	resyncs  []time.Time
	notified chan struct{}
}

func (e *events) handler() Handler {
	return Handler{
		Change: func(m ChangeMessage, _ time.Time) {
			e.mu.Lock()
			e.changes = append(e.changes, m)
			e.mu.Unlock()
			e.poke()
		},
		Resync: func(since time.Time) {
			e.mu.Lock()
			e.resyncs = append(e.resyncs, since)
			e.mu.Unlock()
			e.poke()
		},
	}
}

func (e *events) poke() {
	select {
	case e.notified <- struct{}{}:
	default:
	}
}

func (e *events) counts() (int, int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.changes), len(e.resyncs)
}

func waitUntil(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", timeout, what)
}

// LESSONS B-08 and E-02 with a real broker: absent at the start (the
// handle comes back within ConnectTimeout, never connected), started
// (connected, the subscription resyncs from the start and receives a
// change), stopped mid-run (reconnecting since the loss) and started
// again (connected, a resync from the loss, then a change). The broker
// is a docker container the test stops and starts.
func TestOutageWithARealBroker(t *testing.T) {
	broker := natstest.New(t)
	t0 := time.Now().UTC()
	start := time.Now()
	b, err := Connect(context.Background(), Config{URL: broker.URL(), Name: "outage-test", ConnectTimeout: time.Second, ReconnectWait: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if took := time.Since(start); took < time.Second || took > 5*time.Second {
		t.Errorf("Connect with the broker absent took %s, ConnectTimeout is 1 s", took)
	}
	if st := b.State(); st.Kind != StateNeverConnected {
		t.Fatalf("absent broker: %s", st)
	}
	t.Logf("broker absent at start: %s", b.State())
	ev := &events{notified: make(chan struct{}, 1)}
	sub, err := b.Subscribe(context.Background(), nil, ev.handler())
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Close()

	broker.Start()
	waitUntil(t, "connected", 30*time.Second, func() bool { return b.State().Kind == StateConnected })
	waitUntil(t, "the first resync", 10*time.Second, func() bool { _, r := ev.counts(); return r == 1 })
	t.Logf("broker started: %s", b.State())
	if err := b.EnsureStream(context.Background()); err != nil {
		t.Fatal(err)
	}
	c := change()
	c.ID = time.Now().UnixNano() % 1e12
	if err := b.Publish(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the first change", 10*time.Second, func() bool { n, _ := ev.counts(); return n == 1 })

	lost := time.Now().UTC()
	broker.Stop()
	waitUntil(t, "reconnecting", 30*time.Second, func() bool { return b.State().Kind == StateReconnecting })
	st := b.State()
	if st.Since.Before(lost.Add(-time.Second)) {
		t.Errorf("reconnecting since %s, the broker stopped at %s", st.Since, lost)
	}
	t.Logf("broker stopped mid-run: %s", st)
	if err := b.Publish(context.Background(), change()); err == nil {
		t.Error("a publish succeeded with the broker stopped")
	}

	restarted := time.Now().UTC()
	broker.Start()
	waitUntil(t, "connected again", 60*time.Second, func() bool { return b.State().Kind == StateConnected })
	waitUntil(t, "the second resync", 10*time.Second, func() bool { _, r := ev.counts(); return r == 2 })
	t.Logf("broker back: %s", b.State())
	c.ID++
	c.Dataset = publication.DatasetRestrictions
	waitUntil(t, "a publish after the return", 30*time.Second, func() bool {
		return b.Publish(context.Background(), c) == nil
	})
	// The publish that timed out while the broker was down may still
	// arrive: the client buffers it and sends it on reconnect (the
	// stream deduplicates it by its change id). The restrictions change
	// is the one published after the return.
	waitUntil(t, "the change published after the return", 10*time.Second, func() bool {
		ev.mu.Lock()
		defer ev.mu.Unlock()
		for _, m := range ev.changes {
			if m.Dataset == "restrictions" {
				return true
			}
		}
		return false
	})

	ev.mu.Lock()
	defer ev.mu.Unlock()
	if ev.resyncs[0].Before(t0.Add(-time.Second)) || ev.resyncs[0].After(t0.Add(2*time.Second)) {
		t.Errorf("first resync since %s, Connect was called at %s", ev.resyncs[0], t0)
	}
	// The connection may flap while the container stops; the resync
	// is from a loss between the stop and the restart, never later.
	if ev.resyncs[1].Before(lost.Add(-time.Second)) || ev.resyncs[1].After(restarted) {
		t.Errorf("second resync since %s; the broker stopped at %s and restarted at %s (first seen lost at %s)", ev.resyncs[1], lost, restarted, st.Since)
	}
}
