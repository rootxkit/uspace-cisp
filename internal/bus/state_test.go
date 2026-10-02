package bus

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

// LESSONS B-08, E-02: with the broker absent Connect returns within
// ConnectTimeout (never sooner than the broker could answer, never
// later), the handle says never connected and since when, and the
// connection keeps trying.
func TestConnectTimeoutBoundsTheStart(t *testing.T) {
	for _, timeout := range []time.Duration{0, 300 * time.Millisecond} {
		start := time.Now()
		b, err := Connect(context.Background(), Config{URL: "nats://" + deadAddr(t), ConnectTimeout: timeout, ReconnectWait: 50 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		took := time.Since(start)
		st := b.State()
		ok, status := b.Status()
		b.Close()
		if took < timeout || took > timeout+2*time.Second {
			t.Errorf("timeout %s: Connect took %s", timeout, took)
		}
		if st.Kind != StateNeverConnected || st.Since.IsZero() || !strings.HasPrefix(st.String(), "never connected (trying since ") {
			t.Errorf("state %+v %q", st, st.String())
		}
		if ok || !strings.HasPrefix(status, "never connected") {
			t.Errorf("status %v %q", ok, status)
		}
	}
	// A cancelled context ends the wait at once.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	b, err := Connect(ctx, Config{URL: "nats://" + deadAddr(t), ConnectTimeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	b.Close()
	if time.Since(start) > 5*time.Second {
		t.Errorf("a cancelled start waited %s", time.Since(start))
	}
}

// newStateBus is a Bus with no connection, for the state machine.
func newStateBus(now func() time.Time) *Bus {
	cfg := Config{Now: now}
	cfg.defaults()
	return &Bus{cfg: cfg, watchers: map[int]func(prev, next State){}, owners: map[*nats.Subscription]*Subscription{},
		state: State{Kind: StateNeverConnected, Since: now()}}
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

// The transitions and what each says: a start without the broker stays
// "never connected" through its failed attempts; connected, lost
// (reconnecting since the loss), back; closed is final. Watchers see
// every change once, OnState in its (connected, state) form.
func TestStateTransitions(t *testing.T) {
	t0 := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	c := &clock{t: t0}
	b := newStateBus(c.now)
	var told []string
	b.cfg.OnState = func(_ bool, state string) { told = append(told, state) }
	var seen []string
	stop := b.Watch(func(prev, next State) { seen = append(seen, string(prev.Kind)+">"+string(next.Kind)) })

	b.transition(StateReconnecting, "refused") // a failed first attempt
	if b.State().Kind != StateNeverConnected {
		t.Errorf("a failed first attempt left never connected: %+v", b.State())
	}
	c.set(t0.Add(10 * time.Second))
	b.transition(StateConnected, "")
	b.transition(StateConnected, "") // no change
	c.set(t0.Add(20 * time.Second))
	b.transition(StateReconnecting, "EOF")
	if st := b.State(); st.String() != "reconnecting since 2026-10-02T09:00:20Z" || st.Reason != "EOF" {
		t.Errorf("lost: %+v %q", st, st.String())
	}
	c.set(t0.Add(30 * time.Second))
	b.transition(StateConnected, "")
	stop()
	b.transition(StateClosed, "")
	b.transition(StateConnected, "") // closed is final
	if b.State().Kind != StateClosed || b.State().String() != "closed" {
		t.Errorf("after close: %+v", b.State())
	}
	if strings.Join(seen, " ") != "never_connected>connected connected>reconnecting reconnecting>connected" {
		t.Errorf("watcher saw %v", seen)
	}
	if strings.Join(told, "|") != "connected|disconnected: EOF|connected|closed" {
		t.Errorf("OnState told %v", told)
	}
}

func rawChange(t *testing.T) []byte {
	t.Helper()
	b := &Bus{cfg: Config{PublicBaseURL: "https://cisp.example.test"}}
	raw, err := json.Marshal(b.Message(change()))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// A subscription hands a valid record to Change and anything else to
// Unreadable (E-01 pair); on the connection's return it asks for a
// resync from when it was lost, and from the start for a first
// connection; a slow-consumer drop asks from the last message.
func TestSubscriptionEvents(t *testing.T) {
	t0 := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	c := &clock{t: t0}
	b := newStateBus(c.now)
	var mu sync.Mutex
	var changes []ChangeMessage
	var unreadable []error
	var resyncs []time.Time
	s := &Subscription{b: b, start: t0, h: Handler{
		Change:     func(m ChangeMessage, _ time.Time) { mu.Lock(); changes = append(changes, m); mu.Unlock() },
		Unreadable: func(err error) { mu.Lock(); unreadable = append(unreadable, err); mu.Unlock() },
		Resync:     func(since time.Time) { mu.Lock(); resyncs = append(resyncs, since); mu.Unlock() },
	}}
	s.stop = b.Watch(func(prev, next State) {
		if next.Kind == StateConnected && prev.Kind != StateConnected {
			s.h.Resync(prev.Since)
		}
	})
	s.Dropped() // before any message: from the start
	c.set(t0.Add(5 * time.Second))
	s.deliver(&nats.Msg{Data: rawChange(t)})
	s.deliver(&nats.Msg{Data: []byte(`{"schema":"cis/change/v1","msg_id":"x"}`)})
	s.deliver(&nats.Msg{Data: []byte(`not json`)})
	s.Dropped() // from the last message
	c.set(t0.Add(10 * time.Second))
	b.transition(StateConnected, "") // first connection: from Connect's call
	c.set(t0.Add(20 * time.Second))
	b.transition(StateReconnecting, "EOF")
	c.set(t0.Add(25 * time.Second))
	b.transition(StateConnected, "") // back: from the loss
	s.Close()
	s.Close()
	b.transition(StateReconnecting, "EOF")
	b.transition(StateConnected, "") // closed subscription: nothing
	mu.Lock()
	defer mu.Unlock()
	if len(changes) != 1 || changes[0].MsgID != "42" || changes[0].Dataset != "zones" {
		t.Errorf("changes %+v", changes)
	}
	if len(unreadable) != 2 {
		t.Errorf("unreadable %v", unreadable)
	}
	want := []time.Time{t0, t0.Add(5 * time.Second), t0, t0.Add(20 * time.Second)}
	if len(resyncs) != len(want) {
		t.Fatalf("resyncs %v, want %v", resyncs, want)
	}
	for i := range want {
		if !resyncs[i].Equal(want[i]) {
			t.Errorf("resync %d since %s, want %s", i, resyncs[i], want[i])
		}
	}
}

// Subscribing works with the broker absent (the client sends it on
// connect), and a subscription with no handler functions drops nothing
// on the floor loudly.
func TestSubscribeWithTheBrokerDown(t *testing.T) {
	b, err := Connect(context.Background(), Config{URL: "nats://" + deadAddr(t), ReconnectWait: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	s, err := b.Subscribe(context.Background(), nil, Handler{})
	if err != nil {
		t.Fatalf("subscribe with the broker down: %v", err)
	}
	s.deliver(&nats.Msg{Data: rawChange(t)})
	s.deliver(&nats.Msg{Data: []byte("x")})
	s.Dropped()
	s.Close()
	if _, err := b.Subscribe(context.Background(), []string{"bad subject with spaces"}, Handler{}); err == nil {
		t.Error("an invalid subject subscribed")
	}
}

func TestReadChangeMessageRefusals(t *testing.T) {
	if _, err := ReadChangeMessage(rawChange(t)); err != nil {
		t.Fatalf("a valid record refused: %v", err)
	}
	var m map[string]any
	_ = json.Unmarshal(rawChange(t), &m)
	for name, mutate := range map[string]func(map[string]any){
		"unknown member":     func(m map[string]any) { m["colour"] = "red" },
		"no feature_ids":     func(m map[string]any) { delete(m, "feature_ids") },
		"null removed_ids":   func(m map[string]any) { m["removed_ids"] = nil },
		"another schema":     func(m map[string]any) { m["schema"] = "cis/change/v2" },
		"msg_id not decimal": func(m map[string]any) { m["msg_id"] = "abc" },
	} {
		c := map[string]any{}
		for k, v := range m {
			c[k] = v
		}
		mutate(c)
		raw, _ := json.Marshal(c)
		if _, err := ReadChangeMessage(raw); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
