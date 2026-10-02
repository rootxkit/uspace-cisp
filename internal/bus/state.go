package bus

import (
	"sort"
	"time"
)

// StateKind is where the broker connection is.
type StateKind string

// The connection states. Each is a snake_case slug: the stream's
// console/status/v1 carries it as nats.
const (
	StateConnected      StateKind = "connected"
	StateReconnecting   StateKind = "reconnecting"
	StateNeverConnected StateKind = "never_connected"
	StateClosed         StateKind = "closed"
)

// State is the connection's state and since when it holds: for
// reconnecting, when the connection was lost; for never connected, when
// Connect was called.
type State struct {
	Kind  StateKind
	Since time.Time
	// Reason is the error the connection was lost with, when it said.
	Reason string
}

// String is the state for people: "connected", "reconnecting since
// <RFC 3339>", "never connected since <RFC 3339>", "closed".
func (s State) String() string {
	switch s.Kind {
	case StateReconnecting:
		return "reconnecting since " + s.Since.UTC().Format(time.RFC3339)
	case StateNeverConnected:
		return "never connected (trying since " + s.Since.UTC().Format(time.RFC3339) + ")"
	case StateConnected, StateClosed:
		return string(s.Kind)
	}
	return string(s.Kind)
}

// State is the connection's current state.
func (b *Bus) State() State {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state
}

// Watch calls fn on every state change from now on, after OnState and
// in the order the watchers were added; the returned function stops it. fn runs on the connection's callback
// goroutine and must not block.
func (b *Bus) Watch(fn func(prev, next State)) (stop func()) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.watcherID++
	id := b.watcherID
	b.watchers[id] = fn
	return func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		delete(b.watchers, id)
	}
}

// transition moves the state to kind, unless it is there already or the
// change would be meaningless: a connection never connected stays
// "never connected" through its failed attempts, and a closed one stays
// closed.
func (b *Bus) transition(kind StateKind, reason string) {
	b.mu.Lock()
	prev := b.state
	switch {
	case prev.Kind == kind, prev.Kind == StateClosed:
		b.mu.Unlock()
		return
	case kind == StateReconnecting && prev.Kind == StateNeverConnected:
		b.mu.Unlock()
		return
	}
	next := State{Kind: kind, Since: b.cfg.Now().UTC(), Reason: reason}
	b.state = next
	ids := make([]int, 0, len(b.watchers))
	for id := range b.watchers {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	watchers := make([]func(prev, next State), 0, len(ids))
	for _, id := range ids {
		watchers = append(watchers, b.watchers[id])
	}
	b.mu.Unlock()
	b.tell(next)
	for _, w := range watchers {
		w(prev, next)
	}
}

// tell passes the state to OnState in its (connected, state) form.
func (b *Bus) tell(s State) {
	if b.cfg.OnState == nil {
		return
	}
	state := s.String()
	if s.Kind == StateReconnecting && s.Reason != "" {
		state = "disconnected: " + s.Reason
	}
	b.cfg.OnState(s.Kind == StateConnected, state)
}
