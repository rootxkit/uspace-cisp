package bus

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
)

// The subscribe side (WP-7): the api's stream hub reads the changes as
// they are published, by a plain core NATS subscription on the stream's
// subjects. JetStream stores every message published on them and core
// NATS delivers the same message to every subscriber at once, so the
// hub sees a change as soon as deliver's consumer can, replays nothing
// (no history: a console that missed changes pulls them), and costs the
// stream no consumer state. The client re-sends the subscription on
// every reconnect; what was published meanwhile is lost to it, and the
// handler is told so (Resync) with the instant the connection was lost.

// Subscription defaults.
const (
	// DefaultPendingMsgs and DefaultPendingBytes bound what the client
	// holds for a slow handler; past them it drops messages and reports
	// a slow consumer (counted, never fatal).
	DefaultPendingMsgs  = 4096
	DefaultPendingBytes = 64 << 20
)

// Handler receives a subscription's messages and events. Every function
// is optional and runs on the subscription's delivery goroutine (Change)
// or the connection's callback goroutine (Resync); neither may block.
type Handler struct {
	// Change is a cis/change/v1 record and when it was received.
	Change func(m ChangeMessage, rx time.Time)
	// Unreadable is a message on the subjects that is not a cis/change/v1
	// record; it is dropped.
	Unreadable func(err error)
	// Resync says changes may have been missed since the instant given:
	// the connection came back (after a loss, or for the first time), or
	// the client dropped messages as a slow consumer.
	Resync func(since time.Time)
}

// Subscription is the stream hub's subscription.
type Subscription struct {
	b     *Bus
	subs  []*nats.Subscription
	stop  func()
	h     Handler
	once  sync.Once
	mu    sync.Mutex
	last  time.Time
	start time.Time
}

// Subscribe subscribes h to subjects (nil: every cis.v1.change.*
// subject). It works with the broker down: the client sends the
// subscription when it connects. On every return of the connection
// (the first connection after a start without the broker included) it
// calls h.Resync with when the connection was lost (or when Connect was
// called).
func (b *Bus) Subscribe(_ context.Context, subjects []string, h Handler) (*Subscription, error) {
	if len(subjects) == 0 {
		subjects = []string{SubjectPrefix + "*"}
	}
	s := &Subscription{b: b, h: h, start: b.cfg.Now().UTC()}
	s.stop = b.Watch(func(prev, next State) {
		if next.Kind != StateConnected || prev.Kind == StateConnected {
			return
		}
		if s.h.Resync != nil {
			s.h.Resync(prev.Since)
		}
	})
	for _, subject := range subjects {
		sub, err := b.nc.Subscribe(subject, s.deliver)
		if err != nil {
			s.Close()
			return nil, fmt.Errorf("bus: subscribe %s: %w", subject, err)
		}
		if err := sub.SetPendingLimits(DefaultPendingMsgs, DefaultPendingBytes); err != nil {
			s.Close()
			return nil, fmt.Errorf("bus: subscribe %s: %w", subject, err)
		}
		s.subs = append(s.subs, sub)
		b.mu.Lock()
		b.owners[sub] = s
		b.mu.Unlock()
	}
	return s, nil
}

// deliver reads one message: a valid cis/change/v1 record goes to
// Change, anything else to Unreadable.
func (s *Subscription) deliver(m *nats.Msg) {
	rx := s.b.cfg.Now().UTC()
	s.mu.Lock()
	s.last = rx
	s.mu.Unlock()
	rec, err := ReadChangeMessage(m.Data)
	if err != nil {
		if s.h.Unreadable != nil {
			s.h.Unreadable(err)
		}
		return
	}
	if s.h.Change != nil {
		s.h.Change(rec, rx)
	}
}

// Dropped tells the subscription the client dropped messages as a slow
// consumer: the handler is asked to resync from the last message it
// received (or the subscription's start).
func (s *Subscription) Dropped() {
	s.mu.Lock()
	since := s.last
	if since.IsZero() {
		since = s.start
	}
	s.mu.Unlock()
	if s.h.Resync != nil {
		s.h.Resync(since)
	}
}

// Close unsubscribes; calling it again does nothing.
func (s *Subscription) Close() {
	s.once.Do(func() {
		s.stop()
		for _, sub := range s.subs {
			_ = sub.Unsubscribe() // a closed connection has nothing to unsubscribe
			s.b.mu.Lock()
			delete(s.b.owners, sub)
			s.b.mu.Unlock()
		}
	})
}

// ReadChangeMessage reads a bus message body as the cis/change/v1 record
// it carries, after ParseChange accepts it: the same record the change
// feed and the webhook carry.
func ReadChangeMessage(data []byte) (ChangeMessage, error) {
	if _, err := ParseChange(data); err != nil {
		return ChangeMessage{}, err
	}
	var m ChangeMessage
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return ChangeMessage{}, fmt.Errorf("bus: change message: %w", err)
	}
	if m.FeatureIDs == nil || m.RemovedIDs == nil {
		return ChangeMessage{}, errors.New("bus: change message without feature_ids or removed_ids")
	}
	return m, nil
}
