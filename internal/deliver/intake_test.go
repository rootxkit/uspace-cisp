package deliver

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/geodesy"

	"github.com/rootxkit/uspace-cisp/internal/bus"
	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/store"
	"github.com/rootxkit/uspace-cisp/internal/subscription"
)

// fakeMsg is a consumer message that records how it was settled.
type fakeMsg struct {
	mu        sync.Mutex
	data      []byte
	delivered uint64
	acked     bool
	naked     bool
	delay     time.Duration
}

func (m *fakeMsg) Data() []byte         { return m.data }
func (m *fakeMsg) NumDelivered() uint64 { return m.delivered }
func (m *fakeMsg) Ack() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.acked = true
	return nil
}

func (m *fakeMsg) Nak(d time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.naked, m.delay = true, d
	return nil
}

func (m *fakeMsg) state() (bool, bool, time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.acked, m.naked, m.delay
}

func msgOf(t *testing.T, c publication.Change, delivered uint64) *fakeMsg {
	t.Helper()
	raw, err := json.Marshal(bus.MessageOf(c, "https://uspace-cisp.example.test"))
	if err != nil {
		t.Fatal(err)
	}
	return &fakeMsg{data: raw, delivered: delivered}
}

func (h *harness) deliveriesOf(change int64) int {
	h.st.mu.Lock()
	defer h.st.mu.Unlock()
	n := 0
	for _, d := range h.st.deliveries {
		if d.changeID != nil && *d.changeID == change {
			n++
		}
	}
	return n
}

// Matching: the dataset and the box, the receiving states, and nothing
// for a subscription created after the change.
func TestMatching(t *testing.T) {
	at := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	sub := func(id string, st subscription.Status, created time.Time, box *geodesy.BBox, ds ...publication.Dataset) store.SubscriptionRecord {
		return store.SubscriptionRecord{Subscription: subscription.Subscription{ID: id, Datasets: ds, Status: st, BBox: box}, CreatedAt: created}
	}
	before := at.Add(-time.Minute)
	subs := []store.SubscriptionRecord{
		sub("zones", subscription.Active, before, nil, publication.DatasetZones),
		sub("pending", subscription.PendingVerification, before, nil, publication.DatasetZones),
		sub("suspended", subscription.Suspended, before, nil, publication.DatasetZones),
		sub("later", subscription.Active, at.Add(time.Second), nil, publication.DatasetZones),
		sub("same instant", subscription.Active, at, nil, publication.DatasetZones),
		sub("restrictions", subscription.Active, before, nil, publication.DatasetRestrictions),
		sub("far box", subscription.Active, before, &geodesy.BBox{MinLon: 10, MinLat: 10, MaxLon: 11, MaxLat: 11}, publication.DatasetZones),
	}
	c := publication.Change{ID: 1, Dataset: publication.DatasetZones, At: at, BBox: &geodesy.BBox{MinLon: 44, MinLat: 41, MaxLon: 45, MaxLat: 42}}
	got := Matching(subs, c)
	want := []string{"zones", "pending", "same instant"}
	if len(got) != len(want) {
		t.Fatalf("matching %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("matching %v, want %v", got, want)
		}
	}
}

// A change through the consumer writes one row per match and is
// acknowledged; the same change again (a redelivery) writes nothing and
// is acknowledged (B-05).
func TestHandleIdempotent(t *testing.T) {
	h := newHarness(t, nil)
	h.subscribe("S1", "https://a.example.ge/hook", subscription.Active)
	h.subscribe("S2", "https://b.example.ge/hook", subscription.Active)
	h.subscribe("S3", "https://c.example.ge/hook", subscription.Active, publication.DatasetUSSPList)
	c := h.change(5, time.Now())
	m := msgOf(t, c, 1)
	h.s.Handle(context.Background(), m, bus.DefaultMaxDeliver)
	if acked, _, _ := m.state(); !acked || h.deliveriesOf(5) != 2 || h.counter(CounterIntakeDeliveries) != 2 {
		t.Fatalf("first: acked %v, %d rows", acked, h.deliveriesOf(5))
	}
	again := msgOf(t, c, 2)
	h.s.Handle(context.Background(), again, bus.DefaultMaxDeliver)
	if acked, _, _ := again.state(); !acked || h.deliveriesOf(5) != 2 || h.counter(CounterIntakeDeliveries) != 2 {
		t.Errorf("redelivery: acked %v, %d rows", acked, h.deliveriesOf(5))
	}
}

// A message that is not a change is poison: counted and acknowledged.
// A store failure asks for redelivery with a growing delay until the
// last delivery, which is poison too (the scan covers it).
func TestHandleFailures(t *testing.T) {
	h := newHarness(t, nil)
	h.subscribe("S1", "https://a.example.ge/hook", subscription.Active)
	bad := &fakeMsg{data: []byte(`{"schema":"cis/change/v1","msg_id":"x"}`), delivered: 1}
	h.s.Handle(context.Background(), bad, bus.DefaultMaxDeliver)
	if acked, naked, _ := bad.state(); !acked || naked || h.counter(CounterBusPoison) != 1 {
		t.Errorf("not a change: acked %v naked %v", acked, naked)
	}
	c := h.change(9, time.Now())
	h.st.err = errDown
	m := msgOf(t, c, 3)
	h.s.Handle(context.Background(), m, bus.DefaultMaxDeliver)
	if acked, naked, delay := m.state(); acked || !naked || delay != 3*time.Second {
		t.Errorf("store down: acked %v naked %v delay %s", acked, naked, delay)
	}
	last := msgOf(t, c, bus.DefaultMaxDeliver)
	h.s.Handle(context.Background(), last, bus.DefaultMaxDeliver)
	if acked, naked, _ := last.state(); !acked || naked || h.counter(CounterBusPoison) != 2 {
		t.Errorf("last delivery: acked %v naked %v", acked, naked)
	}
	if h.counter(CounterIntakeFailed) != 2 {
		t.Errorf("intake failures %d", h.counter(CounterIntakeFailed))
	}
}

// fakeFetcher hands out batches, then errors, as scripted.
type fakeFetcher struct {
	mu      sync.Mutex
	batches [][]bus.Msg
	err     error
	cancel  context.CancelFunc
	fetched int
}

func (f *fakeFetcher) Fetch(ctx context.Context, _ int, _ time.Duration, each func(bus.Msg)) error {
	f.mu.Lock()
	f.fetched++
	if len(f.batches) == 0 {
		f.mu.Unlock()
		if f.cancel != nil {
			f.cancel()
		}
		<-ctx.Done()
		return f.err
	}
	b := f.batches[0]
	f.batches = f.batches[1:]
	f.mu.Unlock()
	for _, m := range b {
		each(m)
	}
	return nil
}

// The consumer: opened after a failure, its messages handled; stopped
// with a batch in hand, the unhandled rest are handed back (Nak).
func TestRunConsumer(t *testing.T) {
	h := newHarness(t, nil)
	h.subscribe("S1", "https://a.example.ge/hook", subscription.Active)
	c1, c2 := h.change(1, time.Now()), h.change(2, time.Now())
	m1, m2 := msgOf(t, c1, 1), msgOf(t, c2, 1)
	ctx, cancel := context.WithCancel(context.Background())
	f := &fakeFetcher{batches: [][]bus.Msg{{m1}}, cancel: cancel}
	opens := 0
	var states []string
	h.s.RunConsumer(ctx, ConsumerOptions{
		Open: func(context.Context) (Fetcher, error) {
			opens++
			if opens == 1 {
				return nil, errors.New("nats: no servers available")
			}
			return f, nil
		},
		OnState: func(p string) { states = append(states, p) },
	})
	if opens != 2 || len(states) == 0 || states[0] != "consumer not open: nats: no servers available" {
		t.Errorf("opens %d, states %q", opens, states)
	}
	if acked, _, _ := m1.state(); !acked || h.deliveriesOf(1) != 1 {
		t.Error("message not handled")
	}

	// Stopped mid-batch: the message after the stop is handed back.
	ctx, cancel = context.WithCancel(context.Background())
	stopper := &stopMsg{fakeMsg: msgOf(t, c1, 2), cancel: cancel}
	f = &fakeFetcher{batches: [][]bus.Msg{{stopper, m2}}}
	h.s.RunConsumer(ctx, ConsumerOptions{Open: func(context.Context) (Fetcher, error) { return f, nil }})
	if acked, naked, _ := m2.state(); acked || !naked {
		t.Errorf("unhandled message: acked %v naked %v", acked, naked)
	}
	if h.deliveriesOf(2) != 0 {
		t.Error("a handed-back message was handled")
	}
}

// stopMsg stops the consumer when it is acknowledged.
type stopMsg struct {
	*fakeMsg
	cancel context.CancelFunc
}

func (m *stopMsg) Ack() error {
	m.cancel()
	return m.fakeMsg.Ack()
}

// The scan writes the rows of changes the bus never brought and counts
// them; the watermark passes only settled changes; a second scan writes
// nothing (D6, E-02).
func TestScan(t *testing.T) {
	h := newHarness(t, nil)
	h.subscribe("S1", "https://a.example.ge/hook", subscription.Active)
	now := time.Now()
	h.change(1, now.Add(-time.Minute))      // settled
	h.change(2, now.Add(-40*time.Second))   // settled
	h.change(3, now.Add(-5*time.Second))    // past the grace, not settled
	h.change(4, now.Add(-time.Millisecond)) // within the grace: the bus's
	n, err := h.s.Scan(context.Background())
	if err != nil || n != 3 {
		t.Fatalf("scan wrote %d %v, want 3", n, err)
	}
	if h.deliveriesOf(4) != 0 || h.counter(CounterScanDeliveries) != 3 || h.st.watermark != 2 {
		t.Errorf("rows of 4: %d, counter %d, watermark %d", h.deliveriesOf(4), h.counter(CounterScanDeliveries), h.st.watermark)
	}
	if n, err := h.s.Scan(context.Background()); err != nil || n != 0 {
		t.Errorf("second scan wrote %d %v", n, err)
	}
	if h.counter(CounterScanDeliveries) != 3 || h.counter(CounterScans) != 2 {
		t.Errorf("counters %d %d", h.counter(CounterScanDeliveries), h.counter(CounterScans))
	}
	// Nothing new: no rows, the watermark kept.
	h.st.err = errDown
	if _, err := h.s.Scan(context.Background()); err == nil {
		t.Error("scan with the store down succeeded")
	}
	h.st.err = nil

	// RunScan: a tick scans; a failing tick is counted.
	tick := make(chan time.Time)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.s.RunScan(ctx, tick); close(done) }()
	h.st.mu.Lock()
	h.st.err = errDown
	h.st.mu.Unlock()
	tick <- time.Now()
	tick <- time.Now()
	cancel()
	<-done
	if h.counter(CounterScanFailed) < 1 {
		t.Error("failed scan not counted")
	}
	if h.s.ScanInterval() != DefaultScanInterval {
		t.Errorf("scan interval %s", h.s.ScanInterval())
	}
}
