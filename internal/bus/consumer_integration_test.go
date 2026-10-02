//go:build integration

package bus

import (
	"context"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rootxkit/uspace-cisp/internal/publication"
)

// The consumer side under the bus's policy, against the real broker: a
// durable consumer created from the newest message, a published change
// fetched with its delivery count, a Nak redelivered with the count
// raised, an Ack ending it, a fetch of nothing returning no error, and
// the consumer deleted (E-01 pairs: fetched, then nothing to fetch).
func TestDurableConsumerRoundTrip(t *testing.T) {
	ctx := context.Background()
	b := connectTest(t)
	name := "wp7-test-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	c, err := b.DurableConsumer(ctx, ConsumerConfig{Name: name})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.DeleteConsumer(context.Background(), name) })
	if c.Config().Name != name || c.Config().MaxAckPending != DefaultMaxAckPending || c.Config().AckWait != DefaultConsumerAckWait {
		t.Errorf("config %+v", c.Config())
	}
	ch := change()
	ch.ID = time.Now().UnixNano()%1e12 + 1
	if err := b.Publish(ctx, ch); err != nil {
		t.Fatal(err)
	}
	var got []Msg
	fetch := func() {
		got = got[:0]
		if err := c.Fetch(ctx, 1, 5*time.Second, func(m Msg) { got = append(got, m) }); err != nil {
			t.Fatal(err)
		}
	}
	fetch()
	if len(got) != 1 || got[0].NumDelivered() != 1 {
		t.Fatalf("fetched %d messages", len(got))
	}
	if pc, err := ParseChange(got[0].Data()); err != nil || pc.ID != ch.ID {
		t.Errorf("fetched %+v %v", pc, err)
	}
	if err := got[0].Nak(0); err != nil {
		t.Fatal(err)
	}
	fetch()
	if len(got) != 1 || got[0].NumDelivered() != 2 {
		t.Fatalf("after a Nak: %d messages", len(got))
	}
	if err := got[0].Ack(); err != nil {
		t.Fatal(err)
	}
	dctx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	got = got[:0]
	if err := c.Fetch(dctx, 1, time.Second, func(m Msg) { got = append(got, m) }); err != nil || len(got) != 0 {
		for _, m := range got {
			t.Logf("unexpected %s delivered %d", m.Data(), m.NumDelivered())
		}
		t.Errorf("nothing to fetch: %d messages, %v", len(got), err)
	}
	if err := b.DeleteConsumer(ctx, name); err != nil {
		t.Fatal(err)
	}
	if err := b.DeleteConsumer(ctx, name); err == nil {
		t.Error("a deleted consumer deleted again")
	}
	if ack, err := b.PublishRaw(ctx, publication.DatasetZones, "raw-"+name, []byte(`{}`)); err != nil || ack.Stream != StreamName {
		t.Errorf("raw publish %v %v", ack, err)
	}
}

// The slow-consumer path for real: a handler that does not return lets
// the client's pending buffer overflow; the error is reported to
// OnSlowConsumer (counted, never fatal) and the subscription asks for a
// resync. The healthy twin: the same subscription with a handler that
// keeps up raises nothing (TestOutageWithARealBroker).
func TestSlowConsumerIsReportedAndResyncs(t *testing.T) {
	url := os.Getenv("CISP_TEST_NATS_URL")
	if url == "" {
		t.Fatal("CISP_TEST_NATS_URL is not set; run make dev-deps")
	}
	var slow atomic.Int64
	b, err := Connect(context.Background(), Config{URL: url, Name: "slow-test", ConnectTimeout: 5 * time.Second,
		OnSlowConsumer: func(error) { slow.Add(1) }})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	release := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	resynced := make(chan time.Time, 4)
	subject := SubjectPrefix + "wp7slow" + strconv.FormatInt(time.Now().UnixNano(), 36)
	s, err := b.Subscribe(context.Background(), []string{subject}, Handler{
		Unreadable: func(error) { <-release },
		Resync: func(since time.Time) {
			select {
			case resynced <- since:
			default:
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for i := range DefaultPendingMsgs + 200 {
		if err := b.nc.Publish(subject, []byte(strconv.Itoa(i))); err != nil {
			t.Fatal(err)
		}
	}
	if err := b.nc.Flush(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-resynced:
	case <-time.After(10 * time.Second):
		t.Fatal("no resync after the slow consumer")
	}
	if slow.Load() == 0 {
		t.Error("the slow consumer was not reported")
	}
	once.Do(func() { close(release) })
	if st := b.State(); st.Kind != StateConnected {
		t.Errorf("a slow consumer changed the connection: %s", st)
	}
}
