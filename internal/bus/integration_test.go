//go:build integration

package bus

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/rootxkit/uspace-cisp/internal/publication"
)

func connectTest(t *testing.T) *Bus {
	t.Helper()
	url := os.Getenv("CISP_TEST_NATS_URL")
	if url == "" {
		t.Fatal("CISP_TEST_NATS_URL is not set; run make dev-deps")
	}
	b, err := Connect(context.Background(), Config{URL: url, Name: "uspace-cisp-test", PublicBaseURL: "https://cisp.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	deadline := time.Now().Add(5 * time.Second)
	for !b.nc.IsConnected() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if ok, state := b.Status(); !ok {
		t.Fatalf("not connected: %s", state)
	}
	return b
}

// EnsureStream twice gives one stream with the configured limits.
func TestEnsureStreamIsIdempotent(t *testing.T) {
	ctx := context.Background()
	b := connectTest(t)
	for range 2 {
		if err := b.EnsureStream(ctx); err != nil {
			t.Fatal(err)
		}
	}
	s, err := b.js.Stream(ctx, StreamName)
	if err != nil {
		t.Fatal(err)
	}
	info, err := s.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c := info.Config
	if c.Storage != jetstream.FileStorage || c.MaxAge != 30*24*time.Hour || c.MaxBytes != 1<<30 || c.Duplicates != 2*time.Minute || c.Subjects[0] != "cis.v1.change.*" {
		t.Errorf("stream config %+v", c)
	}
}

// A change is stored once whatever the number of publishes, and the
// stored message is the cis/change/v1 body.
func TestPublishIsAcknowledgedAndDeduplicated(t *testing.T) {
	ctx := context.Background()
	b := connectTest(t)
	c := change()
	c.ID = time.Now().UnixNano() // unique across runs within the dedupe window
	first, err := b.PublishAck(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if first.Duplicate || first.Stream != StreamName {
		t.Fatalf("first ack %+v", first)
	}
	second, err := b.PublishAck(ctx, c)
	if err != nil || !second.Duplicate || second.Sequence != first.Sequence {
		t.Fatalf("second ack %+v %v", second, err)
	}
	s, _ := b.js.Stream(ctx, StreamName)
	msg, err := s.GetMsg(ctx, first.Sequence)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Subject != "cis.v1.change.zones" || msg.Header.Get("Nats-Msg-Id") != b.Message(c).MsgID {
		t.Errorf("subject %s, msg id %q", msg.Subject, msg.Header.Get("Nats-Msg-Id"))
	}
	var got ChangeMessage
	if err := json.Unmarshal(msg.Data, &got); err != nil || got.Version != 7 || got.Dataset != string(publication.DatasetZones) || got.Schema != SchemaChange {
		t.Errorf("stored body %s (%v)", msg.Data, err)
	}
}
