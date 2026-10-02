package stream

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/rootxkit/uspace-cisp/internal/bus"
)

// The frame contract: the lab's envelope/v1, console/status/v1 and
// source/status/v1 (testdata/common, pinned in UPSTREAM) and this
// repository's cis/change/v1.
const (
	idEnvelope = "https://schemas.uspace.ge/envelope/v1.json"
	idStatus   = "https://schemas.uspace.ge/console/status/v1.json"
	idChange   = "https://schemas.uspace.ge/cis/change/v1.json"
)

type contract struct {
	envelope, status, change *jsonschema.Schema
}

var (
	contractOnce sync.Once
	theContract  contract
	errContract  error
)

func loadContract(t testing.TB) contract {
	t.Helper()
	contractOnce.Do(func() {
		c := jsonschema.NewCompiler()
		for _, f := range []string{
			"testdata/common/envelope/v1/schema.json",
			"testdata/common/console/status/v1/schema.json",
			"testdata/common/source/status/v1/schema.json",
			"../../schemas/cis/change/v1.json",
		} {
			raw, err := os.ReadFile(filepath.FromSlash(f))
			if err != nil {
				errContract = err
				return
			}
			doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
			if err != nil {
				errContract = err
				return
			}
			id, _ := doc.(map[string]any)["$id"].(string)
			if err := c.AddResource(id, doc); err != nil {
				errContract = err
				return
			}
		}
		var out contract
		for id, dst := range map[string]**jsonschema.Schema{idEnvelope: &out.envelope, idStatus: &out.status, idChange: &out.change} {
			s, err := c.Compile(id)
			if err != nil {
				errContract = err
				return
			}
			*dst = s
		}
		theContract = out
	})
	if errContract != nil {
		t.Fatal(errContract)
	}
	return theContract
}

// validateFrame validates a frame against the envelope and its body
// against the schema it names; it returns the decoded envelope.
func validateFrame(t testing.TB, frame []byte) Envelope {
	t.Helper()
	c := loadContract(t)
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(frame))
	if err != nil {
		t.Fatalf("frame is not JSON: %v\n%s", err, frame)
	}
	if err := c.envelope.Validate(doc); err != nil {
		t.Fatalf("frame is not envelope/v1: %v\n%s", err, frame)
	}
	var env Envelope
	if err := json.Unmarshal(frame, &env); err != nil {
		t.Fatal(err)
	}
	switch env.Schema {
	case SchemaStatus:
		if err := c.status.Validate(doc); err != nil {
			t.Fatalf("frame is not console/status/v1: %v\n%s", err, frame)
		}
	case SchemaChange:
		body, err := jsonschema.UnmarshalJSON(bytes.NewReader(env.Body))
		if err != nil {
			t.Fatal(err)
		}
		if err := c.change.Validate(body); err != nil {
			t.Fatalf("body is not cis/change/v1: %v\n%s", err, frame)
		}
	default:
		t.Fatalf("frame schema %q: no other frame exists", env.Schema)
	}
	return env
}

func statusOf(t testing.TB, env Envelope) StatusBody {
	t.Helper()
	var b StatusBody
	if err := json.Unmarshal(env.Body, &b); err != nil {
		t.Fatal(err)
	}
	return b
}

// fakeConn records frames; Write blocks while block is set.
type fakeConn struct {
	mu     sync.Mutex
	frames [][]byte
	closed chan websocket.StatusCode
	block  chan struct{}
	fail   error
}

func newFakeConn() *fakeConn { return &fakeConn{closed: make(chan websocket.StatusCode, 1)} }

func (f *fakeConn) Write(ctx context.Context, frame []byte) error {
	f.mu.Lock()
	block, fail := f.block, f.fail
	f.mu.Unlock()
	if fail != nil {
		return fail
	}
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	f.mu.Lock()
	f.frames = append(f.frames, frame)
	f.mu.Unlock()
	return nil
}

func (f *fakeConn) Close(code websocket.StatusCode, _ string) error {
	select {
	case f.closed <- code:
	default:
	}
	return nil
}

func (f *fakeConn) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.frames)
}

func (f *fakeConn) frame(i int) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.frames[i]
}

func waitFor(t testing.TB, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func change(id int64, dataset string, at time.Time) bus.ChangeMessage {
	return bus.ChangeMessage{
		Schema: bus.SchemaChange, MsgID: itoa(id), Producer: bus.Producer, Dataset: dataset, Version: id,
		ETag: dataset + ":" + itoa(id), FeatureIDs: []string{"Z1"}, RemovedIDs: []string{}, Reason: "publication",
		At: at.UTC(), PullURL: "https://cisp.example.ge/v1/" + dataset + "?since_version=" + itoa(id-1),
	}
}

func itoa(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// healthyParts is a status with two datasets and a fresh publisher.
func healthyParts(now time.Time) Parts {
	age := 3.5
	hb := Timestamp(now.Add(-5 * time.Second))
	hbAge := 5.0
	return Parts{
		PolicyVersion: "cfg-0123456789ab", StaleAfterS: 60, Degraded: []string{},
		Datasets: map[string]DatasetStatus{"zones": {Version: "7", AgeS: 12}, "restrictions": {Version: "3", AgeS: 3.5}},
		CISAgeS:  &age, NATS: bus.StateConnected,
		Publishers: []PublisherStatus{{ClientID: "authority-01", Kind: "authority", LastHeartbeatAt: &hb, HeartbeatAgeS: &hbAge, StaleAfterS: 60}},
	}
}

func readFile(name string) ([]byte, error) { return os.ReadFile(filepath.FromSlash(name)) }

func unmarshalJSON(b []byte) (any, error) { return jsonschema.UnmarshalJSON(bytes.NewReader(b)) }
