package stream

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"time"

	"github.com/rootxkit/uspace-cisp/internal/bus"
)

// Frame schemas: the only two bodies the stream carries (M29).
const (
	SchemaStatus = "console/status/v1"
	SchemaChange = bus.SchemaChange
)

// DefaultProducer is the envelope's producer: the system and the
// process, in the pattern of the lab's envelope/v1
// (`<system>/<process>`, or `<system>-<n>/<process>-<n>` with numbered
// instances on both sides).
const DefaultProducer = "cisp/api"

// TimeSourceSystem is the envelope's time_source of every frame here:
// every time it carries is on this system's clock.
const TimeSourceSystem = "system"

// tsLayout is envelope/v1's timestamp: RFC 3339 UTC with Z and exactly
// millisecond precision.
const tsLayout = "2006-01-02T15:04:05.000Z"

// Timestamp formats t as envelope/v1 requires.
func Timestamp(t time.Time) string { return t.UTC().Format(tsLayout) }

// Envelope is the common envelope (envelope/v1) around every frame.
type Envelope struct {
	Schema     string          `json:"schema"`
	MsgID      string          `json:"msg_id"`
	Producer   string          `json:"producer"`
	TS         *string         `json:"ts"`
	RxTS       string          `json:"rx_ts"`
	CapturedAt string          `json:"captured_at"`
	TimeSource string          `json:"time_source"`
	Backlog    bool            `json:"backlog"`
	Body       json.RawMessage `json:"body"`
}

// StatusBody is the console/status/v1 body. The members after Sources
// are the CISP's extras: datasets, cis_age_s, nats and resync_since are
// named by the lab's schema; degraded_since, nats_since and publishers
// are this system's further extras (unknown members are ignored within
// a major, envelope/v1).
type StatusBody struct {
	ConnectionID  string   `json:"connection_id"`
	ServerTS      string   `json:"server_ts"`
	PolicyVersion string   `json:"policy_version"`
	StaleAfterS   float64  `json:"stale_after_s"`
	LiveMaxAgeS   float64  `json:"live_max_age_s"`
	DroppedFrames uint64   `json:"dropped_frames"`
	Degraded      []string `json:"degraded"`
	// Sources is empty: the CISP's data comes from its publishers, which
	// are no source/status/v1 adapter type; they are in Publishers.
	Sources []json.RawMessage `json:"sources"`

	Datasets    map[string]DatasetStatus `json:"datasets,omitempty"`
	CISAgeS     *float64                 `json:"cis_age_s,omitempty"`
	NATS        string                   `json:"nats,omitempty"`
	ResyncSince string                   `json:"resync_since,omitempty"`

	DegradedSince map[string]string `json:"degraded_since,omitempty"`
	NATSSince     string            `json:"nats_since,omitempty"`
	Publishers    []PublisherStatus `json:"publishers"`
}

// DatasetStatus is one dataset's current version (decimal) and its age
// in seconds.
type DatasetStatus struct {
	Version string  `json:"version"`
	AgeS    float64 `json:"age_s"`
}

// PublisherStatus is one configured publisher's heartbeat.
type PublisherStatus struct {
	ClientID        string   `json:"client_id"`
	Kind            string   `json:"kind"`
	LastHeartbeatAt *string  `json:"last_heartbeat_at"`
	HeartbeatAgeS   *float64 `json:"heartbeat_age_s"`
	StaleAfterS     float64  `json:"stale_after_s"`
	Stale           bool     `json:"stale"`
}

// crockford is the ULID alphabet.
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// NewULID is a ULID for t: 48 bits of milliseconds and 80 random bits,
// in Crockford base32 (26 characters, the first 0-7).
func NewULID(t time.Time) string {
	var b [16]byte
	ms := uint64(max(t.UnixMilli(), 0))
	binary.BigEndian.PutUint64(b[0:8], ms<<16)
	_, _ = rand.Read(b[6:]) // crypto/rand.Read never fails (Go 1.24+)
	var out [26]byte
	hi := binary.BigEndian.Uint64(b[0:8])
	lo := binary.BigEndian.Uint64(b[8:16])
	// 128 bits as 26 five-bit groups from the top: the first group holds
	// the top 3 bits.
	for i := 25; i >= 0; i-- {
		out[i] = crockford[lo&0x1f]
		lo = lo>>5 | hi<<59
		hi >>= 5
	}
	return string(out[:])
}

// frameOf encodes an envelope with body.
func frameOf(schema, producer string, ts *time.Time, rx, captured time.Time, body any) ([]byte, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	env := Envelope{
		Schema: schema, MsgID: NewULID(rx), Producer: producer,
		RxTS: Timestamp(rx), CapturedAt: Timestamp(captured), TimeSource: TimeSourceSystem, Body: raw,
	}
	if ts != nil {
		s := Timestamp(*ts)
		env.TS = &s
	}
	return json.Marshal(env)
}
