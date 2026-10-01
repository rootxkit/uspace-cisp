package bus

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/rootxkit/uspace-cisp/internal/publication"
)

// The stream and its subjects (docs/PLAN.md section 7).
const (
	StreamName    = "CIS_CHANGES"
	SubjectPrefix = "cis.v1.change."
	// SchemaChange names the message body.
	SchemaChange = "cis/change/v1"
	// Producer is the producer of every message.
	Producer = "uspace-cisp"
)

// Defaults (docs/PLAN.md section 7).
const (
	DefaultAckWait        = 5 * time.Second
	DefaultReconnectWait  = 2 * time.Second
	DefaultStreamMaxAge   = 30 * 24 * time.Hour
	DefaultStreamMaxBytes = 1 << 30
	DefaultDuplicates     = 2 * time.Minute
)

// Config is the connection and the stream. Zero durations and sizes take
// the defaults.
type Config struct {
	// URL is CISP_NATS_URL; CredsFile is CISP_NATS_CREDS_FILE (empty: none).
	URL, CredsFile string
	// Name is the connection name ("uspace-cisp-api").
	Name string
	// PublicBaseURL prefixes pull_url (CISP_PUBLIC_BASE_URL).
	PublicBaseURL string

	AckWait        time.Duration
	ReconnectWait  time.Duration
	StreamMaxAge   time.Duration
	StreamMaxBytes int64
	Duplicates     time.Duration

	// OnState, when set, is told every connection state change.
	OnState func(connected bool, state string)
}

func (c *Config) defaults() {
	if c.AckWait <= 0 {
		c.AckWait = DefaultAckWait
	}
	if c.ReconnectWait <= 0 {
		c.ReconnectWait = DefaultReconnectWait
	}
	if c.StreamMaxAge <= 0 {
		c.StreamMaxAge = DefaultStreamMaxAge
	}
	if c.StreamMaxBytes <= 0 {
		c.StreamMaxBytes = DefaultStreamMaxBytes
	}
	if c.Duplicates <= 0 {
		c.Duplicates = DefaultDuplicates
	}
}

// Bus is a JetStream connection.
type Bus struct {
	cfg Config
	nc  *nats.Conn
	js  jetstream.JetStream

	mu      sync.Mutex
	ensured bool
}

// Connect connects without blocking on an absent broker and without ever
// giving up reconnecting.
func Connect(_ context.Context, cfg Config) (*Bus, error) {
	cfg.defaults()
	if cfg.URL == "" {
		return nil, errors.New("bus: no NATS URL")
	}
	tell := func(connected bool, state string) {
		if cfg.OnState != nil {
			cfg.OnState(connected, state)
		}
	}
	opts := []nats.Option{
		nats.Name(cfg.Name),
		nats.RetryOnFailedConnect(true),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(cfg.ReconnectWait),
		nats.ConnectHandler(func(*nats.Conn) { tell(true, "connected") }),
		nats.ReconnectHandler(func(*nats.Conn) { tell(true, "reconnected") }),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			state := "disconnected"
			if err != nil {
				state += ": " + err.Error()
			}
			tell(false, state)
		}),
	}
	if cfg.CredsFile != "" {
		opts = append(opts, nats.UserCredentials(cfg.CredsFile))
	}
	nc, err := nats.Connect(cfg.URL, opts...)
	if err != nil {
		return nil, fmt.Errorf("bus: connect: %w", err)
	}
	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("bus: jetstream: %w", err)
	}
	b := &Bus{cfg: cfg, nc: nc, js: js}
	if nc.IsConnected() {
		tell(true, "connected")
	} else {
		tell(false, "connecting")
	}
	return b, nil
}

// Close closes the connection.
func (b *Bus) Close() { b.nc.Close() }

// Conn is the underlying connection (WP-7's subscribe side).
func (b *Bus) Conn() *nats.Conn { return b.nc }

// Status reports whether the connection is up and its state.
func (b *Bus) Status() (connected bool, state string) {
	return b.nc.IsConnected(), strings.ToLower(b.nc.Status().String())
}

// StreamConfig is CIS_CHANGES as Config sets it.
func (b *Bus) StreamConfig() jetstream.StreamConfig {
	return jetstream.StreamConfig{
		Name:       StreamName,
		Subjects:   []string{SubjectPrefix + "*"},
		Storage:    jetstream.FileStorage,
		Retention:  jetstream.LimitsPolicy,
		MaxAge:     b.cfg.StreamMaxAge,
		MaxBytes:   b.cfg.StreamMaxBytes,
		Duplicates: b.cfg.Duplicates,
	}
}

// EnsureStream creates CIS_CHANGES or brings it to the configuration;
// calling it again changes nothing.
func (b *Bus) EnsureStream(ctx context.Context) error {
	if _, err := b.js.CreateOrUpdateStream(ctx, b.StreamConfig()); err != nil {
		return fmt.Errorf("bus: ensure stream %s: %w", StreamName, err)
	}
	b.mu.Lock()
	b.ensured = true
	b.mu.Unlock()
	return nil
}

// ChangeMessage is the cis/change/v1 body (docs/PLAN.md section 6.7).
type ChangeMessage struct {
	Schema     string    `json:"schema"`
	MsgID      string    `json:"msg_id"`
	Producer   string    `json:"producer"`
	Dataset    string    `json:"dataset"`
	Version    int64     `json:"version"`
	ETag       string    `json:"etag"`
	FeatureIDs []string  `json:"feature_ids"`
	RemovedIDs []string  `json:"removed_ids"`
	Reason     string    `json:"reason"`
	At         time.Time `json:"at"`
	PullURL    string    `json:"pull_url"`
	// BBox is [min longitude, min latitude, max longitude, max latitude]
	// (GeoJSON order); absent for the whole dataset.
	BBox []float64 `json:"bbox,omitempty"`
}

// Message is the cis/change/v1 body of a change. pull_url asks for the
// delta from the previous version.
func (b *Bus) Message(c publication.Change) ChangeMessage {
	m := ChangeMessage{
		Schema:     SchemaChange,
		MsgID:      strconv.FormatInt(c.ID, 10),
		Producer:   Producer,
		Dataset:    string(c.Dataset),
		Version:    c.Version,
		ETag:       publication.ETag(c.Dataset, c.Version),
		FeatureIDs: nonNil(c.FeatureIDs),
		RemovedIDs: nonNil(c.RemovedIDs),
		Reason:     string(c.Reason),
		At:         c.At.UTC(),
		PullURL:    strings.TrimSuffix(b.cfg.PublicBaseURL, "/") + "/v1/" + string(c.Dataset) + "?since_version=" + strconv.FormatInt(max(c.Version-1, 0), 10),
	}
	if c.BBox != nil {
		m.BBox = []float64{c.BBox.MinLon, c.BBox.MinLat, c.BBox.MaxLon, c.BBox.MaxLat}
	}
	return m
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// Publish sends the change and waits for the stream's acknowledgement,
// at most AckWait. A change without a cursor (ID 0) is refused: the
// cursor is the deduplication key.
func (b *Bus) Publish(ctx context.Context, c publication.Change) error {
	_, err := b.PublishAck(ctx, c)
	return err
}

// PublishAck is Publish returning the acknowledgement (Duplicate is set
// when the stream had already stored this change).
func (b *Bus) PublishAck(ctx context.Context, c publication.Change) (*jetstream.PubAck, error) {
	if c.ID <= 0 {
		return nil, errors.New("bus: a change without a cursor cannot be deduplicated")
	}
	ctx, cancel := context.WithTimeout(ctx, b.cfg.AckWait)
	defer cancel()
	b.mu.Lock()
	ensured := b.ensured
	b.mu.Unlock()
	if !ensured {
		if err := b.EnsureStream(ctx); err != nil {
			return nil, err
		}
	}
	body, err := json.Marshal(b.Message(c))
	if err != nil {
		return nil, fmt.Errorf("bus: encode change: %w", err)
	}
	msg := nats.NewMsg(SubjectPrefix + string(c.Dataset))
	msg.Data = body
	future, err := b.js.PublishMsgAsync(msg, jetstream.WithMsgID(strconv.FormatInt(c.ID, 10)))
	if err != nil {
		return nil, fmt.Errorf("bus: publish change %d: %w", c.ID, err)
	}
	select {
	case ack := <-future.Ok():
		return ack, nil
	case err := <-future.Err():
		return nil, fmt.Errorf("bus: publish change %d: %w", c.ID, err)
	case <-ctx.Done():
		return nil, fmt.Errorf("bus: publish change %d: no acknowledgement within %s: %w", c.ID, b.cfg.AckWait, ctx.Err())
	}
}
