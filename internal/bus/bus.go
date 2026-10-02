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

	// ConnectTimeout is how long Connect waits for the broker's first
	// answer (CISP_NATS_CONNECT_TIMEOUT_S); past it Connect returns the
	// handle anyway, never connected, and keeps trying in the
	// background. Zero does not wait.
	ConnectTimeout time.Duration

	AckWait        time.Duration
	ReconnectWait  time.Duration
	StreamMaxAge   time.Duration
	StreamMaxBytes int64
	Duplicates     time.Duration

	// OnState, when set, is told every connection state change.
	OnState func(connected bool, state string)
	// OnSlowConsumer, when set, is told every NATS slow-consumer error
	// (a subscription whose pending buffer overflowed and dropped
	// messages); it is counted and logged by the caller, never fatal.
	OnSlowConsumer func(err error)
	// Now is the clock of the state's since-times; nil is time.Now.
	Now func() time.Time
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
	if c.ConnectTimeout < 0 {
		c.ConnectTimeout = 0
	}
	if c.Now == nil {
		c.Now = time.Now
	}
}

// Bus is a JetStream connection.
type Bus struct {
	cfg Config
	nc  *nats.Conn
	js  jetstream.JetStream

	mu      sync.Mutex
	ensured bool

	state     State
	watchers  map[int]func(prev, next State)
	watcherID int
	// owners maps a NATS subscription to the Subscription that made it,
	// for the slow-consumer error.
	owners map[*nats.Subscription]*Subscription
}

// Connect connects without blocking on an absent broker for longer than
// ConnectTimeout and without ever giving up reconnecting (LESSONS B-08):
// with the broker down it returns a handle whose State is never
// connected, and the connection keeps trying in the background.
func Connect(ctx context.Context, cfg Config) (*Bus, error) {
	cfg.defaults()
	if cfg.URL == "" {
		return nil, errors.New("bus: no NATS URL")
	}
	b := &Bus{cfg: cfg, watchers: map[int]func(prev, next State){}, owners: map[*nats.Subscription]*Subscription{},
		state: State{Kind: StateNeverConnected, Since: cfg.Now().UTC()}}
	up := make(chan struct{}, 1)
	signal := func() {
		select {
		case up <- struct{}{}:
		default:
		}
	}
	opts := []nats.Option{
		nats.Name(cfg.Name),
		nats.RetryOnFailedConnect(true),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(cfg.ReconnectWait),
		nats.ConnectHandler(func(*nats.Conn) {
			b.transition(StateConnected, "")
			signal()
		}),
		nats.ReconnectHandler(func(*nats.Conn) { b.transition(StateConnected, "") }),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			reason := ""
			if err != nil {
				reason = err.Error()
			}
			b.transition(StateReconnecting, reason)
		}),
		nats.ClosedHandler(func(*nats.Conn) { b.transition(StateClosed, "") }),
		nats.ErrorHandler(func(_ *nats.Conn, sub *nats.Subscription, err error) {
			if !errors.Is(err, nats.ErrSlowConsumer) {
				return
			}
			if cfg.OnSlowConsumer != nil {
				cfg.OnSlowConsumer(err)
			}
			b.mu.Lock()
			owner := b.owners[sub]
			b.mu.Unlock()
			if owner != nil {
				owner.Dropped()
			}
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
	b.nc, b.js = nc, js
	if nc.IsConnected() {
		b.transition(StateConnected, "")
	} else {
		b.tell(b.State())
		if cfg.ConnectTimeout > 0 {
			wait := time.NewTimer(cfg.ConnectTimeout)
			defer wait.Stop()
			select {
			case <-up:
			case <-wait.C:
			case <-ctx.Done():
			}
		}
	}
	return b, nil
}

// Close closes the connection.
func (b *Bus) Close() { b.nc.Close() }

// Conn is the underlying connection.
func (b *Bus) Conn() *nats.Conn { return b.nc }

// Status reports whether the connection is up and its state, as State
// says it ("connected", "reconnecting since T", "never connected").
func (b *Bus) Status() (connected bool, state string) {
	st := b.State()
	return st.Kind == StateConnected, st.String()
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

// Message is the cis/change/v1 body of a change (MessageOf on the
// bus's CISP_PUBLIC_BASE_URL).
func (b *Bus) Message(c publication.Change) ChangeMessage {
	return MessageOf(c, b.cfg.PublicBaseURL)
}

// MessageOf is the cis/change/v1 body of a change: the same record on
// the bus, in GET /v1/changes and (WP-6) in a webhook. pull_url asks
// publicBaseURL for the delta from the previous version.
func MessageOf(c publication.Change, publicBaseURL string) ChangeMessage {
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
		PullURL:    strings.TrimSuffix(publicBaseURL, "/") + "/v1/" + string(c.Dataset) + "?since_version=" + strconv.FormatInt(max(c.Version-1, 0), 10),
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
