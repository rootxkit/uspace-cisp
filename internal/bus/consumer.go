package bus

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/rootxkit/uspace-core/geodesy"

	"github.com/rootxkit/uspace-cisp/internal/publication"
)

// The consumer side (WP-6): deliver's durable pull consumer on
// CIS_CHANGES (docs/PLAN.md section 7). WP-7 owns the reconnect and
// degraded-start policy; this is the consumer and its messages.

// Defaults of deliver's consumer (docs/WORKPACKAGES/WP-6.md).
const (
	// DeliverConsumer is the durable name every deliver instance shares:
	// JetStream hands each message to one of them.
	DeliverConsumer         = "deliver"
	DefaultMaxAckPending    = 256
	DefaultConsumerAckWait  = 30 * time.Second
	DefaultMaxDeliver       = 20
	DefaultFetchMaxWait     = time.Second
	DefaultFetchBatch       = 64
	maxChangeMessageBytes   = 1 << 20
	maxChangeMessageIDDigit = 19
)

// ConsumerConfig is a durable pull consumer of CIS_CHANGES. Zero values
// take the defaults.
type ConsumerConfig struct {
	Name          string
	MaxAckPending int
	AckWait       time.Duration
	MaxDeliver    int
}

func (c *ConsumerConfig) defaults() {
	if c.Name == "" {
		c.Name = DeliverConsumer
	}
	if c.MaxAckPending <= 0 {
		c.MaxAckPending = DefaultMaxAckPending
	}
	if c.AckWait <= 0 {
		c.AckWait = DefaultConsumerAckWait
	}
	if c.MaxDeliver <= 0 {
		c.MaxDeliver = DefaultMaxDeliver
	}
}

// JetStreamConfig is the consumer as the server holds it: explicit ack,
// at most MaxAckPending unacknowledged, redelivered after AckWait, at
// most MaxDeliver times, every subject of the stream, and from the
// newest message on its first creation (what came before is the
// reconciliation scan's, D6).
func (c ConsumerConfig) JetStreamConfig() jetstream.ConsumerConfig {
	c.defaults()
	return jetstream.ConsumerConfig{
		Durable:       c.Name,
		AckPolicy:     jetstream.AckExplicitPolicy,
		AckWait:       c.AckWait,
		MaxAckPending: c.MaxAckPending,
		MaxDeliver:    c.MaxDeliver,
		FilterSubject: SubjectPrefix + "*",
		DeliverPolicy: jetstream.DeliverNewPolicy,
	}
}

// Consumer is a durable pull consumer.
type Consumer struct {
	c   jetstream.Consumer
	cfg ConsumerConfig
}

// Config is the consumer's configuration with its defaults.
func (c *Consumer) Config() ConsumerConfig { return c.cfg }

// DurableConsumer ensures the stream and creates the durable consumer,
// or brings it to cfg; every instance calling it shares one consumer.
func (b *Bus) DurableConsumer(ctx context.Context, cfg ConsumerConfig) (*Consumer, error) {
	cfg.defaults()
	if err := b.EnsureStream(ctx); err != nil {
		return nil, err
	}
	c, err := b.js.CreateOrUpdateConsumer(ctx, StreamName, cfg.JetStreamConfig())
	if err != nil {
		return nil, fmt.Errorf("bus: consumer %s: %w", cfg.Name, err)
	}
	return &Consumer{c: c, cfg: cfg}, nil
}

// Msg is one message of the consumer.
type Msg interface {
	Data() []byte
	// NumDelivered is how many times the message has been delivered,
	// this time included.
	NumDelivered() uint64
	Ack() error
	// Nak asks for redelivery after delay.
	Nak(delay time.Duration) error
}

type jsMsg struct{ m jetstream.Msg }

// Data is the message body.
func (j jsMsg) Data() []byte { return j.m.Data() }

// NumDelivered is the delivery count from the message's metadata.
func (j jsMsg) NumDelivered() uint64 {
	md, err := j.m.Metadata()
	if err != nil {
		return 1
	}
	return md.NumDelivered
}

// Ack acknowledges the message.
func (j jsMsg) Ack() error { return j.m.Ack() }

// Nak asks for redelivery after delay.
func (j jsMsg) Nak(delay time.Duration) error { return j.m.NakWithDelay(delay) }

// Fetch asks for up to batch messages for at most maxWait and hands
// each to each as it arrives: a change is handled at once, never held
// until the batch fills or the wait ends (that wait would be the
// webhook's latency). No message and no error is the broker saying
// nothing came; an error is the broker or the connection failing.
func (c *Consumer) Fetch(ctx context.Context, batch int, maxWait time.Duration, each func(Msg)) error {
	if batch <= 0 {
		batch = DefaultFetchBatch
	}
	if maxWait <= 0 {
		maxWait = DefaultFetchMaxWait
	}
	if dl, ok := ctx.Deadline(); ok && time.Until(dl) < maxWait {
		maxWait = max(time.Until(dl), time.Millisecond)
	}
	b, err := c.c.Fetch(batch, jetstream.FetchMaxWait(maxWait))
	if err != nil {
		return fmt.Errorf("bus: fetch: %w", err)
	}
	for m := range b.Messages() {
		each(jsMsg{m: m})
	}
	if err := b.Error(); err != nil && !errors.Is(err, jetstream.ErrNoMessages) {
		return fmt.Errorf("bus: fetch: %w", err)
	}
	return nil
}

// ParseChange reads a cis/change/v1 message body back into the change it
// was made of. It refuses a body that is not one: too large, not JSON, an
// unknown member, another schema, a cursor that is not a positive
// decimal, an unknown dataset or reason, or a box that is not four
// numbers. pull_url, etag and producer are derived and not read back.
func ParseChange(data []byte) (publication.Change, error) {
	if len(data) > maxChangeMessageBytes {
		return publication.Change{}, fmt.Errorf("bus: change message of %d bytes", len(data))
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var m ChangeMessage
	if err := dec.Decode(&m); err != nil {
		return publication.Change{}, fmt.Errorf("bus: change message: %w", err)
	}
	if m.Schema != SchemaChange {
		return publication.Change{}, fmt.Errorf("bus: change message schema %q", m.Schema)
	}
	if len(m.MsgID) == 0 || len(m.MsgID) > maxChangeMessageIDDigit {
		return publication.Change{}, fmt.Errorf("bus: change message msg_id %q", m.MsgID)
	}
	id, err := strconv.ParseInt(m.MsgID, 10, 64)
	if err != nil || id <= 0 {
		return publication.Change{}, fmt.Errorf("bus: change message msg_id %q is not a cursor", m.MsgID)
	}
	ds := publication.Dataset(m.Dataset)
	if !ds.Valid() {
		return publication.Change{}, fmt.Errorf("bus: change message dataset %q", m.Dataset)
	}
	r := publication.Reason(m.Reason)
	if !r.VersionReason() {
		return publication.Change{}, fmt.Errorf("bus: change message reason %q", m.Reason)
	}
	c := publication.Change{
		ID: id, Dataset: ds, Version: m.Version, FeatureIDs: m.FeatureIDs, RemovedIDs: m.RemovedIDs,
		Reason: r, At: m.At.UTC(),
	}
	if m.BBox != nil {
		if len(m.BBox) != 4 {
			return publication.Change{}, fmt.Errorf("bus: change message bbox of %d numbers", len(m.BBox))
		}
		c.BBox = &geodesy.BBox{MinLon: m.BBox[0], MinLat: m.BBox[1], MaxLon: m.BBox[2], MaxLat: m.BBox[3]}
	}
	return c, nil
}

// DeleteConsumer removes a durable consumer (tests and operations).
func (b *Bus) DeleteConsumer(ctx context.Context, name string) error {
	if err := b.js.DeleteConsumer(ctx, StreamName, name); err != nil {
		return fmt.Errorf("bus: delete consumer %s: %w", name, err)
	}
	return nil
}

// PublishRaw publishes body on the dataset's subject under msgID, for
// the tests that send the same change under two message ids.
func (b *Bus) PublishRaw(ctx context.Context, ds publication.Dataset, msgID string, body []byte) (*jetstream.PubAck, error) {
	if err := b.EnsureStream(ctx); err != nil {
		return nil, err
	}
	ack, err := b.js.Publish(ctx, SubjectPrefix+string(ds), body, jetstream.WithMsgID(msgID))
	if err != nil {
		return nil, fmt.Errorf("bus: publish: %w", err)
	}
	return ack, nil
}
