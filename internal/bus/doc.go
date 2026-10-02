// Package bus is the CISP's NATS JetStream adapter (docs/PLAN.md section
// 7): connect without ever giving up and start degraded, ensure the
// CIS_CHANGES stream, publish a committed change with an
// acknowledgement, deliver's durable consumer (WP-6) and the stream
// hub's subscription (WP-7).
//
//	func Connect(ctx context.Context, cfg Config) (*Bus, error)
//	func (b *Bus) State() State
//	func (b *Bus) Watch(fn func(prev, next State)) (stop func())
//	func (b *Bus) EnsureStream(ctx context.Context) error
//	func (b *Bus) Publish(ctx context.Context, c publication.Change) error
//	func (b *Bus) Subscribe(ctx context.Context, subjects []string, h Handler) (*Subscription, error)
//
// Connect returns within ConnectTimeout (CISP_NATS_CONNECT_TIMEOUT_S,
// 5 s) whether or not the broker answered (LESSONS B-08, E-02): the
// connection retries in the background (RetryOnFailedConnect,
// MaxReconnects(-1), ReconnectWait 2 s), and State says where it is:
// connected, reconnecting since the loss, or never connected since the
// start. Watch is told every change, in order; the processes put it in
// their status line and the stream's status frames. A slow-consumer
// error is handed to OnSlowConsumer (counted and logged once per
// interval by the caller), never fatal.
//
// EnsureStream creates or updates CIS_CHANGES (subjects
// cis.v1.change.*, file storage, 30 days, 1 GiB, duplicate window
// 2 min) and is idempotent; Publish ensures it once first. Publish
// sends cis/change/v1 on cis.v1.change.<dataset> with Nats-Msg-Id = the
// change cursor, so a repeated publish of one change is stored once,
// and waits at most AckWait (5 s) for the stream's acknowledgement. Its
// error is for the caller to count (bus_publish_failed): the change is
// already committed and deliver's scan covers a lost publish (D6). A
// publish that timed out while the broker was down may still be sent
// on the reconnect from the client's buffer; the cursor deduplicates it.
//
// The consumer side (WP-6) is deliver's durable pull consumer:
//
//	func (b *Bus) DurableConsumer(ctx context.Context, cfg ConsumerConfig) (*Consumer, error)
//	func (c *Consumer) Fetch(ctx context.Context, batch int, maxWait time.Duration, each func(Msg)) error
//	func ParseChange(data []byte) (publication.Change, error)
//
// "deliver" on every cis.v1.change.* subject, explicit ack, at most 256
// unacknowledged, 30 s ack wait, 20 deliveries, from the newest message
// on first creation. Fetch hands each message over as it arrives.
//
// The subscribe side (WP-7) is the api stream hub's: a core NATS
// subscription on the stream's subjects that replays nothing, works
// with the broker absent (the client sends it on connect), and tells
// its Handler to resync, with the instant changes may have been missed
// from, on every return of the connection and after a slow-consumer
// drop.
package bus
