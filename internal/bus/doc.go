// Package bus is the CISP's NATS JetStream adapter, minimal in WP-1
// (docs/PLAN.md section 7): connect without ever giving up, ensure the
// CIS_CHANGES stream, and publish a committed change with an
// acknowledgement. WP-7 adds the subscribe side and the degraded start.
//
//	func Connect(ctx context.Context, cfg Config) (*Bus, error)
//	func (b *Bus) EnsureStream(ctx context.Context) error
//	func (b *Bus) Publish(ctx context.Context, c publication.Change) error
//	func (b *Bus) Status() (connected bool, state string)
//
// Connect returns a usable handle even when the broker is down: the
// connection retries in the background (RetryOnFailedConnect,
// MaxReconnects(-1), ReconnectWait 2 s, LESSONS B-08), and Status says
// where it is. EnsureStream creates or updates CIS_CHANGES (subjects
// cis.v1.change.*, file storage, 30 days, 1 GiB, duplicate window
// 2 min) and is idempotent; Publish ensures it once first. Publish
// sends cis/change/v1 on cis.v1.change.<dataset> with Nats-Msg-Id = the
// change cursor, so a repeated publish of one change is stored once,
// and waits at most AckWait (5 s) for the stream's acknowledgement. Its
// error is for the caller to count (bus_publish_failed): the change is
// already committed and deliver's scan covers a lost publish (D6).
package bus
