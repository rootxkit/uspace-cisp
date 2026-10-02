package deliver

import (
	"context"
	"log/slog"
	"time"

	"github.com/rootxkit/uspace-cisp/internal/bus"
	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/store"
	"github.com/rootxkit/uspace-cisp/internal/subscription"
)

// Matching is the subscriptions a change is sent to: those that match it
// (subscription.Matches) and existed when it was committed (a
// subscription is not sent what happened before it).
func Matching(subs []store.SubscriptionRecord, c publication.Change) []string {
	var ids []string
	for i := range subs {
		s := &subs[i]
		if !s.Status.Receives() || s.CreatedAt.After(c.At) {
			continue
		}
		if subscription.Matches(s.Subscription, c) {
			ids = append(ids, s.ID)
		}
	}
	return ids
}

// Intake queues the deliveries of one change: one row per matching
// subscription, in one transaction, none twice. It returns how many rows
// it wrote and wakes the sender when there are any.
func (s *Service) Intake(ctx context.Context, c publication.Change) (int64, error) {
	subs, err := s.store.ReceivingSubscriptions(ctx)
	if err != nil {
		return 0, err
	}
	n, err := s.store.InsertChangeDeliveries(ctx, c.ID, Matching(subs, c), s.now())
	if err != nil {
		return 0, err
	}
	if n > 0 {
		s.Wake()
	}
	return n, nil
}

// Handle takes one message of the consumer: the change's deliveries are
// written, then the message is acknowledged (B-05: persist before you
// acknowledge). A message that is not a change, or that fails at its
// MaxDeliver-th delivery, is counted bus_poison and acknowledged (the
// scan covers its change); any other failure asks for redelivery after a
// delay that grows with the deliveries. The work runs on its own
// deadline, so a stop never cuts a message in half.
func (s *Service) Handle(ctx context.Context, m bus.Msg, maxDeliver int) {
	c, err := bus.ParseChange(m.Data())
	if err != nil {
		s.counter(CounterBusPoison).Inc()
		s.logger.Error("bus message is not a change; acknowledged and left to the scan", slog.String("error", err.Error()))
		_ = m.Ack()
		return
	}
	ictx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.cfg.IntakeTimeout)
	defer cancel()
	n, err := s.Intake(ictx, c)
	if err != nil {
		s.counter(CounterIntakeFailed).Inc()
		delivered := m.NumDelivered()
		if maxDeliver > 0 && delivered >= uint64(maxDeliver) {
			s.counter(CounterBusPoison).Inc()
			s.logger.Error("change not queued after its last delivery; acknowledged and left to the scan",
				slog.Int64("change_id", c.ID), slog.Uint64("delivered", delivered), slog.String("error", err.Error()))
			_ = m.Ack()
			return
		}
		delay := min(time.Duration(delivered)*time.Second, 30*time.Second)
		s.logger.Warn("change not queued; redelivery asked", slog.Int64("change_id", c.ID),
			slog.Uint64("delivered", delivered), slog.Duration("delay", delay), slog.String("error", err.Error()))
		_ = m.Nak(delay)
		return
	}
	s.counter(CounterIntakeDeliveries).Add(uint64(n))
	if err := m.Ack(); err != nil {
		// The rows are written; a redelivery writes nothing more.
		s.logger.Warn("change queued but not acknowledged", slog.Int64("change_id", c.ID), slog.String("error", err.Error()))
	}
}

// Fetcher is the consumer as RunConsumer reads it (*bus.Consumer): each
// message is handed over as it arrives.
type Fetcher interface {
	Fetch(ctx context.Context, batch int, maxWait time.Duration, each func(bus.Msg)) error
}

// ConsumerOptions are RunConsumer's.
type ConsumerOptions struct {
	// Open makes the durable consumer; it is called again after a
	// failure, with a growing wait (2 s to 30 s).
	Open func(ctx context.Context) (Fetcher, error)
	// MaxDeliver is the consumer's (bus.DefaultMaxDeliver).
	MaxDeliver int
	Batch      int
	MaxWait    time.Duration
	// OnState is told when the consumer is up ("") and why it is not.
	OnState func(problem string)
}

// RunConsumer reads the durable consumer until ctx ends. Without a
// consumer (the broker down at start, or the consumer refused) it keeps
// trying, and the scan delivers meanwhile. When ctx ends it asks for the
// redelivery of what it fetched and has not handled.
func (s *Service) RunConsumer(ctx context.Context, opts ConsumerOptions) {
	if opts.OnState == nil {
		opts.OnState = func(string) {}
	}
	if opts.MaxDeliver <= 0 {
		opts.MaxDeliver = bus.DefaultMaxDeliver
	}
	var f Fetcher
	wait := 2 * time.Second
	for ctx.Err() == nil {
		if f == nil {
			octx, cancel := context.WithTimeout(ctx, 5*time.Second)
			c, err := opts.Open(octx)
			cancel()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				opts.OnState("consumer not open: " + err.Error())
				if !sleep(ctx, wait) {
					return
				}
				wait = min(wait*2, 30*time.Second)
				continue
			}
			f, wait = c, 2*time.Second
			opts.OnState("")
		}
		handedBack := 0
		err := f.Fetch(ctx, opts.Batch, opts.MaxWait, func(m bus.Msg) {
			if ctx.Err() != nil {
				_ = m.Nak(0)
				handedBack++
				return
			}
			s.Handle(ctx, m, opts.MaxDeliver)
		})
		if handedBack > 0 {
			s.logger.Info("stopping: unhandled messages handed back", slog.Int("count", handedBack))
		}
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			opts.OnState("fetch: " + err.Error())
			if !sleep(ctx, time.Second) {
				return
			}
			continue
		}
		opts.OnState("")
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// Scan is one reconciliation pass (D6): the changes past the watermark
// that are older than ScanGrace get their deliveries; the watermark
// passes the leading changes older than ScanSettle. It returns how many
// rows it wrote, the deliveries a lost publish would have lost, counted
// as deliveries_from_scan.
func (s *Service) Scan(ctx context.Context) (int64, error) {
	s.counter(CounterScans).Inc()
	w, err := s.store.Watermark(ctx, WatermarkName)
	if err != nil {
		return 0, err
	}
	now := s.now()
	changes, err := s.store.ScanChanges(ctx, w, now.Add(-s.cfg.ScanGrace), s.cfg.ScanBatch)
	if err != nil || len(changes) == 0 {
		return 0, err
	}
	subs, err := s.store.ReceivingSubscriptions(ctx)
	if err != nil {
		return 0, err
	}
	var inserted int64
	settled, settling := w, true
	for i := range changes {
		c := &changes[i]
		n, err := s.store.InsertChangeDeliveries(ctx, c.ID, Matching(subs, *c), now)
		if err != nil {
			return inserted, err
		}
		inserted += n
		if settling && c.At.Before(now.Add(-s.cfg.ScanSettle)) {
			settled = c.ID
		} else {
			settling = false
		}
	}
	if settled > w {
		if err := s.store.AdvanceWatermark(ctx, WatermarkName, settled, now); err != nil {
			return inserted, err
		}
	}
	if inserted > 0 {
		s.counter(CounterScanDeliveries).Add(uint64(inserted))
		s.logger.Warn("scan queued deliveries the bus did not bring", slog.Int64("deliveries", inserted),
			slog.Int64("from_change", changes[0].ID), slog.Int64("to_change", changes[len(changes)-1].ID))
		s.Wake()
	}
	return inserted, nil
}

// RunScan scans at once (a restarted deliver catches up without
// waiting a period) and then on every tick until ctx ends; a failed scan
// is counted and logged and the next tick tries again.
func (s *Service) RunScan(ctx context.Context, tick <-chan time.Time) {
	scan := func() {
		sctx, cancel := context.WithTimeout(ctx, s.cfg.ScanInterval)
		defer cancel()
		if _, err := s.Scan(sctx); err != nil && ctx.Err() == nil {
			s.counter(CounterScanFailed).Inc()
			s.logger.Warn("reconciliation scan failed", slog.String("error", err.Error()))
		}
	}
	scan()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
			scan()
		}
	}
}

// ScanInterval is the configured scan period.
func (s *Service) ScanInterval() time.Duration { return s.cfg.ScanInterval }
