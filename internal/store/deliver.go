package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/rootxkit/uspace-core/geodesy"

	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/store/relational"
	"github.com/rootxkit/uspace-cisp/internal/subscription"
)

// The store as deliver uses it (docs/PLAN.md section 6.5, D6, D7):
// deliver connects to the relational database as cisp_deliver and reads
// the change feed, the receiving subscriptions and the dataset versions,
// and writes deliveries, the subscriptions' delivery outcome and its
// watermark.

// ReceivingSubscriptions is every active or pending subscription.
func (s *Store) ReceivingSubscriptions(ctx context.Context) ([]SubscriptionRecord, error) {
	rows, err := relational.New(s.pool).ListReceivingSubscriptions(ctx)
	if err != nil {
		return nil, fmt.Errorf("receiving subscriptions: %w", err)
	}
	out := make([]SubscriptionRecord, 0, len(rows))
	for i := range rows {
		r := &rows[i]
		out = append(out, SubscriptionRecord{
			Subscription: subscription.Subscription{
				ID: r.ID, ClientID: r.ClientID, CallbackURL: r.CallbackUrl, Datasets: datasetsOf(r.Datasets),
				BBox: bboxOf(r.HasBbox, r.MinLon, r.MinLat, r.MaxLon, r.MaxLat), Status: subscription.Status(r.Status),
			},
			CreatedAt: r.CreatedAt.UTC(),
		})
	}
	return out, nil
}

// InsertChangeDeliveries queues one delivery of the change to each
// subscription, due now, in one transaction; a delivery that exists
// already (a redelivered message, the scan, another instance) is not
// written again. newID makes the delivery ids. It returns how many rows
// were written.
func (s *Store) InsertChangeDeliveries(ctx context.Context, changeID int64, subscriptionIDs []string, now time.Time) (int64, error) {
	if len(subscriptionIDs) == 0 {
		return 0, nil
	}
	var inserted int64
	err := s.Tx(ctx, func(q *relational.Queries) error {
		for _, sid := range subscriptionIDs {
			n, err := q.InsertChangeDelivery(ctx, relational.InsertChangeDeliveryParams{
				ID: newID(now), SubscriptionID: sid, ChangeID: changeID, Now: now,
			})
			if err != nil {
				return fmt.Errorf("insert delivery: %w", err)
			}
			inserted += n
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return inserted, nil
}

// Watermark is deliver's reconciliation watermark, 0 before the first.
func (s *Store) Watermark(ctx context.Context, name string) (int64, error) {
	w, err := relational.New(s.pool).GetWatermark(ctx, name)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("watermark: %w", err)
	}
	return w, nil
}

// AdvanceWatermark raises the watermark to w; it never lowers it.
func (s *Store) AdvanceWatermark(ctx context.Context, name string, w int64, now time.Time) error {
	if err := relational.New(s.pool).AdvanceWatermark(ctx, relational.AdvanceWatermarkParams{Name: name, Watermark: w, Now: now}); err != nil {
		return fmt.Errorf("advance watermark: %w", err)
	}
	return nil
}

func changeOf(id int64, ds string, version int64, featureIDs, removedIDs []string, reason string, at time.Time,
	hasBox bool, minLon, minLat, maxLon, maxLat float64,
) publication.Change {
	c := publication.Change{
		ID: id, Dataset: publication.Dataset(ds), Version: version, FeatureIDs: featureIDs, RemovedIDs: removedIDs,
		Reason: publication.Reason(reason), At: at.UTC(),
	}
	if hasBox {
		c.BBox = &geodesy.BBox{MinLon: minLon, MinLat: minLat, MaxLon: maxLon, MaxLat: maxLat}
	}
	return c
}

// ScanChanges is the changes after the cursor since and committed
// before before, in cursor order, at most limit.
func (s *Store) ScanChanges(ctx context.Context, since int64, before time.Time, limit int) ([]publication.Change, error) {
	rows, err := relational.New(s.pool).ListChangesForScan(ctx, relational.ListChangesForScanParams{
		SinceID: since, Before: before, MaxRows: int32(min(max(limit, 0), 1<<20)),
	})
	if err != nil {
		return nil, fmt.Errorf("scan changes: %w", err)
	}
	out := make([]publication.Change, 0, len(rows))
	for i := range rows {
		r := &rows[i]
		out = append(out, changeOf(r.ID, r.Dataset, r.Version, r.FeatureIds, r.RemovedIds, r.Reason, r.At,
			r.HasBbox, r.MinLon, r.MinLat, r.MaxLon, r.MaxLat))
	}
	return out, nil
}

// ChangesByID is the changes of ids, by id; an id with no row is absent.
func (s *Store) ChangesByID(ctx context.Context, ids []int64) (map[int64]publication.Change, error) {
	out := make(map[int64]publication.Change, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := relational.New(s.pool).GetChangesByID(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("changes: %w", err)
	}
	for i := range rows {
		r := &rows[i]
		out[r.ID] = changeOf(r.ID, r.Dataset, r.Version, r.FeatureIds, r.RemovedIds, r.Reason, r.At,
			r.HasBbox, r.MinLon, r.MinLat, r.MaxLon, r.MaxLat)
	}
	return out, nil
}

// DatasetVersions is every dataset's current version.
func (s *Store) DatasetVersions(ctx context.Context) (map[publication.Dataset]int64, error) {
	rows, err := relational.New(s.pool).ListDatasetVersions(ctx)
	if err != nil {
		return nil, fmt.Errorf("dataset versions: %w", err)
	}
	out := make(map[publication.Dataset]int64, len(rows))
	for _, r := range rows {
		out[publication.Dataset(r.Name)] = r.CurrentVersion
	}
	return out, nil
}

// Claim is one delivery claimed for an attempt, with its subscription's
// callback as it is now.
type Claim struct {
	DeliveryID     string
	SubscriptionID string
	// ChangeID is nil for a verification ping.
	ChangeID *int64
	// Attempts made before this one.
	Attempts           int
	CreatedAt          time.Time
	CallbackURL        string
	Datasets           []publication.Dataset
	SubscriptionStatus subscription.Status
	// LeaseUntil is when the lease runs out and any instance may claim
	// the row again.
	LeaseUntil time.Time
}

// ClaimDeliveries locks and leases at most limit due deliveries of
// receiving subscriptions, oldest due first: each becomes delivering
// until leaseUntil. Rows another instance holds are skipped (SKIP
// LOCKED); a lease that runs out makes its row due again. A
// subscription gets at most perSubscription rows delivering at once,
// counting those already under a live lease (0 or less: 1).
func (s *Store) ClaimDeliveries(ctx context.Context, now, leaseUntil time.Time, limit, perSubscription int) ([]Claim, error) {
	if limit <= 0 {
		return nil, nil
	}
	var out []Claim
	err := s.Tx(ctx, func(q *relational.Queries) error {
		rows, err := q.ClaimDeliveries(ctx, relational.ClaimDeliveriesParams{
			Now: now, LeaseUntil: leaseUntil, MaxRows: int32(min(limit, 1<<20)),
			MaxPerSubscription: int64(max(perSubscription, 1)),
		})
		if err != nil {
			return fmt.Errorf("claim deliveries: %w", err)
		}
		out = make([]Claim, 0, len(rows))
		for i := range rows {
			r := &rows[i]
			out = append(out, Claim{
				DeliveryID: r.ID, SubscriptionID: r.SubscriptionID, ChangeID: r.ChangeID, Attempts: int(r.Attempts),
				CreatedAt: r.CreatedAt.UTC(), CallbackURL: r.CallbackUrl, Datasets: datasetsOf(r.Datasets),
				SubscriptionStatus: subscription.Status(r.Status), LeaseUntil: leaseUntil,
			})
		}
		return nil
	})
	return out, err
}

// Delivered is the outcome of a 2xx.
type Delivered struct {
	// Attempts is the delivery's attempt count with this one.
	Attempts int
	// Verified is true when this success activated a pending subscription.
	Verified bool
}

// FinishDelivered records a 2xx: the delivery is delivered, and the
// subscription's failure run ends (a pending one becomes active).
func (s *Store) FinishDelivered(ctx context.Context, deliveryID, subscriptionID string, at time.Time, statusCode int) (Delivered, error) {
	var out Delivered
	err := s.Tx(ctx, func(q *relational.Queries) error {
		code := int32(min(max(statusCode, 0), 999))
		n, err := q.FinishDelivered(ctx, relational.FinishDeliveredParams{ID: deliveryID, At: at, StatusCode: &code})
		if err != nil {
			return fmt.Errorf("finish delivered: %w", err)
		}
		r, err := q.SubscriptionSucceeded(ctx, relational.SubscriptionSucceededParams{ID: subscriptionID, At: at})
		if err != nil {
			return fmt.Errorf("subscription succeeded: %w", err)
		}
		out = Delivered{Attempts: int(n), Verified: r.VerifiedNow}
		return nil
	})
	return out, err
}

// FailedAttempt is an attempt that got no 2xx.
type FailedAttempt struct {
	DeliveryID, SubscriptionID string
	At                         time.Time
	// StatusCode is nil when no response arrived.
	StatusCode *int
	Error      string
	// NextRetryAt is when to try again; Expire ends the delivery instead.
	NextRetryAt *time.Time
	Expire      bool
	// Payload says the failure is the payload's, not the subscriber's
	// (the signed webhook is over the bound receivers verify): the
	// delivery expires and the subscription's failure run is not
	// touched, so a change too large to send never suspends anyone.
	Payload bool
}

// Failed is the outcome of a failed attempt.
type Failed struct {
	Attempts int
	// State is failed or expired.
	State string
	// The subscription's failure run with this failure.
	SubscriptionStatus  subscription.Status
	ConsecutiveFailures int
	FailingSince        time.Time
}

// FinishFailed records a failed attempt: the delivery is failed and due
// again at NextRetryAt, or expired; the subscription's failure run grows.
func (s *Store) FinishFailed(ctx context.Context, f FailedAttempt) (Failed, error) {
	var out Failed
	err := s.Tx(ctx, func(q *relational.Queries) error {
		r, err := q.FinishFailed(ctx, relational.FinishFailedParams{
			ID: f.DeliveryID, At: f.At, StatusCode: int32Ptr(f.StatusCode), Error: f.Error,
			NextRetryAt: f.NextRetryAt, Expire: f.Expire || f.Payload,
		})
		if err != nil {
			return fmt.Errorf("finish failed: %w", err)
		}
		if f.Payload {
			// Not the subscriber's failure: its run is left as it is.
			out = Failed{Attempts: int(r.Attempts), State: r.State}
			return nil
		}
		sr, err := q.SubscriptionFailed(ctx, relational.SubscriptionFailedParams{ID: f.SubscriptionID, At: f.At})
		if err != nil {
			return fmt.Errorf("subscription failed: %w", err)
		}
		out = Failed{
			Attempts: int(r.Attempts), State: r.State, SubscriptionStatus: subscription.Status(sr.Status),
			ConsecutiveFailures: int(sr.ConsecutiveFailures),
		}
		if sr.FailingSince != nil {
			out.FailingSince = sr.FailingSince.UTC()
		}
		return nil
	})
	return out, err
}

// SuspendSubscription suspends an active subscription with the reason;
// false when it was not active (already suspended, pending or deleted).
func (s *Store) SuspendSubscription(ctx context.Context, id, reason string) (bool, error) {
	n, err := relational.New(s.pool).SuspendSubscription(ctx, relational.SuspendSubscriptionParams{ID: id, Reason: &reason})
	if err != nil {
		return false, fmt.Errorf("suspend: %w", err)
	}
	return n > 0, nil
}

// QueueStats is what deliver's status line prints.
type QueueStats struct {
	// Queued is deliveries waiting (queued or failed), Due those of them
	// due now, Delivering those being attempted, for receiving
	// subscriptions.
	Queued, Due, Delivering int64
	// OldestDueAge is how long the oldest due delivery has been due.
	OldestDueAge time.Duration
	// Suspended is the suspended subscriptions.
	Suspended int64
}

// DeliveryQueue reads the queue at now.
func (s *Store) DeliveryQueue(ctx context.Context, now time.Time) (QueueStats, error) {
	r, err := relational.New(s.pool).QueueStats(ctx, now)
	if err != nil {
		return QueueStats{}, fmt.Errorf("queue stats: %w", err)
	}
	return QueueStats{
		Queued: r.Queued, Due: r.Due, Delivering: r.Delivering, Suspended: r.Suspended,
		OldestDueAge: time.Duration(r.OldestDueAgeS * float64(time.Second)),
	}, nil
}
