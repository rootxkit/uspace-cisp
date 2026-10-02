package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rootxkit/uspace-core/geodesy"

	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/store/relational"
	"github.com/rootxkit/uspace-cisp/internal/store/timeseries"
	"github.com/rootxkit/uspace-cisp/internal/subscription"
)

// The subscription errors.
var (
	// ErrSubscriptionLimit is a create past the client's limit
	// (CISP_MAX_SUBSCRIPTIONS_PER_CLIENT).
	ErrSubscriptionLimit = errors.New("store: the client holds its maximum of subscriptions")
	// ErrDeliveryInFlight is a retry of a delivery being attempted now.
	ErrDeliveryInFlight = errors.New("store: the delivery is being attempted")
)

// The delivery states (docs/PLAN.md section 5.1).
const (
	DeliveryQueued     = "queued"
	DeliveryDelivering = "delivering"
	DeliveryDelivered  = "delivered"
	DeliveryFailed     = "failed"
	DeliveryExpired    = "expired"
)

// PingChangeID is delivery_attempts.change_id of a verification ping: no
// change exists (deliveries.change_id is null), and 0 is never a cursor.
const PingChangeID = 0

// SubscriptionRecord is a stored subscription with its times and its
// failure run.
type SubscriptionRecord struct {
	subscription.Subscription
	CreatedAt           time.Time
	VerifiedAt          *time.Time
	SuspendedReason     *string
	ConsecutiveFailures int
	LastSuccessAt       *time.Time
	FailingSince        *time.Time
}

// DeliveryRecord is one deliveries row with the reason of its change
// (subscription_test for a ping).
type DeliveryRecord struct {
	ID             string
	SubscriptionID string
	ChangeID       *int64
	Reason         publication.Reason
	State          string
	Attempts       int
	FirstAttemptAt *time.Time
	LastAttemptAt  *time.Time
	NextRetryAt    *time.Time
	DeliveredAt    *time.Time
	LastStatusCode *int
	LastError      *string
	CreatedAt      time.Time
}

// DeliveryAttempt is one delivery_attempts row.
type DeliveryAttempt struct {
	At             time.Time
	DeliveryID     string
	SubscriptionID string
	// ChangeID is PingChangeID for a ping.
	ChangeID     int64
	Attempt      int
	StatusCode   *int
	Error        *string
	LatencyMs    int
	PayloadBytes int
	Instance     string
}

func bboxArgs(b *geodesy.BBox) (bool, float64, float64, float64, float64) {
	if b == nil {
		return false, 0, 0, 0, 0
	}
	return true, b.MinLon, b.MinLat, b.MaxLon, b.MaxLat
}

func bboxOf(has bool, minLon, minLat, maxLon, maxLat float64) *geodesy.BBox {
	if !has {
		return nil
	}
	return &geodesy.BBox{MinLon: minLon, MinLat: minLat, MaxLon: maxLon, MaxLat: maxLat}
}

func datasetsOf(ss []string) []publication.Dataset {
	out := make([]publication.Dataset, 0, len(ss))
	for _, s := range ss {
		out = append(out, publication.Dataset(s))
	}
	return out
}

func datasetStrings(ds []publication.Dataset) []string {
	out := make([]string, 0, len(ds))
	for _, d := range ds {
		out = append(out, string(d))
	}
	return out
}

func intPtr(p *int32) *int {
	if p == nil {
		return nil
	}
	v := int(*p)
	return &v
}

func int32Ptr(p *int) *int32 {
	if p == nil {
		return nil
	}
	v := int32(min(max(*p, 0), 1<<30))
	return &v
}

func subscriptionOf(r relational.GetSubscriptionRow) SubscriptionRecord {
	return SubscriptionRecord{
		Subscription: subscription.Subscription{
			ID: r.ID, ClientID: r.ClientID, CallbackURL: r.CallbackUrl, Datasets: datasetsOf(r.Datasets),
			BBox: bboxOf(r.HasBbox, r.MinLon, r.MinLat, r.MaxLon, r.MaxLat), Status: subscription.Status(r.Status),
		},
		CreatedAt: r.CreatedAt.UTC(), VerifiedAt: r.VerifiedAt, SuspendedReason: r.SuspendedReason,
		ConsecutiveFailures: int(r.ConsecutiveFailures), LastSuccessAt: r.LastSuccessAt, FailingSince: r.FailingSince,
	}
}

func deliveryOf(r relational.GetSubscriptionDeliveryRow) DeliveryRecord {
	return DeliveryRecord{
		ID: r.ID, SubscriptionID: r.SubscriptionID, ChangeID: r.ChangeID, Reason: publication.Reason(r.Reason),
		State: r.State, Attempts: int(r.Attempts), FirstAttemptAt: r.FirstAttemptAt, LastAttemptAt: r.LastAttemptAt,
		NextRetryAt: r.NextRetryAt, DeliveredAt: r.DeliveredAt, LastStatusCode: intPtr(r.LastStatusCode),
		LastError: r.LastError, CreatedAt: r.CreatedAt.UTC(),
	}
}

// NewSubscription is what CreateSubscription writes: the subscription
// (status pending_verification), the id of its verification ping and
// the audit row.
type NewSubscription struct {
	Record SubscriptionRecord
	PingID string
	Event  Event
	// MaxPerClient is the client's limit (CISP_MAX_SUBSCRIPTIONS_PER_CLIENT).
	MaxPerClient int
}

// CreateSubscription writes a subscription, its verification ping (a
// delivery of no change, due now) and the audit row in one transaction,
// under the client's lock, refusing with ErrSubscriptionLimit when the
// client already holds MaxPerClient subscriptions that are not deleted.
func (s *Store) CreateSubscription(ctx context.Context, n NewSubscription) error {
	return s.Tx(ctx, func(q *relational.Queries) error {
		r := n.Record
		if err := q.LockClientSubscriptions(ctx, r.ClientID); err != nil {
			return fmt.Errorf("subscription lock: %w", err)
		}
		count, err := q.CountClientSubscriptions(ctx, r.ClientID)
		if err != nil {
			return fmt.Errorf("count subscriptions: %w", err)
		}
		if count >= int64(n.MaxPerClient) {
			return ErrSubscriptionLimit
		}
		has, minLon, minLat, maxLon, maxLat := bboxArgs(r.BBox)
		if err := q.InsertSubscription(ctx, relational.InsertSubscriptionParams{
			ID: r.ID, ClientID: r.ClientID, CallbackUrl: r.CallbackURL, Datasets: datasetStrings(r.Datasets),
			HasBbox: has, MinLon: minLon, MinLat: minLat, MaxLon: maxLon, MaxLat: maxLat,
			Status: string(r.Status), CreatedAt: r.CreatedAt,
		}); err != nil {
			return fmt.Errorf("insert subscription: %w", err)
		}
		if err := q.InsertPingDelivery(ctx, relational.InsertPingDeliveryParams{ID: n.PingID, SubscriptionID: r.ID, CreatedAt: r.CreatedAt}); err != nil {
			return fmt.Errorf("insert ping: %w", err)
		}
		_, err = AppendEvent(ctx, q, n.Event)
		return err
	})
}

// Subscription is one subscription, deleted ones included, or ErrNotFound.
func (s *Store) Subscription(ctx context.Context, id string) (SubscriptionRecord, error) {
	r, err := relational.New(s.pool).GetSubscription(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return SubscriptionRecord{}, ErrNotFound
	}
	if err != nil {
		return SubscriptionRecord{}, fmt.Errorf("subscription: %w", err)
	}
	return subscriptionOf(r), nil
}

// ClientSubscriptions is a client's subscriptions but the deleted ones,
// oldest first, at most limit.
func (s *Store) ClientSubscriptions(ctx context.Context, clientID string, limit int) ([]SubscriptionRecord, error) {
	rows, err := relational.New(s.pool).ListClientSubscriptions(ctx, relational.ListClientSubscriptionsParams{
		ClientID: clientID, MaxRows: int32(min(max(limit, 0), 1<<20)),
	})
	if err != nil {
		return nil, fmt.Errorf("subscriptions: %w", err)
	}
	out := make([]SubscriptionRecord, 0, len(rows))
	for i := range rows {
		r := &rows[i]
		out = append(out, subscriptionOf(relational.GetSubscriptionRow(*r)))
	}
	return out, nil
}

// SubscriptionUpdate is what UpdateSubscription writes: the record as it
// becomes, a ping id when the callback is to be verified again, and the
// audit row.
type SubscriptionUpdate struct {
	Record SubscriptionRecord
	PingID string
	Event  Event
}

// UpdateSubscription writes a PATCH in one transaction: the record, the
// new ping when PingID is set, and the audit row.
func (s *Store) UpdateSubscription(ctx context.Context, u SubscriptionUpdate) error {
	return s.Tx(ctx, func(q *relational.Queries) error {
		r := u.Record
		has, minLon, minLat, maxLon, maxLat := bboxArgs(r.BBox)
		if err := q.UpdateSubscription(ctx, relational.UpdateSubscriptionParams{
			ID: r.ID, CallbackUrl: r.CallbackURL, Datasets: datasetStrings(r.Datasets),
			HasBbox: has, MinLon: minLon, MinLat: minLat, MaxLon: maxLon, MaxLat: maxLat,
			Status: string(r.Status), SuspendedReason: r.SuspendedReason,
			ConsecutiveFailures: int32(min(max(r.ConsecutiveFailures, 0), 1<<30)),
			FailingSince:        r.FailingSince,
		}); err != nil {
			return fmt.Errorf("update subscription: %w", err)
		}
		if u.PingID != "" {
			if err := q.InsertPingDelivery(ctx, relational.InsertPingDeliveryParams{ID: u.PingID, SubscriptionID: r.ID, CreatedAt: u.Event.TS}); err != nil {
				return fmt.Errorf("insert ping: %w", err)
			}
		}
		_, err := AppendEvent(ctx, q, u.Event)
		return err
	})
}

// DeleteSubscription soft-deletes a subscription: its status becomes
// deleted and its open deliveries expire (a state, never a deletion), in
// one transaction with the audit row. It returns how many expired.
func (s *Store) DeleteSubscription(ctx context.Context, id string, e Event) (int64, error) {
	var expired int64
	err := s.Tx(ctx, func(q *relational.Queries) error {
		if err := q.MarkSubscriptionDeleted(ctx, id); err != nil {
			return fmt.Errorf("delete subscription: %w", err)
		}
		n, err := q.ExpireOpenDeliveries(ctx, id)
		if err != nil {
			return fmt.Errorf("expire deliveries: %w", err)
		}
		expired = n
		if e.Payload == nil {
			e.Payload = map[string]any{}
		}
		e.Payload["deliveries_expired"] = n
		_, err = AppendEvent(ctx, q, e)
		return err
	})
	return expired, err
}

// LatestPing is the subscription's most recent verification ping, or
// ErrNotFound.
func (s *Store) LatestPing(ctx context.Context, subscriptionID string) (DeliveryRecord, error) {
	d, err := relational.New(s.pool).LatestPingDelivery(ctx, subscriptionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return DeliveryRecord{}, ErrNotFound
	}
	if err != nil {
		return DeliveryRecord{}, fmt.Errorf("latest ping: %w", err)
	}
	return DeliveryRecord{
		ID: d.ID, SubscriptionID: d.SubscriptionID, ChangeID: d.ChangeID, Reason: publication.ReasonSubscriptionTest,
		State: d.State, Attempts: int(d.Attempts), FirstAttemptAt: d.FirstAttemptAt, LastAttemptAt: d.LastAttemptAt,
		NextRetryAt: d.NextRetryAt, DeliveredAt: d.DeliveredAt, LastStatusCode: intPtr(d.LastStatusCode),
		LastError: d.LastError, CreatedAt: d.CreatedAt.UTC(),
	}, nil
}

// SubscriptionDeliveries is a subscription's deliveries queued at or
// after since, newest first, at most limit.
func (s *Store) SubscriptionDeliveries(ctx context.Context, subscriptionID string, since time.Time, limit int) ([]DeliveryRecord, error) {
	rows, err := relational.New(s.pool).ListSubscriptionDeliveries(ctx, relational.ListSubscriptionDeliveriesParams{
		SubscriptionID: subscriptionID, Since: since, MaxRows: int32(min(max(limit, 0), 1<<20)),
	})
	if err != nil {
		return nil, fmt.Errorf("deliveries: %w", err)
	}
	out := make([]DeliveryRecord, 0, len(rows))
	for i := range rows {
		r := &rows[i]
		out = append(out, deliveryOf(relational.GetSubscriptionDeliveryRow(*r)))
	}
	return out, nil
}

// RequeueDelivery makes a delivery due now (state queued), with the
// audit row, in one transaction: ErrNotFound when the subscription has no
// such delivery, ErrDeliveryInFlight while it is being attempted.
func (s *Store) RequeueDelivery(ctx context.Context, subscriptionID, deliveryID string, now time.Time, e Event) (DeliveryRecord, error) {
	var out DeliveryRecord
	err := s.Tx(ctx, func(q *relational.Queries) error {
		n, err := q.RequeueDelivery(ctx, relational.RequeueDeliveryParams{ID: deliveryID, SubscriptionID: subscriptionID, Now: now})
		if err != nil {
			return fmt.Errorf("requeue: %w", err)
		}
		r, err := q.GetSubscriptionDelivery(ctx, relational.GetSubscriptionDeliveryParams{ID: deliveryID, SubscriptionID: subscriptionID})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("delivery: %w", err)
		}
		if n == 0 {
			return ErrDeliveryInFlight
		}
		out = deliveryOf(r)
		_, err = AppendEvent(ctx, q, e)
		return err
	})
	return out, err
}

// DeliveryLog is the delivery_attempts hypertable (the timeseries
// database): deliver writes it, the api reads it through its read-only
// grant.
type DeliveryLog struct {
	pool *pgxpool.Pool
}

// NewDeliveryLog is the log on the timeseries pool.
func NewDeliveryLog(pool *pgxpool.Pool) *DeliveryLog { return &DeliveryLog{pool: pool} }

// Record writes one attempt.
func (l *DeliveryLog) Record(ctx context.Context, a DeliveryAttempt) error {
	err := timeseries.New(l.pool).InsertDeliveryAttempt(ctx, timeseries.InsertDeliveryAttemptParams{
		At: a.At, DeliveryID: a.DeliveryID, SubscriptionID: a.SubscriptionID, ChangeID: a.ChangeID,
		Attempt: int32(min(max(a.Attempt, 1), 1<<30)), StatusCode: int32Ptr(a.StatusCode), Error: a.Error,
		LatencyMs:       int32(min(max(a.LatencyMs, 0), 1<<30)),
		PayloadBytes:    int32(min(max(a.PayloadBytes, 0), 1<<30)),
		DeliverInstance: a.Instance,
	})
	if err != nil {
		return fmt.Errorf("delivery attempt: %w", err)
	}
	return nil
}

// AttemptsOf is every logged attempt of some deliveries of one
// subscription, oldest first.
func (l *DeliveryLog) AttemptsOf(ctx context.Context, subscriptionID string, deliveryIDs []string) ([]DeliveryAttempt, error) {
	rows, err := timeseries.New(l.pool).ListAttemptsOfDeliveries(ctx, timeseries.ListAttemptsOfDeliveriesParams{
		SubscriptionID: subscriptionID, DeliveryIds: deliveryIDs,
	})
	if err != nil {
		return nil, fmt.Errorf("delivery attempts: %w", err)
	}
	out := make([]DeliveryAttempt, 0, len(rows))
	for _, r := range rows {
		out = append(out, DeliveryAttempt{
			At: r.At.UTC(), DeliveryID: r.DeliveryID, SubscriptionID: r.SubscriptionID, ChangeID: r.ChangeID,
			Attempt: int(r.Attempt), StatusCode: intPtr(r.StatusCode), Error: r.Error, LatencyMs: int(r.LatencyMs),
			PayloadBytes: int(r.PayloadBytes), Instance: r.DeliverInstance,
		})
	}
	return out, nil
}
