package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/geodesy"

	"github.com/rootxkit/uspace-cisp/internal/auth"
	"github.com/rootxkit/uspace-cisp/internal/httpapi/gen"
	"github.com/rootxkit/uspace-cisp/internal/obs"
	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/store"
	"github.com/rootxkit/uspace-cisp/internal/subscription"
)

// Problem slugs of the subscriptions (docs/WORKPACKAGES/WP-6.md).
const (
	SlugSubscriptionRefused = "subscription_refused"
	SlugLimit               = "limit"
	SlugDelivering          = "delivering"
)

// The route patterns of the subscriptions tag.
const (
	subscriptionCreateRoute = "POST /v1/subscriptions"
	subscriptionListRoute   = "GET /v1/subscriptions"
	subscriptionGetRoute    = "GET /v1/subscriptions/{id}"
	subscriptionPatchRoute  = "PATCH /v1/subscriptions/{id}"
	subscriptionDeleteRoute = "DELETE /v1/subscriptions/{id}"
	deliveriesListRoute     = "GET /v1/subscriptions/{id}/deliveries"
	deliveryRetryRoute      = "POST /v1/subscriptions/{id}/deliveries/{delivery_id}/retry"
)

// SubscriptionWriteRoutes are the two body-carrying patterns, for their
// body cap (Options.RouteBodyCaps, MaxSubscriptionBodyBytes).
var SubscriptionWriteRoutes = []string{subscriptionCreateRoute, subscriptionPatchRoute}

// Limits and defaults of the subscriptions.
const (
	// MaxSubscriptionBodyBytes caps a POST or PATCH body (docs/PLAN.md
	// section 8.1 T8: subscriptions 256 KiB).
	MaxSubscriptionBodyBytes = 256 << 10
	// MaxListedSubscriptions bounds GET /v1/subscriptions; a client holds
	// at most CISP_MAX_SUBSCRIPTIONS_PER_CLIENT.
	MaxListedSubscriptions = 10_000
	// DefaultDeliveriesSince is how far back the deliveries list reaches
	// without since.
	DefaultDeliveriesSince = 24 * time.Hour
	// ResolveTimeout bounds the registration's look-up of the callback host.
	ResolveTimeout = 2 * time.Second
)

// The component and counters of the subscriptions.
const (
	subscriptionsComponent = "subscriptions"

	CounterSubscriptionsCreated = "subscriptions_created"
	CounterSubscriptionsRefused = "subscriptions_refused"
	CounterSubscriptionsChanged = "subscriptions_changed"
	CounterSubscriptionsDeleted = "subscriptions_deleted"
	CounterDeliveriesRequeued   = "deliveries_requeued"
	CounterDeliveryLogFailed    = "delivery_log_read_failed"
)

// The audit events of the subscriptions.
const (
	EventSubscriptionCreated = "subscription_created"
	EventSubscriptionChanged = "subscription_changed"
	EventSubscriptionDeleted = "subscription_deleted"
	EventDeliveryRequeued    = "delivery_requeued"
)

// SubscriptionStore is what the subscriptions need of the store
// (*store.Store in the api; a fake in the unit tests).
type SubscriptionStore interface {
	CreateSubscription(ctx context.Context, n store.NewSubscription) error
	Subscription(ctx context.Context, id string) (store.SubscriptionRecord, error)
	ClientSubscriptions(ctx context.Context, clientID string, limit int) ([]store.SubscriptionRecord, error)
	UpdateSubscription(ctx context.Context, u store.SubscriptionUpdate) error
	DeleteSubscription(ctx context.Context, id string, e store.Event) (int64, error)
	LatestPing(ctx context.Context, subscriptionID string) (store.DeliveryRecord, error)
	SubscriptionDeliveries(ctx context.Context, subscriptionID string, since time.Time, limit int) ([]store.DeliveryRecord, error)
	RequeueDelivery(ctx context.Context, subscriptionID, deliveryID string, now time.Time, e store.Event) (store.DeliveryRecord, error)
}

// AttemptLog is the delivery log read (*store.DeliveryLog on the
// timeseries database).
type AttemptLog interface {
	AttemptsOf(ctx context.Context, subscriptionID string, deliveryIDs []string) ([]store.DeliveryAttempt, error)
}

// Resolver looks up the addresses of a host name.
type Resolver func(ctx context.Context, host string) ([]net.IP, error)

// Subscriptions serves the subscriptions tag of api/openapi.yaml.
type Subscriptions struct {
	Store SubscriptionStore
	// Log reads the attempts of the deliveries list; nil: the list says
	// not_configured.
	Log AttemptLog
	// Policy is CISP_ALLOW_PRIVATE_CALLBACKS and CISP_ALLOW_INSECURE_CALLBACKS.
	Policy subscription.URLPolicy
	// MaxPerClient is CISP_MAX_SUBSCRIPTIONS_PER_CLIENT (0: 20).
	MaxPerClient int
	// Resolve looks up a callback host at registration (nil: the system
	// resolver). A host that resolves to an address AllowedAddress
	// refuses is refused; one that does not resolve is accepted, and its
	// ping says why it cannot be reached.
	Resolve Resolver
	Status  *obs.Status
	Logger  *slog.Logger
	// Now is the clock; nil is time.Now.
	Now func() time.Time
}

func (ss *Subscriptions) now() time.Time {
	if ss.Now == nil {
		return time.Now().UTC()
	}
	return ss.Now().UTC()
}

func (ss *Subscriptions) logger() *slog.Logger {
	if ss.Logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return ss.Logger
}

func (ss *Subscriptions) counter(name string) *obs.Counter {
	if ss.Status == nil {
		ss.Status = obs.NewStatus("api", nil, time.Now())
	}
	return ss.Status.Component(subscriptionsComponent).Counter(name, "Subscriptions ("+name+").")
}

func (ss *Subscriptions) maxPerClient() int {
	if ss.MaxPerClient <= 0 {
		return subscription.DefaultMaxPerClient
	}
	return ss.MaxPerClient
}

// --- route authentication ---------------------------------------------

// SubscriptionAuth builds the route middleware of the subscriptions tag:
// every operation takes an ecosystem token with cis.read (any consumer
// of F3 is a subscriber); POST and PATCH take application/json.
type SubscriptionAuth struct {
	Guard *auth.Guard
}

// Routes is the middleware of the seven operations, keyed by pattern.
func (a SubscriptionAuth) Routes() map[string]func(http.Handler) http.Handler {
	read := a.Guard.RequireScopes(auth.ScopeRead)
	write := func(next http.Handler) http.Handler {
		return auth.Chain(next, a.Guard.RequireScopes(auth.ScopeRead), requireJSONMediaType)
	}
	return map[string]func(http.Handler) http.Handler{
		subscriptionCreateRoute: write,
		subscriptionListRoute:   read,
		subscriptionGetRoute:    read,
		subscriptionPatchRoute:  write,
		subscriptionDeleteRoute: read,
		deliveriesListRoute:     read,
		deliveryRetryRoute:      read,
	}
}

// --- responses ----------------------------------------------------------

// VisitCreateSubscriptionResponse implements gen.CreateSubscriptionResponseObject.
func (j jsonResponse) VisitCreateSubscriptionResponse(w http.ResponseWriter) error { return j.write(w) }

// VisitListSubscriptionsResponse implements gen.ListSubscriptionsResponseObject.
func (j jsonResponse) VisitListSubscriptionsResponse(w http.ResponseWriter) error { return j.write(w) }

// VisitGetSubscriptionResponse implements gen.GetSubscriptionResponseObject.
func (j jsonResponse) VisitGetSubscriptionResponse(w http.ResponseWriter) error { return j.write(w) }

// VisitPatchSubscriptionResponse implements gen.PatchSubscriptionResponseObject.
func (j jsonResponse) VisitPatchSubscriptionResponse(w http.ResponseWriter) error { return j.write(w) }

// VisitDeleteSubscriptionResponse implements gen.DeleteSubscriptionResponseObject.
func (j jsonResponse) VisitDeleteSubscriptionResponse(w http.ResponseWriter) error { return j.write(w) }

// VisitListDeliveriesResponse implements gen.ListDeliveriesResponseObject.
func (j jsonResponse) VisitListDeliveriesResponse(w http.ResponseWriter) error { return j.write(w) }

// VisitRetryDeliveryResponse implements gen.RetryDeliveryResponseObject.
func (j jsonResponse) VisitRetryDeliveryResponse(w http.ResponseWriter) error { return j.write(w) }

// VisitCreateSubscriptionResponse implements gen.CreateSubscriptionResponseObject.
func (p problemResponse) VisitCreateSubscriptionResponse(w http.ResponseWriter) error {
	return p.write(w)
}

// VisitListSubscriptionsResponse implements gen.ListSubscriptionsResponseObject.
func (p problemResponse) VisitListSubscriptionsResponse(w http.ResponseWriter) error {
	return p.write(w)
}

// VisitGetSubscriptionResponse implements gen.GetSubscriptionResponseObject.
func (p problemResponse) VisitGetSubscriptionResponse(w http.ResponseWriter) error { return p.write(w) }

// VisitPatchSubscriptionResponse implements gen.PatchSubscriptionResponseObject.
func (p problemResponse) VisitPatchSubscriptionResponse(w http.ResponseWriter) error {
	return p.write(w)
}

// VisitDeleteSubscriptionResponse implements gen.DeleteSubscriptionResponseObject.
func (p problemResponse) VisitDeleteSubscriptionResponse(w http.ResponseWriter) error {
	return p.write(w)
}

// VisitListDeliveriesResponse implements gen.ListDeliveriesResponseObject.
func (p problemResponse) VisitListDeliveriesResponse(w http.ResponseWriter) error { return p.write(w) }

// VisitRetryDeliveryResponse implements gen.RetryDeliveryResponseObject.
func (p problemResponse) VisitRetryDeliveryResponse(w http.ResponseWriter) error { return p.write(w) }

// subscriptionResponse is any answer of the tag.
type subscriptionResponse interface {
	gen.CreateSubscriptionResponseObject
	gen.ListSubscriptionsResponseObject
	gen.GetSubscriptionResponseObject
	gen.PatchSubscriptionResponseObject
	gen.DeleteSubscriptionResponseObject
	gen.ListDeliveriesResponseObject
	gen.RetryDeliveryResponseObject
}

func deliveryBody(d store.DeliveryRecord) gen.Delivery {
	return gen.Delivery{
		Id: d.ID, SubscriptionId: d.SubscriptionID, ChangeId: d.ChangeID, Reason: gen.DeliveryReason(d.Reason),
		State: gen.DeliveryState(d.State), Attempts: d.Attempts, CreatedAt: d.CreatedAt.UTC(),
		FirstAttemptAt: utc(d.FirstAttemptAt), LastAttemptAt: utc(d.LastAttemptAt), NextRetryAt: utc(d.NextRetryAt),
		DeliveredAt: utc(d.DeliveredAt), LastStatusCode: d.LastStatusCode, LastError: d.LastError,
	}
}

func utc(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

func subscriptionBody(r store.SubscriptionRecord, ping *store.DeliveryRecord) gen.Subscription {
	out := gen.Subscription{
		Id: r.ID, ClientId: r.ClientID, CallbackUrl: r.CallbackURL, Status: gen.SubscriptionStatus(r.Status),
		CreatedAt: r.CreatedAt.UTC(), VerifiedAt: utc(r.VerifiedAt), SuspendedReason: r.SuspendedReason,
		ConsecutiveFailures: r.ConsecutiveFailures, LastSuccessAt: utc(r.LastSuccessAt), FailingSince: utc(r.FailingSince),
		Datasets: make([]gen.SubscriptionDatasets, 0, len(r.Datasets)),
	}
	for _, d := range r.Datasets {
		out.Datasets = append(out.Datasets, gen.SubscriptionDatasets(d))
	}
	if r.BBox != nil {
		b := []float64{r.BBox.MinLon, r.BBox.MinLat, r.BBox.MaxLon, r.BBox.MaxLat}
		out.Bbox = &b
	}
	if ping != nil {
		v := deliveryBody(*ping)
		out.Verification = &v
	}
	return out
}

// --- the operations -------------------------------------------------------

func subscriptionsUnavailable(ctx context.Context) problemResponse {
	return problemOf(ctx, http.StatusServiceUnavailable, SlugIntakeUnavailable, "Subscriptions unavailable",
		"the api runs without a database (CISP_DATABASE_URL); nothing can be stored or read")
}

// CreateSubscription registers a webhook (WP-6).
func (s *Server) CreateSubscription(ctx context.Context, req gen.CreateSubscriptionRequestObject) (gen.CreateSubscriptionResponseObject, error) {
	if s.Subscriptions == nil {
		return subscriptionsUnavailable(ctx), nil
	}
	return s.Subscriptions.create(ctx, req.Body)
}

// ListSubscriptions is the caller's subscriptions (WP-6).
func (s *Server) ListSubscriptions(ctx context.Context, _ gen.ListSubscriptionsRequestObject) (gen.ListSubscriptionsResponseObject, error) {
	if s.Subscriptions == nil {
		return subscriptionsUnavailable(ctx), nil
	}
	return s.Subscriptions.list(ctx)
}

// GetSubscription is one of the caller's subscriptions (WP-6).
func (s *Server) GetSubscription(ctx context.Context, req gen.GetSubscriptionRequestObject) (gen.GetSubscriptionResponseObject, error) {
	if s.Subscriptions == nil {
		return subscriptionsUnavailable(ctx), nil
	}
	return s.Subscriptions.get(ctx, req.Id)
}

// PatchSubscription changes one (WP-6).
func (s *Server) PatchSubscription(ctx context.Context, req gen.PatchSubscriptionRequestObject) (gen.PatchSubscriptionResponseObject, error) {
	if s.Subscriptions == nil {
		return subscriptionsUnavailable(ctx), nil
	}
	return s.Subscriptions.patch(ctx, req.Id, req.Body)
}

// DeleteSubscription soft-deletes one (WP-6).
func (s *Server) DeleteSubscription(ctx context.Context, req gen.DeleteSubscriptionRequestObject) (gen.DeleteSubscriptionResponseObject, error) {
	if s.Subscriptions == nil {
		return subscriptionsUnavailable(ctx), nil
	}
	return s.Subscriptions.remove(ctx, req.Id)
}

// ListDeliveries is a subscription's deliveries with their attempts (WP-6).
func (s *Server) ListDeliveries(ctx context.Context, req gen.ListDeliveriesRequestObject) (gen.ListDeliveriesResponseObject, error) {
	if s.Subscriptions == nil {
		return subscriptionsUnavailable(ctx), nil
	}
	return s.Subscriptions.deliveries(ctx, req.Id, req.Params)
}

// RetryDelivery re-queues one delivery now (WP-6).
func (s *Server) RetryDelivery(ctx context.Context, req gen.RetryDeliveryRequestObject) (gen.RetryDeliveryResponseObject, error) {
	if s.Subscriptions == nil {
		return subscriptionsUnavailable(ctx), nil
	}
	return s.Subscriptions.retry(ctx, req.Id, req.DeliveryId)
}

// caller is the authenticated client; the route middleware set it.
func caller(ctx context.Context) (*auth.Caller, error) {
	c := auth.CallerFrom(ctx)
	if c == nil || c.ClientID == "" {
		// The route middleware did not run: a wiring fault, never served.
		return nil, errors.New("subscription handler reached without authentication")
	}
	return c, nil
}

// failure answers a store error: 503 with Retry-After for an unreachable
// database, the deadline as it is, and 500 otherwise.
func (ss *Subscriptions) failure(ctx context.Context, err error) (problemResponse, error) {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return problemResponse{}, err
	case store.Unavailable(err):
		resp := problemOf(ctx, http.StatusServiceUnavailable, SlugDatabaseUnavailable, "Database unavailable",
			"the database could not be reached; nothing was stored; retry later")
		resp.headers = map[string]string{"Retry-After": retryAfterDatabaseDownS}
		return resp, nil
	}
	ss.logger().LogAttrs(ctx, slog.LevelError, "subscription store error", slog.String("error", err.Error()))
	return problemOf(ctx, http.StatusInternalServerError, SlugInternal, "Internal error",
		"the store failed; the failure is logged with this request id"), nil
}

func (ss *Subscriptions) refuse(ctx context.Context, fe *core.FieldError) problemResponse {
	ss.counter(CounterSubscriptionsRefused).Inc()
	return problemOf(ctx, http.StatusBadRequest, SlugSubscriptionRefused, "Subscription refused", fe.Error(), fe)
}

func notFoundSubscription(ctx context.Context, id string) problemResponse {
	fe := core.Fieldf("id", "%s is not one of this client's subscriptions", quoteShort(id))
	return problemOf(ctx, http.StatusNotFound, SlugNotFound, "Not found", fe.Error(), fe)
}

// own is the caller's subscription id that is not deleted: another
// client's, a deleted one and none at all are all 404, so ids of other
// clients' subscriptions are not disclosed.
func (ss *Subscriptions) own(ctx context.Context, c *auth.Caller, id string) (store.SubscriptionRecord, *problemResponse, error) {
	rec, err := ss.Store.Subscription(ctx, id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && (rec.ClientID != c.ClientID || rec.Status == subscription.Deleted)) {
		p := notFoundSubscription(ctx, id)
		return store.SubscriptionRecord{}, &p, nil
	}
	if err != nil {
		p, ferr := ss.failure(ctx, err)
		return store.SubscriptionRecord{}, &p, ferr
	}
	return rec, nil, nil
}

// validDatasets checks the datasets: at least one, each known, none twice.
func validDatasets(field string, in []string) ([]publication.Dataset, *core.FieldError) {
	if len(in) == 0 {
		return nil, core.Fieldf(field, "at least one dataset")
	}
	seen := map[publication.Dataset]bool{}
	out := make([]publication.Dataset, 0, len(in))
	for i, s := range in {
		d := publication.Dataset(s)
		if !d.Valid() {
			return nil, core.Fieldf(field+"["+strconv.Itoa(i)+"]", "%s is not zones, uspace_airspace, ussp_list or restrictions", quoteShort(s))
		}
		if seen[d] {
			return nil, core.Fieldf(field+"["+strconv.Itoa(i)+"]", "%s is listed twice", quoteShort(s))
		}
		seen[d] = true
		out = append(out, d)
	}
	return out, nil
}

// validBBox checks a box: four finite numbers, longitudes in [-180, 180]
// and latitudes in [-90, 90], min not above max (no antimeridian box).
func validBBox(b []float64) (*geodesy.BBox, *core.FieldError) {
	if len(b) != 4 {
		return nil, core.Fieldf("bbox", "must be [min lng, min lat, max lng, max lat]")
	}
	for i, v := range b {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return nil, core.Fieldf("bbox["+strconv.Itoa(i)+"]", "not a finite number")
		}
	}
	minLon, minLat, maxLon, maxLat := b[0], b[1], b[2], b[3]
	switch {
	case minLon < -180 || maxLon > 180:
		return nil, core.Fieldf("bbox", "longitudes must be within -180..180")
	case minLat < -90 || maxLat > 90:
		return nil, core.Fieldf("bbox", "latitudes must be within -90..90")
	case minLon > maxLon:
		return nil, core.Fieldf("bbox", "min lng is above max lng (a box across the antimeridian is not accepted)")
	case minLat > maxLat:
		return nil, core.Fieldf("bbox", "min lat is above max lat")
	}
	return &geodesy.BBox{MinLon: minLon, MinLat: minLat, MaxLon: maxLon, MaxLat: maxLat}, nil
}

// checkCallback judges a callback URL as written and, unless private
// callbacks are allowed, the addresses its host resolves to now. deliver
// judges the address again at every dial; this answers the registrant
// at once.
func (ss *Subscriptions) checkCallback(ctx context.Context, raw string) *core.FieldError {
	if err := subscription.ValidateCallbackURL(raw, ss.Policy); err != nil {
		var fe *core.FieldError
		if errors.As(err, &fe) {
			return fe
		}
		return core.Fieldf("callback_url", "%v", err)
	}
	if ss.Policy.AllowPrivate {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return core.Fieldf("callback_url", "not a URL")
	}
	resolve := ss.Resolve
	if resolve == nil {
		resolve = func(ctx context.Context, host string) ([]net.IP, error) {
			return net.DefaultResolver.LookupIP(ctx, "ip", host)
		}
	}
	rctx, cancel := context.WithTimeout(ctx, ResolveTimeout)
	defer cancel()
	ips, err := resolve(rctx, u.Hostname())
	if err != nil {
		// Not resolvable now: accepted; the ping says why it fails.
		ss.logger().LogAttrs(ctx, slog.LevelInfo, "callback host not resolved at registration",
			slog.String("host", u.Hostname()), slog.String("error", err.Error()))
		return nil
	}
	for _, ip := range ips {
		if !subscription.AllowedAddress(ip, ss.Policy) {
			return core.Fieldf("callback_url", "the host resolves to %s, which is not a public address (CISP_ALLOW_PRIVATE_CALLBACKS allows it in the lab)", ip)
		}
	}
	return nil
}

func (ss *Subscriptions) event(c *auth.Caller, typ, entityType, entityID string, at time.Time, payload map[string]any) store.Event {
	return store.Event{
		TS: at, ActorType: store.ActorClient, ActorID: c.ClientID, EventType: typ,
		EntityType: entityType, EntityID: entityID, Payload: payload,
	}
}

func datasetNames(ds []publication.Dataset) []string {
	out := make([]string, 0, len(ds))
	for _, d := range ds {
		out = append(out, string(d))
	}
	return out
}

// --- POST /v1/subscriptions ---------------------------------------------

func (ss *Subscriptions) create(ctx context.Context, body *gen.SubscriptionCreate) (subscriptionResponse, error) {
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	if body == nil {
		return ss.refuse(ctx, core.Fieldf("body", "missing")), nil
	}
	names := make([]string, 0, len(body.Datasets))
	for _, d := range body.Datasets {
		names = append(names, string(d))
	}
	datasets, fe := validDatasets("datasets", names)
	if fe != nil {
		return ss.refuse(ctx, fe), nil
	}
	var box *geodesy.BBox
	if body.Bbox != nil {
		if box, fe = validBBox(*body.Bbox); fe != nil {
			return ss.refuse(ctx, fe), nil
		}
	}
	if fe := ss.checkCallback(ctx, body.CallbackUrl); fe != nil {
		return ss.refuse(ctx, fe), nil
	}
	now := ss.now()
	rec := store.SubscriptionRecord{
		Subscription: subscription.Subscription{
			ID: store.NewID(now), ClientID: c.ClientID, CallbackURL: body.CallbackUrl, Datasets: datasets, BBox: box,
			Status: subscription.PendingVerification,
		},
		CreatedAt: now,
	}
	pingID := store.NewID(now)
	err = ss.Store.CreateSubscription(ctx, store.NewSubscription{
		Record: rec, PingID: pingID, MaxPerClient: ss.maxPerClient(),
		Event: ss.event(c, EventSubscriptionCreated, "subscription", rec.ID, now, map[string]any{
			"callback_url": rec.CallbackURL, "datasets": datasetNames(datasets), "ping_id": pingID,
		}),
	})
	if errors.Is(err, store.ErrSubscriptionLimit) {
		ss.counter(CounterSubscriptionsRefused).Inc()
		fe := core.Fieldf("callback_url", "this client already holds %d subscriptions, its maximum; delete one first", ss.maxPerClient())
		return problemOf(ctx, http.StatusConflict, SlugLimit, "Subscription limit", fe.Error(), fe), nil
	}
	if err != nil {
		return ss.failure(ctx, err)
	}
	ss.counter(CounterSubscriptionsCreated).Inc()
	ss.logger().LogAttrs(ctx, slog.LevelInfo, "subscription created", slog.String("client_id", c.ClientID),
		slog.String("subscription_id", rec.ID), slog.Any("datasets", datasetNames(datasets)))
	ping := store.DeliveryRecord{
		ID: pingID, SubscriptionID: rec.ID, Reason: publication.ReasonSubscriptionTest, State: store.DeliveryQueued,
		NextRetryAt: &now, CreatedAt: now,
	}
	return jsonResponse{
		status: http.StatusCreated, headers: map[string]string{"Location": "/v1/subscriptions/" + rec.ID},
		body: subscriptionBody(rec, &ping),
	}, nil
}

// --- GET /v1/subscriptions and /v1/subscriptions/{id} -------------------

func (ss *Subscriptions) withPing(ctx context.Context, rec store.SubscriptionRecord) (*store.DeliveryRecord, error) {
	if rec.Status != subscription.PendingVerification {
		return nil, nil
	}
	p, err := ss.Store.LatestPing(ctx, rec.ID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (ss *Subscriptions) list(ctx context.Context) (subscriptionResponse, error) {
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	recs, err := ss.Store.ClientSubscriptions(ctx, c.ClientID, MaxListedSubscriptions)
	if err != nil {
		return ss.failure(ctx, err)
	}
	out := gen.SubscriptionList{Subscriptions: make([]gen.Subscription, 0, len(recs))}
	for i := range recs {
		r := &recs[i]
		ping, err := ss.withPing(ctx, *r)
		if err != nil {
			return ss.failure(ctx, err)
		}
		out.Subscriptions = append(out.Subscriptions, subscriptionBody(*r, ping))
	}
	return jsonResponse{status: http.StatusOK, body: out}, nil
}

func (ss *Subscriptions) get(ctx context.Context, id string) (subscriptionResponse, error) {
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	rec, p, err := ss.own(ctx, c, id)
	if p != nil || err != nil {
		return *p, err
	}
	ping, err := ss.withPing(ctx, rec)
	if err != nil {
		return ss.failure(ctx, err)
	}
	return jsonResponse{status: http.StatusOK, body: subscriptionBody(rec, ping)}, nil
}

// --- PATCH /v1/subscriptions/{id} ----------------------------------------

func (ss *Subscriptions) patch(ctx context.Context, id string, body *gen.SubscriptionPatch) (subscriptionResponse, error) {
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	if body == nil {
		return ss.refuse(ctx, core.Fieldf("body", "missing")), nil
	}
	rec, p, err := ss.own(ctx, c, id)
	if p != nil || err != nil {
		return *p, err
	}
	next := rec
	changed := map[string]any{}
	if body.Datasets != nil {
		names := make([]string, 0, len(*body.Datasets))
		for _, d := range *body.Datasets {
			names = append(names, string(d))
		}
		ds, fe := validDatasets("datasets", names)
		if fe != nil {
			return ss.refuse(ctx, fe), nil
		}
		next.Datasets = ds
		changed["datasets"] = names
	}
	if body.Bbox != nil {
		if len(*body.Bbox) == 0 {
			next.BBox = nil
		} else {
			box, fe := validBBox(*body.Bbox)
			if fe != nil {
				return ss.refuse(ctx, fe), nil
			}
			next.BBox = box
		}
		changed["bbox"] = *body.Bbox
	}
	reverify := rec.Status == subscription.Suspended
	if body.CallbackUrl != nil && *body.CallbackUrl != rec.CallbackURL {
		if fe := ss.checkCallback(ctx, *body.CallbackUrl); fe != nil {
			return ss.refuse(ctx, fe), nil
		}
		next.CallbackURL = *body.CallbackUrl
		changed["callback_url"] = *body.CallbackUrl
		reverify = true
	}
	if len(changed) == 0 && !reverify {
		ping, err := ss.withPing(ctx, rec)
		if err != nil {
			return ss.failure(ctx, err)
		}
		return jsonResponse{status: http.StatusOK, body: subscriptionBody(rec, ping)}, nil
	}
	now := ss.now()
	u := store.SubscriptionUpdate{Record: next}
	var ping *store.DeliveryRecord
	if reverify {
		next.Status = subscription.PendingVerification
		next.SuspendedReason = nil
		next.ConsecutiveFailures = 0
		next.FailingSince = nil
		u.Record = next
		u.PingID = store.NewID(now)
		changed["ping_id"] = u.PingID
		changed["reverified_from"] = string(rec.Status)
		ping = &store.DeliveryRecord{
			ID: u.PingID, SubscriptionID: rec.ID, Reason: publication.ReasonSubscriptionTest, State: store.DeliveryQueued,
			NextRetryAt: &now, CreatedAt: now,
		}
	}
	u.Event = ss.event(c, EventSubscriptionChanged, "subscription", rec.ID, now, changed)
	if err := ss.Store.UpdateSubscription(ctx, u); err != nil {
		return ss.failure(ctx, err)
	}
	ss.counter(CounterSubscriptionsChanged).Inc()
	if ping == nil {
		if ping, err = ss.withPing(ctx, next); err != nil {
			return ss.failure(ctx, err)
		}
	}
	return jsonResponse{status: http.StatusOK, body: subscriptionBody(next, ping)}, nil
}

// --- DELETE /v1/subscriptions/{id} ---------------------------------------

func (ss *Subscriptions) remove(ctx context.Context, id string) (subscriptionResponse, error) {
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	rec, p, err := ss.own(ctx, c, id)
	if p != nil || err != nil {
		return *p, err
	}
	now := ss.now()
	expired, err := ss.Store.DeleteSubscription(ctx, rec.ID, ss.event(c, EventSubscriptionDeleted, "subscription", rec.ID, now, map[string]any{}))
	if err != nil {
		return ss.failure(ctx, err)
	}
	ss.counter(CounterSubscriptionsDeleted).Inc()
	ss.logger().LogAttrs(ctx, slog.LevelInfo, "subscription deleted", slog.String("client_id", c.ClientID),
		slog.String("subscription_id", rec.ID), slog.Int64("deliveries_expired", expired))
	rec.Status = subscription.Deleted
	return jsonResponse{status: http.StatusOK, body: subscriptionBody(rec, nil)}, nil
}

// --- GET /v1/subscriptions/{id}/deliveries --------------------------------

// Delivery log states of the deliveries list.
const (
	logComplete      = gen.DeliveryListLog("complete")
	logUnavailable   = gen.DeliveryListLog("unavailable")
	logNotConfigured = gen.DeliveryListLog("not_configured")
)

func (ss *Subscriptions) deliveries(ctx context.Context, id string, params gen.ListDeliveriesParams) (subscriptionResponse, error) {
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	limit, fe := listLimit(params.Limit)
	if fe != nil {
		return badRequest(ctx, fe), nil
	}
	since := ss.now().Add(-DefaultDeliveriesSince)
	if params.Since != nil {
		t, fe := parseInstant("since", *params.Since)
		if fe != nil {
			return badRequest(ctx, fe), nil
		}
		since = t
	}
	rec, p, err := ss.own(ctx, c, id)
	if p != nil || err != nil {
		return *p, err
	}
	recs, err := ss.Store.SubscriptionDeliveries(ctx, rec.ID, since, limit)
	if err != nil {
		return ss.failure(ctx, err)
	}
	out := gen.DeliveryList{Deliveries: make([]gen.Delivery, 0, len(recs)), Log: logNotConfigured}
	byID := map[string][]gen.DeliveryAttempt{}
	if ss.Log != nil && len(recs) > 0 {
		ids := make([]string, 0, len(recs))
		for i := range recs {
			r := &recs[i]
			ids = append(ids, r.ID)
		}
		attempts, err := ss.Log.AttemptsOf(ctx, rec.ID, ids)
		if err != nil {
			out.Log = logUnavailable
			ss.counter(CounterDeliveryLogFailed).Inc()
			ss.logger().LogAttrs(ctx, slog.LevelWarn, "delivery log not read", slog.String("subscription_id", rec.ID),
				slog.String("error", err.Error()))
		} else {
			out.Log = logComplete
			for _, a := range attempts {
				byID[a.DeliveryID] = append(byID[a.DeliveryID], gen.DeliveryAttempt{
					At: a.At.UTC(), Attempt: a.Attempt, StatusCode: a.StatusCode, Error: a.Error,
					LatencyMs: a.LatencyMs, PayloadBytes: a.PayloadBytes, DeliverInstance: a.Instance,
				})
			}
		}
	} else if ss.Log != nil {
		out.Log = logComplete
	}
	for i := range recs {
		r := &recs[i]
		d := deliveryBody(*r)
		if out.Log == logComplete {
			log := byID[r.ID]
			if log == nil {
				log = []gen.DeliveryAttempt{}
			}
			d.Log = &log
		}
		out.Deliveries = append(out.Deliveries, d)
	}
	return jsonResponse{status: http.StatusOK, body: out}, nil
}

// --- POST /v1/subscriptions/{id}/deliveries/{delivery_id}/retry -----------

func (ss *Subscriptions) retry(ctx context.Context, id, deliveryID string) (subscriptionResponse, error) {
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	rec, p, err := ss.own(ctx, c, id)
	if p != nil || err != nil {
		return *p, err
	}
	now := ss.now()
	d, err := ss.Store.RequeueDelivery(ctx, rec.ID, deliveryID, now,
		ss.event(c, EventDeliveryRequeued, "delivery", deliveryID, now, map[string]any{"subscription_id": rec.ID}))
	switch {
	case errors.Is(err, store.ErrNotFound):
		fe := core.Fieldf("delivery_id", "%s is not a delivery of this subscription", quoteShort(deliveryID))
		return problemOf(ctx, http.StatusNotFound, SlugNotFound, "Not found", fe.Error(), fe), nil
	case errors.Is(err, store.ErrDeliveryInFlight):
		fe := core.Fieldf("delivery_id", "an attempt is in flight; retry once it has ended")
		return problemOf(ctx, http.StatusConflict, SlugDelivering, "Delivery in flight", fe.Error(), fe), nil
	case err != nil:
		return ss.failure(ctx, err)
	}
	ss.counter(CounterDeliveriesRequeued).Inc()
	ss.logger().LogAttrs(ctx, slog.LevelInfo, "delivery requeued", slog.String("client_id", c.ClientID),
		slog.String("subscription_id", rec.ID), slog.String("delivery_id", deliveryID))
	return jsonResponse{status: http.StatusAccepted, body: deliveryBody(d)}, nil
}
