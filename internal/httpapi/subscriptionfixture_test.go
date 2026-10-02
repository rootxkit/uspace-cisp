package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"github.com/rootxkit/uspace-cisp/internal/auth"
	"github.com/rootxkit/uspace-cisp/internal/obs"
	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/store"
	"github.com/rootxkit/uspace-cisp/internal/subscription"
)

// The fake store's side of the subscriptions (WP-6): the rows, the
// deliveries and the audit rows, with the contracts of the store (the
// per-client limit, the ping written with the subscription, requeue
// refusing a delivery in flight).

type fakeSubscriptions struct {
	rows       map[string]*store.SubscriptionRecord
	deliveries map[string]*store.DeliveryRecord
	events     []store.Event
	// attempts are what the delivery log holds; logErr fails its read.
	attempts []store.DeliveryAttempt
	logErr   error
}

var _ SubscriptionStore = (*fakeStore)(nil)

func (f *fakeStore) sb() *fakeSubscriptions {
	if f.subs == nil {
		f.subs = &fakeSubscriptions{rows: map[string]*store.SubscriptionRecord{}, deliveries: map[string]*store.DeliveryRecord{}}
	}
	return f.subs
}

func (f *fakeStore) CreateSubscription(_ context.Context, n store.NewSubscription) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return errFakeDown
	}
	count := 0
	for _, r := range f.sb().rows {
		if r.ClientID == n.Record.ClientID && r.Status != subscription.Deleted {
			count++
		}
	}
	if count >= n.MaxPerClient {
		return store.ErrSubscriptionLimit
	}
	rec := n.Record
	f.sb().rows[rec.ID] = &rec
	at := rec.CreatedAt
	f.sb().deliveries[n.PingID] = &store.DeliveryRecord{
		ID: n.PingID, SubscriptionID: rec.ID, Reason: publication.ReasonSubscriptionTest, State: store.DeliveryQueued,
		NextRetryAt: &at, CreatedAt: at,
	}
	f.sb().events = append(f.sb().events, n.Event)
	return nil
}

func (f *fakeStore) Subscription(_ context.Context, id string) (store.SubscriptionRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return store.SubscriptionRecord{}, errFakeDown
	}
	r, ok := f.sb().rows[id]
	if !ok {
		return store.SubscriptionRecord{}, store.ErrNotFound
	}
	return *r, nil
}

func (f *fakeStore) ClientSubscriptions(_ context.Context, clientID string, limit int) ([]store.SubscriptionRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return nil, errFakeDown
	}
	var out []store.SubscriptionRecord
	for _, r := range f.sb().rows {
		if r.ClientID == clientID && r.Status != subscription.Deleted {
			out = append(out, *r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (f *fakeStore) UpdateSubscription(_ context.Context, u store.SubscriptionUpdate) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return errFakeDown
	}
	rec := u.Record
	f.sb().rows[rec.ID] = &rec
	if u.PingID != "" {
		at := u.Event.TS
		f.sb().deliveries[u.PingID] = &store.DeliveryRecord{
			ID: u.PingID, SubscriptionID: rec.ID, Reason: publication.ReasonSubscriptionTest, State: store.DeliveryQueued,
			NextRetryAt: &at, CreatedAt: at,
		}
	}
	f.sb().events = append(f.sb().events, u.Event)
	return nil
}

func (f *fakeStore) DeleteSubscription(_ context.Context, id string, e store.Event) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return 0, errFakeDown
	}
	f.sb().rows[id].Status = subscription.Deleted
	var n int64
	for _, d := range f.sb().deliveries {
		if d.SubscriptionID == id && (d.State == store.DeliveryQueued || d.State == store.DeliveryFailed || d.State == store.DeliveryDelivering) {
			d.State = store.DeliveryExpired
			d.NextRetryAt = nil
			n++
		}
	}
	if e.Payload == nil {
		e.Payload = map[string]any{}
	}
	e.Payload["deliveries_expired"] = n
	f.sb().events = append(f.sb().events, e)
	return n, nil
}

func (f *fakeStore) LatestPing(_ context.Context, subscriptionID string) (store.DeliveryRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return store.DeliveryRecord{}, errFakeDown
	}
	var best *store.DeliveryRecord
	for _, d := range f.sb().deliveries {
		if d.SubscriptionID == subscriptionID && d.ChangeID == nil && (best == nil || d.CreatedAt.After(best.CreatedAt) || (d.CreatedAt.Equal(best.CreatedAt) && d.ID > best.ID)) {
			best = d
		}
	}
	if best == nil {
		return store.DeliveryRecord{}, store.ErrNotFound
	}
	return *best, nil
}

func (f *fakeStore) SubscriptionDeliveries(_ context.Context, subscriptionID string, since time.Time, limit int) ([]store.DeliveryRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return nil, errFakeDown
	}
	var out []store.DeliveryRecord
	for _, d := range f.sb().deliveries {
		if d.SubscriptionID == subscriptionID && !d.CreatedAt.Before(since) {
			out = append(out, *d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (f *fakeStore) RequeueDelivery(_ context.Context, subscriptionID, deliveryID string, now time.Time, e store.Event) (store.DeliveryRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return store.DeliveryRecord{}, errFakeDown
	}
	d, ok := f.sb().deliveries[deliveryID]
	if !ok || d.SubscriptionID != subscriptionID {
		return store.DeliveryRecord{}, store.ErrNotFound
	}
	if d.State == store.DeliveryDelivering {
		return store.DeliveryRecord{}, store.ErrDeliveryInFlight
	}
	d.State = store.DeliveryQueued
	d.NextRetryAt = &now
	f.sb().events = append(f.sb().events, e)
	return *d, nil
}

// AttemptsOf is the fake delivery log.
func (f *fakeSubscriptions) AttemptsOf(_ context.Context, subscriptionID string, ids []string) ([]store.DeliveryAttempt, error) {
	if f.logErr != nil {
		return nil, f.logErr
	}
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	var out []store.DeliveryAttempt
	for _, a := range f.attempts {
		if a.SubscriptionID == subscriptionID && want[a.DeliveryID] {
			out = append(out, a)
		}
	}
	return out, nil
}

// publicResolver answers every host with a public address; a test sets
// resolved to answer otherwise.
type fakeResolver struct {
	ips map[string][]net.IP
	err error
}

func (r *fakeResolver) resolve(_ context.Context, host string) ([]net.IP, error) {
	if r.err != nil {
		return nil, r.err
	}
	if ips, ok := r.ips[host]; ok {
		return ips, nil
	}
	return []net.IP{net.ParseIP("93.184.216.34")}, nil
}

// withSubscriptions gives the harness the subscriptions when its store
// serves them, with a resolver that answers public addresses.
func (h *pubHarness) withSubscriptions(st PublicationStore, server *Server, status *obs.Status, logger *slog.Logger) {
	sst, ok := st.(SubscriptionStore)
	if !ok {
		return
	}
	res := &fakeResolver{ips: map[string][]net.IP{}}
	h.subs = &Subscriptions{Store: sst, MaxPerClient: 3, Resolve: res.resolve, Status: status, Logger: logger}
	if f, ok := st.(*fakeStore); ok {
		h.subs.Log = f.sb()
	}
	server.Subscriptions = h.subs
}

// subscriberToken is a USSP's token with cis.read.
func (h *pubHarness) subscriberToken(client string) string {
	return h.token(client, auth.ScopeRead)
}

// subReq is a request of the subscriptions tag by client with body.
func (h *pubHarness) subReq(method, path, client string, body any) *http.Request {
	h.t.Helper()
	var r *http.Request
	if body == nil {
		r = httptest.NewRequest(method, path, http.NoBody)
	} else {
		raw, err := json.Marshal(body)
		if err != nil {
			h.t.Fatal(err)
		}
		r = httptest.NewRequest(method, path, bytes.NewReader(raw))
		r.Header.Set("Content-Type", "application/json")
	}
	if client != "" {
		r.Header.Set("Authorization", "Bearer "+h.subscriberToken(client))
	}
	return r
}

// subDo sends the request and checks the exchange against the spec.
func (h *pubHarness) subDo(t *testing.T, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	var body []byte
	if req.Body != nil && req.Body != http.NoBody {
		raw := new(bytes.Buffer)
		_, _ = raw.ReadFrom(req.Body)
		body = raw.Bytes()
		req.Body = nopCloser{bytes.NewReader(body)}
	}
	rec := h.do(req)
	check := req.Clone(context.Background())
	if body != nil {
		check.Body = nopCloser{bytes.NewReader(body)}
	}
	conform(t, check, rec)
	return rec
}

type nopCloser struct{ *bytes.Reader }

func (nopCloser) Close() error { return nil }

func decodeJSON[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("%v: %s", err, rec.Body.String())
	}
	return v
}

var errLogDown = errors.New("timeseries: connection refused")
