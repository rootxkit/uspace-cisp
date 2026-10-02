package deliver

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	coreauth "github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-cisp/internal/authtest"
	"github.com/rootxkit/uspace-cisp/internal/jws"
	"github.com/rootxkit/uspace-cisp/internal/obs"
	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/store"
	"github.com/rootxkit/uspace-cisp/internal/subscription"
)

// fakeStore is deliver's store in memory, with the contracts of the real
// one: a delivery per (subscription, change) once, claims leased, the
// subscription's failure run.
type fakeStore struct {
	mu         sync.Mutex
	subs       []store.SubscriptionRecord
	deliveries map[string]*fakeDelivery
	changes    map[int64]publication.Change
	versions   map[publication.Dataset]int64
	watermark  int64
	failures   map[string]store.Failed
	suspended  map[string]string
	// err, when set, fails every call.
	err error
	seq int
}

type fakeDelivery struct {
	id, sub   string
	changeID  *int64
	state     string
	attempts  int
	nextRetry *time.Time
	created   time.Time
	callback  string
	datasets  []publication.Dataset
	lastError string
	lastCode  *int
}

var errDown = errors.New("dial tcp: connection refused")

func newFakeStore() *fakeStore {
	return &fakeStore{
		deliveries: map[string]*fakeDelivery{}, changes: map[int64]publication.Change{},
		versions: map[publication.Dataset]int64{}, failures: map[string]store.Failed{}, suspended: map[string]string{},
	}
}

func (f *fakeStore) ReceivingSubscriptions(context.Context) ([]store.SubscriptionRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	var out []store.SubscriptionRecord
	for i := range f.subs {
		s := &f.subs[i]
		if s.Status.Receives() {
			out = append(out, *s)
		}
	}
	return out, nil
}

func (f *fakeStore) sub(id string) *store.SubscriptionRecord {
	for i := range f.subs {
		if f.subs[i].ID == id {
			return &f.subs[i]
		}
	}
	return nil
}

func (f *fakeStore) InsertChangeDeliveries(_ context.Context, changeID int64, ids []string, now time.Time) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return 0, f.err
	}
	var n int64
	for _, sid := range ids {
		dup := false
		for _, d := range f.deliveries {
			if d.sub == sid && d.changeID != nil && *d.changeID == changeID {
				dup = true
			}
		}
		if dup {
			continue
		}
		f.seq++
		cid := changeID
		at := now
		s := f.sub(sid)
		id := fmt.Sprintf("D%025d", f.seq)
		f.deliveries[id] = &fakeDelivery{
			id: id, sub: sid, changeID: &cid, state: store.DeliveryQueued, nextRetry: &at, created: now,
			callback: s.CallbackURL, datasets: s.Datasets,
		}
		n++
	}
	return n, nil
}

func (f *fakeStore) addPing(sub string, at time.Time) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seq++
	id := fmt.Sprintf("P%025d", f.seq)
	s := f.sub(sub)
	f.deliveries[id] = &fakeDelivery{id: id, sub: sub, state: store.DeliveryQueued, nextRetry: &at, created: at,
		callback: s.CallbackURL, datasets: s.Datasets}
	return id
}

func (f *fakeStore) Watermark(context.Context, string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.watermark, f.err
}

func (f *fakeStore) AdvanceWatermark(_ context.Context, _ string, w int64, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.watermark = max(f.watermark, w)
	return nil
}

func (f *fakeStore) ScanChanges(_ context.Context, since int64, before time.Time, limit int) ([]publication.Change, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	var out []publication.Change
	for k := range f.changes {
		c := f.changes[k]
		if c.ID > since && c.At.Before(before) {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (f *fakeStore) ChangesByID(_ context.Context, ids []int64) (map[int64]publication.Change, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	out := map[int64]publication.Change{}
	for _, id := range ids {
		if c, ok := f.changes[id]; ok {
			out[id] = c
		}
	}
	return out, nil
}

func (f *fakeStore) DatasetVersions(context.Context) (map[publication.Dataset]int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.versions, f.err
}

func (f *fakeStore) ClaimDeliveries(_ context.Context, now, lease time.Time, limit int) ([]store.Claim, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	var due []*fakeDelivery
	for _, d := range f.deliveries {
		s := f.sub(d.sub)
		if d.nextRetry != nil && !d.nextRetry.After(now) && s != nil && s.Status.Receives() &&
			(d.state == store.DeliveryQueued || d.state == store.DeliveryFailed || d.state == store.DeliveryDelivering) {
			due = append(due, d)
		}
	}
	sort.Slice(due, func(i, j int) bool { return due[i].nextRetry.Before(*due[j].nextRetry) || due[i].id < due[j].id })
	if len(due) > limit {
		due = due[:limit]
	}
	out := make([]store.Claim, 0, len(due))
	for _, d := range due {
		d.state = store.DeliveryDelivering
		l := lease
		d.nextRetry = &l
		s := f.sub(d.sub)
		out = append(out, store.Claim{DeliveryID: d.id, SubscriptionID: d.sub, ChangeID: d.changeID, Attempts: d.attempts,
			CreatedAt: d.created, CallbackURL: s.CallbackURL, Datasets: s.Datasets, SubscriptionStatus: s.Status})
	}
	return out, nil
}

func (f *fakeStore) FinishDelivered(_ context.Context, id, sub string, at time.Time, code int) (store.Delivered, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return store.Delivered{}, f.err
	}
	d := f.deliveries[id]
	d.state, d.attempts, d.nextRetry, d.lastCode, d.lastError = store.DeliveryDelivered, d.attempts+1, nil, &code, ""
	s := f.sub(sub)
	verified := s.Status == subscription.PendingVerification
	if verified {
		s.Status = subscription.Active
		s.VerifiedAt = &at
	}
	s.ConsecutiveFailures, s.FailingSince, s.LastSuccessAt = 0, nil, &at
	return store.Delivered{Attempts: d.attempts, Verified: verified}, nil
}

func (f *fakeStore) FinishFailed(_ context.Context, fa store.FailedAttempt) (store.Failed, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return store.Failed{}, f.err
	}
	d := f.deliveries[fa.DeliveryID]
	d.attempts++
	d.lastError, d.lastCode = fa.Error, fa.StatusCode
	s := f.sub(fa.SubscriptionID)
	if fa.Expire || s.Status == subscription.Deleted {
		d.state, d.nextRetry = store.DeliveryExpired, nil
	} else {
		d.state, d.nextRetry = store.DeliveryFailed, fa.NextRetryAt
	}
	s.ConsecutiveFailures++
	if s.FailingSince == nil {
		at := fa.At
		s.FailingSince = &at
	}
	out := store.Failed{Attempts: d.attempts, State: d.state, SubscriptionStatus: s.Status, ConsecutiveFailures: s.ConsecutiveFailures, FailingSince: *s.FailingSince}
	if ov, ok := f.failures[fa.SubscriptionID]; ok {
		ov.Attempts, ov.State = out.Attempts, out.State
		out = ov
	}
	return out, nil
}

func (f *fakeStore) SuspendSubscription(_ context.Context, id, reason string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return false, f.err
	}
	s := f.sub(id)
	if s.Status != subscription.Active {
		return false, nil
	}
	s.Status = subscription.Suspended
	f.suspended[id] = reason
	return true, nil
}

func (f *fakeStore) DeliveryQueue(_ context.Context, now time.Time) (store.QueueStats, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return store.QueueStats{}, f.err
	}
	var q store.QueueStats
	var oldest *time.Time
	for _, d := range f.deliveries {
		switch d.state {
		case store.DeliveryQueued, store.DeliveryFailed:
			q.Queued++
			if d.nextRetry != nil && !d.nextRetry.After(now) {
				q.Due++
				if oldest == nil || d.nextRetry.Before(*oldest) {
					oldest = d.nextRetry
				}
			}
		case store.DeliveryDelivering:
			q.Delivering++
		}
	}
	if oldest != nil {
		q.OldestDueAge = now.Sub(*oldest)
	}
	for i := range f.subs {
		s := &f.subs[i]
		if s.Status == subscription.Suspended {
			q.Suspended++
		}
	}
	return q, nil
}

func (f *fakeStore) delivery(id string) fakeDelivery {
	f.mu.Lock()
	defer f.mu.Unlock()
	return *f.deliveries[id]
}

// fakeLog is the delivery log in memory.
type fakeLog struct {
	mu   sync.Mutex
	rows []store.DeliveryAttempt
	err  error
}

func (l *fakeLog) Record(_ context.Context, a store.DeliveryAttempt) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return l.err
	}
	l.rows = append(l.rows, a)
	return nil
}

func (l *fakeLog) all() []store.DeliveryAttempt {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]store.DeliveryAttempt{}, l.rows...)
}

const testIssuer = "https://uspace-cisp.example.test"

// keyRing is a CISP key ring of one 3072-bit key.
func keyRing(t testing.TB, kid string) (*jws.KeyRing, *rsa.PrivateKey) {
	t.Helper()
	k := authtest.Key(t, "cisp-"+kid, 3072)
	pemBytes, err := jws.EncodePrivateKeyPEM(k)
	if err != nil {
		t.Fatal(err)
	}
	ring, err := jws.LoadKeyRing(pemBytes, kid, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	return ring, k
}

// verifier is a receiver's verifier of key's public half (kid) for
// audience.
func verifier(t testing.TB, kid string, key *rsa.PrivateKey, audience string) *coreauth.CompactVerifier {
	t.Helper()
	set := authtest.PublicSet(t, map[string]*rsa.PrivateKey{kid: key})
	v, err := coreauth.NewCompactVerifier(context.Background(), coreauth.CompactConfig{
		Issuers:   map[string]coreauth.IssuerConfig{testIssuer: {Keys: set}},
		Audiences: []string{audience},
	})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

type harness struct {
	s      *Service
	st     *fakeStore
	log    *fakeLog
	ring   *jws.KeyRing
	key    *rsa.PrivateKey
	status *obs.Status
}

func newHarness(t *testing.T, mutate func(*Config)) *harness {
	t.Helper()
	ring, key := keyRing(t, "cisp-1")
	h := &harness{st: newFakeStore(), log: &fakeLog{}, ring: ring, key: key, status: obs.NewStatus("deliver", nil, time.Now())}
	cfg := Config{
		Instance: "test-1", IssuerURL: testIssuer, PublicBaseURL: "https://uspace-cisp.example.test/",
		Policy: subscription.URLPolicy{AllowPrivate: true, AllowInsecure: true}, Version: "v-test",
	}
	if mutate != nil {
		mutate(&cfg)
	}
	s, err := New(cfg, h.st, h.log, ring, Options{Status: h.status, BusState: func() string { return "connected" }})
	if err != nil {
		t.Fatal(err)
	}
	h.s = s
	return h
}

func (h *harness) counter(name string) uint64 {
	return h.status.Component(Component).Counter(name, "").Value()
}

// subscribe adds an active subscription to callback, created an hour ago.
func (h *harness) subscribe(id, callback string, st subscription.Status, ds ...publication.Dataset) {
	if len(ds) == 0 {
		ds = []publication.Dataset{publication.DatasetZones}
	}
	h.st.mu.Lock()
	defer h.st.mu.Unlock()
	h.st.subs = append(h.st.subs, store.SubscriptionRecord{
		Subscription: subscription.Subscription{ID: id, ClientID: "ussp-test-01", CallbackURL: callback, Datasets: ds, Status: st},
		CreatedAt:    time.Now().Add(-time.Hour).UTC(),
	})
}

// change adds a change of zones committed at.
func (h *harness) change(id int64, at time.Time) publication.Change {
	c := publication.Change{ID: id, Dataset: publication.DatasetZones, Version: id, FeatureIDs: []string{"ZA"}, Reason: publication.ReasonPublication, At: at.UTC()}
	h.st.mu.Lock()
	h.st.changes[id] = c
	h.st.mu.Unlock()
	return c
}
