package httpapi

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-cisp/internal/auth"
	"github.com/rootxkit/uspace-cisp/internal/httpapi/gen"
	"github.com/rootxkit/uspace-cisp/internal/store"
	"github.com/rootxkit/uspace-cisp/internal/subscription"
)

const (
	usspA = "ussp-aaa-01"
	usspB = "ussp-bbb-01"
)

func validSub() map[string]any {
	return map[string]any{
		"callback_url": "https://ussp.example.ge/v1/cis/notifications",
		"datasets":     []string{"zones", "restrictions"},
		"bbox":         []float64{44.7, 41.6, 44.9, 41.8},
	}
}

func (h *pubHarness) createSub(t *testing.T, client string, body map[string]any) gen.Subscription {
	t.Helper()
	rec := h.subDo(t, h.subReq(http.MethodPost, "/v1/subscriptions", client, body))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", rec.Code, rec.Body.String())
	}
	return decodeJSON[gen.Subscription](t, rec)
}

// A new subscription is pending with its ping queued, audited and
// counted; it is listed and read back by its owner.
func TestSubscriptionCreate(t *testing.T) {
	h := newPubHarness(t, nil)
	rec := h.subDo(t, h.subReq(http.MethodPost, "/v1/subscriptions", usspA, validSub()))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", rec.Code, rec.Body.String())
	}
	s := decodeJSON[gen.Subscription](t, rec)
	if s.Status != gen.SubscriptionStatus(subscription.PendingVerification) || s.ClientId != usspA || s.Bbox == nil || len(s.Datasets) != 2 {
		t.Errorf("subscription %+v", s)
	}
	if loc := rec.Header().Get("Location"); loc != "/v1/subscriptions/"+s.Id {
		t.Errorf("Location %q", loc)
	}
	if s.Verification == nil || s.Verification.Reason != "subscription_test" || s.Verification.State != "queued" || s.Verification.ChangeId != nil {
		t.Errorf("verification %+v", s.Verification)
	}
	ev := h.fake.sb().events
	if len(ev) != 1 || ev[0].EventType != EventSubscriptionCreated || ev[0].ActorID != usspA || ev[0].ActorType != store.ActorClient || ev[0].EntityID != s.Id {
		t.Errorf("audit %+v", ev)
	}
	if n := h.counter(subscriptionsComponent, CounterSubscriptionsCreated); n != 1 {
		t.Errorf("created counter %d", n)
	}
	got := h.subDo(t, h.subReq(http.MethodGet, "/v1/subscriptions/"+s.Id, usspA, nil))
	if got.Code != http.StatusOK || decodeJSON[gen.Subscription](t, got).Id != s.Id {
		t.Errorf("get = %d %s", got.Code, got.Body.String())
	}
	list := h.subDo(t, h.subReq(http.MethodGet, "/v1/subscriptions", usspA, nil))
	if l := decodeJSON[gen.SubscriptionList](t, list); len(l.Subscriptions) != 1 || l.Subscriptions[0].Verification == nil {
		t.Errorf("list %+v", l)
	}
	// Without a box: the whole of each dataset.
	body := validSub()
	delete(body, "bbox")
	if s := h.createSub(t, usspA, body); s.Bbox != nil {
		t.Errorf("bbox %v", *s.Bbox)
	}
}

// Every refusal beside the acceptance that differs in one thing (E-01).
func TestSubscriptionCreateRefusals(t *testing.T) {
	h := newPubHarness(t, nil)
	res := &fakeResolver{ips: map[string][]net.IP{
		"inside.example.ge":   {net.ParseIP("10.0.0.7")},
		"metadata.example.ge": {net.ParseIP("93.184.216.34"), net.ParseIP("169.254.169.254")},
	}}
	h.subs.Resolve = res.resolve
	h.subs.MaxPerClient = 100
	cases := []struct {
		name   string
		mutate func(map[string]any)
		field  string
		phrase string
	}{
		{"http", func(b map[string]any) { b["callback_url"] = "http://ussp.example.ge/hook" }, "callback_url", "must be https"},
		{"userinfo", func(b map[string]any) { b["callback_url"] = "https://u:p@ussp.example.ge/hook" }, "callback_url", "userinfo"},
		{"literal ip", func(b map[string]any) { b["callback_url"] = "https://93.184.216.34/hook" }, "callback_url", "literal IP"},
		{"resolves private", func(b map[string]any) { b["callback_url"] = "https://inside.example.ge/hook" }, "callback_url", "10.0.0.7"},
		{"one address link-local", func(b map[string]any) { b["callback_url"] = "https://metadata.example.ge/hook" }, "callback_url", "169.254.169.254"},
		{"duplicate dataset", func(b map[string]any) { b["datasets"] = []string{"zones", "zones"} }, "datasets[1]", "twice"},
		{"bbox across the antimeridian", func(b map[string]any) { b["bbox"] = []float64{170, 0, -170, 1} }, "bbox", "antimeridian"},
		{"bbox latitude", func(b map[string]any) { b["bbox"] = []float64{0, -91, 1, 1} }, "bbox", "latitudes"},
		{"bbox min lat above max", func(b map[string]any) { b["bbox"] = []float64{0, 2, 1, 1} }, "bbox", "min lat"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := validSub()
			tc.mutate(body)
			rec := h.do(h.subReq(http.MethodPost, "/v1/subscriptions", usspA, body))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("= %d %s", rec.Code, rec.Body.String())
			}
			p := decodeProblem(t, rec)
			if !strings.HasSuffix(p.Type, "/"+SlugSubscriptionRefused) || !hasProblem(p, tc.field, tc.phrase) {
				t.Errorf("problem %+v", p)
			}
		})
	}
	// The twin: a public name that resolves to public addresses only.
	h.createSub(t, usspA, validSub())
	// A name that does not resolve now is accepted; its ping will say why.
	res.err = &net.DNSError{Err: "no such host", Name: "later.example.ge", IsNotFound: true}
	body := validSub()
	body["callback_url"] = "https://later.example.ge/hook"
	h.createSub(t, usspA, body)
	if n := h.counter(subscriptionsComponent, CounterSubscriptionsRefused); n != uint64(len(cases)) {
		t.Errorf("refused counter %d, want %d", n, len(cases))
	}
	// The lab: private callbacks allowed, no resolution needed.
	h.subs.Policy = subscription.URLPolicy{AllowPrivate: true, AllowInsecure: true}
	body["callback_url"] = "http://localhost:8080/v1/cis/notifications"
	h.createSub(t, usspA, body)
}

// The per-client limit: the 4th of a limit of 3 is 409 limit; another
// client is not affected; a delete frees a place (E-10).
func TestSubscriptionLimit(t *testing.T) {
	h := newPubHarness(t, nil)
	var first gen.Subscription
	for i := range 3 {
		s := h.createSub(t, usspA, validSub())
		if i == 0 {
			first = s
		}
	}
	rec := h.subDo(t, h.subReq(http.MethodPost, "/v1/subscriptions", usspA, validSub()))
	if rec.Code != http.StatusConflict || !strings.HasSuffix(decodeProblem(t, rec).Type, "/limit") {
		t.Fatalf("4th = %d %s", rec.Code, rec.Body.String())
	}
	h.createSub(t, usspB, validSub())
	if rec := h.subDo(t, h.subReq(http.MethodDelete, "/v1/subscriptions/"+first.Id, usspA, nil)); rec.Code != http.StatusOK {
		t.Fatalf("delete = %d", rec.Code)
	}
	h.createSub(t, usspA, validSub())
}

func TestSubscriptionAuthentication(t *testing.T) {
	h := newPubHarness(t, nil)
	if rec := h.do(h.subReq(http.MethodPost, "/v1/subscriptions", "", validSub())); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token = %d", rec.Code)
	}
	req := h.subReq(http.MethodPost, "/v1/subscriptions", "", validSub())
	req.Header.Set("Authorization", "Bearer "+h.token(usspA, auth.ScopePublishZones))
	if rec := h.do(req); rec.Code != http.StatusForbidden {
		t.Errorf("no cis.read = %d", rec.Code)
	}
	req = h.subReq(http.MethodPost, "/v1/subscriptions", usspA, validSub())
	req.Header.Set("Content-Type", "text/plain")
	if rec := h.do(req); rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("text/plain = %d", rec.Code)
	}
	for _, path := range []string{"/v1/subscriptions", "/v1/subscriptions/X", "/v1/subscriptions/X/deliveries"} {
		if rec := h.do(h.subReq(http.MethodGet, path, "", nil)); rec.Code != http.StatusUnauthorized {
			t.Errorf("GET %s without a token = %d", path, rec.Code)
		}
	}
	// A body over the 256 KiB cap.
	big := validSub()
	big["callback_url"] = "https://ussp.example.ge/" + strings.Repeat("a", MaxSubscriptionBodyBytes)
	if rec := h.do(h.subReq(http.MethodPost, "/v1/subscriptions", usspA, big)); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("over the cap = %d", rec.Code)
	}
}

// Another client's subscription, a deleted one and an unknown id are all
// 404 on every operation; the owner reads its own.
func TestSubscriptionOwnership(t *testing.T) {
	h := newPubHarness(t, nil)
	s := h.createSub(t, usspA, validSub())
	ops := []struct{ method, path string }{
		{http.MethodGet, "/v1/subscriptions/" + s.Id},
		{http.MethodDelete, "/v1/subscriptions/" + s.Id},
		{http.MethodGet, "/v1/subscriptions/" + s.Id + "/deliveries"},
		{http.MethodPost, "/v1/subscriptions/" + s.Id + "/deliveries/" + s.Verification.Id + "/retry"},
	}
	for _, op := range ops {
		if rec := h.subDo(t, h.subReq(op.method, op.path, usspB, nil)); rec.Code != http.StatusNotFound {
			t.Errorf("%s %s by another client = %d", op.method, op.path, rec.Code)
		}
	}
	if rec := h.subDo(t, h.subReq(http.MethodPatch, "/v1/subscriptions/"+s.Id, usspB, map[string]any{"datasets": []string{"zones"}})); rec.Code != http.StatusNotFound {
		t.Errorf("PATCH by another client = %d", rec.Code)
	}
	if l := decodeJSON[gen.SubscriptionList](t, h.subDo(t, h.subReq(http.MethodGet, "/v1/subscriptions", usspB, nil))); len(l.Subscriptions) != 0 {
		t.Errorf("another client lists %d", len(l.Subscriptions))
	}
	if rec := h.subDo(t, h.subReq(http.MethodGet, "/v1/subscriptions/NOPE", usspA, nil)); rec.Code != http.StatusNotFound {
		t.Errorf("unknown = %d", rec.Code)
	}
	// Deleted: its queued ping expires; 404 afterwards.
	rec := h.subDo(t, h.subReq(http.MethodDelete, "/v1/subscriptions/"+s.Id, usspA, nil))
	if rec.Code != http.StatusOK || decodeJSON[gen.Subscription](t, rec).Status != "deleted" {
		t.Fatalf("delete = %d %s", rec.Code, rec.Body.String())
	}
	if d := h.fake.sb().deliveries[s.Verification.Id]; d.State != store.DeliveryExpired {
		t.Errorf("ping %s after delete", d.State)
	}
	for _, op := range ops[:3] {
		if rec := h.subDo(t, h.subReq(op.method, op.path, usspA, nil)); rec.Code != http.StatusNotFound {
			t.Errorf("%s %s deleted = %d", op.method, op.path, rec.Code)
		}
	}
	ev := h.fake.sb().events
	if last := ev[len(ev)-1]; last.EventType != EventSubscriptionDeleted || last.Payload["deliveries_expired"] != int64(1) {
		t.Errorf("delete audit %+v", last)
	}
}

// GET on a pending subscription says pending_verification with the last
// attempt's error; an active one carries no verification.
func TestSubscriptionPendingSaysWhy(t *testing.T) {
	h := newPubHarness(t, nil)
	s := h.createSub(t, usspA, validSub())
	d := h.fake.sb().deliveries[s.Verification.Id]
	code, msg := 500, "status 500"
	at := time.Now().UTC()
	d.State, d.Attempts, d.LastStatusCode, d.LastError, d.LastAttemptAt = store.DeliveryFailed, 1, &code, &msg, &at
	got := decodeJSON[gen.Subscription](t, h.subDo(t, h.subReq(http.MethodGet, "/v1/subscriptions/"+s.Id, usspA, nil)))
	if got.Status != "pending_verification" || got.Verification == nil || got.Verification.LastError == nil ||
		*got.Verification.LastError != msg || *got.Verification.LastStatusCode != 500 || got.Verification.State != "failed" {
		t.Errorf("pending %+v %+v", got, got.Verification)
	}
	h.fake.sb().rows[s.Id].Status = subscription.Active
	got = decodeJSON[gen.Subscription](t, h.subDo(t, h.subReq(http.MethodGet, "/v1/subscriptions/"+s.Id, usspA, nil)))
	if got.Status != "active" || got.Verification != nil {
		t.Errorf("active %+v", got)
	}
}

func TestSubscriptionPatch(t *testing.T) {
	h := newPubHarness(t, nil)
	s := h.createSub(t, usspA, validSub())
	h.fake.sb().rows[s.Id].Status = subscription.Active
	patch := func(body map[string]any) *httptest.ResponseRecorder {
		return h.subDo(t, h.subReq(http.MethodPatch, "/v1/subscriptions/"+s.Id, usspA, body))
	}
	pings := func() int {
		n := 0
		for _, d := range h.fake.sb().deliveries {
			if d.SubscriptionID == s.Id && d.ChangeID == nil {
				n++
			}
		}
		return n
	}

	// Datasets and box: no re-verification.
	got := decodeJSON[gen.Subscription](t, patch(map[string]any{"datasets": []string{"uspace_airspace"}, "bbox": []float64{}}))
	if got.Status != "active" || got.Bbox != nil || len(got.Datasets) != 1 || got.Datasets[0] != "uspace_airspace" || pings() != 1 {
		t.Errorf("datasets and box: %+v, %d pings", got, pings())
	}
	// The same callback again: nothing to verify.
	got = decodeJSON[gen.Subscription](t, patch(map[string]any{"callback_url": s.CallbackUrl}))
	if got.Status != "active" || pings() != 1 {
		t.Errorf("same callback: %s, %d pings", got.Status, pings())
	}
	// Nothing at all: unchanged, no audit row.
	events := len(h.fake.sb().events)
	if rec := patch(map[string]any{}); rec.Code != http.StatusOK || len(h.fake.sb().events) != events {
		t.Errorf("empty patch = %d, %d audit rows", rec.Code, len(h.fake.sb().events)-events)
	}
	// A new callback: pending again with a new ping.
	got = decodeJSON[gen.Subscription](t, patch(map[string]any{"callback_url": "https://other.example.ge/hook"}))
	if got.Status != "pending_verification" || got.CallbackUrl != "https://other.example.ge/hook" || got.Verification == nil || pings() != 2 {
		t.Errorf("new callback: %+v, %d pings", got, pings())
	}
	// Refusals beside the acceptances above.
	for _, body := range []map[string]any{
		{"callback_url": "http://other.example.ge/hook"},
		{"datasets": []string{"zones", "nope"}},
		{"bbox": []float64{1, 2, 0, 3}},
	} {
		if rec := h.do(h.subReq(http.MethodPatch, "/v1/subscriptions/"+s.Id, usspA, body)); rec.Code != http.StatusBadRequest {
			t.Errorf("%v = %d", body, rec.Code)
		}
	}
	// A suspended subscription is re-activated by any PATCH: pending,
	// pinged, the failure run and the reason cleared.
	r := h.fake.sb().rows[s.Id]
	reason := "50 consecutive failures since ..."
	since := time.Now().Add(-2 * time.Hour)
	r.Status, r.SuspendedReason, r.ConsecutiveFailures, r.FailingSince = subscription.Suspended, &reason, 50, &since
	got = decodeJSON[gen.Subscription](t, patch(map[string]any{}))
	if got.Status != "pending_verification" || got.SuspendedReason != nil || got.ConsecutiveFailures != 0 || got.FailingSince != nil || pings() != 3 {
		t.Errorf("resume: %+v, %d pings", got, pings())
	}
	if last := h.fake.sb().events[len(h.fake.sb().events)-1]; last.Payload["reverified_from"] != "suspended" {
		t.Errorf("resume audit %+v", last.Payload)
	}
}

func TestDeliveriesListAndRetry(t *testing.T) {
	h := newPubHarness(t, nil)
	s := h.createSub(t, usspA, validSub())
	ping := s.Verification.Id
	code := 500
	msg := "status 500"
	h.fake.sb().attempts = []store.DeliveryAttempt{
		{At: time.Now().UTC(), DeliveryID: ping, SubscriptionID: s.Id, Attempt: 1, StatusCode: &code, Error: &msg, LatencyMs: 12, PayloadBytes: 900, Instance: "d1"},
		{At: time.Now().UTC(), DeliveryID: "OTHER", SubscriptionID: s.Id, Attempt: 1, LatencyMs: 1, PayloadBytes: 1, Instance: "d1"},
	}
	list := decodeJSON[gen.DeliveryList](t, h.subDo(t, h.subReq(http.MethodGet, "/v1/subscriptions/"+s.Id+"/deliveries", usspA, nil)))
	if list.Log != "complete" || len(list.Deliveries) != 1 || list.Deliveries[0].Log == nil || len(*list.Deliveries[0].Log) != 1 ||
		(*list.Deliveries[0].Log)[0].LatencyMs != 12 {
		t.Errorf("list %+v", list)
	}
	// The delivery log down: the deliveries are still listed, and say so.
	h.fake.sb().logErr = errLogDown
	list = decodeJSON[gen.DeliveryList](t, h.subDo(t, h.subReq(http.MethodGet, "/v1/subscriptions/"+s.Id+"/deliveries", usspA, nil)))
	if list.Log != "unavailable" || len(list.Deliveries) != 1 || list.Deliveries[0].Log != nil {
		t.Errorf("log down %+v", list)
	}
	if n := h.counter(subscriptionsComponent, CounterDeliveryLogFailed); n != 1 {
		t.Errorf("log failed counter %d", n)
	}
	// Not configured.
	h.subs.Log = nil
	list = decodeJSON[gen.DeliveryList](t, h.subDo(t, h.subReq(http.MethodGet, "/v1/subscriptions/"+s.Id+"/deliveries", usspA, nil)))
	if list.Log != "not_configured" {
		t.Errorf("no log %+v", list)
	}
	// since in the future: empty; a naive time and a bad limit are 400.
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	list = decodeJSON[gen.DeliveryList](t, h.subDo(t, h.subReq(http.MethodGet, "/v1/subscriptions/"+s.Id+"/deliveries?since="+future, usspA, nil)))
	if len(list.Deliveries) != 0 {
		t.Errorf("since the future: %d", len(list.Deliveries))
	}
	for _, q := range []string{"since=2026-10-02T12:00:00", "limit=0", "limit=501"} {
		// h.do: a limit outside the spec's bounds is not a conforming request.
		if rec := h.do(h.subReq(http.MethodGet, "/v1/subscriptions/"+s.Id+"/deliveries?"+q, usspA, nil)); rec.Code != http.StatusBadRequest {
			t.Errorf("%s = %d", q, rec.Code)
		}
	}

	// Retry: re-queued now and audited; unknown 404; in flight 409.
	d := h.fake.sb().deliveries[ping]
	d.State = store.DeliveryExpired
	rec := h.subDo(t, h.subReq(http.MethodPost, "/v1/subscriptions/"+s.Id+"/deliveries/"+ping+"/retry", usspA, nil))
	if rec.Code != http.StatusAccepted || decodeJSON[gen.Delivery](t, rec).State != "queued" {
		t.Errorf("retry = %d %s", rec.Code, rec.Body.String())
	}
	if last := h.fake.sb().events[len(h.fake.sb().events)-1]; last.EventType != EventDeliveryRequeued || last.EntityID != ping {
		t.Errorf("retry audit %+v", last)
	}
	if rec := h.subDo(t, h.subReq(http.MethodPost, "/v1/subscriptions/"+s.Id+"/deliveries/NOPE/retry", usspA, nil)); rec.Code != http.StatusNotFound {
		t.Errorf("unknown delivery = %d", rec.Code)
	}
	d.State = store.DeliveryDelivering
	rec = h.subDo(t, h.subReq(http.MethodPost, "/v1/subscriptions/"+s.Id+"/deliveries/"+ping+"/retry", usspA, nil))
	if rec.Code != http.StatusConflict || !strings.HasSuffix(decodeProblem(t, rec).Type, "/"+SlugDelivering) {
		t.Errorf("in flight = %d %s", rec.Code, rec.Body.String())
	}
	if n := h.counter(subscriptionsComponent, CounterDeliveriesRequeued); n != 1 {
		t.Errorf("requeued counter %d", n)
	}
}

// The database down: 503 with Retry-After on every operation; without a
// database configured: 503 subscriptions unavailable.
func TestSubscriptionsDatabaseDown(t *testing.T) {
	h := newPubHarness(t, nil)
	s := h.createSub(t, usspA, validSub())
	h.fake.mu.Lock()
	h.fake.down = true
	h.fake.mu.Unlock()
	for _, req := range []*http.Request{
		h.subReq(http.MethodPost, "/v1/subscriptions", usspA, validSub()),
		h.subReq(http.MethodGet, "/v1/subscriptions", usspA, nil),
		h.subReq(http.MethodGet, "/v1/subscriptions/"+s.Id, usspA, nil),
	} {
		rec := h.subDo(t, req)
		if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
			t.Errorf("%s %s = %d", req.Method, req.URL.Path, rec.Code)
		}
	}

	f := newFixture(t, &Server{}, Options{})
	for _, req := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/v1/subscriptions", http.NoBody),
		httptest.NewRequest(http.MethodGet, "/v1/subscriptions/X", http.NoBody),
		httptest.NewRequest(http.MethodDelete, "/v1/subscriptions/X", http.NoBody),
		httptest.NewRequest(http.MethodGet, "/v1/subscriptions/X/deliveries", http.NoBody),
		httptest.NewRequest(http.MethodPost, "/v1/subscriptions/X/deliveries/Y/retry", http.NoBody),
	} {
		rec := f.do(req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s %s without a database = %d", req.Method, req.URL.Path, rec.Code)
		}
		conform(t, req, rec)
	}
	for _, m := range []string{http.MethodPost, http.MethodPatch} {
		path := "/v1/subscriptions"
		if m == http.MethodPatch {
			path += "/X"
		}
		req := httptest.NewRequest(m, path, strings.NewReader(`{"callback_url":"https://a.example.ge/","datasets":["zones"]}`))
		req.Header.Set("Content-Type", "application/json")
		if rec := f.do(req); rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s without a database = %d", m, rec.Code)
		}
	}
}

// The handlers refuse to run without the route middleware's caller.
func TestSubscriptionsWithoutCaller(t *testing.T) {
	ss := &Subscriptions{Store: newFakeStore()}
	if _, err := ss.list(context.Background()); err == nil {
		t.Error("list ran without a caller")
	}
}
