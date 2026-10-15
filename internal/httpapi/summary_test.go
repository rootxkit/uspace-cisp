package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-cisp/internal/auth"
	"github.com/rootxkit/uspace-cisp/internal/httpapi/gen"
	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/store"
	"github.com/rootxkit/uspace-cisp/internal/subscription"
)

// The console overview's figures (GET /v1/console/summary, docs/PLAN.md
// section 15 Q52) on the fakes. Every exchange is checked against the
// spec by consoleDo, so a member the spec does not name fails the test.

const summaryPath = "/v1/console/summary"

// seedSummary adds, beside seedConsole's active SUB-1 with its delivered
// DEL-1: a suspended, a pending and a deleted subscription, and the
// deliveries whose last attempt failed an hour ago (counted), 25 hours
// ago (outside the window), expired an hour ago (counted), and a failed
// one never attempted (not counted); the current USSP list is PUB-U2
// with one entry.
func seedSummary(t *testing.T, h *pubHarness) {
	t.Helper()
	seedConsole(t, h)
	h.fake.mu.Lock()
	defer h.fake.mu.Unlock()
	now := time.Now().UTC()
	for id, st := range map[string]subscription.Status{"SUB-2": subscription.Suspended, "SUB-3": subscription.PendingVerification, "SUB-4": subscription.Deleted} {
		h.fake.sb().rows[id] = &store.SubscriptionRecord{Subscription: subscription.Subscription{
			ID: id, ClientID: "ussp-geo2-0" + id[4:], CallbackURL: "https://ussp2.example.ge/hook/" + id,
			Datasets: []publication.Dataset{publication.DatasetZones}, Status: st,
		}, CreatedAt: now}
	}
	at := func(ago time.Duration) *time.Time { t := now.Add(-ago); return &t }
	for id, d := range map[string]*store.DeliveryRecord{
		"DEL-F1": {State: store.DeliveryFailed, LastAttemptAt: at(time.Hour)},
		"DEL-F2": {State: store.DeliveryFailed, LastAttemptAt: at(25 * time.Hour)},
		"DEL-E1": {State: store.DeliveryExpired, LastAttemptAt: at(time.Hour)},
		"DEL-F3": {State: store.DeliveryFailed},
	} {
		d.ID, d.SubscriptionID, d.Reason, d.CreatedAt = id, "SUB-1", publication.ReasonPublication, now
		h.fake.sb().deliveries[id] = d
	}
	h.cfake.current[publication.DatasetUSSPList] = "PUB-U2"
}

func ptr[T any](v T) *T { return &v }

func TestConsoleSummary(t *testing.T) {
	h := newPubHarness(t, nil)
	seedSummary(t, h)
	lat := &fakeLatency{answer: store.DeliveryLatency{Now: time.Now().UTC(), Attempts: 42, P50Ms: ptr(80), P95Ms: ptr(450)}}
	h.console.Latency = lat
	tok, _ := h.consoleToken(t, auth.RoleViewer)
	rec := h.consoleDo(t, h.consoleReq(http.MethodGet, summaryPath, tok, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("summary: %d %s", rec.Code, rec.Body.String())
	}
	got := decodeJSON[gen.ConsoleSummary](t, rec)
	if s := got.Subscriptions; s.Active != 1 || s.Suspended != 1 || s.PendingVerification != 1 || s.Deleted != 1 {
		t.Errorf("subscriptions %+v", s)
	}
	if f := got.FailedDeliveries; f.WindowS != 86400 || f.Failed != 1 || f.Expired != 1 {
		t.Errorf("failed deliveries %+v, want 86400 s, 1 failed (not the one 25 h ago nor the unattempted one), 1 expired", f)
	}
	if u := got.Ussps; u.Version != 2 || u.Count != 1 {
		t.Errorf("ussps %+v", u)
	}
	l := got.DeliveryLatency
	if l.Log != gen.ConsoleSummaryDeliveryLatencyLogComplete || l.WindowS != 3600 || l.MaxAttempts != MaxSummaryLatencyAttempts ||
		l.Attempts != 42 || l.Sampled || l.P50Ms == nil || *l.P50Ms != 80 || l.P95Ms == nil || *l.P95Ms != 450 {
		t.Errorf("latency %+v", l)
	}
	if got.Now.IsZero() {
		t.Error("no now")
	}
	if len(lat.asked) != 1 || lat.asked[0] != (latencyAsk{SummaryLatencyWindow, MaxSummaryLatencyAttempts}) {
		t.Errorf("the log was asked %+v, want one hour and %d attempts", lat.asked, MaxSummaryLatencyAttempts)
	}

	// No personal data: no client, callback, account or contact reaches
	// the body, though the store holds them all.
	body := rec.Body.String()
	for _, leak := range []string{"ussp-geo", "https://", "example.ge", "client", "callback", "username", "contact", "@"} {
		if strings.Contains(body, leak) {
			t.Errorf("the summary carries %q: %s", leak, body)
		}
	}

	// The bound reached: sampled.
	lat.answer.Attempts = MaxSummaryLatencyAttempts
	if l := decodeJSON[gen.ConsoleSummary](t, h.consoleDo(t, h.consoleReq(http.MethodGet, summaryPath, tok, nil))).DeliveryLatency; !l.Sampled {
		t.Errorf("at the bound: %+v, want sampled", l)
	}

	// An hour with no attempt: complete, a count of 0 and no percentiles.
	lat.answer = store.DeliveryLatency{Now: time.Now().UTC()}
	if l := decodeJSON[gen.ConsoleSummary](t, h.consoleDo(t, h.consoleReq(http.MethodGet, summaryPath, tok, nil))).DeliveryLatency; l.Log != "complete" ||
		l.Attempts != 0 || l.P50Ms != nil || l.P95Ms != nil || l.Sampled {
		t.Errorf("no attempts: %+v", l)
	}
}

// Before the first USSP list, no subscription and no failure: zeros and
// version 0, all members present (E-02, the branch that says nothing).
func TestConsoleSummaryEmpty(t *testing.T) {
	h := newPubHarness(t, nil)
	tok, _ := h.consoleToken(t, auth.RoleViewer)
	got := decodeJSON[gen.ConsoleSummary](t, h.consoleDo(t, h.consoleReq(http.MethodGet, summaryPath, tok, nil)))
	if got.Subscriptions != (gen.ConsoleSummary{}).Subscriptions || got.FailedDeliveries.Failed != 0 || got.FailedDeliveries.Expired != 0 ||
		got.Ussps.Version != 0 || got.Ussps.Count != 0 {
		t.Errorf("empty summary %+v", got)
	}
	if got.DeliveryLatency.Log != gen.ConsoleSummaryDeliveryLatencyLogNotConfigured || got.DeliveryLatency.P50Ms != nil {
		t.Errorf("without a delivery log: %+v", got.DeliveryLatency)
	}
}

// Who may read it: viewer and above 200; a machine token (a USSP's
// cis.read, and the authority's) 403; no token or a bad one 401.
func TestConsoleSummaryAccess(t *testing.T) {
	h := newPubHarness(t, nil)
	seedSummary(t, h)
	for _, r := range auth.Roles {
		tok, _ := h.consoleToken(t, r)
		if rec := h.consoleDo(t, h.consoleReq(http.MethodGet, summaryPath, tok, nil)); rec.Code != http.StatusOK {
			t.Errorf("%s: %d %s", r, rec.Code, rec.Body.String())
		}
	}
	for name, tok := range map[string]string{
		"ussp cis.read": h.token("ussp-geo1-01", auth.ScopeRead),
		"authority":     h.authorityToken(),
	} {
		rec := h.consoleDo(t, h.consoleReq(http.MethodGet, summaryPath, tok, nil))
		if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), `"subscriptions"`) {
			t.Errorf("%s: %d %s, want 403 and no figures", name, rec.Code, rec.Body.String())
		}
	}
	for name, tok := range map[string]string{"no token": "", "not a token": "not.a.token"} {
		rec := h.consoleDo(t, h.consoleReq(http.MethodGet, summaryPath, tok, nil))
		if rec.Code != http.StatusUnauthorized || strings.Contains(rec.Body.String(), `"subscriptions"`) {
			t.Errorf("%s: %d %s, want 401 and no figures", name, rec.Code, rec.Body.String())
		}
	}
	// Read only: no writing method is an operation of the path, for an
	// admin either (ServeMux answers HEAD with GET).
	admin, _ := h.consoleToken(t, auth.RoleAdmin)
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		rec := httptestDo(h, h.consoleReq(m, summaryPath, admin, map[string]any{}))
		if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "GET, HEAD" {
			t.Errorf("%s: %d Allow %q", m, rec.Code, rec.Header().Get("Allow"))
		}
	}
}

// The delivery log down: the latency says unavailable and the counter
// moves, and every other figure is still served; the log back, complete
// again. A deadline that passes is the request's 503, not a figure.
func TestConsoleSummaryLogDown(t *testing.T) {
	h := newPubHarness(t, nil)
	seedSummary(t, h)
	lat := &fakeLatency{err: errors.New("timeseries: connection refused")}
	h.console.Latency = lat
	tok, _ := h.consoleToken(t, auth.RoleViewer)
	counter := func() uint64 { return h.console.Registry.Totals()[consoleComponent+"."+CounterSummaryLogFailed] }
	before := counter()
	got := decodeJSON[gen.ConsoleSummary](t, h.consoleDo(t, h.consoleReq(http.MethodGet, summaryPath, tok, nil)))
	if got.DeliveryLatency.Log != gen.ConsoleSummaryDeliveryLatencyLogUnavailable || got.DeliveryLatency.Attempts != 0 || got.DeliveryLatency.P50Ms != nil {
		t.Errorf("log down: %+v", got.DeliveryLatency)
	}
	if got.Subscriptions.Active != 1 || got.FailedDeliveries.Failed != 1 || got.Ussps.Count != 1 {
		t.Errorf("log down, the other figures: %+v", got)
	}
	if n := counter(); n != before+1 {
		t.Errorf("%s %d -> %d", CounterSummaryLogFailed, before, n)
	}
	lat.err, lat.answer = nil, store.DeliveryLatency{Attempts: 3, P50Ms: ptr(10), P95Ms: ptr(20)}
	if l := decodeJSON[gen.ConsoleSummary](t, h.consoleDo(t, h.consoleReq(http.MethodGet, summaryPath, tok, nil))).DeliveryLatency; l.Log != "complete" || l.Attempts != 3 {
		t.Errorf("log back: %+v", l)
	}
	if n := counter(); n != before+1 {
		t.Errorf("the counter moved on a good read: %d", n)
	}
	lat.err = context.DeadlineExceeded
	if rec := h.consoleDo(t, h.consoleReq(http.MethodGet, summaryPath, tok, nil)); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("deadline: %d %s", rec.Code, rec.Body.String())
	}
}

// The relational database down: 503 database_unavailable with
// Retry-After and no figure; back, 200.
func TestConsoleSummaryStoreDown(t *testing.T) {
	h := newPubHarness(t, nil)
	seedSummary(t, h)
	tok, _ := h.consoleToken(t, auth.RoleViewer)
	h.fake.mu.Lock()
	h.fake.down = true
	h.fake.mu.Unlock()
	rec := h.consoleDo(t, h.consoleReq(http.MethodGet, summaryPath, tok, nil))
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" ||
		decodeProblem(t, rec).Type != ProblemTypeBase+SlugDatabaseUnavailable {
		t.Errorf("store down: %d %s", rec.Code, rec.Body.String())
	}
	h.fake.mu.Lock()
	h.fake.down = false
	h.fake.mu.Unlock()
	if rec := h.consoleDo(t, h.consoleReq(http.MethodGet, summaryPath, tok, nil)); rec.Code != http.StatusOK {
		t.Errorf("back: %d", rec.Code)
	}
}
