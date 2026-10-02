package deliver

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	coreauth "github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-cisp/internal/bus"
	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/store"
	"github.com/rootxkit/uspace-cisp/internal/subscription"
)

// receiver is a callback that records what it was sent and answers with
// what the test sets.
type receiver struct {
	srv   *httptest.Server
	mu    sync.Mutex
	got   []received
	codes []int // answered in turn; the last repeats
	hits  atomic.Int64
}

type received struct {
	token  string
	header http.Header
}

func newReceiver(t *testing.T, codes ...int) *receiver {
	t.Helper()
	r := &receiver{codes: codes}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.got = append(r.got, received{token: string(body), header: req.Header.Clone()})
		code := r.codes[min(len(r.got)-1, len(r.codes)-1)]
		r.mu.Unlock()
		r.hits.Add(1)
		if code >= 300 && code < 400 {
			w.Header().Set("Location", "http://127.0.0.1:1/elsewhere")
		}
		w.WriteHeader(code)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *receiver) url() string { return r.srv.URL + "/v1/cis/notifications" }

func (r *receiver) last(t *testing.T) received {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.got) == 0 {
		t.Fatal("nothing received")
	}
	return r.got[len(r.got)-1]
}

// send claims what is due and waits for the attempts.
func (h *harness) send(t *testing.T) int {
	t.Helper()
	n, err := h.s.Dispatch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	h.s.Wait()
	return n
}

// queueChange adds a change committed at and its delivery to sub.
func (h *harness) queueChange(t *testing.T, sub string, id int64, at time.Time) string {
	t.Helper()
	h.change(id, at)
	if n, err := h.st.InsertChangeDeliveries(context.Background(), id, []string{sub}, time.Now().UTC()); err != nil || n != 1 {
		t.Fatalf("queue: %d %v", n, err)
	}
	h.st.mu.Lock()
	defer h.st.mu.Unlock()
	for did, d := range h.st.deliveries {
		if d.sub == sub && d.changeID != nil && *d.changeID == id {
			return did
		}
	}
	t.Fatal("no delivery")
	return ""
}

// A 200: delivered, the attempt logged, the JWS verified with the key
// ring's public key: iss, aud (the callback's host), sub, jti, and the
// cis/change/v1 body with this instance as producer and pull_url on the
// CISP's base URL; the headers name the delivery and the attempt.
func TestSend200(t *testing.T) {
	h := newHarness(t, nil)
	r := newReceiver(t, http.StatusOK)
	h.subscribe("S1", r.url(), subscription.Active)
	did := h.queueChange(t, "S1", 7, time.Now().Add(-100*time.Millisecond))
	if n := h.send(t); n != 1 {
		t.Fatalf("claimed %d", n)
	}
	d := h.st.delivery(did)
	if d.state != store.DeliveryDelivered || d.attempts != 1 || *d.lastCode != 200 {
		t.Errorf("delivery %+v", d)
	}
	got := r.last(t)
	if ct := got.header.Get("Content-Type"); ct != MediaJOSE {
		t.Errorf("Content-Type %q", ct)
	}
	if got.header.Get(HeaderDeliveryID) != did || got.header.Get(HeaderAttempt) != "1" || got.header.Get("User-Agent") != "uspace-cisp/v-test" {
		t.Errorf("headers %v", got.header)
	}
	cl, body, err := verifier(t, "cisp-1", h.key, "127.0.0.1").Verify(context.Background(), got.token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if cl.Issuer != testIssuer || cl.Audience != "127.0.0.1" || cl.Subject != "S1" || cl.JTI != did || cl.IssuedAt.IsZero() {
		t.Errorf("claims %+v", cl)
	}
	var m bus.ChangeMessage
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		t.Fatal(err)
	}
	if m.Schema != "cis/change/v1" || m.MsgID != "7" || m.Producer != "cisp/deliver-test-1" || m.Reason != "publication" ||
		m.PullURL != "https://uspace-cisp.example.test/v1/zones?since_version=6" || m.ETag != `"zones:7"` {
		t.Errorf("body %+v", m)
	}
	logged := h.log.all()
	if len(logged) != 1 || logged[0].Attempt != 1 || *logged[0].StatusCode != 200 || logged[0].Error != nil ||
		logged[0].ChangeID != 7 || logged[0].PayloadBytes != len(got.token) || logged[0].Instance != "test-1" {
		t.Errorf("log %+v", logged)
	}
	if h.counter(CounterDelivered) != 1 || testutilCount(t, h.s.results.WithLabelValues("200")) != 1 {
		t.Error("counted")
	}
	if c := histCount(t, h.s.firstHist); c != 1 {
		t.Errorf("first-attempt histogram count %d", c)
	}
}

// The audience is the callback's host without its port, lower-case: the
// same with a port and without.
func TestAudience(t *testing.T) {
	for raw, want := range map[string]string{
		"https://ussp.example.ge/v1/cis/notifications":      "ussp.example.ge",
		"https://ussp.example.ge:8443/v1/cis/notifications": "ussp.example.ge",
		"https://USSP.Example.GE/hook":                      "ussp.example.ge",
		"http://localhost:8080/v1/cis/notifications":        "localhost",
		"https://[2001:db8::1]:8443/hook":                   "2001:db8::1",
	} {
		if got, err := Audience(raw); err != nil || got != want {
			t.Errorf("%s: %q %v, want %q", raw, got, err, want)
		}
	}
	if _, err := Audience("/relative"); err == nil {
		t.Error("a URL without a host has an audience")
	}
	// Signed for a callback with a port, verified by the receiver's host.
	h := newHarness(t, nil)
	tok, err := h.s.Sign(store.Claim{DeliveryID: "D1", SubscriptionID: "S1", CallbackURL: "https://ussp.example.ge:8443/x"},
		bus.ChangeMessage{Schema: bus.SchemaChange}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifier(t, "cisp-1", h.key, "ussp.example.ge").Verify(context.Background(), tok); err != nil {
		t.Errorf("aud with a port: %v", err)
	}
	if _, _, err := verifier(t, "cisp-1", h.key, "other.example.ge").Verify(context.Background(), tok); err == nil {
		t.Error("another host's verifier accepted it")
	}
}

// 500 then 200: the retry is scheduled 1 s on (±10 %), made as attempt
// 2, and both attempts are logged.
func TestSend500Then200(t *testing.T) {
	h := newHarness(t, nil)
	r := newReceiver(t, http.StatusInternalServerError, http.StatusOK)
	h.subscribe("S1", r.url(), subscription.Active)
	did := h.queueChange(t, "S1", 1, time.Now())
	h.send(t)
	d := h.st.delivery(did)
	end := h.log.all()[0].At
	if d.state != store.DeliveryFailed || d.attempts != 1 || d.lastError != "status 500" || d.nextRetry == nil {
		t.Fatalf("after 500: %+v", d)
	}
	if delay := d.nextRetry.Sub(end); delay < 900*time.Millisecond || delay > 1100*time.Millisecond {
		t.Errorf("retry in %s, want 1 s ±10 %%", delay)
	}
	if n := h.send(t); n != 0 {
		t.Fatalf("claimed %d before it was due", n)
	}
	h.st.mu.Lock()
	past := time.Now().Add(-time.Millisecond)
	h.st.deliveries[did].nextRetry = &past
	h.st.mu.Unlock()
	h.send(t)
	d = h.st.delivery(did)
	if d.state != store.DeliveryDelivered || d.attempts != 2 {
		t.Errorf("after 200: %+v", d)
	}
	if got := r.last(t).header.Get(HeaderAttempt); got != "2" {
		t.Errorf("X-CIS-Attempt %q", got)
	}
	logged := h.log.all()
	if len(logged) != 2 || logged[0].Attempt != 1 || *logged[0].StatusCode != 500 || *logged[0].Error != "status 500" || logged[1].Attempt != 2 {
		t.Errorf("log %+v", logged)
	}
	if c := histCount(t, h.s.firstHist); c != 1 {
		t.Errorf("first-attempt histogram observed %d times, want once", c)
	}
	if h.counter(CounterFailed) != 1 || h.counter(CounterDelivered) != 1 {
		t.Error("counters")
	}
}

// A 301 is a failure; the Location is never followed.
func TestSendRedirectIsFailure(t *testing.T) {
	h := newHarness(t, nil)
	target := newReceiver(t, http.StatusOK)
	r := newReceiver(t, http.StatusMovedPermanently)
	r.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		r.hits.Add(1)
		w.Header().Set("Location", target.url())
		w.WriteHeader(http.StatusMovedPermanently)
	})
	h.subscribe("S1", r.url(), subscription.Active)
	did := h.queueChange(t, "S1", 1, time.Now())
	h.send(t)
	d := h.st.delivery(did)
	if d.state != store.DeliveryFailed || *d.lastCode != 301 || !strings.Contains(d.lastError, "redirect") {
		t.Errorf("delivery %+v", d)
	}
	if target.hits.Load() != 0 {
		t.Error("the redirect was followed")
	}
	if testutilCount(t, h.s.results.WithLabelValues("301")) != 1 {
		t.Error("result 301 not counted")
	}
}

// A handler slower than the timeout: the attempt ends at the timeout and
// is a failure (the default timeout is 2 s; the test uses 100 ms).
func TestSendTimeout(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Timeout = 100 * time.Millisecond })
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		case <-time.After(3 * time.Second):
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(func() { close(release); srv.Close() })
	h.subscribe("S1", srv.URL+"/hook", subscription.Active)
	did := h.queueChange(t, "S1", 1, time.Now())
	start := time.Now()
	h.send(t)
	if took := time.Since(start); took > time.Second {
		t.Errorf("attempt took %s", took)
	}
	d := h.st.delivery(did)
	if d.state != store.DeliveryFailed || d.lastCode != nil || !strings.Contains(d.lastError, "no answer within 100ms") {
		t.Errorf("delivery %+v", d)
	}
	if testutilCount(t, h.s.results.WithLabelValues("timeout")) != 1 {
		t.Error("timeout not counted")
	}
	if def := newHarness(t, nil); def.s.cfg.Timeout != 2*time.Second || def.s.client.Timeout != 2*time.Second {
		t.Errorf("default timeout %s", def.s.cfg.Timeout)
	}
}

// A callback whose name resolves to a private address is refused at
// dial and counted ssrf_refused; the server is never reached. The twin
// with private callbacks allowed (the lab) is delivered (E-01).
func TestSendSSRFRefusedAtDial(t *testing.T) {
	r := newReceiver(t, http.StatusOK)
	// localhost resolves to a loopback address; the URL's shape is fine.
	cb := strings.Replace(r.url(), "127.0.0.1", "localhost", 1)

	h := newHarness(t, func(c *Config) { c.Policy = subscription.URLPolicy{AllowInsecure: true} })
	h.subscribe("S1", cb, subscription.Active)
	did := h.queueChange(t, "S1", 1, time.Now())
	h.send(t)
	d := h.st.delivery(did)
	if d.state != store.DeliveryFailed || !strings.Contains(d.lastError, "refused at dial") || !strings.Contains(d.lastError, "not a public address") {
		t.Errorf("delivery %+v", d)
	}
	if r.hits.Load() != 0 {
		t.Error("the private server was reached")
	}
	if h.counter(CounterSSRFRefused) != 1 || testutilCount(t, h.s.results.WithLabelValues("ssrf_refused")) != 1 {
		t.Error("ssrf_refused not counted")
	}

	lab := newHarness(t, nil)
	lab.subscribe("S1", cb, subscription.Active)
	did = lab.queueChange(t, "S1", 1, time.Now())
	lab.send(t)
	if d := lab.st.delivery(did); d.state != store.DeliveryDelivered {
		t.Errorf("lab delivery %+v", d)
	}
	if r.hits.Load() != 1 || lab.counter(CounterSSRFRefused) != 0 {
		t.Error("lab twin")
	}
}

// A URL whose shape is refused at send time is a failure, never a dial.
func TestSendRefusesAMalformedCallback(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Policy = subscription.URLPolicy{AllowPrivate: true} })
	r := newReceiver(t, http.StatusOK)
	h.subscribe("S1", r.url(), subscription.Active) // http without AllowInsecure
	did := h.queueChange(t, "S1", 1, time.Now())
	h.send(t)
	if d := h.st.delivery(did); d.state != store.DeliveryFailed || !strings.Contains(d.lastError, "must be https") || r.hits.Load() != 0 {
		t.Errorf("delivery %+v", d)
	}
}

// A 1 MiB answer: at most 1 KiB of it is read.
func TestSendReadsAtMost1KiB(t *testing.T) {
	h := newHarness(t, nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bytes.Repeat([]byte("x"), 1<<20))
	}))
	t.Cleanup(srv.Close)
	counting := &countingTransport{base: h.s.client.Transport}
	h.s.client.Transport = counting
	h.subscribe("S1", srv.URL+"/hook", subscription.Active)
	did := h.queueChange(t, "S1", 1, time.Now())
	h.send(t)
	if d := h.st.delivery(did); d.state != store.DeliveryDelivered {
		t.Errorf("delivery %+v", d)
	}
	if n := counting.read.Load(); n > DefaultMaxResponseBytes || n == 0 {
		t.Errorf("read %d bytes of a 1 MiB answer, want 1..%d", n, DefaultMaxResponseBytes)
	}
}

type countingTransport struct {
	base http.RoundTripper
	read atomic.Int64
}

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := c.base.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	resp.Body = &countingBody{ReadCloser: resp.Body, n: &c.read}
	return resp, nil
}

type countingBody struct {
	io.ReadCloser
	n *atomic.Int64
}

func (b *countingBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.n.Add(int64(n))
	return n, err
}

// The verification ping: a subscription_test record of the first
// dataset at its current version, msg_id the delivery id; a 2xx
// activates the pending subscription; a 500 leaves it pending with the
// error on the delivery (E-01).
func TestPingActivates(t *testing.T) {
	h := newHarness(t, nil)
	ok := newReceiver(t, http.StatusNoContent)
	bad := newReceiver(t, http.StatusInternalServerError)
	h.subscribe("S-OK", ok.url(), subscription.PendingVerification, publication.DatasetRestrictions, publication.DatasetZones)
	h.subscribe("S-BAD", bad.url(), subscription.PendingVerification)
	h.st.versions[publication.DatasetRestrictions] = 4
	at := time.Now().UTC()
	p1 := h.st.addPing("S-OK", at)
	p2 := h.st.addPing("S-BAD", at)
	h.send(t)
	if s := h.st.sub("S-OK"); s.Status != subscription.Active || s.VerifiedAt == nil {
		t.Errorf("ok subscription %+v", s)
	}
	if s := h.st.sub("S-BAD"); s.Status != subscription.PendingVerification {
		t.Errorf("bad subscription %s", s.Status)
	}
	if d := h.st.delivery(p2); d.lastError != "status 500" || d.state != store.DeliveryFailed {
		t.Errorf("bad ping %+v", d)
	}
	if h.st.delivery(p1).state != store.DeliveryDelivered || h.counter(CounterVerified) != 1 {
		t.Error("ok ping")
	}
	_, body, err := verifier(t, "cisp-1", h.key, "127.0.0.1").Verify(context.Background(), ok.last(t).token)
	if err != nil {
		t.Fatal(err)
	}
	var m bus.ChangeMessage
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	if m.Reason != "subscription_test" || m.MsgID != p1 || m.Dataset != "restrictions" || m.Version != 4 || m.ETag != `"restrictions:4"` ||
		len(m.FeatureIDs) != 0 || m.PullURL != "https://uspace-cisp.example.test/v1/restrictions?since_version=4" || !m.At.Equal(at.Truncate(time.Microsecond)) && !m.At.Equal(at) {
		t.Errorf("ping body %+v", m)
	}
	for _, l := range h.log.all() {
		if l.ChangeID != store.PingChangeID {
			t.Errorf("a ping logged with change %d", l.ChangeID)
		}
	}
}

// Past the 24 h window a failure expires the delivery: a state and a
// counter, never a deletion.
func TestExpiry(t *testing.T) {
	h := newHarness(t, nil)
	r := newReceiver(t, http.StatusServiceUnavailable)
	h.subscribe("S1", r.url(), subscription.Active)
	did := h.queueChange(t, "S1", 1, time.Now().Add(-25*time.Hour))
	h.send(t)
	if d := h.st.delivery(did); d.state != store.DeliveryExpired || d.nextRetry != nil {
		t.Errorf("delivery %+v", d)
	}
	if h.counter(CounterExpired) != 1 {
		t.Error("expiry not counted")
	}
	// The twin inside the window is failed and due again.
	did = h.queueChange(t, "S1", 2, time.Now().Add(-23*time.Hour))
	h.send(t)
	if d := h.st.delivery(did); d.state != store.DeliveryFailed || d.nextRetry == nil {
		t.Errorf("inside the window %+v", d)
	}
}

// 50 consecutive failures over an hour suspend an active subscription
// with the reason; 49 do not; a pending one is never suspended.
func TestSuspension(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  subscription.Status
		n       int
		suspend bool
	}{
		{"50 over two hours", subscription.Active, 50, true},
		{"49 over two hours", subscription.Active, 49, false},
		{"pending", subscription.PendingVerification, 60, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, nil)
			r := newReceiver(t, http.StatusBadGateway)
			h.subscribe("S1", r.url(), tc.status)
			h.st.failures["S1"] = store.Failed{SubscriptionStatus: tc.status, ConsecutiveFailures: tc.n, FailingSince: time.Now().Add(-2 * time.Hour)}
			h.queueChange(t, "S1", 1, time.Now())
			h.send(t)
			reason, suspended := h.st.suspended["S1"]
			if suspended != tc.suspend {
				t.Fatalf("suspended %v, want %v", suspended, tc.suspend)
			}
			if suspended && (!strings.Contains(reason, "50 consecutive failures since") || !strings.Contains(reason, "status 502")) {
				t.Errorf("reason %q", reason)
			}
			if got := h.counter(CounterSuspended); got != map[bool]uint64{true: 1, false: 0}[tc.suspend] {
				t.Errorf("suspended counter %d", got)
			}
		})
	}
}

// At most MaxInFlight attempts run at once; the rest wait their turn
// (E-10). A slow subscriber holds only its own slots.
func TestInFlightBound(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.MaxInFlight = 2 })
	release := make(chan struct{})
	arrived := make(chan struct{}, 8)
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrived <- struct{}{}
		select {
		case <-release:
		case <-r.Context().Done():
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(slow.Close)
	h.subscribe("S1", slow.URL+"/hook", subscription.Active)
	for i := int64(1); i <= 5; i++ {
		h.queueChange(t, "S1", i, time.Now())
	}
	n, err := h.s.Dispatch(context.Background())
	if err != nil || n != 2 {
		t.Fatalf("claimed %d %v, want 2", n, err)
	}
	<-arrived
	<-arrived
	if got := h.s.InFlight(); got != 2 {
		t.Errorf("in flight %d", got)
	}
	if n, _ := h.s.Dispatch(context.Background()); n != 0 {
		t.Errorf("claimed %d past the bound", n)
	}
	h.s.Probe(context.Background())
	if g := h.status.Component(Component).Gauge(GaugeInFlight, "").Value(); g != 2 {
		t.Errorf("in-flight gauge %v", g)
	}
	close(release)
	h.s.Wait()
	if n1, n2 := h.send(t), h.send(t); n1 != 2 || n2 != 1 {
		t.Errorf("then claimed %d and %d, want 2 and 1", n1, n2)
	}
}

// The status line's summary: the healthy reading, then the store gone
// (degraded, the queue unknown), then back (E-02).
func TestProbeSummary(t *testing.T) {
	h := newHarness(t, nil)
	h.s.Probe(context.Background())
	comp := h.status.Component(Component)
	if got := summaryOf(t, h); got != "0 queued, 0 due, oldest due 0 s, 0 in flight, broker connected" {
		t.Errorf("healthy summary %q", got)
	}
	if comp.DegradedReason() != "" {
		t.Error("healthy probe degraded")
	}
	h.st.err = errDown
	h.s.Probe(context.Background())
	if !strings.Contains(comp.DegradedReason(), "queue not read") || !strings.Contains(summaryOf(t, h), "queue unknown") {
		t.Errorf("down: %q %q", comp.DegradedReason(), summaryOf(t, h))
	}
	h.st.err = nil
	h.subscribe("S1", "https://ussp.example.ge/hook", subscription.Active)
	h.queueChange(t, "S1", 1, time.Now())
	h.s.Probe(context.Background())
	if comp.DegradedReason() != "" || !strings.HasPrefix(summaryOf(t, h), "1 queued, 1 due") {
		t.Errorf("back: %q %q", comp.DegradedReason(), summaryOf(t, h))
	}
}

func summaryOf(t *testing.T, h *harness) string {
	t.Helper()
	var buf bytes.Buffer
	h.status.Log(context.Background(), slogJSON(&buf), time.Now())
	var line map[string]any
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
		t.Fatal(err)
	}
	d, _ := line[Component].(map[string]any)
	s, _ := d["summary"].(string)
	return s
}

// A sign failure and a record failure are counted, never silent.
func TestSignAndRecordFailures(t *testing.T) {
	h := newHarness(t, nil)
	r := newReceiver(t, http.StatusOK)
	h.subscribe("S1", r.url(), subscription.Active)
	h.queueChange(t, "S1", 1, time.Now())
	h.s.signer = failingSigner{}
	h.send(t)
	if h.counter(CounterSignFailed) != 1 || r.hits.Load() != 0 {
		t.Error("sign failure")
	}
	h.s.signer = h.ring
	h.log.err = errDown
	h.st.mu.Lock()
	for _, d := range h.st.deliveries {
		past := time.Now().Add(-time.Second)
		d.nextRetry = &past
	}
	h.st.mu.Unlock()
	h.send(t)
	if h.counter(CounterLogWriteFailed) != 1 {
		t.Error("log write failure not counted")
	}
}

type failingSigner struct{}

func (failingSigner) SignCompact(coreauth.CompactClaims, json.RawMessage, time.Time) (string, error) {
	return "", errDown
}

func TestNewRefusesIncompleteConfig(t *testing.T) {
	ring, _ := keyRing(t, "k")
	st := newFakeStore()
	for _, cfg := range []Config{
		{IssuerURL: testIssuer, PublicBaseURL: testIssuer},
		{Instance: "bad instance", IssuerURL: testIssuer, PublicBaseURL: testIssuer},
		{Instance: "d1", PublicBaseURL: testIssuer},
		{Instance: "d1", IssuerURL: testIssuer, PublicBaseURL: testIssuer, Timeout: time.Minute, Lease: time.Second},
	} {
		if _, err := New(cfg, st, nil, ring, Options{}); err == nil {
			t.Errorf("accepted %+v", cfg)
		}
	}
	if _, err := New(Config{Instance: "d1", IssuerURL: testIssuer, PublicBaseURL: testIssuer}, nil, nil, ring, Options{}); err == nil {
		t.Error("accepted no store")
	}
	if _, err := New(Config{Instance: "d1", IssuerURL: testIssuer, PublicBaseURL: testIssuer}, st, nil, ring, Options{}); err != nil {
		t.Errorf("refused a complete config: %v", err)
	}
}

// RunSender sends what is due and, stopped, waits for the attempts in
// flight before it returns.
func TestRunSenderDrains(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.PollInterval = 10 * time.Millisecond })
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		started <- struct{}{}
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	h.subscribe("S1", srv.URL+"/hook", subscription.Active)
	did := h.queueChange(t, "S1", 1, time.Now())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.s.RunSender(ctx); close(done) }()
	h.s.Wake()
	<-started
	cancel()
	select {
	case <-done:
		t.Fatal("returned with an attempt in flight")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	<-done
	if d := h.st.delivery(did); d.state != store.DeliveryDelivered {
		t.Errorf("in-flight attempt lost: %+v", d)
	}
}
