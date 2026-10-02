package stream

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	coreauth "github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-cisp/internal/authtest"
	"github.com/rootxkit/uspace-cisp/internal/bus"
	"github.com/rootxkit/uspace-cisp/internal/obs"
)

const testOrigin = "https://cisp.example.ge"

type rig struct {
	hub    *Hub
	status *obs.Status
	srv    *httptest.Server
	url    string
}

func problems(w http.ResponseWriter, status int, slug, title, detail string, fields ...*core.FieldError) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	body := map[string]any{"type": "https://schemas.uspace.ge/problems/" + slug, "title": title, "status": status, "detail": detail}
	errs := []map[string]string{}
	for _, f := range fields {
		errs = append(errs, map[string]string{"field": f.Field, "reason": f.Reason})
	}
	body["errors"] = errs
	_ = json.NewEncoder(w).Encode(body)
}

func newRig(t *testing.T, cfg Config, hcfg HandlerConfig) *rig {
	t.Helper()
	if cfg.Status == nil {
		cfg.Status = obs.NewStatus("api", nil, time.Now())
	}
	if cfg.Source == nil {
		cfg.Source = healthyParts
	}
	if hcfg.AllowedOrigins == nil {
		hcfg.AllowedOrigins = []string{testOrigin}
	}
	hcfg.Problems = problems
	hub := NewHub(cfg)
	srv := httptest.NewServer(NewHandler(hub, hcfg))
	t.Cleanup(func() {
		hub.Close()
		srv.Close()
	})
	return &rig{hub: hub, status: cfg.Status, srv: srv, url: "ws" + strings.TrimPrefix(srv.URL, "http") + "/v1/stream"}
}

func (r *rig) counter(name string) uint64 {
	return r.status.Component(Component).Counter(name, "").Value()
}

type dialOpts struct {
	origin, cookie, query string
}

func (r *rig) dial(t *testing.T, o dialOpts) (*websocket.Conn, *http.Response, error) {
	t.Helper()
	h := http.Header{}
	if o.origin != "" {
		h.Set("Origin", o.origin)
	}
	if o.cookie != "" {
		h.Set("Cookie", SessionCookie+"="+o.cookie)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, resp, err := websocket.Dial(ctx, r.url+o.query, &websocket.DialOptions{HTTPHeader: h})
	if c != nil {
		c.SetReadLimit(1 << 20)
		t.Cleanup(func() { _ = c.CloseNow() })
	}
	return c, resp, err
}

func read(t *testing.T, c *websocket.Conn) Envelope {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, data, err := c.Read(ctx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return validateFrame(t, data)
}

// readChange reads frames until a change, skipping status frames.
func readChange(t *testing.T, c *websocket.Conn) bus.ChangeMessage {
	t.Helper()
	for {
		env := read(t, c)
		if env.Schema != SchemaChange {
			continue
		}
		var m bus.ChangeMessage
		if err := json.Unmarshal(env.Body, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
}

// E-02, the healthy branch read back field by field: the first frame
// is console/status/v1, valid against the lab's envelope/v1 and
// console/status/v1, with the dataset versions, no degradation, the bus
// connected and the publisher's heartbeat.
func TestStatusOnConnectHealthy(t *testing.T) {
	r := newRig(t, Config{LiveMaxAge: 6 * time.Second}, HandlerConfig{Public: true})
	c, _, err := r.dial(t, dialOpts{origin: testOrigin})
	if err != nil {
		t.Fatal(err)
	}
	env := read(t, c)
	if env.Schema != SchemaStatus || env.Producer != DefaultProducer || env.TimeSource != "system" || env.Backlog {
		t.Errorf("envelope = %+v", env)
	}
	if !regexp.MustCompile(`^[0-7][0-9A-HJKMNP-TV-Z]{25}$`).MatchString(env.MsgID) {
		t.Errorf("msg_id %q is not a ULID", env.MsgID)
	}
	b := statusOf(t, env)
	if b.ConnectionID == "" || b.PolicyVersion != "cfg-0123456789ab" || b.StaleAfterS != 60 || b.LiveMaxAgeS != 6 || b.DroppedFrames != 0 {
		t.Errorf("status = %+v", b)
	}
	if len(b.Degraded) != 0 || b.NATS != "connected" || b.NATSSince != "" || b.ResyncSince != "" || len(b.Sources) != 0 {
		t.Errorf("healthy status names a problem: %+v", b)
	}
	if b.Datasets["zones"].Version != "7" || b.Datasets["restrictions"].Version != "3" || b.CISAgeS == nil || *b.CISAgeS != 3.5 {
		t.Errorf("datasets = %+v, cis_age_s = %v", b.Datasets, b.CISAgeS)
	}
	if len(b.Publishers) != 1 || b.Publishers[0].Stale || *b.Publishers[0].HeartbeatAgeS != 5 {
		t.Errorf("publishers = %+v", b.Publishers)
	}
	if r.hub.Len() != 1 || r.status.Component(Component).Gauge(GaugeClients, "").Value() != 1 {
		t.Errorf("clients = %d", r.hub.Len())
	}
}

// E-02, the degraded branch read back: the bus reconnecting since a
// time, the database and the bus named in degraded[] with their
// since-times, and no change; then a resync on the next status, once.
func TestStatusDegradedThenResync(t *testing.T) {
	lost := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	parts := Parts{
		PolicyVersion: "cfg-x", StaleAfterS: 60, Degraded: []string{"database", "nats"},
		DegradedSince: map[string]time.Time{"database": lost, "nats": lost},
		NATS:          bus.StateReconnecting, NATSSince: lost,
	}
	src := func(time.Time) Parts {
		mu.Lock()
		defer mu.Unlock()
		return parts
	}
	r := newRig(t, Config{Source: src}, HandlerConfig{Public: true})
	c, _, err := r.dial(t, dialOpts{})
	if err != nil {
		t.Fatal(err)
	}
	b := statusOf(t, read(t, c))
	if b.NATS != "reconnecting" || b.NATSSince != "2026-10-02T09:00:00.000Z" || strings.Join(b.Degraded, ",") != "database,nats" ||
		b.DegradedSince["nats"] != "2026-10-02T09:00:00.000Z" || b.ResyncSince != "" {
		t.Errorf("degraded status = %+v", b)
	}

	mu.Lock()
	parts = healthyParts(time.Now())
	mu.Unlock()
	r.hub.Resync(lost)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go r.hub.Run(ctx, nil) // the resync's status is sent at once
	b = statusOf(t, read(t, c))
	if b.ResyncSince != "2026-10-02T09:00:00.000Z" || b.NATS != "connected" || len(b.Degraded) != 0 {
		t.Errorf("status after the bus returned = %+v", b)
	}
	r.hub.Tick(time.Now())
	if b := statusOf(t, read(t, c)); b.ResyncSince != "" {
		t.Errorf("resync_since repeated: %+v", b)
	}
	if r.counter(CounterResyncs) != 1 {
		t.Errorf("stream_resyncs = %d", r.counter(CounterResyncs))
	}
}

// A change reaches the clients that asked for its dataset (or for all)
// and not the others; every change frame validates (E-01 pair).
func TestChangeFanOutByDataset(t *testing.T) {
	r := newRig(t, Config{}, HandlerConfig{Public: true})
	zones, _, err := r.dial(t, dialOpts{query: "?datasets=zones"})
	if err != nil {
		t.Fatal(err)
	}
	all, _, err := r.dial(t, dialOpts{})
	if err != nil {
		t.Fatal(err)
	}
	read(t, zones)
	read(t, all)
	at := time.Now().Add(-time.Second)
	r.hub.Publish(change(11, "restrictions", at), time.Now())
	r.hub.Publish(change(12, "zones", at), time.Now())
	if m := readChange(t, zones); m.MsgID != "12" || m.Dataset != "zones" {
		t.Errorf("zones client got %+v first", m)
	}
	if m := readChange(t, all); m.MsgID != "11" {
		t.Errorf("all-datasets client got %+v first", m)
	}
	if m := readChange(t, all); m.MsgID != "12" {
		t.Errorf("all-datasets client got %+v second", m)
	}
	if r.counter(CounterChanges) != 2 {
		t.Errorf("stream_changes = %d", r.counter(CounterChanges))
	}
}

func TestChangeFrameEnvelopeTimes(t *testing.T) {
	r := newRig(t, Config{}, HandlerConfig{Public: true})
	c, _, err := r.dial(t, dialOpts{})
	if err != nil {
		t.Fatal(err)
	}
	read(t, c)
	at := time.Date(2026, 10, 2, 9, 15, 3, 120_000_000, time.UTC)
	rx := at.Add(125 * time.Millisecond)
	r.hub.Publish(change(5, "zones", at), rx)
	env := read(t, c)
	if env.Schema != SchemaChange || env.TS == nil || *env.TS != "2026-10-02T09:15:03.120Z" || env.RxTS != "2026-10-02T09:15:03.245Z" ||
		env.CapturedAt != "2026-10-02T09:15:03.120Z" {
		t.Errorf("change envelope = %+v", env)
	}
}

// The Origin allow-list: a browser upgrade from another origin (or
// "null") is 403 and counted; the allowed origin, its default port
// spelt out, and a client without Origin are served (E-01).
func TestOriginAllowList(t *testing.T) {
	r := newRig(t, Config{}, HandlerConfig{Public: true, AllowedOrigins: []string{testOrigin, "http://localhost:3000"}})
	for _, o := range []string{"https://evil.example", "null", "https://cisp.example.ge.evil.example", "https://cisp.example.ge:8443"} {
		_, resp, err := r.dial(t, dialOpts{origin: o})
		if err == nil || resp == nil || resp.StatusCode != http.StatusForbidden {
			t.Errorf("origin %q: err %v, resp %v", o, err, resp)
			continue
		}
		if ct := resp.Header.Get("Content-Type"); ct != "application/problem+json" {
			t.Errorf("origin %q refusal is %s", o, ct)
		}
	}
	if got := r.counter(CounterRefusedOrigin); got != 4 {
		t.Errorf("stream_refused_origin = %d", got)
	}
	for _, o := range []string{testOrigin, "HTTPS://CISP.example.ge:443", "http://localhost:3000", ""} {
		c, _, err := r.dial(t, dialOpts{origin: o})
		if err != nil {
			t.Errorf("origin %q refused: %v", o, err)
			continue
		}
		if env := read(t, c); env.Schema != SchemaStatus {
			t.Errorf("origin %q: first frame %s", o, env.Schema)
		}
	}
}

// A request that is not an upgrade is 426, an unknown dataset 400
// naming datasets; the same upgrade with a known dataset is served.
func TestUpgradeRefusals(t *testing.T) {
	r := newRig(t, Config{}, HandlerConfig{Public: true})
	resp, err := http.Get(r.srv.URL + "/v1/stream")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUpgradeRequired || resp.Header.Get("Upgrade") != "websocket" {
		t.Errorf("plain GET = %d", resp.StatusCode)
	}
	for _, q := range []string{"?datasets=zones,parcels", "?datasets=" + strings.Repeat("zones,", 60)} {
		_, resp, err := r.dial(t, dialOpts{query: q})
		if err == nil || resp == nil || resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: %v %v", q, err, resp)
		}
	}
	if r.counter(CounterRefusedRequest) != 3 {
		t.Errorf("stream_refused_request = %d", r.counter(CounterRefusedRequest))
	}
	if _, _, err := r.dial(t, dialOpts{query: "?datasets=zones,%20uspace_airspace"}); err != nil {
		t.Errorf("known datasets refused: %v", err)
	}
}

func TestParseDatasets(t *testing.T) {
	if m, fe := ParseDatasets(""); m != nil || fe != nil {
		t.Errorf("empty = %v %v", m, fe)
	}
	m, fe := ParseDatasets("zones,restrictions,zones")
	if fe != nil || len(m) != 2 || !m["zones"] || !m["restrictions"] {
		t.Errorf("= %v %v", m, fe)
	}
	if _, fe := ParseDatasets("zones,"); fe == nil || fe.Field != "datasets" {
		t.Errorf("trailing comma accepted: %v", fe)
	}
}

// The client bound (E-10): MaxClients are served, the next is 503 with
// Retry-After and counted; once one leaves, a new one is served.
func TestClientBound(t *testing.T) {
	r := newRig(t, Config{MaxClients: 3}, HandlerConfig{Public: true})
	var conns []*websocket.Conn
	for range 3 {
		c, _, err := r.dial(t, dialOpts{})
		if err != nil {
			t.Fatal(err)
		}
		read(t, c)
		conns = append(conns, c)
	}
	_, resp, err := r.dial(t, dialOpts{})
	if err == nil || resp == nil || resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("the 4th client: %v %v", err, resp)
	}
	if r.counter(CounterRefusedCapacity) != 1 {
		t.Errorf("stream_refused_capacity = %d", r.counter(CounterRefusedCapacity))
	}
	_ = conns[0].Close(websocket.StatusNormalClosure, "")
	waitFor(t, "the hub to see the client go", func() bool { return r.hub.Len() == 2 })
	c, _, err := r.dial(t, dialOpts{})
	if err != nil {
		t.Fatalf("a client after one left: %v", err)
	}
	read(t, c)
}

// The brief's bound at its default: 1 000 clients each receive one
// change, and the 1 001st upgrade is refused 503 (fan-out order
// irrelevant). The clients are the hub's own connections (a fake
// transport), so the test needs no 2 000 sockets.
func TestThousandClientsAndTheNext(t *testing.T) {
	st := obs.NewStatus("api", nil, time.Now())
	hub := NewHub(Config{Status: st, Source: healthyParts})
	defer hub.Close()
	conns := make([]*fakeConn, DefaultMaxClients)
	for i := range conns {
		if !hub.reserve() {
			t.Fatalf("client %d refused", i)
		}
		conns[i] = newFakeConn()
		hub.attach(conns[i], nil, false, nil)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/stream", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	NewHandler(hub, HandlerConfig{Public: true, Problems: problems}).ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("the 1 001st = %d", rec.Code)
	}
	hub.Publish(change(1, "zones", time.Now()), time.Now())
	waitFor(t, "every client to get the change", func() bool {
		for _, c := range conns {
			if c.count() < 2 {
				return false
			}
		}
		return true
	})
	for i, c := range conns {
		if env := validateFrame(t, c.frame(1)); env.Schema != SchemaChange {
			t.Fatalf("client %d second frame is %s", i, env.Schema)
		}
	}
}

// A client that stops reading: its queue fills, frames are dropped
// (dropped_frames), and at the next status tick it is closed with 1013
// and counted; a client that keeps up beside it is untouched (E-01).
func TestSlowClientClosedWith1013(t *testing.T) {
	st := obs.NewStatus("api", nil, time.Now())
	hub := NewHub(Config{Status: st, Source: healthyParts, SendBuffer: 4, WriteTimeout: time.Minute})
	defer hub.Close()
	slow, fast := newFakeConn(), newFakeConn()
	slow.block = make(chan struct{})
	defer close(slow.block)
	for _, c := range []*fakeConn{slow, fast} {
		hub.reserve()
		hub.attach(c, nil, false, nil)
	}
	// Paced: each publish waits for the fast client to write it, so the
	// fast client's buffer (4) never holds more than one frame and only
	// the slow client, whose writer is blocked, overflows. A burst of
	// more publishes than SendBuffer could overflow the fast client too.
	for i := range 10 {
		hub.Publish(change(int64(i+1), "zones", time.Now()), time.Now())
		want := i + 2 // the status frame on attach, then i+1 changes
		waitFor(t, "the fast client to drain", func() bool { return fast.count() == want })
	}
	waitFor(t, "the fast client's frames", func() bool { return fast.count() == 11 })
	if st.Component(Component).Counter(CounterFramesDropped, "").Value() == 0 {
		t.Fatal("no frame dropped for the slow client")
	}
	hub.Tick(time.Now())
	select {
	case code := <-slow.closed:
		if code != CloseTryAgainLater {
			t.Errorf("slow client closed with %d, want 1013", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the slow client was not closed")
	}
	select {
	case code := <-fast.closed:
		t.Errorf("the client that kept up was closed with %d", code)
	default:
	}
	if got := st.Component(Component).Counter(CounterClientsDropped, "").Value(); got != 1 {
		t.Errorf("stream_clients_dropped = %d", got)
	}
	if hub.Len() != 1 {
		t.Errorf("clients = %d", hub.Len())
	}
	waitFor(t, "the fast client's status", func() bool { return fast.count() == 12 })
	if b := statusOf(t, validateFrame(t, fast.frame(11))); b.DroppedFrames != 0 {
		t.Errorf("the fast client's dropped_frames = %d", b.DroppedFrames)
	}
}

// A client that missed frames but drains before the tick stays, and its
// status says how many it missed.
func TestDroppedFramesVisible(t *testing.T) {
	st := obs.NewStatus("api", nil, time.Now())
	hub := NewHub(Config{Status: st, Source: healthyParts, SendBuffer: 2, WriteTimeout: time.Minute})
	defer hub.Close()
	c := newFakeConn()
	c.block = make(chan struct{})
	hub.reserve()
	hub.attach(c, nil, false, nil)
	for i := range 6 {
		hub.Publish(change(int64(i+1), "zones", time.Now()), time.Now())
	}
	close(c.block)
	c.mu.Lock()
	c.block = nil
	c.mu.Unlock()
	waitFor(t, "the queue to drain", func() bool { return len(firstClient(hub).send) == 0 })
	hub.Tick(time.Now())
	waitFor(t, "the status", func() bool {
		n := c.count()
		return n > 0 && validateFrame(t, c.frame(n-1)).Schema == SchemaStatus
	})
	b := statusOf(t, validateFrame(t, c.frame(c.count()-1)))
	if b.DroppedFrames == 0 || hub.Len() != 1 {
		t.Errorf("dropped_frames = %d, clients = %d", b.DroppedFrames, hub.Len())
	}
}

func firstClient(h *Hub) *client {
	for _, c := range h.snapshot() {
		return c
	}
	return nil
}

// A write that fails ends the client.
func TestWriteFailureDetaches(t *testing.T) {
	hub := NewHub(Config{Source: healthyParts})
	defer hub.Close()
	c := newFakeConn()
	c.fail = errors.New("connection reset")
	hub.reserve()
	hub.attach(c, nil, false, nil)
	waitFor(t, "the client to go", func() bool { return hub.Len() == 0 })
}

// Close ends every client with 1001 and refuses the next.
func TestCloseGoingAway(t *testing.T) {
	r := newRig(t, Config{}, HandlerConfig{Public: true})
	c, _, err := r.dial(t, dialOpts{})
	if err != nil {
		t.Fatal(err)
	}
	read(t, c)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.hub.Run(ctx, nil); close(done) }()
	cancel()
	<-done
	rctx, rcancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer rcancel()
	_, _, err = c.Read(rctx)
	if websocket.CloseStatus(err) != CloseGoingAway {
		t.Errorf("close = %v", err)
	}
	if r.hub.reserve() {
		t.Error("a closed hub took a client")
	}
}

// --- sessions -----------------------------------------------------------------

const sessionIssuer = "https://cisp.example.ge/console"

type sessions struct {
	issuer   *coreauth.Issuer
	verifier ClaimsSessions
}

func newSessions(t *testing.T) sessions {
	t.Helper()
	iss, err := coreauth.NewIssuer(sessionIssuer, authtest.Key(t, "stream-session", 2048), "s1")
	if err != nil {
		t.Fatal(err)
	}
	v, err := coreauth.NewVerifier(context.Background(), coreauth.Config{
		Issuers: map[string]coreauth.IssuerConfig{sessionIssuer: {Keys: iss.JWKS()}}, Audience: "cisp.example.ge", StrictSessionClaims: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return sessions{issuer: iss, verifier: ClaimsSessions{Verifier: v}}
}

func (s sessions) token(t *testing.T, realm string) string {
	t.Helper()
	now := time.Now()
	tok, err := s.issuer.IssueSession(coreauth.SessionClaims{
		Audience: "cisp.example.ge", Subject: "acc-1", Roles: []string{"viewer"}, Realm: realm,
		IssuedAt: now, ExpiresAt: now.Add(time.Hour), JTI: NewULID(now),
	})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func closeCode(t *testing.T, c *websocket.Conn) websocket.StatusCode {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		_, _, err := c.Read(ctx)
		if err != nil {
			return websocket.CloseStatus(err)
		}
	}
}

// A non-public stream: no cookie and an invalid one are closed with
// 4401 and counted; a valid console session is served (E-01).
func TestNonPublicSessions(t *testing.T) {
	s := newSessions(t)
	r := newRig(t, Config{}, HandlerConfig{Public: false, Sessions: s.verifier})
	for name, cookie := range map[string]string{"none": "", "garbage": "not-a-token", "portal realm": s.token(t, "portal")} {
		c, _, err := r.dial(t, dialOpts{origin: testOrigin, cookie: cookie})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if code := closeCode(t, c); code != CloseRelogin {
			t.Errorf("%s: close %d, want 4401", name, code)
		}
	}
	if got := r.counter(CounterSessionRefused); got != 3 {
		t.Errorf("stream_session_refused = %d", got)
	}
	c, _, err := r.dial(t, dialOpts{origin: testOrigin, cookie: s.token(t, "console")})
	if err != nil {
		t.Fatal(err)
	}
	if env := read(t, c); env.Schema != SchemaStatus {
		t.Errorf("a console session got %s", env.Schema)
	}
	if r.counter(CounterSessions) != 1 || !firstClient(r.hub).console {
		t.Errorf("stream_sessions = %d", r.counter(CounterSessions))
	}
	// A valid cookie without an Origin is not a same-origin upgrade.
	c, _, err = r.dial(t, dialOpts{cookie: s.token(t, "console")})
	if err != nil {
		t.Fatal(err)
	}
	if code := closeCode(t, c); code != CloseRelogin {
		t.Errorf("a cookie without Origin: close %d, want 4401", code)
	}
}

// A public stream serves an invalid cookie as public (counted) and
// marks a valid one as a console; the content is the same.
func TestPublicSessions(t *testing.T) {
	s := newSessions(t)
	r := newRig(t, Config{}, HandlerConfig{Public: true, Sessions: s.verifier})
	c, _, err := r.dial(t, dialOpts{origin: testOrigin, cookie: "not-a-token"})
	if err != nil {
		t.Fatal(err)
	}
	read(t, c)
	if r.counter(CounterSessionIgnored) != 1 || r.counter(CounterSessions) != 0 {
		t.Errorf("ignored = %d, sessions = %d", r.counter(CounterSessionIgnored), r.counter(CounterSessions))
	}
	c2, _, err := r.dial(t, dialOpts{origin: testOrigin, cookie: s.token(t, "console")})
	if err != nil {
		t.Fatal(err)
	}
	read(t, c2)
	if r.counter(CounterSessions) != 1 {
		t.Errorf("sessions = %d", r.counter(CounterSessions))
	}
}

func TestClaimsSessionsRefusals(t *testing.T) {
	if err := (ClaimsSessions{}).VerifySession(context.Background(), "x"); err == nil {
		t.Error("no verifier accepted a token")
	}
	s := newSessions(t)
	if err := s.verifier.VerifySession(context.Background(), s.token(t, "console")); err != nil {
		t.Errorf("console session refused: %v", err)
	}
	for _, c := range []coreauth.Claims{
		{Scopes: []string{"cis.read"}, Realm: "console", Roles: []string{"viewer"}},
		{Scopes: []string{"session"}, Realm: "console"},
	} {
		v := ClaimsSessions{Verifier: staticVerifier{c}}
		if err := v.VerifySession(context.Background(), "t"); err == nil {
			t.Errorf("%+v accepted", c)
		}
	}
}

type staticVerifier struct{ c coreauth.Claims }

func (s staticVerifier) Verify(context.Context, string) (coreauth.Claims, error) { return s.c, nil }

// --- small pieces -------------------------------------------------------------

func TestNewULID(t *testing.T) {
	re := regexp.MustCompile(`^[0-7][0-9A-HJKMNP-TV-Z]{25}$`)
	seen := map[string]bool{}
	t0 := time.Date(2026, 10, 2, 9, 15, 6, 0, time.UTC)
	for range 1000 {
		id := NewULID(t0)
		if !re.MatchString(id) || seen[id] {
			t.Fatalf("ULID %q", id)
		}
		seen[id] = true
	}
	// The time prefix sorts: a later millisecond is a larger id.
	if a, b := NewULID(t0), NewULID(t0.Add(time.Millisecond)); a[:10] >= b[:10] {
		t.Errorf("%s not before %s", a, b)
	}
	if got := NewULID(time.Unix(0, 0))[:10]; got != "0000000000" {
		t.Errorf("epoch prefix %s", got)
	}
}

func TestNormalizeOrigin(t *testing.T) {
	for in, want := range map[string]string{
		"https://CISP.example.ge":      "https://cisp.example.ge",
		"https://cisp.example.ge:443/": "https://cisp.example.ge",
		"http://localhost:3000":        "http://localhost:3000",
		"http://[::1]:8080":            "http://[::1]:8080",
		"https://cisp.example.ge:8443": "https://cisp.example.ge:8443",
		"http://cisp.example.ge:80":    "http://cisp.example.ge",
	} {
		if got, ok := NormalizeOrigin(in); !ok || got != want {
			t.Errorf("%s = %q %v, want %q", in, got, ok, want)
		}
	}
	for _, bad := range []string{"null", "", "ftp://x", "https://u@x", "https://x/path", "https://x?q=1", "x"} {
		if got, ok := NormalizeOrigin(bad); ok {
			t.Errorf("%q accepted as %q", bad, got)
		}
	}
	got := AllowedOrigins("https://cisp.example.ge/base", []string{"http://localhost:3000", "https://cisp.example.ge", "bad"})
	if strings.Join(got, " ") != "https://cisp.example.ge http://localhost:3000" {
		t.Errorf("AllowedOrigins = %v", got)
	}
}

// The lab's own CISP status example validates against the copy of the
// schema the frames are tested with (the contract is the lab's, not a
// reading of it), and so does a frame this package makes.
func TestContractCopyIsTheLabs(t *testing.T) {
	ex, err := readFile("testdata/common/console/status/v1/examples/cisp-resync.json")
	if err != nil {
		t.Fatal(err)
	}
	validateFrame(t, ex)
	// The twin that differs in one thing is refused: dropped_frames < 0.
	var m map[string]any
	_ = json.Unmarshal(ex, &m)
	m["body"].(map[string]any)["dropped_frames"] = -1
	bad, _ := json.Marshal(m)
	doc, _ := unmarshalJSON(bad)
	if err := loadContract(t).status.Validate(doc); err == nil {
		t.Error("a negative dropped_frames validates")
	}
}
