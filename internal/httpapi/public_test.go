package httpapi

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-cisp/internal/obs"
)

// The public read: no token, the same snapshot and filters as /v1, the
// USSP list without base_url and certificate_id and unsigned,
// since_version refused.
func TestPublicRead(t *testing.T) {
	h := newPubHarness(t, nil)
	h.publishReadZones()
	if rec := h.put("ussp_list", usspListBody(t)); rec.Code != 201 {
		t.Fatal(rec.Code)
	}
	auth := h.read(http.MethodGet, "/v1/zones")
	pub := h.read(http.MethodGet, "/public/v1/zones")
	if pub.Code != 200 || !bytes.Equal(pub.Body.Bytes(), auth.Body.Bytes()) || pub.Header().Get(HeaderSignature) != auth.Header().Get(HeaderSignature) || pub.Header().Get("ETag") != `"zones:1"` {
		t.Errorf("public zones = %d", pub.Code)
	}
	if head := h.read(http.MethodHead, "/public/v1/zones"); head.Code != 200 || head.Body.Len() != 0 {
		t.Errorf("public HEAD = %d", head.Code)
	}
	if nm := h.read(http.MethodGet, "/public/v1/zones", "If-None-Match", `"zones:1"`); nm.Code != 304 {
		t.Errorf("public 304 = %d", nm.Code)
	}
	filtered := h.read(http.MethodGet, "/public/v1/zones?applies_at="+url.QueryEscape(winterMonday))
	if _, byID := collection(t, filtered); len(byID) != 3 || annotation(byID["TSP001"]) != "unknown" {
		t.Errorf("public applies_at %v", ids(byID))
	}
	list := h.read(http.MethodGet, "/public/v1/ussp_list")
	if list.Code != 200 || list.Header().Get(HeaderSignature) != "" {
		t.Fatalf("public ussp_list = %d sig %q", list.Code, list.Header().Get(HeaderSignature))
	}
	var doc struct {
		Ussps     []map[string]any `json:"ussps"`
		CISVerson int64            `json:"cis_version"`
	}
	if err := json.Unmarshal(list.Body.Bytes(), &doc); err != nil || len(doc.Ussps) == 0 || doc.CISVerson != 1 {
		t.Fatalf("%v %s", err, list.Body.String())
	}
	for _, u := range doc.Ussps {
		if _, ok := u["base_url"]; ok {
			t.Error("base_url on the public list")
		}
		if _, ok := u["certificate_id"]; ok {
			t.Error("certificate_id on the public list")
		}
		if u["ussp_id"] == nil || u["terms_url"] == nil {
			t.Errorf("a public member was dropped: %v", u)
		}
	}
	full := h.read(http.MethodGet, "/v1/ussp_list")
	if !strings.Contains(full.Body.String(), "base_url") {
		t.Error("the authenticated list lost base_url")
	}
	req := httptest.NewRequest(http.MethodGet, "/public/v1/zones?since_version=0", http.NoBody)
	rec := h.do(req)
	if p := decodeProblem(t, rec); rec.Code != 400 || !hasProblem(p, "since_version", "not served on the public read") {
		t.Errorf("public since_version = %d %s", rec.Code, rec.Body.String())
	}
	conformResponse(t, req, rec)
	if nf := h.read(http.MethodGet, "/public/v1/restrictions"); nf.Code != 404 {
		t.Errorf("public, no version = %d", nf.Code)
	}
}

func TestProjectUsspListRefusesWhatIsNotAList(t *testing.T) {
	for name, body := range map[string]string{
		"not gzip":      "plain",
		"not json":      "",
		"no ussps":      `{"schema":"cis/ussp_list/v1"}`,
		"a ussp string": `{"ussps":["x"]}`,
	} {
		raw := []byte(body)
		if name != "not gzip" {
			raw = gzipOf(t, []byte(body))
		}
		if _, err := projectUsspList(raw); err == nil {
			t.Errorf("%s: projected", name)
		}
	}
	out, err := projectUsspList(gzipOf(t, []byte(`{"ussps":[{"ussp_id":"A","base_url":"https://a","certificate_id":"C"}],"cis_version":1}`)))
	if err != nil || string(out) != `{"cis_version":1,"ussps":[{"ussp_id":"A"}]}` {
		t.Errorf("%s %v", out, err)
	}
}

func gzipOf(t testing.TB, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// limiterRig is a router whose public reads are limited at 60 a minute
// (burst 10) on a clock the test moves.
type limiterRig struct {
	h       http.Handler
	limiter *RateLimiter
	status  *obs.Status
	mu      sync.Mutex
	now     time.Time
}

func newLimiterRig(t *testing.T, cfg RateLimiterConfig, server *Server) *limiterRig {
	t.Helper()
	r := &limiterRig{status: obs.NewStatus("api", nil, time.Now()), now: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)}
	cfg.Now = func() time.Time {
		r.mu.Lock()
		defer r.mu.Unlock()
		return r.now
	}
	cfg.Component = r.status.Component(rateLimitComponent)
	r.limiter = NewRateLimiter(cfg)
	routes := openRoutes()
	for k, v := range PublicReadAuth(r.limiter) {
		routes[k] = v
	}
	r.h = mustRouter(t, server, Options{RouteMiddleware: routes})
	return r
}

func (r *limiterRig) advance(d time.Duration) {
	r.mu.Lock()
	r.now = r.now.Add(d)
	r.mu.Unlock()
}

func (r *limiterRig) do(method, target, peer string, headers ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, http.NoBody)
	req.RemoteAddr = peer
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	rec := httptest.NewRecorder()
	r.h.ServeHTTP(rec, req)
	return rec
}

func (r *limiterRig) counter(name string) uint64 {
	return r.status.Component(rateLimitComponent).Counter(name, "").Value()
}

// The full-read bucket: a burst of 10 at once, then one a second
// (CISP_PUBLIC_RPM 60); past it 429 rate_limited with Retry-After. HEAD
// and a 304 have their own bucket at ten times the rate, so a client
// over its full-read rate still reconciles.
func TestRateLimitFullReads(t *testing.T) {
	h := newPubHarness(t, nil)
	h.publishReadZones()
	r := newLimiterRig(t, RateLimiterConfig{RPM: 60, Cheap: h.reads.NotModified}, &Server{Reads: h.reads})
	const peer = "198.51.100.7:40000"
	for i := range 10 {
		if rec := r.do(http.MethodGet, "/public/v1/zones", peer); rec.Code != 200 {
			t.Fatalf("read %d = %d", i+1, rec.Code)
		}
	}
	rec := r.do(http.MethodGet, "/public/v1/zones", peer)
	if p := decodeProblem(t, rec); rec.Code != 429 || p.Type != ProblemTypeBase+SlugRateLimited || rec.Header().Get("Retry-After") != "1" {
		t.Fatalf("11th = %d %q %s", rec.Code, rec.Header().Get("Retry-After"), rec.Body.String())
	}
	conformResponse(t, httptest.NewRequest(http.MethodGet, "/public/v1/zones", http.NoBody), rec)
	if r.counter(CounterRateLimited) != 1 {
		t.Error("rate_limited not counted")
	}
	// The cheap bucket is untouched.
	if head := r.do(http.MethodHead, "/public/v1/zones", peer); head.Code != 200 {
		t.Errorf("HEAD over the full rate = %d", head.Code)
	}
	if nm := r.do(http.MethodGet, "/public/v1/zones", peer, "If-None-Match", `"zones:1"`); nm.Code != 304 {
		t.Errorf("304 over the full rate = %d", nm.Code)
	}
	// A stale If-None-Match is a full read and is refused.
	if stale := r.do(http.MethodGet, "/public/v1/zones", peer, "If-None-Match", `"zones:0"`); stale.Code != 429 {
		t.Errorf("full read behind a stale If-None-Match = %d", stale.Code)
	}
	// Another client has its own bucket.
	if other := r.do(http.MethodGet, "/public/v1/zones", "198.51.100.8:40000"); other.Code != 200 {
		t.Errorf("another client = %d", other.Code)
	}
	// A second later one more token; and one only.
	r.advance(time.Second)
	if rec := r.do(http.MethodGet, "/public/v1/zones", peer); rec.Code != 200 {
		t.Errorf("after 1 s = %d", rec.Code)
	}
	if rec := r.do(http.MethodGet, "/public/v1/zones", peer); rec.Code != 429 {
		t.Errorf("second after 1 s = %d", rec.Code)
	}
	// A new client asking three times a second for a minute gets the
	// burst, then one a second: 10 at its first second and 59 refills in
	// the 59 seconds after it.
	served := 0
	for range 60 {
		r.advance(time.Second)
		for range 3 {
			if rec := r.do(http.MethodGet, "/public/v1/zones", "203.0.113.9:1"); rec.Code == 200 {
				served++
			}
		}
	}
	if served != 10+59 {
		t.Errorf("a minute at 3 a second served %d, want 69", served)
	}
	// since_version is refused only after the bucket allowed the request.
	if rec := r.do(http.MethodGet, "/public/v1/zones?since_version=0", "192.0.2.1:1"); rec.Code != 400 {
		t.Errorf("since_version = %d", rec.Code)
	}
}

// The cheap bucket is ten times the full one: 100 HEADs at once, then
// 429; Retry-After rounds up to a whole second.
func TestRateLimitCheapReads(t *testing.T) {
	h := newPubHarness(t, nil)
	h.publishReadZones()
	r := newLimiterRig(t, RateLimiterConfig{RPM: 6}, &Server{Reads: h.reads})
	for i := range 100 {
		if rec := r.do(http.MethodHead, "/public/v1/zones", "198.51.100.7:1"); rec.Code != 200 {
			t.Fatalf("HEAD %d = %d", i+1, rec.Code)
		}
	}
	rec := r.do(http.MethodHead, "/public/v1/zones", "198.51.100.7:1")
	if rec.Code != 429 || rec.Header().Get("Retry-After") != "1" {
		t.Errorf("101st HEAD = %d %q", rec.Code, rec.Header().Get("Retry-After"))
	}
	for range 10 {
		r.do(http.MethodGet, "/public/v1/zones", "198.51.100.7:1")
	}
	full := r.do(http.MethodGet, "/public/v1/zones", "198.51.100.7:1")
	if full.Code != 429 || full.Header().Get("Retry-After") != "10" {
		t.Errorf("full at 6 a minute: %d Retry-After %q", full.Code, full.Header().Get("Retry-After"))
	}
}

// E-10: the client map is bounded; the 10 001st client evicts the least
// recently seen, which is counted, and the map stays at its bound.
func TestRateLimitClientsBounded(t *testing.T) {
	l := NewRateLimiter(RateLimiterConfig{RPM: 60})
	pass := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	for i := range DefaultRateLimitClients + 1 {
		req := httptest.NewRequest(http.MethodGet, "/public/v1/zones", http.NoBody)
		req.RemoteAddr = netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}).String() + ":1"
		rec := httptest.NewRecorder()
		pass.ServeHTTP(rec, req)
		if rec.Code != 204 {
			t.Fatalf("client %d = %d", i, rec.Code)
		}
	}
	if l.Len() != DefaultRateLimitClients {
		t.Errorf("tracks %d clients, bound %d", l.Len(), DefaultRateLimitClients)
	}
	if got := l.cfg.Component.Counter(CounterRateLimitEvicted, "").Value(); got != 1 {
		t.Errorf("evicted %d, want 1", got)
	}
	// The first client was evicted: it starts with a full bucket again.
	if _, ok := l.clients[netip.AddrFrom4([4]byte{10, 0, 0, 0})]; ok {
		t.Error("the least recently seen client is still tracked")
	}
	if _, ok := l.clients[netip.AddrFrom4([4]byte{10, 0, 39, 16})]; !ok {
		t.Error("the newest client is not tracked")
	}
}

// The client address: the peer, unless the peer is a trusted proxy;
// then the rightmost X-Forwarded-For entry that is not a trusted proxy.
// An untrusted peer's X-Forwarded-For is never believed (E-01).
func TestRateLimitClientAddress(t *testing.T) {
	l := NewRateLimiter(RateLimiterConfig{TrustedProxies: []netip.Prefix{netip.MustParsePrefix("172.18.0.0/16"), netip.MustParsePrefix("::1/128")}})
	cases := []struct {
		name, peer, xff, want string
	}{
		{"untrusted peer, forged header", "198.51.100.7:1", "203.0.113.1", "198.51.100.7"},
		{"trusted proxy", "172.18.0.5:1", "203.0.113.1", "203.0.113.1"},
		{"trusted proxy, client-supplied entries left of it", "172.18.0.5:1", "1.2.3.4, 203.0.113.1", "203.0.113.1"},
		{"two trusted hops", "172.18.0.5:1", "203.0.113.1, 172.18.0.9", "203.0.113.1"},
		{"trusted proxy, no header", "172.18.0.5:1", "", "172.18.0.5"},
		{"trusted proxy, unreadable entry", "172.18.0.5:1", "nonsense", "172.18.0.5"},
		{"only trusted entries", "172.18.0.5:1", "172.18.0.6", "172.18.0.5"},
		{"IPv6 loopback proxy", "[::1]:1", "2001:db8::7", "2001:db8::7"},
		{"IPv4-mapped peer", "[::ffff:198.51.100.7]:1", "", "198.51.100.7"},
		{"no port", "198.51.100.7", "", "198.51.100.7"},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodGet, "/public/v1/zones", http.NoBody)
		req.RemoteAddr = c.peer
		if c.xff != "" {
			req.Header.Set("X-Forwarded-For", c.xff)
		}
		if got := l.ClientAddr(req).String(); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
	if got := l.cfg.Component.Counter(CounterRateLimitBadForward, "").Value(); got != 1 {
		t.Errorf("unreadable entries counted %d", got)
	}
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.RemoteAddr = "garbage"
	if l.ClientAddr(req).IsValid() {
		t.Error("an unreadable peer gave an address")
	}
	// Every unreadable peer shares one bucket: it is limited, not let through.
	pass := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	codes := map[int]int{}
	for range 11 {
		rec := httptest.NewRecorder()
		pass.ServeHTTP(rec, req)
		codes[rec.Code]++
	}
	if codes[429] != 1 {
		t.Errorf("unreadable peers: %v", codes)
	}
}
