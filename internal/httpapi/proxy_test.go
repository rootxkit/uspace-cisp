package httpapi

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-cisp/internal/obs"
)

// loginRig is the console login limiter (20 per 15 minutes) in front of
// a handler that answers 401, reached through a BFF at bffPeer that
// writes the browser's address into X-Forwarded-For.
func loginRig(trusted []netip.Prefix) (*RateLimiter, func(browser string) int) {
	l := NewRateLimiter(RateLimiterConfig{Burst: LoginBurst, Window: LoginWindow, TrustedProxies: trusted,
		Component: obs.NewStatus("api", nil, time.Now()).Component(rateLimitComponent)})
	h := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) }))
	return l, func(browser string) int {
		req := httptest.NewRequest(http.MethodPost, "/v1/console/session", http.NoBody)
		req.RemoteAddr = "172.20.0.5:41000" // the web container
		req.Header.Set(headerForwardedFor, browser)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
}

// Behind the BFF with CISP_TRUSTED_PROXY_CIDR empty every operator is
// one client: 20 failed logins from 20 browsers lock out a 21st, and
// each forwarded header the api did not believe is counted, so the
// misconfiguration shows on the status line (B2). With the BFF's
// network trusted, the 21st browser has its own bucket and nothing is
// counted (E-01).
func TestLoginLimiterBehindTheBFF(t *testing.T) {
	l, login := loginRig(nil)
	for i := range LoginBurst {
		if code := login("203.0.113." + itoa(i+1)); code != http.StatusUnauthorized {
			t.Fatalf("login %d = %d", i+1, code)
		}
	}
	if code := login("198.51.100.99"); code != http.StatusTooManyRequests {
		t.Errorf("untrusted BFF: another browser = %d, want 429 (one shared bucket)", code)
	}
	if got := l.cfg.Component.Counter(CounterRateLimitUntrustedForward, "").Value(); got != LoginBurst+1 {
		t.Errorf("untrusted X-Forwarded-For counted %d, want %d", got, LoginBurst+1)
	}

	l, login = loginRig([]netip.Prefix{netip.MustParsePrefix("172.20.0.0/16")})
	for i := range LoginBurst {
		if code := login("203.0.113." + itoa(i+1)); code != http.StatusUnauthorized {
			t.Fatalf("trusted login %d = %d", i+1, code)
		}
	}
	if code := login("198.51.100.99"); code != http.StatusUnauthorized {
		t.Errorf("trusted BFF: another browser = %d, want its own bucket", code)
	}
	for range LoginBurst {
		login("198.51.100.100")
	}
	if code := login("198.51.100.100"); code != http.StatusTooManyRequests {
		t.Errorf("trusted BFF: one browser past its 20 = %d", code)
	}
	if got := l.cfg.Component.Counter(CounterRateLimitUntrustedForward, "").Value(); got != 0 {
		t.Errorf("trusted forwards counted %d", got)
	}
}

// A request with no X-Forwarded-For from an untrusted peer is the normal
// case and is not counted.
func TestUntrustedForwardNotCountedWithoutHeader(t *testing.T) {
	l := NewRateLimiter(RateLimiterConfig{})
	req := httptest.NewRequest(http.MethodGet, "/public/v1/zones", http.NoBody)
	req.RemoteAddr = "198.51.100.7:1"
	l.ClientAddr(req)
	if got := l.cfg.Component.Counter(CounterRateLimitUntrustedForward, "").Value(); got != 0 {
		t.Errorf("counted %d", got)
	}
}

// An https public base URL (an edge in front) with no trusted proxy
// degrades the ratelimit_proxy component at error level, naming the
// variable; a configured CIDR, or a plain-http lab URL, is healthy.
func TestReportTrustedProxies(t *testing.T) {
	for _, c := range []struct {
		name, base string
		proxies    []netip.Prefix
		degraded   bool
	}{
		{"https edge, none trusted", "https://uspace-cisp.chikox.net", nil, true},
		{"https edge, trusted", "https://uspace-cisp.chikox.net", []netip.Prefix{netip.MustParsePrefix("172.18.0.0/16")}, false},
		{"plain http lab", "http://127.0.0.1:8080", nil, false},
	} {
		comp := obs.NewStatus("api", nil, time.Now()).Component("ratelimit_proxy")
		ReportTrustedProxies(comp, c.base, c.proxies)
		reason, _ := comp.DegradedSince()
		if (reason != "") != c.degraded {
			t.Errorf("%s: degraded %q", c.name, reason)
		}
		if c.degraded && !strings.Contains(reason, "CISP_TRUSTED_PROXY_CIDR") {
			t.Errorf("%s: reason %q does not name the variable", c.name, reason)
		}
	}
}

// IPv6 clients are limited by their /64 (S1): 10 001 addresses in one
// /64 are one client, share one bucket (the 11th full read is refused
// whichever address sends it) and evict nobody; 10 001 distinct /64s
// are 10 001 clients and the bound evicts and counts (E-10). IPv4 stays
// per address.
func TestRateLimitIPv6ByPrefix(t *testing.T) {
	l := NewRateLimiter(RateLimiterConfig{RPM: 60})
	pass := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	do := func(addr netip.Addr) int {
		req := httptest.NewRequest(http.MethodGet, "/public/v1/zones", http.NoBody)
		req.RemoteAddr = netip.AddrPortFrom(addr, 1).String()
		rec := httptest.NewRecorder()
		pass.ServeHTTP(rec, req)
		return rec.Code
	}
	in64 := func(i int) netip.Addr {
		return netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, byte(i >> 16), byte(i >> 8), byte(i)})
	}
	codes := map[int]int{}
	for i := range DefaultRateLimitClients + 1 {
		codes[do(in64(i))]++
	}
	if codes[204] != DefaultPublicBurst || l.Len() != 1 {
		t.Errorf("one /64: %v served, %d clients tracked", codes, l.Len())
	}
	if got := l.cfg.Component.Counter(CounterRateLimitEvicted, "").Value(); got != 0 {
		t.Errorf("one /64 evicted %d", got)
	}

	l = NewRateLimiter(RateLimiterConfig{RPM: 60})
	pass = l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	for i := range DefaultRateLimitClients + 1 {
		a := netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, byte(i >> 16), byte(i >> 8), byte(i), 0, 0, 0, 0, 0, 0, 0, 0, 1})
		if code := do(a); code != 204 {
			t.Fatalf("/64 %d = %d", i, code)
		}
	}
	if got := l.cfg.Component.Counter(CounterRateLimitEvicted, "").Value(); got != 1 || l.Len() != DefaultRateLimitClients {
		t.Errorf("distinct /64s: evicted %d, %d tracked", got, l.Len())
	}

	// IPv4 neighbours are separate clients.
	l = NewRateLimiter(RateLimiterConfig{RPM: 60})
	pass = l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	for i := range 20 {
		if code := do(netip.AddrFrom4([4]byte{198, 51, 100, byte(i)})); code != 204 {
			t.Errorf("IPv4 %d = %d", i, code)
		}
	}
	if l.Len() != 20 {
		t.Errorf("IPv4: %d clients", l.Len())
	}
}
