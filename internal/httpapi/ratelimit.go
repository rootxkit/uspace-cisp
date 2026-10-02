package httpapi

import (
	"container/list"
	"math"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"golang.org/x/time/rate"

	"github.com/rootxkit/uspace-cisp/internal/obs"
)

// SlugRateLimited is the problem of a request over its client's rate.
const SlugRateLimited = "rate_limited"

// Counters of the rate limiter (component ratelimit).
const (
	CounterRateLimited         = "rate_limited"
	CounterRateLimitEvicted    = "rate_limit_clients_evicted"
	CounterRateLimitBadForward = "rate_limit_forwarded_for_unreadable"
)

// Rate limiter defaults (docs/WORKPACKAGES/WP-4.md).
const (
	DefaultPublicBurst       = 10
	DefaultCheapFactor       = 10
	DefaultRateLimitClients  = 10_000
	rateLimitComponent       = "ratelimit"
	headerForwardedFor       = "X-Forwarded-For"
	minRetryAfterS           = 1
	defaultRateLimitRPMIfNil = 60
)

// RateLimiterConfig configures a RateLimiter.
type RateLimiterConfig struct {
	// RPM is the full reads a client may make a minute (CISP_PUBLIC_RPM);
	// 0 is 60.
	RPM int64
	// Burst is the full reads a client may make at once (0: 10).
	Burst int
	// Window, when set, replaces RPM: Burst requests per Window (the
	// console login: 20 per 15 minutes, WP-8).
	Window time.Duration
	// CheapFactor multiplies the rate and the burst for HEAD and for a
	// request that will be answered 304 (0: 10).
	CheapFactor int
	// MaxClients bounds the clients tracked (0: 10 000); past it the
	// least recently seen is forgotten and counted.
	MaxClients int
	// TrustedProxies are the addresses (CISP_TRUSTED_PROXY_CIDR) whose
	// X-Forwarded-For is believed; from anyone else the peer address is
	// the client.
	TrustedProxies []netip.Prefix
	// Cheap reports whether a GET will be answered 304 (Reads.NotModified);
	// nil: none is.
	Cheap func(*http.Request) bool
	// Component counts rate_limited and evictions; nil: a private one.
	Component *obs.Component
	// Now is the clock; nil is time.Now.
	Now func() time.Time
}

// RateLimiter is a token bucket per client address and class (full, or
// cheap: HEAD and 304), with a bounded, least-recently-used client map
// (E-10).
type RateLimiter struct {
	cfg               RateLimiterConfig
	full, cheap       rate.Limit
	burst, cheapBurst int

	mu      sync.Mutex
	order   *list.List // front: most recently seen; values are *bucket
	clients map[netip.Addr]*list.Element
}

type bucket struct {
	addr        netip.Addr
	full, cheap *rate.Limiter
}

// NewRateLimiter builds a limiter; zero fields take the defaults.
func NewRateLimiter(cfg RateLimiterConfig) *RateLimiter {
	if cfg.RPM <= 0 {
		cfg.RPM = defaultRateLimitRPMIfNil
	}
	if cfg.Burst <= 0 {
		cfg.Burst = DefaultPublicBurst
	}
	if cfg.CheapFactor <= 0 {
		cfg.CheapFactor = DefaultCheapFactor
	}
	if cfg.MaxClients <= 0 {
		cfg.MaxClients = DefaultRateLimitClients
	}
	if cfg.Component == nil {
		cfg.Component = obs.NewStatus("api", nil, time.Now()).Component(rateLimitComponent)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	perS := float64(cfg.RPM) / 60
	if cfg.Window > 0 {
		perS = float64(cfg.Burst) / cfg.Window.Seconds()
	}
	return &RateLimiter{
		cfg: cfg, full: rate.Limit(perS), cheap: rate.Limit(perS * float64(cfg.CheapFactor)),
		burst: cfg.Burst, cheapBurst: cfg.Burst * cfg.CheapFactor,
		order: list.New(), clients: map[netip.Addr]*list.Element{},
	}
}

// Len is the number of clients tracked.
func (l *RateLimiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.order.Len()
}

// bucketFor is addr's bucket, created (and the least recently seen
// evicted past MaxClients) when new.
func (l *RateLimiter) bucketFor(addr netip.Addr) *bucket {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e, ok := l.clients[addr]; ok {
		l.order.MoveToFront(e)
		b, _ := e.Value.(*bucket)
		return b
	}
	b := &bucket{addr: addr, full: rate.NewLimiter(l.full, l.burst), cheap: rate.NewLimiter(l.cheap, l.cheapBurst)}
	l.clients[addr] = l.order.PushFront(b)
	for l.order.Len() > l.cfg.MaxClients {
		last := l.order.Back()
		old, _ := last.Value.(*bucket)
		l.order.Remove(last)
		delete(l.clients, old.addr)
		l.cfg.Component.Counter(CounterRateLimitEvicted, "Rate-limit clients forgotten past the bound (least recently seen first).").Inc()
	}
	return b
}

// ClientAddr is the address a request is limited by: the peer address,
// or, when the peer is a trusted proxy, the rightmost X-Forwarded-For
// entry that is not itself a trusted proxy (what the proxy saw).
func (l *RateLimiter) ClientAddr(r *http.Request) netip.Addr {
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	var addr netip.Addr
	if err == nil {
		addr = peer.Addr().Unmap()
	} else if a, err := netip.ParseAddr(r.RemoteAddr); err == nil {
		addr = a.Unmap()
	}
	if !l.trusted(addr) {
		return addr
	}
	hops := r.Header.Values(headerForwardedFor)
	var entries []string
	for _, h := range hops {
		entries = append(entries, strings.Split(h, ",")...)
	}
	for i := len(entries) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(entries[i]))
		if err != nil {
			l.cfg.Component.Counter(CounterRateLimitBadForward, "X-Forwarded-For entries from a trusted proxy that are not addresses.").Inc()
			return addr
		}
		a = a.Unmap()
		if !l.trusted(a) {
			return a
		}
	}
	return addr
}

func (l *RateLimiter) trusted(a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	for _, p := range l.cfg.TrustedProxies {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Middleware takes a token from the client's bucket of the request's
// class and answers 429 rate_limited with Retry-After when there is
// none.
func (l *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := l.bucketFor(l.ClientAddr(r))
		lim := b.full
		if r.Method == http.MethodHead || (l.cfg.Cheap != nil && l.cfg.Cheap(r)) {
			lim = b.cheap
		}
		now := l.cfg.Now()
		if lim.AllowN(now, 1) {
			next.ServeHTTP(w, r)
			return
		}
		l.cfg.Component.Counter(CounterRateLimited, "Public reads refused over the per-client rate.").Inc()
		wait := (1 - lim.TokensAt(now)) / float64(lim.Limit())
		secs := max(minRetryAfterS, int(math.Ceil(wait)))
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		fe := core.Fieldf("rate", "this client may make %d full reads a minute (burst %d); retry after %d s", l.cfg.RPM, l.burst, secs)
		WriteProblem(w, http.StatusTooManyRequests, SlugRateLimited, "Too many requests", fe.Error(), fe)
	})
}
