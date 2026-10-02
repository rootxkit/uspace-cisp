package subscription

import (
	"math"
	"math/rand/v2"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/geodesy"

	"github.com/rootxkit/uspace-cisp/internal/publication"
)

// Status is the state of a subscription (docs/PLAN.md section 5.1).
type Status string

// The states. A new subscription is PendingVerification until deliver
// receives a 2xx from its callback; Suspended after
// MaxConsecutiveFailures over SuspendAfter; Deleted is a soft delete.
const (
	PendingVerification Status = "pending_verification"
	Active              Status = "active"
	Suspended           Status = "suspended"
	Deleted             Status = "deleted"
)

// Valid reports whether st is one of the four states.
func (st Status) Valid() bool {
	switch st {
	case PendingVerification, Active, Suspended, Deleted:
		return true
	}
	return false
}

// Receives reports whether a subscription in st is sent notifications:
// active and pending ones are (a pending one is how its callback proves
// itself); suspended and deleted ones are not.
func (st Status) Receives() bool { return st == Active || st == PendingVerification }

// Subscription is one registration of a callback for some datasets,
// optionally within a box.
type Subscription struct {
	ID, ClientID, CallbackURL string
	Datasets                  []publication.Dataset
	// BBox, when set, limits the subscription to changes whose box
	// intersects it; nil is the whole of each dataset.
	BBox   *geodesy.BBox
	Status Status
}

// The suspension rule (docs/PLAN.md section 6.5).
const (
	// MaxConsecutiveFailures is how many failed attempts in a row, with
	// no success between, make a subscription a candidate for suspension.
	MaxConsecutiveFailures = 50
	// SuspendAfter is how long it must have been failing as well.
	SuspendAfter = time.Hour
)

// ShouldSuspend reports whether an active subscription that has failed
// consecutiveFailures times in a row since failingSince is suspended at
// now: at least MaxConsecutiveFailures failures over at least
// SuspendAfter. A burst of failures in a minute suspends nothing, and
// neither does an hour of rare failures.
func ShouldSuspend(consecutiveFailures int, failingSince, now time.Time) bool {
	return consecutiveFailures >= MaxConsecutiveFailures && !failingSince.IsZero() && now.Sub(failingSince) >= SuspendAfter
}

// Limits of a subscription (docs/PLAN.md sections 6.5 and 8.1).
const (
	// MaxHostLen is the longest host name accepted (RFC 1035 section 2.3.4).
	MaxHostLen = 253
	// MaxCallbackURLLen bounds a callback URL as stored and as sent.
	MaxCallbackURLLen = 2048
	// DefaultMaxPerClient is CISP_MAX_SUBSCRIPTIONS_PER_CLIENT's default.
	DefaultMaxPerClient = 20
)

// URLPolicy is what callback URLs may name.
type URLPolicy struct {
	// AllowPrivate (CISP_ALLOW_PRIVATE_CALLBACKS, the lab) lets a callback
	// be a literal IP, a localhost, .local, .internal or .localhost name,
	// and resolve to a loopback, private, link-local, CGNAT or other
	// non-public address.
	AllowPrivate bool
	// AllowInsecure (CISP_ALLOW_INSECURE_CALLBACKS) lets a callback to
	// localhost or a loopback literal use plain http.
	AllowInsecure bool
}

// Field names of the refusals.
const (
	fieldCallbackURL = "callback_url"
)

// privateSuffixes are the names that never leave a site: mDNS (.local),
// the reserved internal TLD and the loopback name (RFC 6761, 6762, ICANN
// .internal).
var privateSuffixes = []string{".local", ".internal", ".localhost"}

// ValidateCallbackURL judges a callback URL as written: https (plain
// http only to localhost or a loopback literal, and only with
// AllowInsecure), an absolute URL with a host and no userinfo or
// fragment, a host of at most MaxHostLen characters, no literal IP and no
// localhost, .local, .internal or .localhost name unless AllowPrivate.
// The refusal is a *core.FieldError on callback_url naming the rule.
// It resolves nothing: the dialer applies AllowedAddress to the address
// it connects to.
func ValidateCallbackURL(raw string, pol URLPolicy) error {
	if raw == "" {
		return core.Fieldf(fieldCallbackURL, "missing")
	}
	if len(raw) > MaxCallbackURLLen {
		return core.Fieldf(fieldCallbackURL, "longer than %d characters", MaxCallbackURLLen)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return core.Fieldf(fieldCallbackURL, "not a URL")
	}
	if !u.IsAbs() || u.Opaque != "" {
		return core.Fieldf(fieldCallbackURL, "not an absolute URL")
	}
	if u.User != nil {
		return core.Fieldf(fieldCallbackURL, "carries userinfo; credentials never travel in a callback URL")
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return core.Fieldf(fieldCallbackURL, "carries a fragment")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return core.Fieldf(fieldCallbackURL, "has no host")
	}
	if len(host) > MaxHostLen {
		return core.Fieldf(fieldCallbackURL, "host is longer than %d characters", MaxHostLen)
	}
	if p := u.Port(); p != "" {
		if n, ok := portNumber(p); !ok || n == 0 {
			return core.Fieldf(fieldCallbackURL, "port %q is not 1..65535", p)
		}
	}
	addr, literal := literalIP(host)
	loopbackName := host == "localhost" || (literal && addr.IsLoopback())
	switch strings.ToLower(u.Scheme) {
	case "https":
	case "http":
		if !pol.AllowInsecure || !loopbackName {
			return core.Fieldf(fieldCallbackURL, "must be https (plain http only to localhost, and only with CISP_ALLOW_INSECURE_CALLBACKS)")
		}
	default:
		return core.Fieldf(fieldCallbackURL, "scheme %q is not https", u.Scheme)
	}
	if pol.AllowPrivate {
		return nil
	}
	if literal {
		return core.Fieldf(fieldCallbackURL, "a literal IP address is not accepted; register a host name (CISP_ALLOW_PRIVATE_CALLBACKS allows it in the lab)")
	}
	if host == "localhost" || strings.TrimSuffix(host, ".") == "localhost" {
		return core.Fieldf(fieldCallbackURL, "localhost is not accepted (CISP_ALLOW_PRIVATE_CALLBACKS allows it in the lab)")
	}
	name := strings.TrimSuffix(host, ".")
	for _, s := range privateSuffixes {
		if strings.HasSuffix(name, s) {
			return core.Fieldf(fieldCallbackURL, "a %s name is not public (CISP_ALLOW_PRIVATE_CALLBACKS allows it in the lab)", s)
		}
	}
	if !strings.Contains(name, ".") {
		return core.Fieldf(fieldCallbackURL, "%q is not a fully qualified host name", name)
	}
	return nil
}

func portNumber(p string) (int, bool) {
	n := 0
	for _, r := range p {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int(r-'0')
		if n > 65535 {
			return 0, false
		}
	}
	return n, true
}

// literalIP parses host as an IP literal (url.Hostname strips the IPv6
// brackets); a zone is never accepted as public.
func literalIP(host string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return a, true
}

// cgnat is the shared address space of RFC 6598.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// nonPublic are further ranges no subscriber is reached on: "this
// network" (RFC 791), the IETF protocol assignments (RFC 6890), the
// documentation and benchmarking ranges (RFC 5737, 2544, 3849), 6to4
// relay anycast and the reserved block (RFC 1112), and the IPv6
// discard and NAT64 local-use prefixes (RFC 6666, 8215).
var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
}

// AllowedAddress reports whether a callback may be reached at ip: never
// at a loopback, private (RFC 1918, IPv6 ULA), link-local, multicast,
// unspecified, CGNAT (100.64.0.0/10) or other non-public address, unless
// AllowPrivate. An IPv4-mapped IPv6 address is judged as its IPv4
// address, so ::ffff:127.0.0.1 is loopback. A nil or malformed address
// is refused.
func AllowedAddress(ip net.IP, pol URLPolicy) bool {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	if pol.AllowPrivate {
		return true
	}
	a = a.Unmap()
	switch {
	case a.IsLoopback(), a.IsPrivate(), a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast(),
		a.IsInterfaceLocalMulticast(), a.IsMulticast(), a.IsUnspecified(), cgnat.Contains(a):
		return false
	}
	if a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return false
	}
	for _, p := range nonPublic {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// Matches reports whether change c is sent to subscription s: its
// dataset is one of s's, and either side has no box (the whole dataset)
// or the two boxes intersect. A box that touches the other's edge
// intersects: the box is a prefilter and is kept conservative (a
// notification is a hint, D7). A box across the antimeridian is never
// produced (ed318.Parse refuses one) and is treated as the whole world.
func Matches(s Subscription, c publication.Change) bool {
	found := false
	for _, d := range s.Datasets {
		if d == c.Dataset {
			found = true
			break
		}
	}
	if !found {
		return false
	}
	if c.BBox == nil || s.BBox == nil {
		return true
	}
	return intersects(*s.BBox, *c.BBox)
}

func intersects(a, b geodesy.BBox) bool {
	if a.MinLon > a.MaxLon || b.MinLon > b.MaxLon {
		return true // across the antimeridian: conservative
	}
	return a.MinLon <= b.MaxLon && b.MinLon <= a.MaxLon && a.MinLat <= b.MaxLat && b.MinLat <= a.MaxLat
}

// Retry is the retry schedule of a delivery: the first retry Base after
// the first failure, doubling to at most Max, for Window after the
// change (docs/PLAN.md section 6.5; spec 02 F3: 24 h).
type Retry struct{ Base, Max, Window time.Duration }

// DefaultRetry is 1 s doubling to 300 s, for 24 h.
var DefaultRetry = Retry{Base: time.Second, Max: 300 * time.Second, Window: 24 * time.Hour}

// Jitter is the spread of each delay either way (±10 %), so that the
// deliveries one outage failed together do not retry together.
const Jitter = 0.10

// jitter is the random factor in [1-Jitter, 1+Jitter]; a variable so a
// test can pin it.
var jitter = func() float64 { return 1 + Jitter*(2*rand.Float64()-1) } //nolint:gosec // G404: retry spread, not a secret

// Delay is the nominal delay after the attempt-th failed attempt (1-based):
// Base, 2 Base, 4 Base ... at most Max. A non-positive attempt is the
// first.
func (r Retry) Delay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	base, maxD := r.Base, r.Max
	if base <= 0 {
		base = DefaultRetry.Base
	}
	if maxD < base {
		maxD = base
	}
	// 2^62 ns is far past any Max; stop doubling before it overflows.
	exp := min(attempt-1, 62)
	d := float64(base) * math.Pow(2, float64(exp))
	if d >= float64(maxD) {
		return maxD
	}
	return time.Duration(d)
}

// NextAttempt is when to try again after the attempt-th failed attempt
// at now: now plus Delay(attempt) with ±10 % jitter. It is false once now
// is past changeAt + Window: the delivery then expires (a state, never a
// deletion). The time it returns may lie past the window; the attempt
// then made is the last.
func NextAttempt(attempt int, changeAt, now time.Time, r Retry) (time.Time, bool) {
	window := r.Window
	if window <= 0 {
		window = DefaultRetry.Window
	}
	if now.After(changeAt.Add(window)) {
		return time.Time{}, false
	}
	d := time.Duration(float64(r.Delay(attempt)) * jitter())
	return now.Add(d), true
}
