package subscription

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/geodesy"

	"github.com/rootxkit/uspace-cisp/internal/publication"
)

// Every class of callback URL is refused beside the acceptance that
// differs in one thing (E-01).
func TestValidateCallbackURL(t *testing.T) {
	strict := URLPolicy{}
	insecure := URLPolicy{AllowInsecure: true}
	private := URLPolicy{AllowPrivate: true}
	lab := URLPolicy{AllowPrivate: true, AllowInsecure: true}
	long := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 59) + ".ge"
	if len(long) != 254 {
		t.Fatalf("host is %d characters", len(long))
	}
	ok253 := long[1:]
	cases := []struct {
		name   string
		url    string
		pol    URLPolicy
		refuse string // "" accepts; else a phrase of the reason
	}{
		{"https", "https://ussp.example.ge/v1/cis/notifications", strict, ""},
		{"https with a port", "https://ussp.example.ge:8443/v1/cis/notifications", strict, ""},
		{"https with a query", "https://ussp.example.ge/hook?tenant=1", strict, ""},
		{"http to a public host", "http://ussp.example.ge/v1/cis/notifications", strict, "must be https"},
		{"http to a public host with AllowInsecure", "http://ussp.example.ge/v1/cis/notifications", lab, "must be https"},
		{"http to localhost without AllowInsecure", "http://localhost:8080/v1/cis/notifications", private, "must be https"},
		{"http to localhost with AllowInsecure, not private", "http://localhost:8080/v1/cis/notifications", insecure, "localhost is not accepted"},
		{"http to localhost in the lab", "http://localhost:8080/v1/cis/notifications", lab, ""},
		{"http to 127.0.0.1 in the lab", "http://127.0.0.1:8080/hook", lab, ""},
		{"http to 127.0.0.1 without AllowInsecure", "http://127.0.0.1:8080/hook", private, "must be https"},
		{"ftp", "ftp://ussp.example.ge/x", strict, "is not https"},
		{"userinfo", "https://user:pw@ussp.example.ge/hook", strict, "userinfo"},
		{"userinfo name only", "https://user@ussp.example.ge/hook", strict, "userinfo"},
		{"fragment", "https://ussp.example.ge/hook#x", strict, "fragment"},
		{"empty fragment", "https://ussp.example.ge/hook#", strict, "fragment"},
		{"253-character host", "https://" + ok253 + "/hook", strict, ""},
		{"254-character host", "https://" + long + "/hook", strict, "longer than 253"},
		{"literal public IPv4", "https://93.184.216.34/hook", strict, "literal IP"},
		{"literal public IPv4 in the lab", "https://93.184.216.34/hook", private, ""},
		{"literal private IPv4", "https://10.0.0.5/hook", strict, "literal IP"},
		{"literal private IPv4 in the lab", "https://10.0.0.5/hook", private, ""},
		{"literal IPv6", "https://[2001:4860::8888]/hook", strict, "literal IP"},
		{".local", "https://printer.local/hook", strict, ".local name"},
		{".local in the lab", "https://printer.local/hook", private, ""},
		{".internal", "https://deliver.internal/hook", strict, ".internal name"},
		{".localhost", "https://app.localhost/hook", strict, ".localhost name"},
		{"localhost", "https://localhost/hook", strict, "localhost is not accepted"},
		{"single label", "https://subscriber/hook", strict, "fully qualified"},
		{"single label in the lab", "https://subscriber/hook", private, ""},
		{"no host", "https:///hook", strict, "no host"},
		{"relative", "/v1/cis/notifications", strict, "absolute"},
		{"empty", "", strict, "missing"},
		{"bad port", "https://ussp.example.ge:0/hook", strict, "port"},
		{"too long", "https://ussp.example.ge/" + strings.Repeat("p", MaxCallbackURLLen), strict, "longer than 2048"},
		{"not a URL", "https://ussp.example.ge/%zz", strict, "not a URL"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateCallbackURL(tc.url, tc.pol)
			if tc.refuse == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("accepted, want a refusal naming %q", tc.refuse)
			}
			var fe *core.FieldError
			if !errors.As(err, &fe) || fe.Field != "callback_url" {
				t.Fatalf("not a callback_url field error: %v", err)
			}
			if !strings.Contains(fe.Reason, tc.refuse) {
				t.Errorf("reason %q does not say %q", fe.Reason, tc.refuse)
			}
		})
	}
}

// Every refused address class beside a public address, and each one
// accepted with AllowPrivate (E-01).
func TestAllowedAddress(t *testing.T) {
	refused := map[string]string{
		"loopback v4":         "127.0.0.1",
		"loopback v4 range":   "127.8.9.10",
		"loopback v6":         "::1",
		"mapped loopback":     "::ffff:127.0.0.1",
		"rfc1918 10":          "10.1.2.3",
		"rfc1918 172.16":      "172.16.0.9",
		"rfc1918 192.168":     "192.168.1.1",
		"ula":                 "fd00::1",
		"link-local v4":       "169.254.169.254",
		"link-local v6":       "fe80::1",
		"multicast v4":        "224.0.0.1",
		"multicast v6":        "ff02::1",
		"unspecified v4":      "0.0.0.0",
		"unspecified v6":      "::",
		"cgnat":               "100.64.0.1",
		"cgnat top":           "100.127.255.254",
		"broadcast":           "255.255.255.255",
		"this network":        "0.1.2.3",
		"documentation v4":    "192.0.2.10",
		"documentation v6":    "2001:db8::1",
		"benchmarking":        "198.18.0.1",
		"reserved class e":    "240.0.0.1",
		"ietf assignments v4": "192.0.0.8",
	}
	for name, s := range refused {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("%s: %q does not parse", name, s)
		}
		if AllowedAddress(ip, URLPolicy{}) {
			t.Errorf("%s %s allowed", name, s)
		}
		if !AllowedAddress(ip, URLPolicy{AllowPrivate: true}) {
			t.Errorf("%s %s refused with AllowPrivate", name, s)
		}
	}
	for _, s := range []string{"93.184.216.34", "100.128.0.1", "2001:4860:4860::8888", "8.8.8.8", "172.32.0.1"} {
		if !AllowedAddress(net.ParseIP(s), URLPolicy{}) {
			t.Errorf("public %s refused", s)
		}
	}
	if AllowedAddress(nil, URLPolicy{AllowPrivate: true}) {
		t.Error("a nil address allowed")
	}
	if AllowedAddress(net.IP{1, 2, 3}, URLPolicy{}) {
		t.Error("a malformed address allowed")
	}
}

func box(minLon, minLat, maxLon, maxLat float64) *geodesy.BBox {
	return &geodesy.BBox{MinLon: minLon, MinLat: minLat, MaxLon: maxLon, MaxLat: maxLat}
}

func TestMatches(t *testing.T) {
	sub := Subscription{Datasets: []publication.Dataset{publication.DatasetZones, publication.DatasetRestrictions}, Status: Active}
	zones := publication.Change{Dataset: publication.DatasetZones}
	cases := []struct {
		name   string
		subBox *geodesy.BBox
		ds     publication.Dataset
		chBox  *geodesy.BBox
		want   bool
	}{
		{"dataset subscribed, no boxes", nil, publication.DatasetZones, nil, true},
		{"dataset not subscribed", nil, publication.DatasetUSSPList, nil, false},
		{"dataset not subscribed, boxes overlap", box(44, 41, 45, 42), publication.DatasetUSpaceAirspace, box(44, 41, 45, 42), false},
		{"subscription box, change without one", box(44, 41, 45, 42), publication.DatasetZones, nil, true},
		{"change box, subscription without one", nil, publication.DatasetZones, box(10, 10, 11, 11), true},
		{"boxes overlap", box(44, 41, 45, 42), publication.DatasetZones, box(44.5, 41.5, 46, 43), true},
		{"change inside", box(44, 41, 45, 42), publication.DatasetZones, box(44.2, 41.2, 44.3, 41.3), true},
		{"boxes touch on an edge", box(44, 41, 45, 42), publication.DatasetRestrictions, box(45, 41.5, 46, 41.7), true},
		{"boxes touch at a corner", box(44, 41, 45, 42), publication.DatasetZones, box(45, 42, 46, 43), true},
		{"boxes apart in longitude", box(44, 41, 45, 42), publication.DatasetZones, box(45.0001, 41, 46, 42), false},
		{"boxes apart in latitude", box(44, 41, 45, 42), publication.DatasetZones, box(44, 42.0001, 45, 43), false},
		{"antimeridian box is conservative", box(170, -10, -170, 10), publication.DatasetZones, box(0, 0, 1, 1), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := sub
			s.BBox = tc.subBox
			c := zones
			c.Dataset = tc.ds
			c.BBox = tc.chBox
			if got := Matches(s, c); got != tc.want {
				t.Errorf("Matches = %v, want %v", got, tc.want)
			}
		})
	}
}

func pinJitter(t *testing.T, f float64) {
	t.Helper()
	old := jitter
	jitter = func() float64 { return f }
	t.Cleanup(func() { jitter = old })
}

// The schedule is 1, 2, 4 ... 256, then 300 s for ever; jitter stays in
// ±10 %; NextAttempt is false exactly past the window.
func TestNextAttemptSchedule(t *testing.T) {
	pinJitter(t, 1)
	changeAt := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	want := []int64{1, 2, 4, 8, 16, 32, 64, 128, 256, 300, 300}
	for i, w := range want {
		next, ok := NextAttempt(i+1, changeAt, changeAt, DefaultRetry)
		if !ok {
			t.Fatalf("attempt %d expired", i+1)
		}
		if got, ws := next.Sub(changeAt), time.Duration(w)*time.Second; got != ws {
			t.Errorf("attempt %d: %s, want %s", i+1, got, ws)
		}
	}
	if d := DefaultRetry.Delay(1000); d != 300*time.Second {
		t.Errorf("attempt 1000: %s", d)
	}
	if d := DefaultRetry.Delay(0); d != time.Second {
		t.Errorf("attempt 0: %s", d)
	}
	if d := (Retry{Base: 0, Max: 0}).Delay(3); d != time.Second {
		t.Errorf("zero retry: %s", d)
	}

	end := changeAt.Add(24 * time.Hour)
	if _, ok := NextAttempt(9, changeAt, end, DefaultRetry); !ok {
		t.Error("expired exactly at the end of the window")
	}
	if _, ok := NextAttempt(9, changeAt, end.Add(time.Nanosecond), DefaultRetry); ok {
		t.Error("not expired a nanosecond past the window")
	}
	if _, ok := NextAttempt(1, changeAt, changeAt.Add(25*time.Hour), Retry{Base: time.Second, Max: time.Minute}); ok {
		t.Error("a zero window is not the 24 h default")
	}
}

func TestNextAttemptJitterBounds(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	for _, f := range []float64{0.9, 1.1} {
		t.Run("pinned", func(t *testing.T) {
			pinJitter(t, f)
			next, _ := NextAttempt(10, now, now, DefaultRetry)
			if got, w := next.Sub(now), time.Duration(float64(300*time.Second)*f); got != w {
				t.Errorf("jitter %v: %s, want %s", f, got, w)
			}
		})
	}
	// The real source: every draw within ±10 %, and not all equal.
	seen := map[time.Duration]bool{}
	for range 200 {
		next, ok := NextAttempt(3, now, now, DefaultRetry)
		if !ok {
			t.Fatal("expired")
		}
		d := next.Sub(now)
		if d < 3600*time.Millisecond || d > 4400*time.Millisecond {
			t.Fatalf("delay %s outside 4 s ±10 %%", d)
		}
		seen[d] = true
	}
	if len(seen) < 2 {
		t.Error("jitter never varied")
	}
}

// 49 failures over two hours do not suspend; 50 over an hour do; 50 in
// 59 minutes do not.
func TestShouldSuspendBoundary(t *testing.T) {
	since := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		n    int
		age  time.Duration
		want bool
	}{
		{MaxConsecutiveFailures - 1, 2 * time.Hour, false},
		{MaxConsecutiveFailures, SuspendAfter, true},
		{MaxConsecutiveFailures, SuspendAfter - time.Second, false},
		{MaxConsecutiveFailures + 10, 3 * time.Hour, true},
	}
	for _, tc := range cases {
		if got := ShouldSuspend(tc.n, since, since.Add(tc.age)); got != tc.want {
			t.Errorf("%d failures over %s: %v, want %v", tc.n, tc.age, got, tc.want)
		}
	}
	if ShouldSuspend(100, time.Time{}, since) {
		t.Error("suspended without a failing-since time")
	}
}

func TestStatus(t *testing.T) {
	for _, st := range []Status{PendingVerification, Active, Suspended, Deleted} {
		if !st.Valid() {
			t.Errorf("%s not valid", st)
		}
	}
	if Status("paused").Valid() {
		t.Error("paused valid")
	}
	if !Active.Receives() || !PendingVerification.Receives() || Suspended.Receives() || Deleted.Receives() {
		t.Error("Receives")
	}
}
