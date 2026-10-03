package httpapi

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
)

var (
	deprecatedSince = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	sunsetAt        = time.Date(2027, 10, 1, 0, 0, 0, 0, time.UTC)
)

// A deprecated operation carries Deprecation (RFC 9745: "@" and Unix
// seconds), Sunset (RFC 8594: an HTTP-date) and the deprecation Link on
// every response, an error response included and through a dataset
// alias; an operation not in the table carries none of them (E-01).
func TestDeprecatedOperationCarriesTheHeaders(t *testing.T) {
	f := newFixture(t, &Server{}, Options{Deprecations: map[string]Deprecation{
		"GET /healthz":               {Since: deprecatedSince, Sunset: sunsetAt, Link: "https://uspace-cisp.example/releases/v2"},
		"GET /v1/{dataset}/versions": {Since: deprecatedSince, Sunset: sunsetAt},
	}})
	rec := f.do(httptest.NewRequest(http.MethodGet, "/healthz", http.NoBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz = %d", rec.Code)
	}
	if got, want := rec.Header().Get("Deprecation"), "@"+strconv.FormatInt(deprecatedSince.Unix(), 10); got != want {
		t.Errorf("Deprecation = %q, want %q", got, want)
	}
	if got := rec.Header().Get("Sunset"); got != "Fri, 01 Oct 2027 00:00:00 GMT" {
		t.Errorf("Sunset = %q", got)
	}
	if got := rec.Header().Get("Link"); got != `<https://uspace-cisp.example/releases/v2>; rel="deprecation"` {
		t.Errorf("Link = %q", got)
	}
	if _, err := http.ParseTime(rec.Header().Get("Sunset")); err != nil {
		t.Errorf("Sunset is no HTTP-date: %v", err)
	}

	// Through the per-dataset alias, on whatever the handler answers.
	alias := f.do(httptest.NewRequest(http.MethodGet, "/v1/zones/versions", http.NoBody))
	if alias.Header().Get("Deprecation") == "" || alias.Header().Get("Sunset") == "" || alias.Header().Get("Link") != "" {
		t.Errorf("alias %d: Deprecation %q Sunset %q Link %q", alias.Code,
			alias.Header().Get("Deprecation"), alias.Header().Get("Sunset"), alias.Header().Get("Link"))
	}

	// The twin: an operation outside the table.
	other := f.do(httptest.NewRequest(http.MethodGet, "/readyz", http.NoBody))
	for _, h := range []string{"Deprecation", "Sunset", "Link"} {
		if v := other.Header().Get(h); v != "" {
			t.Errorf("readyz carries %s: %q", h, v)
		}
	}
}

// The published table is empty today, so no response carries the
// headers by default (and the default router is built from it).
func TestNoOperationIsDeprecatedByDefault(t *testing.T) {
	if len(Deprecated) != 0 {
		t.Fatalf("Deprecated = %v: update docs/RELEASING.md and the CHANGELOG with it", Deprecated)
	}
	f := newFixture(t, &Server{}, Options{})
	if rec := f.do(httptest.NewRequest(http.MethodGet, "/healthz", http.NoBody)); rec.Header().Get("Deprecation") != "" {
		t.Errorf("Deprecation = %q", rec.Header().Get("Deprecation"))
	}
}

// NewRouter refuses a table it cannot honour, each beside the entry
// that differs in one thing and is accepted.
func TestNewRouterRefusesABadDeprecation(t *testing.T) {
	ok := Deprecation{Since: deprecatedSince, Sunset: deprecatedSince.Add(MinDeprecationWindow)}
	cases := []struct {
		name  string
		route string
		d     Deprecation
		want  string
	}{
		{"accepted at exactly 12 months", "GET /healthz", ok, ""},
		{"no operation", "GET /v1/nothing", ok, "no operation"},
		{"sunset a second early", "GET /healthz", Deprecation{Since: ok.Since, Sunset: ok.Sunset.Add(-time.Second)}, "less than 12 months"},
		{"sunset before since", "GET /healthz", Deprecation{Since: ok.Sunset, Sunset: ok.Since}, "less than 12 months"},
		{"no sunset", "GET /healthz", Deprecation{Since: ok.Since}, "both required"},
		{"relative link", "GET /healthz", Deprecation{Since: ok.Since, Sunset: ok.Sunset, Link: "/releases"}, "absolute"},
		{"link that breaks the header", "GET /healthz", Deprecation{Since: ok.Since, Sunset: ok.Sunset, Link: "https://x.example/a>b"}, "absolute"},
		{"absolute link", "GET /healthz", Deprecation{Since: ok.Since, Sunset: ok.Sunset, Link: "https://x.example/a"}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := NewRouter(&Server{}, Options{RouteMiddleware: openRoutes(), Deprecations: map[string]Deprecation{c.route: c.d}})
			switch {
			case c.want == "" && err != nil:
				t.Fatalf("refused: %v", err)
			case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}

// The table and api/openapi.yaml agree: an operation is in Deprecated
// exactly when the spec marks it `deprecated: true`.
func TestDeprecatedTableMatchesSpec(t *testing.T) {
	doc, err := openapi3.NewLoader().LoadFromFile(filepath.Join("..", "..", "api", "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var inSpec []string
	for path, item := range doc.Paths.Map() {
		for method, op := range item.Operations() {
			if op.Deprecated {
				inSpec = append(inSpec, method+" "+path)
			}
		}
	}
	sort.Strings(inSpec)
	for _, op := range inSpec {
		if _, ok := Deprecated[op]; !ok {
			t.Errorf("%s is deprecated in the spec but not in Deprecated", op)
		}
	}
	for op := range Deprecated {
		found := false
		for _, s := range inSpec {
			found = found || s == op
		}
		if !found {
			t.Errorf("%s is in Deprecated but not deprecated in the spec", op)
		}
	}
	t.Logf("%d deprecated operations in the spec", len(inSpec))
}
