package httpapi

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// MinDeprecationWindow is the shortest time between an operation's
// deprecation and its sunset: the compatibility policy of spec 00
// section 7 keeps a deprecated operation served for 12 months
// (docs/RELEASING.md). 365 days, so a leap year never shortens it.
const MinDeprecationWindow = 365 * 24 * time.Hour

// Deprecation marks one operation as deprecated (the compatibility
// policy, docs/RELEASING.md). Every response of the operation, its
// errors included, carries
//
//	Deprecation: @<Since in Unix seconds>       (RFC 9745, a Structured Field Date)
//	Sunset: <Sunset as an HTTP-date>            (RFC 8594)
//	Link: <Link>; rel="deprecation"             (RFC 9745), when Link is set
//
// so a client learns of it from any call, before the operation goes.
type Deprecation struct {
	// Since is when the operation was deprecated.
	Since time.Time
	// Sunset is when it stops being served: at least
	// MinDeprecationWindow after Since.
	Sunset time.Time
	// Link is the absolute URL of the human-readable notice (the
	// release notes); empty: no Link header.
	Link string
}

// Deprecated is the table of deprecated operations, keyed by their
// ServeMux pattern ("GET /v1/zones/versions" is written as the
// operation, "GET /v1/{dataset}/versions"). No operation of /v1 is
// deprecated yet. An operation listed here is also `deprecated: true`
// in api/openapi.yaml, and the reverse (TestDeprecatedTableMatchesSpec).
var Deprecated = map[string]Deprecation{}

// checkDeprecations refuses a table entry for no operation, a sunset
// less than MinDeprecationWindow after the deprecation, and a link that
// is not an absolute http(s) URL.
func checkDeprecations(patterns []string, table map[string]Deprecation) error {
	var errs []error
	routes := make([]string, 0, len(table))
	for r := range table {
		routes = append(routes, r)
	}
	sort.Strings(routes)
	for _, route := range routes {
		d := table[route]
		switch {
		case !slices.Contains(patterns, route):
			errs = append(errs, fmt.Errorf("a deprecation for no operation: %s", route))
		case d.Since.IsZero() || d.Sunset.IsZero():
			errs = append(errs, fmt.Errorf("deprecation of %s: Since and Sunset are both required", route))
		case d.Sunset.Sub(d.Since) < MinDeprecationWindow:
			errs = append(errs, fmt.Errorf("deprecation of %s: sunset %s is less than 12 months after %s",
				route, d.Sunset.UTC().Format(time.RFC3339), d.Since.UTC().Format(time.RFC3339)))
		case d.Link != "" && !absoluteHTTP(d.Link):
			errs = append(errs, fmt.Errorf("deprecation of %s: link %q is not an absolute http(s) URL", route, d.Link))
		}
	}
	return errors.Join(errs...)
}

func absoluteHTTP(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" &&
		!strings.ContainsAny(raw, "<>\" ")
}

// deprecationHeaders sets the headers of the matched route's entry, if
// any, before the handler writes anything.
func deprecationHeaders(next http.Handler, table map[string]Deprecation) http.Handler {
	if len(table) == 0 {
		return next
	}
	type headers struct{ deprecation, sunset, link string }
	byRoute := make(map[string]headers, len(table))
	for route, d := range table {
		h := headers{
			deprecation: "@" + strconv.FormatInt(d.Since.Unix(), 10),
			sunset:      d.Sunset.UTC().Format(http.TimeFormat),
		}
		if d.Link != "" {
			h.link = "<" + d.Link + `>; rel="deprecation"`
		}
		byRoute[route] = h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h, ok := byRoute[routeOf(r.Context())]; ok {
			w.Header().Set("Deprecation", h.deprecation)
			w.Header().Set("Sunset", h.sunset)
			if h.link != "" {
				w.Header().Add("Link", h.link)
			}
		}
		next.ServeHTTP(w, r)
	})
}
