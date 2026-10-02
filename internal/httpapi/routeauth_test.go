package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

func passthrough(h http.Handler) http.Handler { return h }

// openRoutes gives every non-public operation a passthrough entry, for
// the tests that exercise handlers rather than authentication.
func openRoutes() map[string]func(http.Handler) http.Handler {
	return map[string]func(http.Handler) http.Handler{
		"GET /v1/status":                          passthrough,
		"PUT /v1/publications/{dataset}":          passthrough,
		"GET /v1/publications/{dataset}":          passthrough,
		"GET /v1/publications/{dataset}/attempts": passthrough,
		"POST /v1/publishers/heartbeat":           passthrough,
		"GET /v1/{dataset}":                       passthrough,
		"HEAD /v1/{dataset}":                      passthrough,
		"GET /v1/{dataset}/versions":              passthrough,
		"GET /v1/{dataset}/versions/{version}":    passthrough,
		"GET /v1/changes":                         passthrough,
		"GET /public/v1/{dataset}":                passthrough,
		"HEAD /public/v1/{dataset}":               passthrough,
		"POST /v1/restrictions":                   passthrough,
		"PATCH /v1/restrictions/{id}":             passthrough,
		"GET /v1/restrictions/heads":              passthrough,
		"GET /v1/restrictions/{id}":               passthrough,
	}
}

func mustRouter(t *testing.T, s *Server, opts Options) http.Handler {
	t.Helper()
	h, err := NewRouter(s, opts)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// specOperations is every operation of api/openapi.yaml as a ServeMux
// pattern, read from the file itself.
func specOperations(t *testing.T) []string {
	t.Helper()
	doc, err := openapi3.NewLoader().LoadFromFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for path, item := range doc.Paths.Map() {
		for method := range item.Operations() {
			out = append(out, method+" "+path)
		}
	}
	return out
}

// Fail closed: every operation of the spec outside PublicRoutes needs an
// entry; a missing one, and one naming no operation, refuse the router.
// The complete map is accepted.
func TestRouteAuthIsFailClosed(t *testing.T) {
	ops := specOperations(t)
	complete := map[string]func(http.Handler) http.Handler{}
	for _, op := range ops {
		if !PublicRoutes[op] {
			complete[op] = passthrough
		}
	}
	if len(complete) == 0 {
		t.Fatal("the spec has no protected operation; the check would be vacuous")
	}
	if _, err := NewRouter(&Server{}, Options{RouteMiddleware: complete}); err != nil {
		t.Fatalf("every protected operation has an entry, yet: %v", err)
	}
	for op := range complete {
		missing := map[string]func(http.Handler) http.Handler{}
		for k, v := range complete {
			if k != op {
				missing[k] = v
			}
		}
		_, err := NewRouter(&Server{}, Options{RouteMiddleware: missing})
		if err == nil || !strings.Contains(err.Error(), op) {
			t.Errorf("no entry for %s: %v", op, err)
		}
	}
	if _, err := NewRouter(&Server{}, Options{}); err == nil {
		t.Error("no entries at all: the router was built")
	}
	typo := map[string]func(http.Handler) http.Handler{"GET /v1/statuz": passthrough}
	for k, v := range complete {
		typo[k] = v
	}
	if _, err := NewRouter(&Server{}, Options{RouteMiddleware: typo}); err == nil || !strings.Contains(err.Error(), "GET /v1/statuz") {
		t.Errorf("an entry for no operation: %v", err)
	}
	// Every public route is an operation of the spec (none is stale).
	for p := range PublicRoutes {
		found := false
		for _, op := range ops {
			found = found || op == p
		}
		if !found {
			t.Errorf("public route %s is not in api/openapi.yaml", p)
		}
	}
	// And they really are served without an entry.
	h := mustRouter(t, &Server{}, Options{RouteMiddleware: complete})
	for p := range PublicRoutes {
		path := strings.TrimPrefix(p, "GET ")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, http.NoBody))
		if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
			t.Errorf("%s: %d", p, rec.Code)
		}
	}
}
