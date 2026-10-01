package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	coreauth "github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-cisp/internal/auth"
	"github.com/rootxkit/uspace-cisp/internal/authtest"
	"github.com/rootxkit/uspace-cisp/internal/config"
	"github.com/rootxkit/uspace-cisp/internal/jws"
)

func keyRing(t *testing.T) *jws.KeyRing {
	t.Helper()
	cur, err := jws.EncodePrivateKeyPEM(authtest.Key(t, "cisp", 3072))
	if err != nil {
		t.Fatal(err)
	}
	prev, err := jws.EncodePrivateKeyPEM(authtest.Key(t, "cisp-prev", 3072))
	if err != nil {
		t.Fatal(err)
	}
	r, err := jws.LoadKeyRing(cur, "cisp-2", prev, "cisp-1")
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// GET /.well-known/jwks.json: the ring's bytes with ETag and
// Cache-Control, no auth; 304 for the current ETag beside 200 for a stale
// one; 503 without a key. Every response conforms to api/openapi.yaml.
func TestJWKSEndpoint(t *testing.T) {
	keys := keyRing(t)
	f := newFixture(t, &Server{Keys: keys}, Options{})
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", http.NoBody)
	rec := f.do(req)
	if rec.Code != http.StatusOK || rec.Body.String() != string(keys.JWKS()) {
		t.Fatalf("GET = %d %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("ETag") != keys.ETag() || rec.Header().Get("Cache-Control") != "public, max-age=3600" {
		t.Errorf("headers %v", rec.Header())
	}
	var doc struct {
		Keys []struct {
			KID string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil || len(doc.Keys) != 2 || doc.Keys[0].KID != "cisp-2" || doc.Keys[1].KID != "cisp-1" {
		t.Errorf("keys = %+v %v", doc, err)
	}
	conform(t, req, rec)
	t.Logf("GET /.well-known/jwks.json = %d, ETag %s, Cache-Control %s", rec.Code, rec.Header().Get("ETag"), rec.Header().Get("Cache-Control"))

	for _, inm := range []string{keys.ETag(), "W/" + keys.ETag(), `"other", ` + keys.ETag(), "*"} {
		req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", http.NoBody)
		req.Header.Set("If-None-Match", inm)
		rec := f.do(req)
		if rec.Code != http.StatusNotModified || rec.Body.Len() != 0 || rec.Header().Get("ETag") != keys.ETag() {
			t.Errorf("If-None-Match %s: %d", inm, rec.Code)
		}
		conform(t, req, rec)
	}
	req = httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", http.NoBody)
	req.Header.Set("If-None-Match", `"stale"`)
	if rec := f.do(req); rec.Code != http.StatusOK {
		t.Errorf("a stale ETag: %d", rec.Code)
	}

	none := newFixture(t, &Server{}, Options{})
	req = httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", http.NoBody)
	rec = none.do(req)
	if p := decodeProblem(t, rec); rec.Code != http.StatusServiceUnavailable || p.Type != ProblemTypeBase+SlugKeysUnavailable {
		t.Errorf("without keys: %d %s", rec.Code, rec.Body.String())
	}
	conform(t, req, rec)
}

// GET /v1/status runs the guard (cis.read): no token is a 401 problem
// that conforms to the spec, a cis.read token reaches the handler (501
// until WP-7), a token without cis.read is 403. A route without
// middleware runs none.
func TestRouteMiddlewareGuardsStatus(t *testing.T) {
	iss, err := coreauth.NewIssuer("https://authority.example.test/", authtest.Key(t, "issuer", 2048), "tok-1")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	mv, err := auth.NewMachineVerifier(context.Background(), auth.MachineConfig{
		Issuers:   []auth.Source{{ID: "https://authority.example.test/", Keys: iss.JWKS()}},
		Audiences: []string{"uspace-cisp.example.test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	g, err := auth.NewGuard(auth.GuardConfig{Verifier: mv, Problems: WriteProblem, MTLSMode: config.MTLSOff})
	if err != nil {
		t.Fatal(err)
	}
	routes := openRoutes()
	routes["GET /v1/status"] = g.RequireScopes(auth.ScopeRead)
	f := newFixture(t, &Server{}, Options{RouteMiddleware: routes})
	tok := func(scopes ...string) string {
		s, err := iss.Issue("ussp-GEO1-01", "uspace-cisp.example.test", scopes, time.Minute, now)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	cases := []struct {
		name, token string
		code        int
		slug        string
	}{
		{"no token", "", 401, auth.SlugUnauthenticated},
		{"no cis.read", tok("cis.publish:zones"), 403, auth.SlugForbidden},
		{"cis.read", tok(auth.ScopeRead), 501, SlugNotImplemented},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodGet, "/v1/status", http.NoBody)
		if c.token != "" {
			req.Header.Set("Authorization", "Bearer "+c.token)
		}
		rec := f.do(req)
		if p := decodeProblem(t, rec); rec.Code != c.code || p.Type != ProblemTypeBase+c.slug {
			t.Errorf("%s: %d %s", c.name, rec.Code, rec.Body.String())
		}
		if c.code == 401 && (!strings.Contains(rec.Body.String(), `"field":"authorization"`) || rec.Header().Get(HeaderRequestID) == "") {
			t.Errorf("%s: %s", c.name, rec.Body.String())
		}
		conform(t, req, rec)
		t.Logf("%s: %d %s", c.name, rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	req := httptest.NewRequest(http.MethodGet, "/healthz", http.NoBody)
	if rec := f.do(req); rec.Code != http.StatusOK {
		t.Errorf("an unguarded route: %d", rec.Code)
	}
}
