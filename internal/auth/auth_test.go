package auth_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	jwxjws "github.com/lestrrat-go/jwx/v3/jws"

	coreauth "github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-cisp/internal/auth"
	"github.com/rootxkit/uspace-cisp/internal/authtest"
	"github.com/rootxkit/uspace-cisp/internal/config"
	"github.com/rootxkit/uspace-cisp/internal/httpapi"
	"github.com/rootxkit/uspace-cisp/internal/obs"
	"github.com/rootxkit/uspace-cisp/internal/publication"
)

const (
	issuer   = "https://authority.example.test/"
	labIss   = "https://lab.example.test/"
	host     = "uspace-cisp.example.test"
	labAlias = "cisp"
	subject  = "ANSP subject CN=ansp-01,O=Example"
)

var now = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

type fixture struct {
	iss      *coreauth.Issuer
	labIss   *coreauth.Issuer
	stranger *coreauth.Issuer
	guard    *auth.Guard
	comp     *obs.Component
	logs     *bytes.Buffer
}

func newIssuer(t testing.TB, iss, name, kid string) *coreauth.Issuer {
	t.Helper()
	i, err := coreauth.NewIssuer(iss, authtest.Key(t, name, 2048), kid)
	if err != nil {
		t.Fatal(err)
	}
	return i
}

func newFixture(t *testing.T, mtlsMode string) fixture {
	t.Helper()
	f := fixture{
		iss:      newIssuer(t, issuer, "issuer", "tok-1"),
		labIss:   newIssuer(t, labIss, "lab", "lab-1"),
		stranger: newIssuer(t, issuer, "stranger", "tok-unknown"),
		logs:     &bytes.Buffer{},
	}
	mv, err := auth.NewMachineVerifier(context.Background(), auth.MachineConfig{
		Issuers:   []auth.Source{{ID: issuer, Keys: f.iss.JWKS()}, {ID: labIss, Keys: f.labIss.JWKS()}},
		Audiences: []string{host, labAlias},
		Now:       func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	f.comp = obs.NewStatus("test", nil, now).Component("auth")
	f.guard, err = auth.NewGuard(auth.GuardConfig{
		Verifier: mv, Problems: httpapi.WriteProblem,
		AuthorityClientID: "authority-01", ANSPClientID: "ansp-01",
		MTLSMode: mtlsMode, ANSPMTLSSubject: subject,
		Component: f.comp,
		Logger:    slog.New(slog.NewJSONHandler(f.logs, nil)),
		Now:       func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f fixture) token(t *testing.T, sub, aud string, scopes ...string) string {
	t.Helper()
	tok, err := f.iss.Issue(sub, aud, scopes, 5*time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

type problem struct {
	Type   string `json:"type"`
	Status int    `json:"status"`
	Detail string `json:"detail"`
	Errors []struct {
		Field  string `json:"field"`
		Reason string `json:"reason"`
	} `json:"errors"`
}

type result struct {
	code    int
	problem problem
	header  http.Header
	caller  *auth.Caller
	raw     string
}

func call(t *testing.T, h http.Handler, token string, hdr map[string]string) result {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/restrictions", http.NoBody)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	var caller *auth.Caller
	h.ServeHTTP(rec, req.WithContext(context.WithValue(req.Context(), callerSink{}, &caller)))
	res := result{code: rec.Code, header: rec.Header(), raw: rec.Body.String()}
	if rec.Code != http.StatusNoContent {
		if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
			t.Errorf("refusal content type %q", ct)
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &res.problem); err != nil {
			t.Fatalf("problem body %q: %v", rec.Body.String(), err)
		}
	}
	res.caller = caller
	return res
}

type callerSink struct{}

// sink is the protected handler: 204, recording the caller.
var sink = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	if p, ok := r.Context().Value(callerSink{}).(**auth.Caller); ok {
		*p = auth.CallerFrom(r.Context())
	}
	w.WriteHeader(http.StatusNoContent)
})

func wantProblem(t *testing.T, r result, status int, slug, field string) {
	t.Helper()
	if r.code != status || r.problem.Type != httpapi.ProblemTypeBase+slug || r.problem.Status != status {
		t.Fatalf("got %d %s, want %d %s: %s", r.code, r.problem.Type, status, slug, r.raw)
	}
	if len(r.problem.Errors) == 0 || r.problem.Errors[0].Field != field {
		t.Fatalf("errors[0].field = %+v, want %s", r.problem.Errors, field)
	}
	if !strings.HasPrefix(r.problem.Detail, field+": ") {
		t.Errorf("detail %q does not name %s", r.problem.Detail, field)
	}
}

// E-01: the accepted publisher request beside every refusal of the token,
// scope, publisher and mTLS rows of docs/PLAN.md section 8.1 T4, each
// differing from it in one thing, each counted under its reason.
func TestGuardT4Pairs(t *testing.T) {
	f := newFixture(t, config.MTLSRequired)
	h := auth.Chain(sink,
		f.guard.RequireScopes(auth.ScopePublishRestrictions),
		f.guard.RequirePublisher(auth.PublisherANSP),
		f.guard.RequireMTLSSubject())
	mtls := map[string]string{auth.HeaderClientCertSubject: subject}

	ok := call(t, h, f.token(t, "ansp-01", host, auth.ScopePublishRestrictions, auth.ScopeRead), mtls)
	if ok.code != http.StatusNoContent || ok.caller == nil || ok.caller.ClientID != "ansp-01" ||
		ok.caller.Kind != auth.KindMachine || ok.caller.MTLSSubject != subject || ok.caller.Claims.Audience != host {
		t.Fatalf("the accepted request: %d %+v %s", ok.code, ok.caller, ok.raw)
	}

	expired, err := f.iss.Issue("ansp-01", host, []string{auth.ScopePublishRestrictions}, time.Minute, now.Add(-2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	stranger, err := f.stranger.Issue("ansp-01", host, []string{auth.ScopePublishRestrictions}, time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name        string
		token       string
		hdr         map[string]string
		status      int
		slug, field string
		counter     string
	}{
		{"no token", "", mtls, 401, auth.SlugUnauthenticated, "authorization", auth.CounterRejectedNoToken},
		{"wrong aud", f.token(t, "ansp-01", "uspace-ussp.example.test", auth.ScopePublishRestrictions), mtls, 401, auth.SlugUnauthenticated, "aud", coreauth.CounterRejectedAudience},
		{"unknown kid", stranger, mtls, 401, auth.SlugUnauthenticated, "kid", coreauth.CounterRejectedKID},
		{"expired", expired, mtls, 401, auth.SlugUnauthenticated, "exp", coreauth.CounterRejectedExpired},
		{"garbage token", "not.a.token", mtls, 401, auth.SlugUnauthenticated, "token", coreauth.CounterRejectedMalformed},
		{"right sub, wrong scope", f.token(t, "ansp-01", host, auth.ScopeRead), mtls, 403, auth.SlugForbidden, "scope", auth.CounterRejectedScope},
		{"wrong sub", f.token(t, "authority-01", host, auth.ScopePublishRestrictions), mtls, 403, auth.SlugNotAPublisher, "sub", auth.CounterRejectedPublisherBinding},
		{"mTLS subject mismatch", f.token(t, "ansp-01", host, auth.ScopePublishRestrictions), map[string]string{auth.HeaderClientCertSubject: "CN=someone-else"}, 403, auth.SlugMTLSRequired, auth.HeaderClientCertSubject, auth.CounterRejectedMTLSSubject},
		{"mTLS header absent", f.token(t, "ansp-01", host, auth.ScopePublishRestrictions), nil, 403, auth.SlugMTLSRequired, auth.HeaderClientCertSubject, auth.CounterRejectedMTLSMissing},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := f.comp.Counter(c.counter, "").Value()
			r := call(t, h, c.token, c.hdr)
			wantProblem(t, r, c.status, c.slug, c.field)
			if r.caller != nil {
				t.Error("the handler ran")
			}
			if f.comp.Counter(c.counter, "").Value() != before+1 {
				t.Errorf("%s not counted", c.counter)
			}
			if c.status == 401 && r.header.Get("WWW-Authenticate") == "" {
				t.Error("401 without WWW-Authenticate")
			}
		})
	}
	// The mismatch problem never echoes the expected subject.
	r := call(t, h, f.token(t, "ansp-01", host, auth.ScopePublishRestrictions), map[string]string{auth.HeaderClientCertSubject: "CN=x"})
	if strings.Contains(r.raw, subject) {
		t.Errorf("the configured subject leaks: %s", r.raw)
	}
}

// aud is accepted for each value of a two-entry CISP_AUDIENCES and
// refused for a third; a token of the lab issuer is accepted too.
func TestAudiencesAndIssuers(t *testing.T) {
	f := newFixture(t, config.MTLSOff)
	h := f.guard.RequireScopes(auth.ScopeRead)(sink)
	for _, aud := range []string{host, labAlias} {
		if r := call(t, h, f.token(t, "ussp-GEO1-01", aud, auth.ScopeRead), nil); r.code != 204 || r.caller.Claims.Audience != aud {
			t.Errorf("aud %s: %d %s", aud, r.code, r.raw)
		}
	}
	wantProblem(t, call(t, h, f.token(t, "ussp-GEO1-01", "uspace-authority.example.test", auth.ScopeRead), nil), 401, auth.SlugUnauthenticated, "aud")

	lab, err := f.labIss.Issue("lab-01", labAlias, []string{auth.ScopeRead}, time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	if r := call(t, h, lab, nil); r.code != 204 || r.caller.Claims.Issuer != labIss {
		t.Errorf("lab issuer: %d %s", r.code, r.raw)
	}
	other := newIssuer(t, "https://elsewhere.example.test/", "issuer", "tok-1")
	tok, err := other.Issue("x-01", host, []string{auth.ScopeRead}, time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	wantProblem(t, call(t, h, tok, nil), 401, auth.SlugUnauthenticated, "iss")
}

// signToken signs claims as the issuer's key would, for the claims
// core's Issuer does not write (roles, realm).
func signToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	k, err := jwk.Import(authtest.Key(t, "issuer", 2048))
	if err != nil {
		t.Fatal(err)
	}
	hdr := jwxjws.NewHeaders()
	if err := hdr.Set(jwxjws.KeyIDKey, "tok-1"); err != nil {
		t.Fatal(err)
	}
	tok, err := jwxjws.Sign(payload, jwxjws.WithKey(jwa.RS256(), k, jwxjws.WithProtectedHeaders(hdr)))
	if err != nil {
		t.Fatal(err)
	}
	return string(tok)
}

// StrictSessionClaims is on: roles that is not an array of strings is
// refused, beside the same token with a well-formed roles.
func TestStrictSessionClaims(t *testing.T) {
	f := newFixture(t, config.MTLSOff)
	h := f.guard.RequireScopes()(sink)
	base := func(roles any) map[string]any {
		return map[string]any{"iss": issuer, "sub": "console-1", "aud": host, "exp": now.Add(time.Minute).Unix(),
			"iat": now.Unix(), "jti": "j-1", "scope": "session", "roles": roles, "realm": "cisp"}
	}
	if r := call(t, h, signToken(t, base([]string{"viewer"})), nil); r.code != 204 || len(r.caller.Claims.Roles) != 1 {
		t.Fatalf("well-formed roles: %d %s", r.code, r.raw)
	}
	r := call(t, h, signToken(t, base("viewer")), nil)
	if r.code != 401 || f.comp.Counter(coreauth.CounterRejectedClaims, "").Value() != 1 {
		t.Errorf("roles as a string: %d %s", r.code, r.raw)
	}
}

func TestRequireAnyScope(t *testing.T) {
	f := newFixture(t, config.MTLSOff)
	h := f.guard.RequireAnyScope(auth.ScopePublishZones, auth.ScopePublishUSpace)(sink)
	if r := call(t, h, f.token(t, "authority-01", host, auth.ScopePublishUSpace), nil); r.code != 204 {
		t.Errorf("one of the scopes: %d %s", r.code, r.raw)
	}
	r := call(t, h, f.token(t, "authority-01", host, auth.ScopeRead), nil)
	wantProblem(t, r, 403, auth.SlugForbidden, "scope")
	if !strings.Contains(r.problem.Errors[0].Reason, auth.ScopePublishZones) {
		t.Errorf("the missing scopes are not named: %s", r.raw)
	}
	wantProblem(t, call(t, h, "", nil), 401, auth.SlugUnauthenticated, "authorization")
}

func TestRequirePublisherAuthority(t *testing.T) {
	f := newFixture(t, config.MTLSOff)
	h := f.guard.RequirePublisher(auth.PublisherAuthority)(sink)
	if r := call(t, h, f.token(t, "authority-01", host), nil); r.code != 204 {
		t.Errorf("authority: %d %s", r.code, r.raw)
	}
	wantProblem(t, call(t, h, f.token(t, "ansp-01", host), nil), 403, auth.SlugNotAPublisher, "sub")
	wantProblem(t, call(t, h, "", nil), 401, auth.SlugUnauthenticated, "authorization")
	unknown := f.guard.RequirePublisher(auth.Publisher("nobody"))(sink)
	wantProblem(t, call(t, unknown, f.token(t, "authority-01", host), nil), 403, auth.SlugNotAPublisher, "sub")
	if f.guard.ClientID(auth.PublisherANSP) != "ansp-01" {
		t.Error("ClientID")
	}
}

// mTLS off: the ANSP route passes without the header and counts it; the
// status line's mtls component says off at every period (ReportMTLS).
func TestMTLSOff(t *testing.T) {
	f := newFixture(t, config.MTLSOff)
	h := auth.Chain(sink, f.guard.RequirePublisher(auth.PublisherANSP), f.guard.RequireMTLSSubject())
	r := call(t, h, f.token(t, "ansp-01", host), nil)
	if r.code != 204 || r.caller.MTLSSubject != "" || f.comp.Counter(auth.CounterMTLSOffPassed, "").Value() != 1 {
		t.Errorf("mTLS off: %d %+v", r.code, r.caller)
	}
	wantProblem(t, call(t, h, "", nil), 401, auth.SlugUnauthenticated, "authorization")

	st := obs.NewStatus("api", nil, now)
	comp := st.Component("mtls")
	auth.ReportMTLS(comp, config.MTLSOff)
	var line bytes.Buffer
	st.Log(context.Background(), slog.New(slog.NewJSONHandler(&line, nil)), now)
	if !strings.Contains(line.String(), `"level":"ERROR"`) || !strings.Contains(line.String(), `"mtls":{"degraded":"off (CISP_MTLS_MODE=off)`) {
		t.Errorf("status line: %s", line.String())
	}
	t.Logf("status line: %s", strings.TrimSpace(line.String()))
	auth.ReportMTLS(comp, config.MTLSRequired)
	if comp.DegradedReason() != "" {
		t.Error("required mode left the component degraded")
	}
}

// A forged X-Client-Cert-Subject on a route without the mTLS middleware
// is never read: the caller carries no subject. The same header on the
// mTLS route is bound.
func TestForgedSubjectIgnoredOffTheMTLSRoutes(t *testing.T) {
	f := newFixture(t, config.MTLSRequired)
	forged := map[string]string{auth.HeaderClientCertSubject: subject}
	read := f.guard.RequireScopes(auth.ScopeRead)(sink)
	r := call(t, read, f.token(t, "ussp-GEO1-01", host, auth.ScopeRead), forged)
	if r.code != 204 || r.caller.MTLSSubject != "" {
		t.Errorf("non-mTLS route: %d, subject %q", r.code, r.caller.MTLSSubject)
	}
	bound := auth.Chain(sink, f.guard.RequireScopes(auth.ScopeRead), f.guard.RequireMTLSSubject())
	if r := call(t, bound, f.token(t, "ussp-GEO1-01", host, auth.ScopeRead), forged); r.code != 204 || r.caller.MTLSSubject != subject {
		t.Errorf("mTLS route: %d, subject %q", r.code, r.caller.MTLSSubject)
	}
}

func TestBearerParsing(t *testing.T) {
	f := newFixture(t, config.MTLSOff)
	h := f.guard.RequireScopes()(sink)
	tok := f.token(t, "x-01", host)
	for _, v := range []string{"Bearer " + tok, "bearer " + tok, "BEARER  " + tok} {
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		req.Header.Set("Authorization", v)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 204 {
			t.Errorf("%q: %d", v[:8], rec.Code)
		}
	}
	for _, v := range []string{"Basic " + base64.StdEncoding.EncodeToString([]byte("a:b")), "Bearer", "Bearer   ", tok} {
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		req.Header.Set("Authorization", v)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 401 || !strings.Contains(rec.Body.String(), `"field":"authorization"`) {
			t.Errorf("%q: %d %s", v, rec.Code, rec.Body.String())
		}
	}
}

// The first refusal of a reason is logged at once, the next ones within
// the interval are counted and logged with the count after it (E-09).
func TestRefusalLogIsRateLimited(t *testing.T) {
	logs := &bytes.Buffer{}
	clock := now
	mv, err := auth.NewMachineVerifier(context.Background(), auth.MachineConfig{
		Issuers: []auth.Source{{ID: issuer, Keys: newIssuer(t, issuer, "issuer", "tok-1").JWKS()}}, Audiences: []string{host},
	})
	if err != nil {
		t.Fatal(err)
	}
	g, err := auth.NewGuard(auth.GuardConfig{Verifier: mv, Problems: httpapi.WriteProblem, MTLSMode: config.MTLSOff,
		Logger: slog.New(slog.NewJSONHandler(logs, nil)), LogEvery: time.Minute, Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatal(err)
	}
	h := g.RequireScopes()(sink)
	for range 3 {
		call(t, h, "", nil)
	}
	if n := strings.Count(logs.String(), "request refused"); n != 1 {
		t.Fatalf("%d log lines for 3 refusals within a minute", n)
	}
	clock = clock.Add(time.Minute)
	call(t, h, "", nil)
	if !strings.Contains(logs.String(), `"suppressed_since_last":2`) {
		t.Errorf("the count since the last line is missing: %s", logs.String())
	}
	if strings.Contains(logs.String(), "eyJ") {
		t.Error("a token reached the log")
	}
}

func TestNewGuardRefusesIncompleteConfig(t *testing.T) {
	mv, err := auth.NewMachineVerifier(context.Background(), auth.MachineConfig{
		Issuers: []auth.Source{{ID: issuer, Keys: newIssuer(t, issuer, "issuer", "tok-1").JWKS()}}, Audiences: []string{host},
	})
	if err != nil {
		t.Fatal(err)
	}
	bad := map[string]auth.GuardConfig{
		"no verifier":          {Problems: httpapi.WriteProblem, MTLSMode: config.MTLSOff},
		"no problem writer":    {Verifier: mv, MTLSMode: config.MTLSOff},
		"required, no subject": {Verifier: mv, Problems: httpapi.WriteProblem, MTLSMode: config.MTLSRequired},
		"unknown mode":         {Verifier: mv, Problems: httpapi.WriteProblem, MTLSMode: "optional"},
	}
	for name, c := range bad {
		if _, err := auth.NewGuard(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := auth.NewGuard(auth.GuardConfig{Verifier: mv, Problems: httpapi.WriteProblem, MTLSMode: config.MTLSRequired, ANSPMTLSSubject: subject}); err != nil {
		t.Errorf("a complete config: %v", err)
	}
}

func TestCallerFromEmptyContext(t *testing.T) {
	if auth.CallerFrom(context.Background()) != nil {
		t.Error("a caller in an empty context")
	}
}

func TestScopeTable(t *testing.T) {
	for ds, want := range map[string]string{"zones": auth.ScopePublishZones, "uspace_airspace": auth.ScopePublishUSpace,
		"ussp_list": auth.ScopePublishUSSPList, "restrictions": auth.ScopePublishRestrictions} {
		if got, ok := auth.PublishScope(publicationDataset(ds)); !ok || got != want {
			t.Errorf("%s: %s %v", ds, got, ok)
		}
	}
	if _, ok := auth.PublishScope("airports"); ok {
		t.Error("an unknown dataset has a scope")
	}
	for ds, want := range map[string]auth.Publisher{"zones": auth.PublisherAuthority, "ussp_list": auth.PublisherAuthority, "restrictions": auth.PublisherANSP} {
		if got, ok := auth.PublisherOf(publicationDataset(ds)); !ok || got != want {
			t.Errorf("%s: %s", ds, got)
		}
	}
	if _, ok := auth.PublisherOf("airports"); ok {
		t.Error("an unknown dataset has a publisher")
	}
}

func TestGuardConfigFrom(t *testing.T) {
	cfg := &config.API{AuthorityClientID: "authority-01", ANSPClientID: "ansp-01", MTLSMode: config.MTLSRequired, ANSPMTLSSubject: subject}
	cfg.StatusInterval = 30 * time.Second
	gc := auth.GuardConfigFrom(cfg, nil, httpapi.WriteProblem, nil, nil)
	if gc.AuthorityClientID != "authority-01" || gc.ANSPMTLSSubject != subject || gc.LogEvery != 30*time.Second {
		t.Errorf("%+v", gc)
	}
	mc := auth.MachineConfigFrom(&config.API{TokenIssuer: issuer, TokenJWKSURL: "https://a/jwks", LabIssuer: labIss, LabJWKSURL: "https://l/jwks", Audiences: []string{host}}, nil, nil)
	if len(mc.Issuers) != 2 || mc.Issuers[1].ID != labIss || mc.Audiences[0] != host {
		t.Errorf("%+v", mc)
	}
	if mc := auth.MachineConfigFrom(&config.API{TokenIssuer: issuer, TokenJWKSURL: "https://a/jwks"}, nil, nil); len(mc.Issuers) != 1 {
		t.Errorf("without a lab issuer: %+v", mc.Issuers)
	}
}

func publicationDataset(s string) publication.Dataset { return publication.Dataset(s) }
