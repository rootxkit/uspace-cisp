package httpapi

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-cisp/internal/auth"
	"github.com/rootxkit/uspace-cisp/internal/console"
	"github.com/rootxkit/uspace-cisp/internal/httpapi/gen"
)

// The two-step sign-in over HTTP (docs/PLAN.md section 15 Q41 (3)), in
// the shape the kit's BFF sends: POST /v1/console/session {username,
// password} answers 200 {mfa_token, expires_at} for an account with
// MFA, and POST /v1/console/session/mfa {mfa_token, code} answers the
// session (201). Every exchange is checked against api/openapi.yaml.
func TestConsoleLoginTwoSteps(t *testing.T) {
	h := newPubHarness(t, nil)
	u := h.consoleUser(t, auth.RoleAdmin)
	before := time.Now()
	ch := h.challengeFor(t, u)
	if len(ch.MfaToken) < 43 || ch.ExpiresAt.Before(before.Add(console.DefaultChallengeTTL-time.Minute)) {
		t.Fatalf("challenge %+v", ch)
	}
	if h.counter("console", CounterConsoleMFA) != 1 || h.counter("console", CounterConsoleLogins) != 0 {
		t.Errorf("counters: challenges %d, sessions %d", h.counter("console", CounterConsoleMFA), h.counter("console", CounterConsoleLogins))
	}
	code, err := auth.TOTPCode(u.secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// A wrong code first: 401 invalid_totp, and the challenge stays.
	bad := "000000"
	if code == bad {
		bad = "111111"
	}
	rec := h.consoleDo(t, h.consoleReq(http.MethodPost, "/v1/console/session/mfa", "", map[string]any{"mfa_token": ch.MfaToken, "code": bad}))
	if rec.Code != http.StatusUnauthorized || decodeProblem(t, rec).Type != ProblemTypeBase+console.SlugInvalidTOTP {
		t.Fatalf("wrong code: %d %s", rec.Code, rec.Body.String())
	}
	rec = h.consoleDo(t, h.consoleReq(http.MethodPost, "/v1/console/session/mfa", "", map[string]any{"mfa_token": ch.MfaToken, "code": code}))
	if rec.Code != http.StatusCreated {
		t.Fatalf("code step: %d %s", rec.Code, rec.Body.String())
	}
	s := decodeJSON[gen.ConsoleSession](t, rec)
	if s.Token == "" || s.Account.Username != u.username || s.Account.Role != "admin" || s.Account.FailedLogins != 0 {
		t.Errorf("session %+v", s)
	}
	me := h.consoleDo(t, h.consoleReq(http.MethodGet, "/v1/console/me", s.Token, nil))
	if me.Code != http.StatusOK || decodeJSON[gen.ConsoleMe](t, me).Account.Username != u.username {
		t.Fatalf("me: %d %s", me.Code, me.Body.String())
	}
	// Single use: the same challenge again is challenge_invalid.
	rec = h.consoleDo(t, h.consoleReq(http.MethodPost, "/v1/console/session/mfa", "", map[string]any{"mfa_token": ch.MfaToken, "code": code}))
	p := decodeProblem(t, rec)
	if rec.Code != http.StatusUnauthorized || p.Type != ProblemTypeBase+console.SlugChallengeInvalid {
		t.Errorf("reused challenge: %d %s", rec.Code, rec.Body.String())
	}
	if p.Errors == nil || len(*p.Errors) != 1 || (*p.Errors)[0].Field != "mfa_token" {
		t.Errorf("problem errors %+v", p.Errors)
	}
	// An unknown challenge, the same.
	rec = h.consoleDo(t, h.consoleReq(http.MethodPost, "/v1/console/session/mfa", "", map[string]any{"mfa_token": "not-a-challenge", "code": code}))
	if rec.Code != http.StatusUnauthorized || decodeProblem(t, rec).Type != ProblemTypeBase+console.SlugChallengeInvalid {
		t.Errorf("unknown challenge: %d %s", rec.Code, rec.Body.String())
	}
	if h.counter("console", CounterConsoleLogins) != 1 || h.counter("console", CounterConsoleRefused) != 3 {
		t.Errorf("counters: sessions %d, refused %d", h.counter("console", CounterConsoleLogins), h.counter("console", CounterConsoleRefused))
	}
	// An account without MFA still signs in in one request (the pair).
	v := h.consoleUser(t, auth.RoleViewer)
	rec = h.consoleDo(t, h.consoleReq(http.MethodPost, "/v1/console/session", "", h.loginBody(t, v, 0)))
	if rec.Code != http.StatusCreated || decodeJSON[gen.ConsoleSession](t, rec).Token == "" {
		t.Errorf("viewer: %d %s", rec.Code, rec.Body.String())
	}
}

// The code step's request is the spec's: a missing or out-of-bounds
// member, or a code that is not six digits, is 400 before any account
// is read, a body that is not JSON 415, one
// over the console cap 413 (E-10), each beside the accepted request.
func TestConsoleMFARequestShape(t *testing.T) {
	h := newPubHarness(t, nil)
	u := h.consoleUser(t, auth.RoleAdmin)
	for name, body := range map[string]map[string]any{
		"no code":      {"mfa_token": "x"},
		"no challenge": {"code": "123456"},
		"letters":      {"mfa_token": "x", "code": "12345a"},
		"long token":   {"mfa_token": strings.Repeat("a", 257), "code": "123456"},
		"seven digits": {"mfa_token": "x", "code": "1234567"},
		"empty token":  {"mfa_token": "", "code": "123456"},
	} {
		req := h.consoleReq(http.MethodPost, "/v1/console/session/mfa", "", body)
		req.RemoteAddr = nextAddr()
		// The request breaks the spec on purpose: no conformance check.
		rec := httptestDo(h, req)
		if rec.Code != http.StatusBadRequest || decodeProblem(t, rec).Type != ProblemTypeBase+"bad_request" {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
	req := h.consoleReq(http.MethodPost, "/v1/console/session/mfa", "", h.mfaBody(t, u))
	req.Header.Set("Content-Type", "text/plain")
	if rec := httptestDo(h, req); rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("text/plain: %d", rec.Code)
	}
	big := map[string]any{"mfa_token": strings.Repeat("a", MaxConsoleBodyBytes), "code": "123456"}
	if rec := httptestDo(h, h.consoleReq(http.MethodPost, "/v1/console/session/mfa", "", big)); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("over the cap: %d", rec.Code)
	}
	req = h.consoleReq(http.MethodPost, "/v1/console/session/mfa", "", h.mfaBody(t, u))
	req.RemoteAddr = nextAddr()
	if rec := h.consoleDo(t, req); rec.Code != http.StatusCreated {
		t.Errorf("the accepted twin: %d %s", rec.Code, rec.Body.String())
	}
}

// The login limiter counts both steps of one address together: LoginBurst
// requests of either step pass, the next of either is 429 with
// Retry-After, and another address is not affected (the pair).
func TestConsoleLoginLimiterCountsBothSteps(t *testing.T) {
	h := newPubHarness(t, nil)
	addr := nextAddr()
	send := func(path string, body map[string]any, from string) int {
		req := h.consoleReq(http.MethodPost, path, "", body)
		req.RemoteAddr = from
		return httptestDo(h, req).Code
	}
	half := LoginBurst / 2
	for i := range half {
		if code := send("/v1/console/session", map[string]any{"username": "nobody", "password": "p"}, addr); code != http.StatusUnauthorized {
			t.Fatalf("password step %d: %d", i, code)
		}
	}
	for i := range LoginBurst - half {
		if code := send("/v1/console/session/mfa", map[string]any{"mfa_token": "unknown", "code": "123456"}, addr); code != http.StatusUnauthorized {
			t.Fatalf("code step %d: %d", i, code)
		}
	}
	req := h.consoleReq(http.MethodPost, "/v1/console/session/mfa", "", map[string]any{"mfa_token": "unknown", "code": "123456"})
	req.RemoteAddr = addr
	rec := httptestDo(h, req)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Errorf("over the burst: %d %q", rec.Code, rec.Header().Get("Retry-After"))
	}
	if code := send("/v1/console/session", map[string]any{"username": "nobody", "password": "p"}, addr); code != http.StatusTooManyRequests {
		t.Errorf("password step over the burst: %d", code)
	}
	if code := send("/v1/console/session/mfa", map[string]any{"mfa_token": "unknown", "code": "123456"}, nextAddr()); code != http.StatusUnauthorized {
		t.Errorf("another address: %d", code)
	}
}

// The account store unreachable between the two steps: the code step is
// 503 database_unavailable with Retry-After, nothing is spent, and with
// the store back the same challenge signs in (E-02 and its pair).
func TestConsoleMFAStoreDown(t *testing.T) {
	h := newPubHarness(t, nil)
	u := h.consoleUser(t, auth.RoleAdmin)
	body := h.mfaBody(t, u)
	h.accounts.SetFail(io.ErrUnexpectedEOF)
	req := h.consoleReq(http.MethodPost, "/v1/console/session/mfa", "", body)
	req.RemoteAddr = nextAddr()
	rec := h.consoleDo(t, req)
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" ||
		decodeProblem(t, rec).Type != ProblemTypeBase+SlugDatabaseUnavailable {
		t.Errorf("store down: %d %s", rec.Code, rec.Body.String())
	}
	h.accounts.SetFail(nil)
	req = h.consoleReq(http.MethodPost, "/v1/console/session/mfa", "", body)
	req.RemoteAddr = nextAddr()
	if rec := h.consoleDo(t, req); rec.Code != http.StatusCreated {
		t.Errorf("store back: %d %s", rec.Code, rec.Body.String())
	}
}
