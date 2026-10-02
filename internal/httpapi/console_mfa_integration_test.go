//go:build integration

package httpapi

import (
	"net/http"
	"testing"
	"time"

	"github.com/rootxkit/uspace-cisp/internal/auth"
	"github.com/rootxkit/uspace-cisp/internal/console"
	"github.com/rootxkit/uspace-cisp/internal/httpapi/gen"
)

// The two-step sign-in on PostgreSQL (Q41 (3), migration 0012): the
// password step stores the challenge's hash and an audit row and
// changes nothing on the account; a wrong code counts on the challenge
// and the account; the right code spends the challenge and writes the
// session; the spent challenge is refused; five wrong codes lock the
// account on the database's clock, and the right code is then 423.
func TestConsoleTwoStepSignInOnPostgres(t *testing.T) {
	st, _ := pgStore(t)
	h := newPubHarness(t, st)
	u := h.consoleUser(t, auth.RoleAdmin)
	ch := h.challengeFor(t, u)
	hash := console.ChallengeHash(ch.MfaToken)
	if n := pgCount(t, st, `SELECT count(*) FROM login_challenges WHERE token_hash = $1 AND account_id = $2 AND used_at IS NULL
		AND expires_at > now() AND expires_at <= now() + interval '5 minutes'`, hash, u.id); n != 1 {
		t.Fatalf("challenge row %d", n)
	}
	if n := pgCount(t, st, `SELECT count(*) FROM events WHERE event_type = 'login_challenge_issued' AND entity_id = $1`, u.id); n != 1 {
		t.Errorf("%d login_challenge_issued rows", n)
	}
	if n := pgCount(t, st, `SELECT count(*) FROM accounts WHERE id = $1 AND last_login_at IS NULL AND failed_logins = 0`, u.id); n != 1 {
		t.Error("the password step changed the account")
	}
	code, err := auth.TOTPCode(u.secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	bad := "000000"
	if code == bad {
		bad = "111111"
	}
	post := func(body map[string]any) (int, string) {
		req := h.consoleReq(http.MethodPost, "/v1/console/session/mfa", "", body)
		req.RemoteAddr = nextAddr()
		rec := h.consoleDo(t, req)
		if rec.Code >= 400 {
			return rec.Code, decodeProblem(t, rec).Type
		}
		return rec.Code, rec.Body.String()
	}
	if c, typ := post(map[string]any{"mfa_token": ch.MfaToken, "code": bad}); c != http.StatusUnauthorized || typ != ProblemTypeBase+console.SlugInvalidTOTP {
		t.Fatalf("wrong code: %d %s", c, typ)
	}
	if n := pgCount(t, st, `SELECT attempts FROM login_challenges WHERE token_hash = $1`, hash); n != 1 {
		t.Errorf("attempts %d", n)
	}
	if n := pgCount(t, st, `SELECT failed_logins FROM accounts WHERE id = $1`, u.id); n != 1 {
		t.Errorf("failed_logins %d", n)
	}
	req := h.consoleReq(http.MethodPost, "/v1/console/session/mfa", "", map[string]any{"mfa_token": ch.MfaToken, "code": code})
	req.RemoteAddr = nextAddr()
	rec := h.consoleDo(t, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("code step: %d %s", rec.Code, rec.Body.String())
	}
	s := decodeJSON[gen.ConsoleSession](t, rec)
	if n := pgCount(t, st, `SELECT count(*) FROM sessions WHERE jti = $1 AND account_id = $2`, sessionJTI(t, s.Token), u.id); n != 1 {
		t.Error("no session row")
	}
	if n := pgCount(t, st, `SELECT count(*) FROM login_challenges WHERE token_hash = $1 AND used_at IS NOT NULL`, hash); n != 1 {
		t.Error("the challenge was not spent")
	}
	if n := pgCount(t, st, `SELECT count(*) FROM accounts WHERE id = $1 AND failed_logins = 0 AND totp_last_step IS NOT NULL AND last_login_at IS NOT NULL`, u.id); n != 1 {
		t.Error("the account's sign-in was not written")
	}
	if n := pgCount(t, st, `SELECT count(*) FROM events WHERE event_type = 'session_issued' AND actor_id = $1 AND payload->>'challenge' = 'true'`, u.id); n != 1 {
		t.Errorf("%d session_issued rows from a challenge", n)
	}
	if rec := h.consoleDo(t, h.consoleReq(http.MethodGet, "/v1/console/me", s.Token, nil)); rec.Code != http.StatusOK {
		t.Errorf("me: %d", rec.Code)
	}
	if c, typ := post(map[string]any{"mfa_token": ch.MfaToken, "code": code}); c != http.StatusUnauthorized || typ != ProblemTypeBase+console.SlugChallengeInvalid {
		t.Errorf("spent challenge: %d %s", c, typ)
	}

	// Five wrong codes over two challenges lock the account.
	a, b := h.challengeFor(t, u), h.challengeFor(t, u)
	for i := range 5 {
		tok := a.MfaToken
		if i%2 == 1 {
			tok = b.MfaToken
		}
		if c, typ := post(map[string]any{"mfa_token": tok, "code": bad}); c != http.StatusUnauthorized || typ != ProblemTypeBase+console.SlugInvalidTOTP {
			t.Fatalf("wrong code %d: %d %s", i, c, typ)
		}
	}
	if n := pgCount(t, st, `SELECT count(*) FROM accounts WHERE id = $1 AND locked_until > now()`, u.id); n != 1 {
		t.Fatal("not locked after five wrong codes")
	}
	next, err := auth.TOTPCode(u.secret, time.Now().Add(auth.TOTPStep))
	if err != nil {
		t.Fatal(err)
	}
	req = h.consoleReq(http.MethodPost, "/v1/console/session/mfa", "", map[string]any{"mfa_token": b.MfaToken, "code": next})
	req.RemoteAddr = nextAddr()
	rec = h.consoleDo(t, req)
	if rec.Code != http.StatusLocked || rec.Header().Get("Retry-After") == "" {
		t.Errorf("locked: %d %q %s", rec.Code, rec.Header().Get("Retry-After"), rec.Body.String())
	}
}
