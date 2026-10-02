package console_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-cisp/internal/auth"
	"github.com/rootxkit/uspace-cisp/internal/console"
	"github.com/rootxkit/uspace-cisp/internal/store"
)

// The two-step sign-in (docs/PLAN.md section 15 Q41 (3)): the password
// step opens an MFA challenge for an account with MFA, VerifyMFA
// exchanges it and a TOTP code for a session. The uspace-authority's
// internal/authz contract: single use, expiring, bound to the account,
// stored by its hash; the per-account lockout counts the codes.

func (f *fixture) challenge(t *testing.T, username, password string) *console.Challenge {
	t.Helper()
	res, err := f.login(username, password, nil)
	if err != nil {
		t.Fatalf("password step: %v", err)
	}
	if res.Challenge == nil || res.Token != "" || res.JTI != "" {
		t.Fatalf("password step = %+v, want a challenge and no session", res)
	}
	return res.Challenge
}

func (f *fixture) verify(token string, code *string) (console.LoginResult, error) {
	c := ""
	if code != nil {
		c = *code
	}
	return f.acc.VerifyMFA(context.Background(), console.MFARequest{Challenge: token, Code: c})
}

func wrongCode(right *string) *string {
	bad := "000000"
	if *right == bad {
		bad = "111111"
	}
	return &bad
}

func (f *fixture) admin2(t *testing.T, name string) (console.Created, string) {
	t.Helper()
	c := f.create(t, name, auth.RoleAdmin, false)
	return c, secretOf(t, c.TOTPURL)
}

// The challenge carries a 256-bit token whose SHA-256 alone is stored,
// bound to the account, expiring after the TTL; it counts nothing and
// writes an audit row. The code step issues the session with its row
// and session_issued, resets the counter and spends the challenge: the
// same challenge again is challenge_invalid (E-01 pair).
func TestMFAChallengeExchange(t *testing.T) {
	f := newFixture(t, cheap)
	c, secret := f.admin2(t, "chief")
	now := f.st.Now()
	ch := f.challenge(t, "chief", c.Password)
	if len(ch.Token) != 43 || !ch.ExpiresAt.Equal(now.Add(console.DefaultChallengeTTL)) {
		t.Errorf("challenge %q expires %s", ch.Token, ch.ExpiresAt)
	}
	rows := f.st.Challenges()
	if len(rows) != 1 || rows[0].TokenHash != console.ChallengeHash(ch.Token) || rows[0].AccountID != c.Account.ID ||
		strings.Contains(rows[0].TokenHash, ch.Token) || rows[0].UsedAt != nil {
		t.Fatalf("stored %+v", rows)
	}
	if countEvents(f.st, console.EventChallengeIssued) != 1 || countEvents(f.st, console.EventSessionIssued) != 0 {
		t.Errorf("events %+v", f.st.Events())
	}

	res, err := f.verify(ch.Token, f.code(t, secret))
	if err != nil || res.Token == "" || res.JTI == "" || res.Challenge != nil || res.Account.ID != c.Account.ID {
		t.Fatalf("code step = %+v, %v", res, err)
	}
	if _, err := f.st.Session(context.Background(), res.JTI); err != nil {
		t.Errorf("session row: %v", err)
	}
	var issued *store.Event
	for _, e := range f.st.Events() {
		if e.EventType == console.EventSessionIssued {
			issued = &e
		}
	}
	if issued == nil || issued.Payload["challenge"] != true || issued.Payload["mfa"] != true {
		t.Errorf("session_issued %+v", issued)
	}
	if rows := f.st.Challenges(); rows[0].UsedAt == nil {
		t.Error("the challenge was not spent")
	}
	f.st.Advance(auth.TOTPStep)
	_, err = f.verify(ch.Token, f.code(t, secret))
	refusal(t, err, http.StatusUnauthorized, console.SlugChallengeInvalid)
}

// A wrong code keeps the challenge (the API bounds the attempts): it is
// invalid_totp, counts one attempt and one failure, and the right code
// on the same challenge then signs in. A code already used is
// totp_reused through a challenge as in one request.
func TestMFAWrongCodeKeepsTheChallenge(t *testing.T) {
	f := newFixture(t, cheap)
	c, secret := f.admin2(t, "chief")
	ch := f.challenge(t, "chief", c.Password)
	right := f.code(t, secret)
	_, err := f.verify(ch.Token, wrongCode(right))
	refusal(t, err, http.StatusUnauthorized, console.SlugInvalidTOTP)
	if acc, _ := f.st.Get(c.Account.ID); acc.FailedLogins != 1 {
		t.Errorf("failures %d, want 1", acc.FailedLogins)
	}
	if rows := f.st.Challenges(); rows[0].Attempts != 1 || rows[0].UsedAt != nil {
		t.Errorf("challenge %+v", rows[0])
	}
	if _, err := f.verify(ch.Token, right); err != nil {
		t.Fatalf("right code after a wrong one: %v", err)
	}
	if acc, _ := f.st.Get(c.Account.ID); acc.FailedLogins != 0 {
		t.Errorf("failures %d after a sign-in, want 0", acc.FailedLogins)
	}
	// The code just used, on a new challenge in the same step.
	ch = f.challenge(t, "chief", c.Password)
	_, err = f.verify(ch.Token, right)
	refusal(t, err, http.StatusUnauthorized, console.SlugTOTPReused)
}

// Expiry on the database's clock: a second before expires_at the code
// signs in, at expires_at the challenge is challenge_invalid.
func TestMFAChallengeExpires(t *testing.T) {
	f := newFixture(t, cheap)
	c, secret := f.admin2(t, "chief")
	ch := f.challenge(t, "chief", c.Password)
	f.st.Advance(console.DefaultChallengeTTL - time.Second)
	if _, err := f.verify(ch.Token, f.code(t, secret)); err != nil {
		t.Fatalf("a second before expiry: %v", err)
	}
	ch = f.challenge(t, "chief", c.Password)
	f.st.Advance(console.DefaultChallengeTTL + auth.TOTPStep)
	_, err := f.verify(ch.Token, f.code(t, secret))
	ce := refusal(t, err, http.StatusUnauthorized, console.SlugChallengeInvalid)
	if ce.Field != "mfa_token" || !strings.Contains(ce.Detail, "expired") {
		t.Errorf("refusal %+v", ce)
	}
	if countEvents(f.st, console.EventLoginFailed) != 1 {
		t.Errorf("an expired challenge is not audited: %+v", f.st.Events())
	}
}

// A challenge takes MaxChallengeAttempts wrong codes; then even the
// right code is challenge_invalid. One fewer, and the right code signs
// in (E-10: the bound is exceeded, and its pair).
func TestMFAChallengeExhausted(t *testing.T) {
	f := newFixture(t, cheap)
	acc, err := console.NewAccounts(console.Config{Store: f.st, Sessions: f.issuer, Sealer: mustSealer(t), Argon2: cheap, MaxChallengeAttempts: 2, MaxFailedLogins: 10})
	if err != nil {
		t.Fatal(err)
	}
	f.acc = acc
	c, secret := f.admin2(t, "chief")
	ch := f.challenge(t, "chief", c.Password)
	right := f.code(t, secret)
	_, err = f.verify(ch.Token, wrongCode(right))
	refusal(t, err, http.StatusUnauthorized, console.SlugInvalidTOTP)
	if _, err := f.verify(ch.Token, right); err != nil {
		t.Fatalf("one wrong code under the bound: %v", err)
	}
	f.st.Advance(auth.TOTPStep)
	right = f.code(t, secret)
	ch = f.challenge(t, "chief", c.Password)
	for range 2 {
		_, err = f.verify(ch.Token, wrongCode(right))
		refusal(t, err, http.StatusUnauthorized, console.SlugInvalidTOTP)
	}
	_, err = f.verify(ch.Token, right)
	ce := refusal(t, err, http.StatusUnauthorized, console.SlugChallengeInvalid)
	if !strings.Contains(ce.Detail, "too many") {
		t.Errorf("refusal %+v", ce)
	}
}

// The per-account lockout holds across challenges: five wrong codes
// lock the account; a challenge opened before the lock is then 423
// locked even with the right code, and the password step is too. The
// password step resets nothing: two wrong codes, a new password step,
// and the counter still reads two.
func TestMFALockoutAcrossChallenges(t *testing.T) {
	f := newFixture(t, cheap)
	c, secret := f.admin2(t, "chief")
	a := f.challenge(t, "chief", c.Password)
	right := f.code(t, secret)
	for range 2 {
		_, err := f.verify(a.Token, wrongCode(right))
		refusal(t, err, http.StatusUnauthorized, console.SlugInvalidTOTP)
	}
	b := f.challenge(t, "chief", c.Password)
	if acc, _ := f.st.Get(c.Account.ID); acc.FailedLogins != 2 {
		t.Fatalf("the password step changed the counter to %d", acc.FailedLogins)
	}
	for range 3 {
		_, err := f.verify(a.Token, wrongCode(right))
		refusal(t, err, http.StatusUnauthorized, console.SlugInvalidTOTP)
	}
	if countEvents(f.st, console.EventAccountLocked) != 1 {
		t.Fatalf("no lock after five wrong codes: %+v", f.st.Events())
	}
	_, err := f.verify(b.Token, right)
	ce := refusal(t, err, http.StatusLocked, console.SlugLocked)
	if ce.RetryAfter != console.DefaultLockout {
		t.Errorf("retry after %s", ce.RetryAfter)
	}
	_, err = f.login("chief", c.Password, nil)
	refusal(t, err, http.StatusLocked, console.SlugLocked)
	// The pair: after the lockout the two steps sign in.
	f.st.Advance(console.DefaultLockout)
	ch := f.challenge(t, "chief", c.Password)
	if _, err := f.verify(ch.Token, f.code(t, secret)); err != nil {
		t.Fatalf("after the lockout: %v", err)
	}
}

// Unknown, empty and over-long challenges are challenge_invalid before
// any account is touched; a disabled account's challenge too. An
// enrolled account gets a challenge; one with MFA and no authenticator
// stays mfa_required (E-01 pair). A store that fails is an error, not a
// refusal.
func TestMFARefusals(t *testing.T) {
	f := newFixture(t, cheap)
	code := "123456"
	for name, tok := range map[string]string{"unknown": "AAAA", "empty": "", "long": strings.Repeat("a", console.MaxChallengeTokenBytes+1)} {
		_, err := f.verify(tok, &code)
		if ce := refusal(t, err, http.StatusUnauthorized, console.SlugChallengeInvalid); ce.Field != "mfa_token" {
			t.Errorf("%s: field %q", name, ce.Field)
		}
	}
	if n := len(f.st.Events()); n != 0 {
		t.Errorf("%d events for unknown challenges", n)
	}

	c, secret := f.admin2(t, "chief")
	ch := f.challenge(t, "chief", c.Password)
	f.admin2(t, "deputy") // the last-admin invariant lets chief be disabled
	disabled := console.StatusDisabled
	if _, err := f.acc.Patch(context.Background(), f.admin, c.Account.ID, console.Patch{Status: &disabled}); err != nil {
		t.Fatal(err)
	}
	_, err := f.verify(ch.Token, f.code(t, secret))
	refusal(t, err, http.StatusUnauthorized, console.SlugChallengeInvalid)

	f.st.Put(store.Account{ID: "acc-noauth", Username: "noauth", PasswordHash: c.Account.PasswordHash, Role: auth.RoleViewer, MFARequired: true, Status: console.StatusActive})
	_, err = f.login("noauth", c.Password, nil)
	refusal(t, err, http.StatusUnauthorized, console.SlugMFARequired)

	f.st.SetFail(errors.New("database down"))
	_, err = f.verify("AAAA", &code)
	var ce *console.Error
	if err == nil || errors.As(err, &ce) {
		t.Errorf("store down: %v", err)
	}
	f.st.SetFail(nil)
}

// A code step without a code (the body requires one) is mfa_required and
// no failure; the challenge stays usable.
func TestMFAEmptyCodeIsNotAFailure(t *testing.T) {
	f := newFixture(t, cheap)
	c, secret := f.admin2(t, "chief")
	ch := f.challenge(t, "chief", c.Password)
	_, err := f.verify(ch.Token, nil)
	refusal(t, err, http.StatusUnauthorized, console.SlugMFARequired)
	if acc, _ := f.st.Get(c.Account.ID); acc.FailedLogins != 0 {
		t.Errorf("failures %d", acc.FailedLogins)
	}
	if _, err := f.verify(ch.Token, f.code(t, secret)); err != nil {
		t.Fatalf("after an empty code: %v", err)
	}
}

// E-10: a new challenge deletes its account's spent and expired ones in
// the same write; a live one stays (the pair), and another account's
// are not touched.
func TestMFAChallengesStayBounded(t *testing.T) {
	f := newFixture(t, cheap)
	c, secret := f.admin2(t, "chief")
	o, _ := f.admin2(t, "deputy")
	used := f.challenge(t, "chief", c.Password)
	if _, err := f.verify(used.Token, f.code(t, secret)); err != nil {
		t.Fatal(err)
	}
	f.challenge(t, "deputy", o.Password)
	f.challenge(t, "chief", c.Password)
	f.st.Advance(console.DefaultChallengeTTL)
	f.challenge(t, "chief", c.Password)
	f.challenge(t, "chief", c.Password)
	mine, theirs := 0, 0
	for _, r := range f.st.Challenges() {
		switch r.AccountID {
		case c.Account.ID:
			mine++
			if r.UsedAt != nil || !r.ExpiresAt.After(f.st.Now()) {
				t.Errorf("a spent challenge stayed: %+v", r)
			}
		case o.Account.ID:
			theirs++
		}
	}
	if mine != 2 || theirs != 1 {
		t.Errorf("challenges: %d of chief (want the 2 live), %d of deputy (want 1)", mine, theirs)
	}
}

// A password hashed with older parameters is re-hashed at the password
// step, which issues no session.
func TestMFAPasswordStepRehashes(t *testing.T) {
	f := newFixture(t, auth.DefaultArgon2)
	old, err := auth.HashPassword("correct horse", cheap)
	if err != nil {
		t.Fatal(err)
	}
	c := f.create(t, "legacy-admin", auth.RoleAdmin, false)
	a, _ := f.st.Get(c.Account.ID)
	a.PasswordHash, a.FailedLogins = old, 2
	f.st.Put(a)
	f.challenge(t, "legacy-admin", "correct horse")
	got, _ := f.st.Get(c.Account.ID)
	if got.PasswordHash == old || got.FailedLogins != 2 || got.LastLoginAt != nil {
		t.Errorf("after the password step: hash changed %v, failures %d, last login %v", got.PasswordHash != old, got.FailedLogins, got.LastLoginAt)
	}
}

func mustSealer(t *testing.T) *console.Sealer {
	t.Helper()
	s, err := console.NewSealer(k32())
	if err != nil {
		t.Fatal(err)
	}
	return s
}
