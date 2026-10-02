package console_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	coreauth "github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-cisp/internal/auth"
	"github.com/rootxkit/uspace-cisp/internal/authtest"
	"github.com/rootxkit/uspace-cisp/internal/console"
	"github.com/rootxkit/uspace-cisp/internal/console/consoletest"
	"github.com/rootxkit/uspace-cisp/internal/store"
)

const (
	consoleIssuer = "https://cisp.example.test/console"
	ownHost       = "cisp.example.test"
)

// cheap are argon2id parameters fast enough for unit tests; the
// production set is exercised by the upgrade test.
var cheap = auth.Argon2Params{MemoryKiB: 64, Iterations: 1, Lanes: 1}

type revoked struct{ jtis []string }

func (r *revoked) Add(j string) { r.jtis = append(r.jtis, j) }

type fixture struct {
	st      *consoletest.Store
	acc     *console.Accounts
	issuer  *auth.SessionIssuer
	revoked *revoked
	admin   console.Actor
}

func newFixture(t *testing.T, params auth.Argon2Params) *fixture {
	t.Helper()
	st := consoletest.New(time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC))
	is, err := auth.NewSessionIssuer(authtest.Key(t, "session", 2048), consoleIssuer, ownHost)
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := console.NewSealer(k32())
	if err != nil {
		t.Fatal(err)
	}
	rv := &revoked{}
	acc, err := console.NewAccounts(console.Config{Store: st, Sessions: is, Sealer: sealer, Revoker: rv, Argon2: params})
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{st: st, acc: acc, issuer: is, revoked: rv, admin: console.Actor{ID: "root", Role: auth.RoleAdmin, Type: store.ActorSystem}}
}

func (f *fixture) create(t *testing.T, username, role string, mfa bool) console.Created {
	t.Helper()
	c, err := f.acc.Create(context.Background(), f.admin, username, role, mfa)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (f *fixture) login(username, password string, totp *string) (console.LoginResult, error) {
	return f.acc.Login(context.Background(), console.LoginRequest{Username: username, Password: password, TOTP: totp})
}

func refusal(t *testing.T, err error, status int, slug string) *console.Error {
	t.Helper()
	var ce *console.Error
	if !errors.As(err, &ce) || ce.Status != status || ce.Slug != slug {
		t.Fatalf("err = %v (%+v), want %d %s", err, ce, status, slug)
	}
	return ce
}

func secretOf(t *testing.T, otpauth string) string {
	t.Helper()
	u, err := url.Parse(otpauth)
	if err != nil {
		t.Fatal(err)
	}
	s := u.Query().Get("secret")
	if s == "" {
		t.Fatalf("no secret in %s", otpauth)
	}
	return s
}

func (f *fixture) code(t *testing.T, secret string) *string {
	t.Helper()
	now, _ := f.st.DatabaseNow(context.Background())
	c, err := auth.TOTPCode(secret, now)
	if err != nil {
		t.Fatal(err)
	}
	return &c
}

func countEvents(st *consoletest.Store, typ string) int {
	n := 0
	for _, e := range st.Events() {
		if e.EventType == typ {
			n++
		}
	}
	return n
}

// A login issues a session in the one shape (M20) the shared verifier
// accepts under StrictSessionClaims, with its row and its audit row;
// the wrong password beside it is refused (E-01).
func TestLoginIssuesASession(t *testing.T) {
	f := newFixture(t, cheap)
	c := f.create(t, "Operator.One", auth.RoleViewer, false)
	if c.Account.Username != "operator.one" || c.TOTPURL != "" || len(c.Password) != 32 {
		t.Fatalf("created %+v", c)
	}
	if _, err := f.login("operator.one", c.Password+"x", nil); err == nil {
		t.Fatal("a wrong password logged in")
	}
	res, err := f.login("OPERATOR.ONE", c.Password, nil)
	if err != nil {
		t.Fatal(err)
	}
	v, err := coreauth.NewVerifier(context.Background(), coreauth.Config{
		Issuers:  map[string]coreauth.IssuerConfig{consoleIssuer: {Keys: f.issuer.Source().Keys}},
		Audience: ownHost, StrictSessionClaims: true,
		Now: func() time.Time { return res.ExpiresAt.Add(-time.Hour) },
	})
	if err != nil {
		t.Fatal(err)
	}
	cl, err := v.Verify(context.Background(), res.Token)
	if err != nil {
		t.Fatal(err)
	}
	if cl.Subject != c.Account.ID || cl.Realm != auth.ConsoleRealm || len(cl.Roles) != 1 || cl.Roles[0] != auth.RoleViewer ||
		len(cl.Scopes) != 1 || cl.Scopes[0] != coreauth.SessionScope || cl.JTI != res.JTI || cl.KeyID != f.issuer.KID() {
		t.Errorf("claims %+v", cl)
	}
	if got := cl.ExpiresAt.Sub(cl.IssuedAt); got != auth.SessionTTL {
		t.Errorf("ttl %s", got)
	}
	sess, err := f.st.Session(context.Background(), res.JTI)
	if err != nil || !sess.ExpiresAt.Equal(res.ExpiresAt) {
		t.Errorf("session row %+v %v", sess, err)
	}
	if countEvents(f.st, console.EventSessionIssued) != 1 || countEvents(f.st, console.EventLoginFailed) != 1 {
		t.Errorf("events %+v", f.st.Events())
	}
	acc, _ := f.st.Get(c.Account.ID)
	if acc.FailedLogins != 0 || acc.LastLoginAt == nil {
		t.Errorf("account after login %+v", acc)
	}
}

// Five failures lock the account for 15 minutes on the store's clock;
// the sixth attempt with the right password is 423 locked with
// Retry-After; once the lockout has passed the right password works.
func TestLoginLockout(t *testing.T) {
	f := newFixture(t, cheap)
	c := f.create(t, "locked", auth.RoleViewer, false)
	for i := 1; i <= console.DefaultMaxFailedLogins; i++ {
		_, err := f.login("locked", "wrong", nil)
		refusal(t, err, http.StatusUnauthorized, console.SlugInvalidCredentials)
	}
	acc, _ := f.st.Get(c.Account.ID)
	if acc.LockedUntil == nil || acc.FailedLogins != 0 {
		t.Fatalf("after five failures %+v", acc)
	}
	_, err := f.login("locked", c.Password, nil)
	ce := refusal(t, err, http.StatusLocked, console.SlugLocked)
	if ce.RetryAfter != console.DefaultLockout || console.RetryAfterSeconds(ce.RetryAfter) != "900" {
		t.Errorf("retry after %s", ce.RetryAfter)
	}
	if countEvents(f.st, console.EventAccountLocked) != 1 || countEvents(f.st, console.EventLoginFailed) != 5 {
		t.Errorf("events %+v", f.st.Events())
	}
	f.st.Advance(console.DefaultLockout - time.Second)
	_, err = f.login("locked", c.Password, nil)
	refusal(t, err, http.StatusLocked, console.SlugLocked)
	f.st.Advance(time.Second)
	if _, err := f.login("locked", c.Password, nil); err != nil {
		t.Fatalf("after the lockout: %v", err)
	}
}

// An unknown and a disabled username are refused as a wrong password
// is; an over-long one too, before any work.
func TestLoginUnknownAndDisabled(t *testing.T) {
	f := newFixture(t, cheap)
	c := f.create(t, "gone", auth.RoleViewer, false)
	_, err := f.login("nobody", "x", nil)
	refusal(t, err, http.StatusUnauthorized, console.SlugInvalidCredentials)
	_, err = f.login(strings.Repeat("a", 65), "x", nil)
	refusal(t, err, http.StatusUnauthorized, console.SlugInvalidCredentials)
	_, err = f.login("gone", strings.Repeat("p", auth.MaxPasswordBytes+1), nil)
	refusal(t, err, http.StatusUnauthorized, console.SlugInvalidCredentials)
	disabled := console.StatusDisabled
	if _, err := f.acc.Patch(context.Background(), f.admin, c.Account.ID, console.Patch{Status: &disabled}); err != nil {
		t.Fatal(err)
	}
	_, err = f.login("gone", c.Password, nil)
	refusal(t, err, http.StatusUnauthorized, console.SlugInvalidCredentials)
}

// MFA: an admin always has it; without a code the login is
// mfa_required and not a failure; a valid code logs in; the same code
// again is totp_reused; a wrong code invalid_totp; the next step's code
// is accepted (E-01 pairs).
func TestLoginTOTP(t *testing.T) {
	f := newFixture(t, cheap)
	c := f.create(t, "chief", auth.RoleAdmin, false)
	if !c.Account.MFARequired || c.TOTPURL == "" || len(c.Account.TOTPSecretEnc) == 0 {
		t.Fatalf("admin created without MFA: %+v", c)
	}
	secret := secretOf(t, c.TOTPURL)
	_, err := f.login("chief", c.Password, nil)
	refusal(t, err, http.StatusUnauthorized, console.SlugMFARequired)
	if acc, _ := f.st.Get(c.Account.ID); acc.FailedLogins != 0 {
		t.Errorf("a missing code counted as a failure: %d", acc.FailedLogins)
	}
	code := f.code(t, secret)
	if _, err := f.login("chief", c.Password, code); err != nil {
		t.Fatalf("valid code: %v", err)
	}
	_, err = f.login("chief", c.Password, code)
	refusal(t, err, http.StatusUnauthorized, console.SlugTOTPReused)
	bad := "000000"
	if *code == bad {
		bad = "111111"
	}
	_, err = f.login("chief", c.Password, &bad)
	refusal(t, err, http.StatusUnauthorized, console.SlugInvalidTOTP)
	notDigits := "12345a"
	_, err = f.login("chief", c.Password, &notDigits)
	refusal(t, err, http.StatusUnauthorized, console.SlugInvalidTOTP)
	if acc, _ := f.st.Get(c.Account.ID); acc.FailedLogins != 3 {
		t.Errorf("failures counted %d, want 3 (reused, wrong, malformed)", acc.FailedLogins)
	}
	f.st.Advance(auth.TOTPStep)
	if _, err := f.login("chief", c.Password, f.code(t, secret)); err != nil {
		t.Fatalf("next step's code: %v", err)
	}
}

// A hash made with older parameters is re-hashed with the current ones
// on the next successful login; the stored hash is read back.
func TestLoginUpgradesTheHash(t *testing.T) {
	f := newFixture(t, auth.DefaultArgon2)
	old, err := auth.HashPassword("correct horse", cheap)
	if err != nil {
		t.Fatal(err)
	}
	f.st.Put(store.Account{ID: "acc-old", Username: "legacy", PasswordHash: old, Role: auth.RoleViewer, Status: console.StatusActive})
	if _, err := f.login("legacy", "correct horse", nil); err != nil {
		t.Fatal(err)
	}
	acc, _ := f.st.Get("acc-old")
	if acc.PasswordHash == old || !strings.HasPrefix(acc.PasswordHash, "$argon2id$v=19$m=65536,t=3,p=4$") {
		t.Fatalf("stored hash %q", acc.PasswordHash)
	}
	ok, rehash, err := auth.VerifyPassword(acc.PasswordHash, "correct horse", auth.DefaultArgon2)
	if !ok || rehash || err != nil {
		t.Errorf("re-hashed hash: ok %v rehash %v err %v", ok, rehash, err)
	}
	// A current hash is not re-hashed (the pair).
	before := acc.PasswordHash
	if _, err := f.login("legacy", "correct horse", nil); err != nil {
		t.Fatal(err)
	}
	if acc, _ := f.st.Get("acc-old"); acc.PasswordHash != before {
		t.Error("a current hash was re-hashed")
	}
}

// A stored hash that does not parse is an error, not a login and not a
// panic.
func TestLoginBrokenHash(t *testing.T) {
	f := newFixture(t, cheap)
	f.st.Put(store.Account{ID: "acc-x", Username: "broken", PasswordHash: "$argon2id$garbage", Role: auth.RoleViewer, Status: console.StatusActive})
	_, err := f.login("broken", "x", nil)
	var ce *console.Error
	if err == nil || errors.As(err, &ce) {
		t.Fatalf("err = %v", err)
	}
}

func TestCreateRefusals(t *testing.T) {
	f := newFixture(t, cheap)
	f.create(t, "taken", auth.RoleViewer, false)
	for name, c := range map[string]struct {
		username, role string
		status         int
		slug           string
	}{
		"short username": {"ab", auth.RoleViewer, http.StatusBadRequest, "bad_request"},
		"bad username":   {"a b c", auth.RoleViewer, http.StatusBadRequest, "bad_request"},
		"unknown role":   {"someone", "owner", http.StatusBadRequest, "bad_request"},
		"taken":          {"TAKEN", auth.RoleViewer, http.StatusConflict, console.SlugUsernameTaken},
	} {
		_, err := f.acc.Create(context.Background(), f.admin, c.username, c.role, false)
		var ce *console.Error
		if !errors.As(err, &ce) || ce.Status != c.status || ce.Slug != c.slug {
			t.Errorf("%s: %v", name, err)
		}
	}
	mfa := f.create(t, "careful", auth.RolePublisherAdmin, true)
	if !mfa.Account.MFARequired || mfa.TOTPURL == "" {
		t.Errorf("mfa asked for: %+v", mfa)
	}
	if n := countEvents(f.st, console.EventAccountCreated); n != 2 {
		t.Errorf("%d account_created rows", n)
	}
	f.st.Fail = consoletest.ErrDown
	if _, err := f.acc.Create(context.Background(), f.admin, "later", auth.RoleViewer, false); !errors.Is(err, consoletest.ErrDown) {
		t.Errorf("store down: %v", err)
	}
}

// The last active admin can be neither demoted nor disabled; with a
// second admin both are allowed (E-01).
func TestPatchLastAdmin(t *testing.T) {
	f := newFixture(t, cheap)
	a := f.create(t, "admin-one", auth.RoleAdmin, false)
	viewer := auth.RoleViewer
	disabled := console.StatusDisabled
	for _, p := range []console.Patch{{Role: &viewer}, {Status: &disabled}} {
		_, err := f.acc.Patch(context.Background(), f.admin, a.Account.ID, p)
		refusal(t, err, http.StatusConflict, console.SlugLastAdmin)
	}
	f.create(t, "admin-two", auth.RoleAdmin, false)
	p, err := f.acc.Patch(context.Background(), f.admin, a.Account.ID, console.Patch{Role: &viewer})
	if err != nil {
		t.Fatal(err)
	}
	if p.Account.Role != auth.RoleViewer || !p.Account.MFARequired {
		t.Errorf("demoted %+v", p.Account)
	}
}

// A changed role or status revokes the account's open sessions (and
// tells the cache); a reset gives a new secret once; a promotion to
// admin enrols MFA.
func TestPatchRevokesAndResets(t *testing.T) {
	f := newFixture(t, cheap)
	f.create(t, "root", auth.RoleAdmin, false)
	c := f.create(t, "worker", auth.RoleViewer, false)
	res, err := f.login("worker", c.Password, nil)
	if err != nil {
		t.Fatal(err)
	}
	// No change, no revocation.
	same := auth.RoleViewer
	if p, err := f.acc.Patch(context.Background(), f.admin, c.Account.ID, console.Patch{Role: &same}); err != nil || len(p.Revoked) != 0 {
		t.Fatalf("no-op patch %+v %v", p, err)
	}
	pa := auth.RolePublisherAdmin
	p, err := f.acc.Patch(context.Background(), f.admin, c.Account.ID, console.Patch{Role: &pa})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Revoked) != 1 || p.Revoked[0] != res.JTI || len(f.revoked.jtis) != 1 {
		t.Errorf("revoked %v, cache told %v", p.Revoked, f.revoked.jtis)
	}
	if rv, _ := f.st.SessionRevoked(context.Background(), res.JTI); !rv {
		t.Error("the session is not revoked")
	}
	r, err := f.acc.Patch(context.Background(), f.admin, c.Account.ID, console.Patch{ResetMFA: true})
	if err != nil || r.TOTPURL == "" || len(r.Account.TOTPSecretEnc) == 0 {
		t.Fatalf("reset %+v %v", r, err)
	}
	r2, err := f.acc.Patch(context.Background(), f.admin, c.Account.ID, console.Patch{ResetMFA: true})
	if err != nil || secretOf(t, r2.TOTPURL) == secretOf(t, r.TOTPURL) {
		t.Errorf("a second reset kept the secret: %v", err)
	}
	admin := auth.RoleAdmin
	promoted := f.create(t, "rising", auth.RoleViewer, false)
	pr, err := f.acc.Patch(context.Background(), f.admin, promoted.Account.ID, console.Patch{Role: &admin})
	if err != nil || !pr.Account.MFARequired || pr.TOTPURL == "" {
		t.Errorf("promotion %+v %v", pr, err)
	}
	bad := "owner"
	_, err = f.acc.Patch(context.Background(), f.admin, c.Account.ID, console.Patch{Role: &bad})
	refusal(t, err, http.StatusBadRequest, "bad_request")
	badStatus := "gone"
	_, err = f.acc.Patch(context.Background(), f.admin, c.Account.ID, console.Patch{Status: &badStatus})
	refusal(t, err, http.StatusBadRequest, "bad_request")
	_, err = f.acc.Patch(context.Background(), f.admin, "nobody", console.Patch{ResetMFA: true})
	refusal(t, err, http.StatusNotFound, "not_found")
	if n := countEvents(f.st, console.EventAccountChanged); n != 5 {
		t.Errorf("%d account_changed rows, want 5", n)
	}
}

func TestMeLogoutList(t *testing.T) {
	f := newFixture(t, cheap)
	c := f.create(t, "someone", auth.RoleViewer, false)
	res, err := f.login("someone", c.Password, nil)
	if err != nil {
		t.Fatal(err)
	}
	acc, sess, err := f.acc.Me(context.Background(), c.Account.ID, res.JTI)
	if err != nil || acc.Username != "someone" || sess.JTI != res.JTI {
		t.Fatalf("me %+v %+v %v", acc, sess, err)
	}
	_, _, err = f.acc.Me(context.Background(), "nobody", res.JTI)
	refusal(t, err, http.StatusNotFound, "not_found")
	_, _, err = f.acc.Me(context.Background(), c.Account.ID, "no-such-jti")
	refusal(t, err, http.StatusNotFound, "not_found")
	actor := console.AccountActor(c.Account.ID, auth.RoleViewer)
	if err := f.acc.Logout(context.Background(), actor, res.JTI); err != nil {
		t.Fatal(err)
	}
	if rv, _ := f.st.SessionRevoked(context.Background(), res.JTI); !rv || len(f.revoked.jtis) != 1 {
		t.Errorf("logout did not revoke (%v, cache %v)", rv, f.revoked.jtis)
	}
	if countEvents(f.st, console.EventSessionRevoked) != 1 {
		t.Error("no session_revoked row")
	}
	list, err := f.acc.List(context.Background())
	if err != nil || len(list) != 1 {
		t.Errorf("list %v %v", list, err)
	}
	f.st.Fail = consoletest.ErrDown
	if err := f.acc.Logout(context.Background(), actor, res.JTI); !errors.Is(err, consoletest.ErrDown) {
		t.Errorf("logout with the store down: %v", err)
	}
	if _, _, err := f.acc.Me(context.Background(), c.Account.ID, res.JTI); !errors.Is(err, consoletest.ErrDown) {
		t.Errorf("me with the store down: %v", err)
	}
	if _, err := f.login("someone", c.Password, nil); !errors.Is(err, consoletest.ErrDown) {
		t.Errorf("login with the store down: %v", err)
	}
}

// The argon2id work is bounded: with every slot taken, a login whose
// context ends waits no longer and answers 503 busy.
func TestLoginSlotsBounded(t *testing.T) {
	st := consoletest.New(time.Now())
	is, err := auth.NewSessionIssuer(authtest.Key(t, "session", 2048), consoleIssuer, ownHost)
	if err != nil {
		t.Fatal(err)
	}
	sealer, _ := console.NewSealer(k32())
	block := make(chan struct{})
	st.Put(store.Account{ID: "a", Username: "slow", PasswordHash: "x", Role: auth.RoleViewer, Status: console.StatusActive})
	acc, err := console.NewAccounts(console.Config{Store: blockingStore{Store: st, block: block}, Sessions: is, Sealer: sealer, Argon2: cheap, HashSlots: 1})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		_, _ = acc.Login(context.Background(), console.LoginRequest{Username: "slow", Password: "p"})
		close(done)
	}()
	time.Sleep(20 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err = acc.Login(ctx, console.LoginRequest{Username: "slow", Password: "p"})
	refusal(t, err, http.StatusServiceUnavailable, console.SlugBusy)
	close(block)
	<-done
}

type blockingStore struct {
	*consoletest.Store
	block chan struct{}
}

func (b blockingStore) Login(ctx context.Context, u string, d func(*store.Account, time.Time) (store.LoginOutcome, error)) error {
	<-b.block
	return b.Store.Login(ctx, u, d)
}

func TestNewAccountsRefusesAnIncompleteConfig(t *testing.T) {
	if _, err := console.NewAccounts(console.Config{}); err == nil {
		t.Error("an empty config was accepted")
	}
}

// k32 is a secrets key for tests: 32 bytes built at run time so no
// key-shaped literal sits in the repository.
func k32() []byte { return bytes.Repeat([]byte{0x5a}, 32) }
