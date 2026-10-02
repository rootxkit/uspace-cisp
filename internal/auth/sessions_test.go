package auth_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	coreauth "github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-cisp/internal/auth"
	"github.com/rootxkit/uspace-cisp/internal/authtest"
	"github.com/rootxkit/uspace-cisp/internal/obs"
)

const consoleIss = "https://uspace-cisp.example.test/console"

var fast = auth.Argon2Params{MemoryKiB: 64, Iterations: 1, Lanes: 1}

func TestPasswordHashVerify(t *testing.T) {
	h, err := auth.HashPassword("s3cret", fast)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=64,t=1,p=1$") {
		t.Errorf("PHC %q", h)
	}
	h2, _ := auth.HashPassword("s3cret", fast)
	if h == h2 {
		t.Error("two hashes of one password are equal (no salt)")
	}
	ok, rehash, err := auth.VerifyPassword(h, "s3cret", fast)
	if !ok || rehash || err != nil {
		t.Errorf("right password: %v %v %v", ok, rehash, err)
	}
	ok, _, err = auth.VerifyPassword(h, "s3cret!", fast)
	if ok || err != nil {
		t.Errorf("wrong password: %v %v", ok, err)
	}
	// Other current parameters: the hash still verifies and asks for a
	// re-hash.
	ok, rehash, err = auth.VerifyPassword(h, "s3cret", auth.Argon2Params{MemoryKiB: 128, Iterations: 1, Lanes: 1})
	if !ok || !rehash || err != nil {
		t.Errorf("older parameters: %v %v %v", ok, rehash, err)
	}
	long := strings.Repeat("x", auth.MaxPasswordBytes+1)
	if _, err := auth.HashPassword(long, fast); !errors.Is(err, auth.ErrPasswordTooLong) {
		t.Errorf("long hash: %v", err)
	}
	if _, _, err := auth.VerifyPassword(h, long, fast); !errors.Is(err, auth.ErrPasswordTooLong) {
		t.Errorf("long verify: %v", err)
	}
	for _, p := range []auth.Argon2Params{{MemoryKiB: 1, Iterations: 1, Lanes: 1}, {MemoryKiB: 64, Iterations: 0, Lanes: 1}, {MemoryKiB: 64, Iterations: 1, Lanes: 0}, {MemoryKiB: 2 << 20, Iterations: 1, Lanes: 1}} {
		if _, err := auth.HashPassword("x", p); err == nil {
			t.Errorf("parameters %+v accepted", p)
		}
	}
}

// A stored hash is read as untrusted: every malformed form is an error,
// never a panic and never a match.
func TestPasswordMalformedHashes(t *testing.T) {
	salt := "c2FsdHNhbHRzYWx0c2FsdA"
	key := "a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2U"
	for _, h := range []string{
		"", "plain", "$argon2i$v=19$m=64,t=1,p=1$" + salt + "$" + key, "$argon2id$v=18$m=64,t=1,p=1$" + salt + "$" + key,
		"$argon2id$v=19$m=64,t=1$" + salt + "$" + key + "$x", "$argon2id$v=19$m64,t=1,p=1$" + salt + "$" + key,
		"$argon2id$v=19$m=x,t=1,p=1$" + salt + "$" + key, "$argon2id$v=19$m=64,t=1,p=999$" + salt + "$" + key,
		"$argon2id$v=19$m=64,t=1,q=1$" + salt + "$" + key, "$argon2id$v=19$m=99999999,t=1,p=1$" + salt + "$" + key,
		"$argon2id$v=19$m=64,t=1,p=1$!!$" + key, "$argon2id$v=19$m=64,t=1,p=1$c2E$" + key,
		"$argon2id$v=19$m=64,t=1,p=1$" + salt + "$!!", "$argon2id$v=19$m=64,t=1,p=1$" + salt + "$a2V5",
		"$argon2id$v=19$m=64,t=1,p=1$" + salt + "$" + strings.Repeat("A", 600),
	} {
		ok, _, err := auth.VerifyPassword(h, "x", fast)
		if ok || err == nil {
			t.Errorf("%q: ok %v err %v", h, ok, err)
		}
	}
}

func TestTOTP(t *testing.T) {
	secret, url, err := auth.NewTOTPSecret("uspace-cisp", "chief")
	if err != nil || !strings.HasPrefix(url, "otpauth://totp/uspace-cisp:chief?") || !strings.Contains(url, "secret="+secret) {
		t.Fatalf("%q %q %v", secret, url, err)
	}
	now := time.Date(2026, 10, 2, 12, 0, 15, 0, time.UTC)
	step := auth.TOTPStepAt(now)
	for _, d := range []int64{-1, 0, 1} {
		at := time.Unix((step+d)*30, 0)
		code, err := auth.TOTPCode(secret, at)
		if err != nil {
			t.Fatal(err)
		}
		got, ok := auth.MatchTOTP(secret, code, now)
		if !ok || got != step+d {
			t.Errorf("skew %d: %d %v", d, got, ok)
		}
	}
	far, _ := auth.TOTPCode(secret, time.Unix((step+3)*30, 0))
	if _, ok := auth.MatchTOTP(secret, far, now); ok {
		// A collision of two six-digit codes is possible but rare; the
		// fixed instant makes this deterministic.
		t.Error("a code three steps away matched")
	}
	for _, c := range []string{"", "12345", "1234567", "12a456", "１２３４５６"} {
		if _, ok := auth.MatchTOTP(secret, c, now); ok {
			t.Errorf("%q matched", c)
		}
	}
	if _, ok := auth.MatchTOTP("not base32 !!", "123456", now); ok {
		t.Error("a broken secret matched")
	}
}

type sessionRig struct {
	machine *coreauth.Issuer
	session *auth.SessionIssuer
	rawKey  *coreauth.Issuer // the session key outside the helper (realm tests)
	guard   *auth.SessionGuard
	revoked *fakeRevocations
	comp    *obs.Component
}

type fakeRevocations struct {
	mu   sync.Mutex
	jtis map[string]bool
	err  error
}

func (f *fakeRevocations) Revoked(_ context.Context, jti string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.jtis[jti], f.err
}

func newSessionRig(t *testing.T) *sessionRig {
	t.Helper()
	key := authtest.Key(t, "session", 3072)
	si, err := auth.NewSessionIssuer(key, consoleIss, host)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := coreauth.NewIssuer(consoleIss, key, si.KID())
	if err != nil {
		t.Fatal(err)
	}
	machine := newIssuer(t, issuer, "issuer", "tok-1")
	mv, err := auth.NewMachineVerifier(context.Background(), auth.MachineConfig{
		Issuers:   []auth.Source{{ID: issuer, Keys: machine.JWKS()}, si.Source()},
		Audiences: []string{host},
	})
	if err != nil {
		t.Fatal(err)
	}
	rv := &fakeRevocations{jtis: map[string]bool{}}
	comp := obs.NewStatus("api", nil, time.Now()).Component("console_auth")
	g, err := auth.NewSessionGuard(auth.SessionGuardConfig{Verifier: mv, Issuer: consoleIss, Revocations: rv, Problems: problems, Component: comp})
	if err != nil {
		t.Fatal(err)
	}
	return &sessionRig{machine: machine, session: si, rawKey: raw, guard: g, revoked: rv, comp: comp}
}

func problems(w http.ResponseWriter, status int, slug, _, detail string, _ ...*core.FieldError) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": slug, "status": status, "detail": detail})
}

func (r *sessionRig) token(t *testing.T, role, jti string) string {
	t.Helper()
	now := time.Now()
	tok, err := r.session.Issue("acc-1", role, jti, now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func (r *sessionRig) do(t *testing.T, role string, bearer string) (int, string) {
	t.Helper()
	mw, err := r.guard.RequireRole(role)
	if err != nil {
		t.Fatal(err)
	}
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		c := auth.CallerFrom(req.Context())
		w.Header().Set("X-Role", auth.ConsoleRole(c))
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/v1/console/me", http.NoBody)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var p struct{ Type string }
	_ = json.Unmarshal(rec.Body.Bytes(), &p)
	return rec.Code, p.Type
}

// The role middleware: every refusal beside the acceptance that differs
// from it in one thing (E-01).
func TestRequireRole(t *testing.T) {
	r := newSessionRig(t)
	now := time.Now()
	viewer := r.token(t, auth.RoleViewer, "jti-viewer")
	admin := r.token(t, auth.RoleAdmin, "jti-admin")
	machine, _ := r.machine.Issue("ussp-GEO1-01", host, []string{auth.ScopeRead}, time.Minute, now)
	ecoSession, _ := r.machine.IssueSession(coreauth.SessionClaims{Audience: host, Subject: "acc-1", Roles: []string{"admin"}, Realm: "console", IssuedAt: now, ExpiresAt: now.Add(time.Hour), JTI: "j1"})
	portal, _ := r.rawKey.IssueSession(coreauth.SessionClaims{Audience: host, Subject: "acc-1", Roles: []string{"admin"}, Realm: "portal", IssuedAt: now, ExpiresAt: now.Add(time.Hour), JTI: "j2"})
	twoRoles, _ := r.rawKey.IssueSession(coreauth.SessionClaims{Audience: host, Subject: "acc-1", Roles: []string{"viewer", "admin"}, Realm: "console", IssuedAt: now, ExpiresAt: now.Add(time.Hour), JTI: "j3"})
	owner, _ := r.rawKey.IssueSession(coreauth.SessionClaims{Audience: host, Subject: "acc-1", Roles: []string{"owner"}, Realm: "console", IssuedAt: now, ExpiresAt: now.Add(time.Hour), JTI: "j4"})
	cases := []struct {
		name, need, bearer string
		status             int
		slug               string
	}{
		{"viewer on a viewer route", auth.RoleViewer, viewer, 200, ""},
		{"admin on a viewer route", auth.RoleViewer, admin, 200, ""},
		{"admin on an admin route", auth.RoleAdmin, admin, 200, ""},
		{"viewer on a publisher_admin route", auth.RolePublisherAdmin, viewer, 403, auth.SlugForbidden},
		{"no token", auth.RoleViewer, "", 401, auth.SlugUnauthenticated},
		{"garbage", auth.RoleViewer, "not.a.token", 401, auth.SlugUnauthenticated},
		{"machine token with cis.read", auth.RoleViewer, machine, 403, auth.SlugForbidden},
		{"a session from the ecosystem issuer", auth.RoleViewer, ecoSession, 403, auth.SlugForbidden},
		{"realm portal", auth.RoleViewer, portal, 403, auth.SlugForbidden},
		{"two roles", auth.RoleViewer, twoRoles, 403, auth.SlugForbidden},
		{"an unknown role", auth.RoleViewer, owner, 403, auth.SlugForbidden},
	}
	for _, c := range cases {
		status, slug := r.do(t, c.need, c.bearer)
		if status != c.status || slug != c.slug {
			t.Errorf("%s: %d %q, want %d %q", c.name, status, slug, c.status, c.slug)
		}
	}
	// Revoked: 401 session_revoked; the list unreadable: 503 (fail closed).
	r.revoked.mu.Lock()
	r.revoked.jtis["jti-viewer"] = true
	r.revoked.mu.Unlock()
	if s, slug := r.do(t, auth.RoleViewer, viewer); s != 401 || slug != auth.SlugSessionRevoked {
		t.Errorf("revoked: %d %s", s, slug)
	}
	if s, _ := r.do(t, auth.RoleViewer, admin); s != 200 {
		t.Errorf("not revoked: %d", s)
	}
	r.revoked.mu.Lock()
	r.revoked.err = errors.New("database down")
	r.revoked.mu.Unlock()
	if s, slug := r.do(t, auth.RoleViewer, admin); s != 503 || slug != auth.SlugSessionUnavailable {
		t.Errorf("revocation list down: %d %s", s, slug)
	}
	if _, err := r.guard.RequireRole("owner"); err == nil {
		t.Error("an unknown required role was accepted")
	}
	if got := r.comp.Counter(auth.CounterSessionNotSession, "").Value(); got != 2 {
		t.Errorf("not-a-session refusals counted %d, want 2", got)
	}
}

func TestVerifySessionAndIssuer(t *testing.T) {
	r := newSessionRig(t)
	if err := r.guard.VerifySession(context.Background(), r.token(t, auth.RoleViewer, "j")); err != nil {
		t.Errorf("a session: %v", err)
	}
	machine, _ := r.machine.Issue("ussp-GEO1-01", host, []string{auth.ScopeRead}, time.Minute, time.Now())
	var se *auth.SessionError
	if err := r.guard.VerifySession(context.Background(), machine); !errors.As(err, &se) || se.Status != 403 {
		t.Errorf("a machine token: %v", err)
	}
	now := time.Now()
	if _, err := r.session.Issue("acc", "owner", "j", now, now.Add(time.Hour)); err == nil {
		t.Error("an unknown role was signed")
	}
	if _, err := r.session.Issue("acc", auth.RoleViewer, "j", now, now.Add(13*time.Hour)); err == nil {
		t.Error("a 13 h session was signed")
	}
	if _, err := auth.NewSessionIssuer(nil, consoleIss, host); err == nil {
		t.Error("no key accepted")
	}
	k1, _ := auth.SessionKID(authtest.Key(t, "session", 3072))
	k2, _ := auth.SessionKID(authtest.Key(t, "other-session", 3072))
	if k1 != r.session.KID() || k1 == k2 || !strings.HasPrefix(k1, "session-") || r.session.Issuer() != consoleIss {
		t.Errorf("kids %s %s %s", k1, k2, r.session.KID())
	}
	if _, err := auth.NewSessionGuard(auth.SessionGuardConfig{}); err == nil {
		t.Error("an empty guard config was accepted")
	}
	if auth.ConsoleRole(nil) != "" || auth.ConsoleRole(&auth.Caller{Kind: auth.KindMachine}) != "" {
		t.Error("a role for no console caller")
	}
}

type revSource struct {
	mu       sync.Mutex
	jtis     []string
	err      error
	lookups  int
	revoked  map[string]bool
	lookupEr error
}

func (s *revSource) RevokedSessions(_ context.Context, limit int) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	out := append([]string{}, s.jtis...)
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *revSource) SessionRevoked(_ context.Context, jti string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lookups++
	return s.revoked[jti], s.lookupEr
}

// The negative cache: a hit answers without the database, a miss on a
// fresh cache too; a stale cache and an overflowing one ask the
// database (E-10: the bound is exceeded by one).
func TestRevocationCache(t *testing.T) {
	src := &revSource{jtis: []string{"a", "b"}, revoked: map[string]bool{"c": true}}
	clock := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	comp := obs.NewStatus("api", nil, clock).Component("console_auth")
	c := auth.NewRevocationCache(auth.RevocationCacheConfig{Source: src, MaxEntries: 3, MaxAge: 30 * time.Second, Component: comp, Now: func() time.Time { return clock }})
	ctx := context.Background()
	// Before the first refresh every check asks the database.
	if rv, _ := c.Revoked(ctx, "c"); !rv || src.lookups != 1 {
		t.Fatalf("before a refresh: %v %d", rv, src.lookups)
	}
	if err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if rv, _ := c.Revoked(ctx, "a"); !rv {
		t.Error("a cached jti is not revoked")
	}
	if rv, _ := c.Revoked(ctx, "z"); rv || src.lookups != 1 {
		t.Errorf("a miss on a fresh cache: %v, %d lookups", rv, src.lookups)
	}
	c.Add("d")
	if rv, _ := c.Revoked(ctx, "d"); !rv || c.Len() != 3 {
		t.Errorf("added: %v %d", rv, c.Len())
	}
	c.Add("e") // past the bound: bypass
	if _, _ = c.Revoked(ctx, "z"); src.lookups != 2 {
		t.Errorf("full cache did not ask the database (%d)", src.lookups)
	}
	if err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _ = c.Revoked(ctx, "z"); src.lookups != 2 {
		t.Error("a refreshed cache asked the database")
	}
	clock = clock.Add(31 * time.Second)
	if _, _ = c.Revoked(ctx, "z"); src.lookups != 3 {
		t.Error("a stale cache did not ask the database")
	}
	src.err = errors.New("down")
	if err := c.Refresh(ctx); err == nil {
		t.Error("a failed refresh reported success")
	}
	src.err = nil
	src.jtis = []string{"1", "2", "3", "4"} // more than MaxEntries
	if err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _ = c.Revoked(ctx, "z"); src.lookups != 4 || c.Len() != 0 {
		t.Errorf("an overflowing list was cached (%d lookups, %d held)", src.lookups, c.Len())
	}
	src.lookupEr = errors.New("down")
	if _, err := c.Revoked(ctx, "z"); err == nil {
		t.Error("a database error was swallowed")
	}
	if got := comp.Counter(auth.CounterRevocationCacheBypass, "").Value(); got != 5 {
		t.Errorf("bypasses counted %d, want 5", got)
	}
	tick := make(chan time.Time)
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { c.Run(runCtx, tick); close(done) }()
	src.mu.Lock()
	src.jtis = []string{"x"}
	src.mu.Unlock()
	tick <- clock
	cancel()
	<-done
	if rv, _ := c.Revoked(ctx, "x"); !rv {
		t.Error("Run did not refresh")
	}
	d := auth.NewRevocationCache(auth.RevocationCacheConfig{Source: src})
	if d.Len() != 0 {
		t.Error("defaults")
	}
}
