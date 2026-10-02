package auth

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	coreauth "github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-cisp/internal/obs"
)

// The console roles (spec 01 section 2), ordered viewer <
// publisher_admin < admin.
const (
	RoleViewer         = "viewer"
	RolePublisherAdmin = "publisher_admin"
	RoleAdmin          = "admin"
)

// Roles are the console roles, lowest first.
var Roles = []string{RoleViewer, RolePublisherAdmin, RoleAdmin}

// RoleRank is the order of a console role, and false for a value that
// is not one.
func RoleRank(role string) (int, bool) {
	for i, r := range Roles {
		if r == role {
			return i, true
		}
	}
	return 0, false
}

// The session shape every console in the ecosystem uses (M20,
// docs/PLAN.md section 6.6): realm console, scope "session", one role
// in roles[], at most 12 h.
const (
	ConsoleRealm = "console"
	SessionTTL   = 12 * time.Hour
)

// Problem slugs and counters of the session guard.
const (
	SlugSessionRevoked     = "session_revoked"
	SlugSessionUnavailable = "session_check_unavailable"

	CounterSessionAccepted       = "session_accepted"
	CounterSessionNotSession     = "session_rejected_not_session"
	CounterSessionRealm          = "session_rejected_realm"
	CounterSessionRole           = "session_rejected_role"
	CounterSessionRevoked        = "session_rejected_revoked"
	CounterSessionIdle           = "session_rejected_idle"
	CounterSessionRoleTooLow     = "session_rejected_role_too_low"
	CounterSessionCheckFailed    = "session_check_failed"
	CounterRevocationCacheBypass = "session_revocation_cache_bypassed"
)

// SessionIssuer signs console session tokens with the CISP's session
// key (CISP_SESSION_KEY_FILE) through core's Issuer.IssueSession, and
// holds the static key set the shared verifier allow-lists for it.
type SessionIssuer struct {
	issuer   *coreauth.Issuer
	iss, aud string
	kid      string
	jwks     jwk.Set
}

// SessionKID is the kid of a session key: "session-" and the first 16
// hex digits of the SHA-256 of its public key (PKIX DER), so the key
// file alone names it and a new key never reuses a kid.
func SessionKID(key *rsa.PrivateKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", fmt.Errorf("session key: %w", err)
	}
	sum := sha256.Sum256(der)
	return "session-" + hex.EncodeToString(sum[:8]), nil
}

// NewSessionIssuer builds the issuer for iss (CISP_CONSOLE_ISSUER)
// writing aud (the CISP's own host, the first of CISP_AUDIENCES).
func NewSessionIssuer(key *rsa.PrivateKey, iss, aud string) (*SessionIssuer, error) {
	if key == nil || iss == "" || aud == "" {
		return nil, errors.New("session issuer: a key, an issuer and an audience are required")
	}
	kid, err := SessionKID(key)
	if err != nil {
		return nil, err
	}
	is, err := coreauth.NewIssuer(iss, key, kid)
	if err != nil {
		return nil, fmt.Errorf("session issuer: %w", err)
	}
	pub, err := jwk.Import(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("session issuer: %w", err)
	}
	for name, v := range map[string]any{jwk.KeyIDKey: kid, jwk.AlgorithmKey: jwa.RS256(), jwk.KeyUsageKey: "sig"} {
		if err := pub.Set(name, v); err != nil {
			return nil, fmt.Errorf("session issuer: %w", err)
		}
	}
	set := jwk.NewSet()
	if err := set.AddKey(pub); err != nil {
		return nil, fmt.Errorf("session issuer: %w", err)
	}
	return &SessionIssuer{issuer: is, iss: iss, aud: aud, kid: kid, jwks: set}, nil
}

// Issuer is the iss of the session tokens.
func (s *SessionIssuer) Issuer() string { return s.iss }

// KID is the kid of the session key.
func (s *SessionIssuer) KID() string { return s.kid }

// Source is the console issuer as the shared verifier allow-lists it: a
// static key set beside the ecosystem issuers (D10).
func (s *SessionIssuer) Source() Source { return Source{ID: s.iss, Keys: s.jwks} }

// Issue signs a session for account with role, valid from iat to exp
// (both the database's clock), under jti (the sessions row).
func (s *SessionIssuer) Issue(accountID, role, jti string, iat, exp time.Time) (string, error) {
	if _, ok := RoleRank(role); !ok {
		return "", core.Fieldf("role", "%q is not a console role", role)
	}
	if exp.Sub(iat) > SessionTTL {
		return "", core.Fieldf("exp", "a session lasts at most %s", SessionTTL)
	}
	return s.issuer.IssueSession(coreauth.SessionClaims{
		Audience: s.aud, Subject: accountID, Roles: []string{role}, Realm: ConsoleRealm,
		IssuedAt: iat, ExpiresAt: exp, JTI: jti,
	})
}

// RevocationChecker says whether a session (by jti) is revoked.
type RevocationChecker interface {
	Revoked(ctx context.Context, jti string) (bool, error)
}

// SessionActivity records a session's use and enforces its idle end
// (Activity).
type SessionActivity interface {
	Active(ctx context.Context, jti string) (bool, error)
}

// SessionGuardConfig configures a SessionGuard.
type SessionGuardConfig struct {
	// Verifier is the shared verifier (the console issuer allow-listed
	// beside the ecosystem's).
	Verifier TokenVerifier
	// Issuer is CISP_CONSOLE_ISSUER: a session from any other issuer is
	// not a console session here.
	Issuer      string
	Revocations RevocationChecker
	// Activity records each use and refuses a session idle for more
	// than 30 minutes.
	Activity SessionActivity
	Problems ProblemWriter
	// Component counts the outcomes; nil: a private one.
	Component *obs.Component
	Logger    *slog.Logger
	LogEvery  time.Duration
	// Now is the clock of the log limiter; nil is time.Now.
	Now func() time.Time
}

// SessionGuard is the console's role middleware.
type SessionGuard struct {
	cfg SessionGuardConfig
	log *refusalLog
}

// NewSessionGuard returns the guard; it refuses a config without a
// verifier, an issuer, a revocation check, an activity tracker or a
// problem writer.
func NewSessionGuard(cfg SessionGuardConfig) (*SessionGuard, error) {
	if cfg.Verifier == nil || cfg.Issuer == "" || cfg.Revocations == nil || cfg.Activity == nil || cfg.Problems == nil {
		return nil, errors.New("session guard: a verifier, an issuer, a revocation check, an activity tracker and a problem writer are required")
	}
	if cfg.Component == nil {
		cfg.Component = obs.NewStatus("auth", nil, time.Now()).Component("console_auth")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.LogEvery <= 0 {
		cfg.LogEvery = time.Minute
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &SessionGuard{cfg: cfg, log: &refusalLog{every: cfg.LogEvery, seen: map[string]*refusalEntry{}}}, nil
}

func (g *SessionGuard) count(name string) {
	g.cfg.Component.Counter(name, "Console session outcomes by reason ("+name+").").Inc()
}

// SessionError is a refused session: the status (401 or 403, or 503
// when the revocation list cannot be read), the problem slug, the
// counter and the field at fault.
type SessionError struct {
	Status  int
	Slug    string
	Counter string
	Field   *core.FieldError
}

func (e *SessionError) Error() string { return e.Field.Error() }

func sessionErr(status int, slug, counter string, fe *core.FieldError) *SessionError {
	return &SessionError{Status: status, Slug: slug, Counter: counter, Field: fe}
}

// Session verifies a console session token: the shared verifier (401
// on its refusals), then the console issuer and scope exactly "session"
// (403: a machine token is not a session), realm console, exactly one
// known role (403), a jti that is not revoked (401 session_revoked) and
// a session used within the idle timeout (401 session_revoked; the use
// is recorded).
// It returns the caller with its role in Claims.Roles[0].
func (g *SessionGuard) Session(ctx context.Context, token string) (*Caller, error) {
	claims, err := g.cfg.Verifier.Verify(ctx, token)
	if err != nil {
		var te *coreauth.TokenError
		if errors.As(err, &te) {
			return nil, sessionErr(http.StatusUnauthorized, SlugUnauthenticated, te.Counter, core.Fieldf(te.Claim, "%s", te.Reason))
		}
		return nil, sessionErr(http.StatusUnauthorized, SlugUnauthenticated, coreauth.CounterRejectedMalformed, core.Fieldf("token", "%v", err))
	}
	if claims.Issuer != g.cfg.Issuer || len(claims.Scopes) != 1 || claims.Scopes[0] != coreauth.SessionScope {
		return nil, sessionErr(http.StatusForbidden, SlugForbidden, CounterSessionNotSession,
			core.Fieldf("scope", "a console session (scope session from the console issuer) is required; machine tokens do not open the console"))
	}
	if claims.Realm != ConsoleRealm {
		return nil, sessionErr(http.StatusForbidden, SlugForbidden, CounterSessionRealm, core.Fieldf("realm", "%q is not console", claims.Realm))
	}
	if len(claims.Roles) != 1 {
		return nil, sessionErr(http.StatusForbidden, SlugForbidden, CounterSessionRole, core.Fieldf("roles", "exactly one role is required, got %d", len(claims.Roles)))
	}
	if _, ok := RoleRank(claims.Roles[0]); !ok {
		return nil, sessionErr(http.StatusForbidden, SlugForbidden, CounterSessionRole, core.Fieldf("roles", "%q is not a console role", claims.Roles[0]))
	}
	revoked, err := g.cfg.Revocations.Revoked(ctx, claims.JTI)
	if err != nil {
		return nil, sessionErr(http.StatusServiceUnavailable, SlugSessionUnavailable, CounterSessionCheckFailed,
			core.Fieldf("jti", "the session list cannot be read: %v", err))
	}
	if revoked {
		return nil, sessionErr(http.StatusUnauthorized, SlugSessionRevoked, CounterSessionRevoked, core.Fieldf("jti", "the session is revoked or expired"))
	}
	active, err := g.cfg.Activity.Active(ctx, claims.JTI)
	if err != nil {
		return nil, sessionErr(http.StatusServiceUnavailable, SlugSessionUnavailable, CounterSessionCheckFailed,
			core.Fieldf("jti", "the session's last use cannot be recorded: %v", err))
	}
	if !active {
		return nil, sessionErr(http.StatusUnauthorized, SlugSessionRevoked, CounterSessionIdle,
			core.Fieldf("jti", "the session was idle for more than %s, or is revoked or expired; sign in again", SessionIdle))
	}
	g.count(CounterSessionAccepted)
	return &Caller{Kind: KindConsole, ClientID: claims.Subject, Scopes: claims.Scopes, Claims: claims}, nil
}

// VerifySession implements stream.SessionVerifier: the stream accepts a
// cookie only when Session would.
func (g *SessionGuard) VerifySession(ctx context.Context, token string) error {
	_, err := g.Session(ctx, token)
	return err
}

// ConsoleRole is the role of a console caller, empty for any other.
func ConsoleRole(c *Caller) string {
	if c == nil || c.Kind != KindConsole || len(c.Claims.Roles) != 1 {
		return ""
	}
	return c.Claims.Roles[0]
}

// RequireRole authenticates a console session from the bearer token
// (the BFF forwards the uspace_session cookie as a bearer) and requires
// role or a higher one (403 otherwise). An unknown role is refused at
// start, never at request time.
func (g *SessionGuard) RequireRole(role string) (Middleware, error) {
	need, ok := RoleRank(role)
	if !ok {
		return nil, fmt.Errorf("require role: %q is not a console role", role)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, ok := bearer(r.Header.Get("Authorization"))
			if !ok {
				g.refuse(w, r, sessionErr(http.StatusUnauthorized, SlugUnauthenticated, CounterRejectedNoToken, core.Fieldf("authorization", "no bearer token")))
				return
			}
			c, err := g.Session(r.Context(), token)
			if err != nil {
				var se *SessionError
				if errors.As(err, &se) {
					g.refuse(w, r, se)
					return
				}
				g.refuse(w, r, sessionErr(http.StatusUnauthorized, SlugUnauthenticated, coreauth.CounterRejectedMalformed, core.Fieldf("token", "%v", err)))
				return
			}
			if have, _ := RoleRank(ConsoleRole(c)); have < need {
				g.refuse(w, r, sessionErr(http.StatusForbidden, SlugForbidden, CounterSessionRoleTooLow,
					core.Fieldf("roles", "%s or higher is required", role)))
				return
			}
			next.ServeHTTP(w, r.WithContext(WithCaller(r.Context(), c)))
		})
	}, nil
}

func (g *SessionGuard) refuse(w http.ResponseWriter, r *http.Request, se *SessionError) {
	g.count(se.Counter)
	g.log.note(r.Context(), g.cfg.Logger, g.cfg.Now(), se.Counter, se.Field)
	title := "Forbidden"
	switch se.Status {
	case http.StatusUnauthorized:
		title = "Unauthenticated"
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	case http.StatusServiceUnavailable:
		title = "Session check unavailable"
	}
	g.cfg.Problems(w, se.Status, se.Slug, title, se.Field.Error(), se.Field)
}

// RevocationSource reads the sessions table.
type RevocationSource interface {
	// RevokedSessions is the jtis of the revoked sessions that have not
	// expired yet (the database's clock), at most limit.
	RevokedSessions(ctx context.Context, limit int) ([]string, error)
	// SessionRevoked says whether jti is revoked, expired or unknown.
	SessionRevoked(ctx context.Context, jti string) (bool, error)
}

// RevocationCacheConfig configures a RevocationCache.
type RevocationCacheConfig struct {
	Source RevocationSource
	// MaxEntries bounds the cached jtis (E-10; 0: 10 000). Past it the
	// cache is bypassed: every request asks the database.
	MaxEntries int
	// MaxAge is how old the last successful refresh may be before the
	// cache is bypassed (0: 30 s, three refresh periods).
	MaxAge time.Duration
	// Component counts the bypasses; nil: none.
	Component *obs.Component
	// Now is the clock; nil is time.Now.
	Now func() time.Time
}

// RevocationCache is the bounded in-memory negative cache of revoked
// session jtis, refreshed from the database every period (10 s in the
// api), so a revoked session is refused by every replica within one
// period without a query per request. A jti this replica revoked is
// added at once. While the cache is over its bound or its last refresh
// is older than MaxAge, every check goes to the database (and fails
// closed when the database does not answer).
type RevocationCache struct {
	cfg RevocationCacheConfig

	mu       sync.RWMutex
	revoked  map[string]struct{}
	full     bool
	loadedAt time.Time
}

// NewRevocationCache returns an empty cache; until its first Refresh
// every check goes to the database.
func NewRevocationCache(cfg RevocationCacheConfig) *RevocationCache {
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = 10_000
	}
	if cfg.MaxAge <= 0 {
		cfg.MaxAge = 30 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &RevocationCache{cfg: cfg, revoked: map[string]struct{}{}}
}

// Refresh reloads the revoked jtis. On an error the previous set is
// kept and ages towards MaxAge.
func (c *RevocationCache) Refresh(ctx context.Context) error {
	jtis, err := c.cfg.Source.RevokedSessions(ctx, c.cfg.MaxEntries+1)
	if err != nil {
		return err
	}
	set := make(map[string]struct{}, min(len(jtis), c.cfg.MaxEntries))
	full := len(jtis) > c.cfg.MaxEntries
	if !full {
		for _, j := range jtis {
			set[j] = struct{}{}
		}
	}
	c.mu.Lock()
	c.revoked, c.full, c.loadedAt = set, full, c.cfg.Now()
	c.mu.Unlock()
	return nil
}

// Run refreshes on every tick until ctx ends.
func (c *RevocationCache) Run(ctx context.Context, tick <-chan time.Time) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
			_ = c.Refresh(ctx) // a failed refresh ages the cache towards a bypass
		}
	}
}

// Add marks jti revoked at once (this replica revoked it); the bound
// applies: past it the cache is bypassed until the next refresh.
func (c *RevocationCache) Add(jti string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.revoked) >= c.cfg.MaxEntries {
		c.full = true
		return
	}
	c.revoked[jti] = struct{}{}
}

// Len is the number of cached jtis.
func (c *RevocationCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.revoked)
}

// Revoked implements RevocationChecker.
func (c *RevocationCache) Revoked(ctx context.Context, jti string) (bool, error) {
	c.mu.RLock()
	_, hit := c.revoked[jti]
	usable := !c.full && !c.loadedAt.IsZero() && c.cfg.Now().Sub(c.loadedAt) <= c.cfg.MaxAge
	c.mu.RUnlock()
	if hit {
		return true, nil
	}
	if usable {
		return false, nil
	}
	if c.cfg.Component != nil {
		c.cfg.Component.Counter(CounterRevocationCacheBypass, "Session checks that asked the database because the revocation cache was full or stale.").Inc()
	}
	return c.cfg.Source.SessionRevoked(ctx, jti)
}
