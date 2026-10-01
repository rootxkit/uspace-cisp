package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	coreauth "github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-cisp/internal/config"
	"github.com/rootxkit/uspace-cisp/internal/obs"
)

// HeaderClientCertSubject carries the subject of the client certificate
// Caddy verified (docs/PLAN.md section 8.3). Caddy strips it from every
// request that presented no certificate and from every other route.
const HeaderClientCertSubject = "X-Client-Cert-Subject"

// Problem slugs of the middleware (the type is
// https://schemas.uspace.ge/problems/<slug>).
const (
	SlugUnauthenticated = "unauthenticated"
	SlugForbidden       = "forbidden"
	SlugNotAPublisher   = "not_a_publisher"
	SlugMTLSRequired    = "mtls_required"
)

// Counters of the auth component beside core's refusal reasons
// (rejected_audience, rejected_kid, ... are counted under core's names).
const (
	CounterAccepted                 = coreauth.CounterAccepted
	CounterRejectedNoToken          = "rejected_no_token"
	CounterRejectedScope            = "rejected_scope"
	CounterRejectedPublisherBinding = "rejected_publisher_binding"
	CounterRejectedMTLSMissing      = "rejected_mtls_missing"
	CounterRejectedMTLSSubject      = "rejected_mtls_subject"
	CounterMTLSOffPassed            = "mtls_off_passed" //nolint:gosec // G101: a counter name, not a credential
)

// ProblemWriter writes an application/problem+json response;
// httpapi.WriteProblem is one.
type ProblemWriter func(w http.ResponseWriter, status int, slug, title, detail string, fields ...*core.FieldError)

// TokenVerifier verifies a bearer token (MachineVerifier, or core's
// Verifier in tests).
type TokenVerifier interface {
	Verify(ctx context.Context, token string) (coreauth.Claims, error)
}

// Kind says how a caller authenticated.
type Kind string

// The caller kinds; console sessions are WP-8's.
const (
	KindMachine Kind = "machine"
	KindConsole Kind = "console"
)

// Caller is the authenticated caller of a request.
type Caller struct {
	Kind     Kind
	ClientID string
	Scopes   []string
	Claims   coreauth.Claims
	// MTLSSubject is the certificate subject RequireMTLSSubject bound;
	// empty on every other route, whatever the request carried.
	MTLSSubject string
}

type callerKey struct{}

// WithCaller returns ctx carrying c.
func WithCaller(ctx context.Context, c *Caller) context.Context {
	return context.WithValue(ctx, callerKey{}, c)
}

// CallerFrom is the caller the middleware authenticated, or nil.
func CallerFrom(ctx context.Context) *Caller {
	c, _ := ctx.Value(callerKey{}).(*Caller)
	return c
}

// GuardConfig configures a Guard.
type GuardConfig struct {
	Verifier TokenVerifier
	Problems ProblemWriter
	// AuthorityClientID and ANSPClientID bind the publishers (M24).
	AuthorityClientID string
	ANSPClientID      string
	// MTLSMode is config.MTLSRequired or config.MTLSOff.
	MTLSMode string
	// ANSPMTLSSubject is the expected certificate subject of the ANSP.
	ANSPMTLSSubject string
	// Component counts every acceptance and refusal; nil: a private one.
	Component *obs.Component
	// Logger logs refusals, the first of each reason at once and then at
	// most one line per LogEvery with the count; nil discards.
	Logger   *slog.Logger
	LogEvery time.Duration
	// Now is the clock of the log limiter; nil is time.Now.
	Now func() time.Time
}

// GuardConfigFrom is the guard configuration of the api.
func GuardConfigFrom(cfg *config.API, v TokenVerifier, problems ProblemWriter, comp *obs.Component, logger *slog.Logger) GuardConfig {
	return GuardConfig{
		Verifier:          v,
		Problems:          problems,
		AuthorityClientID: cfg.AuthorityClientID,
		ANSPClientID:      cfg.ANSPClientID,
		MTLSMode:          cfg.MTLSMode,
		ANSPMTLSSubject:   cfg.ANSPMTLSSubject,
		Component:         comp,
		Logger:            logger,
		LogEvery:          cfg.StatusInterval,
	}
}

// Guard builds the authentication and authorisation middleware.
type Guard struct {
	cfg GuardConfig
	log *refusalLog
}

// NewGuard returns a Guard; it refuses a config without a verifier or a
// problem writer, and an mTLS mode other than required or off.
func NewGuard(cfg GuardConfig) (*Guard, error) {
	if cfg.Verifier == nil || cfg.Problems == nil {
		return nil, errors.New("auth guard: a verifier and a problem writer are required")
	}
	switch cfg.MTLSMode {
	case config.MTLSRequired:
		if cfg.ANSPMTLSSubject == "" {
			return nil, errors.New("auth guard: mTLS required but no ANSP subject configured")
		}
	case config.MTLSOff:
	default:
		return nil, errors.New("auth guard: mTLS mode must be required or off")
	}
	if cfg.Component == nil {
		cfg.Component = obs.NewStatus("auth", nil, time.Now()).Component("auth")
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
	return &Guard{cfg: cfg, log: &refusalLog{every: cfg.LogEvery, seen: map[string]*refusalEntry{}}}, nil
}

// Middleware wraps a handler.
type Middleware func(http.Handler) http.Handler

// Chain applies ms so that the first runs first.
func Chain(h http.Handler, ms ...Middleware) http.Handler {
	for i := len(ms) - 1; i >= 0; i-- {
		h = ms[i](h)
	}
	return h
}

func (g *Guard) count(name string) {
	g.cfg.Component.Counter(name, "Machine authentication outcomes by reason ("+name+").").Inc()
}

// authenticate returns the caller already in the context, or verifies
// the bearer token. On a refusal it has answered 401 and returns nil.
func (g *Guard) authenticate(w http.ResponseWriter, r *http.Request) (*Caller, *http.Request) {
	if c := CallerFrom(r.Context()); c != nil {
		return c, r
	}
	token, ok := bearer(r.Header.Get("Authorization"))
	if !ok {
		g.refuse401(w, r, CounterRejectedNoToken, core.Fieldf("authorization", "no bearer token"))
		return nil, r
	}
	claims, err := g.cfg.Verifier.Verify(r.Context(), token)
	if err != nil {
		var te *coreauth.TokenError
		if errors.As(err, &te) {
			g.refuse401(w, r, te.Counter, core.Fieldf(te.Claim, "%s", te.Reason))
			return nil, r
		}
		g.refuse401(w, r, coreauth.CounterRejectedMalformed, core.Fieldf("token", "%v", err))
		return nil, r
	}
	g.count(CounterAccepted)
	c := &Caller{Kind: KindMachine, ClientID: claims.Subject, Scopes: claims.Scopes, Claims: claims}
	return c, r.WithContext(WithCaller(r.Context(), c))
}

// bearer extracts the token of an "Authorization: Bearer <token>" value
// (the scheme is case-insensitive, RFC 9110 section 11.1).
func bearer(v string) (string, bool) {
	scheme, token, ok := strings.Cut(v, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	return token, token != ""
}

func (g *Guard) refuse401(w http.ResponseWriter, r *http.Request, counter string, fe *core.FieldError) {
	g.count(counter)
	g.log.note(r.Context(), g.cfg.Logger, g.cfg.Now(), counter, fe)
	w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	g.cfg.Problems(w, http.StatusUnauthorized, SlugUnauthenticated, "Unauthenticated", fe.Error(), fe)
}

func (g *Guard) refuse403(w http.ResponseWriter, r *http.Request, counter, slug, title string, fe *core.FieldError) {
	g.count(counter)
	g.log.note(r.Context(), g.cfg.Logger, g.cfg.Now(), counter, fe)
	g.cfg.Problems(w, http.StatusForbidden, slug, title, fe.Error(), fe)
}

// RequireScopes authenticates the caller and requires every one of
// scopes; with none it only authenticates.
func (g *Guard) RequireScopes(scopes ...string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, r := g.authenticate(w, r)
			if c == nil {
				return
			}
			for _, s := range scopes {
				if err := coreauth.RequireScope(c.Claims, s); err != nil {
					g.refuse403(w, r, CounterRejectedScope, SlugForbidden, "Forbidden", core.Fieldf("scope", "%s is required", s))
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAnyScope authenticates the caller and requires one of scopes.
func (g *Guard) RequireAnyScope(scopes ...string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, r := g.authenticate(w, r)
			if c == nil {
				return
			}
			for _, s := range scopes {
				if c.Claims.HasScope(s) {
					next.ServeHTTP(w, r)
					return
				}
			}
			g.refuse403(w, r, CounterRejectedScope, SlugForbidden, "Forbidden",
				core.Fieldf("scope", "one of %s is required", strings.Join(scopes, ", ")))
		})
	}
}

// ClientID is the configured client id of publisher p.
func (g *Guard) ClientID(p Publisher) string {
	switch p {
	case PublisherAuthority:
		return g.cfg.AuthorityClientID
	case PublisherANSP:
		return g.cfg.ANSPClientID
	}
	return ""
}

// RequirePublisher authenticates the caller and requires its sub to be
// the configured client id of publisher p (M24).
func (g *Guard) RequirePublisher(p Publisher) Middleware {
	want := g.ClientID(p)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, r := g.authenticate(w, r)
			if c == nil {
				return
			}
			if want == "" || c.ClientID != want {
				g.refuse403(w, r, CounterRejectedPublisherBinding, SlugNotAPublisher, "Not a publisher",
					core.Fieldf("sub", "this client is not the %s publisher of this dataset", string(p)))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireMTLSSubject binds the ANSP's client certificate on the mTLS
// routes: in mode required the subject Caddy forwarded must equal the
// configured one (compared in constant time); in mode off every request
// passes and is counted (the status line reports the mode at error level).
// The bound subject is put on the caller, authenticating it first.
func (g *Guard) RequireMTLSSubject() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, r := g.authenticate(w, r)
			if c == nil {
				return
			}
			if g.cfg.MTLSMode == config.MTLSOff {
				g.count(CounterMTLSOffPassed)
				next.ServeHTTP(w, r)
				return
			}
			got := r.Header.Get(HeaderClientCertSubject)
			if got == "" {
				g.refuse403(w, r, CounterRejectedMTLSMissing, SlugMTLSRequired, "Client certificate required",
					core.Fieldf(HeaderClientCertSubject, "absent: this route needs the ANSP's client certificate"))
				return
			}
			if subtle.ConstantTimeCompare([]byte(got), []byte(g.cfg.ANSPMTLSSubject)) != 1 {
				g.refuse403(w, r, CounterRejectedMTLSSubject, SlugMTLSRequired, "Client certificate required",
					core.Fieldf(HeaderClientCertSubject, "does not match the ANSP's certificate subject"))
				return
			}
			bound := *c
			bound.MTLSSubject = got
			next.ServeHTTP(w, r.WithContext(WithCaller(r.Context(), &bound)))
		})
	}
}

// MTLSOffReason is the degraded text of the mtls component in mode off.
const MTLSOffReason = "off (CISP_MTLS_MODE=off): the ANSP's client certificate subject is not checked"

// ReportMTLS sets the mtls component: degraded at every status line while
// the mode is off (a disabled safeguard is never quiet), healthy otherwise.
func ReportMTLS(comp *obs.Component, mode string) {
	if mode == config.MTLSOff {
		comp.SetDegraded(MTLSOffReason)
		return
	}
	comp.SetHealthy()
}

// refusalLog logs the first refusal of each reason at once and then at
// most one line per interval with the number of refusals since (E-09).
// Its keys are the counter names, a fixed set, so it is bounded.
type refusalLog struct {
	every time.Duration
	mu    sync.Mutex
	seen  map[string]*refusalEntry
}

type refusalEntry struct {
	last       time.Time
	suppressed uint64
}

func (l *refusalLog) note(ctx context.Context, logger *slog.Logger, now time.Time, reason string, fe *core.FieldError) {
	l.mu.Lock()
	e, ok := l.seen[reason]
	if !ok {
		e = &refusalEntry{}
		l.seen[reason] = e
	}
	if ok && now.Sub(e.last) < l.every {
		e.suppressed++
		l.mu.Unlock()
		return
	}
	suppressed := e.suppressed
	e.last, e.suppressed = now, 0
	l.mu.Unlock()
	logger.LogAttrs(ctx, slog.LevelWarn, "request refused",
		slog.String("reason", reason),
		slog.String("field", fe.Field),
		slog.String("detail", fe.Reason),
		slog.Uint64("suppressed_since_last", suppressed),
	)
}
