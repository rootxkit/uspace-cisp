package stream

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/coder/websocket"
	coreauth "github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-cisp/internal/obs"
	"github.com/rootxkit/uspace-cisp/internal/publication"
)

// SessionCookie is the console session cookie every console in the
// ecosystem uses (M21).
const SessionCookie = "uspace_session"

// Problem slugs of the upgrade's refusals.
const (
	SlugUpgradeRequired = "upgrade_required"
	SlugBadRequest      = "bad_request"
	SlugOrigin          = "origin"
	SlugStreamFull      = "stream_full"
)

// maxDatasetsParam bounds the ?datasets= value read.
const maxDatasetsParam = 256

// defaultSessionTimeout bounds a session cookie's verification.
const defaultSessionTimeout = 2 * time.Second

// ProblemWriter writes an application/problem+json response
// (httpapi.WriteProblem).
type ProblemWriter func(w http.ResponseWriter, status int, slug, title, detail string, fields ...*core.FieldError)

// SessionVerifier verifies a console session token; nil error is a
// console session.
type SessionVerifier interface {
	VerifySession(ctx context.Context, token string) error
}

// TokenVerifier is the shared verifier (internal/auth.MachineVerifier).
type TokenVerifier interface {
	Verify(ctx context.Context, token string) (coreauth.Claims, error)
}

// ClaimsSessions verifies a session cookie with the shared verifier and
// the session shape of M20: scope exactly "session", realm "console",
// at least one role. WP-8 replaces it with its session check (which
// also refuses a revoked jti); the stream's content is the same for a
// console client.
type ClaimsSessions struct {
	Verifier TokenVerifier
}

// VerifySession implements SessionVerifier.
func (s ClaimsSessions) VerifySession(ctx context.Context, token string) error {
	if s.Verifier == nil {
		return errors.New("no session verifier configured")
	}
	cl, err := s.Verifier.Verify(ctx, token)
	if err != nil {
		return err
	}
	switch {
	case len(cl.Scopes) != 1 || cl.Scopes[0] != coreauth.SessionScope:
		return core.Fieldf("scope", "not a session token")
	case cl.Realm != "console":
		return core.Fieldf("realm", "%q is not console", cl.Realm)
	case len(cl.Roles) == 0:
		return core.Fieldf("roles", "none")
	}
	return nil
}

// HandlerConfig configures the upgrade of WS /v1/stream.
type HandlerConfig struct {
	// AllowedOrigins are the origins (scheme://host[:port]) a browser may
	// upgrade from: CISP_PUBLIC_BASE_URL's and CISP_STREAM_ALLOWED_ORIGINS.
	// An upgrade with an Origin outside them is refused 403; one without
	// an Origin is not a browser's and is served (public).
	AllowedOrigins []string
	// Public: a session cookie is optional (an invalid one is served as
	// public and counted). false: every client needs a valid console
	// session, and is closed with 4401 without one.
	Public bool
	// Sessions verifies the uspace_session cookie of a same-origin
	// upgrade; nil: no cookie verifies.
	Sessions       SessionVerifier
	SessionTimeout time.Duration
	Problems       ProblemWriter
}

// Handler is the WS /v1/stream upgrade on hub.
type Handler struct {
	hub     *Hub
	cfg     HandlerConfig
	origins map[string]bool
}

// NewHandler returns the upgrade handler. An origin that does not parse
// is left out (config refused it at start).
func NewHandler(hub *Hub, cfg HandlerConfig) *Handler {
	if cfg.SessionTimeout <= 0 {
		cfg.SessionTimeout = defaultSessionTimeout
	}
	if cfg.Problems == nil {
		cfg.Problems = func(w http.ResponseWriter, status int, _, title, _ string, _ ...*core.FieldError) {
			http.Error(w, title, status)
		}
	}
	h := &Handler{hub: hub, cfg: cfg, origins: map[string]bool{}}
	for _, o := range cfg.AllowedOrigins {
		if n, ok := NormalizeOrigin(o); ok {
			h.origins[n] = true
		}
	}
	return h
}

// NormalizeOrigin is an origin as browsers send it: lower-case scheme
// and host, the port only when it is not the scheme's default. ok is
// false for anything that is not an http(s) origin ("null" included).
func NormalizeOrigin(raw string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", false
	}
	host, port := strings.ToLower(u.Hostname()), u.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		host += ":" + port
	}
	return scheme + "://" + host, true
}

// ParseDatasets reads ?datasets=a,b: nil (every dataset) when absent or
// empty, else the named datasets, each a CIS dataset.
func ParseDatasets(raw string) (map[string]bool, *core.FieldError) {
	if raw == "" {
		return nil, nil
	}
	if len(raw) > maxDatasetsParam {
		return nil, core.Fieldf("datasets", "%d characters, at most %d", len(raw), maxDatasetsParam)
	}
	out := map[string]bool{}
	for _, name := range strings.Split(raw, ",") {
		name = strings.TrimSpace(name)
		if !publication.Dataset(name).Valid() {
			names := make([]string, 0, len(publication.Datasets))
			for _, d := range publication.Datasets {
				names = append(names, string(d))
			}
			return nil, core.Fieldf("datasets", "%q is not one of %s", name, strings.Join(names, ", "))
		}
		out[name] = true
	}
	return out, nil
}

func isUpgrade(r *http.Request) bool {
	return headerHas(r.Header, "Connection", "upgrade") && headerHas(r.Header, "Upgrade", "websocket")
}

func headerHas(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, part := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

func (h *Handler) refuse(w http.ResponseWriter, r *http.Request, counter string, status int, slug, title string, fe *core.FieldError) {
	h.hub.counter(counter).Inc()
	if ok, held := obs.Once("stream: upgrade refused "+slug, logEvery); ok {
		h.hub.cfg.Logger.LogAttrs(r.Context(), levelOf(status), "stream: upgrade refused",
			attrString("reason", slug), attrString("field", fe.Field), attrString("detail", fe.Reason),
			attrUint("also_refused_since_last_line", held))
	}
	h.cfg.Problems(w, status, slug, title, fe.Error(), fe)
}

// ServeHTTP judges the upgrade, then hands the connection to the hub.
// Every refusal before the upgrade is a problem+json with the field
// named; a session refusal after it is the close code 4401.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !isUpgrade(r) {
		w.Header().Set("Connection", "Upgrade")
		w.Header().Set("Upgrade", "websocket")
		h.refuse(w, r, CounterRefusedRequest, http.StatusUpgradeRequired, SlugUpgradeRequired, "WebSocket upgrade required",
			core.Fieldf("Upgrade", "this operation is a WebSocket upgrade (Connection: Upgrade, Upgrade: websocket)"))
		return
	}
	datasets, fe := ParseDatasets(r.URL.Query().Get("datasets"))
	if fe != nil {
		h.refuse(w, r, CounterRefusedRequest, http.StatusBadRequest, SlugBadRequest, "Bad request", fe)
		return
	}
	origin, hasOrigin := r.Header.Get("Origin"), r.Header.Get("Origin") != ""
	if hasOrigin {
		n, ok := NormalizeOrigin(origin)
		if !ok || !h.origins[n] {
			h.refuse(w, r, CounterRefusedOrigin, http.StatusForbidden, SlugOrigin, "Origin not allowed",
				core.Fieldf("Origin", "%q is not an origin this stream accepts", truncateOrigin(origin)))
			return
		}
	}
	if !h.hub.reserve() {
		w.Header().Set("Retry-After", strconv.Itoa(max(1, int(h.hub.cfg.StatusInterval/time.Second))))
		h.refuse(w, r, CounterRefusedCapacity, http.StatusServiceUnavailable, SlugStreamFull, "Stream full",
			core.Fieldf("stream", "this instance serves %d clients, its limit", h.hub.cfg.MaxClients))
		return
	}
	console, sessionOK := h.session(r, hasOrigin)

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true}) // the Origin is judged above
	if err != nil {
		h.hub.release()
		return // Accept has answered
	}
	if !sessionOK {
		h.hub.release()
		h.hub.counter(CounterSessionRefused).Inc()
		go func() { _ = conn.Close(CloseRelogin, "re-login") }()
		return
	}
	// The reader: CloseRead answers pings and the close handshake, and
	// ends the client when the peer goes or sends a data frame (the
	// stream takes none). Its context is not the hub's: cancelling it
	// would drop the connection before a close frame could be written.
	readCtx := conn.CloseRead(context.Background())
	h.hub.attach(wsConn{conn}, datasets, console, readCtx.Done())
}

// session reads the uspace_session cookie: (true, true) for a verified
// console session; (false, true) for a public client; (false, false)
// when the client must be closed with 4401 (a non-public stream without
// a valid session). A cookie counts only on a browser's upgrade from an
// allowed origin (same-origin, M22).
func (h *Handler) session(r *http.Request, hasOrigin bool) (console, ok bool) {
	ck, err := r.Cookie(SessionCookie)
	present := err == nil && ck.Value != "" && hasOrigin
	if present && h.cfg.Sessions != nil {
		ctx, cancel := context.WithTimeout(r.Context(), h.cfg.SessionTimeout)
		verr := h.cfg.Sessions.VerifySession(ctx, ck.Value)
		cancel()
		if verr == nil {
			h.hub.counter(CounterSessions).Inc()
			return true, true
		}
		if ok, held := obs.Once("stream: session cookie refused", logEvery); ok {
			h.hub.cfg.Logger.LogAttrs(r.Context(), levelOf(http.StatusUnauthorized), "stream: session cookie did not verify",
				attrString("error", verr.Error()), attrBool("public", h.cfg.Public), attrUint("also_refused_since_last_line", held))
		}
	}
	if h.cfg.Public {
		if present {
			h.hub.counter(CounterSessionIgnored).Inc()
		}
		return false, true
	}
	return false, false
}

// maxOriginEchoBytes bounds the refused Origin a problem echoes.
const maxOriginEchoBytes = 128

// truncateOrigin is s cut to at most maxOriginEchoBytes on a rune
// boundary, so a problem detail never holds half a UTF-8 sequence.
func truncateOrigin(s string) string {
	n := maxOriginEchoBytes
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// wsConn adapts *websocket.Conn to frameConn: every frame is a text
// message.
type wsConn struct{ c *websocket.Conn }

// Write sends frame as one text message.
func (w wsConn) Write(ctx context.Context, frame []byte) error {
	return w.c.Write(ctx, websocket.MessageText, frame)
}

// Close closes the connection with code and reason.
func (w wsConn) Close(code websocket.StatusCode, reason string) error {
	return w.c.Close(code, reason)
}

// AllowedOrigins is the origin of publicBaseURL followed by extra, each
// normalised; values that are not origins are left out.
func AllowedOrigins(publicBaseURL string, extra []string) []string {
	var out []string
	if u, err := url.Parse(publicBaseURL); err == nil && u.Host != "" {
		if n, ok := NormalizeOrigin(u.Scheme + "://" + u.Host); ok {
			out = append(out, n)
		}
	}
	for _, o := range extra {
		if n, ok := NormalizeOrigin(o); ok && !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out
}
