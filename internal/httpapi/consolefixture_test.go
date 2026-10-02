package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rootxkit/uspace-cisp/internal/auth"
	"github.com/rootxkit/uspace-cisp/internal/authtest"
	"github.com/rootxkit/uspace-cisp/internal/console"
	"github.com/rootxkit/uspace-cisp/internal/console/consoletest"
	"github.com/rootxkit/uspace-cisp/internal/obs"
	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/store"
)

// The console's side of the harness (WP-8): the session issuer
// allow-listed in the harness's one verifier, the account service on an
// in-memory store (or PostgreSQL), the console store fake, the session
// guard with its revocation cache, and the console routes.

const (
	consoleIssuer = "https://uspace-cisp.example.test/console"
)

var testArgon2 = auth.Argon2Params{MemoryKiB: 64, Iterations: 1, Lanes: 1}

func consoleSessionIssuer(t testing.TB) *auth.SessionIssuer {
	t.Helper()
	si, err := auth.NewSessionIssuer(authtest.Key(t, "console-session", 3072), consoleIssuer, tokenAudience)
	if err != nil {
		t.Fatal(err)
	}
	return si
}

// fakeConsole is the console store on the harness's fake store: the
// versions and the subscriptions are the fake store's; the publication
// heads, the feature changes and the audit rows are its own.
type fakeConsole struct {
	*fakeStore
	pubs     map[string]store.PublicationHead
	changes  map[string][]store.FeatureChange
	current  map[publication.Dataset]string
	audit    []store.AuditRow
	events   []store.Event
	cursor   int64
	consoleE error
}

var _ ConsoleStore = (*fakeConsole)(nil)

func newFakeConsole(f *fakeStore) *fakeConsole {
	return &fakeConsole{fakeStore: f, pubs: map[string]store.PublicationHead{}, changes: map[string][]store.FeatureChange{}, current: map[publication.Dataset]string{}}
}

func (c *fakeConsole) err() error {
	if c.consoleE != nil {
		return c.consoleE
	}
	if c.down {
		return errFakeDown
	}
	return nil
}

func (c *fakeConsole) PublicationByID(_ context.Context, id string) (store.PublicationHead, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.err(); err != nil {
		return store.PublicationHead{}, err
	}
	p, ok := c.pubs[id]
	if !ok {
		return store.PublicationHead{}, store.ErrNotFound
	}
	return p, nil
}

func (c *fakeConsole) PreviousPublication(_ context.Context, p store.PublicationHead) (store.PublicationHead, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if p.SupersedesVersion == nil {
		return store.PublicationHead{}, store.ErrNotFound
	}
	for id := range c.pubs {
		if q := c.pubs[id]; q.Dataset == p.Dataset && q.Version == *p.SupersedesVersion {
			return q, nil
		}
	}
	return store.PublicationHead{}, store.ErrNotFound
}

func (c *fakeConsole) FeatureChanges(_ context.Context, pubID, _ string, limit int) ([]store.FeatureChange, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := append([]store.FeatureChange{}, c.changes[pubID]...)
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (c *fakeConsole) Republish(_ context.Context, pubID string, e store.Event) (publication.Change, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.err(); err != nil {
		return publication.Change{}, err
	}
	p, ok := c.pubs[pubID]
	if !ok {
		return publication.Change{}, store.ErrNotFound
	}
	if c.current[p.Dataset] != pubID {
		return publication.Change{}, store.ErrNotCurrent
	}
	c.events = append(c.events, e)
	c.cursor++
	return publication.Change{ID: c.cursor, Dataset: p.Dataset, Version: p.Version, FeatureIDs: []string{}, RemovedIDs: []string{},
		Reason: publication.ReasonRepublished, At: e.TS}, nil
}

func (c *fakeConsole) AllSubscriptions(_ context.Context, f store.SubscriptionFilter) ([]store.SubscriptionRecord, map[string]map[string]int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.err(); err != nil {
		return nil, nil, err
	}
	var out []store.SubscriptionRecord
	sums := map[string]map[string]int64{}
	for _, r := range c.sb().rows {
		if r.ID <= f.AfterID || (f.Status == nil && r.Status == "deleted") || (f.Status != nil && string(r.Status) != *f.Status) {
			continue
		}
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	if len(out) > f.Limit {
		out = out[:f.Limit]
	}
	for _, d := range c.sb().deliveries {
		m := sums[d.SubscriptionID]
		if m == nil {
			m = map[string]int64{}
			sums[d.SubscriptionID] = m
		}
		m[d.State]++
	}
	return out, sums, nil
}

func (c *fakeConsole) SuspendSubscriptionAudited(_ context.Context, id, reason string, e store.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.err(); err != nil {
		return err
	}
	r, ok := c.sb().rows[id]
	if !ok || r.Status == "deleted" {
		return store.ErrNotFound
	}
	if r.Status == "suspended" {
		return store.ErrSubscriptionState
	}
	c.events = append(c.events, e)
	r.Status, r.SuspendedReason = "suspended", &reason
	return nil
}

func (c *fakeConsole) ResumeSubscriptionAudited(_ context.Context, id, pingID string, e store.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.err(); err != nil {
		return err
	}
	r, ok := c.sb().rows[id]
	if !ok || r.Status == "deleted" {
		return store.ErrNotFound
	}
	if r.Status != "suspended" {
		return store.ErrSubscriptionState
	}
	c.events = append(c.events, e)
	r.Status, r.SuspendedReason = "pending_verification", nil
	c.sb().deliveries[pingID] = &store.DeliveryRecord{ID: pingID, SubscriptionID: id, Reason: publication.ReasonSubscriptionTest, State: store.DeliveryQueued, CreatedAt: e.TS}
	return nil
}

func (c *fakeConsole) AuditEvents(_ context.Context, f store.AuditFilter) ([]store.AuditRow, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.err(); err != nil {
		return nil, err
	}
	var out []store.AuditRow
	for i := len(c.audit) - 1; i >= 0; i-- {
		r := c.audit[i]
		if (f.BeforeID > 0 && r.ID >= f.BeforeID) || r.TS.Before(f.Since) || (f.Actor != nil && r.ActorID != *f.Actor) || (f.EventType != nil && r.EventType != *f.EventType) {
			continue
		}
		out = append(out, r)
		if len(out) == f.Limit {
			break
		}
	}
	return out, nil
}

// consoleAccountStore is what the harness's account service runs on.
type consoleAccountStore interface {
	console.Store
	auth.RevocationSource
	auth.ActivitySource
}

// withConsole builds the console on st and returns its routes.
func (h *pubHarness) withConsole(st PublicationStore, server *Server, status *obs.Status, logger *slog.Logger) map[string]func(http.Handler) http.Handler {
	h.t.Helper()
	var accounts consoleAccountStore
	var cs ConsoleStore
	switch s := st.(type) {
	case *fakeStore:
		h.accounts = consoletest.New(time.Now())
		accounts = h.accounts
		h.cfake = newFakeConsole(s)
		cs = h.cfake
	case *store.Store:
		accounts, cs = s, s
	default:
		return ConsoleOffRoutes()
	}
	h.revocations = auth.NewRevocationCache(auth.RevocationCacheConfig{Source: accounts, Component: status.Component("console_auth")})
	// As the api does: a database that is down at start leaves the cache
	// unloaded, and every check asks the database (fail closed).
	_ = h.revocations.Refresh(context.Background())
	// On the fake store the throttle reads the store's clock, so a test
	// that advances it moves both, as time does in the api.
	var clock func() time.Time
	if h.accounts != nil {
		clock = h.accounts.Now
	}
	activity, err := auth.NewActivity(auth.ActivityConfig{Source: accounts, Now: clock})
	if err != nil {
		h.t.Fatal(err)
	}
	guard, err := auth.NewSessionGuard(auth.SessionGuardConfig{
		Verifier: h.verifier, Issuer: consoleIssuer, Revocations: h.revocations, Activity: activity, Problems: WriteProblem, Component: status.Component("console_auth"),
	})
	if err != nil {
		h.t.Fatal(err)
	}
	sealer, err := console.NewSealer(k32())
	if err != nil {
		h.t.Fatal(err)
	}
	acc, err := console.NewAccounts(console.Config{Store: accounts, Sessions: h.sessions, Sealer: sealer, Revoker: h.revocations, Argon2: testArgon2})
	if err != nil {
		h.t.Fatal(err)
	}
	h.loginLimiter = NewRateLimiter(RateLimiterConfig{Burst: LoginBurst, Window: LoginWindow, Component: status.Component("console_login_ratelimit")})
	routes, err := ConsoleAuth{Sessions: guard, Login: h.loginLimiter}.Routes()
	if err != nil {
		h.t.Fatal(err)
	}
	h.console = &Console{
		Accounts: acc, Store: cs, Subscriptions: server.Subscriptions, Restrictions: server.Restrictions,
		Report: server.Status, Registry: status, PublicBaseURL: "https://uspace-cisp.example.test", Logger: logger,
	}
	server.Console = h.console
	return routes
}

var consoleUsers atomic.Int64

// consoleUser is a new account of role (MFA for admin) with its
// password and TOTP secret.
type consoleUser struct {
	id, username, password, secret, role string
}

func (h *pubHarness) consoleUser(t testing.TB, role string) consoleUser {
	t.Helper()
	name := "user-" + role + "-" + strconv.FormatInt(consoleUsers.Add(1), 10) + "-" + strconv.FormatInt(time.Now().UnixNano()%1_000_000, 10)
	c, err := h.console.Accounts.Create(context.Background(), console.Actor{ID: "test", Role: auth.RoleAdmin, Type: store.ActorSystem}, name, role, false)
	if err != nil {
		t.Fatal(err)
	}
	u := consoleUser{id: c.Account.ID, username: name, password: c.Password, role: role}
	if c.TOTPURL != "" {
		parsed, err := url.Parse(c.TOTPURL)
		if err != nil {
			t.Fatal(err)
		}
		u.secret = parsed.Query().Get("secret")
	}
	return u
}

// loginBody is the login body of u, with a TOTP code when it has MFA.
func (h *pubHarness) loginBody(t testing.TB, u consoleUser, step int) map[string]any {
	t.Helper()
	body := map[string]any{"username": u.username, "password": u.password}
	if u.secret != "" {
		code, err := auth.TOTPCode(u.secret, time.Now().Add(time.Duration(step)*auth.TOTPStep))
		if err != nil {
			t.Fatal(err)
		}
		body["totp"] = code
	}
	return body
}

// consoleToken logs a new account of role in and returns its token.
func (h *pubHarness) consoleToken(t testing.TB, role string) (string, consoleUser) {
	t.Helper()
	u := h.consoleUser(t, role)
	rec := h.consoleDo(t, h.consoleReq(http.MethodPost, "/v1/console/session", "", h.loginBody(t, u, 0)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("login %s = %d %s", role, rec.Code, rec.Body.String())
	}
	var s struct{ Token string }
	if err := json.Unmarshal(rec.Body.Bytes(), &s); err != nil {
		t.Fatal(err)
	}
	return s.Token, u
}

func (h *pubHarness) consoleReq(method, path, token string, body any) *http.Request {
	var rdr io.Reader = http.NoBody
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			h.t.Fatal(err)
		}
		rdr = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, rdr)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.RemoteAddr = "192.0.2.10:1234"
	return req
}

// httptestDo serves req without the conformance check (requests the
// spec itself refuses).
func httptestDo(h *pubHarness, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)
	return rec
}

// consoleDo serves req and checks the exchange against the spec.
func (h *pubHarness) consoleDo(t testing.TB, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(body))
	}
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)
	check := req.Clone(req.Context())
	check.Body = io.NopCloser(bytes.NewReader(body))
	conform(t, check, rec)
	return rec
}

// k32 is a secrets key for tests: 32 bytes built at run time so no
// key-shaped literal sits in the repository.
func k32() []byte { return bytes.Repeat([]byte{0x5a}, 32) }
