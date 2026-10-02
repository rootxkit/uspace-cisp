package httpapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-cisp/internal/auth"
	"github.com/rootxkit/uspace-cisp/internal/bus"
	"github.com/rootxkit/uspace-cisp/internal/console"
	"github.com/rootxkit/uspace-cisp/internal/httpapi/gen"
	"github.com/rootxkit/uspace-cisp/internal/obs"
	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/store"
)

// The console (docs/PLAN.md section 6.6, WP-8). THE CONSOLE HAS NO WRITE
// PATH TO CONTENT (hard rule 2, Annex III B(5)): nothing in this file
// writes a publication, a feature, a snapshot or a restriction. Its
// writes are accounts, sessions, subscription states, delivery retries
// and change records of the current version (republish); each is one
// transaction with its audit row, written first. A test reads this
// file and refuses a reference to the publication transaction.

// ConsoleRoute* are the console's operation patterns with the role each
// needs (the x-role of api/openapi.yaml; a test keeps the two equal).
const (
	ConsoleLoginRoute = "POST /v1/console/session"
)

// ConsoleRoles is the role each console operation needs; the login
// needs none (it is rate-limited per address instead).
var ConsoleRoles = map[string]string{
	"DELETE /v1/console/session":                                         auth.RoleViewer,
	"GET /v1/console/me":                                                 auth.RoleViewer,
	"GET /v1/console/accounts":                                           auth.RoleAdmin,
	"POST /v1/console/accounts":                                          auth.RoleAdmin,
	"PATCH /v1/console/accounts/{id}":                                    auth.RoleAdmin,
	"GET /v1/console/publications":                                       auth.RoleViewer,
	"GET /v1/console/publications/{id}/diff":                             auth.RoleViewer,
	"POST /v1/console/publications/{id}/republish":                       auth.RolePublisherAdmin,
	"GET /v1/console/restrictions":                                       auth.RoleViewer,
	"GET /v1/console/subscriptions":                                      auth.RoleViewer,
	"GET /v1/console/subscriptions/{id}/deliveries":                      auth.RoleViewer,
	"POST /v1/console/subscriptions/{id}/suspend":                        auth.RolePublisherAdmin,
	"POST /v1/console/subscriptions/{id}/resume":                         auth.RolePublisherAdmin,
	"POST /v1/console/subscriptions/{id}/deliveries/{delivery_id}/retry": auth.RolePublisherAdmin,
	"GET /v1/console/audit":                                              auth.RoleAdmin,
	"GET /v1/console/status":                                             auth.RoleViewer,
}

// consoleBodyRoutes are the console operations that carry a body:
// application/json only, and the console cap (docs/PLAN.md section 8.1
// T8: 64 KiB).
var consoleBodyRoutes = []string{
	ConsoleLoginRoute,
	"POST /v1/console/accounts",
	"PATCH /v1/console/accounts/{id}",
	"POST /v1/console/publications/{id}/republish",
	"POST /v1/console/subscriptions/{id}/suspend",
	"POST /v1/console/subscriptions/{id}/resume",
	"POST /v1/console/subscriptions/{id}/deliveries/{delivery_id}/retry",
}

// MaxConsoleBodyBytes caps a console body (64 KiB).
const MaxConsoleBodyBytes = 64 << 10

// ConsoleBodyCaps is the body cap of every console operation that
// carries one (Options.RouteBodyCaps).
func ConsoleBodyCaps() map[string]int64 {
	out := make(map[string]int64, len(consoleBodyRoutes))
	for _, r := range consoleBodyRoutes {
		out[r] = MaxConsoleBodyBytes
	}
	return out
}

// Login rate (docs/WORKPACKAGES/WP-8.md): 20 attempts per address per 15
// minutes, through the WP-4 limiter.
const (
	LoginBurst  = 20
	LoginWindow = 15 * time.Minute
)

// ConsoleAuth is the console's route middleware: the role of each
// operation through the session guard, application/json on the bodies,
// and the per-address login limiter on the login.
type ConsoleAuth struct {
	Sessions *auth.SessionGuard
	// Login limits the login per client address (a RateLimiter with
	// LoginBurst over LoginWindow).
	Login *RateLimiter
}

// Routes is the middleware of every console operation, keyed by
// pattern; it refuses a role it does not know.
func (a ConsoleAuth) Routes() (map[string]func(http.Handler) http.Handler, error) {
	if a.Sessions == nil || a.Login == nil {
		return nil, errors.New("console routes: a session guard and a login limiter are required")
	}
	body := map[string]bool{}
	for _, r := range consoleBodyRoutes {
		body[r] = true
	}
	out := map[string]func(http.Handler) http.Handler{
		ConsoleLoginRoute: func(next http.Handler) http.Handler {
			return auth.Chain(next, a.Login.Middleware, requireJSONMediaType)
		},
	}
	for route, role := range ConsoleRoles {
		mw, err := a.Sessions.RequireRole(role)
		if err != nil {
			return nil, err
		}
		if body[route] {
			out[route] = func(next http.Handler) http.Handler { return auth.Chain(next, mw, requireJSONMediaType) }
			continue
		}
		out[route] = mw
	}
	return out, nil
}

// ConsoleOffRoutes is the console's route middleware when the console is
// not configured: every operation answers 503 console_unavailable before
// anything else runs (fail closed: no console route is ever open).
func ConsoleOffRoutes() map[string]func(http.Handler) http.Handler {
	off := func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			WriteProblem(w, http.StatusServiceUnavailable, SlugConsoleUnavailable, "Console unavailable",
				"the console is not configured (CISP_SESSION_KEY_FILE, CISP_CONSOLE_ISSUER, CISP_SECRETS_KEY_FILE)")
		})
	}
	out := map[string]func(http.Handler) http.Handler{ConsoleLoginRoute: off}
	for route := range ConsoleRoles {
		out[route] = off
	}
	return out
}

// ConsoleStore is what the console's read models and actions need of
// the store (*store.Store in the api; a fake in the unit tests).
type ConsoleStore interface {
	Versions(ctx context.Context, ds publication.Dataset, before int64, limit int) ([]store.Version, error)
	PublicationByID(ctx context.Context, id string) (store.PublicationHead, error)
	PreviousPublication(ctx context.Context, p store.PublicationHead) (store.PublicationHead, error)
	FeatureChanges(ctx context.Context, pubID, prevID string, limit int) ([]store.FeatureChange, error)
	Republish(ctx context.Context, pubID string, e store.Event) (publication.Change, error)
	AllSubscriptions(ctx context.Context, f store.SubscriptionFilter) ([]store.SubscriptionRecord, map[string]map[string]int64, error)
	Subscription(ctx context.Context, id string) (store.SubscriptionRecord, error)
	SuspendSubscriptionAudited(ctx context.Context, id, reason string, e store.Event) error
	ResumeSubscriptionAudited(ctx context.Context, id, pingID string, e store.Event) error
	AuditEvents(ctx context.Context, f store.AuditFilter) ([]store.AuditRow, error)
}

// The audit events of the console's actions.
const (
	EventConsoleSuspended  = "console_subscription_suspended"
	EventConsoleResumed    = "console_subscription_resumed"
	EventConsoleRetried    = "console_delivery_retried"
	EventConsoleRepublish  = "console_republish"
	DefaultAuditSince      = 30 * 24 * time.Hour
	DefaultDiffFeatures    = 1000
	MaxDiffFeatures        = 5000
	CounterConsoleLogins   = "console_logins"
	CounterConsoleRefused  = "console_logins_refused"
	CounterConsoleActions  = "console_actions"
	consoleComponent       = "console"
	SlugSubscriptionState  = "subscription_state"
	SlugNotCurrent         = "not_current"
	SlugConsoleUnavailable = "console_unavailable"
)

// Console serves the console tag of api/openapi.yaml.
type Console struct {
	Accounts *console.Accounts
	Store    ConsoleStore
	// Subscriptions reads the deliveries with their attempts and requeues
	// a delivery (WP-6's code; the console reaches any client's).
	Subscriptions *Subscriptions
	// Restrictions lists the heads with the ANSP's staleness (WP-5's).
	Restrictions *Restrictions
	// Report is GET /v1/status's document.
	Report *StatusReport
	// Registry gives the process counters (nil: none).
	Registry *obs.Status
	// PublicBaseURL makes the pull_url of a republished change.
	PublicBaseURL string
	Logger        *slog.Logger
	// Now is the clock; nil is time.Now.
	Now func() time.Time
}

func (c *Console) now() time.Time {
	if c.Now == nil {
		return time.Now().UTC()
	}
	return c.Now().UTC()
}

func (c *Console) logger() *slog.Logger {
	if c.Logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return c.Logger
}

func (c *Console) counter(name, help string) {
	if c.Registry == nil {
		return
	}
	c.Registry.Component(consoleComponent).Counter(name, help).Inc()
}

// consoleResponse answers any console operation with a JSON body, a
// problem or no content.
type consoleResponse struct {
	w interface {
		write(http.ResponseWriter) error
	}
}

type noContent struct{}

func (noContent) write(w http.ResponseWriter) error {
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func ok(status int, body any) consoleResponse {
	return consoleResponse{w: jsonResponse{status: status, body: body}}
}

func prob(p problemResponse) consoleResponse { return consoleResponse{w: p} }

// VisitCreateConsoleSessionResponse implements gen.CreateConsoleSessionResponseObject.
func (r consoleResponse) VisitCreateConsoleSessionResponse(w http.ResponseWriter) error {
	return r.w.write(w)
}

// VisitDeleteConsoleSessionResponse implements gen.DeleteConsoleSessionResponseObject.
func (r consoleResponse) VisitDeleteConsoleSessionResponse(w http.ResponseWriter) error {
	return r.w.write(w)
}

// VisitGetConsoleMeResponse implements gen.GetConsoleMeResponseObject.
func (r consoleResponse) VisitGetConsoleMeResponse(w http.ResponseWriter) error {
	return r.w.write(w)
}

// VisitListConsoleAccountsResponse implements gen.ListConsoleAccountsResponseObject.
func (r consoleResponse) VisitListConsoleAccountsResponse(w http.ResponseWriter) error {
	return r.w.write(w)
}

// VisitCreateConsoleAccountResponse implements gen.CreateConsoleAccountResponseObject.
func (r consoleResponse) VisitCreateConsoleAccountResponse(w http.ResponseWriter) error {
	return r.w.write(w)
}

// VisitPatchConsoleAccountResponse implements gen.PatchConsoleAccountResponseObject.
func (r consoleResponse) VisitPatchConsoleAccountResponse(w http.ResponseWriter) error {
	return r.w.write(w)
}

// VisitListConsolePublicationsResponse implements gen.ListConsolePublicationsResponseObject.
func (r consoleResponse) VisitListConsolePublicationsResponse(w http.ResponseWriter) error {
	return r.w.write(w)
}

// VisitGetConsolePublicationDiffResponse implements gen.GetConsolePublicationDiffResponseObject.
func (r consoleResponse) VisitGetConsolePublicationDiffResponse(w http.ResponseWriter) error {
	return r.w.write(w)
}

// VisitRepublishConsolePublicationResponse implements gen.RepublishConsolePublicationResponseObject.
func (r consoleResponse) VisitRepublishConsolePublicationResponse(w http.ResponseWriter) error {
	return r.w.write(w)
}

// VisitListConsoleRestrictionsResponse implements gen.ListConsoleRestrictionsResponseObject.
func (r consoleResponse) VisitListConsoleRestrictionsResponse(w http.ResponseWriter) error {
	return r.w.write(w)
}

// VisitListConsoleSubscriptionsResponse implements gen.ListConsoleSubscriptionsResponseObject.
func (r consoleResponse) VisitListConsoleSubscriptionsResponse(w http.ResponseWriter) error {
	return r.w.write(w)
}

// VisitListConsoleDeliveriesResponse implements gen.ListConsoleDeliveriesResponseObject.
func (r consoleResponse) VisitListConsoleDeliveriesResponse(w http.ResponseWriter) error {
	return r.w.write(w)
}

// VisitSuspendConsoleSubscriptionResponse implements gen.SuspendConsoleSubscriptionResponseObject.
func (r consoleResponse) VisitSuspendConsoleSubscriptionResponse(w http.ResponseWriter) error {
	return r.w.write(w)
}

// VisitResumeConsoleSubscriptionResponse implements gen.ResumeConsoleSubscriptionResponseObject.
func (r consoleResponse) VisitResumeConsoleSubscriptionResponse(w http.ResponseWriter) error {
	return r.w.write(w)
}

// VisitRetryConsoleDeliveryResponse implements gen.RetryConsoleDeliveryResponseObject.
func (r consoleResponse) VisitRetryConsoleDeliveryResponse(w http.ResponseWriter) error {
	return r.w.write(w)
}

// VisitListConsoleAuditResponse implements gen.ListConsoleAuditResponseObject.
func (r consoleResponse) VisitListConsoleAuditResponse(w http.ResponseWriter) error {
	return r.w.write(w)
}

// VisitGetConsoleStatusResponse implements gen.GetConsoleStatusResponseObject.
func (r consoleResponse) VisitGetConsoleStatusResponse(w http.ResponseWriter) error {
	return r.w.write(w)
}

func consoleUnavailable(ctx context.Context) consoleResponse {
	return prob(problemOf(ctx, http.StatusServiceUnavailable, SlugConsoleUnavailable, "Console unavailable",
		"the api runs without a database (CISP_DATABASE_URL); the console has no accounts"))
}

// consoleCaller is the console session the route middleware verified.
func consoleCaller(ctx context.Context) (*auth.Caller, console.Actor, error) {
	c := auth.CallerFrom(ctx)
	role := auth.ConsoleRole(c)
	if role == "" {
		// The route middleware did not run: a wiring fault, never served.
		return nil, console.Actor{}, errors.New("console handler reached without a console session")
	}
	return c, console.AccountActor(c.ClientID, role), nil
}

// failure answers an error: a console refusal as its problem, the
// deadline as it is, an unreachable database 503, anything else 500
// (logged).
func (c *Console) failure(ctx context.Context, err error) (consoleResponse, error) {
	var ce *console.Error
	switch {
	case errors.As(err, &ce):
		fe := core.Fieldf(ce.Field, "%s", ce.Detail)
		p := problemOf(ctx, ce.Status, ce.Slug, http.StatusText(ce.Status), ce.Detail, fe)
		if ce.RetryAfter > 0 {
			p = retryAfter(p, console.RetryAfterSeconds(ce.RetryAfter))
		}
		return prob(p), nil
	case errors.Is(err, context.DeadlineExceeded):
		return consoleResponse{}, err
	case store.Unavailable(err):
		return prob(retryAfter(problemOf(ctx, http.StatusServiceUnavailable, SlugDatabaseUnavailable, "Database unavailable",
			"the database could not be reached; nothing was stored; retry later"), retryAfterDatabaseDownS)), nil
	}
	c.logger().LogAttrs(ctx, slog.LevelError, "console error", slog.String("route", routeOf(ctx)), slog.String("error", err.Error()))
	return prob(problemOf(ctx, http.StatusInternalServerError, SlugInternal, "Internal error",
		"the console failed; the failure is logged with this request id")), nil
}

func accountBody(a store.Account) gen.ConsoleAccount {
	return gen.ConsoleAccount{
		Id: a.ID, Username: a.Username, Role: gen.ConsoleRole(a.Role), Status: gen.ConsoleAccountStatus(a.Status),
		MfaRequired: a.MFARequired, MfaEnrolled: len(a.TOTPSecretEnc) > 0, CreatedAt: a.CreatedAt.UTC(),
		LastLoginAt: utc(a.LastLoginAt), FailedLogins: a.FailedLogins, LockedUntil: utc(a.LockedUntil),
	}
}

// actionEvent is the audit row of a console action: actor, role, target
// and the reason given.
func actionEvent(actor console.Actor, typ, entityType, entityID, reason string, at time.Time, extra map[string]any) store.Event {
	p := map[string]any{"reason": reason, "actor_role": actor.Role}
	for k, v := range extra {
		p[k] = v
	}
	return store.Event{TS: at, ActorType: actor.Type, ActorID: actor.ID, EventType: typ, EntityType: entityType, EntityID: entityID, Payload: p}
}

func reasonOf(ctx context.Context, body *gen.ConsoleActionReason) (string, *consoleResponse) {
	if body == nil || body.Reason == "" || len(body.Reason) > 500 {
		r := prob(badRequest(ctx, core.Fieldf("reason", "required, 1 to 500 characters: why, for the audit log")))
		return "", &r
	}
	return body.Reason, nil
}

// --- sessions and accounts -------------------------------------------------

// CreateConsoleSession logs in (WP-8).
func (s *Server) CreateConsoleSession(ctx context.Context, req gen.CreateConsoleSessionRequestObject) (gen.CreateConsoleSessionResponseObject, error) {
	c := s.Console
	if c == nil || c.Accounts == nil {
		return consoleUnavailable(ctx), nil
	}
	if req.Body == nil {
		return prob(badRequest(ctx, core.Fieldf("body", "required"))), nil
	}
	res, err := c.Accounts.Login(ctx, console.LoginRequest{Username: req.Body.Username, Password: req.Body.Password, TOTP: req.Body.Totp})
	if err != nil {
		var ce *console.Error
		if errors.As(err, &ce) {
			c.counter(CounterConsoleRefused, "Console logins refused (wrong credentials, locked, TOTP).")
		}
		return c.failure(ctx, err)
	}
	c.counter(CounterConsoleLogins, "Console sessions issued.")
	c.logger().LogAttrs(ctx, slog.LevelInfo, "console session issued", slog.String("account_id", res.Account.ID),
		slog.String("role", res.Account.Role), slog.String("jti", res.JTI))
	return ok(http.StatusCreated, gen.ConsoleSession{Token: res.Token, ExpiresAt: res.ExpiresAt.UTC(), Account: accountBody(res.Account)}), nil
}

// DeleteConsoleSession logs out (WP-8).
func (s *Server) DeleteConsoleSession(ctx context.Context, _ gen.DeleteConsoleSessionRequestObject) (gen.DeleteConsoleSessionResponseObject, error) {
	c := s.Console
	if c == nil || c.Accounts == nil {
		return consoleUnavailable(ctx), nil
	}
	caller, actor, err := consoleCaller(ctx)
	if err != nil {
		return nil, err
	}
	if err := c.Accounts.Logout(ctx, actor, caller.Claims.JTI); err != nil {
		return c.failure(ctx, err)
	}
	return consoleResponse{w: noContent{}}, nil
}

// GetConsoleMe is the caller (WP-8).
func (s *Server) GetConsoleMe(ctx context.Context, _ gen.GetConsoleMeRequestObject) (gen.GetConsoleMeResponseObject, error) {
	c := s.Console
	if c == nil || c.Accounts == nil {
		return consoleUnavailable(ctx), nil
	}
	caller, _, err := consoleCaller(ctx)
	if err != nil {
		return nil, err
	}
	acc, sess, err := c.Accounts.Me(ctx, caller.ClientID, caller.Claims.JTI)
	if err != nil {
		return c.failure(ctx, err)
	}
	out := gen.ConsoleMe{Account: accountBody(acc)}
	out.Session.Jti, out.Session.IssuedAt, out.Session.ExpiresAt = sess.JTI, sess.IssuedAt.UTC(), sess.ExpiresAt.UTC()
	return ok(http.StatusOK, out), nil
}

// ListConsoleAccounts lists the accounts (WP-8, admin).
func (s *Server) ListConsoleAccounts(ctx context.Context, _ gen.ListConsoleAccountsRequestObject) (gen.ListConsoleAccountsResponseObject, error) {
	c := s.Console
	if c == nil || c.Accounts == nil {
		return consoleUnavailable(ctx), nil
	}
	accs, err := c.Accounts.List(ctx)
	if err != nil {
		return c.failure(ctx, err)
	}
	out := gen.ConsoleAccountList{Accounts: make([]gen.ConsoleAccount, 0, len(accs))}
	for i := range accs {
		out.Accounts = append(out.Accounts, accountBody(accs[i]))
	}
	return ok(http.StatusOK, out), nil
}

// CreateConsoleAccount creates an account (WP-8, admin).
func (s *Server) CreateConsoleAccount(ctx context.Context, req gen.CreateConsoleAccountRequestObject) (gen.CreateConsoleAccountResponseObject, error) {
	c := s.Console
	if c == nil || c.Accounts == nil {
		return consoleUnavailable(ctx), nil
	}
	_, actor, err := consoleCaller(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return prob(badRequest(ctx, core.Fieldf("body", "required"))), nil
	}
	mfa := req.Body.MfaRequired != nil && *req.Body.MfaRequired
	created, err := c.Accounts.Create(ctx, actor, req.Body.Username, string(req.Body.Role), mfa)
	if err != nil {
		return c.failure(ctx, err)
	}
	c.counter(CounterConsoleActions, "Console actions written (accounts, subscriptions, retries, republications).")
	out := gen.ConsoleAccountCreated{Account: accountBody(created.Account), InitialPassword: created.Password}
	if created.TOTPURL != "" {
		u := created.TOTPURL
		out.TotpUri = &u
	}
	return ok(http.StatusCreated, out), nil
}

// PatchConsoleAccount changes an account (WP-8, admin).
func (s *Server) PatchConsoleAccount(ctx context.Context, req gen.PatchConsoleAccountRequestObject) (gen.PatchConsoleAccountResponseObject, error) {
	c := s.Console
	if c == nil || c.Accounts == nil {
		return consoleUnavailable(ctx), nil
	}
	_, actor, err := consoleCaller(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return prob(badRequest(ctx, core.Fieldf("body", "required"))), nil
	}
	p := console.Patch{ResetMFA: req.Body.ResetMfa != nil && *req.Body.ResetMfa}
	if req.Body.Role != nil {
		r := string(*req.Body.Role)
		p.Role = &r
	}
	if req.Body.Status != nil {
		st := string(*req.Body.Status)
		p.Status = &st
	}
	patched, err := c.Accounts.Patch(ctx, actor, req.Id, p)
	if err != nil {
		return c.failure(ctx, err)
	}
	c.counter(CounterConsoleActions, "Console actions written (accounts, subscriptions, retries, republications).")
	out := gen.ConsoleAccountPatched{Account: accountBody(patched.Account), SessionsRevoked: len(patched.Revoked)}
	if patched.TOTPURL != "" {
		u := patched.TOTPURL
		out.TotpUri = &u
	}
	return ok(http.StatusOK, out), nil
}

// --- read models -------------------------------------------------------------

func consolePublication(p store.PublicationHead) gen.ConsolePublicationVersion {
	return gen.ConsolePublicationVersion{
		Id: p.ID, Dataset: string(p.Dataset), Version: p.Version, Publisher: p.PublisherClientID, ReceivedAt: p.ReceivedAt.UTC(),
		FeatureCount: p.FeatureCount, Added: p.Added, Changed: p.Changed, Removed: p.Removed,
		SupersedesVersion: p.SupersedesVersion, Reason: string(p.Reason),
	}
}

// ListConsolePublications is a dataset's versions (WP-8, viewer).
func (s *Server) ListConsolePublications(ctx context.Context, req gen.ListConsolePublicationsRequestObject) (gen.ListConsolePublicationsResponseObject, error) {
	c := s.Console
	if c == nil || c.Store == nil {
		return consoleUnavailable(ctx), nil
	}
	ds := publication.Dataset(req.Params.Dataset)
	if !ds.Valid() {
		return prob(badRequest(ctx, core.Fieldf("dataset", "%q is not a dataset", quoteShort(string(ds))))), nil
	}
	limit, fe := listLimit(req.Params.Limit)
	if fe == nil && req.Params.Before != nil && *req.Params.Before < 1 {
		fe = core.Fieldf("before", "must be at least 1")
	}
	if fe != nil {
		return prob(badRequest(ctx, fe)), nil
	}
	var before int64
	if req.Params.Before != nil {
		before = *req.Params.Before
	}
	vs, err := c.Store.Versions(ctx, ds, before, limit)
	if err != nil {
		return c.failure(ctx, err)
	}
	out := gen.ConsolePublicationList{Dataset: string(ds), Versions: make([]gen.ConsolePublicationVersion, 0, len(vs))}
	for i := range vs {
		v := &vs[i]
		out.Versions = append(out.Versions, consolePublication(store.PublicationHead{
			ID: v.ID, Dataset: v.Dataset, Version: v.Version, PublisherClientID: v.PublisherClientID, ReceivedAt: v.ReceivedAt,
			FeatureCount: v.FeatureCount, Added: v.Added, Changed: v.Changed, Removed: v.Removed,
			SupersedesVersion: v.SupersedesVersion, Reason: v.Reason,
		}))
	}
	if n := len(vs); n == limit && n > 0 && vs[n-1].Version > 1 {
		next := vs[n-1].Version
		out.NextBefore = &next
	}
	return ok(http.StatusOK, out), nil
}

func pathChanges(ps []console.PathChange) *[]gen.ConsolePathChange {
	out := make([]gen.ConsolePathChange, 0, len(ps))
	for _, p := range ps {
		out = append(out, gen.ConsolePathChange{Path: p.Path, Op: gen.ConsolePathChangeOp(p.Op)})
	}
	return &out
}

// GetConsolePublicationDiff is what a version added, changed and
// removed (WP-8, viewer).
func (s *Server) GetConsolePublicationDiff(ctx context.Context, req gen.GetConsolePublicationDiffRequestObject) (gen.GetConsolePublicationDiffResponseObject, error) {
	c := s.Console
	if c == nil || c.Store == nil {
		return consoleUnavailable(ctx), nil
	}
	limit := DefaultDiffFeatures
	if req.Params.Limit != nil {
		if *req.Params.Limit < 1 || *req.Params.Limit > MaxDiffFeatures {
			return prob(badRequest(ctx, core.Fieldf("limit", "must be 1 to %d", MaxDiffFeatures))), nil
		}
		limit = *req.Params.Limit
	}
	pub, err := c.Store.PublicationByID(ctx, req.Id)
	if errors.Is(err, store.ErrNotFound) {
		fe := core.Fieldf("id", "%s is no publication", quoteShort(req.Id))
		return prob(problemOf(ctx, http.StatusNotFound, SlugNotFound, "Not found", fe.Error(), fe)), nil
	}
	if err != nil {
		return c.failure(ctx, err)
	}
	out := gen.ConsolePublicationDiff{Publication: consolePublication(pub)}
	out.Features = []struct {
		FeatureId      string                               `json:"feature_id"`
		Op             gen.ConsolePublicationDiffFeaturesOp `json:"op"`
		Paths          *[]gen.ConsolePathChange             `json:"paths,omitempty"`
		PathsTruncated *bool                                `json:"paths_truncated,omitempty"`
	}{}
	prev, err := c.Store.PreviousPublication(ctx, pub)
	switch {
	case errors.Is(err, store.ErrNotFound):
	case err != nil:
		return c.failure(ctx, err)
	default:
		v := prev.Version
		out.PreviousVersion = &v
	}
	if pub.Dataset.Kind() == publication.KindUsspList {
		if prev.ID != "" {
			paths, truncated, err := console.DiffPaths(prev.Body, pub.Body, console.MaxDiffPaths)
			if err != nil {
				return c.failure(ctx, err)
			}
			out.BodyPaths, out.BodyPathsTruncated = pathChanges(paths), &truncated
		}
		return ok(http.StatusOK, out), nil
	}
	changes, err := c.Store.FeatureChanges(ctx, pub.ID, prev.ID, limit+1)
	if err != nil {
		return c.failure(ctx, err)
	}
	if len(changes) > limit {
		changes, out.Truncated = changes[:limit], true
	}
	for _, fc := range changes {
		item := struct {
			FeatureId      string                               `json:"feature_id"`
			Op             gen.ConsolePublicationDiffFeaturesOp `json:"op"`
			Paths          *[]gen.ConsolePathChange             `json:"paths,omitempty"`
			PathsTruncated *bool                                `json:"paths_truncated,omitempty"`
		}{FeatureId: fc.FeatureID, Op: gen.ConsolePublicationDiffFeaturesOp(fc.Op)}
		if fc.Op == "changed" && len(fc.Previous) > 0 {
			paths, truncated, err := console.DiffPaths(fc.Previous, fc.Feature, console.MaxDiffPaths)
			if err != nil {
				return c.failure(ctx, fmt.Errorf("feature %s: %w", fc.FeatureID, err))
			}
			item.Paths, item.PathsTruncated = pathChanges(paths), &truncated
		}
		out.Features = append(out.Features, item)
	}
	return ok(http.StatusOK, out), nil
}

// ListConsoleRestrictions is the restriction heads (WP-8, viewer).
func (s *Server) ListConsoleRestrictions(ctx context.Context, req gen.ListConsoleRestrictionsRequestObject) (gen.ListConsoleRestrictionsResponseObject, error) {
	c := s.Console
	if c == nil || c.Restrictions == nil {
		return consoleUnavailable(ctx), nil
	}
	p := gen.ListRestrictionsParams{Limit: req.Params.Limit}
	if req.Params.State != nil {
		st := gen.ListRestrictionsParamsState(*req.Params.State)
		p.State = &st
	}
	resp, err := c.Restrictions.list(ctx, p)
	if err != nil {
		return nil, err
	}
	w, isWriter := resp.(interface {
		write(http.ResponseWriter) error
	})
	if !isWriter {
		return nil, fmt.Errorf("restrictions list answered %T", resp)
	}
	return consoleResponse{w: w}, nil
}

// ListConsoleSubscriptions is every client's subscriptions (WP-8, viewer).
func (s *Server) ListConsoleSubscriptions(ctx context.Context, req gen.ListConsoleSubscriptionsRequestObject) (gen.ListConsoleSubscriptionsResponseObject, error) {
	c := s.Console
	if c == nil || c.Store == nil {
		return consoleUnavailable(ctx), nil
	}
	limit, fe := listLimit(req.Params.Limit)
	if fe != nil {
		return prob(badRequest(ctx, fe)), nil
	}
	f := store.SubscriptionFilter{Limit: limit}
	if req.Params.Status != nil {
		st := string(*req.Params.Status)
		f.Status = &st
	}
	if req.Params.After != nil {
		f.AfterID = *req.Params.After
	}
	subs, sums, err := c.Store.AllSubscriptions(ctx, f)
	if err != nil {
		return c.failure(ctx, err)
	}
	out := gen.ConsoleSubscriptionList{Subscriptions: make([]gen.ConsoleSubscription, 0, len(subs))}
	for i := range subs {
		item := gen.ConsoleSubscription{Subscription: subscriptionBody(subs[i], nil)}
		m := sums[subs[i].ID]
		item.Deliveries.Queued, item.Deliveries.Delivering = m[store.DeliveryQueued], m[store.DeliveryDelivering]
		item.Deliveries.Delivered, item.Deliveries.Failed, item.Deliveries.Expired = m[store.DeliveryDelivered], m[store.DeliveryFailed], m[store.DeliveryExpired]
		out.Subscriptions = append(out.Subscriptions, item)
	}
	if n := len(subs); n == limit && n > 0 {
		next := subs[n-1].ID
		out.NextAfter = &next
	}
	return ok(http.StatusOK, out), nil
}

// existing is any client's subscription that is not deleted, or a 404.
func (c *Console) existing(ctx context.Context, id string) (store.SubscriptionRecord, *consoleResponse, error) {
	rec, err := c.Store.Subscription(ctx, id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && rec.Status == "deleted") {
		fe := core.Fieldf("id", "%s is no subscription", quoteShort(id))
		r := prob(problemOf(ctx, http.StatusNotFound, SlugNotFound, "Not found", fe.Error(), fe))
		return rec, &r, nil
	}
	if err != nil {
		r, ferr := c.failure(ctx, err)
		return rec, &r, ferr
	}
	return rec, nil, nil
}

// ListConsoleDeliveries is a subscription's deliveries (WP-8, viewer).
func (s *Server) ListConsoleDeliveries(ctx context.Context, req gen.ListConsoleDeliveriesRequestObject) (gen.ListConsoleDeliveriesResponseObject, error) {
	c := s.Console
	if c == nil || c.Store == nil || c.Subscriptions == nil {
		return consoleUnavailable(ctx), nil
	}
	limit, fe := listLimit(req.Params.Limit)
	if fe != nil {
		return prob(badRequest(ctx, fe)), nil
	}
	since := c.now().Add(-DefaultDeliveriesSince)
	if req.Params.Since != nil {
		t, fe := parseInstant("since", *req.Params.Since)
		if fe != nil {
			return prob(badRequest(ctx, fe)), nil
		}
		since = t
	}
	rec, r, err := c.existing(ctx, req.Id)
	if r != nil || err != nil {
		return *r, err
	}
	out, err := c.Subscriptions.deliveryList(ctx, rec.ID, since, limit)
	if err != nil {
		return c.failure(ctx, err)
	}
	return ok(http.StatusOK, out), nil
}

// --- actions -----------------------------------------------------------------

func (c *Console) subscriptionState(ctx context.Context, detail string) consoleResponse {
	fe := core.Fieldf("status", "%s", detail)
	return prob(problemOf(ctx, http.StatusConflict, SlugSubscriptionState, "Subscription state", fe.Error(), fe))
}

// SuspendConsoleSubscription suspends a subscription (WP-8,
// publisher_admin): audited with the reason before it happens.
func (s *Server) SuspendConsoleSubscription(ctx context.Context, req gen.SuspendConsoleSubscriptionRequestObject) (gen.SuspendConsoleSubscriptionResponseObject, error) {
	c := s.Console
	if c == nil || c.Store == nil {
		return consoleUnavailable(ctx), nil
	}
	_, actor, err := consoleCaller(ctx)
	if err != nil {
		return nil, err
	}
	reason, bad := reasonOf(ctx, req.Body)
	if bad != nil {
		return *bad, nil
	}
	now := c.now()
	stored := "suspended by the console at " + now.Format(time.RFC3339) + ": " + reason
	err = c.Store.SuspendSubscriptionAudited(ctx, req.Id, stored, actionEvent(actor, EventConsoleSuspended, "subscription", req.Id, reason, now, nil))
	switch {
	case errors.Is(err, store.ErrNotFound):
		_, r, _ := c.existing(ctx, req.Id)
		if r == nil {
			return c.failure(ctx, err)
		}
		return *r, nil
	case errors.Is(err, store.ErrSubscriptionState):
		return c.subscriptionState(ctx, "already suspended"), nil
	case err != nil:
		return c.failure(ctx, err)
	}
	return c.actionDone(ctx, actor, req.Id, EventConsoleSuspended)
}

// ResumeConsoleSubscription resumes a suspended subscription (WP-8,
// publisher_admin): pending_verification with a new ping.
func (s *Server) ResumeConsoleSubscription(ctx context.Context, req gen.ResumeConsoleSubscriptionRequestObject) (gen.ResumeConsoleSubscriptionResponseObject, error) {
	c := s.Console
	if c == nil || c.Store == nil {
		return consoleUnavailable(ctx), nil
	}
	_, actor, err := consoleCaller(ctx)
	if err != nil {
		return nil, err
	}
	reason, bad := reasonOf(ctx, req.Body)
	if bad != nil {
		return *bad, nil
	}
	now := c.now()
	ping := store.NewID(now)
	err = c.Store.ResumeSubscriptionAudited(ctx, req.Id, ping, actionEvent(actor, EventConsoleResumed, "subscription", req.Id, reason, now, map[string]any{"ping_id": ping}))
	switch {
	case errors.Is(err, store.ErrNotFound):
		_, r, _ := c.existing(ctx, req.Id)
		if r == nil {
			return c.failure(ctx, err)
		}
		return *r, nil
	case errors.Is(err, store.ErrSubscriptionState):
		return c.subscriptionState(ctx, "not suspended"), nil
	case err != nil:
		return c.failure(ctx, err)
	}
	return c.actionDone(ctx, actor, req.Id, EventConsoleResumed)
}

func (c *Console) actionDone(ctx context.Context, actor console.Actor, id, typ string) (consoleResponse, error) {
	c.counter(CounterConsoleActions, "Console actions written (accounts, subscriptions, retries, republications).")
	c.logger().LogAttrs(ctx, slog.LevelInfo, "console action", slog.String("event_type", typ),
		slog.String("account_id", actor.ID), slog.String("subscription_id", id))
	rec, err := c.Store.Subscription(ctx, id)
	if err != nil {
		return c.failure(ctx, err)
	}
	return ok(http.StatusOK, subscriptionBody(rec, nil)), nil
}

// RetryConsoleDelivery re-queues a delivery (WP-8, publisher_admin),
// through WP-6's requeue.
func (s *Server) RetryConsoleDelivery(ctx context.Context, req gen.RetryConsoleDeliveryRequestObject) (gen.RetryConsoleDeliveryResponseObject, error) {
	c := s.Console
	if c == nil || c.Store == nil || c.Subscriptions == nil {
		return consoleUnavailable(ctx), nil
	}
	_, actor, err := consoleCaller(ctx)
	if err != nil {
		return nil, err
	}
	reason, bad := reasonOf(ctx, req.Body)
	if bad != nil {
		return *bad, nil
	}
	rec, r, err := c.existing(ctx, req.Id)
	if r != nil || err != nil {
		return *r, err
	}
	now := c.now()
	d, err := c.Subscriptions.Store.RequeueDelivery(ctx, rec.ID, req.DeliveryId, now,
		actionEvent(actor, EventConsoleRetried, "delivery", req.DeliveryId, reason, now, map[string]any{"subscription_id": rec.ID}))
	switch {
	case errors.Is(err, store.ErrNotFound):
		fe := core.Fieldf("delivery_id", "%s is not a delivery of this subscription", quoteShort(req.DeliveryId))
		return prob(problemOf(ctx, http.StatusNotFound, SlugNotFound, "Not found", fe.Error(), fe)), nil
	case errors.Is(err, store.ErrDeliveryInFlight):
		fe := core.Fieldf("delivery_id", "an attempt is in flight; retry once it has ended")
		return prob(problemOf(ctx, http.StatusConflict, SlugDelivering, "Delivery in flight", fe.Error(), fe)), nil
	case err != nil:
		return c.failure(ctx, err)
	}
	c.counter(CounterConsoleActions, "Console actions written (accounts, subscriptions, retries, republications).")
	return ok(http.StatusAccepted, deliveryBody(d)), nil
}

// RepublishConsolePublication announces the current version again (WP-8,
// publisher_admin): a change record, never content.
func (s *Server) RepublishConsolePublication(ctx context.Context, req gen.RepublishConsolePublicationRequestObject) (gen.RepublishConsolePublicationResponseObject, error) {
	c := s.Console
	if c == nil || c.Store == nil {
		return consoleUnavailable(ctx), nil
	}
	_, actor, err := consoleCaller(ctx)
	if err != nil {
		return nil, err
	}
	reason, bad := reasonOf(ctx, req.Body)
	if bad != nil {
		return *bad, nil
	}
	ch, err := c.Store.Republish(ctx, req.Id, actionEvent(actor, EventConsoleRepublish, "publication", req.Id, reason, c.now(), nil))
	switch {
	case errors.Is(err, store.ErrNotFound):
		fe := core.Fieldf("id", "%s is no publication", quoteShort(req.Id))
		return prob(problemOf(ctx, http.StatusNotFound, SlugNotFound, "Not found", fe.Error(), fe)), nil
	case errors.Is(err, store.ErrNotCurrent):
		fe := core.Fieldf("id", "only the current version of a dataset is republished")
		return prob(problemOf(ctx, http.StatusConflict, SlugNotCurrent, "Not the current version", fe.Error(), fe)), nil
	case err != nil:
		return c.failure(ctx, err)
	}
	c.counter(CounterConsoleActions, "Console actions written (accounts, subscriptions, retries, republications).")
	c.logger().LogAttrs(ctx, slog.LevelInfo, "console republish", slog.String("account_id", actor.ID),
		slog.String("dataset", string(ch.Dataset)), slog.Int64("version", ch.Version), slog.Int64("change_id", ch.ID))
	m := bus.MessageOf(ch, c.PublicBaseURL)
	return ok(http.StatusAccepted, gen.Change{
		Schema: gen.ChangeSchema(m.Schema), MsgId: m.MsgID, Producer: m.Producer, Dataset: gen.ChangeDataset(m.Dataset),
		Version: m.Version, Etag: m.ETag, FeatureIds: m.FeatureIDs, RemovedIds: m.RemovedIDs,
		Reason: gen.ChangeReason(m.Reason), At: m.At, PullUrl: m.PullURL,
	}), nil
}

// --- audit and status ----------------------------------------------------------

// ListConsoleAudit is the audit log (WP-8, admin).
func (s *Server) ListConsoleAudit(ctx context.Context, req gen.ListConsoleAuditRequestObject) (gen.ListConsoleAuditResponseObject, error) {
	c := s.Console
	if c == nil || c.Store == nil {
		return consoleUnavailable(ctx), nil
	}
	limit, fe := listLimit(req.Params.Limit)
	if fe != nil {
		return prob(badRequest(ctx, fe)), nil
	}
	f := store.AuditFilter{Since: c.now().Add(-DefaultAuditSince), Actor: req.Params.Actor, EventType: req.Params.Type, Limit: limit}
	if req.Params.Since != nil {
		t, fe := parseInstant("since", *req.Params.Since)
		if fe != nil {
			return prob(badRequest(ctx, fe)), nil
		}
		f.Since = t
	}
	if req.Params.BeforeId != nil {
		if *req.Params.BeforeId < 1 {
			return prob(badRequest(ctx, core.Fieldf("before_id", "must be at least 1"))), nil
		}
		f.BeforeID = *req.Params.BeforeId
	}
	rows, err := c.Store.AuditEvents(ctx, f)
	if err != nil {
		return c.failure(ctx, err)
	}
	out := gen.ConsoleAuditList{Events: make([]gen.ConsoleAuditEvent, 0, len(rows))}
	for i := range rows {
		r := &rows[i]
		payload := map[string]any{}
		if len(r.Payload) > 0 {
			if err := json.Unmarshal(r.Payload, &payload); err != nil {
				return c.failure(ctx, fmt.Errorf("events row %d: %w", r.ID, err))
			}
		}
		e := gen.ConsoleAuditEvent{
			Id: r.ID, Ts: r.TS.UTC(), ActorType: gen.ConsoleAuditEventActorType(r.ActorType), ActorId: r.ActorID,
			EventType: r.EventType, EntityType: r.EntityType, EntityId: r.EntityID, Payload: payload, Hash: hex.EncodeToString(r.Hash),
		}
		if len(r.PrevHash) > 0 {
			ph := hex.EncodeToString(r.PrevHash)
			e.PrevHash = &ph
		}
		out.Events = append(out.Events, e)
	}
	if n := len(rows); n == limit && n > 0 && rows[n-1].ID > 1 {
		next := rows[n-1].ID
		out.NextBeforeId = &next
	}
	return ok(http.StatusOK, out), nil
}

// GetConsoleStatus is the status document with the counters (WP-8,
// viewer).
func (s *Server) GetConsoleStatus(ctx context.Context, _ gen.GetConsoleStatusRequestObject) (gen.GetConsoleStatusResponseObject, error) {
	c := s.Console
	if c == nil {
		return consoleUnavailable(ctx), nil
	}
	rep := c.Report
	if rep == nil {
		rep = &StatusReport{}
	}
	body := struct {
		Status   statusBody        `json:"status"`
		Counters map[string]uint64 `json:"counters"`
	}{Status: rep.build(ctx), Counters: map[string]uint64{}}
	if c.Registry != nil {
		body.Counters = c.Registry.Totals()
	}
	return ok(http.StatusOK, body), nil
}
