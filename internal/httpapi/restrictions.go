package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed269"
	"github.com/rootxkit/uspace-core/ed318"

	"github.com/rootxkit/uspace-cisp/internal/auth"
	"github.com/rootxkit/uspace-cisp/internal/dataset"
	"github.com/rootxkit/uspace-cisp/internal/httpapi/gen"
	"github.com/rootxkit/uspace-cisp/internal/jws"
	"github.com/rootxkit/uspace-cisp/internal/obs"
	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/restriction"
	"github.com/rootxkit/uspace-cisp/internal/store"
)

// Problem slugs of the restrictions (docs/WORKPACKAGES/WP-5.md).
const (
	SlugRestrictionRefused = "restriction_refused"
	SlugAnspVersion        = "ansp_version"
	SlugState              = "state"
)

// The route patterns of the restrictions tag.
const (
	restrictionCreateRoute = "POST /v1/restrictions"
	restrictionPatchRoute  = "PATCH /v1/restrictions/{id}"
	restrictionListRoute   = "GET /v1/restrictions/heads"
	restrictionGetRoute    = "GET /v1/restrictions/{id}"
)

// RestrictionWriteRoutes are the two write patterns, for their body cap
// (Options.RouteBodyCaps, CISP_MAX_RESTRICTION_BYTES).
var RestrictionWriteRoutes = []string{restrictionCreateRoute, restrictionPatchRoute}

// The components and counters of the restrictions.
const (
	restrictionsComponent = "restrictions"
	// ExpiryComponent is degraded while the expiry has not run for
	// ExpiryStaleAfter (a dead ticker) or could not expire a restriction.
	ExpiryComponent = "restriction_expiry"
	// ANSPComponent warns while the ANSP is stale (never an error: its
	// restrictions stay active until their ends_at, spec 02 F2).
	ANSPComponent = "ansp"

	CounterRestrictionsAccepted = "restrictions_accepted"
	CounterRestrictionsReplayed = "restrictions_replayed"
	CounterRestrictionsRefused  = "restrictions_refused"
	CounterRestrictionsExpired  = "restrictions_expired"
	CounterExpiryFailed         = "restriction_expiry_failed"
	CounterExpiryTicks          = "expiry_ticks"
	CounterExpiryNotLeader      = "expiry_ticks_not_leader"
	CounterHeartbeatRefUnknown  = "heartbeat_ref_unknown"
	CounterHeartbeatRefMissing  = "heartbeat_ref_missing"
	GaugeRestrictionsActive     = "restrictions_active"
)

// Defaults of the restrictions.
const (
	// JobRestrictionExpiry is the expiry's job name (its advisory lock and
	// its job_runs row).
	JobRestrictionExpiry = "restriction_expiry"
	// DefaultExpiryInterval is the expiry's tick (CISP_RESTRICTION_EXPIRY_INTERVAL_S).
	DefaultExpiryInterval = 5 * time.Second
	// DefaultExpiryStaleAfter is how old the last run may be before the
	// status line errs (CISP_RESTRICTION_EXPIRY_STALE_AFTER_S).
	DefaultExpiryStaleAfter = 30 * time.Second
	// MaxExpiredPerTick bounds one tick's work (E-10); the rest wait for
	// the next tick, 5 s later.
	MaxExpiredPerTick = 500
	// MaxListedRefs bounds the refs GET /v1/status lists per kind.
	MaxListedRefs = 100
	// mediaJSONRestriction is the content type of a restriction body and
	// of the expiry's own version body.
	mediaJSONRestriction = "application/json"
)

// RestrictionStore is what the restrictions need of the store
// (*store.Store in the api; a fake in the unit tests).
type RestrictionStore interface {
	Reserved(ctx context.Context, ds publication.Dataset, ids []string) (map[string]publication.Dataset, error)
	InsertAttempt(ctx context.Context, a store.Attempt) (string, error)
	RestrictionByFeatureID(ctx context.Context, featureID string) (store.RestrictionRecord, error)
	RestrictionPlacement(ctx context.Context, uspaceID string, parts []publication.GeomPart) (store.Placement, error)
	ApplyRestriction(ctx context.Context, w store.RestrictionWrite, signer store.Signer) (store.RestrictionResult, error)
	Restriction(ctx context.Context, ref string, byAnspRef bool) (store.RestrictionRecord, error)
	Restrictions(ctx context.Context, f store.RestrictionFilter) ([]store.RestrictionRecord, error)
	ExpiredRestrictions(ctx context.Context, now time.Time, limit int) ([]string, error)
	ActiveRestrictionRefs(ctx context.Context) ([]string, error)
	CountActiveRestrictions(ctx context.Context) (int64, error)
	RunJob(ctx context.Context, name, instance string, now time.Time, fn func(ctx context.Context) (int, error)) (bool, error)
	LastJobRun(ctx context.Context, name string) (store.JobRun, error)
	PublishersRefs(ctx context.Context) ([]store.PublisherRefs, error)
}

// Restrictions serves the restrictions tag of api/openapi.yaml, runs the
// expiry and reads the ANSP's staleness.
type Restrictions struct {
	Store RestrictionStore
	// Signer signs each new snapshot (KeyRingSigner); nil answers the
	// writes 503 signing_unavailable and leaves the expiry degraded.
	Signer store.Signer
	// Limits are the window limits; the api passes F3548Limits. Zero
	// refuses every window (E-15).
	Limits restriction.Limits
	// ANSPClientID is the configured ANSP (its staleness is read).
	ANSPClientID string
	// MaxBodyBytes bounds ed318.Parse of a restriction feature.
	MaxBodyBytes int64
	// ExpiryStaleAfter is how old the expiry's last run may be (0:
	// DefaultExpiryStaleAfter).
	ExpiryStaleAfter time.Duration
	// Instance names this process in job_runs.
	Instance string
	// Started is when the process started: before the first run, the
	// expiry is stale ExpiryStaleAfter after it.
	Started time.Time
	Status  *obs.Status
	Logger  *slog.Logger
	// Now is the clock; nil is time.Now.
	Now func() time.Time
	// OnPublished is called after each new version commits.
	OnPublished func()
}

func (rs *Restrictions) now() time.Time {
	if rs.Now == nil {
		return time.Now().UTC()
	}
	return rs.Now().UTC()
}

func (rs *Restrictions) logger() *slog.Logger {
	if rs.Logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return rs.Logger
}

func (rs *Restrictions) status() *obs.Status {
	if rs.Status == nil {
		rs.Status = obs.NewStatus("api", nil, time.Now())
	}
	return rs.Status
}

func (rs *Restrictions) counter(name string) *obs.Counter {
	return rs.status().Component(restrictionsComponent).Counter(name, "Dynamic restrictions ("+name+").")
}

// --- route authentication ---------------------------------------------

// RestrictionAuth builds the route middleware of the restrictions tag
// (docs/PLAN.md sections 6.2 and 8.3).
type RestrictionAuth struct {
	Guard *auth.Guard
	// ANSPSignature verifies the ANSP's X-JWS-Signature with the ANSP's
	// own JWKS (CISP_ANSP_JWKS_URL, section 15 Q8).
	ANSPSignature jws.SignatureGuard
}

// Routes is the middleware of the four operations, keyed by pattern.
//
//   - POST and PATCH: cis.publish:restrictions, sub = the ANSP, the
//     ANSP's client certificate subject, application/json, the detached
//     signature over the raw body, then the verified bytes kept for the
//     handler.
//   - GET heads and GET one: cis.read.
func (a RestrictionAuth) Routes() map[string]func(http.Handler) http.Handler {
	g := a.Guard
	write := func(next http.Handler) http.Handler {
		return auth.Chain(next,
			g.RequireScopes(auth.ScopePublishRestrictions),
			g.RequirePublisher(auth.PublisherANSP),
			g.RequireMTLSSubject(),
			requireJSONMediaType,
			a.ANSPSignature.RequireSignature(),
			keepVerifiedBody,
		)
	}
	read := g.RequireScopes(auth.ScopeRead)
	return map[string]func(http.Handler) http.Handler{
		restrictionCreateRoute: write,
		restrictionPatchRoute:  write,
		restrictionListRoute:   read,
		restrictionGetRoute:    read,
	}
}

// requireJSONMediaType answers 415 for anything but application/json.
func requireJSONMediaType(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mt != mediaJSONRestriction {
			fe := core.Fieldf("Content-Type", "must be application/json")
			WriteProblem(w, http.StatusUnsupportedMediaType, SlugUnsupportedMediaType, "Unsupported media type", fe.Error(), fe)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// --- responses ----------------------------------------------------------

// jsonResponse is a JSON answer of any operation of the tag.
type jsonResponse struct {
	status  int
	headers map[string]string
	body    any
}

func (j jsonResponse) write(w http.ResponseWriter) error {
	raw, err := json.Marshal(j.body)
	if err != nil {
		return err
	}
	for k, v := range j.headers {
		w.Header().Set(k, v)
	}
	w.Header().Set("Content-Type", mediaJSON)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(j.status)
	_, err = w.Write(append(raw, '\n'))
	return err
}

// VisitCreateRestrictionResponse implements gen.CreateRestrictionResponseObject.
func (j jsonResponse) VisitCreateRestrictionResponse(w http.ResponseWriter) error { return j.write(w) }

// VisitPatchRestrictionResponse implements gen.PatchRestrictionResponseObject.
func (j jsonResponse) VisitPatchRestrictionResponse(w http.ResponseWriter) error { return j.write(w) }

// VisitGetRestrictionResponse implements gen.GetRestrictionResponseObject.
func (j jsonResponse) VisitGetRestrictionResponse(w http.ResponseWriter) error { return j.write(w) }

// VisitListRestrictionsResponse implements gen.ListRestrictionsResponseObject.
func (j jsonResponse) VisitListRestrictionsResponse(w http.ResponseWriter) error { return j.write(w) }

// VisitCreateRestrictionResponse implements gen.CreateRestrictionResponseObject.
func (p problemResponse) VisitCreateRestrictionResponse(w http.ResponseWriter) error {
	return p.write(w)
}

// VisitPatchRestrictionResponse implements gen.PatchRestrictionResponseObject.
func (p problemResponse) VisitPatchRestrictionResponse(w http.ResponseWriter) error {
	return p.write(w)
}

// VisitGetRestrictionResponse implements gen.GetRestrictionResponseObject.
func (p problemResponse) VisitGetRestrictionResponse(w http.ResponseWriter) error { return p.write(w) }

// VisitListRestrictionsResponse implements gen.ListRestrictionsResponseObject.
func (p problemResponse) VisitListRestrictionsResponse(w http.ResponseWriter) error {
	return p.write(w)
}

// restrictionResponse is any answer of the tag.
type restrictionResponse interface {
	gen.CreateRestrictionResponseObject
	gen.PatchRestrictionResponseObject
	gen.GetRestrictionResponseObject
	gen.ListRestrictionsResponseObject
}

// headOf is the API head of a record.
func headOf(r store.RestrictionRecord) gen.RestrictionHead {
	h := gen.RestrictionHead{
		Id: r.ID, AnspRef: r.AnspRef, AnspVersion: r.AnspVersion, UspaceAirspaceId: r.UspaceAirspaceID,
		FeatureId: r.FeatureID, State: gen.RestrictionHeadState(r.State), StartsAt: r.StartsAt.UTC(), EndsAt: r.EndsAt.UTC(),
		CreatedAt: r.CreatedAt.UTC(), UpdatedAt: r.UpdatedAt.UTC(), Events: make([]gen.RestrictionEvent, 0, len(r.Events)),
	}
	if r.EndedBy != nil {
		by := gen.RestrictionHeadEndedBy(*r.EndedBy)
		h.EndedBy = &by
	}
	if r.LastPublisherClientID != "" {
		p := r.LastPublisherClientID
		h.LastPublisher = &p
	}
	for _, e := range r.Events {
		h.Events = append(h.Events, gen.RestrictionEvent{
			At: e.At.UTC(), Op: gen.RestrictionEventOp(e.Op), AnspVersion: e.AnspVersion,
			PublicationId: e.PublicationID, Actor: e.Actor,
		})
	}
	return h
}

// --- the operations -------------------------------------------------------

func restrictionsUnavailable(ctx context.Context) problemResponse {
	return problemOf(ctx, http.StatusServiceUnavailable, SlugIntakeUnavailable, "Restrictions unavailable",
		"the api runs without a database (CISP_DATABASE_URL); nothing can be stored or read")
}

// CreateRestriction creates a dynamic restriction (WP-5).
func (s *Server) CreateRestriction(ctx context.Context, req gen.CreateRestrictionRequestObject) (gen.CreateRestrictionResponseObject, error) {
	if s.Restrictions == nil {
		return restrictionsUnavailable(ctx), nil
	}
	return s.Restrictions.create(ctx, req.Params.XJWSSignature)
}

// PatchRestriction activates, extends, ends or cancels one (WP-5).
func (s *Server) PatchRestriction(ctx context.Context, req gen.PatchRestrictionRequestObject) (gen.PatchRestrictionResponseObject, error) {
	if s.Restrictions == nil {
		return restrictionsUnavailable(ctx), nil
	}
	return s.Restrictions.patch(ctx, req.Id, req.Params.By != nil && *req.Params.By == gen.PatchRestrictionParamsByAnspRef, req.Params.XJWSSignature)
}

// GetRestriction is one head with its events (WP-5).
func (s *Server) GetRestriction(ctx context.Context, req gen.GetRestrictionRequestObject) (gen.GetRestrictionResponseObject, error) {
	if s.Restrictions == nil {
		return restrictionsUnavailable(ctx), nil
	}
	return s.Restrictions.get(ctx, req.Id, req.Params.By != nil && *req.Params.By == gen.GetRestrictionParamsByAnspRef)
}

// ListRestrictions is the heads (WP-5).
func (s *Server) ListRestrictions(ctx context.Context, req gen.ListRestrictionsRequestObject) (gen.ListRestrictionsResponseObject, error) {
	if s.Restrictions == nil {
		return restrictionsUnavailable(ctx), nil
	}
	return s.Restrictions.list(ctx, req.Params)
}

// write is the context of one POST or PATCH: the verified body, the
// caller, the signature and the attempt it records when refused.
type write struct {
	body     []byte
	caller   *auth.Caller
	header   string
	kid      string
	received time.Time
	attempt  store.Attempt
}

func (rs *Restrictions) begin(ctx context.Context, signature *string) (write, error) {
	v, ok := verifiedBody(ctx)
	caller := auth.CallerFrom(ctx)
	sig, signed := jws.SignatureFrom(ctx)
	header := ""
	if signature != nil {
		header = *signature
	}
	if !ok || caller == nil || !signed || header == "" {
		// The route middleware did not run: a wiring fault, never served.
		return write{}, errors.New("restriction handler reached without authentication, signature and body")
	}
	received := rs.now()
	sum := sha256.Sum256(v.body)
	return write{
		body: v.body, caller: caller, header: header, kid: sig.KID, received: received,
		attempt: store.Attempt{
			Dataset: publication.DatasetRestrictions, PublisherClientID: caller.ClientID, ReceivedAt: received,
			Bytes: int64(len(v.body)), BodySHA256: sum[:],
		},
	}, nil
}

// refuse records the refused attempt and answers status with every
// problem: 400 restriction_refused, or 409 ansp_version or state.
func (rs *Restrictions) refuse(ctx context.Context, w write, status int, slug, title string, probs *ed269.Problems) problemResponse {
	rs.counter(CounterRestrictionsRefused).Inc()
	a := w.attempt
	a.Outcome = store.OutcomeRefused
	fields := make([]*core.FieldError, 0, len(probs.List))
	for _, pr := range probs.List {
		if len(a.Problems) < MaxProblemErrors {
			a.Problems = append(a.Problems, store.AttemptProblem{Field: pr.Field, Reason: pr.Reason})
		}
		fields = append(fields, &core.FieldError{Field: pr.Field, Reason: pr.Reason})
	}
	a.Truncated = probs.Truncated + max(0, len(probs.List)-MaxProblemErrors)
	if _, err := rs.Store.InsertAttempt(ctx, a); err != nil {
		rs.counter(CounterAttemptRecordFailed).Inc()
		rs.logger().LogAttrs(ctx, slog.LevelError, "restriction attempt not recorded",
			slog.String("client_id", a.PublisherClientID), slog.String("error", err.Error()))
	}
	n := len(probs.List) + probs.Truncated
	detail := strconv.Itoa(n) + " problems; the restriction op is refused whole and nothing was stored"
	if status == http.StatusConflict {
		detail = fields[0].Error() + "; nothing was stored"
	}
	resp := problemOf(ctx, status, slug, title, detail, fields...)
	if a.Truncated > 0 {
		t := true
		resp.problem.Truncated = &t
	}
	return resp
}

// refuseField refuses with one problem; a Conflict field is 409.
func (rs *Restrictions) refuseField(ctx context.Context, w write, fe *core.FieldError) problemResponse {
	probs := &ed269.Problems{List: []ed269.Problem{{Field: fe.Field, Reason: fe.Reason}}}
	if restriction.Conflict(fe.Field) {
		slug := SlugState
		if fe.Field == restriction.FieldAnspVersion {
			slug = SlugAnspVersion
		}
		return rs.refuse(ctx, w, http.StatusConflict, slug, "Conflict", probs)
	}
	return rs.refuse(ctx, w, http.StatusBadRequest, SlugRestrictionRefused, "Restriction refused", probs)
}

// failure answers a store error: refusals the database made (the D8 and
// identifier backstops), 503 for an unreachable database, the deadline
// as it is, and 500 otherwise.
func (rs *Restrictions) failure(ctx context.Context, w *write, err error) (problemResponse, error) {
	var fe *core.FieldError
	switch {
	case w != nil && errors.As(err, &fe):
		return rs.refuseField(ctx, *w, fe), nil
	case w != nil && store.IsIdentifierConflict(err):
		return rs.refuseField(ctx, *w, core.Fieldf("feature.properties.identifier",
			"is held by the current version of another dataset (published at the same time); identifiers are unique across zones, uspace_airspace and restrictions")), nil
	case w != nil && store.IsRestrictionIdentifierTaken(err):
		return rs.refuseField(ctx, *w, core.Fieldf("feature.properties.identifier",
			"names another restriction (created at the same time); an identifier names one restriction for ever")), nil
	case errors.Is(err, context.DeadlineExceeded):
		return problemResponse{}, err
	case store.Unavailable(err):
		resp := problemOf(ctx, http.StatusServiceUnavailable, SlugDatabaseUnavailable, "Database unavailable",
			"the database could not be reached; nothing was stored; retry later")
		resp.headers = map[string]string{"Retry-After": retryAfterDatabaseDownS}
		return resp, nil
	}
	rs.logger().LogAttrs(ctx, slog.LevelError, "restriction store error", slog.String("error", err.Error()))
	return problemOf(ctx, http.StatusInternalServerError, SlugInternal, "Internal error",
		"the store failed; the failure is logged with this request id"), nil
}

func signingUnavailable(ctx context.Context) problemResponse {
	return problemOf(ctx, http.StatusServiceUnavailable, SlugSigningUnavailable, "Signing unavailable",
		"no CISP signing key is configured (CISP_SIGNING_KEY_FILE); nothing was stored")
}

func (rs *Restrictions) featureLimits() ed318.Limits {
	return ed318.Limits{MaxBytes: int(rs.MaxBodyBytes)}
}

// --- POST /v1/restrictions ----------------------------------------------

func (rs *Restrictions) create(ctx context.Context, signature *string) (restrictionResponse, error) {
	w, err := rs.begin(ctx, signature)
	if err != nil {
		return nil, err
	}
	if rs.Signer == nil {
		return signingUnavailable(ctx), nil
	}
	body, probs := dataset.ParseRestrictionBody(w.body)
	if probs != nil {
		return rs.refuse(ctx, w, http.StatusBadRequest, SlugRestrictionRefused, "Restriction refused", probs), nil
	}
	req := restriction.Request{
		Op: restriction.OpCreate, AnspVersion: body.AnspVersion, State: restriction.State(body.State),
		Now: w.received, Limits: rs.Limits,
	}
	// A stored ansp_ref is a replay or a conflict: the transition alone
	// answers it, whatever the feature says now.
	_, err = rs.Store.Restriction(ctx, body.AnspRef, true)
	switch {
	case err == nil:
		return rs.apply(ctx, w, store.RestrictionWrite{AnspRef: body.AnspRef}, req, nil, nil, http.StatusCreated)
	case !errors.Is(err, store.ErrNotFound):
		return rs.failure(ctx, &w, err)
	}
	acc, probs := dataset.ValidateRestriction(body.Feature, dataset.RestrictionWindow{StartsAt: body.StartsAt, EndsAt: body.EndsAt}, rs.featureLimits())
	if probs != nil {
		return rs.refuse(ctx, w, http.StatusBadRequest, SlugRestrictionRefused, "Restriction refused", probs), nil
	}
	if resp, refused, err := rs.place(ctx, w, acc, body.AnspRef, body.UspaceAirspaceID); refused || err != nil {
		return resp, err
	}
	proposed := restriction.Head{
		ID: store.NewID(w.received), AnspRef: body.AnspRef, UspaceAirspaceID: body.UspaceAirspaceID,
		FeatureID: acc.Row.ID, StartsAt: body.StartsAt, EndsAt: body.EndsAt,
	}
	return rs.apply(ctx, w, store.RestrictionWrite{AnspRef: body.AnspRef}, req, &proposed, &acc, http.StatusCreated)
}

// place refuses an identifier another dataset or another restriction
// holds, and an outline the placement rules refuse.
func (rs *Restrictions) place(ctx context.Context, w write, acc dataset.AcceptedRestriction, anspRef, uspaceID string) (problemResponse, bool, error) {
	id := acc.Row.ID
	reserved, err := rs.Store.Reserved(ctx, publication.DatasetRestrictions, []string{id})
	if err != nil {
		resp, err := rs.failure(ctx, nil, err)
		return resp, true, err
	}
	if other, ok := reserved[id]; ok {
		return rs.refuseField(ctx, w, core.Fieldf("feature.properties.identifier",
			"%q is held by the current version of %s; identifiers are unique across zones, uspace_airspace and restrictions", id, other)), true, nil
	}
	holder, err := rs.Store.RestrictionByFeatureID(ctx, id)
	switch {
	case err == nil && holder.AnspRef != anspRef:
		return rs.refuseField(ctx, w, core.Fieldf("feature.properties.identifier",
			"%q names restriction %s (ansp_ref %q, %s); an identifier names one restriction for ever", id, holder.ID, holder.AnspRef, holder.State)), true, nil
	case err != nil && !errors.Is(err, store.ErrNotFound):
		resp, err := rs.failure(ctx, nil, err)
		return resp, true, err
	}
	pl, err := rs.Store.RestrictionPlacement(ctx, uspaceID, acc.Row.Geom)
	if err != nil {
		resp, err := rs.failure(ctx, &w, err)
		return resp, true, err
	}
	if probs := dataset.CheckPlacement(dataset.Placement(pl), uspaceID); probs != nil {
		return rs.refuse(ctx, w, http.StatusBadRequest, SlugRestrictionRefused, "Restriction refused", probs), true, nil
	}
	return problemResponse{}, false, nil
}

// apply runs the transition under the dataset's lock through the store
// and answers: created (status), replayed (200), or refused.
func (rs *Restrictions) apply(ctx context.Context, w write, target store.RestrictionWrite, req restriction.Request,
	proposed *restriction.Head, acc *dataset.AcceptedRestriction, status int,
) (restrictionResponse, error) {
	var published *ed318.Feature
	var warnings []dataset.Warning
	if acc != nil {
		published, warnings = acc.Feature, acc.Warnings
	}
	target.Decide = func(head *restriction.Head, current []store.StoredFeature) (store.RestrictionDecision, error) {
		var h restriction.Head
		switch {
		case head != nil:
			h = *head
		case proposed != nil:
			h = *proposed
		default:
			return store.RestrictionDecision{}, store.ErrNotFound
		}
		next, reason, err := restriction.Transition(h, req)
		if err != nil || reason == "" {
			return store.RestrictionDecision{Head: next}, err
		}
		var feature *ed318.Feature
		if published != nil && (head == nil || req.Op == restriction.OpExtend) {
			feature = published
		}
		return decision(next, req.Op, reason, current, feature)
	}
	target.Body, target.ContentType = w.body, mediaJSONRestriction
	target.PublisherClientID, target.ReceivedAt = w.caller.ClientID, w.received
	target.PublisherSignature, target.SignatureKID = &w.header, &w.kid
	res, err := rs.Store.ApplyRestriction(ctx, target, rs.Signer)
	if errors.Is(err, store.ErrNotFound) {
		return notFoundRestriction(ctx, target.ID+target.AnspRef), nil
	}
	if err != nil {
		return rs.failure(ctx, &w, err)
	}
	if res.Replay {
		rs.counter(CounterRestrictionsReplayed).Inc()
		return jsonResponse{status: http.StatusOK, headers: map[string]string{"ETag": res.ETag}, body: rs.result(ctx, res, nil)}, nil
	}
	rs.counter(CounterRestrictionsAccepted).Inc()
	if rs.OnPublished != nil {
		rs.OnPublished()
	}
	pubID := res.PublicationID
	a := w.attempt
	a.Outcome, a.PublicationID = store.OutcomeAccepted, &pubID
	if _, err := rs.Store.InsertAttempt(ctx, a); err != nil {
		rs.counter(CounterAttemptRecordFailed).Inc()
		rs.logger().LogAttrs(ctx, slog.LevelError, "restriction attempt not recorded",
			slog.String("client_id", a.PublisherClientID), slog.String("error", err.Error()))
	}
	rs.logger().LogAttrs(ctx, slog.LevelInfo, "restriction accepted",
		slog.String("restriction_id", res.Head.ID), slog.String("ansp_ref", res.Head.AnspRef),
		slog.Int64("ansp_version", res.Head.AnspVersion), slog.String("state", string(res.Head.State)),
		slog.String("reason", string(res.Reason)), slog.Int64("version", res.Version))
	return jsonResponse{status: status, headers: map[string]string{"ETag": res.ETag}, body: rs.result(ctx, res, warnings)}, nil
}

// decision is the new head with the current set after it, parsed from
// the stored features through ed318.Parse (the same code as a
// publication).
func decision(next restriction.Head, op restriction.Op, reason publication.Reason, current []store.StoredFeature, published *ed318.Feature) (store.RestrictionDecision, error) {
	stored := []ed318.Feature{}
	if len(current) > 0 {
		fc, err := collectionOf(current)
		if err != nil {
			return store.RestrictionDecision{}, err
		}
		stored = fc.Features
	}
	fc, err := restriction.CurrentSet(stored, next, published)
	if err != nil {
		var fe *core.FieldError
		if errors.As(err, &fe) {
			// The stored set lacks a current head's feature: a fault of
			// the store, never of the request.
			return store.RestrictionDecision{}, errors.New("restriction current set: " + fe.Error())
		}
		return store.RestrictionDecision{}, err
	}
	return store.RestrictionDecision{Head: next, Op: op, Reason: reason, Collection: fc}, nil
}

// result is the answer body of an accepted or replayed op: the head as
// stored now with its events.
func (rs *Restrictions) result(ctx context.Context, res store.RestrictionResult, warnings []dataset.Warning) gen.RestrictionResult {
	rec, err := rs.Store.Restriction(ctx, res.Head.ID, false)
	if err != nil {
		// The op stands; only its events are missing from the answer.
		rs.logger().LogAttrs(ctx, slog.LevelWarn, "restriction head not read back",
			slog.String("restriction_id", res.Head.ID), slog.String("error", err.Error()))
		rec = store.RestrictionRecord{Head: res.Head}
	}
	out := gen.RestrictionResult{
		Restriction: headOf(rec), Dataset: gen.RestrictionResultDataset(publication.DatasetRestrictions),
		Version: res.Version, Etag: res.ETag, Replay: res.Replay,
	}
	if !res.Replay {
		reason := gen.RestrictionResultReason(res.Reason)
		out.Reason = &reason
	}
	if len(warnings) > 0 {
		ws := make([]gen.Warning, 0, len(warnings))
		for _, w := range warnings {
			ws = append(ws, gen.Warning{Field: w.Field, Reason: w.Reason})
		}
		out.Warnings = &ws
	}
	return out
}

func notFoundRestriction(ctx context.Context, ref string) problemResponse {
	fe := core.Fieldf("id", "no restriction %s", quoteShort(ref))
	return problemOf(ctx, http.StatusNotFound, SlugNotFound, "Not found", fe.Error(), fe)
}

// --- PATCH /v1/restrictions/{id} ----------------------------------------

func (rs *Restrictions) patch(ctx context.Context, ref string, byAnspRef bool, signature *string) (restrictionResponse, error) {
	w, err := rs.begin(ctx, signature)
	if err != nil {
		return nil, err
	}
	if rs.Signer == nil {
		return signingUnavailable(ctx), nil
	}
	p, probs := dataset.ParseRestrictionPatch(w.body)
	if probs != nil {
		return rs.refuse(ctx, w, http.StatusBadRequest, SlugRestrictionRefused, "Restriction refused", probs), nil
	}
	head, err := rs.Store.Restriction(ctx, ref, byAnspRef)
	if errors.Is(err, store.ErrNotFound) {
		return notFoundRestriction(ctx, ref), nil
	}
	if err != nil {
		return rs.failure(ctx, &w, err)
	}
	req := restriction.Request{Op: restriction.Op(p.Op), AnspVersion: p.AnspVersion, EndsAt: p.EndsAt, Now: w.received, Limits: rs.Limits}
	var acc *dataset.AcceptedRestriction
	// The feature of a new extend is held to the rules with the new
	// window; a replay or a conflict is the transition's to answer.
	if p.Op == dataset.PatchExtend && p.AnspVersion > head.AnspVersion && !head.State.Terminal() {
		a, probs := dataset.ValidateRestriction(p.Feature, dataset.RestrictionWindow{StartsAt: head.StartsAt, EndsAt: *p.EndsAt}, rs.featureLimits())
		if probs != nil {
			return rs.refuse(ctx, w, http.StatusBadRequest, SlugRestrictionRefused, "Restriction refused", probs), nil
		}
		if a.Row.ID != head.FeatureID {
			return rs.refuseField(ctx, w, core.Fieldf("feature.properties.identifier",
				"%q is not this restriction's identifier %q; an extend republishes the same feature", a.Row.ID, head.FeatureID)), nil
		}
		if resp, refused, err := rs.place(ctx, w, a, head.AnspRef, head.UspaceAirspaceID); refused || err != nil {
			return resp, err
		}
		acc = &a
	}
	return rs.apply(ctx, w, store.RestrictionWrite{ID: head.ID}, req, nil, acc, http.StatusOK)
}

// --- GET /v1/restrictions/{id} and /v1/restrictions/heads ---------------

func (rs *Restrictions) get(ctx context.Context, ref string, byAnspRef bool) (restrictionResponse, error) {
	rec, err := rs.Store.Restriction(ctx, ref, byAnspRef)
	if errors.Is(err, store.ErrNotFound) {
		return notFoundRestriction(ctx, ref), nil
	}
	if err != nil {
		return rs.failure(ctx, nil, err)
	}
	return jsonResponse{status: http.StatusOK, body: headOf(rec)}, nil
}

// restrictionList is the RestrictionList body: cis_publisher_stale_since
// is absent while the ANSP is heard, a time once it is stale, and null
// when it has never been heard from.
type restrictionList struct {
	Restrictions []gen.RestrictionHead `json:"restrictions"`
	StaleSince   *staleSince           `json:"cis_publisher_stale_since,omitempty"`
}

// staleSince marshals as the time, or null when it is unknown.
type staleSince struct{ at *time.Time }

// MarshalJSON writes the time or null.
func (s staleSince) MarshalJSON() ([]byte, error) {
	if s.at == nil {
		return []byte("null"), nil
	}
	return json.Marshal(s.at.UTC())
}

func (rs *Restrictions) list(ctx context.Context, p gen.ListRestrictionsParams) (restrictionResponse, error) {
	f := store.RestrictionFilter{Limit: DefaultListLimit, Airspace: p.Airspace}
	if p.Limit != nil {
		if *p.Limit < 1 || *p.Limit > MaxListLimit {
			return badRequest(ctx, core.Fieldf("limit", "must be 1 to %d", MaxListLimit)), nil
		}
		f.Limit = *p.Limit
	}
	if p.State != nil {
		st := restriction.State(*p.State)
		if !st.Current() && !st.Terminal() {
			return badRequest(ctx, core.Fieldf("state", "%q is not planned, active, ended or cancelled", quoteShort(string(st)))), nil
		}
		f.State = &st
	}
	if p.At != nil {
		t, fe := parseInstant("at", *p.At)
		if fe != nil {
			return badRequest(ctx, fe), nil
		}
		f.At = &t
	}
	recs, err := rs.Store.Restrictions(ctx, f)
	if err != nil {
		return rs.failure(ctx, nil, err)
	}
	out := restrictionList{Restrictions: make([]gen.RestrictionHead, 0, len(recs))}
	for i := range recs {
		out.Restrictions = append(out.Restrictions, headOf(recs[i]))
	}
	if stale, since, err := rs.ANSPStale(ctx); err == nil && stale {
		out.StaleSince = &staleSince{at: since}
	} else if err != nil {
		rs.logger().LogAttrs(ctx, slog.LevelWarn, "ansp staleness not read", slog.String("error", err.Error()))
	}
	return jsonResponse{status: http.StatusOK, body: out}, nil
}

// --- staleness -------------------------------------------------------------

// ANSPStale reads the ANSP's staleness: stale when its last heartbeat is
// older than its stale_after_s (60 s, three missed 15 s heartbeats) or
// when it was never heard from (since nil). It decides nothing: no
// restriction is ended or hidden because the ANSP is silent (B-04, B-11).
func (rs *Restrictions) ANSPStale(ctx context.Context) (bool, *time.Time, error) {
	pubs, err := rs.Store.PublishersRefs(ctx)
	if err != nil {
		return false, nil, err
	}
	for _, p := range pubs {
		if p.ClientID == rs.ANSPClientID {
			return staleOf(p, rs.now())
		}
	}
	return true, nil, nil
}

func staleOf(p store.PublisherRefs, now time.Time) (bool, *time.Time, error) {
	after := time.Duration(p.StaleAfterS) * time.Second
	if after <= 0 {
		after = DefaultStaleAfter
	}
	if p.LastHeartbeatAt == nil {
		return true, nil, nil
	}
	if now.Sub(*p.LastHeartbeatAt) <= after {
		return false, nil, nil
	}
	since := p.LastHeartbeatAt.UTC().Add(after)
	return true, &since, nil
}
