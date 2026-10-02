package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"strings"
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
	"github.com/rootxkit/uspace-cisp/internal/store"
)

// Problem slugs of the publication intake.
const (
	SlugPublicationRefused   = "publication_refused"
	SlugPreconditionRequired = "precondition_required"
	SlugPreconditionFailed   = "precondition_failed"
	SlugUnsupportedMediaType = "unsupported_media_type"
	SlugDatabaseUnavailable  = "database_unavailable"
	SlugSigningUnavailable   = "signing_unavailable"
	SlugIntakeUnavailable    = "intake_unavailable"
	SlugForbidden            = auth.SlugForbidden
	SlugNotAPublisher        = auth.SlugNotAPublisher
)

// The route patterns of the publications tag.
const (
	publicationRoute         = "PUT /v1/publications/{dataset}"
	publicationsListRoute    = "GET /v1/publications/{dataset}"
	publicationAttemptsRoute = "GET /v1/publications/{dataset}/attempts"
	publisherHeartbeatRoute  = "POST /v1/publishers/heartbeat"
	publicationsPathPrefix   = "/v1/publications/"
	// retryAfterDatabaseDownS is the Retry-After of a 503 for a database
	// that could not be reached.
	retryAfterDatabaseDownS = "5"
)

// PublicationRoute is the PUT pattern, for its body cap
// (Options.RouteBodyCaps).
const PublicationRoute = publicationRoute

// Counters of the publication intake, per dataset component (the
// component is the dataset name: publications_refused{dataset}).
const (
	CounterPublicationsRefused   = "publications_refused"
	CounterPublicationsAccepted  = "publications_accepted"
	CounterPublicationsUnchanged = "publications_unchanged"
	CounterAttemptRecordFailed   = "attempt_record_failed"
	CounterHeartbeats            = "heartbeats"
	CounterHeartbeatNotPublisher = "heartbeat_rejected_not_publisher"
)

// Bounds of the intake (E-10).
const (
	// MaxIDsPerList caps added, changed and removed in a PUT answer.
	MaxIDsPerList = 1000
	// MaxActiveRefs caps a heartbeat's active_refs.
	MaxActiveRefs = 1000
	// DefaultListLimit and MaxListLimit bound the history and attempts.
	DefaultListLimit = 100
	MaxListLimit     = 500
)

// The publishers' kinds as the publishers table names them.
const (
	publisherKindAuthority = "authority"
	publisherKindANSP      = "ansp"
)

// PublicationStore is what the publication handlers need of the store
// (*store.Store in the api; a fake in the unit tests).
type PublicationStore interface {
	CurrentVersion(ctx context.Context, ds publication.Dataset) (int64, error)
	Reserved(ctx context.Context, ds publication.Dataset, ids []string) (map[string]publication.Dataset, error)
	PublishTx(ctx context.Context, in store.PublishInput, signer store.Signer) (store.PublishResult, error)
	InsertAttempt(ctx context.Context, a store.Attempt) (string, error)
	Versions(ctx context.Context, ds publication.Dataset, before int64, limit int) ([]store.Version, error)
	RefusedAttempts(ctx context.Context, ds publication.Dataset, publisher string, since time.Time, limit int) ([]store.Attempt, error)
	RecordHeartbeat(ctx context.Context, h store.Heartbeat) error
}

// Publications serves the publications tag of api/openapi.yaml.
type Publications struct {
	Store PublicationStore
	// Signer signs each new snapshot with the CISP's key (KeyRingSigner);
	// nil answers PUT with 503 signing_unavailable.
	Signer store.Signer
	// MaxPublicationBytes is CISP_MAX_PUBLICATION_BYTES: the body cap of
	// PUT and the byte limit of ed318.Parse.
	MaxPublicationBytes int64
	// AuthorityClientID and ANSPClientID name the publishers.
	AuthorityClientID, ANSPClientID string
	// Status receives the per-dataset counters; nil: a private one.
	Status *obs.Status
	Logger *slog.Logger
	// Now is the clock; nil is time.Now.
	Now func() time.Time
	// OnPublished, when set, is called after each new version commits
	// (the api pokes its snapshot cache, so this instance's reads see the
	// version at once instead of at the next refresh).
	OnPublished func()
	// OnANSPRefs, when set, is handed the active_refs of every recorded
	// ANSP heartbeat that declares some (WP-5 compares them with the
	// active restrictions and counts the differences; it never acts on
	// them).
	OnANSPRefs func(ctx context.Context, refs []string)
}

func (p *Publications) now() time.Time {
	if p.Now == nil {
		return time.Now().UTC()
	}
	return p.Now().UTC()
}

func (p *Publications) logger() *slog.Logger {
	if p.Logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return p.Logger
}

func (p *Publications) count(component, name string) {
	if p.Status == nil {
		p.Status = obs.NewStatus("api", nil, time.Now())
	}
	p.Status.Component(component).Counter(name, "Publication intake outcomes ("+name+").").Inc()
}

// KeyRingSigner signs snapshots with the CISP's key ring (the Signer
// PublishTx takes).
type KeyRingSigner struct {
	Keys *jws.KeyRing
	// Now is the iat clock; nil is time.Now.
	Now func() time.Time
}

// Sign returns the compact detached JWS of body.
func (s KeyRingSigner) Sign(_ context.Context, body []byte) (string, error) {
	if s.Keys == nil {
		return "", errors.New("no signing key ring")
	}
	now := time.Now()
	if s.Now != nil {
		now = s.Now()
	}
	return s.Keys.SignDetached(body, now)
}

// --- route authentication ---------------------------------------------

// PublicationAuth builds the route middleware of the publications tag
// (docs/PLAN.md sections 6.1 and 8.3): every entry authenticates, and
// the router is fail-closed, so an operation of the tag without one
// stops the start.
type PublicationAuth struct {
	Guard *auth.Guard
	// AuthoritySignature verifies the authority's X-JWS-Signature on PUT.
	AuthoritySignature jws.SignatureGuard
	// Component counts heartbeat refusals; nil: a private one.
	Component *obs.Component
}

// Routes is the middleware of the four operations, keyed by pattern.
//
//   - PUT: the dataset's publish scope, sub = the authority, an
//     ED-318 or JSON content type, the detached signature over the raw
//     body (before anything else reads it), then the verified bytes are
//     kept for the handler.
//   - GET history: cis.read or the dataset's publisher.
//   - GET attempts: the dataset's publish scope and its publisher.
//   - POST heartbeat: any cis.publish:* scope, sub a configured
//     publisher, and for the ANSP its client certificate subject.
func (a PublicationAuth) Routes() map[string]func(http.Handler) http.Handler {
	g := a.Guard
	return map[string]func(http.Handler) http.Handler{
		publicationRoute: perDataset(func(ds publication.Dataset) []auth.Middleware {
			scope, okScope := auth.PublishScope(ds)
			if _, ok := dataset.KindOf(ds); !ok || !okScope {
				return []auth.Middleware{g.RequireScopes()} // 404 from the handler
			}
			return []auth.Middleware{
				g.RequireScopes(scope),
				g.RequirePublisher(auth.PublisherAuthority),
				requirePublicationMediaType,
				a.AuthoritySignature.RequireSignature(),
				keepVerifiedBody,
			}
		}),
		publicationsListRoute: perDataset(func(ds publication.Dataset) []auth.Middleware {
			pub, ok := auth.PublisherOf(ds)
			if !ok {
				return []auth.Middleware{g.RequireScopes()}
			}
			return []auth.Middleware{g.RequireScopes(), readerOrPublisher(g.ClientID(pub))}
		}),
		publicationAttemptsRoute: perDataset(func(ds publication.Dataset) []auth.Middleware {
			pub, okPub := auth.PublisherOf(ds)
			scope, okScope := auth.PublishScope(ds)
			if !okPub || !okScope {
				return []auth.Middleware{g.RequireScopes()}
			}
			return []auth.Middleware{g.RequireScopes(scope), g.RequirePublisher(pub)}
		}),
		publisherHeartbeatRoute: func(next http.Handler) http.Handler {
			return auth.Chain(next,
				g.RequireAnyScope(auth.ScopePublishZones, auth.ScopePublishUSpace, auth.ScopePublishUSSPList, auth.ScopePublishRestrictions),
				a.bindPublisher(),
			)
		},
	}
}

// perDataset picks the chain by the dataset in the path. Route
// middleware runs before the mux has set path values, so the dataset is
// read from the path itself; the handler validates it again.
func perDataset(chain func(ds publication.Dataset) []auth.Middleware) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		byDataset := map[publication.Dataset]http.Handler{}
		for _, ds := range publication.Datasets {
			byDataset[ds] = auth.Chain(next, chain(ds)...)
		}
		unknown := auth.Chain(next, chain("")...)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h, ok := byDataset[datasetOf(r.URL.Path)]; ok {
				h.ServeHTTP(w, r)
				return
			}
			unknown.ServeHTTP(w, r)
		})
	}
}

// datasetOf is the {dataset} segment of a /v1/publications/... path.
func datasetOf(path string) publication.Dataset {
	rest, ok := strings.CutPrefix(path, publicationsPathPrefix)
	if !ok {
		return ""
	}
	seg, _, _ := strings.Cut(rest, "/")
	return publication.Dataset(seg)
}

// readerOrPublisher lets through a caller with cis.read or the client
// id publisher (the dataset's publisher reads its own history).
func readerOrPublisher(publisher string) auth.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c := auth.CallerFrom(r.Context())
			if c != nil && (c.Claims.HasScope(auth.ScopeRead) || (publisher != "" && c.ClientID == publisher)) {
				next.ServeHTTP(w, r)
				return
			}
			fe := core.Fieldf("scope", "%s is required, or the caller must be this dataset's publisher", auth.ScopeRead)
			WriteProblem(w, http.StatusForbidden, SlugForbidden, "Forbidden", fe.Error(), fe)
		})
	}
}

// bindPublisher lets through the authority, puts the ANSP through its
// client certificate check, and refuses every other client.
func (a PublicationAuth) bindPublisher() auth.Middleware {
	authority := a.Guard.ClientID(auth.PublisherAuthority)
	ansp := a.Guard.ClientID(auth.PublisherANSP)
	mtls := a.Guard.RequireMTLSSubject()
	return func(next http.Handler) http.Handler {
		anspNext := mtls(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c := auth.CallerFrom(r.Context())
			switch {
			case c != nil && authority != "" && c.ClientID == authority:
				next.ServeHTTP(w, r)
			case c != nil && ansp != "" && c.ClientID == ansp:
				anspNext.ServeHTTP(w, r)
			default:
				if a.Component != nil {
					a.Component.Counter(CounterHeartbeatNotPublisher, "Heartbeats refused because sub is not a configured publisher.").Inc()
				}
				fe := core.Fieldf("sub", "this client is not a configured publisher")
				WriteProblem(w, http.StatusForbidden, SlugNotAPublisher, "Not a publisher", fe.Error(), fe)
			}
		})
	}
}

// publicationMediaTypes are the content types a publication may have.
var publicationMediaTypes = map[string]bool{"application/geo+json": true, "application/json": true}

// requirePublicationMediaType answers 415 for any other content type.
func requirePublicationMediaType(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || !publicationMediaTypes[mt] {
			fe := core.Fieldf("Content-Type", "must be application/geo+json or application/json")
			WriteProblem(w, http.StatusUnsupportedMediaType, SlugUnsupportedMediaType, "Unsupported media type", fe.Error(), fe)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type verifiedBodyKey struct{}

// verified is the request body the signature covered and its
// Content-Type.
type verified struct {
	body        []byte
	contentType string
}

// keepVerifiedBody runs after the signature check: it keeps the exact
// bytes the signature covered for the handler, and hands the generated
// decoder a JSON null instead, so that nothing but ed318.Parse and the
// dataset rules ever judges the body (a refusal is then an attempt with
// its problems, never a decoder error).
func keepVerifiedBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			fe := core.Fieldf("body", "could not be read: %v", err)
			WriteProblem(w, http.StatusBadRequest, SlugBadRequest, "Bad request", fe.Error(), fe)
			return
		}
		r.Body = io.NopCloser(strings.NewReader("null"))
		r.ContentLength = 4
		v := verified{body: body, contentType: r.Header.Get("Content-Type")}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), verifiedBodyKey{}, v)))
	})
}

func verifiedBody(ctx context.Context) (verified, bool) {
	v, ok := ctx.Value(verifiedBodyKey{}).(verified)
	return v, ok
}

// --- responses ----------------------------------------------------------

// problemResponse is a problem+json answer of any of the four
// operations, with optional headers.
type problemResponse struct {
	status  int
	problem gen.Problem
	headers map[string]string
}

func (p problemResponse) write(w http.ResponseWriter) error {
	for k, v := range p.headers {
		w.Header().Set(k, v)
	}
	body, err := json.Marshal(p.problem)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(p.status)
	_, err = w.Write(append(body, '\n'))
	return err
}

// VisitPutPublicationResponse implements gen.PutPublicationResponseObject.
func (p problemResponse) VisitPutPublicationResponse(w http.ResponseWriter) error { return p.write(w) }

// VisitListPublicationsResponse implements gen.ListPublicationsResponseObject.
func (p problemResponse) VisitListPublicationsResponse(w http.ResponseWriter) error {
	return p.write(w)
}

// VisitListPublicationAttemptsResponse implements gen.ListPublicationAttemptsResponseObject.
func (p problemResponse) VisitListPublicationAttemptsResponse(w http.ResponseWriter) error {
	return p.write(w)
}

// VisitPostPublisherHeartbeatResponse implements gen.PostPublisherHeartbeatResponseObject.
func (p problemResponse) VisitPostPublisherHeartbeatResponse(w http.ResponseWriter) error {
	return p.write(w)
}

func problemOf(ctx context.Context, status int, slug, title, detail string, fields ...*core.FieldError) problemResponse {
	return problemResponse{status: status, problem: NewProblem(status, slug, title, detail, obs.RequestID(ctx), fields...)}
}

func notFoundDataset(ctx context.Context, ds string) problemResponse {
	fe := core.Fieldf("dataset", "%q has no such operation", ds)
	return problemOf(ctx, http.StatusNotFound, SlugNotFound, "Not found", fe.Error(), fe)
}

// storeFailure is the answer to a store error: 503 with Retry-After for
// a connectivity failure (store.Unavailable), the deadline error as it is
// (503 timeout), and for anything else a 500 internal problem, logged
// with the dataset, the client and the error.
func (p *Publications) storeFailure(ctx context.Context, ds publication.Dataset, err error) (problemResponse, error) {
	if errors.Is(err, context.DeadlineExceeded) {
		return problemResponse{}, err
	}
	if store.Unavailable(err) {
		resp := problemOf(ctx, http.StatusServiceUnavailable, SlugDatabaseUnavailable, "Database unavailable",
			"the database could not be reached; nothing was stored; retry later")
		resp.headers = map[string]string{"Retry-After": retryAfterDatabaseDownS}
		return resp, nil
	}
	client := ""
	if c := auth.CallerFrom(ctx); c != nil {
		client = c.ClientID
	}
	p.logger().LogAttrs(ctx, slog.LevelError, "store error",
		slog.String("dataset", string(ds)), slog.String("client_id", client), slog.String("error", err.Error()))
	return problemOf(ctx, http.StatusInternalServerError, SlugInternal, "Internal error",
		"the store failed; the failure is logged with this request id"), nil
}

// --- PUT /v1/publications/{dataset} -------------------------------------

func (p *Publications) put(ctx context.Context, req gen.PutPublicationRequestObject) (gen.PutPublicationResponseObject, error) {
	ds := publication.Dataset(req.Dataset)
	kind, ok := dataset.KindOf(ds)
	if !ok {
		return notFoundDataset(ctx, string(req.Dataset)), nil
	}
	v, ok := verifiedBody(ctx)
	body := v.body
	caller := auth.CallerFrom(ctx)
	sig, signed := jws.SignatureFrom(ctx)
	if !ok || caller == nil || !signed || req.Params.XJWSSignature == nil {
		// The route middleware did not run: a wiring fault, never served.
		return nil, errors.New("publication handler reached without authentication, signature and body")
	}
	if p.Signer == nil {
		return problemOf(ctx, http.StatusServiceUnavailable, SlugSigningUnavailable, "Signing unavailable",
			"no CISP signing key is configured (CISP_SIGNING_KEY_FILE); nothing was stored"), nil
	}
	if req.Params.IfMatch == nil {
		fe := core.Fieldf("If-Match", "is required: send the current ETag of %s", ds)
		return problemOf(ctx, http.StatusPreconditionRequired, SlugPreconditionRequired, "Precondition required", fe.Error(), fe), nil
	}
	current, err := p.Store.CurrentVersion(ctx, ds)
	if err != nil {
		return p.storeFailure(ctx, ds, err)
	}
	if etag := publication.ETag(ds, current); strings.TrimSpace(*req.Params.IfMatch) != etag {
		return preconditionFailed(ctx, *req.Params.IfMatch, etag), nil
	}

	received := p.now()
	attempt := store.Attempt{Dataset: ds, PublisherClientID: caller.ClientID, ReceivedAt: received, Bytes: int64(len(body))}
	sum := sha256.Sum256(body)
	attempt.BodySHA256 = sum[:]

	lim := ed318.Limits{MaxBytes: int(p.MaxPublicationBytes)}
	acc, probs := dataset.For(kind).Validate(body, lim, received)
	if probs == nil && len(acc.Rows) > 0 {
		reserved, err := p.Store.Reserved(ctx, ds, rowIDs(acc.Rows))
		if err != nil {
			return p.storeFailure(ctx, ds, err)
		}
		probs = reservedProblems(acc.Rows, reserved)
	}
	if probs != nil {
		return p.refuse(ctx, ds, attempt, probs), nil
	}

	warnings, err := json.Marshal(nonNilWarnings(acc.Warnings))
	if err != nil {
		return nil, err
	}
	mediaType, _, _ := mime.ParseMediaType(v.contentType)
	header, kid := *req.Params.XJWSSignature, sig.KID
	in := store.PublishInput{
		Dataset: ds, Body: body, ContentType: mediaType, PublisherClientID: caller.ClientID,
		PublisherSignature: &header, SignatureKID: &kid, Collection: acc.Collection, Rows: acc.Rows,
		Warnings: warnings, Reason: publication.ReasonPublication, ReceivedAt: received,
		ExpectedVersion: &current,
	}
	res, err := p.Store.PublishTx(ctx, in, p.Signer)
	switch {
	case errors.Is(err, store.ErrUnchanged):
		p.count(string(ds), CounterPublicationsUnchanged)
		unchanged := true
		etag := res.ETag
		return gen.PutPublication200JSONResponse{
			Body:    gen.PublicationResult{Dataset: gen.PublicationResultDataset(ds), Version: res.Version, Etag: etag, Unchanged: &unchanged},
			Headers: gen.PutPublication200ResponseHeaders{ETag: &etag},
		}, nil
	case errors.Is(err, store.ErrVersionMismatch):
		return preconditionFailed(ctx, *req.Params.IfMatch, res.ETag), nil
	case store.IsIdentifierConflict(err):
		return p.refuse(ctx, ds, attempt, &ed269.Problems{List: []ed269.Problem{{
			Field:  "features",
			Reason: "an identifier is held by the current version of another dataset (published at the same time); identifiers are unique across zones, uspace_airspace and restrictions",
		}}}), nil
	case err != nil:
		var fe *core.FieldError
		if errors.As(err, &fe) {
			return p.refuse(ctx, ds, attempt, &ed269.Problems{List: []ed269.Problem{{Field: fe.Field, Reason: fe.Reason}}}), nil
		}
		return p.storeFailure(ctx, ds, err)
	}

	p.count(string(ds), CounterPublicationsAccepted)
	if p.OnPublished != nil {
		p.OnPublished()
	}
	attempt.Outcome, attempt.PublicationID = store.OutcomeAccepted, &res.PublicationID
	p.record(ctx, attempt)
	return gen.PutPublication201JSONResponse{
		Body:    resultOf(ds, res, received, len(acc.Rows), acc.Warnings),
		Headers: gen.PutPublication201ResponseHeaders{ETag: &res.ETag},
	}, nil
}

func preconditionFailed(ctx context.Context, got, etag string) problemResponse {
	fe := core.Fieldf("If-Match", "names %s; the current version is %s", quoteShort(got), etag)
	p := problemOf(ctx, http.StatusPreconditionFailed, SlugPreconditionFailed, "Precondition failed", fe.Error(), fe)
	p.headers = map[string]string{"ETag": etag}
	return p
}

// refuse records the refused attempt, counts it and answers 400 with
// every problem (at most MaxProblemErrors listed).
func (p *Publications) refuse(ctx context.Context, ds publication.Dataset, a store.Attempt, probs *ed269.Problems) problemResponse {
	p.count(string(ds), CounterPublicationsRefused)
	a.Outcome = store.OutcomeRefused
	a.Problems = make([]store.AttemptProblem, 0, len(probs.List))
	fields := make([]*core.FieldError, 0, len(probs.List))
	for _, pr := range probs.List {
		a.Problems = append(a.Problems, store.AttemptProblem{Field: pr.Field, Reason: pr.Reason})
		fields = append(fields, &core.FieldError{Field: pr.Field, Reason: pr.Reason})
	}
	extra := probs.Truncated
	if len(a.Problems) > MaxProblemErrors {
		extra += len(a.Problems) - MaxProblemErrors
		a.Problems = a.Problems[:MaxProblemErrors]
	}
	a.Truncated = extra
	p.record(ctx, a)
	detail := strconv.Itoa(len(a.Problems)+extra) + " problems; the publication is refused whole and nothing was stored"
	if extra > 0 {
		detail += " (" + strconv.Itoa(extra) + " not listed)"
	}
	resp := problemOf(ctx, http.StatusBadRequest, SlugPublicationRefused, "Publication refused", detail, fields...)
	if extra > 0 {
		t := true
		resp.problem.Truncated = &t
	}
	return resp
}

// record writes the attempt row; a failure is counted and logged, never
// turned into another answer (the publication's outcome stands).
func (p *Publications) record(ctx context.Context, a store.Attempt) {
	if _, err := p.Store.InsertAttempt(ctx, a); err != nil {
		p.count(string(a.Dataset), CounterAttemptRecordFailed)
		p.logger().LogAttrs(ctx, slog.LevelError, "publication attempt not recorded",
			slog.String("dataset", string(a.Dataset)), slog.String("client_id", a.PublisherClientID),
			slog.String("outcome", a.Outcome), slog.String("error", err.Error()))
	}
}

func rowIDs(rows []publication.FeatureRow) []string {
	out := make([]string, 0, len(rows))
	for i := range rows {
		out = append(out, rows[i].ID)
	}
	return out
}

// reservedProblems names every feature whose identifier another
// dataset's current version holds (D8), in feature order.
func reservedProblems(rows []publication.FeatureRow, reserved map[string]publication.Dataset) *ed269.Problems {
	if len(reserved) == 0 {
		return nil
	}
	var out ed269.Problems
	for i := range rows {
		other, ok := reserved[rows[i].ID]
		if !ok {
			continue
		}
		reason := strconv.Quote(rows[i].ID) + " is held by the current version of " + string(other) +
			"; identifiers are unique across zones, uspace_airspace and restrictions"
		if len(out.List) < MaxProblemErrors {
			out.List = append(out.List, ed269.Problem{Field: "features[" + strconv.Itoa(i) + "].properties.identifier", Reason: reason})
		} else {
			out.Truncated++
		}
	}
	return &out
}

func nonNilWarnings(w []dataset.Warning) []dataset.Warning {
	if w == nil {
		return []dataset.Warning{}
	}
	return w
}

func resultOf(ds publication.Dataset, res store.PublishResult, received time.Time, features int, warnings []dataset.Warning) gen.PublicationResult {
	added, addedMore := capIDs(res.Diff.Added)
	changed, changedMore := capIDs(res.Diff.Changed)
	removed, removedMore := capIDs(res.Diff.Removed)
	nAdded, nChanged, nRemoved := len(res.Diff.Added), len(res.Diff.Changed), len(res.Diff.Removed)
	ws := make([]gen.Warning, 0, len(warnings))
	for _, w := range warnings {
		ws = append(ws, gen.Warning{Field: w.Field, Reason: w.Reason})
	}
	out := gen.PublicationResult{
		Dataset: gen.PublicationResultDataset(ds), Version: res.Version, Etag: res.ETag,
		ReceivedAt: &received, FeatureCount: &features,
		AddedCount: &nAdded, ChangedCount: &nChanged, RemovedCount: &nRemoved,
		Added: &added, Changed: &changed, Removed: &removed, Warnings: &ws,
	}
	if addedMore+changedMore+removedMore > 0 {
		out.Truncated = &struct {
			Added   int `json:"added"`
			Changed int `json:"changed"`
			Removed int `json:"removed"`
		}{Added: addedMore, Changed: changedMore, Removed: removedMore}
	}
	return out
}

// capIDs is ids cut at MaxIDsPerList and the count left out.
func capIDs(ids []string) ([]string, int) {
	if len(ids) <= MaxIDsPerList {
		out := make([]string, len(ids))
		copy(out, ids)
		return out, 0
	}
	return append([]string{}, ids[:MaxIDsPerList]...), len(ids) - MaxIDsPerList
}

func quoteShort(s string) string {
	if len(s) > 80 {
		s = s[:80] + "..."
	}
	return strconv.Quote(s)
}

// --- GET /v1/publications/{dataset} -------------------------------------

func listLimit(limit *int) (int, *core.FieldError) {
	if limit == nil {
		return DefaultListLimit, nil
	}
	if *limit < 1 || *limit > MaxListLimit {
		return 0, core.Fieldf("limit", "must be 1 to %d", MaxListLimit)
	}
	return *limit, nil
}

func (p *Publications) list(ctx context.Context, req gen.ListPublicationsRequestObject) (gen.ListPublicationsResponseObject, error) {
	ds := publication.Dataset(req.Dataset)
	if !ds.Valid() {
		return notFoundDataset(ctx, string(req.Dataset)), nil
	}
	limit, fe := listLimit(req.Params.Limit)
	if fe == nil && req.Params.Before != nil && *req.Params.Before < 1 {
		fe = core.Fieldf("before", "must be at least 1")
	}
	if fe != nil {
		return problemOf(ctx, http.StatusBadRequest, SlugBadRequest, "Bad request", fe.Error(), fe), nil
	}
	var before int64
	if req.Params.Before != nil {
		before = *req.Params.Before
	}
	versions, err := p.Store.Versions(ctx, ds, before, limit)
	if err != nil {
		return p.storeFailure(ctx, ds, err)
	}
	out, err := versionList(ds, versions, limit)
	if err != nil {
		return nil, err
	}
	return gen.ListPublications200JSONResponse(out), nil
}

// versionList is the history body of versions (newest first, one page
// of at most limit): GET /v1/publications/{dataset} and (WP-4)
// GET /v1/{dataset}/versions answer the same.
func versionList(ds publication.Dataset, versions []store.Version, limit int) (gen.PublicationVersionList, error) {
	out := gen.PublicationVersionList{Dataset: string(ds), Versions: make([]gen.PublicationVersion, 0, len(versions))}
	for i := range versions {
		v := &versions[i]
		var ws []gen.Warning
		if len(v.Warnings) > 0 {
			if err := json.Unmarshal(v.Warnings, &ws); err != nil {
				return gen.PublicationVersionList{}, err
			}
		}
		if ws == nil {
			ws = []gen.Warning{}
		}
		out.Versions = append(out.Versions, gen.PublicationVersion{
			Dataset: string(v.Dataset), Version: v.Version, Etag: publication.ETag(v.Dataset, v.Version),
			Publisher: v.PublisherClientID, ReceivedAt: v.ReceivedAt.UTC(), FeatureCount: v.FeatureCount,
			Added: v.Added, Changed: v.Changed, Removed: v.Removed, SupersedesVersion: v.SupersedesVersion,
			Reason: gen.PublicationVersionReason(v.Reason), Warnings: ws, SignatureKid: v.SignatureKID,
			BodySha256: hex.EncodeToString(v.BodySHA256), Bytes: v.Bytes, ContentType: v.ContentType,
		})
	}
	if n := len(versions); n == limit && n > 0 && versions[n-1].Version > 1 {
		next := versions[n-1].Version
		out.NextBefore = &next
	}
	return out, nil
}

// --- GET /v1/publications/{dataset}/attempts ----------------------------

func (p *Publications) attempts(ctx context.Context, req gen.ListPublicationAttemptsRequestObject) (gen.ListPublicationAttemptsResponseObject, error) {
	ds := publication.Dataset(req.Dataset)
	if !ds.Valid() {
		return notFoundDataset(ctx, string(req.Dataset)), nil
	}
	caller := auth.CallerFrom(ctx)
	if caller == nil {
		return nil, errors.New("attempts handler reached without authentication")
	}
	limit, fe := listLimit(req.Params.Limit)
	if fe != nil {
		return problemOf(ctx, http.StatusBadRequest, SlugBadRequest, "Bad request", fe.Error(), fe), nil
	}
	var since time.Time
	if req.Params.Since != nil {
		since = *req.Params.Since
	}
	rows, err := p.Store.RefusedAttempts(ctx, ds, caller.ClientID, since, limit)
	if err != nil {
		return p.storeFailure(ctx, ds, err)
	}
	out := gen.PublicationAttemptList{Dataset: string(ds), Attempts: make([]gen.PublicationAttempt, 0, len(rows))}
	for i := range rows {
		a := &rows[i]
		probs := make([]gen.FieldProblem, 0, len(a.Problems))
		for _, pr := range a.Problems {
			probs = append(probs, gen.FieldProblem{Field: pr.Field, Reason: pr.Reason})
		}
		item := gen.PublicationAttempt{
			Id: a.ID, Dataset: string(a.Dataset), ReceivedAt: a.ReceivedAt.UTC(),
			Outcome: gen.PublicationAttemptOutcome(a.Outcome), PublicationId: a.PublicationID,
			Problems: probs, Bytes: a.Bytes,
		}
		if a.Truncated > 0 {
			t := a.Truncated
			item.Truncated = &t
		}
		if len(a.BodySHA256) > 0 {
			h := hex.EncodeToString(a.BodySHA256)
			item.BodySha256 = &h
		}
		out.Attempts = append(out.Attempts, item)
	}
	return gen.ListPublicationAttempts200JSONResponse(out), nil
}

// --- POST /v1/publishers/heartbeat --------------------------------------

func (p *Publications) heartbeat(ctx context.Context, req gen.PostPublisherHeartbeatRequestObject) (gen.PostPublisherHeartbeatResponseObject, error) {
	caller := auth.CallerFrom(ctx)
	if caller == nil {
		return nil, errors.New("heartbeat handler reached without authentication")
	}
	var kind string
	switch {
	case p.AuthorityClientID != "" && caller.ClientID == p.AuthorityClientID:
		kind = publisherKindAuthority
	case p.ANSPClientID != "" && caller.ClientID == p.ANSPClientID:
		kind = publisherKindANSP
	default:
		fe := core.Fieldf("sub", "this client is not a configured publisher")
		return problemOf(ctx, http.StatusForbidden, SlugNotAPublisher, "Not a publisher", fe.Error(), fe), nil
	}
	if req.Body == nil || req.Body.SentAt.IsZero() {
		fe := core.Fieldf("sent_at", "is required (RFC 3339)")
		return problemOf(ctx, http.StatusBadRequest, SlugBadRequest, "Bad request", fe.Error(), fe), nil
	}
	var refs []string
	if req.Body.ActiveRefs != nil {
		refs = *req.Body.ActiveRefs
		if refs == nil {
			refs = []string{}
		}
		if len(refs) > MaxActiveRefs {
			fe := core.Fieldf("active_refs", "has %d entries; at most %d", len(refs), MaxActiveRefs)
			return problemOf(ctx, http.StatusBadRequest, SlugBadRequest, "Bad request", fe.Error(), fe), nil
		}
	}
	if err := p.Store.RecordHeartbeat(ctx, store.Heartbeat{
		ClientID: caller.ClientID, Kind: kind, ReceivedAt: p.now(), SentAt: req.Body.SentAt, ActiveRefs: refs,
	}); err != nil {
		return p.storeFailure(ctx, "", err)
	}
	p.count("publishers", CounterHeartbeats)
	if kind == publisherKindANSP && refs != nil && p.OnANSPRefs != nil {
		p.OnANSPRefs(ctx, refs)
	}
	return gen.PostPublisherHeartbeat204Response{}, nil
}
