package httpapi

import (
	"bytes"
	"compress/gzip"
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed318"

	"github.com/rootxkit/uspace-cisp/internal/applicability"
	"github.com/rootxkit/uspace-cisp/internal/bus"
	"github.com/rootxkit/uspace-cisp/internal/httpapi/gen"
	"github.com/rootxkit/uspace-cisp/internal/obs"
	"github.com/rootxkit/uspace-cisp/internal/outline"
	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/store"
)

// Problem slugs of the reads (docs/WORKPACKAGES/WP-4.md).
const (
	SlugFilterNotApplicable = "filter_not_applicable"
	SlugFilterConflict      = "filter_conflict"
	SlugDeltaUnavailable    = "delta_unavailable"
	SlugCISStale            = "cis_stale"
	SlugIntegrity           = "integrity"
	SlugNoVersion           = "no_version"
	SlugReadsUnavailable    = "reads_unavailable"
)

// The headers of the reads (docs/PLAN.md section 6.3).
const (
	HeaderVersion       = "X-CIS-Version"
	HeaderSignature     = "X-CIS-Signature"
	HeaderFiltered      = "X-CIS-Filtered"
	HeaderStale         = "X-CIS-Stale"
	HeaderAgeS          = "X-CIS-Age-S"
	HeaderPublisherSig  = "X-Publisher-Signature"
	HeaderPublisherKID  = "X-Publisher-Kid"
	retryAfterStaleS    = "5"
	mediaGeoJSON        = "application/geo+json"
	mediaJSON           = "application/json"
	filterBBox          = "bbox"
	filterAt            = "at"
	filterAppliesAt     = "applies_at"
	filterSinceVersion  = "since_version"
	readsComponent      = "reads"
	defaultCacheControl = "public, max-age="
)

// Counters of the reads (component reads).
const (
	CounterApplicabilityUnknown = "applicability_unknown"
	CounterIntegrityFailed      = "integrity_failed"
	CounterStaleServed          = "stale_served"
	CounterStaleRefused         = "stale_refused"
	CounterSignatureEvicted     = "signature_cache_evicted"
	CounterStalePublisherServed = "stale_publisher_served"
	CounterOutlineFailed        = "outline_failed"
)

// MemberPublisherStaleSince is the top-level member of a restrictions
// body while the ANSP is stale (docs/PLAN.md section 15 Q3).
const MemberPublisherStaleSince = "cis_publisher_stale_since"

// Bounds of the reads (E-10).
const (
	// DefaultMaxDeltaVersions is how far back since_version reaches
	// before the answer is 410 delta_unavailable.
	DefaultMaxDeltaVersions = 1000
	// MaxChangesLimit caps GET /v1/changes.
	MaxChangesLimit = 500
	// DefaultChangesLimit is its page when limit is absent.
	DefaultChangesLimit = 100
	// DefaultSignatureCacheEntries bounds the per-version signatures of
	// GET /v1/{dataset}/versions/{v}.
	DefaultSignatureCacheEntries = 256
)

// ReadStore is what the reads need of the database (*store.Store; a
// fake in the unit tests).
type ReadStore interface {
	ReadCurrent(ctx context.Context, ds publication.Dataset, box *store.BBox) (store.CurrentRead, error)
	ReadDelta(ctx context.Context, ds publication.Dataset, from, maxBack int64) (store.DeltaRead, error)
	Publication(ctx context.Context, ds publication.Dataset, version int64) (store.StoredPublication, error)
	Versions(ctx context.Context, ds publication.Dataset, before int64, limit int) ([]store.Version, error)
	Changes(ctx context.Context, since int64, ds *publication.Dataset, limit int) ([]publication.Change, error)
	Publishers(ctx context.Context) ([]store.Publisher, error)
}

// SnapshotReader is the per-instance snapshot cache (*store.SnapshotCache).
type SnapshotReader interface {
	Current(ctx context.Context, ds publication.Dataset) (store.Snapshot, error)
	CurrentVersion(ctx context.Context, ds publication.Dataset) (int64, error)
	Stale() (since time.Time, ok bool)
	Refreshed() time.Time
	Versions() (map[publication.Dataset]int64, map[publication.Dataset]time.Time)
}

// Reads serves the datasets tag of api/openapi.yaml: GET and HEAD
// /v1/{dataset} and /public/v1/{dataset}, the versions and the change
// feed.
type Reads struct {
	Store ReadStore
	Cache SnapshotReader
	// Signer signs a stored version's bytes at serve time
	// (KeyRingSigner); nil answers GET /v1/{dataset}/versions/{v} 503.
	Signer store.Signer
	// MaxAge is CISP_READ_MAX_AGE_S, the Cache-Control max-age.
	MaxAge time.Duration
	// PublicBaseURL prefixes pull_url in the change feed.
	PublicBaseURL string
	// MaxDeltaVersions is how far back since_version reaches (0:
	// DefaultMaxDeltaVersions).
	MaxDeltaVersions int64
	// SignatureCacheEntries bounds the per-version signatures (0:
	// DefaultSignatureCacheEntries).
	SignatureCacheEntries int
	// Daylight resolves ED-318 daylight events (nil: NOAADaylight).
	Daylight ed318.Daylight
	// PublisherStale, when set, says whether the ANSP, the publisher of
	// the restrictions dataset, is stale and since when (nil: never
	// heard from) (WP-5). A stale ANSP's dataset bodies carry
	// cis_publisher_stale_since; nothing else about them changes.
	PublisherStale func(ctx context.Context) (bool, *time.Time, error)
	// Status receives the reads' counters; nil: a private one.
	Status *obs.Status
	Logger *slog.Logger
	// Now is the clock; nil is time.Now.
	Now func() time.Time

	statusOnce sync.Once
	sigsOnce   sync.Once
	sigs       *signatureCache
}

func (r *Reads) now() time.Time {
	if r.Now == nil {
		return time.Now().UTC()
	}
	return r.Now().UTC()
}

func (r *Reads) logger() *slog.Logger {
	if r.Logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return r.Logger
}

func (r *Reads) component() *obs.Component {
	r.statusOnce.Do(func() {
		if r.Status == nil {
			r.Status = obs.NewStatus("api", nil, time.Now())
		}
	})
	return r.Status.Component(readsComponent)
}

func (r *Reads) count(name string) {
	r.component().Counter(name, "Dataset reads ("+name+").").Inc()
}

func (r *Reads) daylight() ed318.Daylight {
	if r.Daylight == nil {
		return ed318.NOAADaylight{}
	}
	return r.Daylight
}

func (r *Reads) maxDelta() int64 {
	if r.MaxDeltaVersions <= 0 {
		return DefaultMaxDeltaVersions
	}
	return r.MaxDeltaVersions
}

func (r *Reads) cacheControl() string {
	return defaultCacheControl + strconv.FormatInt(int64(r.MaxAge/time.Second), 10)
}

// --- responses -----------------------------------------------------------

// readResponse is a read's answer: headers and a body held as bytes or
// as gzip bytes (inflated while written unless the client takes gzip).
type readResponse struct {
	status  int
	headers map[string]string
	body    []byte
	// gz is a gzip body; served as it is when encoded is set, inflated
	// otherwise.
	gz      []byte
	encoded bool
	// head drops the body (HEAD).
	head bool
}

func (rr readResponse) write(w http.ResponseWriter) error {
	for k, v := range rr.headers {
		w.Header().Set(k, v)
	}
	if rr.encoded {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", strconv.Itoa(len(rr.gz)))
	}
	w.WriteHeader(rr.status)
	if rr.head || rr.status == http.StatusNotModified {
		return nil
	}
	switch {
	case rr.encoded:
		_, err := w.Write(rr.gz)
		return err
	case rr.gz != nil:
		zr, err := gzip.NewReader(bytes.NewReader(rr.gz))
		if err != nil {
			return err
		}
		if _, err := io.Copy(w, zr); err != nil { //nolint:gosec // G110: our own snapshot, written by PublishTx, not untrusted input
			return err
		}
		return zr.Close()
	}
	_, err := w.Write(rr.body)
	return err
}

// VisitGetDatasetResponse implements gen.GetDatasetResponseObject.
func (rr readResponse) VisitGetDatasetResponse(w http.ResponseWriter) error { return rr.write(w) }

// VisitHeadDatasetResponse implements gen.HeadDatasetResponseObject.
func (rr readResponse) VisitHeadDatasetResponse(w http.ResponseWriter) error { return rr.write(w) }

// VisitGetPublicDatasetResponse implements gen.GetPublicDatasetResponseObject.
func (rr readResponse) VisitGetPublicDatasetResponse(w http.ResponseWriter) error {
	return rr.write(w)
}

// VisitHeadPublicDatasetResponse implements gen.HeadPublicDatasetResponseObject.
func (rr readResponse) VisitHeadPublicDatasetResponse(w http.ResponseWriter) error {
	return rr.write(w)
}

// VisitGetDatasetVersionResponse implements gen.GetDatasetVersionResponseObject.
func (rr readResponse) VisitGetDatasetVersionResponse(w http.ResponseWriter) error {
	return rr.write(w)
}

// VisitGetDatasetResponse implements gen.GetDatasetResponseObject.
func (p problemResponse) VisitGetDatasetResponse(w http.ResponseWriter) error { return p.write(w) }

// VisitHeadDatasetResponse implements gen.HeadDatasetResponseObject.
func (p problemResponse) VisitHeadDatasetResponse(w http.ResponseWriter) error { return p.write(w) }

// VisitGetPublicDatasetResponse implements gen.GetPublicDatasetResponseObject.
func (p problemResponse) VisitGetPublicDatasetResponse(w http.ResponseWriter) error {
	return p.write(w)
}

// VisitHeadPublicDatasetResponse implements gen.HeadPublicDatasetResponseObject.
func (p problemResponse) VisitHeadPublicDatasetResponse(w http.ResponseWriter) error {
	return p.write(w)
}

// VisitListDatasetVersionsResponse implements gen.ListDatasetVersionsResponseObject.
func (p problemResponse) VisitListDatasetVersionsResponse(w http.ResponseWriter) error {
	return p.write(w)
}

// VisitGetDatasetVersionResponse implements gen.GetDatasetVersionResponseObject.
func (p problemResponse) VisitGetDatasetVersionResponse(w http.ResponseWriter) error {
	return p.write(w)
}

// VisitListChangesResponse implements gen.ListChangesResponseObject.
func (p problemResponse) VisitListChangesResponse(w http.ResponseWriter) error { return p.write(w) }

// VisitGetStatusResponse implements gen.GetStatusResponseObject.
func (p problemResponse) VisitGetStatusResponse(w http.ResponseWriter) error { return p.write(w) }

// readsUnavailable answers a read when the api runs without a database.
func readsUnavailable(ctx context.Context) problemResponse {
	return problemOf(ctx, http.StatusServiceUnavailable, SlugReadsUnavailable, "Reads unavailable",
		"the api runs without a database (CISP_DATABASE_URL); nothing can be read")
}

func badRequest(ctx context.Context, fe *core.FieldError) problemResponse {
	return problemOf(ctx, http.StatusBadRequest, SlugBadRequest, "Bad request", fe.Error(), fe)
}

func retryAfter(p problemResponse, secs string) problemResponse {
	if p.headers == nil {
		p.headers = map[string]string{}
	}
	p.headers["Retry-After"] = secs
	return p
}

// failure is the answer to a store or cache error on a read: the
// deadline as it is (503 timeout), 503 database_unavailable with
// Retry-After for a database that cannot be reached, and 500 otherwise,
// logged with the dataset.
func (r *Reads) failure(ctx context.Context, ds publication.Dataset, err error) (problemResponse, error) {
	if errors.Is(err, context.DeadlineExceeded) {
		return problemResponse{}, err
	}
	if store.Unavailable(err) {
		return retryAfter(problemOf(ctx, http.StatusServiceUnavailable, SlugDatabaseUnavailable, "Database unavailable",
			"the database could not be reached; nothing was read; retry later"), retryAfterDatabaseDownS), nil
	}
	r.logger().LogAttrs(ctx, slog.LevelError, "read failed",
		slog.String("dataset", string(ds)), slog.String("error", err.Error()))
	return problemOf(ctx, http.StatusInternalServerError, SlugInternal, "Internal error",
		"the read failed; the failure is logged with this request id"), nil
}

// stale is the 503 of a read that cannot be answered from the cache.
func (r *Reads) stale(ctx context.Context, since time.Time, what string) problemResponse {
	r.count(CounterStaleRefused)
	detail := "the database is unreachable"
	if !since.IsZero() {
		detail += " since " + since.UTC().Format(time.RFC3339)
	}
	detail += "; " + what + "; retry later"
	return retryAfter(problemOf(ctx, http.StatusServiceUnavailable, SlugCISStale, "Dataset stale", detail), retryAfterStaleS)
}

// --- GET and HEAD /v1/{dataset} ----------------------------------------

// readQuery is one read of a dataset.
type readQuery struct {
	bbox, at, appliesAt, ifNoneMatch, acceptEncoding *string
	sinceVersion                                     *int64
	head, public                                     bool
}

// filter is a parsed readQuery.
type filter struct {
	box       *store.BBox
	at        *time.Time
	appliesAt *time.Time
	since     *int64
}

func (f filter) any() bool {
	return f.box != nil || f.at != nil || f.appliesAt != nil || f.since != nil
}

// names lists the filters applied, for X-CIS-Filtered.
func (f filter) names() string {
	var out []string
	if f.box != nil {
		out = append(out, filterBBox)
	}
	if f.at != nil {
		out = append(out, filterAt)
	}
	if f.appliesAt != nil {
		out = append(out, filterAppliesAt)
	}
	if f.since != nil {
		out = append(out, filterSinceVersion)
	}
	return strings.Join(out, ", ")
}

// parseFilter validates the query of a read of ds.
func parseFilter(ds publication.Dataset, q readQuery) (filter, *core.FieldError, string) {
	var f filter
	if q.at != nil && q.appliesAt != nil {
		return f, core.Fieldf("applies_at", "is given with at: at filters, applies_at annotates; give one"), SlugFilterConflict
	}
	if ds.Kind() == publication.KindUsspList {
		for name, v := range map[string]*string{filterBBox: q.bbox, filterAt: q.at, filterAppliesAt: q.appliesAt} {
			if v != nil {
				return f, core.Fieldf(name, "ussp_list is not ED-318 and has no zones to filter"), SlugFilterNotApplicable
			}
		}
	}
	if q.sinceVersion != nil {
		if *q.sinceVersion < 0 {
			return f, core.Fieldf(filterSinceVersion, "must be 0 or more"), SlugBadRequest
		}
		if q.bbox != nil || q.at != nil || q.appliesAt != nil {
			return f, core.Fieldf(filterSinceVersion, "is a delta of the whole dataset; it is not combined with bbox, at or applies_at"), SlugFilterConflict
		}
		v := *q.sinceVersion
		f.since = &v
	}
	if q.bbox != nil {
		box, fe := parseBBox(*q.bbox)
		if fe != nil {
			return f, fe, SlugBadRequest
		}
		f.box = &box
	}
	for _, p := range []struct {
		name string
		raw  *string
		dst  **time.Time
	}{{filterAt, q.at, &f.at}, {filterAppliesAt, q.appliesAt, &f.appliesAt}} {
		if p.raw == nil {
			continue
		}
		t, fe := parseInstant(p.name, *p.raw)
		if fe != nil {
			return f, fe, SlugBadRequest
		}
		*p.dst = &t
	}
	return f, nil, ""
}

// parseBBox reads minlng,minlat,maxlng,maxlat.
func parseBBox(raw string) (store.BBox, *core.FieldError) {
	parts := strings.Split(raw, ",")
	if len(parts) != 4 {
		return store.BBox{}, core.Fieldf(filterBBox, "must be minlng,minlat,maxlng,maxlat (4 numbers), got %d values", len(parts))
	}
	var v [4]float64
	for i, p := range parts {
		x, err := strconv.ParseFloat(strings.TrimSpace(p), 64)
		if err != nil || math.IsNaN(x) || math.IsInf(x, 0) {
			return store.BBox{}, core.Fieldf(filterBBox, "value %d (%q) is not a finite number", i+1, quoteShort(p))
		}
		v[i] = x
	}
	b := store.BBox{MinLon: v[0], MinLat: v[1], MaxLon: v[2], MaxLat: v[3]}
	switch {
	case b.MinLon < -180 || b.MinLon > 180 || b.MaxLon < -180 || b.MaxLon > 180:
		return b, core.Fieldf(filterBBox, "longitudes must be within -180..180")
	case b.MinLat < -90 || b.MinLat > 90 || b.MaxLat < -90 || b.MaxLat > 90:
		return b, core.Fieldf(filterBBox, "latitudes must be within -90..90")
	case b.MinLat > b.MaxLat:
		return b, core.Fieldf(filterBBox, "minlat %v is above maxlat %v", b.MinLat, b.MaxLat)
	case b.MinLon > b.MaxLon:
		return b, core.Fieldf(filterBBox, "minlng %v is above maxlng %v: a box across the antimeridian is not served yet; ask for its two halves", b.MinLon, b.MaxLon)
	}
	return b, nil
}

// parseInstant reads an RFC 3339 instant with an offset (T-09: a naive
// time is refused, never read as UTC).
func parseInstant(name, raw string) (time.Time, *core.FieldError) {
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err == nil {
		return t.UTC(), nil
	}
	reason := "%s is not an RFC 3339 time with an offset (2026-10-02T12:00:00Z or 2026-10-02T16:00:00+04:00)"
	if strings.Contains(raw, " ") {
		reason += "; a + in a query string reads as a space: encode it as %%2B"
	}
	return time.Time{}, core.Fieldf(name, reason, quoteShort(raw))
}

// acceptsGzip reports whether an Accept-Encoding value takes gzip (RFC
// 9110 section 12.5.3): gzip or * listed without q=0.
func acceptsGzip(header *string) bool {
	if header == nil {
		return false
	}
	for _, part := range strings.Split(*header, ",") {
		coding, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		coding = strings.ToLower(strings.TrimSpace(coding))
		if coding != "gzip" && coding != "*" {
			continue
		}
		q := 1.0
		for _, p := range strings.Split(params, ";") {
			k, v, ok := strings.Cut(strings.TrimSpace(p), "=")
			if ok && strings.EqualFold(strings.TrimSpace(k), "q") {
				if x, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
					q = x
				}
			}
		}
		if q > 0 {
			return true
		}
	}
	return false
}

// headers are the version headers of every read answer.
func (r *Reads) headers(ds publication.Dataset, version int64, modified time.Time, staleSince *time.Time) map[string]string {
	h := map[string]string{
		"ETag":        publication.ETag(ds, version),
		HeaderVersion: strconv.FormatInt(version, 10),
		"Vary":        "Accept-Encoding",
	}
	if !modified.IsZero() {
		h["Last-Modified"] = modified.UTC().Format(http.TimeFormat)
	}
	if staleSince == nil {
		h["Cache-Control"] = r.cacheControl()
		return h
	}
	// Never cached anywhere: a stale answer must not outlive the outage.
	h["Cache-Control"] = "no-store"
	h[HeaderStale] = "true"
	age := int64(0)
	if refreshed := r.Cache.Refreshed(); !refreshed.IsZero() {
		age = max(0, int64(r.now().Sub(refreshed)/time.Second))
	}
	h[HeaderAgeS] = strconv.FormatInt(age, 10)
	return h
}

func notModified(h map[string]string, head bool) readResponse {
	keep := map[string]string{}
	for _, k := range []string{"ETag", HeaderVersion, "Cache-Control", "Vary", HeaderStale, HeaderAgeS, "Last-Modified"} {
		if v, ok := h[k]; ok {
			keep[k] = v
		}
	}
	return readResponse{status: http.StatusNotModified, headers: keep, head: head}
}

// readObject is any read answer.
type readObject interface {
	gen.GetDatasetResponseObject
	gen.HeadDatasetResponseObject
	gen.GetPublicDatasetResponseObject
	gen.HeadPublicDatasetResponseObject
}

// read answers GET and HEAD on /v1/{dataset} and /public/v1/{dataset}.
func (r *Reads) read(ctx context.Context, ds publication.Dataset, q readQuery) (readObject, error) {
	if !ds.Valid() {
		return notFoundDataset(ctx, string(ds)), nil
	}
	f, fe, slug := parseFilter(ds, q)
	if fe != nil {
		return problemOf(ctx, http.StatusBadRequest, slug, "Bad request", fe.Error(), fe), nil
	}
	staleSince, stale := r.Cache.Stale()
	var since *time.Time
	if stale {
		since = &staleSince
	}
	// The USSP list has no features: since_version answers the whole
	// list, after the same check against the current version.
	if ds.Kind() == publication.KindUsspList && f.since != nil {
		cur, err := r.Cache.CurrentVersion(ctx, ds)
		if err != nil {
			return r.cacheFailure(ctx, ds, err, since)
		}
		if *f.since > cur {
			return badRequest(ctx, core.Fieldf(filterSinceVersion, "%d is above the current version %d", *f.since, cur)), nil
		}
		f.since = nil
	}
	if f.any() {
		if stale {
			// Never answer a filter from a stale cache: the rows may be
			// newer than the snapshot, and the answer could not carry one
			// version honestly.
			return r.stale(ctx, staleSince, "a filtered read is built from the current features and is not served from the cache"), nil
		}
		if f.since != nil {
			return r.delta(ctx, ds, *f.since, q)
		}
		return r.filtered(ctx, ds, f, q)
	}
	return r.unfiltered(ctx, ds, q, since)
}

// cacheFailure answers a read the cache could not serve.
func (r *Reads) cacheFailure(ctx context.Context, ds publication.Dataset, err error, since *time.Time) (readObject, error) {
	if errors.Is(err, store.ErrNoVersion) {
		return noVersion(ctx, ds), nil
	}
	if since != nil || store.Unavailable(err) {
		var at time.Time
		if since != nil {
			at = *since
		}
		return r.stale(ctx, at, "this instance holds no snapshot of "+string(ds)+" to serve"), nil
	}
	return r.failure(ctx, ds, err)
}

func noVersion(ctx context.Context, ds publication.Dataset) problemResponse {
	fe := core.Fieldf("dataset", "%s has no version yet; its ETag is %s", ds, publication.ETag(ds, 0))
	p := problemOf(ctx, http.StatusNotFound, SlugNoVersion, "No version yet", fe.Error(), fe)
	p.headers = map[string]string{"ETag": publication.ETag(ds, 0), HeaderVersion: "0"}
	return p
}

// unfiltered serves the cache's snapshot of the current version.
func (r *Reads) unfiltered(ctx context.Context, ds publication.Dataset, q readQuery, since *time.Time) (readObject, error) {
	snap, err := r.Cache.Current(ctx, ds)
	if err != nil {
		return r.cacheFailure(ctx, ds, err, since)
	}
	if since != nil {
		r.count(CounterStaleServed)
	}
	h := r.headers(ds, snap.Version, snap.ReceivedAt, since)
	if q.ifNoneMatch != nil && etagMatches(*q.ifNoneMatch, h["ETag"]) {
		return notModified(h, q.head), nil
	}
	if ds.Kind() == publication.KindUsspList {
		h["Content-Type"] = mediaJSON
		if q.public {
			body, err := projectUsspList(snap.BodyGz)
			if err != nil {
				return r.failure(ctx, ds, err)
			}
			return readResponse{status: http.StatusOK, headers: h, body: body, head: q.head}, nil
		}
	} else {
		h["Content-Type"] = mediaGeoJSON
	}
	if member, stale := r.stalePublisher(ctx, ds, q.head); stale {
		return r.withStalePublisher(ctx, ds, h, snap.BodyGz, member)
	}
	// Only a test store holds an unsigned snapshot (NoopSigner); an empty
	// header would read as a signature that does not verify.
	if snap.CISPSignature != "" {
		h[HeaderSignature] = snap.CISPSignature
	}
	return readResponse{status: http.StatusOK, headers: h, gz: snap.BodyGz, encoded: acceptsGzip(q.acceptEncoding) && !q.head, head: q.head}, nil
}

// stalePublisher is the cis_publisher_stale_since value of a
// restrictions body while the ANSP is stale (a time, or null when never
// heard from). A staleness that cannot be read is logged and leaves the
// body as stored: the member says the ANSP is stale, never that it is not.
func (r *Reads) stalePublisher(ctx context.Context, ds publication.Dataset, head bool) (json.RawMessage, bool) {
	if ds != publication.DatasetRestrictions || r.PublisherStale == nil || head {
		return nil, false
	}
	stale, since, err := r.PublisherStale(ctx)
	if err != nil {
		r.logger().LogAttrs(ctx, slog.LevelWarn, "ansp staleness not read for the restrictions read", slog.String("error", err.Error()))
		return nil, false
	}
	if !stale {
		return nil, false
	}
	if since == nil {
		return json.RawMessage("null"), true
	}
	raw, err := json.Marshal(since.UTC())
	if err != nil {
		return nil, false
	}
	return raw, true
}

// withStalePublisher serves the snapshot with cis_publisher_stale_since
// added at the top level, signed at serve time over the bytes served and
// never cached (the member must not outlive the silence).
func (r *Reads) withStalePublisher(ctx context.Context, ds publication.Dataset, h map[string]string, gz []byte, member json.RawMessage) (readObject, error) {
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return r.failure(ctx, ds, err)
	}
	body, err := io.ReadAll(zr)
	if err != nil {
		return r.failure(ctx, ds, err)
	}
	body = withTopMember(body, member)
	if r.Signer != nil {
		sig, err := r.Signer.Sign(ctx, body)
		if err != nil {
			return r.failure(ctx, ds, err)
		}
		h[HeaderSignature] = sig
	}
	h["Cache-Control"] = "no-store"
	r.count(CounterStalePublisherServed)
	return readResponse{status: http.StatusOK, headers: h, body: body}, nil
}

// jsonSpace is the JSON whitespace (RFC 8259 section 2).
const jsonSpace = " \t\r\n"

// withTopMember is the JSON object body with cis_publisher_stale_since
// first; the rest of the bytes are as they were.
func withTopMember(body []byte, value json.RawMessage) []byte {
	i := bytes.IndexByte(body, '{')
	if i < 0 {
		return body
	}
	out := make([]byte, 0, len(body)+len(value)+32)
	out = append(out, body[:i+1]...)
	out = append(out, '"')
	out = append(out, MemberPublisherStaleSince...)
	out = append(out, '"', ':')
	out = append(out, value...)
	if rest := bytes.TrimLeft(body[i+1:], jsonSpace); len(rest) > 0 && rest[0] != '}' {
		out = append(out, ',')
	}
	return append(out, body[i+1:]...)
}

// filtered builds the collection of the current features in the box,
// filtered or annotated at an instant.
func (r *Reads) filtered(ctx context.Context, ds publication.Dataset, f filter, q readQuery) (readObject, error) {
	cur, err := r.Store.ReadCurrent(ctx, ds, f.box)
	if err != nil {
		return r.failure(ctx, ds, err)
	}
	if cur.Version == 0 {
		return noVersion(ctx, ds), nil
	}
	h := r.headers(ds, cur.Version, cur.ReceivedAt, nil)
	h[HeaderFiltered] = f.names()
	if q.ifNoneMatch != nil && etagMatches(*q.ifNoneMatch, h["ETag"]) {
		return notModified(h, q.head), nil
	}
	fc, err := collectionOf(cur.Features)
	if err != nil {
		return r.failure(ctx, ds, err)
	}
	switch {
	case f.at != nil:
		kept := fc.Features[:0]
		for i := range fc.Features {
			v := r.judge(&fc.Features[i], *f.at)
			switch v {
			case applicability.DoesNotApply:
				continue
			case applicability.Unknown:
				annotate(&fc.Features[i], v)
			case applicability.Applies:
			}
			kept = append(kept, fc.Features[i])
		}
		fc.Features = kept
	case f.appliesAt != nil:
		for i := range fc.Features {
			annotate(&fc.Features[i], r.judge(&fc.Features[i], *f.appliesAt))
		}
	}
	for i := range fc.Features {
		r.drawCircles(ctx, &fc.Features[i])
	}
	body, err := publication.Snapshot(ds, cur.Version, cur.ReceivedAt, cur.Publisher, fc)
	if err != nil {
		return r.failure(ctx, ds, err)
	}
	h["Content-Type"] = mediaGeoJSON
	if member, stale := r.stalePublisher(ctx, ds, q.head); stale {
		body = withTopMember(body, member)
		h["Cache-Control"] = "no-store"
		r.count(CounterStalePublisherServed)
	}
	return readResponse{status: http.StatusOK, headers: h, body: body, head: q.head}, nil
}

// judge is the feature's verdict at an instant; Unknown is counted.
func (r *Reads) judge(f *ed318.Feature, at time.Time) applicability.Verdict {
	v, err := applicability.At(f, at, r.daylight())
	if err != nil {
		r.count(CounterApplicabilityUnknown)
	}
	return v
}

// drawCircles writes extendedProperties.cis_display_geometry into the
// copy of a feature that holds a circle: its drawable outline (section 15
// Q43). A drawing, never a judgement. A circle that cannot be drawn is
// served without the member and counted; the feature itself is never
// dropped.
func (r *Reads) drawCircles(ctx context.Context, f *ed318.Feature) {
	raw, ok, err := outline.Display(f.Geometry)
	if err != nil {
		r.count(CounterOutlineFailed)
		r.logger().LogAttrs(ctx, slog.LevelWarn, "circle outline not drawn",
			slog.String("identifier", f.Properties.Identifier), slog.String("error", err.Error()))
		return
	}
	if ok {
		setExtended(f, outline.Member, raw)
	}
}

// setExtended writes one member into the feature's copy of
// extendedProperties (the stored row is never touched).
func setExtended(f *ed318.Feature, member string, value json.RawMessage) {
	ext := make(map[string]json.RawMessage, len(f.Properties.ExtendedProperties)+1)
	for k, x := range f.Properties.ExtendedProperties {
		ext[k] = x
	}
	ext[member] = value
	f.Properties.ExtendedProperties = ext
}

// annotate writes the verdict into the feature's copy (the stored row is
// never touched).
func annotate(f *ed318.Feature, v applicability.Verdict) {
	setExtended(f, applicability.Member, json.RawMessage(strconv.Quote(v.Annotation())))
}

// collectionOf parses stored features back into one collection, through
// ed318.Parse: the same code as a publication.
func collectionOf(features []store.StoredFeature) (*ed318.FeatureCollection, error) {
	var b bytes.Buffer
	b.WriteString(`{"type":"FeatureCollection","features":[`)
	for i := range features {
		if i > 0 {
			b.WriteByte(',')
		}
		b.Write(features[i].Feature)
	}
	b.WriteString(`]}`)
	fc, probs := ed318.Parse(b.Bytes(), ed318.Limits{})
	if probs != nil {
		return nil, errors.New("stored features do not parse: " + probs.Error())
	}
	return fc, nil
}

// deltaBody is the DatasetDelta schema.
type deltaBody struct {
	Dataset     string      `json:"dataset"`
	FromVersion int64       `json:"from_version"`
	ToVersion   int64       `json:"to_version"`
	Added       featureList `json:"added"`
	Changed     featureList `json:"changed"`
	Removed     []string    `json:"removed"`
}

type featureList struct {
	Type     string            `json:"type"`
	Features []json.RawMessage `json:"features"`
}

// delta answers since_version from the features of both versions.
func (r *Reads) delta(ctx context.Context, ds publication.Dataset, from int64, q readQuery) (readObject, error) {
	d, err := r.Store.ReadDelta(ctx, ds, from, r.maxDelta())
	var unavailable *store.DeltaUnavailableError
	switch {
	case errors.Is(err, store.ErrVersionAhead):
		return badRequest(ctx, core.Fieldf(filterSinceVersion, "%d is above the current version", from)), nil
	case errors.As(err, &unavailable):
		fe := core.Fieldf(filterSinceVersion, "%d is more than %d versions behind the current version %d; pull the dataset whole (no since_version)",
			from, unavailable.Max, unavailable.Current)
		p := problemOf(ctx, http.StatusGone, SlugDeltaUnavailable, "Delta unavailable", fe.Error(), fe)
		p.headers = map[string]string{"ETag": publication.ETag(ds, unavailable.Current)}
		return p, nil
	case err != nil:
		return r.failure(ctx, ds, err)
	}
	h := r.headers(ds, d.To, time.Time{}, nil)
	h[HeaderFiltered] = filterSinceVersion
	if q.ifNoneMatch != nil && etagMatches(*q.ifNoneMatch, h["ETag"]) {
		return notModified(h, q.head), nil
	}
	fromRows, err := rowsOf(d.FromFeatures)
	if err != nil {
		return r.failure(ctx, ds, err)
	}
	toRows, err := rowsOf(d.ToFeatures)
	if err != nil {
		return r.failure(ctx, ds, err)
	}
	delta := publication.Delta(fromRows, toRows, d.From, d.To)
	body, err := json.Marshal(deltaBody{
		Dataset: string(ds), FromVersion: delta.FromVersion, ToVersion: delta.ToVersion,
		Added:   featureList{Type: "FeatureCollection", Features: delta.Added},
		Changed: featureList{Type: "FeatureCollection", Features: delta.Changed},
		Removed: delta.Removed,
	})
	if err != nil {
		return nil, err
	}
	h["Content-Type"] = mediaJSON
	return readResponse{status: http.StatusOK, headers: h, body: body, head: q.head}, nil
}

func rowsOf(features []store.StoredFeature) ([]publication.FeatureRow, error) {
	out := make([]publication.FeatureRow, 0, len(features))
	for _, f := range features {
		row, err := f.Row()
		if err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, nil
}

// --- the operations ------------------------------------------------------

// GetDataset reads a dataset (WP-4).
func (s *Server) GetDataset(ctx context.Context, req gen.GetDatasetRequestObject) (gen.GetDatasetResponseObject, error) {
	if s.Reads == nil {
		return readsUnavailable(ctx), nil
	}
	p := req.Params
	return s.Reads.read(ctx, publication.Dataset(req.Dataset), readQuery{
		bbox: p.Bbox, at: p.At, appliesAt: p.AppliesAt, sinceVersion: p.SinceVersion,
		ifNoneMatch: p.IfNoneMatch, acceptEncoding: p.AcceptEncoding,
	})
}

// HeadDataset is the headers of the unfiltered read (WP-4).
func (s *Server) HeadDataset(ctx context.Context, req gen.HeadDatasetRequestObject) (gen.HeadDatasetResponseObject, error) {
	if s.Reads == nil {
		return readsUnavailable(ctx), nil
	}
	return s.Reads.read(ctx, publication.Dataset(req.Dataset), readQuery{ifNoneMatch: req.Params.IfNoneMatch, head: true})
}

// ListDatasetVersions is the version history of a dataset (WP-4).
func (s *Server) ListDatasetVersions(ctx context.Context, req gen.ListDatasetVersionsRequestObject) (gen.ListDatasetVersionsResponseObject, error) {
	if s.Reads == nil {
		return readsUnavailable(ctx), nil
	}
	return s.Reads.versions(ctx, req)
}

// GetDatasetVersion is one version as published (WP-4).
func (s *Server) GetDatasetVersion(ctx context.Context, req gen.GetDatasetVersionRequestObject) (gen.GetDatasetVersionResponseObject, error) {
	if s.Reads == nil {
		return readsUnavailable(ctx), nil
	}
	return s.Reads.version(ctx, req)
}

// ListChanges is the change feed (WP-4).
func (s *Server) ListChanges(ctx context.Context, req gen.ListChangesRequestObject) (gen.ListChangesResponseObject, error) {
	if s.Reads == nil {
		return readsUnavailable(ctx), nil
	}
	return s.Reads.changes(ctx, req)
}

// --- GET /v1/{dataset}/versions -----------------------------------------

func (r *Reads) versions(ctx context.Context, req gen.ListDatasetVersionsRequestObject) (gen.ListDatasetVersionsResponseObject, error) {
	ds := publication.Dataset(req.Dataset)
	if !ds.Valid() {
		return notFoundDataset(ctx, string(req.Dataset)), nil
	}
	limit, fe := listLimit(req.Params.Limit)
	if fe == nil && req.Params.Before != nil && *req.Params.Before < 1 {
		fe = core.Fieldf("before", "must be at least 1")
	}
	if fe != nil {
		return badRequest(ctx, fe), nil
	}
	var before int64
	if req.Params.Before != nil {
		before = *req.Params.Before
	}
	versions, err := r.Store.Versions(ctx, ds, before, limit)
	if err != nil {
		return r.failure(ctx, ds, err)
	}
	out, err := versionList(ds, versions, limit)
	if err != nil {
		return nil, err
	}
	return gen.ListDatasetVersions200JSONResponse(out), nil
}

// --- GET /v1/{dataset}/versions/{version} -------------------------------

func (r *Reads) version(ctx context.Context, req gen.GetDatasetVersionRequestObject) (gen.GetDatasetVersionResponseObject, error) {
	ds := publication.Dataset(req.Dataset)
	if !ds.Valid() {
		return notFoundDataset(ctx, string(req.Dataset)), nil
	}
	if req.Version < 1 {
		return badRequest(ctx, core.Fieldf("version", "must be at least 1")), nil
	}
	p, err := r.Store.Publication(ctx, ds, req.Version)
	if errors.Is(err, store.ErrNotFound) {
		fe := core.Fieldf("version", "%s has no version %d", ds, req.Version)
		return problemOf(ctx, http.StatusNotFound, SlugNotFound, "Not found", fe.Error(), fe), nil
	}
	if err != nil {
		return r.failure(ctx, ds, err)
	}
	// T7: the bytes served are the bytes the publisher signed, or nothing.
	if sum := sha256Sum(p.Body); !bytes.Equal(sum, p.BodySHA256) {
		r.count(CounterIntegrityFailed)
		r.logger().LogAttrs(ctx, slog.LevelError, "publication body integrity check failed; the version is not served",
			slog.String("dataset", string(ds)), slog.Int64("version", req.Version),
			slog.String("stored_sha256", hexOf(p.BodySHA256)), slog.String("body_sha256", hexOf(sum)))
		return problemOf(ctx, http.StatusInternalServerError, SlugIntegrity, "Integrity check failed",
			"the stored body of this version does not match its recorded hash; it is not served and the failure is logged"), nil
	}
	if r.Signer == nil {
		return problemOf(ctx, http.StatusServiceUnavailable, SlugSigningUnavailable, "Signing unavailable",
			"no CISP signing key is configured (CISP_SIGNING_KEY_FILE); a version is never served unsigned"), nil
	}
	sig, err := r.signature(ctx, ds, p)
	if err != nil {
		return nil, err
	}
	h := r.headers(ds, p.Version, p.ReceivedAt, nil)
	delete(h, "Vary")
	if req.Params.IfNoneMatch != nil && etagMatches(*req.Params.IfNoneMatch, h["ETag"]) {
		return notModified(h, false), nil
	}
	h["Content-Type"] = p.ContentType
	h[HeaderSignature] = sig
	if p.PublisherSignature != nil {
		h[HeaderPublisherSig] = *p.PublisherSignature
	}
	if p.SignatureKID != nil {
		h[HeaderPublisherKID] = *p.SignatureKID
	}
	return readResponse{status: http.StatusOK, headers: h, body: p.Body}, nil
}

// signature is the CISP's signature over a version's bytes, made once
// per version and kept in a bounded cache.
func (r *Reads) signature(ctx context.Context, ds publication.Dataset, p store.StoredPublication) (string, error) {
	r.sigsOnce.Do(func() {
		n := r.SignatureCacheEntries
		if n <= 0 {
			n = DefaultSignatureCacheEntries
		}
		r.sigs = newSignatureCache(n, r.component().Counter(CounterSignatureEvicted, "Version signatures evicted from the bounded cache."))
	})
	key := publication.ETag(ds, p.Version)
	if sig, ok := r.sigs.get(key); ok {
		return sig, nil
	}
	sig, err := r.Signer.Sign(ctx, p.Body)
	if err != nil {
		return "", err
	}
	r.sigs.put(key, sig)
	return sig, nil
}

// --- GET /v1/changes -----------------------------------------------------

func (r *Reads) changes(ctx context.Context, req gen.ListChangesRequestObject) (gen.ListChangesResponseObject, error) {
	var since int64
	if req.Params.Since != nil {
		since = *req.Params.Since
	}
	if since < 0 {
		return badRequest(ctx, core.Fieldf("since", "must be 0 or more")), nil
	}
	limit := DefaultChangesLimit
	if req.Params.Limit != nil {
		limit = *req.Params.Limit
	}
	if limit < 1 || limit > MaxChangesLimit {
		return badRequest(ctx, core.Fieldf("limit", "must be 1 to %d", MaxChangesLimit)), nil
	}
	var ds *publication.Dataset
	if req.Params.Dataset != nil {
		d := publication.Dataset(*req.Params.Dataset)
		if !d.Valid() {
			return badRequest(ctx, core.Fieldf("dataset", "%q is not a dataset", quoteShort(string(d)))), nil
		}
		ds = &d
	}
	rows, err := r.Store.Changes(ctx, since, ds, limit)
	if err != nil {
		return r.failure(ctx, "", err)
	}
	out := gen.ListChanges200JSONResponse{Changes: make([]gen.Change, 0, len(rows)), Next: since}
	for i := range rows {
		c := &rows[i]
		m := bus.MessageOf(*c, r.PublicBaseURL)
		item := gen.Change{
			Schema: gen.ChangeSchema(m.Schema), MsgId: m.MsgID, Producer: m.Producer, Dataset: gen.ChangeDataset(m.Dataset),
			Version: m.Version, Etag: m.ETag, FeatureIds: m.FeatureIDs, RemovedIds: m.RemovedIDs,
			Reason: gen.ChangeReason(m.Reason), At: m.At, PullUrl: m.PullURL,
		}
		if m.BBox != nil {
			b := append([]float64{}, m.BBox...)
			item.Bbox = &b
		}
		out.Changes = append(out.Changes, item)
		out.Next = c.ID
	}
	return out, nil
}

func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

func hexOf(b []byte) string { return hex.EncodeToString(b) }

// signatureCache is a bounded LRU of version signatures (E-10).
type signatureCache struct {
	max     int
	evicted *obs.Counter

	mu    sync.Mutex
	order *list.List // front: most recent; values are keys
	items map[string]*list.Element
	sigs  map[string]string
}

func newSignatureCache(maxEntries int, evicted *obs.Counter) *signatureCache {
	return &signatureCache{max: maxEntries, evicted: evicted, order: list.New(), items: map[string]*list.Element{}, sigs: map[string]string{}}
}

func (c *signatureCache) get(key string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.items[key]
	if !ok {
		return "", false
	}
	c.order.MoveToFront(e)
	return c.sigs[key], true
}

func (c *signatureCache) put(key, sig string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.items[key]; ok {
		c.order.MoveToFront(e)
		c.sigs[key] = sig
		return
	}
	c.items[key] = c.order.PushFront(key)
	c.sigs[key] = sig
	for c.order.Len() > c.max {
		last := c.order.Back()
		k, _ := last.Value.(string)
		c.order.Remove(last)
		delete(c.items, k)
		delete(c.sigs, k)
		c.evicted.Inc()
	}
}

func (c *signatureCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}
