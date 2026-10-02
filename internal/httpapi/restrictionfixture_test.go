package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"testing"
	"time"

	coreauth "github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-cisp/internal/auth"
	"github.com/rootxkit/uspace-cisp/internal/httpapi/gen"
	"github.com/rootxkit/uspace-cisp/internal/jws"
	"github.com/rootxkit/uspace-cisp/internal/obs"
	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/restriction"
	"github.com/rootxkit/uspace-cisp/internal/store"
)

// The fake store's side of the restrictions (WP-5): the heads and their
// events, the job run, and ApplyRestriction's contract (Decide on the
// stored head and the current features, a replay writes nothing, the
// version through PublishTx).

type fakeRestrictions struct {
	heads map[string]*store.RestrictionRecord
	jobs  map[string]store.JobRun
	// otherLeader makes RunJob find the lock held by another replica.
	otherLeader bool
	// placement, when set, is what RestrictionPlacement answers.
	placement *store.Placement
	// applyErr, when set, is returned by ApplyRestriction.
	applyErr error
	// refsErr, when set, is returned by ActiveRestrictionRefs.
	refsErr error
	// refs are the publishers' declared refs (PublishersRefs).
	declared map[string][]string
	// clock is the database's clock (RunJob, LastJobRun); nil is
	// time.Now. The harness's at sets it with the restrictions' clock.
	clock func() time.Time
}

// The fake is a RestrictionStore (a mismatch would leave the harness
// without restrictions at run time).
var _ RestrictionStore = (*fakeStore)(nil)

func (r *fakeRestrictions) now() time.Time {
	if r.clock == nil {
		return time.Now().UTC()
	}
	return r.clock()
}

func (f *fakeStore) rs() *fakeRestrictions {
	if f.restr == nil {
		f.restr = &fakeRestrictions{heads: map[string]*store.RestrictionRecord{}, jobs: map[string]store.JobRun{}, declared: map[string][]string{}}
	}
	return f.restr
}

func (f *fakeStore) RestrictionByFeatureID(_ context.Context, featureID string) (store.RestrictionRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return store.RestrictionRecord{}, errFakeDown
	}
	for _, h := range f.rs().heads {
		if h.FeatureID == featureID {
			return *h, nil
		}
	}
	return store.RestrictionRecord{}, store.ErrNotFound
}

// RestrictionPlacement measures on the rows: the airspace is current
// when uspace_airspace holds it, the outline intersects it when their
// bounding boxes overlap, and the area is the outline box's (a fake for
// the handler tests; PostGIS measures in the integration tests).
func (f *fakeStore) RestrictionPlacement(_ context.Context, uspaceID string, parts []publication.GeomPart) (store.Placement, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return store.Placement{}, errFakeDown
	}
	if p := f.rs().placement; p != nil {
		return *p, nil
	}
	box, ok := rowBox(publication.FeatureRow{Geom: parts})
	if !ok {
		return store.Placement{}, nil
	}
	latM := (box.MaxLat - box.MinLat) * 111_320
	lonM := (box.MaxLon - box.MinLon) * 111_320 * math.Cos((box.MinLat+box.MaxLat)/2*math.Pi/180)
	out := store.Placement{AreaM2: latM * lonM}
	for i := range f.current[publication.DatasetUSpaceAirspace] {
		r := f.current[publication.DatasetUSpaceAirspace][i]
		if r.ID != uspaceID {
			continue
		}
		out.AirspaceCurrent = true
		if ab, ok := rowBox(r); ok {
			out.Intersects = overlaps(ab, store.BBox{MinLon: box.MinLon, MinLat: box.MinLat, MaxLon: box.MaxLon, MaxLat: box.MaxLat})
		}
	}
	return out, nil
}

func (f *fakeStore) findHead(id, anspRef string) *store.RestrictionRecord {
	for _, h := range f.rs().heads {
		if (id != "" && h.ID == id) || (id == "" && h.AnspRef == anspRef) {
			return h
		}
	}
	return nil
}

func (f *fakeStore) ApplyRestriction(ctx context.Context, w store.RestrictionWrite, signer store.Signer) (store.RestrictionResult, error) {
	f.mu.Lock()
	if f.down {
		f.mu.Unlock()
		return store.RestrictionResult{}, errFakeDown
	}
	if err := f.rs().applyErr; err != nil {
		f.mu.Unlock()
		return store.RestrictionResult{}, err
	}
	rec := f.findHead(w.ID, w.AnspRef)
	var head *restriction.Head
	if rec != nil {
		h := rec.Head
		head = &h
	}
	current := storedOf(f.current[publication.DatasetRestrictions])
	version := f.version[publication.DatasetRestrictions]
	f.mu.Unlock()

	d, err := w.Decide(head, current)
	if err != nil {
		return store.RestrictionResult{}, err
	}
	if d.Reason == "" {
		out := store.RestrictionResult{Replay: true, Version: version, ETag: publication.ETag(publication.DatasetRestrictions, version)}
		if head != nil {
			out.Head = *head
		}
		return out, nil
	}
	res, err := f.PublishTx(ctx, store.PublishInput{
		Dataset: publication.DatasetRestrictions, Body: w.Body, ContentType: w.ContentType, PublisherClientID: w.PublisherClientID,
		PublisherSignature: w.PublisherSignature, SignatureKID: w.SignatureKID, Collection: d.Collection, Reason: d.Reason,
		ReceivedAt: w.ReceivedAt,
	}, signer)
	if err != nil {
		return store.RestrictionResult{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	actor := w.Actor
	if actor == "" {
		actor = w.PublisherClientID
	}
	at := w.ReceivedAt.UTC()
	if rec == nil {
		rec = &store.RestrictionRecord{CreatedAt: at}
		f.rs().heads[d.Head.ID] = rec
	}
	rec.Head, rec.UpdatedAt, rec.LastPublisherClientID = d.Head, at, w.PublisherClientID
	pubID := res.PublicationID
	rec.Events = append(rec.Events, store.RestrictionEvent{At: at, Op: d.Op, AnspVersion: d.Head.AnspVersion, PublicationID: &pubID, Actor: actor})
	return store.RestrictionResult{
		Head: d.Head, Version: res.Version, ETag: res.ETag, PublicationID: pubID, Reason: d.Reason, Change: res.Change,
	}, nil
}

func (f *fakeStore) Restriction(_ context.Context, ref string, byAnspRef bool) (store.RestrictionRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return store.RestrictionRecord{}, errFakeDown
	}
	var h *store.RestrictionRecord
	if byAnspRef {
		h = f.findHead("", ref)
	} else {
		h = f.findHead(ref, "")
	}
	if h == nil {
		return store.RestrictionRecord{}, store.ErrNotFound
	}
	out := *h
	out.Events = append([]store.RestrictionEvent{}, h.Events...)
	return out, nil
}

func (f *fakeStore) Restrictions(_ context.Context, flt store.RestrictionFilter) ([]store.RestrictionRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return nil, errFakeDown
	}
	var out []store.RestrictionRecord
	for _, h := range f.rs().heads {
		switch {
		case flt.State != nil && h.State != *flt.State:
		case flt.Airspace != nil && h.UspaceAirspaceID != *flt.Airspace:
		case flt.At != nil && (flt.At.Before(h.StartsAt) || !flt.At.Before(h.EndsAt)):
		default:
			r := *h
			r.Events = append([]store.RestrictionEvent{}, h.Events...)
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].StartsAt.Equal(out[j].StartsAt) {
			return out[i].StartsAt.After(out[j].StartsAt)
		}
		return out[i].ID > out[j].ID
	})
	if len(out) > flt.Limit {
		out = out[:flt.Limit]
	}
	return out, nil
}

func (f *fakeStore) ExpiredRestrictions(_ context.Context, now time.Time, limit int) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return nil, errFakeDown
	}
	var out []string
	for _, h := range f.rs().heads {
		if h.State.Current() && !h.EndsAt.After(now) {
			out = append(out, h.ID)
		}
	}
	sort.Strings(out)
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (f *fakeStore) ActiveRestrictionRefs(context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.rs().refsErr != nil {
		return nil, f.rs().refsErr
	}
	if f.down {
		return nil, errFakeDown
	}
	var out []string
	for _, h := range f.rs().heads {
		if h.State == restriction.StateActive {
			out = append(out, h.AnspRef)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (f *fakeStore) CountActiveRestrictions(ctx context.Context) (int64, error) {
	refs, err := f.ActiveRestrictionRefs(ctx)
	return int64(len(refs)), err
}

func (f *fakeStore) RunJob(ctx context.Context, name, instance string, fn func(ctx context.Context, now time.Time) (int, error)) (bool, error) {
	f.mu.Lock()
	if f.down {
		f.mu.Unlock()
		return false, errFakeDown
	}
	if f.rs().otherLeader {
		f.mu.Unlock()
		return false, nil
	}
	now := f.rs().now()
	f.mu.Unlock()
	n, err := fn(ctx, now)
	if err != nil {
		return false, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rs().jobs[name] = store.JobRun{Name: name, RanAt: now.UTC(), Instance: instance, Count: n}
	return true, nil
}

func (f *fakeStore) LastJobRun(_ context.Context, name string) (store.JobRun, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return store.JobRun{}, errFakeDown
	}
	r, ok := f.rs().jobs[name]
	if !ok {
		return store.JobRun{}, store.ErrNotFound
	}
	r.Age = f.rs().now().Sub(r.RanAt)
	return r, nil
}

// PublishersRefs is the heartbeats recorded, with their active_refs.
func (f *fakeStore) PublishersRefs(context.Context) ([]store.PublisherRefs, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return nil, errFakeDown
	}
	out := []store.PublisherRefs{}
	for _, b := range f.beats {
		at := b.ReceivedAt
		out = append(out, store.PublisherRefs{ClientID: b.ClientID, Kind: b.Kind, LastHeartbeatAt: &at, StaleAfterS: 60, ActiveRefs: b.ActiveRefs})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ClientID < out[j].ClientID })
	return out, nil
}

// --- the harness ------------------------------------------------------------

// withRestrictions gives the harness the restrictions when its store
// serves them, with the heartbeat comparison, the staleness of the
// dataset reads and the status block wired as the api wires them.
func (h *pubHarness) withRestrictions(st PublicationStore, server *Server, status *obs.Status, logger *slog.Logger) {
	rst, ok := st.(RestrictionStore)
	if !ok {
		return
	}
	h.rs = &Restrictions{
		Store: rst, Signer: KeyRingSigner{Keys: h.ring}, Limits: restriction.F3548Limits(), ANSPClientID: anspID,
		MaxBodyBytes: restrictionMaxBytes, Instance: "test/1", Started: time.Now().UTC(), Status: status, Logger: logger,
	}
	if h.cache != nil {
		h.rs.OnPublished = func() { _ = h.cache.Refresh(context.Background()) }
	}
	server.Restrictions = h.rs
	h.pubs.OnANSPRefs = h.rs.CompareRefs
	if h.reads != nil {
		h.reads.PublisherStale = h.rs.ANSPStale
	}
	server.Status.Restrictions = h.rs.Report
}

// at sets the restrictions' clock and, on the fake store, the
// database's.
func (h *pubHarness) at(t time.Time) {
	h.rs.Now = func() time.Time { return t }
	if h.fake != nil {
		h.fake.rs().clock = func() time.Time { return t }
	}
}

// processAt sets only the restrictions' (the process's) clock.
func (h *pubHarness) processAt(t time.Time) { h.rs.Now = func() time.Time { return t } }

func (h *pubHarness) anspToken() string {
	return h.token(anspID, auth.ScopePublishRestrictions, auth.ScopeRead)
}

func (h *pubHarness) signANSP(body []byte) string {
	h.t.Helper()
	s, err := coreauth.SignDetached(coreauth.SigningKey{KID: anspKID, Key: h.anspSigner}, body, time.Now())
	if err != nil {
		h.t.Fatal(err)
	}
	return s
}

// restrictionReq is a signed restriction write by the ANSP with its
// client certificate subject.
func (h *pubHarness) restrictionReq(method, target string, body []byte, edit ...func(*http.Request)) *http.Request {
	h.t.Helper()
	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+h.anspToken())
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(auth.HeaderClientCertSubject, anspSubject)
	req.Header.Set(jws.HeaderSignature, h.signANSP(body))
	for _, e := range edit {
		e(req)
	}
	return req
}

// send does the request and checks it against the spec with a fresh
// copy of the body.
func (h *pubHarness) send(req *http.Request, body []byte) *httptest.ResponseRecorder {
	h.t.Helper()
	rec := h.do(req)
	conformPut(h.t, req, body, rec)
	return rec
}

// sendRaw does a request the spec itself refuses (a refusal test):
// only the response is checked against the spec.
func (h *pubHarness) sendRaw(req *http.Request) *httptest.ResponseRecorder {
	h.t.Helper()
	rec := h.do(req)
	conformResponse(h.t, req, rec)
	return rec
}

// postRestrictionRaw is postRestriction for a body the spec refuses.
func (h *pubHarness) postRestrictionRaw(body doc) *httptest.ResponseRecorder {
	h.t.Helper()
	return h.sendRaw(h.restrictionReq(http.MethodPost, "/v1/restrictions", jsonBytes(h.t, body)))
}

// postRestriction POSTs body (a doc) signed.
func (h *pubHarness) postRestriction(body doc, edit ...func(*http.Request)) *httptest.ResponseRecorder {
	h.t.Helper()
	raw := jsonBytes(h.t, body)
	return h.send(h.restrictionReq(http.MethodPost, "/v1/restrictions", raw, edit...), raw)
}

// patchRestriction PATCHes the restriction ref (an id, or with by an
// ansp_ref).
func (h *pubHarness) patchRestriction(ref string, body doc, edit ...func(*http.Request)) *httptest.ResponseRecorder {
	h.t.Helper()
	raw := jsonBytes(h.t, body)
	return h.send(h.restrictionReq(http.MethodPatch, "/v1/restrictions/"+ref, raw, edit...), raw)
}

func decodeRestriction(t testing.TB, rec *httptest.ResponseRecorder) gen.RestrictionResult {
	t.Helper()
	var r gen.RestrictionResult
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatalf("%v: %s", err, rec.Body.String())
	}
	return r
}

// --- documents ----------------------------------------------------------------

// darDoc is a DAR feature over the vector's U-space airspace TSU001
// ([44.70..44.95] x [41.65..41.80]), its one period [starts, ends].
func darDoc(id string, starts, ends time.Time) doc {
	return doc{
		"type": "Feature",
		"geometry": doc{
			"type":        "Polygon",
			"coordinates": []any{[]any{[]any{44.80, 41.70}, []any{44.82, 41.70}, []any{44.82, 41.72}, []any{44.80, 41.72}, []any{44.80, 41.70}}},
			"layer":       doc{"lower": 0, "lowerReference": "AGL", "upper": 120, "upperReference": "AGL", "uom": "m"},
		},
		"properties": doc{
			"identifier": id, "country": "GEO", "type": "PROHIBITED", "variant": "COMMON", "reason": []any{"DAR"},
			"name": []any{doc{"lang": "en-GB", "text": "Dynamic restriction " + id}},
			"limitedApplicability": []any{doc{
				"startDateTime": starts.UTC().Format(time.RFC3339), "endDateTime": ends.UTC().Format(time.RFC3339),
			}},
			"zoneAuthority": []any{doc{"name": []any{doc{"lang": "en-GB", "text": "Test ANSP"}}, "purpose": "NOTIFICATION"}},
		},
	}
}

// createDoc is a POST body for the restriction ref with feature id.
func createDoc(ref string, version int64, state, id string, starts, ends time.Time) doc {
	return doc{
		"ansp_ref": ref, "ansp_version": version, "uspace_airspace_id": "TSU001", "state": state,
		"starts_at": starts.UTC().Format(time.RFC3339), "ends_at": ends.UTC().Format(time.RFC3339),
		"feature": darDoc(id, starts, ends),
	}
}

// publishAirspace makes TSU001 a current U-space airspace.
func (h *pubHarness) publishAirspace() {
	h.t.Helper()
	if rec := h.put("uspace_airspace", jsonBytes(h.t, uspaceDoc(h.t))); rec.Code != 201 && rec.Code != 200 {
		h.t.Fatalf("uspace_airspace = %d %s", rec.Code, rec.Body.String())
	}
}

// restrictionsVersion is the restrictions dataset's current version.
func (h *pubHarness) restrictionsVersion() int64 {
	h.t.Helper()
	v, err := h.store.CurrentVersion(context.Background(), publication.DatasetRestrictions)
	if err != nil {
		h.t.Fatal(err)
	}
	return v
}

// servedRestrictions reads GET /v1/restrictions and returns the members
// cis_restriction by identifier.
func (h *pubHarness) servedRestrictions(query string) (doc, map[string]restriction.Member) {
	h.t.Helper()
	rec := h.read(http.MethodGet, "/v1/restrictions"+query)
	if rec.Code != http.StatusOK {
		h.t.Fatalf("GET /v1/restrictions%s = %d %s", query, rec.Code, rec.Body.String())
	}
	d, byID := collection(h.t, rec)
	out := map[string]restriction.Member{}
	for id, f := range byID {
		ext, _ := f["properties"].(doc)["extendedProperties"].(doc)
		raw, err := json.Marshal(ext[restriction.MemberName])
		if err != nil {
			h.t.Fatal(err)
		}
		var m restriction.Member
		if err := json.Unmarshal(raw, &m); err != nil {
			h.t.Fatalf("%s: %v", id, err)
		}
		out[id] = m
	}
	return d, out
}

// lastChange is the newest change of the restrictions dataset.
func (h *pubHarness) lastChange() publication.Change {
	h.t.Helper()
	ds := publication.DatasetRestrictions
	cs, err := h.reads.Store.Changes(context.Background(), 0, &ds, 1<<20)
	if err != nil || len(cs) == 0 {
		h.t.Fatalf("changes: %v %d", err, len(cs))
	}
	return cs[len(cs)-1]
}

func i64toa(v int64) string { return strconv.FormatInt(v, 10) }
