package httpapi

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rsa"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	coreauth "github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/geodesy"

	"github.com/rootxkit/uspace-cisp/internal/auth"
	"github.com/rootxkit/uspace-cisp/internal/authtest"
	"github.com/rootxkit/uspace-cisp/internal/jws"
	"github.com/rootxkit/uspace-cisp/internal/outline"
	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/store"
)

// readZones is a zones dataset of three features with known verdicts at
// winterMonday (Monday 21 December 2026, 12:00 UTC, 16:00 at +04:00):
//
//   - TSR001, Tbilisi, weekdays 08:00-18:00+04:00: applies;
//   - TSC001, Tbilisi, weekends 22:00-02:00Z: does not apply;
//   - TSP001, Svalbard (78.2 N), sunrise to sunset every day: in polar
//     night there is no sunrise, so it cannot be evaluated: unknown.
func readZones(t testing.TB) doc {
	t.Helper()
	d := zonesDoc(t) // TSD001, TSR001, TSC001, TSN001
	tsr := feats(d)[1].(doc)
	tsc := feats(d)[2].(doc)
	var polar doc
	if err := json.Unmarshal(jsonBytes(t, tsr), &polar); err != nil {
		t.Fatal(err)
	}
	p := polar["properties"].(doc)
	p["identifier"] = "TSP001"
	p["name"] = []any{doc{"lang": "en-GB", "text": "Polar daylight zone"}}
	p["limitedApplicability"] = []any{doc{"schedule": []any{doc{"day": []any{"ANY"}, "startEvent": "SR", "endEvent": "SS"}}}}
	polar["id"] = "TSP001"
	g := polar["geometry"].(doc)
	g["coordinates"] = []any{[]any{[]any{15.60, 78.20}, []any{15.65, 78.20}, []any{15.65, 78.25}, []any{15.60, 78.25}, []any{15.60, 78.20}}}
	d["features"] = []any{tsr, tsc, polar}
	return d
}

var (
	winterMonday = "2026-12-21T12:00:00Z"
	winterNight  = "2026-12-21T20:00:00Z"
)

// verifyCISP checks the CISP's detached signature over body against the
// harness key ring's public key.
func verifyCISP(t testing.TB, sig string, body []byte) {
	t.Helper()
	set := authtest.PublicSet(t, map[string]*rsa.PrivateKey{"cisp-2": authtest.Key(t, "cisp", 3072)})
	v, err := jws.NewDetachedVerifier(context.Background(), jws.KeySource{Publisher: "cisp", Keys: coreauth.IssuerConfig{Keys: set}},
		time.Hour, jws.Options{MaxPayloadBytes: 64 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), sig, body); err != nil {
		t.Errorf("X-CIS-Signature does not verify over the body: %v", err)
	}
}

func (h *pubHarness) reader() string { return h.token(usspID, auth.ScopeRead) }

// read sends a request with the reader's token (none for /public) and
// the given headers, and checks request and response against the spec.
func (h *pubHarness) read(method, target string, headers ...string) *httptest.ResponseRecorder {
	h.t.Helper()
	req := httptest.NewRequest(method, target, http.NoBody)
	if strings.HasPrefix(target, "/v1/") {
		req.Header.Set("Authorization", "Bearer "+h.reader())
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	rec := h.do(req)
	if rec.Header().Get("Content-Encoding") == "" {
		conform(h.t, req, rec)
	}
	return rec
}

// readRaw is read for a request the spec itself refuses (past a
// minimum or maximum): only the response is checked against the spec.
func (h *pubHarness) readRaw(method, target string) *httptest.ResponseRecorder {
	h.t.Helper()
	req := httptest.NewRequest(method, target, http.NoBody)
	req.Header.Set("Authorization", "Bearer "+h.reader())
	rec := h.do(req)
	conformResponse(h.t, req, rec)
	return rec
}

// collection decodes a served FeatureCollection into id -> feature.
func collection(t testing.TB, rec *httptest.ResponseRecorder) (doc, map[string]doc) {
	t.Helper()
	var d doc
	if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil {
		t.Fatalf("%v: %s", err, rec.Body.String())
	}
	out := map[string]doc{}
	for _, f := range feats(d) {
		fd := f.(doc)
		out[fd["properties"].(doc)["identifier"].(string)] = fd
	}
	return d, out
}

func annotation(f doc) any {
	ext, _ := f["properties"].(doc)["extendedProperties"].(doc)
	if ext == nil {
		return nil
	}
	return ext["cis_applicability"]
}

func ids(m map[string]doc) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func inflate(t testing.TB, gz []byte) []byte {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (h *pubHarness) publishReadZones() int64 {
	h.t.Helper()
	rec := h.put("zones", jsonBytes(h.t, readZones(h.t)))
	if rec.Code != 201 {
		h.t.Fatalf("PUT = %d %s", rec.Code, rec.Body.String())
	}
	return decodeResultTB(h.t, rec).Version
}

func decodeResultTB(t testing.TB, rec *httptest.ResponseRecorder) struct{ Version int64 } {
	t.Helper()
	var r struct{ Version int64 }
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	return r
}

// Unfiltered: the snapshot's bytes, signed, with the section 6.3 headers;
// HEAD the same headers and no body; gzip when the client takes it.
func TestReadUnfilteredSnapshot(t *testing.T) {
	h := newPubHarness(t, nil)
	v := h.publishReadZones()
	snap := h.fake.snaps[publication.DatasetZones][v]
	want := inflate(t, snap.BodyGz)

	rec := h.read(http.MethodGet, "/v1/zones")
	if rec.Code != 200 || !bytes.Equal(rec.Body.Bytes(), want) {
		t.Fatalf("GET = %d, body equal %v", rec.Code, bytes.Equal(rec.Body.Bytes(), want))
	}
	hd := rec.Header()
	checks := map[string]string{
		"Content-Type": "application/geo+json", "ETag": `"zones:1"`, "X-CIS-Version": "1",
		"Cache-Control": "public, max-age=60", "Vary": "Accept-Encoding",
		"Last-Modified": snap.ReceivedAt.UTC().Format(http.TimeFormat),
	}
	for k, w := range checks {
		if hd.Get(k) != w {
			t.Errorf("%s = %q, want %q", k, hd.Get(k), w)
		}
	}
	for _, k := range []string{HeaderStale, HeaderAgeS, HeaderFiltered} {
		if hd.Get(k) != "" {
			t.Errorf("%s set on a fresh unfiltered read: %q", k, hd.Get(k))
		}
	}
	verifyCISP(t, hd.Get(HeaderSignature), rec.Body.Bytes())
	d, byID := collection(t, rec)
	if d["cis_dataset"] != "zones" || d["cis_version"] != 1.0 || d["cis_updated_at"] == nil || len(byID) != 3 {
		t.Errorf("members %v %v", d["cis_dataset"], ids(byID))
	}
	t.Logf("GET /v1/zones: %d, headers %v", rec.Code, hd)

	head := h.read(http.MethodHead, "/v1/zones")
	if head.Code != 200 || head.Body.Len() != 0 {
		t.Errorf("HEAD = %d, %d bytes", head.Code, head.Body.Len())
	}
	for _, k := range []string{"ETag", "X-CIS-Version", "Cache-Control", "Last-Modified", HeaderSignature} {
		if head.Header().Get(k) != hd.Get(k) {
			t.Errorf("HEAD %s = %q, GET %q", k, head.Header().Get(k), hd.Get(k))
		}
	}

	gz := h.read(http.MethodGet, "/v1/zones", "Accept-Encoding", "br;q=1, gzip;q=0.5")
	if gz.Code != 200 || gz.Header().Get("Content-Encoding") != "gzip" || !bytes.Equal(gz.Body.Bytes(), snap.BodyGz) {
		t.Errorf("gzip GET = %d %q", gz.Code, gz.Header().Get("Content-Encoding"))
	}
	if off := h.read(http.MethodGet, "/v1/zones", "Accept-Encoding", "gzip;q=0"); off.Header().Get("Content-Encoding") != "" || !bytes.Equal(off.Body.Bytes(), want) {
		t.Error("gzip;q=0 was served compressed")
	}
}

// If-None-Match: the current ETag is 304 (GET and HEAD), an older one is
// the full answer (E-01).
func TestReadIfNoneMatch(t *testing.T) {
	h := newPubHarness(t, nil)
	h.publishReadZones()
	for _, m := range []string{http.MethodGet, http.MethodHead} {
		hit := h.read(m, "/v1/zones", "If-None-Match", `W/"zones:1"`)
		if hit.Code != 304 || hit.Body.Len() != 0 || hit.Header().Get("ETag") != `"zones:1"` {
			t.Errorf("%s hit = %d %q %v", m, hit.Code, hit.Body.String(), hit.Header())
		}
		miss := h.read(m, "/v1/zones", "If-None-Match", `"zones:0"`)
		if miss.Code != 200 {
			t.Errorf("%s miss = %d", m, miss.Code)
		}
	}
	// A filtered read is 304 for the same version too.
	if rec := h.read(http.MethodGet, "/v1/zones?bbox=44.79,41.69,44.83,41.725", "If-None-Match", `"zones:1"`); rec.Code != 304 {
		t.Errorf("filtered hit = %d", rec.Code)
	}
}

// A dataset never published is 404 no_version with its ETag; an
// unknown dataset is the router's 404; the public surface has no
// versions and no change feed.
func TestReadNotFound(t *testing.T) {
	h := newPubHarness(t, nil)
	rec := h.read(http.MethodGet, "/v1/restrictions")
	if p := decodeProblem(t, rec); rec.Code != 404 || p.Type != ProblemTypeBase+SlugNoVersion || rec.Header().Get("ETag") != `"restrictions:0"` {
		t.Errorf("no version = %d %s", rec.Code, rec.Body.String())
	}
	if rec := h.read(http.MethodGet, "/v1/restrictions?bbox=0,0,1,1"); rec.Code != 404 {
		t.Errorf("filtered, no version = %d", rec.Code)
	}
	for _, target := range []string{"/v1/nosuch", "/public/v1/changes", "/public/v1/zones/versions", "/public/v1/zones/versions/1"} {
		req := httptest.NewRequest(http.MethodGet, target, http.NoBody)
		req.Header.Set("Authorization", "Bearer "+h.reader())
		rec := h.do(req)
		if p := decodeProblem(t, rec); rec.Code != 404 || p.Type != ProblemTypeBase+SlugNotFound {
			t.Errorf("%s = %d %s", target, rec.Code, rec.Body.String())
		}
	}
}

// bbox: the features whose box overlaps, none outside; the filtered
// collection carries the cis_* members, X-CIS-Filtered, the version's
// ETag and no signature. Every malformed box is 400 naming bbox.
func TestReadBBox(t *testing.T) {
	h := newPubHarness(t, nil)
	h.publishReadZones()
	rec := h.read(http.MethodGet, "/v1/zones?bbox=44.79,41.69,44.83,41.725")
	d, byID := collection(t, rec)
	if rec.Code != 200 || len(byID) != 1 || byID["TSR001"] == nil {
		t.Fatalf("inside = %d %v", rec.Code, ids(byID))
	}
	if rec.Header().Get(HeaderFiltered) != "bbox" || rec.Header().Get(HeaderSignature) != "" || rec.Header().Get("ETag") != `"zones:1"` {
		t.Errorf("headers %v", rec.Header())
	}
	meta, _ := d["metadata"].(doc)
	if d["cis_version"] != 1.0 || meta["issued"] == nil {
		t.Errorf("collection members %v %v", d["cis_version"], meta)
	}
	if annotation(byID["TSR001"]) != nil {
		t.Error("a bbox read annotated a feature")
	}
	outside := h.read(http.MethodGet, "/v1/zones?bbox=0,0,1,1")
	if _, none := collection(t, outside); outside.Code != 200 || len(none) != 0 {
		t.Errorf("outside = %d %v", outside.Code, ids(none))
	}
	for _, bad := range []string{"1,2,3", "a,0,1,1", "NaN,0,1,1", "0,0,1,Inf", "-181,0,1,1", "0,-91,1,1", "0,2,1,1", "10,0,-10,1"} {
		rec := h.read(http.MethodGet, "/v1/zones?bbox="+url.QueryEscape(bad))
		if p := decodeProblem(t, rec); rec.Code != 400 || !hasProblem(p, "bbox", "") {
			t.Errorf("bbox=%s: %d %s", bad, rec.Code, rec.Body.String())
		}
	}
	anti := h.read(http.MethodGet, "/v1/zones?bbox=170,0,-170,1")
	if !strings.Contains(anti.Body.String(), "antimeridian") {
		t.Errorf("antimeridian: %s", anti.Body.String())
	}
}

// at: inside the window the applying feature and the unknown one (kept,
// marked) are served and the other dropped; at night only the unknown
// one is left. A naive time, a + read as a space, and at with
// applies_at are 400.
func TestReadAt(t *testing.T) {
	h := newPubHarness(t, nil)
	h.publishReadZones()
	unknownBefore := h.counter(readsComponent, CounterApplicabilityUnknown)
	rec := h.read(http.MethodGet, "/v1/zones?at="+url.QueryEscape(winterMonday))
	_, byID := collection(t, rec)
	if rec.Code != 200 || strings.Join(ids(byID), ",") != "TSP001,TSR001" || rec.Header().Get(HeaderFiltered) != "at" {
		t.Fatalf("at day = %d %v", rec.Code, ids(byID))
	}
	if annotation(byID["TSP001"]) != "unknown" || annotation(byID["TSR001"]) != nil {
		t.Errorf("annotations %v %v", annotation(byID["TSP001"]), annotation(byID["TSR001"]))
	}
	if got := h.counter(readsComponent, CounterApplicabilityUnknown) - unknownBefore; got != 1 {
		t.Errorf("applicability_unknown counted %d", got)
	}
	night := h.read(http.MethodGet, "/v1/zones?at="+url.QueryEscape(winterNight))
	if _, byID := collection(t, night); strings.Join(ids(byID), ",") != "TSP001" {
		t.Errorf("at night %v", ids(byID))
	}
	// The stored feature is never annotated.
	if bytes.Contains(h.fake.current[publication.DatasetZones][2].Canonical, []byte("cis_applicability")) {
		t.Error("the stored row was annotated")
	}
	for raw, phrase := range map[string]string{
		"2026-12-21T12:00:00":       "offset",
		"2026-12-21T16:00:00 04:00": "%2B",
		"yesterday":                 "RFC 3339",
	} {
		rec := h.read(http.MethodGet, "/v1/zones?at="+url.QueryEscape(raw))
		if p := decodeProblem(t, rec); rec.Code != 400 || !hasProblem(p, "at", phrase) {
			t.Errorf("at=%q: %d %s", raw, rec.Code, rec.Body.String())
		}
	}
	both := h.read(http.MethodGet, "/v1/zones?at="+url.QueryEscape(winterMonday)+"&applies_at="+url.QueryEscape(winterMonday))
	if p := decodeProblem(t, both); both.Code != 400 || p.Type != ProblemTypeBase+SlugFilterConflict {
		t.Errorf("at and applies_at = %d %s", both.Code, both.Body.String())
	}
	if rec := h.read(http.MethodGet, "/v1/zones?applies_at=nope"); rec.Code != 400 {
		t.Errorf("applies_at=nope = %d", rec.Code)
	}
}

// applies_at annotates and never filters: the same features as no
// filter, each with the right annotation; combined with bbox it
// annotates what the box keeps.
func TestReadAppliesAt(t *testing.T) {
	h := newPubHarness(t, nil)
	h.publishReadZones()
	_, all := collection(t, h.read(http.MethodGet, "/v1/zones"))
	rec := h.read(http.MethodGet, "/v1/zones?applies_at="+url.QueryEscape(winterMonday))
	_, byID := collection(t, rec)
	if len(byID) != len(all) || len(all) != 3 || rec.Header().Get(HeaderFiltered) != "applies_at" {
		t.Fatalf("applies_at kept %v of %v", ids(byID), ids(all))
	}
	want := map[string]string{"TSR001": "applies", "TSC001": "not_applicable", "TSP001": "unknown"}
	for id, w := range want {
		if got := annotation(byID[id]); got != w {
			t.Errorf("%s = %v, want %s", id, got, w)
		}
	}
	boxed := h.read(http.MethodGet, "/v1/zones?bbox=44.79,41.69,44.83,41.725&applies_at="+url.QueryEscape(winterMonday))
	if _, b := collection(t, boxed); len(b) != 1 || annotation(b["TSR001"]) != "applies" || boxed.Header().Get(HeaderFiltered) != "bbox, applies_at" {
		t.Errorf("bbox and applies_at: %v %q", ids(b), boxed.Header().Get(HeaderFiltered))
	}
}

// since_version: 0, one change and several, the current version (empty),
// a version above the current one (400) and one past the window (410).
func TestReadSinceVersion(t *testing.T) {
	h := newPubHarness(t, nil)
	h.publishReadZones() // v1: TSR001, TSC001, TSP001
	d := readZones(t)
	fprops(d, 1)["name"] = []any{doc{"lang": "en-GB", "text": "Weekend nights, renamed"}} // TSC001 changed
	d["features"] = feats(d)[:2]                                                          // TSP001 removed
	if rec := h.put("zones", jsonBytes(t, d)); rec.Code != 201 {
		t.Fatalf("v2 = %d %s", rec.Code, rec.Body.String())
	}
	tsn := feats(zonesDoc(t))[3]
	d["features"] = append(feats(d), tsn) // TSN001 added
	if rec := h.put("zones", jsonBytes(t, d)); rec.Code != 201 {
		t.Fatalf("v3 = %d %s", rec.Code, rec.Body.String())
	}
	type delta struct {
		From, To        int64
		Added, Changed  []string
		Removed         []string
		Filtered, ETag  string
		ContentTypeJSON bool
	}
	get := func(v string) (int, delta) {
		rec := h.read(http.MethodGet, "/v1/zones?since_version="+v)
		if rec.Code != 200 {
			return rec.Code, delta{}
		}
		var body struct {
			FromVersion int64 `json:"from_version"`
			ToVersion   int64 `json:"to_version"`
			Added       doc   `json:"added"`
			Changed     doc   `json:"changed"`
			Removed     []string
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		names := func(fc doc) []string {
			var out []string
			for _, f := range feats(fc) {
				out = append(out, f.(doc)["properties"].(doc)["identifier"].(string))
			}
			return out
		}
		return rec.Code, delta{
			From: body.FromVersion, To: body.ToVersion, Added: names(body.Added), Changed: names(body.Changed), Removed: body.Removed,
			Filtered: rec.Header().Get(HeaderFiltered), ETag: rec.Header().Get("ETag"),
			ContentTypeJSON: rec.Header().Get("Content-Type") == "application/json",
		}
	}
	if code, d0 := get("0"); code != 200 || strings.Join(d0.Added, ",") != "TSC001,TSN001,TSR001" || len(d0.Changed)+len(d0.Removed) != 0 || d0.To != 3 || !d0.ContentTypeJSON || d0.Filtered != "since_version" || d0.ETag != `"zones:3"` {
		t.Errorf("since 0 = %d %+v", code, d0)
	}
	if code, d2 := get("2"); code != 200 || strings.Join(d2.Added, ",") != "TSN001" || len(d2.Changed)+len(d2.Removed) != 0 {
		t.Errorf("since 2 (one change) = %d %+v", code, d2)
	}
	if code, d1 := get("1"); code != 200 || strings.Join(d1.Added, ",") != "TSN001" || strings.Join(d1.Changed, ",") != "TSC001" || strings.Join(d1.Removed, ",") != "TSP001" {
		t.Errorf("since 1 (several) = %d %+v", code, d1)
	}
	if code, d3 := get("3"); code != 200 || len(d3.Added)+len(d3.Changed)+len(d3.Removed) != 0 || d3.From != 3 {
		t.Errorf("since 3 (current) = %d %+v", code, d3)
	}
	ahead := h.read(http.MethodGet, "/v1/zones?since_version=4")
	if p := decodeProblem(t, ahead); ahead.Code != 400 || !hasProblem(p, "since_version", "above") {
		t.Errorf("ahead = %d %s", ahead.Code, ahead.Body.String())
	}
	h.reads.MaxDeltaVersions = 2
	gone := h.read(http.MethodGet, "/v1/zones?since_version=0")
	if p := decodeProblem(t, gone); gone.Code != 410 || p.Type != ProblemTypeBase+SlugDeltaUnavailable || gone.Header().Get("ETag") != `"zones:3"` {
		t.Errorf("too old = %d %s", gone.Code, gone.Body.String())
	}
	if code, _ := get("1"); code != 200 {
		t.Errorf("inside the window = %d", code)
	}
	mixed := h.read(http.MethodGet, "/v1/zones?since_version=1&bbox=0,0,1,1")
	if p := decodeProblem(t, mixed); mixed.Code != 400 || p.Type != ProblemTypeBase+SlugFilterConflict {
		t.Errorf("since_version with bbox = %d %s", mixed.Code, mixed.Body.String())
	}
	if neg := h.readRaw(http.MethodGet, "/v1/zones?since_version=-1"); neg.Code != 400 {
		t.Errorf("since_version=-1 = %d %s", neg.Code, neg.Body.String())
	}
}

// The USSP list: served as published plus the cis_* members, signed;
// bbox, at and applies_at are 400 filter_not_applicable; since_version
// answers the whole list (no features to diff), above current is 400.
func TestReadUsspList(t *testing.T) {
	h := newPubHarness(t, nil)
	if rec := h.put("ussp_list", usspListBody(t)); rec.Code != 201 {
		t.Fatalf("PUT = %d %s", rec.Code, rec.Body.String())
	}
	rec := h.read(http.MethodGet, "/v1/ussp_list")
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "application/json" || !strings.Contains(rec.Body.String(), `"base_url"`) {
		t.Fatalf("GET = %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
	verifyCISP(t, rec.Header().Get(HeaderSignature), rec.Body.Bytes())
	for _, q := range []string{"bbox=0,0,1,1", "at=" + url.QueryEscape(winterMonday), "applies_at=" + url.QueryEscape(winterMonday)} {
		bad := h.read(http.MethodGet, "/v1/ussp_list?"+q)
		if p := decodeProblem(t, bad); bad.Code != 400 || p.Type != ProblemTypeBase+SlugFilterNotApplicable {
			t.Errorf("%s = %d %s", q, bad.Code, bad.Body.String())
		}
	}
	whole := h.read(http.MethodGet, "/v1/ussp_list?since_version=0")
	if whole.Code != 200 || !bytes.Equal(whole.Body.Bytes(), rec.Body.Bytes()) {
		t.Errorf("since_version on ussp_list = %d", whole.Code)
	}
	if ahead := h.read(http.MethodGet, "/v1/ussp_list?since_version=2"); ahead.Code != 400 {
		t.Errorf("ahead = %d", ahead.Code)
	}
}

// E-02 on the cache: the database gone, an unfiltered read serves the
// held snapshot marked stale and uncacheable, a filtered read is 503
// with Retry-After, a snapshot never held is 503; the database back,
// the marks are gone.
func TestReadStaleThenFresh(t *testing.T) {
	h := newPubHarness(t, nil)
	h.publishReadZones()
	if rec := h.read(http.MethodGet, "/v1/zones"); rec.Code != 200 {
		t.Fatalf("warm = %d", rec.Code)
	}
	if rec := h.put("ussp_list", usspListBody(t)); rec.Code != 201 { // never read: not held
		t.Fatalf("ussp_list = %d", rec.Code)
	}
	h.fake.mu.Lock()
	h.fake.down = true
	h.fake.mu.Unlock()
	if err := h.cache.Refresh(context.Background()); err == nil {
		t.Fatal("refresh succeeded with the store down")
	}
	stale := h.read(http.MethodGet, "/v1/zones")
	hd := stale.Header()
	if stale.Code != 200 || hd.Get(HeaderStale) != "true" || hd.Get("Cache-Control") != "no-store" || hd.Get(HeaderAgeS) == "" || hd.Get(HeaderSignature) == "" {
		t.Errorf("stale GET = %d %v", stale.Code, hd)
	}
	t.Logf("stale GET: %d X-CIS-Stale=%s X-CIS-Age-S=%s Cache-Control=%s", stale.Code, hd.Get(HeaderStale), hd.Get(HeaderAgeS), hd.Get("Cache-Control"))
	if head := h.read(http.MethodHead, "/v1/zones"); head.Header().Get(HeaderStale) != "true" || head.Code != 200 {
		t.Errorf("stale HEAD = %d", head.Code)
	}
	if nm := h.read(http.MethodGet, "/v1/zones", "If-None-Match", `"zones:1"`); nm.Code != 304 || nm.Header().Get(HeaderStale) != "true" {
		t.Errorf("stale 304 = %d %v", nm.Code, nm.Header())
	}
	for _, q := range []string{"bbox=0,0,1,1", "at=" + url.QueryEscape(winterMonday), "since_version=0"} {
		rec := h.read(http.MethodGet, "/v1/zones?"+q)
		if p := decodeProblem(t, rec); rec.Code != 503 || p.Type != ProblemTypeBase+SlugCISStale || rec.Header().Get("Retry-After") != "5" || !strings.Contains(*p.Detail, "unreachable since") {
			t.Errorf("stale %s = %d %s", q, rec.Code, rec.Body.String())
		}
	}
	never := h.read(http.MethodGet, "/v1/ussp_list")
	if p := decodeProblem(t, never); never.Code != 503 || p.Type != ProblemTypeBase+SlugCISStale {
		t.Errorf("never held = %d %s", never.Code, never.Body.String())
	}
	if h.counter(readsComponent, CounterStaleServed) == 0 || h.counter(readsComponent, CounterStaleRefused) == 0 {
		t.Error("stale reads not counted")
	}

	h.fake.mu.Lock()
	h.fake.down = false
	h.fake.mu.Unlock()
	if err := h.cache.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	fresh := h.read(http.MethodGet, "/v1/zones")
	if fresh.Header().Get(HeaderStale) != "" || fresh.Header().Get(HeaderAgeS) != "" || fresh.Header().Get("Cache-Control") != "public, max-age=60" {
		t.Errorf("fresh again: %v", fresh.Header())
	}
	if rec := h.read(http.MethodGet, "/v1/zones?bbox=0,0,1,1"); rec.Code != 200 {
		t.Errorf("filtered fresh = %d", rec.Code)
	}
}

// A store failure on a filtered read with a fresh cache: 503
// database_unavailable for a connectivity failure, 500 for anything else
// (logged).
func TestReadStoreFailures(t *testing.T) {
	h := newPubHarness(t, nil)
	h.publishReadZones()
	if rec := h.read(http.MethodGet, "/v1/zones"); rec.Code != 200 {
		t.Fatal(rec.Code)
	}
	h.reads.Store = failingReads{fakeStore: h.fake, err: errFakeDown}
	rec := h.read(http.MethodGet, "/v1/zones?bbox=0,0,1,1")
	if p := decodeProblem(t, rec); rec.Code != 503 || p.Type != ProblemTypeBase+SlugDatabaseUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Errorf("down = %d %s", rec.Code, rec.Body.String())
	}
	h.reads.Store = failingReads{fakeStore: h.fake, err: io.ErrShortBuffer}
	for _, target := range []string{"/v1/zones?bbox=0,0,1,1", "/v1/zones?since_version=0", "/v1/zones/versions", "/v1/zones/versions/1", "/v1/changes"} {
		rec := h.read(http.MethodGet, target)
		if p := decodeProblem(t, rec); rec.Code != 500 || p.Type != ProblemTypeBase+SlugInternal {
			t.Errorf("%s = %d %s", target, rec.Code, rec.Body.String())
		}
	}
	if !strings.Contains(h.logs.String(), `"msg":"read failed"`) {
		t.Error("no log line for the failure")
	}
	h.reads.Store = failingReads{fakeStore: h.fake, err: context.DeadlineExceeded}
	if rec := h.read(http.MethodGet, "/v1/zones?bbox=0,0,1,1"); rec.Code != 503 {
		t.Errorf("deadline = %d", rec.Code)
	}
	// A stored feature that no longer parses is a fault, never a silent
	// drop.
	h.reads.Store = brokenRows{fakeStore: h.fake}
	if rec := h.read(http.MethodGet, "/v1/zones?bbox=40,40,50,50"); rec.Code != 500 {
		t.Errorf("unparseable row = %d", rec.Code)
	}
	if rec := h.read(http.MethodGet, "/v1/zones?since_version=0"); rec.Code != 500 {
		t.Errorf("unparseable delta row = %d", rec.Code)
	}
}

type failingReads struct {
	*fakeStore
	err error
}

func (f failingReads) ReadCurrent(context.Context, publication.Dataset, *store.BBox) (store.CurrentRead, error) {
	return store.CurrentRead{}, f.err
}

func (f failingReads) ReadDelta(context.Context, publication.Dataset, int64, int64) (store.DeltaRead, error) {
	return store.DeltaRead{}, f.err
}

func (f failingReads) Publication(context.Context, publication.Dataset, int64) (store.StoredPublication, error) {
	return store.StoredPublication{}, f.err
}

func (f failingReads) Versions(context.Context, publication.Dataset, int64, int) ([]store.Version, error) {
	return nil, f.err
}

func (f failingReads) Changes(context.Context, int64, *publication.Dataset, int) ([]publication.Change, error) {
	return nil, f.err
}

type brokenRows struct{ *fakeStore }

func (b brokenRows) ReadCurrent(ctx context.Context, ds publication.Dataset, box *store.BBox) (store.CurrentRead, error) {
	r, err := b.fakeStore.ReadCurrent(ctx, ds, box)
	r.Features = append(r.Features, store.StoredFeature{ID: "BAD", Feature: []byte(`{"type":"Feature"}`)})
	return r, err
}

func (b brokenRows) ReadDelta(ctx context.Context, ds publication.Dataset, from, maxBack int64) (store.DeltaRead, error) {
	r, err := b.fakeStore.ReadDelta(ctx, ds, from, maxBack)
	r.ToFeatures = append(r.ToFeatures, store.StoredFeature{ID: "BAD", Feature: []byte(`{not json`)})
	return r, err
}

// Without a database the reads answer 503 reads_unavailable.
func TestReadsWithoutADatabase(t *testing.T) {
	f := newFixture(t, &Server{}, Options{})
	for _, target := range []string{"/v1/zones", "/v1/zones/versions", "/v1/zones/versions/1", "/v1/changes", "/public/v1/zones"} {
		req := httptest.NewRequest(http.MethodGet, target, http.NoBody)
		rec := f.do(req)
		if p := decodeProblem(t, rec); rec.Code != 503 || p.Type != ProblemTypeBase+SlugReadsUnavailable {
			t.Errorf("%s = %d %s", target, rec.Code, rec.Body.String())
		}
		conform(t, req, rec)
	}
	for _, target := range []string{"/v1/zones", "/public/v1/zones"} {
		if rec := f.do(httptest.NewRequest(http.MethodHead, target, http.NoBody)); rec.Code != 503 {
			t.Errorf("HEAD %s = %d", target, rec.Code)
		}
	}
}

func TestAcceptsGzip(t *testing.T) {
	for v, want := range map[string]bool{
		"gzip": true, "GZIP": true, "deflate, gzip": true, "*": true, "gzip;q=0": false, "gzip; q=0.0": false,
		"identity": false, "": false, "gzip;q=0.001": true, "*;q=0": false, "gzip;q=x": true,
	} {
		if got := acceptsGzip(&v); got != want {
			t.Errorf("%q: %v", v, got)
		}
	}
	if acceptsGzip(nil) {
		t.Error("absent header takes gzip")
	}
}

// displayRing is the outer ring of a feature's cis_display_geometry, or
// nil when the copy carries none.
func displayRing(t testing.TB, f doc) []core.LatLon {
	t.Helper()
	ext, _ := f["properties"].(doc)["extendedProperties"].(doc)
	g, _ := ext[outline.Member].(doc)
	if g == nil {
		return nil
	}
	if g["type"] != "Polygon" {
		t.Fatalf("cis_display_geometry type %v", g["type"])
	}
	rings := g["coordinates"].([]any)
	var out []core.LatLon
	for _, p := range rings[0].([]any) {
		pos := p.([]any)
		out = append(out, core.LatLon{LatDeg: pos[1].(float64), LonDeg: pos[0].(float64)})
	}
	return out
}

// A filtered read draws each circle as its geodesic outline: 64
// vertices, closed, each at the published radius within 5 mm by
// uspace-core's Vincenty inverse. Polygons get no member, the stored row
// and the unfiltered (published, signed) bytes never carry it.
func TestReadDrawsCircles(t *testing.T) {
	h := newPubHarness(t, nil)
	if rec := h.put("zones", jsonBytes(t, zonesDoc(t))); rec.Code != 201 {
		t.Fatalf("publish = %d %s", rec.Code, rec.Body.String())
	}
	circles := map[string]struct {
		centre  core.LatLon
		radiusM float64
	}{
		"TSD001": {core.LatLon{LatDeg: 41.7151, LonDeg: 44.8271}, 1500},
		"TSN001": {core.LatLon{LatDeg: 41.75, LonDeg: 44.9}, 250.5},
	}
	for _, target := range []string{
		"/v1/zones?applies_at=" + url.QueryEscape(winterMonday),
		"/v1/zones?bbox=44.6,41.6,45.0,41.9",
		"/v1/zones?at=" + url.QueryEscape(winterMonday),
		"/public/v1/zones?applies_at=" + url.QueryEscape(winterMonday),
	} {
		rec := h.read(http.MethodGet, target)
		_, byID := collection(t, rec)
		if rec.Code != 200 {
			t.Fatalf("%s = %d", target, rec.Code)
		}
		for id, f := range byID {
			ring := displayRing(t, f)
			c, isCircle := circles[id]
			if !isCircle {
				if ring != nil {
					t.Errorf("%s: polygon %s carries %s", target, id, outline.Member)
				}
				continue
			}
			if len(ring) != outline.Vertices+1 || ring[0] != ring[outline.Vertices] {
				t.Fatalf("%s: %s ring of %d positions, closed %v", target, id, len(ring), ring[0] == ring[len(ring)-1])
			}
			for i, p := range ring {
				d, err := geodesy.DistanceM(c.centre, p)
				if err != nil || math.Abs(d-c.radiusM) > 0.005 {
					t.Errorf("%s: %s vertex %d at %.4f m, want %v m (%v)", target, id, i, d, c.radiusM, err)
				}
			}
		}
	}
	_, all := collection(t, h.read(http.MethodGet, "/v1/zones"))
	for id, f := range all {
		if displayRing(t, f) != nil {
			t.Errorf("unfiltered read: %s carries %s", id, outline.Member)
		}
	}
	for _, row := range h.fake.current[publication.DatasetZones] {
		if bytes.Contains(row.Canonical, []byte(outline.Member)) {
			t.Error("the stored row carries the outline")
		}
	}
}

// A circle the CISP cannot draw (its centre within a degree of the pole)
// is served whole without the member and counted, beside one it draws.
func TestReadCountsACircleItCannotDraw(t *testing.T) {
	h := newPubHarness(t, nil)
	d := zonesDoc(t)
	g := feats(d)[3].(doc)["geometry"].(doc) // TSN001
	g["coordinates"] = []any{15.0, 89.5}
	if rec := h.put("zones", jsonBytes(t, d)); rec.Code != 201 {
		t.Fatalf("publish = %d %s", rec.Code, rec.Body.String())
	}
	before := h.counter(readsComponent, CounterOutlineFailed)
	_, byID := collection(t, h.read(http.MethodGet, "/v1/zones?applies_at="+url.QueryEscape(winterMonday)))
	if _, ok := byID["TSN001"]; !ok || displayRing(t, byID["TSN001"]) != nil {
		t.Errorf("polar circle: present %v, outline %v", ok, displayRing(t, byID["TSN001"]))
	}
	if displayRing(t, byID["TSD001"]) == nil {
		t.Error("the drawable circle beside it has no outline")
	}
	if got := h.counter(readsComponent, CounterOutlineFailed) - before; got != 1 {
		t.Errorf("outline_failed counted %d, want 1", got)
	}
}
