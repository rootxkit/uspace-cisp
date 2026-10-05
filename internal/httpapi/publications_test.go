package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-cisp/internal/auth"
	"github.com/rootxkit/uspace-cisp/internal/dataset"
	"github.com/rootxkit/uspace-cisp/internal/httpapi/gen"
	"github.com/rootxkit/uspace-cisp/internal/jws"
	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/store"
)

func decodeResult(t *testing.T, rec *httptest.ResponseRecorder) gen.PublicationResult {
	t.Helper()
	var r gen.PublicationResult
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatalf("%v: %s", err, rec.Body.String())
	}
	return r
}

// A zones publication: 201 with the version, counts and ids; the same
// body again 200 unchanged with no new version; one feature changed 201
// with that id in changed[]. The bytes stored are the bytes received.
func TestPutPublicationAcceptedUnchangedChanged(t *testing.T) {
	h := newPubHarness(t, nil)
	body := jsonBytes(t, zonesDoc(t))
	rec := h.put("zones", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("PUT = %d %s", rec.Code, rec.Body.String())
	}
	r := decodeResult(t, rec)
	if r.Version != 1 || r.Etag != `"zones:1"` || rec.Header().Get("ETag") != `"zones:1"` || *r.FeatureCount != 4 || *r.AddedCount != 4 ||
		!reflect.DeepEqual(*r.Added, []string{"TSC001", "TSD001", "TSN001", "TSR001"}) || len(*r.Changed) != 0 || r.Unchanged != nil || r.Truncated != nil {
		t.Fatalf("result %s", rec.Body.String())
	}
	if !bytes.Equal(h.fake.bodies["zones"][1], body) || h.fake.signed != 1 {
		t.Error("the stored bytes are not the bytes received, or the snapshot was not signed")
	}
	if h.counter("zones", CounterPublicationsAccepted) != 1 {
		t.Error("publications_accepted not counted")
	}
	if a := h.fake.attempts; len(a) != 1 || a[0].Outcome != store.OutcomeAccepted || *a[0].PublicationID != "PUB0" || a[0].Bytes != int64(len(body)) {
		t.Errorf("accepted attempt %+v", a)
	}
	v := h.fake.versions[0]
	if v.ContentType != "application/geo+json" || *v.SignatureKID != publisherKID || v.PublisherClientID != authorityID || string(v.Warnings) != "[]" {
		t.Errorf("version %+v", v)
	}

	// Idempotent re-PUT, also re-spaced: 200, unchanged, no version.
	again := append([]byte("\n"), body...)
	rec = h.put("zones", again)
	r = decodeResult(t, rec)
	if rec.Code != http.StatusOK || r.Unchanged == nil || !*r.Unchanged || r.Version != 1 || rec.Header().Get("ETag") != `"zones:1"` {
		t.Fatalf("re-PUT = %d %s", rec.Code, rec.Body.String())
	}
	if h.fake.version["zones"] != 1 || h.counter("zones", CounterPublicationsUnchanged) != 1 {
		t.Error("an unchanged publication made a version or was not counted")
	}

	// One feature changed: 201 with that id in changed[].
	d := zonesDoc(t)
	fprops(d, 1)["restrictionConditions"] = "Authorisation by the authority, 48 h ahead"
	rec = h.put("zones", jsonBytes(t, d))
	r = decodeResult(t, rec)
	if rec.Code != http.StatusCreated || r.Version != 2 || !reflect.DeepEqual(*r.Changed, []string{"TSR001"}) || len(*r.Added) != 0 || len(*r.Removed) != 0 {
		t.Fatalf("changed = %d %s", rec.Code, rec.Body.String())
	}
	// And one removed.
	d["features"] = feats(d)[:3]
	if r := decodeResult(t, h.put("zones", jsonBytes(t, d))); r.Version != 3 || !reflect.DeepEqual(*r.Removed, []string{"TSN001"}) {
		t.Errorf("removed = %+v", r)
	}
}

// If-Match: absent 428, stale 412 with the current ETag, current 201.
func TestPutPublicationIfMatch(t *testing.T) {
	h := newPubHarness(t, nil)
	body := jsonBytes(t, zonesDoc(t))

	req := h.putReq("zones", body, "")
	rec := h.do(req)
	conformPut(t, req, body, rec)
	p := decodeProblem(t, rec)
	if rec.Code != http.StatusPreconditionRequired || p.Type != ProblemTypeBase+SlugPreconditionRequired || !hasProblem(p, "If-Match", "is required") {
		t.Fatalf("absent = %d %s", rec.Code, rec.Body.String())
	}

	req = h.putReq("zones", body, `"zones:7"`)
	rec = h.do(req)
	conformPut(t, req, body, rec)
	p = decodeProblem(t, rec)
	if rec.Code != http.StatusPreconditionFailed || rec.Header().Get("ETag") != `"zones:0"` || !hasProblem(p, "If-Match", `the current version is "zones:0"`) {
		t.Fatalf("stale = %d %v %s", rec.Code, rec.Header(), rec.Body.String())
	}
	if len(h.fake.attempts) != 0 || h.fake.version["zones"] != 0 {
		t.Error("a precondition failure was stored")
	}

	req = h.putReq("zones", body, `"zones:0"`)
	if rec := h.do(req); rec.Code != http.StatusCreated {
		t.Fatalf("current = %d %s", rec.Code, rec.Body.String())
	}
}

// The race the If-Match check cannot see: the store's check under the
// lock answers 412 with the version that won.
func TestPutPublicationVersionMismatchUnderTheLock(t *testing.T) {
	h := newPubHarness(t, nil)
	h.fake.beforePublish = func(f *fakeStore) { f.version["zones"] = 5 } // another publisher won
	rec := h.put("zones", jsonBytes(t, zonesDoc(t)))
	if p := decodeProblem(t, rec); rec.Code != http.StatusPreconditionFailed || rec.Header().Get("ETag") != `"zones:5"` || !hasProblem(p, "If-Match", `"zones:5"`) {
		t.Fatalf("= %d %v %s", rec.Code, rec.Header(), rec.Body.String())
	}
	if len(h.fake.attempts) != 0 {
		t.Error("a lost race was recorded as an attempt")
	}
}

// The unsigned-and-invalid body is refused naming only the signature:
// nothing reads it, nothing is recorded (WP-2 safety note). The same
// invalid body signed reaches validation and is refused for its content.
func TestPutPublicationSignatureFirst(t *testing.T) {
	h := newPubHarness(t, nil)
	bad := []byte(`{"type":"FeatureCollection","features":[{"broken":`)
	for name, sig := range map[string]string{"absent": "", "not a JWS": "x..y", "over another body": h.sign([]byte(`{}`))} {
		t.Run(name, func(t *testing.T) {
			req := h.putReq("zones", bad, `"zones:0"`)
			if sig == "" {
				req.Header.Del(jws.HeaderSignature)
			} else {
				req.Header.Set(jws.HeaderSignature, sig)
			}
			rec := h.do(req)
			conformResponse(t, req, rec)
			p := decodeProblem(t, rec)
			if rec.Code != http.StatusForbidden || p.Type != ProblemTypeBase+jws.SlugSignature || len(p.Errors) != 1 {
				t.Fatalf("= %d %s", rec.Code, rec.Body.String())
			}
			if f := p.Errors[0].Field; strings.Contains(f, "features") || strings.HasPrefix(f, "$") {
				t.Errorf("the refusal names the body: %s", f)
			}
		})
	}
	if len(h.fake.attempts) != 0 {
		t.Fatalf("an unsigned body was recorded: %+v", h.fake.attempts)
	}
	// Signed, the same bytes are refused for what they are.
	req := h.putReq("zones", bad, `"zones:0"`)
	rec := h.do(req)
	conformResponse(t, req, rec)
	if p := decodeProblem(t, rec); rec.Code != http.StatusBadRequest || p.Type != ProblemTypeBase+SlugPublicationRefused || !hasProblem(p, "$", "") {
		t.Fatalf("signed invalid = %d %s", rec.Code, rec.Body.String())
	}
}

// T4 at the route: no token, a token without the dataset's scope, the
// right scope from another client, a foreign content type; each beside
// the accepted request.
func TestPutPublicationAuthPairs(t *testing.T) {
	h := newPubHarness(t, nil)
	body := jsonBytes(t, zonesDoc(t))
	cases := []struct {
		name   string
		edit   func(r *http.Request)
		status int
		slug   string
	}{
		{"no token", func(r *http.Request) { r.Header.Del("Authorization") }, 401, auth.SlugUnauthenticated},
		{"uspace scope on zones", func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer "+h.token(authorityID, auth.ScopePublishUSpace))
		}, 403, auth.SlugForbidden},
		{"zones scope, not the authority", func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer "+h.token(usspID, auth.ScopePublishZones))
		}, 403, auth.SlugNotAPublisher},
		{"text/plain", func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, 415, SlugUnsupportedMediaType},
		{"no content type", func(r *http.Request) { r.Header.Del("Content-Type") }, 415, SlugUnsupportedMediaType},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := h.putReq("zones", body, `"zones:0"`)
			c.edit(req)
			rec := h.do(req)
			conformResponse(t, req, rec)
			if p := decodeProblem(t, rec); rec.Code != c.status || p.Type != ProblemTypeBase+c.slug {
				t.Fatalf("= %d %s", rec.Code, rec.Body.String())
			}
		})
	}
	req := h.putReq("zones", body, `"zones:0"`)
	req.Header.Set("Authorization", "Bearer "+h.token(authorityID, auth.ScopePublishZones))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	rec := h.do(req)
	conformPut(t, req, body, rec)
	if rec.Code != http.StatusCreated || h.fake.versions[0].ContentType != "application/json" {
		t.Fatalf("the accepted twin = %d %s", rec.Code, rec.Body.String())
	}
}

// E-01 pairs through the API for each dataset rule: the refusal is 400
// with the path, recorded as a refused attempt and counted; the twin
// that differs in one thing is 201.
func TestPutPublicationRefusalPairs(t *testing.T) {
	cases := []struct {
		name, ds      string
		bad, good     func(t *testing.T) []byte
		field, phrase string
	}{
		{"USPACE in zones", "zones",
			func(t *testing.T) []byte { d := zonesDoc(t); fprops(d, 2)["type"] = "USPACE"; return jsonBytes(t, d) },
			func(t *testing.T) []byte { return jsonBytes(t, zonesDoc(t)) },
			"features[2].properties.type", "uspace_airspace dataset"},
		{"DAR in zones", "zones",
			func(t *testing.T) []byte {
				d := zonesDoc(t)
				fprops(d, 0)["reason"] = []any{"DAR", "EMERGENCY"}
				return jsonBytes(t, d)
			},
			func(t *testing.T) []byte { return jsonBytes(t, zonesDoc(t)) },
			"features[0].properties.reason[0]", "ANSP"},
		{"duplicate identifier within the publication", "zones",
			func(t *testing.T) []byte {
				d := zonesDoc(t)
				fprops(d, 3)["identifier"] = "TSD001"
				return jsonBytes(t, d)
			},
			func(t *testing.T) []byte {
				d := zonesDoc(t)
				fprops(d, 3)["identifier"] = "TSN002"
				return jsonBytes(t, d)
			},
			"features[3].properties.identifier", ""},
		{"missing requirements block", "uspace_airspace",
			func(t *testing.T) []byte {
				d := uspaceDoc(t)
				delete(fprops(d, 0)["extendedProperties"].(doc), dataset.RequirementsMember)
				return jsonBytes(t, d)
			},
			func(t *testing.T) []byte { return jsonBytes(t, uspaceDoc(t)) },
			"features[0].properties.extendedProperties.uspace_requirements", "is required"},
		{"adjacent naming an identifier not in the publication", "uspace_airspace",
			func(t *testing.T) []byte {
				d := uspaceDoc(t)
				fprops(d, 0)["extendedProperties"].(doc)["uspace_requirements"].(doc)["adjacent"] = []any{"TSU404"}
				return jsonBytes(t, d)
			},
			func(t *testing.T) []byte {
				d := uspaceDoc(t)
				fprops(d, 0)["extendedProperties"].(doc)["uspace_requirements"].(doc)["adjacent"] = []any{"TSU001"}
				return jsonBytes(t, d)
			},
			"features[0].properties.extendedProperties.uspace_requirements.adjacent[0]", "not an identifier of this publication"},
		{"USSP list with a duplicate ussp_id", "ussp_list",
			func(t *testing.T) []byte {
				return bytes.Replace(usspListBody(t), []byte(`"USSP-B2"`), []byte(`"USSP-DEV"`), 1)
			},
			func(t *testing.T) []byte { return usspListBody(t) },
			"ussps[1].ussp_id", "repeats ussps[0].ussp_id"},
		{"USSP list base_url with userinfo", "ussp_list",
			func(t *testing.T) []byte {
				return bytes.Replace(usspListBody(t), []byte(`"https://ussp.example.test"`), []byte(`"https://admin:pw@ussp.example.test"`), 1)
			},
			func(t *testing.T) []byte { return usspListBody(t) },
			"ussps[0].base_url", "userinfo"},
		{"USSP list with an unknown member", "ussp_list",
			func(t *testing.T) []byte {
				return bytes.Replace(usspListBody(t), []byte(`"ussps":`), []byte(`"note":"x","ussps":`), 1)
			},
			func(t *testing.T) []byte { return usspListBody(t) },
			"note", "unknown member"},
		{"USSP list of 201 entries", "ussp_list",
			func(t *testing.T) []byte { return usspList(t, dataset.MaxUssps+1) },
			func(t *testing.T) []byte { return usspList(t, dataset.MaxUssps) },
			"ussps", "at most 200"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newPubHarness(t, nil)
			bad := c.bad(t)
			rec := h.put(c.ds, bad)
			p := decodeProblem(t, rec)
			if rec.Code != http.StatusBadRequest || p.Type != ProblemTypeBase+SlugPublicationRefused || !hasProblem(p, c.field, c.phrase) {
				t.Fatalf("refusal = %d %s", rec.Code, rec.Body.String())
			}
			refused := h.fake.refused()
			if len(refused) != 1 || refused[0].Dataset != publication.Dataset(c.ds) || refused[0].PublisherClientID != authorityID || len(refused[0].Problems) == 0 {
				t.Fatalf("attempt %+v", refused)
			}
			if h.counter(c.ds, CounterPublicationsRefused) != 1 || h.fake.version[publication.Dataset(c.ds)] != 0 {
				t.Error("refusal not counted, or a version was made")
			}
			if rec := h.put(c.ds, c.good(t)); rec.Code != http.StatusCreated {
				t.Fatalf("twin = %d %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func usspList(t *testing.T, n int) []byte {
	t.Helper()
	var d doc
	if err := json.Unmarshal(usspListBody(t), &d); err != nil {
		t.Fatal(err)
	}
	tmpl := jsonBytes(t, d["ussps"].([]any)[0])
	list := make([]any, n)
	for i := range list {
		var u doc
		_ = json.Unmarshal(tmpl, &u)
		u["ussp_id"] = "U" + strconv.Itoa(i)
		list[i] = u
	}
	d["ussps"] = list
	return jsonBytes(t, d)
}

// D8 through the API: an identifier the current uspace_airspace holds is
// refused in zones, naming the feature and the dataset; a free one is
// accepted. And the store's unique index, the backstop, is a refusal
// too.
func TestPutPublicationIdentifierReservedByAnotherDataset(t *testing.T) {
	h := newPubHarness(t, nil)
	if rec := h.put("uspace_airspace", jsonBytes(t, uspaceDoc(t))); rec.Code != http.StatusCreated {
		t.Fatalf("uspace = %d %s", rec.Code, rec.Body.String())
	}
	d := zonesDoc(t)
	fprops(d, 3)["identifier"] = "TSU001"
	rec := h.put("zones", jsonBytes(t, d))
	p := decodeProblem(t, rec)
	if rec.Code != http.StatusBadRequest || !hasProblem(p, "features[3].properties.identifier", `"TSU001" is held by the current version of uspace_airspace`) {
		t.Fatalf("reserved = %d %s", rec.Code, rec.Body.String())
	}
	fprops(d, 3)["identifier"] = "TSN001"
	if rec := h.put("zones", jsonBytes(t, d)); rec.Code != http.StatusCreated {
		t.Fatalf("free = %d %s", rec.Code, rec.Body.String())
	}

	// The backstop (a publication that raced the lookup).
	fs := newFakeStore()
	h = newPubHarness(t, fs)
	fs.current["restrictions"] = []publication.FeatureRow{{ID: "TSD001"}}
	h.pubs.Store = noReserve{fs}
	rec = h.put("zones", jsonBytes(t, zonesDoc(t)))
	if p := decodeProblem(t, rec); rec.Code != http.StatusBadRequest || !hasProblem(p, "features", "held by the current version of another dataset") {
		t.Fatalf("backstop = %d %s", rec.Code, rec.Body.String())
	}
}

// noReserve hides every reservation, as a concurrent publication would.
type noReserve struct{ *fakeStore }

func (noReserve) Reserved(context.Context, publication.Dataset, []string) (map[string]publication.Dataset, error) {
	return map[string]publication.Dataset{}, nil
}

// Warnings (E-02): an open-ended sunrise/sunset schedule is accepted with
// a warning naming the feature, stored with the version and read back
// from the history.
func TestPutPublicationWarningsReadBack(t *testing.T) {
	h := newPubHarness(t, nil)
	d := zonesDoc(t)
	delete(fprops(d, 0)["limitedApplicability"].([]any)[0].(doc), "endDateTime")
	rec := h.put("zones", jsonBytes(t, d))
	r := decodeResult(t, rec)
	if rec.Code != http.StatusCreated || r.Warnings == nil || len(*r.Warnings) != 1 || !strings.Contains((*r.Warnings)[0].Reason, `"TSD001"`) {
		t.Fatalf("PUT = %d %s", rec.Code, rec.Body.String())
	}
	rec = h.get("/v1/publications/zones", h.token(usspID, auth.ScopeRead))
	var list gen.PublicationVersionList
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || rec.Code != 200 || len(list.Versions) != 1 {
		t.Fatalf("GET = %d %s", rec.Code, rec.Body.String())
	}
	w := list.Versions[0].Warnings
	if len(w) != 1 || w[0].Field != "features[0].properties.limitedApplicability[0]" || !strings.Contains(w[0].Reason, "ed318.Applies") {
		t.Errorf("warnings read back %+v", w)
	}
	t.Logf("warning read back: %s: %s", w[0].Field, w[0].Reason)
}

// The other datasets and their bodies: uspace_airspace with its block and
// the USSP list are 201; the USSP list has no rows.
func TestPutPublicationUSpaceAndUsspList(t *testing.T) {
	h := newPubHarness(t, nil)
	rec := h.put("uspace_airspace", jsonBytes(t, uspaceDoc(t)))
	if r := decodeResult(t, rec); rec.Code != http.StatusCreated || *r.FeatureCount != 1 {
		t.Fatalf("uspace = %d %s", rec.Code, rec.Body.String())
	}
	body := usspListBody(t)
	req := h.putReq("ussp_list", body, `"ussp_list:0"`)
	req.Header.Set("Content-Type", "application/json")
	rec = h.do(req)
	conformPut(t, req, body, rec)
	if r := decodeResult(t, rec); rec.Code != http.StatusCreated || *r.FeatureCount != 0 || r.Dataset != "ussp_list" {
		t.Fatalf("ussp_list = %d %s", rec.Code, rec.Body.String())
	}
	if !bytes.Equal(h.fake.bodies["ussp_list"][1], body) {
		t.Error("the list was not stored as received")
	}
}

// Problems past the cap: 100 listed, truncated true, the count in detail,
// and the attempt keeps the 100 with the count of the rest (E-10).
func TestPutPublicationProblemsTruncated(t *testing.T) {
	h := newPubHarness(t, nil)
	d := zonesDoc(t)
	tmpl := jsonBytes(t, feats(d)[3])
	var list []any
	for i := range 130 {
		var f doc
		_ = json.Unmarshal(tmpl, &f)
		f["properties"].(doc)["identifier"] = "U" + strconv.Itoa(i)
		f["properties"].(doc)["type"] = "USPACE"
		list = append(list, f)
	}
	d["features"] = list
	rec := h.put("zones", jsonBytes(t, d))
	p := decodeProblem(t, rec)
	if rec.Code != 400 || len(p.Errors) != 100 || p.Truncated == nil || !*p.Truncated || !strings.Contains(*p.Detail, "130 problems") || !strings.Contains(*p.Detail, "30 not listed") {
		t.Fatalf("= %d errors %d %v %s", rec.Code, len(problemFields(p)), p.Truncated, *p.Detail)
	}
	if a := h.fake.refused()[0]; len(a.Problems) != 100 || a.Truncated != 30 {
		t.Errorf("attempt keeps %d with %d more", len(a.Problems), a.Truncated)
	}
	// Exactly at the cap: not truncated.
	d["features"] = list[:100]
	p = decodeProblem(t, h.put("zones", jsonBytes(t, d)))
	if p.Truncated != nil {
		t.Errorf("at the cap: truncated %v", *p.Truncated)
	}
}

// The reservation list itself is capped (E-10).
func TestReservedProblemsCapped(t *testing.T) {
	rows := make([]publication.FeatureRow, 150)
	reserved := map[string]publication.Dataset{}
	for i := range rows {
		rows[i].ID = "Z" + strconv.Itoa(i)
		reserved[rows[i].ID] = publication.DatasetUSpaceAirspace
	}
	p := reservedProblems(rows, reserved)
	if len(p.List) != MaxProblemErrors || p.Truncated != 50 {
		t.Errorf("%d listed, %d more", len(p.List), p.Truncated)
	}
	if reservedProblems(rows, nil) != nil {
		t.Error("no reservation is a problem")
	}
}

// added, changed and removed are capped at 1000 each with the count of
// the rest (E-10); at the cap nothing is truncated.
func TestResultListsCapped(t *testing.T) {
	ids := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = "Z" + strconv.Itoa(i)
		}
		return out
	}
	res := store.PublishResult{Version: 2, ETag: `"zones:2"`, Diff: publication.Diff{Added: ids(1001), Changed: ids(1000), Removed: ids(3)}}
	r := resultOf("zones", res, time.Now(), 2001, nil)
	if len(*r.Added) != 1000 || len(*r.Changed) != 1000 || r.Truncated == nil || r.Truncated.Added != 1 || r.Truncated.Changed != 0 || *r.AddedCount != 1001 {
		t.Errorf("capped %+v", r.Truncated)
	}
	res.Diff.Added = ids(1000)
	if r := resultOf("zones", res, time.Now(), 2000, nil); r.Truncated != nil {
		t.Errorf("at the cap: %+v", r.Truncated)
	}
}

// What the intake cannot do says so: no database 503, no signing key 503,
// the database gone 503 with Retry-After, another store error 500, an
// unknown dataset 404.
func TestPutPublicationUnavailableAndUnknown(t *testing.T) {
	h := newPubHarness(t, nil, func(_ *Publications, s *Server) { s.Publications = nil })
	rec := h.put("zones", jsonBytes(t, zonesDoc(t)))
	if p := decodeProblem(t, rec); rec.Code != 503 || p.Type != ProblemTypeBase+SlugIntakeUnavailable {
		t.Fatalf("no database = %d %s", rec.Code, rec.Body.String())
	}
	for _, path := range []string{"/v1/publications/zones", "/v1/publications/zones/attempts"} {
		if rec := h.get(path, h.authorityToken()); rec.Code != 503 {
			t.Errorf("%s without a database = %d", path, rec.Code)
		}
	}

	h = newPubHarness(t, nil, func(p *Publications, _ *Server) { p.Signer = nil })
	if p := decodeProblem(t, h.put("zones", jsonBytes(t, zonesDoc(t)))); p.Type != ProblemTypeBase+SlugSigningUnavailable {
		t.Errorf("no signing key: %+v", p)
	}

	h = newPubHarness(t, nil)
	h.fake.down = true
	req := h.putReq("zones", jsonBytes(t, zonesDoc(t)), `"zones:0"`)
	rec = h.do(req)
	if p := decodeProblem(t, rec); rec.Code != 503 || p.Type != ProblemTypeBase+SlugDatabaseUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("database down = %d %v %s", rec.Code, rec.Header(), rec.Body.String())
	}
	conformResponse(t, req, rec)
	for _, path := range []string{"/v1/publications/zones", "/v1/publications/zones/attempts"} {
		if rec := h.get(path, h.authorityToken()); rec.Code != 503 || rec.Header().Get("Retry-After") == "" {
			t.Errorf("%s database down = %d", path, rec.Code)
		}
	}
	h.fake.down = false
	// Not connectivity: a 500 internal problem, logged with the dataset
	// and the client, never a 503 that invites a retry.
	for name, fault := range map[string]error{
		"an unclassified error": errors.New("closed pool"),
		"a database refusal":    &pgconn.PgError{Code: "42P01", Message: "relation does not exist"},
	} {
		h.logs.Reset()
		h.fake.failWith = fault
		req := h.putReq("zones", jsonBytes(t, zonesDoc(t)), `"zones:0"`)
		rec := h.do(req)
		conformResponse(t, req, rec)
		if p := decodeProblem(t, rec); rec.Code != 500 || p.Type != ProblemTypeBase+SlugInternal || rec.Header().Get("Retry-After") != "" {
			t.Errorf("%s = %d %s", name, rec.Code, rec.Body.String())
		}
		logs := h.logs.String()
		if !strings.Contains(logs, `"msg":"store error"`) || !strings.Contains(logs, `"dataset":"zones"`) || !strings.Contains(logs, `"client_id":"authority-01"`) || !strings.Contains(logs, fault.Error()) {
			t.Errorf("%s not logged with its context: %s", name, logs)
		}
	}
	h.fake.failWith = nil
	h.fake.down = true
	h.fake.beforePublish = nil
	if _, rec := h.heartbeat(h.token(authorityID, auth.ScopePublishZones), `{"sent_at":"2026-10-02T10:00:00Z"}`); rec.Code != 503 {
		t.Errorf("heartbeat with the database down = %d", rec.Code)
	}
	h.fake.down = false

	// restrictions is not published here; an unknown dataset neither.
	h = newPubHarness(t, nil)
	for _, ds := range []string{"restrictions", "zonez"} {
		req := h.putReq(ds, []byte(`{}`), `"x:0"`)
		rec := h.do(req)
		if p := decodeProblem(t, rec); rec.Code != 404 || p.Type != ProblemTypeBase+SlugNotFound {
			t.Errorf("PUT %s = %d %s", ds, rec.Code, rec.Body.String())
		}
	}
}

// A failed attempt record is counted and logged; the answer stands.
func TestPutPublicationAttemptRecordFailure(t *testing.T) {
	h := newPubHarness(t, nil)
	h.fake.attemptFn = func(store.Attempt) error { return errors.New("insert attempt: connection reset") }
	if rec := h.put("zones", jsonBytes(t, zonesDoc(t))); rec.Code != http.StatusCreated {
		t.Fatalf("= %d", rec.Code)
	}
	d := zonesDoc(t)
	fprops(d, 0)["type"] = "USPACE"
	if rec := h.put("zones", jsonBytes(t, d)); rec.Code != http.StatusBadRequest {
		t.Fatalf("= %d", rec.Code)
	}
	if h.counter("zones", CounterAttemptRecordFailed) != 2 || !strings.Contains(h.logs.String(), "publication attempt not recorded") {
		t.Errorf("not counted or logged: %d %s", h.counter("zones", CounterAttemptRecordFailed), h.logs.String())
	}
}

// A field error from the store's own rows (publication.Rows) is a
// refusal, recorded.
func TestPutPublicationStoreFieldErrorIsARefusal(t *testing.T) {
	h := newPubHarness(t, nil)
	h.fake.failWith = core.Fieldf("features", "has 50001 features; at most 50000 per publication")
	rec := h.put("zones", jsonBytes(t, zonesDoc(t)))
	if p := decodeProblem(t, rec); rec.Code != 400 || !hasProblem(p, "features", "at most 50000") {
		t.Fatalf("= %d %s", rec.Code, rec.Body.String())
	}
}
