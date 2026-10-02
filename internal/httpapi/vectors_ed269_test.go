package httpapi

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3filter"
	coreauth "github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/ed269"
	"github.com/rootxkit/uspace-core/ed318"
	"github.com/rootxkit/uspace-core/vectors"

	"github.com/rootxkit/uspace-cisp/internal/authtest"
	"github.com/rootxkit/uspace-cisp/internal/dataset"
	"github.com/rootxkit/uspace-cisp/internal/httpapi/gen"
	"github.com/rootxkit/uspace-cisp/internal/jws"
	"github.com/rootxkit/uspace-cisp/internal/publication"
)

// kin-openapi reads an ED-269 document as JSON (the spec's
// ED269Document is an object; uspace-core validates it).
func init() {
	openapi3filter.RegisterBodyDecoder(dataset.MediaTypeED269, openapi3filter.JSONBodyDecoder)
}

// putED269 sends a signed ED-269 PUT to zones with the current ETag and
// query (such as "?lang=en-GB"), conformance checked: the whole exchange
// when the body is a JSON object (the spec's ED269Document), the answer
// alone otherwise (the spec cannot describe bytes that are not JSON, and
// the server must still answer them by the spec).
func (h *pubHarness) putED269(body []byte, query string) *httptest.ResponseRecorder {
	h.t.Helper()
	cur := currentOf(h.t.(*testing.T), h, publication.DatasetZones)
	req := h.putReq("zones"+query, body, publication.ETag(publication.DatasetZones, cur))
	req.Header.Set("Content-Type", dataset.MediaTypeED269)
	rec := h.do(req)
	if isJSONObject(body) {
		conformPut(h.t, req, body, rec)
	} else {
		conformResponse(h.t, req, rec)
	}
	return rec
}

func isJSONObject(b []byte) bool {
	var m map[string]any
	return json.Unmarshal(b, &m) == nil
}

// emptyZones publishes an empty zones collection, so that the next
// publication is a new version even when it equals an earlier one.
func emptyZones(t *testing.T, h *pubHarness) {
	t.Helper()
	if rec := h.put("zones", []byte(emptyCollection)); rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Fatalf("emptying zones = %d %s", rec.Code, rec.Body.String())
	}
}

// ed269CaseBody is the bytes a vector case feeds to the bridge: the
// document as it is, a zone in a one-zone document, the BOM file or the
// raw bytes decoded.
func ed269CaseBody(t *testing.T, raw json.RawMessage) []byte {
	t.Helper()
	var in struct {
		Document         json.RawMessage `json:"document"`
		Zone             json.RawMessage `json:"zone"`
		DocumentBOM64    string          `json:"document_utf8_with_bom_base64"`
		Bytes64          string          `json:"bytes_base64"`
		BytesDescription string          `json:"bytes_description"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		t.Fatal(err)
	}
	switch {
	case in.Document != nil:
		return in.Document
	case in.Zone != nil:
		return []byte(`{"features":[` + string(in.Zone) + `]}`)
	case in.DocumentBOM64 != "" || in.Bytes64 != "":
		b, err := base64.StdEncoding.DecodeString(in.DocumentBOM64 + in.Bytes64)
		if err != nil {
			t.Fatal(err)
		}
		return b
	case in.BytesDescription == "100000 '[' then 100000 ']'":
		return append(bytes.Repeat([]byte("["), 100000), bytes.Repeat([]byte("]"), 100000)...)
	}
	t.Fatalf("unknown input shape %s", raw)
	return nil
}

// unmappableED269 are the ed269_parse.json files ed269.Parse accepts
// and ED-318 cannot hold: the valid file's TST003 has no zone authority,
// which ED-318 requires (core refuses it by name; the CISP never fills
// one in). They are refused whole, and their other zones are published
// without it.
var unmappableED269 = map[string]string{
	"valid-file-round-trips-unchanged": "features[2].zoneAuthority",
	"list-wrapper-and-byte-order-mark": "features[2].zoneAuthority",
}

// TestVectorsED269Parse runs every ed269_parse.json case the cisp owns
// (54) through PUT /v1/publications/zones with Content-Type
// application/vnd.ed269+json:
//
//   - a refusal is 400 publication_refused whose errors[] hold the
//     vector's path suffix and phrase (or its listed problems), recorded
//     as a refused attempt, and makes no version;
//   - an accepted file that maps is 201 mapped_from ed269, and reads back
//     from GET /v1/zones/versions/{v}?format=ed269 equal to the input by
//     value (both through ed269.Parse and ed269.Export; byte equality is
//     not promised across the mapping, which writes RFC 3339 clock times
//     and core's member order), and verbatim from &source=true;
//   - an accepted file ED-318 cannot hold is 400 naming core's reason,
//     and the same file without the zone that does not map is published
//     and read back as above (the C-M1 round trip).
func TestVectorsED269Parse(t *testing.T) {
	f := vectors.Load(t, "ed269_parse.json")
	h := newPubHarness(t, nil)
	ran, roundTrips := 0, 0
	f.RunOwned(t, "cisp", func(t *testing.T, c vectors.Case) {
		ran++
		body := ed269CaseBody(t, c.Input)
		var exp struct {
			Accepted    bool `json:"accepted"`
			MustInclude *struct {
				Field          string `json:"field"`
				FieldEndsWith  string `json:"field_endswith"`
				ReasonContains string `json:"reason_contains"`
			} `json:"must_include"`
			Problems []ed269.Problem `json:"problems"`
		}
		if err := json.Unmarshal(c.Expected, &exp); err != nil {
			t.Fatal(err)
		}
		emptyZones(t, h)
		if !exp.Accepted {
			p := ed269Refusal(t, h, body)
			switch m := exp.MustInclude; {
			case m != nil && m.Field != "":
				requireProblem(t, p, func(f string) bool { return f == m.Field }, m.ReasonContains)
			case m != nil:
				requireProblem(t, p, func(f string) bool { return strings.HasSuffix(f, m.FieldEndsWith) }, m.ReasonContains)
			default:
				if len(exp.Problems) == 0 {
					t.Fatal("a refusal case without must_include or problems")
				}
				for _, w := range exp.Problems {
					requireProblem(t, p, func(f string) bool { return f == w.Field }, w.Reason)
				}
			}
			return
		}
		if field, ok := unmappableED269[c.Name]; ok {
			p := ed269Refusal(t, h, body)
			requireProblem(t, p, func(f string) bool { return f == field }, "ED-318 requires at least one zone authority")
			body = withoutZone(t, body, "TST003")
			t.Logf("refused by core's mapping at %s; published without TST003", field)
			emptyZones(t, h)
		}
		ed269RoundTrip(t, h, body)
		roundTrips++
	})
	if ran != 54 {
		t.Errorf("%d cases ran; ed269_parse.json has 54 the cisp owns", ran)
	}
	t.Logf("%d ed269_parse cases ran through PUT; %d round-tripped through the mapping", ran, roundTrips)
}

// ed269Refusal PUTs body and requires 400 publication_refused, no new
// version and the refusal recorded as an attempt with the same problems.
func ed269Refusal(t *testing.T, h *pubHarness, body []byte) gen.Problem {
	t.Helper()
	before := currentOf(t, h, publication.DatasetZones)
	attempts := len(h.fake.refused())
	rec := h.putED269(body, "")
	p := decodeProblem(t, rec)
	if rec.Code != http.StatusBadRequest || p.Type != ProblemTypeBase+SlugPublicationRefused || p.Errors == nil {
		t.Fatalf("PUT = %d %s", rec.Code, rec.Body.String())
	}
	if currentOf(t, h, publication.DatasetZones) != before {
		t.Error("a refused publication made a version")
	}
	refused := h.fake.refused()
	if len(refused) != attempts+1 || len(refused[attempts].Problems) != len(*p.Errors) {
		t.Errorf("the refusal is not recorded with its %d problems", len(*p.Errors))
	}
	return p
}

func requireProblem(t *testing.T, p gen.Problem, field func(string) bool, phrase string) {
	t.Helper()
	for _, e := range *p.Errors {
		if field(e.Field) && strings.Contains(e.Reason, phrase) {
			return
		}
	}
	t.Fatalf("no problem with %q in %s", phrase, problemFields(p))
}

// withoutZone is body without the zone identifier (in features or in
// the UASZoneList wrapper), re-encoded without a byte order mark.
func withoutZone(t *testing.T, body []byte, identifier string) []byte {
	t.Helper()
	var d doc
	if err := json.Unmarshal(bytes.TrimPrefix(body, []byte("\xef\xbb\xbf")), &d); err != nil {
		t.Fatal(err)
	}
	key := "features"
	if _, ok := d[key]; !ok {
		key = "UASZoneList"
	}
	var keep []any
	for _, z := range d[key].([]any) {
		if z.(doc)["identifier"] != identifier {
			keep = append(keep, z)
		}
	}
	d[key] = keep
	return jsonBytes(t, d)
}

// sameED269Value reports whether two ED-269 documents are equal by value,
// as uspace-core's own mapping test compares them: the title, the
// description and every zone field equal, extendedProperties as JSON
// values, periods by their instants and clock windows (the mapping writes
// clock times in RFC 3339, so 08:00+04:00 returns as 08:00:00+04:00, the
// same time). The UASZoneList wrapper's formatVersion and createdAt are
// not carried by the mapping (core's FromED269) and are not compared.
func sameED269Value(t *testing.T, a, b []byte) bool {
	t.Helper()
	parse := func(raw []byte) *ed269.Document {
		d, probs := ed269.Parse(raw, ed269.Limits{})
		if probs != nil {
			t.Fatalf("not ED-269: %v\n%s", probs, raw)
		}
		return d
	}
	got, want := parse(a), parse(b)
	same := reflect.DeepEqual(got.Title, want.Title) && reflect.DeepEqual(got.Description, want.Description) &&
		len(got.Zones) == len(want.Zones)
	for i := 0; same && i < len(want.Zones); i++ {
		g, w := got.Zones[i], want.Zones[i]
		if !sameJSONValue(g.ExtendedProperties, w.ExtendedProperties) || !samePeriods(g.Applicability, w.Applicability) {
			return false
		}
		g.ExtendedProperties, w.ExtendedProperties = nil, nil
		g.Applicability, w.Applicability = nil, nil
		same = reflect.DeepEqual(g, w)
	}
	return same
}

func sameJSONValue(a, b json.RawMessage) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	var x, y any
	return json.Unmarshal(a, &x) == nil && json.Unmarshal(b, &y) == nil && reflect.DeepEqual(x, y)
}

func samePeriods(a, b []ed269.Period) bool {
	if len(a) != len(b) {
		return false
	}
	sameInstant := func(p, q *time.Time) bool {
		if p == nil || q == nil {
			return p == nil && q == nil
		}
		return p.Equal(*q)
	}
	for i := range a {
		p, q := a[i], b[i]
		if p.Permanent != q.Permanent || !sameInstant(p.Start, q.Start) || !sameInstant(p.End, q.End) || len(p.Schedule) != len(q.Schedule) {
			return false
		}
		for k := range p.Schedule {
			d, e := p.Schedule[k], q.Schedule[k]
			if !reflect.DeepEqual(d.Days, e.Days) || !d.Start.Equal(e.Start) || !d.End.Equal(e.End) || d.Offset.String() != e.Offset.String() {
				return false
			}
		}
	}
	return true
}

// publisherVerifier verifies the authority's detached signatures, with
// the harness's publisher key.
func publisherVerifier(t *testing.T, h *pubHarness) *jws.DetachedVerifier {
	t.Helper()
	set := authtest.PublicSet(t, map[string]*rsa.PrivateKey{publisherKID: h.signer})
	v, err := jws.NewDetachedVerifier(context.Background(), jws.KeySource{Publisher: authorityID, Keys: coreauth.IssuerConfig{Keys: set}},
		time.Hour, jws.Options{MaxPayloadBytes: 64 << 20})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// ed269RoundTrip publishes body and reads it back three ways, returning
// the version.
func ed269RoundTrip(t *testing.T, h *pubHarness, body []byte) int64 {
	t.Helper()
	rec := h.putED269(body, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("PUT = %d %s", rec.Code, rec.Body.String())
	}
	var res gen.PublicationResult
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.MappedFrom == nil || *res.MappedFrom != gen.PublicationResultMappedFromEd269 {
		t.Errorf("mapped_from = %v, want ed269", res.MappedFrom)
	}
	target := "/v1/zones/versions/" + strconv.FormatInt(res.Version, 10)

	// The export: equal to the input by value, signed by the CISP.
	exp := h.read(http.MethodGet, target+"?format=ed269")
	if exp.Code != http.StatusOK || exp.Header().Get("Content-Type") != dataset.MediaTypeED269 ||
		exp.Header().Get(HeaderMappedFrom) != dataset.MappedFromED318 || exp.Header().Get(HeaderPublisherSig) != "" {
		t.Fatalf("export = %d %v %s", exp.Code, exp.Header(), exp.Body.String())
	}
	verifyCISP(t, exp.Header().Get(HeaderSignature), exp.Body.Bytes())
	if !sameED269Value(t, exp.Body.Bytes(), body) {
		t.Errorf("the export differs from the input by value:\n got %s\nwant %s", exp.Body.String(), body)
	}

	// The source: the bytes sent, verbatim, with the publisher's
	// signature over them; core reads them back to the same value.
	src := h.read(http.MethodGet, target+"?format=ed269&source=true")
	if src.Code != http.StatusOK || !bytes.Equal(src.Body.Bytes(), body) || src.Header().Get("Content-Type") != dataset.MediaTypeED269 {
		t.Fatalf("source = %d %s", src.Code, src.Body.String())
	}
	if _, err := publisherVerifier(t, h).Verify(context.Background(), src.Header().Get(HeaderPublisherSig), src.Body.Bytes()); err != nil {
		t.Errorf("X-Publisher-Signature does not verify over the source: %v", err)
	}
	if src.Header().Get(HeaderPublisherKID) != publisherKID || src.Header().Get(HeaderMappedFrom) != "" {
		t.Errorf("source headers %v", src.Header())
	}
	verifyCISP(t, src.Header().Get(HeaderSignature), src.Body.Bytes())
	if !sameED269Value(t, src.Body.Bytes(), body) {
		t.Error("the source differs from the input by value")
	}

	// The version itself: the mapped ED-318, which core parses, without
	// the publisher's signature (it covers the source, not this).
	ver := h.read(http.MethodGet, target)
	if ver.Code != http.StatusOK || ver.Header().Get(HeaderMappedFrom) != dataset.MappedFromED269 ||
		ver.Header().Get(HeaderPublisherSig) != "" || ver.Header().Get("Content-Type") != mediaGeoJSON {
		t.Fatalf("version = %d %v", ver.Code, ver.Header())
	}
	if _, probs := ed318.Parse(ver.Body.Bytes(), ed318.Limits{}); probs != nil {
		t.Errorf("the stored version is not ED-318: %v", probs)
	}
	verifyCISP(t, ver.Header().Get(HeaderSignature), ver.Body.Bytes())
	return res.Version
}

// mappableED269 is the valid vector file without TST003.
func mappableED269(t *testing.T) []byte {
	t.Helper()
	f := vectors.Load(t, "ed269_parse.json")
	for _, c := range f.Cases {
		if c.Name == "valid-file-round-trips-unchanged" {
			return withoutZone(t, ed269CaseBody(t, c.Input), "TST003")
		}
	}
	t.Fatal("no valid file")
	return nil
}

// oneED269Zone is the mappable file's TST001 alone, with edit applied.
func oneED269Zone(t *testing.T, edit func(z doc)) []byte {
	t.Helper()
	var d doc
	if err := json.Unmarshal(mappableED269(t), &d); err != nil {
		t.Fatal(err)
	}
	z := feats(d)[0].(doc)
	if edit != nil {
		edit(z)
	}
	d["features"] = []any{z}
	return jsonBytes(t, d)
}

// E-01: each refusal of the bridge beside the acceptance that differs in
// one thing.
func TestED269RefusalsAndTheirTwins(t *testing.T) {
	for _, c := range []struct {
		name          string
		refuse, admit func(z doc)
		field, phrase string
	}{
		{
			name:   "ED-318's REQ_AUTHORIZATION is refused by name, ED-269's REQ_AUTHORISATION accepted",
			refuse: func(z doc) { z["restriction"] = "REQ_AUTHORIZATION" },
			admit:  func(z doc) { z["restriction"] = "REQ_AUTHORISATION" },
			field:  "features[0].restriction", phrase: "spells it REQ_AUTHORISATION",
		},
		{
			name:   "a FOREIGN_TERRITORY reason is refused (ED-318 has none), SENSITIVE accepted",
			refuse: func(z doc) { z["reason"] = []any{"FOREIGN_TERRITORY"} },
			admit:  func(z doc) { z["reason"] = []any{"SENSITIVE"} },
			field:  "features[0].reason[0]", phrase: "FOREIGN_TERRITORY has no ED-318 reason",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newPubHarness(t, nil)
			p := ed269Refusal(t, h, oneED269Zone(t, c.refuse))
			requireProblem(t, p, func(f string) bool { return f == c.field }, c.phrase)
			if rec := h.putED269(oneED269Zone(t, c.admit), ""); rec.Code != http.StatusCreated {
				t.Fatalf("the twin = %d %s", rec.Code, rec.Body.String())
			}
		})
	}
}

// The signature covers the ED-269 bytes and is checked before anything
// parses them: unsigned is 403 signature (docs/PLAN.md section 15 Q30),
// even for bytes that are not ED-269, and no attempt is recorded; the
// same bytes signed reach the parser (E-01).
func TestED269SignatureBeforeParse(t *testing.T) {
	h := newPubHarness(t, nil)
	for _, body := range [][]byte{oneED269Zone(t, nil), []byte("not json")} {
		req := h.putReq("zones", body, `"zones:0"`)
		req.Header.Set("Content-Type", dataset.MediaTypeED269)
		req.Header.Del(jws.HeaderSignature)
		rec := h.do(req)
		p := decodeProblem(t, rec)
		if rec.Code != http.StatusForbidden || p.Type != ProblemTypeBase+"signature" {
			t.Fatalf("unsigned = %d %s", rec.Code, rec.Body.String())
		}
		// Signed over other bytes: still refused before the parse.
		req = h.putReq("zones", body, `"zones:0"`)
		req.Header.Set("Content-Type", dataset.MediaTypeED269)
		req.Header.Set(jws.HeaderSignature, h.sign([]byte("other bytes")))
		if rec := h.do(req); rec.Code != http.StatusForbidden {
			t.Fatalf("signed over other bytes = %d %s", rec.Code, rec.Body.String())
		}
	}
	if n := len(h.fake.refused()); n != 0 {
		t.Errorf("%d attempts recorded for unsigned bodies", n)
	}
	if rec := h.putED269([]byte("not json"), ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("signed non-JSON = %d %s", rec.Code, rec.Body.String())
	}
	if rec := h.putED269(oneED269Zone(t, nil), ""); rec.Code != http.StatusCreated {
		t.Fatalf("signed ED-269 = %d %s", rec.Code, rec.Body.String())
	}
}

// ED-269 is a form of zones only: 415 on the other datasets, the same
// body accepted on zones.
func TestED269OnlyForZones(t *testing.T) {
	h := newPubHarness(t, nil)
	body := oneED269Zone(t, nil)
	for _, ds := range []string{"uspace_airspace", "ussp_list"} {
		req := h.putReq(ds, body, publication.ETag(publication.Dataset(ds), 0))
		req.Header.Set("Content-Type", dataset.MediaTypeED269)
		rec := h.do(req)
		conformResponse(t, req, rec)
		if p := decodeProblem(t, rec); rec.Code != http.StatusUnsupportedMediaType || !hasProblem(p, "Content-Type", "application/json") {
			t.Fatalf("%s = %d %s", ds, rec.Code, rec.Body.String())
		}
	}
	if rec := h.putED269(body, ""); rec.Code != http.StatusCreated {
		t.Fatalf("zones = %d %s", rec.Code, rec.Body.String())
	}
}

// The language of ED-269's single strings: ka by default, ?lang=
// overrides, a lang that is no tag is refused by name.
func TestED269Lang(t *testing.T) {
	h := newPubHarness(t, nil)
	textLang := func() string {
		cur := currentOf(t, h, publication.DatasetZones)
		fc, probs := ed318.Parse(h.fake.bodies[publication.DatasetZones][cur], ed318.Limits{})
		if probs != nil {
			t.Fatal(probs)
		}
		return fc.Features[0].Properties.Name[0].Lang
	}
	if rec := h.putED269(oneED269Zone(t, nil), ""); rec.Code != http.StatusCreated {
		t.Fatal(rec.Body.String())
	}
	if got := textLang(); got != "ka" {
		t.Errorf("default lang %q, want ka", got)
	}
	if rec := h.putED269(oneED269Zone(t, nil), "?lang=en-GB"); rec.Code != http.StatusCreated {
		t.Fatal(rec.Body.String())
	}
	if got := textLang(); got != "en-GB" {
		t.Errorf("lang %q, want en-GB", got)
	}
	for _, bad := range []string{"en-GB-x", "e%20n"} {
		cur := currentOf(t, h, publication.DatasetZones)
		req := h.putReq("zones?lang="+bad, oneED269Zone(t, nil), publication.ETag(publication.DatasetZones, cur))
		req.Header.Set("Content-Type", dataset.MediaTypeED269)
		rec := h.do(req)
		conformResponse(t, req, rec)
		if p := decodeProblem(t, rec); rec.Code != http.StatusBadRequest || !hasProblem(p, "lang", "language tag") {
			t.Fatalf("lang %q = %d %s", bad, rec.Code, rec.Body.String())
		}
	}
	// The texts of the export follow the export's lang.
	v := currentOf(t, h, publication.DatasetZones)
	rec := h.read(http.MethodGet, "/v1/zones/versions/"+strconv.FormatInt(v, 10)+"?format=ed269&lang=en-GB")
	if rec.Code != http.StatusOK || rec.Header().Get("ETag") != `"zones:`+strconv.FormatInt(v, 10)+`;ed269;en-GB"` {
		t.Fatalf("export en-GB = %d %v", rec.Code, rec.Header())
	}
}

// The mapping warnings name every ED-269 member carried under
// extendedProperties.ed269; a file without one has none (E-01). An
// unchanged re-publication is 200 and still says mapped_from.
func TestED269WarningsAndUnchanged(t *testing.T) {
	h := newPubHarness(t, nil)
	rec := h.putED269(mappableED269(t), "")
	if rec.Code != http.StatusCreated {
		t.Fatal(rec.Body.String())
	}
	var res gen.PublicationResult
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	carried := 0
	for _, w := range *res.Warnings {
		if strings.HasPrefix(w.Field, "features[1].properties.extendedProperties.ed269.") {
			carried++
		}
	}
	if carried == 0 {
		t.Errorf("no carried member of TST002 is warned of: %+v", *res.Warnings)
	}
	rec = h.putED269(mappableED269(t), "")
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK || res.Unchanged == nil || !*res.Unchanged || res.MappedFrom == nil {
		t.Fatalf("unchanged = %d %s", rec.Code, rec.Body.String())
	}
	emptyZones(t, h)
	rec = h.putED269(oneED269Zone(t, nil), "")
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	for _, w := range *res.Warnings {
		if strings.Contains(w.Field, "extendedProperties.ed269") {
			t.Errorf("TST001 carries nothing, warned %+v", w)
		}
	}
}

// The export of what ED-269 cannot hold is 406 naming the field; a plain
// zones version is 200 (E-01).
func TestED269ExportNotRepresentable(t *testing.T) {
	h, t0 := restrictionHarness(t)
	if rec := h.postRestriction(createDoc("R-1", 1, "active", "DAR0001", t0, t0.Add(time.Hour))); rec.Code != http.StatusCreated {
		t.Fatalf("restriction = %d %s", rec.Code, rec.Body.String())
	}
	cases := []struct {
		target, field, phrase string
	}{
		{"/v1/restrictions/versions/" + strconv.FormatInt(h.restrictionsVersion(), 10), "properties.reason[0]", "DAR has no ED-269 reason"},
		{"/v1/uspace_airspace/versions/1", "format", "has no ED-269 form"},
		{"/v1/ussp_list/versions/1", "format", "has no ED-269 form"},
	}
	if rec := h.put("ussp_list", usspListBody(t)); rec.Code != http.StatusCreated {
		t.Fatal(rec.Body.String())
	}
	before := h.counter(readsComponent, CounterED269NotRepresentable)
	for _, c := range cases {
		rec := h.read(http.MethodGet, c.target+"?format=ed269")
		p := decodeProblem(t, rec)
		if rec.Code != http.StatusNotAcceptable || p.Type != ProblemTypeBase+SlugNotRepresentable {
			t.Fatalf("%s = %d %s\n%s", c.target, rec.Code, rec.Body.String(), h.logs.String())
		}
		requireProblem(t, p, func(f string) bool { return strings.HasSuffix(f, c.field) }, c.phrase)
	}
	if got := h.counter(readsComponent, CounterED269NotRepresentable) - before; got != uint64(len(cases)) {
		t.Errorf("not_representable counted %d, want %d", got, len(cases))
	}
	// A plain ED-318 zones version exports; it has no source.
	if rec := h.put("zones", jsonBytes(t, plainZones(t))); rec.Code != http.StatusCreated {
		t.Fatal(rec.Body.String())
	}
	target := "/v1/zones/versions/" + strconv.FormatInt(currentOf(t, h, publication.DatasetZones), 10)
	exported := h.counter(readsComponent, CounterED269Exported)
	if rec := h.read(http.MethodGet, target+"?format=ed269"); rec.Code != http.StatusOK {
		t.Fatalf("plain zones export = %d %s", rec.Code, rec.Body.String())
	}
	if h.counter(readsComponent, CounterED269Exported) != exported+1 {
		t.Error("the export is not counted")
	}
	rec := h.read(http.MethodGet, target+"?format=ed269&source=true")
	if p := decodeProblem(t, rec); rec.Code != http.StatusNotFound || !hasProblem(p, "source", "not published as ED-269") {
		t.Fatalf("source of an ED-318 version = %d %s", rec.Code, rec.Body.String())
	}
	// The ED-318 version keeps its publisher's signature and says nothing
	// of a mapping (the twin of the imported version's headers).
	rec = h.read(http.MethodGet, target)
	if rec.Header().Get(HeaderPublisherSig) == "" || rec.Header().Get(HeaderMappedFrom) != "" {
		t.Errorf("ED-318 version headers %v", rec.Header())
	}
}

// plainZones is one polygon zone ED-269 can hold.
func plainZones(t *testing.T) doc {
	t.Helper()
	imp, probs := dataset.FromED269(oneED269Zone(t, nil), 1<<20, dataset.ED269Meta{Lang: "en-GB"})
	if probs != nil {
		t.Fatal(probs)
	}
	var d doc
	if err := json.Unmarshal(imp.Body, &d); err != nil {
		t.Fatal(err)
	}
	return d
}

// The parameters of the export are refused by name out of place, and an
// export answers If-None-Match on its own ETag.
func TestED269ExportParameters(t *testing.T) {
	h := newPubHarness(t, nil)
	v := ed269RoundTrip(t, h, oneED269Zone(t, nil))
	target := "/v1/zones/versions/" + strconv.FormatInt(v, 10)
	for query, field := range map[string]string{
		"?source=true":           "source",
		"?lang=ka":               "lang",
		"?format=ed269&lang=x_y": "lang",
	} {
		rec := h.read(http.MethodGet, target+query)
		if p := decodeProblem(t, rec); rec.Code != http.StatusBadRequest || p.Errors == nil || (*p.Errors)[0].Field != field {
			t.Errorf("%s = %d %s", query, rec.Code, rec.Body.String())
		}
	}
	for query, etag := range map[string]string{
		"?format=ed269":             `"zones:` + strconv.FormatInt(v, 10) + `;ed269;ka"`,
		"?format=ed269&source=true": `"zones:` + strconv.FormatInt(v, 10) + `;source"`,
		"":                          `"zones:` + strconv.FormatInt(v, 10) + `"`,
	} {
		rec := h.read(http.MethodGet, target+query)
		if rec.Header().Get("ETag") != etag {
			t.Errorf("%q ETag %s, want %s", query, rec.Header().Get("ETag"), etag)
		}
		if rec := h.read(http.MethodGet, target+query, "If-None-Match", etag); rec.Code != http.StatusNotModified {
			t.Errorf("%q If-None-Match = %d", query, rec.Code)
		}
	}
	// Another representation's ETag does not match (E-01).
	if rec := h.read(http.MethodGet, target+"?format=ed269", "If-None-Match", `"zones:`+strconv.FormatInt(v, 10)+`"`); rec.Code != http.StatusOK {
		t.Errorf("the version's ETag matched the export: %d", rec.Code)
	}
}

// T7 for the source: a stored source whose hash does not match is never
// served; the intact one is (the round trip above).
func TestED269SourceIntegrity(t *testing.T) {
	h := newPubHarness(t, nil)
	v := ed269RoundTrip(t, h, oneED269Zone(t, nil))
	h.fake.mu.Lock()
	head := h.fake.heads[publication.DatasetZones][v]
	head.SourceBody = append([]byte(" "), head.SourceBody...)
	h.fake.heads[publication.DatasetZones][v] = head
	h.fake.mu.Unlock()
	rec := h.read(http.MethodGet, "/v1/zones/versions/"+strconv.FormatInt(v, 10)+"?format=ed269&source=true")
	if p := decodeProblem(t, rec); rec.Code != http.StatusInternalServerError || p.Type != ProblemTypeBase+SlugIntegrity {
		t.Fatalf("tampered source = %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(h.logs.String(), "publication source integrity check failed") {
		t.Error("the integrity failure is not logged")
	}
}

// The C-M1 item "an ED-269 file round-trips through the import mapping",
// as a transcript (go test -v -run TestED269CM1Transcript): the vector
// file's mappable zones PUT as ED-269, the export and the source read
// back, and the difference by value and by bytes.
func TestED269CM1Transcript(t *testing.T) {
	h := newPubHarness(t, nil)
	body := mappableED269(t)
	sum := func(b []byte) string { s := sha256Sum(b); return hexOf(s)[:16] }
	rec := h.putED269(body, "")
	t.Logf("PUT /v1/publications/zones Content-Type: %s (%d bytes, sha256 %s) -> %d %s",
		dataset.MediaTypeED269, len(body), sum(body), rec.Code, strings.TrimSpace(rec.Body.String()))
	if rec.Code != http.StatusCreated {
		t.Fatal("not accepted")
	}
	v := currentOf(t, h, publication.DatasetZones)
	target := "/v1/zones/versions/" + strconv.FormatInt(v, 10)
	ver := h.read(http.MethodGet, target)
	t.Logf("GET %s -> %d Content-Type %s X-CIS-Mapped-From %s X-Publisher-Signature %q (%d bytes of ED-318)",
		target, ver.Code, ver.Header().Get("Content-Type"), ver.Header().Get(HeaderMappedFrom), ver.Header().Get(HeaderPublisherSig), ver.Body.Len())
	exp := h.read(http.MethodGet, target+"?format=ed269")
	t.Logf("GET %s?format=ed269 -> %d Content-Type %s ETag %s X-CIS-Mapped-From %s (%d bytes, sha256 %s)",
		target, exp.Code, exp.Header().Get("Content-Type"), exp.Header().Get("ETag"), exp.Header().Get(HeaderMappedFrom), exp.Body.Len(), sum(exp.Body.Bytes()))
	src := h.read(http.MethodGet, target+"?format=ed269&source=true")
	t.Logf("GET %s?format=ed269&source=true -> %d ETag %s X-Publisher-Kid %s (%d bytes, sha256 %s)",
		target, src.Code, src.Header().Get("ETag"), src.Header().Get(HeaderPublisherKID), src.Body.Len(), sum(src.Body.Bytes()))
	t.Logf("diff input export: equal by value %v; equal by bytes %v", sameED269Value(t, body, exp.Body.Bytes()), bytes.Equal(body, exp.Body.Bytes()))
	t.Logf("diff input source: equal by bytes %v", bytes.Equal(body, src.Body.Bytes()))
	if !sameED269Value(t, body, exp.Body.Bytes()) || !bytes.Equal(body, src.Body.Bytes()) {
		t.Fatal("the round trip differs")
	}
}
