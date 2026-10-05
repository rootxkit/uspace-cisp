package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/rootxkit/uspace-core/ed269"
	"github.com/rootxkit/uspace-core/ed318"
	"github.com/rootxkit/uspace-core/vectors"

	"github.com/rootxkit/uspace-cisp/internal/httpapi/gen"
	"github.com/rootxkit/uspace-cisp/internal/publication"
)

// TestVectorsED318Roundtrip runs every ed318_roundtrip.json case the
// cisp owns (22) through PUT /v1/publications/{dataset}, on the fake
// store; the integration test TestVectorsED318RoundtripStore runs the
// same on PostgreSQL. See runED318Vectors for how each kind of case is
// published.
func TestVectorsED318Roundtrip(t *testing.T) {
	ran := runED318Vectors(t, func(t *testing.T) (*pubHarness, storedBody) {
		h := newPubHarness(t, nil)
		return h, func(_ *testing.T, ds publication.Dataset, v int64) []byte { return h.fake.bodies[ds][v] }
	})
	t.Logf("%d ed318_roundtrip cases ran through PUT", ran)
}

// storedBody is the verbatim body of a stored version (the bytes
// GET /v1/{dataset}/versions/{v} will serve, WP-4).
type storedBody func(t *testing.T, ds publication.Dataset, version int64) []byte

const emptyCollection = `{"type":"FeatureCollection","features":[]}`

// runED318Vectors publishes each case and returns how many ran:
//
//   - A refusal (kind parse, accepted false) is PUT to zones as it is and
//     must be 400 with errors[] holding the vector's path and phrase:
//     ed318.Parse refuses first, so the dataset rules never shift a path.
//   - An accepted collection (kind parse accepted, to_ed269, applies) is
//     split as the CISP's datasets require: its USPACE features
//     (TSU001 in accept-authority-collection and refuse-ed269-mapping-
//     uspace) go to uspace_airspace, given the cis/uspace_requirements/v1
//     block made of the members the vector carries flat in their
//     extendedProperties; every other feature goes to zones. A feature
//     with the reason DAR (TSD001, in accept-authority-collection,
//     refuse-ed269-mapping-dar and the applies cases) is a dynamic
//     restriction, the ANSP's (F2): the zones part is first PUT as it is
//     and must be refused naming that reason, then PUT with DAR taken
//     from the reasons. Each part must be 201 and the stored body must
//     equal the bytes sent.
//   - map-ed269-zone-to-ed318 (kind from_ed269) is mapped with
//     ed318.FromED269 and ed318.Export, checked equal by value to the
//     vector's expected ED-318, and PUT to zones: 201, bytes equal.
//
// Before every accepted PUT the dataset is emptied (an empty collection
// is a valid publication), so that a case equal to the previous one is
// still a new version.
func runED318Vectors(t *testing.T, newHarness func(t *testing.T) (*pubHarness, storedBody)) int {
	t.Helper()
	f := vectors.Load(t, "ed318_roundtrip.json")
	h, stored := newHarness(t)
	ran := 0
	f.RunOwned(t, "cisp", func(t *testing.T, c vectors.Case) {
		ran++
		var in struct {
			Kind          string          `json:"kind"`
			Document      json.RawMessage `json:"document"`
			ED269Document json.RawMessage `json:"ed269_document"`
			Lang          string          `json:"lang"`
		}
		if err := json.Unmarshal(c.Input, &in); err != nil {
			t.Fatal(err)
		}
		var exp struct {
			Accepted    *bool `json:"accepted"`
			MustInclude *struct {
				FieldEndsWith  string `json:"field_endswith"`
				ReasonContains string `json:"reason_contains"`
			} `json:"must_include"`
			ED318 json.RawMessage `json:"ed318"`
		}
		if err := json.Unmarshal(c.Expected, &exp); err != nil {
			t.Fatal(err)
		}
		switch {
		case in.Kind == "parse" && exp.Accepted != nil && !*exp.Accepted:
			vectorRefusal(t, h, in.Document, exp.MustInclude.FieldEndsWith, exp.MustInclude.ReasonContains)
		case in.Kind == "from_ed269":
			body := mapED269(t, in.ED269Document, in.Lang)
			if !equalJSON(t, body, exp.ED318) {
				t.Fatalf("the mapped collection differs from the vector's expected ED-318:\n%s", body)
			}
			vectorPublish(t, h, stored, publication.DatasetZones, body)
		default:
			var d doc
			if err := json.Unmarshal(in.Document, &d); err != nil {
				t.Fatal(err)
			}
			zones, uspace := splitVector(d)
			if len(feats(uspace)) > 0 {
				t.Logf("USPACE features to uspace_airspace with the requirements block: %d", len(feats(uspace)))
				vectorPublish(t, h, stored, publication.DatasetUSpaceAirspace, jsonBytes(t, withRequirements(uspace)))
			}
			if len(feats(zones)) > 0 {
				if path := darPath(zones); path != "" {
					vectorRefusal(t, h, jsonBytes(t, zones), path, "dynamic restrictions are published by the ANSP")
					stripDAR(zones)
					t.Logf("DAR refused at %s, then taken from the reasons", path)
				}
				vectorPublish(t, h, stored, publication.DatasetZones, jsonBytes(t, zones))
			}
		}
	})
	if ran != 22 {
		t.Errorf("%d cases ran; ed318_roundtrip.json has 22 the cisp owns", ran)
	}
	return ran
}

// vectorRefusal PUTs body to zones and requires a 400 naming a field
// that ends with fieldSuffix with a reason holding phrase.
func vectorRefusal(t *testing.T, h *pubHarness, body []byte, fieldSuffix, phrase string) {
	t.Helper()
	before := currentOf(t, h, publication.DatasetZones)
	rec := h.put("zones", body)
	p := decodeProblem(t, rec)
	if rec.Code != http.StatusBadRequest || p.Type != ProblemTypeBase+SlugPublicationRefused || len(p.Errors) == 0 {
		t.Fatalf("PUT = %d %s", rec.Code, rec.Body.String())
	}
	for _, e := range p.Errors {
		if strings.HasSuffix(e.Field, fieldSuffix) && strings.Contains(e.Reason, phrase) {
			if currentOf(t, h, publication.DatasetZones) != before {
				t.Error("a refused publication made a version")
			}
			return
		}
	}
	t.Fatalf("no problem ending %s with %q in %s", fieldSuffix, phrase, rec.Body.String())
}

// vectorPublish empties ds, PUTs body and requires 201 and the stored
// bytes equal to body.
func vectorPublish(t *testing.T, h *pubHarness, stored storedBody, ds publication.Dataset, body []byte) {
	t.Helper()
	if rec := h.put(string(ds), []byte(emptyCollection)); rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Fatalf("emptying %s = %d %s", ds, rec.Code, rec.Body.String())
	}
	rec := h.put(string(ds), body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("PUT %s = %d %s", ds, rec.Code, rec.Body.String())
	}
	var r gen.PublicationResult
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if got := stored(t, ds, r.Version); !bytes.Equal(got, body) {
		t.Fatalf("%s version %d stored %d bytes that differ from the %d sent", ds, r.Version, len(got), len(body))
	}
}

func currentOf(t *testing.T, h *pubHarness, ds publication.Dataset) int64 {
	t.Helper()
	v, err := h.store.CurrentVersion(context.Background(), ds)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// splitVector is the collection's non-USPACE features (zones) and its
// USPACE features (uspace_airspace), each with the collection's other
// members.
func splitVector(d doc) (zones, uspace doc) {
	zones, uspace = doc{}, doc{}
	for k, v := range d {
		if k != "features" {
			zones[k], uspace[k] = v, v
		}
	}
	var zf, uf []any
	for _, f := range feats(d) {
		if f.(doc)["properties"].(doc)["type"] == "USPACE" {
			uf = append(uf, f)
		} else {
			zf = append(zf, f)
		}
	}
	zones["features"], uspace["features"] = append([]any{}, zf...), append([]any{}, uf...)
	return zones, uspace
}

// darPath is the path of the first DAR reason in d, or "".
func darPath(d doc) string {
	for i := range feats(d) {
		reasons, _ := fprops(d, i)["reason"].([]any)
		for k, r := range reasons {
			if r == "DAR" {
				return "features[" + itoa(i) + "].properties.reason[" + itoa(k) + "]"
			}
		}
	}
	return ""
}

// stripDAR takes DAR from every feature's reasons.
func stripDAR(d doc) {
	for i := range feats(d) {
		p := fprops(d, i)
		reasons, _ := p["reason"].([]any)
		var kept []any
		for _, r := range reasons {
			if r != "DAR" {
				kept = append(kept, r)
			}
		}
		if reasons != nil {
			p["reason"] = append([]any{}, kept...)
		}
	}
}

// mapED269 maps an ED-269 document with core and exports the ED-318.
func mapED269(t *testing.T, raw json.RawMessage, lang string) []byte {
	t.Helper()
	d, probs := ed269.Parse(raw, ed269.Limits{})
	if probs != nil {
		t.Fatal(probs)
	}
	fc, err := ed318.FromED269(d, ed318.Metadata{}, lang)
	if err != nil {
		t.Fatal(err)
	}
	body, err := ed318.Export(fc)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func equalJSON(t *testing.T, a, b []byte) bool {
	t.Helper()
	var x, y any
	if err := json.Unmarshal(a, &x); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &y); err != nil {
		t.Fatal(err)
	}
	return reflect.DeepEqual(x, y)
}

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}

// zoneWithApplicability is an ED-318 zones collection of one zone,
// TAP001, carrying an ED-269 applicability list mapped by core
// (ed269.Parse, ed318.FromED269): the zone the applicability vectors
// put through the read.
func zoneWithApplicability(t testing.TB, applicability json.RawMessage) []byte {
	t.Helper()
	zone := map[string]any{
		"identifier": "TAP001", "country": "GEO", "name": "Applicability vector", "type": "COMMON",
		"restriction": "PROHIBITED", "reason": []any{"SENSITIVE"}, "applicability": applicability,
		"zoneAuthority": []any{map[string]any{"name": "Test authority", "purpose": "AUTHORIZATION"}},
		"geometry": []any{map[string]any{
			"uomDimensions": "M", "lowerLimit": 0, "lowerVerticalReference": "AGL", "upperLimit": 120, "upperVerticalReference": "AGL",
			"horizontalProjection": map[string]any{"type": "Polygon", "coordinates": []any{[]any{
				[]any{44.80, 41.70}, []any{44.82, 41.70}, []any{44.82, 41.72}, []any{44.80, 41.72}, []any{44.80, 41.70},
			}}},
		}},
	}
	d, probs := ed269.Parse(jsonBytes(t, map[string]any{"features": []any{zone}}), ed269.Limits{})
	if probs != nil {
		t.Fatalf("ed269.Parse: %v", probs)
	}
	fc, err := ed318.FromED269(d, ed318.Metadata{}, "en-GB")
	if err != nil {
		t.Fatalf("ed318.FromED269: %v", err)
	}
	out, err := ed318.Export(fc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestVectorsZonesApplicability runs the 32 zones_applicability.json
// cases the cisp owns through the read: zones holds the case's zone, and
// GET /v1/zones?at=<the case's instant> includes it exactly when the
// vector says it applies (internal/applicability runs the same cases on
// At).
func TestVectorsZonesApplicability(t *testing.T) {
	f := vectors.Load(t, "zones_applicability.json")
	h := newPubHarness(t, nil)
	ran := 0
	f.RunOwned(t, "cisp", func(t *testing.T, c vectors.Case) {
		ran++
		var in struct {
			Applicability json.RawMessage `json:"applicability"`
			At            string          `json:"at"`
		}
		var exp struct {
			Applies bool `json:"applies"`
		}
		c.Decode(t, &in, &exp)
		if rec := h.put("zones", zoneWithApplicability(t, in.Applicability)); rec.Code != 201 && rec.Code != 200 {
			t.Fatalf("PUT = %d %s", rec.Code, rec.Body.String())
		}
		rec := h.read(http.MethodGet, "/v1/zones?at="+url.QueryEscape(in.At))
		_, byID := collection(t, rec)
		if got := byID["TAP001"] != nil; got != exp.Applies || rec.Code != 200 {
			t.Errorf("GET ?at=%s: %d, TAP001 present %v, want %v", in.At, rec.Code, got, exp.Applies)
		}
		if f := byID["TAP001"]; f != nil && annotation(f) != nil {
			t.Errorf("an evaluated zone was marked %v", annotation(f))
		}
	})
	t.Logf("%d zones_applicability cases ran through GET /v1/zones?at=", ran)
}

// geodesyZone is a zones collection of one zone, TGE001, with the
// vector case's polygon (rings in [lng, lat]) or circle (centre in
// [lat, lng], radius in metres).
func geodesyZone(t testing.TB, rings [][][2]float64, center []float64, radiusM float64) []byte {
	t.Helper()
	geom := map[string]any{"layer": map[string]any{"lower": 0, "lowerReference": "AGL", "upper": 120, "upperReference": "AGL", "uom": "m"}}
	if rings != nil {
		geom["type"], geom["coordinates"] = "Polygon", rings
	} else {
		geom["type"], geom["coordinates"] = "Point", []float64{center[1], center[0]}
		geom["extent"] = map[string]any{"subType": "Circle", "radius": radiusM}
	}
	return jsonBytes(t, map[string]any{"type": "FeatureCollection", "features": []any{map[string]any{
		"type": "Feature", "geometry": geom,
		"properties": map[string]any{
			"identifier": "TGE001", "country": "GEO", "type": "PROHIBITED", "variant": "COMMON", "reason": []any{"SENSITIVE"},
			"zoneAuthority": []any{map[string]any{"name": []any{map[string]any{"lang": "en-GB", "text": "Test authority"}}, "purpose": "AUTHORIZATION"}},
		},
	}}})
}

// runGeodesyVectors puts the in_polygon and in_circle cases of
// geodesy.json the cisp owns through the bbox prefilter: a zone with the
// case's ring or circle, and GET /v1/zones?bbox= of a box of 1e-6
// degrees around the point. The prefilter is conservative, so only the
// presence direction is asserted: whenever the point is inside, the zone
// is returned; a zone returned for a point outside is logged, not
// failed (Z-11: a prefilter, never a judgement). It returns how many
// cases ran.
func runGeodesyVectors(t *testing.T, h *pubHarness) int {
	t.Helper()
	f := vectors.Load(t, "geodesy.json")
	// Only the containment cases: the distances are core's, run by core.
	containment := *f
	containment.Cases = nil
	for _, c := range f.Cases {
		var head struct {
			Function string `json:"function"`
		}
		if err := json.Unmarshal(c.Input, &head); err != nil {
			t.Fatal(err)
		}
		if head.Function == "in_polygon" || head.Function == "in_circle" {
			containment.Cases = append(containment.Cases, c)
		}
	}
	ran := 0
	containment.RunOwned(t, "cisp", func(t *testing.T, c vectors.Case) {
		ran++
		var in struct {
			Function    string         `json:"function"`
			RingsLonLat [][][2]float64 `json:"rings_lon_lat"`
			Center      []float64      `json:"center"`
			Radius      float64        `json:"radius"`
			RadiusUnit  string         `json:"radius_unit"`
			Point       []float64      `json:"point"`
		}
		var exp struct {
			Inside    bool     `json:"inside"`
			DistanceM *float64 `json:"distance_m"`
		}
		c.Decode(t, &in, &exp)
		if in.Function == "in_circle" && in.RadiusUnit != "m" {
			t.Fatalf("radius_unit %q", in.RadiusUnit)
		}
		if rec := h.put("zones", geodesyZone(t, in.RingsLonLat, in.Center, in.Radius)); rec.Code != 201 && rec.Code != 200 {
			t.Fatalf("PUT = %d %s", rec.Code, rec.Body.String())
		}
		lat, lng := in.Point[0], in.Point[1]
		const d = 1e-6
		box := fmt.Sprintf("%.7f,%.7f,%.7f,%.7f", lng-d, lat-d, lng+d, lat+d)
		rec := h.read(http.MethodGet, "/v1/zones?bbox="+box)
		_, byID := collection(t, rec)
		present := byID["TGE001"] != nil
		switch {
		case exp.Inside && !present:
			t.Errorf("the point (%v, %v) is inside, yet bbox=%s left the zone out", lat, lng, box)
		case !exp.Inside && present:
			t.Logf("the point is outside and the prefilter kept the zone (conservative, allowed): bbox=%s", box)
		}
	})
	return ran
}

// TestVectorsGeodesy runs the containment cases through the read on the
// fake store, whose prefilter is core's bounding box; the integration
// test TestVectorsGeodesyStore runs them on PostGIS's &&.
func TestVectorsGeodesy(t *testing.T) {
	n := runGeodesyVectors(t, newPubHarness(t, nil))
	if n != 7 {
		t.Errorf("%d containment cases ran, want 7", n)
	}
	t.Logf("%d geodesy containment cases ran through GET /v1/zones?bbox=", n)
}
