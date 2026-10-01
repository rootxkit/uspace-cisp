package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
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
	if rec.Code != http.StatusBadRequest || p.Type != ProblemTypeBase+SlugPublicationRefused || p.Errors == nil {
		t.Fatalf("PUT = %d %s", rec.Code, rec.Body.String())
	}
	for _, e := range *p.Errors {
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
