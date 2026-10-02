package dataset

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed269"
	"github.com/rootxkit/uspace-core/ed318"
	"github.com/rootxkit/uspace-core/vectors"
)

// doc is a JSON document as maps, for one-change edits.
type doc = map[string]any

// baseDoc is the accepted collection of ed318_roundtrip.json
// (accept-authority-collection), decoded fresh on every call.
func baseDoc(t *testing.T) doc {
	t.Helper()
	f := vectors.Load(t, "ed318_roundtrip.json")
	for _, c := range f.Cases {
		if c.Name != "accept-authority-collection" {
			continue
		}
		var in struct {
			Document doc `json:"document"`
		}
		if err := json.Unmarshal(c.Input, &in); err != nil {
			t.Fatal(err)
		}
		return in.Document
	}
	t.Fatal("no accept-authority-collection case")
	return nil
}

func features(d doc) []any { return d["features"].([]any) }

func props(d doc, i int) doc { return features(d)[i].(doc)["properties"].(doc) }

func body(t *testing.T, d doc) []byte {
	t.Helper()
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// zonesDoc is the base collection as a zones publication: the USPACE
// feature (0) left out and DAR taken from TSD001's reasons.
func zonesDoc(t *testing.T) doc {
	t.Helper()
	d := baseDoc(t)
	d["features"] = features(d)[1:]
	props(d, 0)["reason"] = []any{"EMERGENCY"}
	return d
}

// requirementsBlock is the Art. 3(4) block made of the members the
// vector's USPACE feature carries flat in extendedProperties.
func requirementsBlock(t *testing.T) doc {
	t.Helper()
	ext := props(baseDoc(t), 0)["extendedProperties"].(doc)
	out := doc{}
	for _, k := range requirementMembers {
		out[k] = ext[k]
	}
	return out
}

// uspaceDoc is the base collection's USPACE feature alone, with the
// requirements block under RequirementsMember.
func uspaceDoc(t *testing.T) doc {
	t.Helper()
	d := baseDoc(t)
	d["features"] = features(d)[:1]
	props(d, 0)["extendedProperties"].(doc)[RequirementsMember] = requirementsBlock(t)
	return d
}

// secondUSpace adds a copy of the USPACE feature with identifier id.
func secondUSpace(t *testing.T, d doc, id string) {
	t.Helper()
	raw, err := json.Marshal(features(d)[0])
	if err != nil {
		t.Fatal(err)
	}
	var f doc
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	f["id"] = id
	f["properties"].(doc)["identifier"] = id
	d["features"] = append(features(d), f)
}

func validate(t *testing.T, kind Kind, d doc) (Accepted, *ed269.Problems) {
	t.Helper()
	return For(kind).Validate(body(t, d), ed318.Limits{}, time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC))
}

func mustAccept(t *testing.T, kind Kind, d doc) Accepted {
	t.Helper()
	acc, probs := validate(t, kind, d)
	if probs != nil {
		t.Fatalf("refused: %v", probs)
	}
	return acc
}

// mustRefuse fails unless the refusal names field with a reason holding
// phrase.
func mustRefuse(t *testing.T, kind Kind, d doc, field, phrase string) *ed269.Problems {
	t.Helper()
	_, probs := validate(t, kind, d)
	if probs == nil {
		t.Fatalf("accepted; want %s: %s", field, phrase)
	}
	for _, p := range probs.List {
		if p.Field == field && strings.Contains(p.Reason, phrase) {
			return probs
		}
	}
	t.Fatalf("no problem %s containing %q in %v", field, phrase, probs)
	return nil
}

func TestKindsAndRules(t *testing.T) {
	for ds, want := range map[string]Kind{"zones": KindZones, "uspace_airspace": KindUspaceAirspace, "ussp_list": KindUsspList} {
		if k, ok := KindOf(publicationDataset(ds)); !ok || k != want {
			t.Errorf("KindOf(%s) = %s %v", ds, k, ok)
		}
	}
	for _, ds := range []string{"restrictions", "", "zone"} {
		if _, ok := KindOf(publicationDataset(ds)); ok {
			t.Errorf("KindOf(%q) has rules", ds)
		}
	}
	// A kind without rules refuses, naming it; never accepts.
	_, probs := For("restrictions").Validate([]byte(`{}`), ed318.Limits{}, time.Time{})
	if probs == nil || probs.List[0].Field != "$" || !strings.Contains(probs.List[0].Reason, `"restrictions"`) {
		t.Errorf("unknown kind: %v", probs)
	}
}

// The zones dataset: the base collection without U-space airspace and
// DAR is accepted with one row per feature and no warning.
func TestZonesAccepted(t *testing.T) {
	acc := mustAccept(t, KindZones, zonesDoc(t))
	if acc.Collection == nil || len(acc.Rows) != 4 || acc.UsspList != nil {
		t.Fatalf("accepted %+v", acc)
	}
	if acc.Rows[0].ID != "TSD001" || acc.Rows[3].ID != "TSN001" {
		t.Errorf("rows %s..%s", acc.Rows[0].ID, acc.Rows[3].ID)
	}
	if len(acc.Warnings) != 0 {
		t.Errorf("warnings %v", acc.Warnings)
	}
}

// E-01 pairs for zones: each refusal beside the acceptance that differs
// in one thing.
func TestZonesRefusalPairs(t *testing.T) {
	t.Run("USPACE refused in zones", func(t *testing.T) {
		d := zonesDoc(t)
		props(d, 1)["type"] = "USPACE"
		mustRefuse(t, KindZones, d, "features[1].properties.type", "published in the uspace_airspace dataset")
		props(d, 1)["type"] = "PROHIBITED"
		mustAccept(t, KindZones, d)
	})
	t.Run("DAR refused in zones", func(t *testing.T) {
		d := zonesDoc(t)
		props(d, 0)["reason"] = []any{"EMERGENCY", "DAR"}
		mustRefuse(t, KindZones, d, "features[0].properties.reason[1]", "dynamic restrictions are published by the ANSP")
		props(d, 0)["reason"] = []any{"EMERGENCY"}
		mustAccept(t, KindZones, d)
	})
	t.Run("the vector's own collection is refused for both", func(t *testing.T) {
		d := baseDoc(t)
		probs := mustRefuse(t, KindZones, d, "features[0].properties.type", "uspace_airspace")
		mustRefuse(t, KindZones, d, "features[1].properties.reason[0]", "ANSP")
		if len(probs.List) != 2 {
			t.Errorf("problems %v", probs)
		}
	})
	t.Run("duplicate identifier: core refuses and names the path", func(t *testing.T) {
		d := zonesDoc(t)
		props(d, 3)["identifier"] = "TSR001"
		_, probs := validate(t, KindZones, d)
		if probs == nil || !hasField(probs, "features[3].properties.identifier") {
			t.Fatalf("got %v", probs)
		}
		props(d, 3)["identifier"] = "TSN002"
		mustAccept(t, KindZones, d)
	})
	t.Run("core refusals come back whole and unchanged", func(t *testing.T) {
		d := zonesDoc(t)
		props(d, 1)["colour"] = "red"
		mustRefuse(t, KindZones, d, "features[1].properties.colour", "unknown property")
	})
}

func hasField(p *ed269.Problems, field string) bool {
	for _, pr := range p.List {
		if pr.Field == field {
			return true
		}
	}
	return false
}

// Judgeability (E-02): a daylight schedule without end dates is accepted
// with a warning naming the feature; the same zone with its end date
// has none. More than MaxEventDays is a warning too.
func TestZonesWarnOnOpenEndedDaylightSchedule(t *testing.T) {
	d := zonesDoc(t)
	period := props(d, 0)["limitedApplicability"].([]any)[0].(doc)
	delete(period, "endDateTime")
	acc := mustAccept(t, KindZones, d)
	if len(acc.Warnings) != 1 {
		t.Fatalf("warnings %v", acc.Warnings)
	}
	w := acc.Warnings[0]
	if w.Field != "features[0].properties.limitedApplicability[0]" || !strings.Contains(w.Reason, `"TSD001"`) || !strings.Contains(w.Reason, "ed318.Applies") {
		t.Errorf("warning %+v", w)
	}
	t.Logf("warning: %s: %s", w.Field, w.Reason)

	period["endDateTime"] = "2027-12-01T00:00:00Z" // over a year of events
	acc = mustAccept(t, KindZones, d)
	if len(acc.Warnings) != 1 || !strings.Contains(acc.Warnings[0].Reason, "366") {
		t.Errorf("over MaxEventDays: %v", acc.Warnings)
	}
	period["endDateTime"] = "2026-10-08T00:00:00Z"
	if acc := mustAccept(t, KindZones, d); len(acc.Warnings) != 0 {
		t.Errorf("bounded schedule warned: %v", acc.Warnings)
	}
}

// A zone ToZones cannot build is refused at its geometry or limit; core's
// Parse refuses most such shapes first, so the branch is driven with
// features built in code (E-01: beside a buildable one).
func TestJudgeableRefusesWhatCannotBeBuilt(t *testing.T) {
	fc, probs := ed318.Parse(body(t, zonesDoc(t)), ed318.Limits{})
	if probs != nil {
		t.Fatal(probs)
	}
	good := fc.Features[0] // TSD001, a circle
	c := newCollector(ed318.Limits{})
	if w := judgeable(&good, "features[7]", c); w != nil || c.result() != nil {
		t.Fatalf("a buildable zone: %v %v", w, c.result())
	}
	zero := 0.0
	bad := good
	bad.Geometry.RadiusM = &zero
	c = newCollector(ed318.Limits{})
	if w := judgeable(&bad, "features[7]", c); w != nil {
		t.Fatalf("warning instead of a refusal: %v", w)
	}
	p := c.result()
	if p == nil || p.List[0].Field != "features[7].geometry.extent.radius" || !strings.Contains(p.List[0].Reason, "ed318.ToZones") {
		t.Fatalf("got %v", p)
	}

	ring := fc.Features[1] // TSR001, a polygon with a hole
	ring.Geometry.Rings = [][]core.LatLon{ring.Geometry.Rings[0][:3]}
	c = newCollector(ed318.Limits{})
	judgeable(&ring, "features[2]", c)
	if p := c.result(); p == nil || !strings.HasPrefix(p.List[0].Field, "features[2].geometry.coordinates") {
		t.Fatalf("an open ring: %v", p)
	}

	limit := fc.Features[1]
	limit.Geometry.Layer = &ed318.Layer{Upper: limit.Geometry.Layer.Upper, UpperReference: "MSL"}
	c = newCollector(ed318.Limits{})
	judgeable(&limit, "features[2]", c)
	if p := c.result(); p == nil || p.List[0].Field != "features[2].geometry.layer.upper" {
		t.Fatalf("an unknown reference: %v", p)
	}
}

func TestRefusesBuildClassifies(t *testing.T) {
	for field, want := range map[string]bool{
		"features[0].geometry.coordinates[0]":                  true,
		"features[0].geometry.geometries[1].layer.lower":       true,
		"features[0].geometry.extent.radius":                   true,
		"features[0].properties.limitedApplicability[0]":       false,
		"features[0].properties.limitedApplicability.schedule": false,
	} {
		if got := refusesBuild(field); got != want {
			t.Errorf("%s: %v", field, got)
		}
	}
	if got := rebase("features[0].geometry", "features[9]"); got != "features[9].geometry" {
		t.Errorf("rebase %s", got)
	}
	if got := rebase("$", "features[9]"); got != "features[9]" {
		t.Errorf("rebase $ = %s", got)
	}
}

// E-10: past the problem cap, the list stops at 100 and counts the rest.
func TestProblemsCappedWithTheCount(t *testing.T) {
	d := zonesDoc(t)
	tmpl := features(d)[3]
	raw, _ := json.Marshal(tmpl)
	var list []any
	for i := range 150 {
		var f doc
		_ = json.Unmarshal(raw, &f)
		f["properties"].(doc)["identifier"] = "U" + strconv.Itoa(i)
		f["properties"].(doc)["type"] = "USPACE"
		list = append(list, f)
	}
	d["features"] = list
	_, probs := validate(t, KindZones, d)
	if probs == nil || len(probs.List) != 100 || probs.Truncated != 50 {
		t.Fatalf("got %d listed, %d more", len(probs.List), probs.Truncated)
	}
	if probs.List[0].Field != "features[0].properties.type" || probs.List[99].Field != "features[99].properties.type" {
		t.Errorf("not in document order: %s .. %s", probs.List[0].Field, probs.List[99].Field)
	}
	// At the cap: exactly 100, nothing truncated.
	d["features"] = list[:100]
	if _, probs := validate(t, KindZones, d); probs == nil || len(probs.List) != 100 || probs.Truncated != 0 {
		t.Errorf("at the cap: %v", probs)
	}
}
