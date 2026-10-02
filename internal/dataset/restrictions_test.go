package dataset

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/ed269"
	"github.com/rootxkit/uspace-core/ed318"
)

var (
	darStart = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	darEnd   = darStart.Add(2 * time.Hour)
	darWin   = RestrictionWindow{StartsAt: darStart, EndsAt: darEnd}
)

type obj = map[string]any

// darFeature is an accepted DAR feature: DAR + 4 base-36, PROHIBITED,
// one period equal to darWin, a square near Tbilisi.
func darFeature(id string) obj {
	return obj{
		"type": "Feature",
		"geometry": obj{
			"type":        "Polygon",
			"coordinates": []any{[]any{[]any{44.80, 41.70}, []any{44.82, 41.70}, []any{44.82, 41.72}, []any{44.80, 41.72}, []any{44.80, 41.70}}},
			"layer":       obj{"lower": 0, "lowerReference": "AGL", "upper": 120, "upperReference": "AGL", "uom": "m"},
		},
		"properties": obj{
			"identifier": id, "country": "GEO", "type": "PROHIBITED", "variant": "COMMON", "reason": []any{"DAR"},
			"name": []any{obj{"lang": "en-GB", "text": "Test dynamic restriction"}},
			"limitedApplicability": []any{obj{
				"startDateTime": darStart.Format(time.RFC3339), "endDateTime": darEnd.Format(time.RFC3339),
			}},
			"zoneAuthority": []any{obj{"name": []any{obj{"lang": "en-GB", "text": "Test ANSP"}}, "purpose": "NOTIFICATION"}},
		},
	}
}

func darProps(f obj) obj { return f["properties"].(obj) }

func raw(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// polygonOf is a closed ring of n vertices around the fixture's square.
func polygonOf(n int) []any {
	ring := make([]any, 0, n+1)
	for k := range n {
		a := 2 * math.Pi * float64(k) / float64(n)
		ring = append(ring, []any{math.Round((44.81+0.01*math.Cos(a))*1e7) / 1e7, math.Round((41.71+0.01*math.Sin(a))*1e7) / 1e7})
	}
	return []any{append(ring, ring[0])}
}

func names(p *ed269.Problems) string {
	if p == nil {
		return ""
	}
	var out []string
	for _, x := range p.List {
		out = append(out, x.Field+": "+x.Reason)
	}
	return strings.Join(out, "\n")
}

// Every refusal beside the accepted DAR feature it differs from in one
// thing (E-01). The ANSP's DAR + 4 base-36 identifier is accepted; one
// of 8 characters is refused by the parse at its path.
func TestValidateRestriction(t *testing.T) {
	cases := []struct {
		name   string
		edit   func(f obj)
		win    *RestrictionWindow
		field  string // "" accepts
		phrase string
	}{
		{name: "the DAR feature", edit: func(obj) {}},
		{name: "DAR with another reason", edit: func(f obj) { darProps(f)["reason"] = []any{"EMERGENCY", "DAR"} }},
		{name: "REQ_AUTHORIZATION", edit: func(f obj) { darProps(f)["type"] = "REQ_AUTHORIZATION" }},
		{name: "CONDITIONAL", edit: func(f obj) { darProps(f)["type"] = "CONDITIONAL" }},
		{name: "a 7-character identifier other than DAR", edit: func(f obj) { darProps(f)["identifier"] = "ZZ00009" }},
		{name: "a clock-time schedule", edit: func(f obj) {
			darProps(f)["limitedApplicability"].([]any)[0].(obj)["schedule"] = []any{obj{"day": []any{"ANY"}, "startTime": "12:00:00Z", "endTime": "13:00:00Z"}}
		}},
		{name: "the period written with an offset", edit: func(f obj) {
			darProps(f)["limitedApplicability"].([]any)[0].(obj)["startDateTime"] = "2026-10-02T16:00:00+04:00"
		}},
		{name: "1000 vertices", edit: func(f obj) { f["geometry"].(obj)["coordinates"] = polygonOf(1000) }},
		{name: "another extendedProperties member", edit: func(f obj) { darProps(f)["extendedProperties"] = obj{"source": "ansp"} }},

		{name: "a reason without DAR", edit: func(f obj) { darProps(f)["reason"] = []any{"EMERGENCY"} }, field: "feature.properties.reason", phrase: "DAR"},
		{name: "NO_RESTRICTION", edit: func(f obj) { darProps(f)["type"] = "NO_RESTRICTION" }, field: "feature.properties.type", phrase: "opens airspace"},
		{name: "USPACE", edit: func(f obj) { darProps(f)["type"] = "USPACE" }, field: "feature.properties.type", phrase: "PROHIBITED, REQ_AUTHORIZATION or CONDITIONAL"},
		{name: "an 8-character identifier", edit: func(f obj) { darProps(f)["identifier"] = "DAR1A2BC" }, field: "feature.properties.identifier"},
		{name: "no limitedApplicability", edit: func(f obj) { delete(darProps(f), "limitedApplicability") }, field: "feature.properties.limitedApplicability", phrase: "is required"},
		{name: "two periods", edit: func(f obj) {
			p := darProps(f)["limitedApplicability"].([]any)
			darProps(f)["limitedApplicability"] = append(p, p[0])
		}, field: "feature.properties.limitedApplicability", phrase: "exactly one"},
		{name: "a start not equal to starts_at", edit: func(f obj) {
			darProps(f)["limitedApplicability"].([]any)[0].(obj)["startDateTime"] = darStart.Add(time.Second).Format(time.RFC3339)
		}, field: "feature.properties.limitedApplicability[0].startDateTime", phrase: "same instant"},
		{name: "an end not equal to ends_at", edit: func(f obj) {
			darProps(f)["limitedApplicability"].([]any)[0].(obj)["endDateTime"] = darEnd.Add(-time.Second).Format(time.RFC3339)
		}, field: "feature.properties.limitedApplicability[0].endDateTime", phrase: "ends_at"},
		{name: "no start", edit: func(f obj) {
			delete(darProps(f)["limitedApplicability"].([]any)[0].(obj), "startDateTime")
		}, field: "feature.properties.limitedApplicability[0].startDateTime", phrase: "is required"},
		{name: "the window of the body differs", edit: func(obj) {}, win: &RestrictionWindow{StartsAt: darStart, EndsAt: darEnd.Add(time.Hour)},
			field: "feature.properties.limitedApplicability[0].endDateTime", phrase: "ends_at"},
		{name: "a daylight start event", edit: func(f obj) {
			darProps(f)["limitedApplicability"].([]any)[0].(obj)["schedule"] = []any{obj{"day": []any{"ANY"}, "startEvent": "SR", "endTime": "13:00:00Z"}}
		}, field: "feature.properties.limitedApplicability[0].schedule[0].startEvent", phrase: "daylight"},
		{name: "a daylight end event", edit: func(f obj) {
			darProps(f)["limitedApplicability"].([]any)[0].(obj)["schedule"] = []any{obj{"day": []any{"ANY"}, "startTime": "08:00:00Z", "endEvent": "SS"}}
		}, field: "feature.properties.limitedApplicability[0].schedule[0].endEvent", phrase: "daylight"},
		{name: "1001 vertices", edit: func(f obj) { f["geometry"].(obj)["coordinates"] = polygonOf(1001) }, field: "feature.geometry", phrase: "1001 vertices"},
		{name: "a cis_restriction member from the publisher", edit: func(f obj) {
			darProps(f)["extendedProperties"] = obj{"cis_restriction": obj{"state": "active"}}
		}, field: "feature.properties.extendedProperties.cis_restriction", phrase: "written by the CISP"},
		{name: "a geometry ed318 refuses", edit: func(f obj) { f["geometry"].(obj)["coordinates"] = []any{[]any{[]any{44.8, 41.7}}} }, field: "feature.geometry"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := darFeature("DAR1A2B")
			c.edit(f)
			w := darWin
			if c.win != nil {
				w = *c.win
			}
			acc, probs := ValidateRestriction(raw(t, f), w, ed318.Limits{})
			if c.field == "" {
				if probs != nil {
					t.Fatalf("refused:\n%s", names(probs))
				}
				if acc.Feature == nil || acc.Row.ID != darProps(f)["identifier"] || len(acc.Row.Geom) != 1 {
					t.Fatalf("accepted %+v", acc)
				}
				return
			}
			if probs == nil {
				t.Fatal("accepted")
			}
			for _, p := range probs.List {
				if strings.HasPrefix(p.Field, c.field) && strings.Contains(p.Reason, c.phrase) {
					return
				}
			}
			t.Fatalf("no problem at %s with %q:\n%s", c.field, c.phrase, names(probs))
		})
	}
}

// The feature member absent, null, or not an object.
func TestValidateRestrictionNotAFeature(t *testing.T) {
	for name, body := range map[string]string{"absent": "", "null": "null", "an array": "[1]", "a string": `"DAR"`} {
		_, probs := ValidateRestriction(json.RawMessage(body), darWin, ed318.Limits{})
		if probs == nil || probs.List[0].Field != "feature" {
			t.Errorf("%s: %s", name, names(probs))
		}
	}
	// A feature that is not an ED-318 feature at all names its paths
	// under feature.
	_, probs := ValidateRestriction(json.RawMessage(`{"type":"Feature"}`), darWin, ed318.Limits{})
	if probs == nil || !strings.HasPrefix(probs.List[0].Field, "feature") {
		t.Errorf("bare feature: %s", names(probs))
	}
}

// The parse's problems are capped and counted like a publication's.
func TestValidateRestrictionProblemCap(t *testing.T) {
	f := darFeature("DAR1A2B")
	darProps(f)["reason"] = []any{"EMERGENCY"}
	darProps(f)["type"] = "NO_RESTRICTION"
	_, probs := ValidateRestriction(raw(t, f), darWin, ed318.Limits{MaxProblems: 1})
	if probs == nil || len(probs.List) != 1 || probs.Truncated != 1 {
		t.Fatalf("capped: %+v", probs)
	}
}

func TestRebaseFeature(t *testing.T) {
	for in, want := range map[string]string{
		"features[0].properties.identifier": "feature.properties.identifier",
		"features[0]":                       "feature",
		"features":                          "feature",
		"$":                                 "feature",
	} {
		if got := rebaseFeature(in); got != want {
			t.Errorf("%s -> %s, want %s", in, got, want)
		}
	}
}

// The placement: the F3548 area at its bound, the airspace unknown, and
// the outline outside it; each beside the accepted placement.
func TestCheckPlacement(t *testing.T) {
	ok := Placement{AreaM2: 4e6, AirspaceCurrent: true, Intersects: true}
	if p := CheckPlacement(ok, "TSU001"); p != nil {
		t.Fatalf("accepted placement refused: %s", names(p))
	}
	if p := CheckPlacement(Placement{AreaM2: MaxRestrictionAreaM2, AirspaceCurrent: true, Intersects: true}, "TSU001"); p != nil {
		t.Errorf("exactly 10 000 km2: %s", names(p))
	}
	for name, c := range map[string]struct {
		p      Placement
		field  string
		phrase string
	}{
		"over 10 000 km2":   {Placement{AreaM2: MaxRestrictionAreaM2 + 1e6, AirspaceCurrent: true, Intersects: true}, "feature.geometry", "CstrMaxAreaKm2"},
		"unknown airspace":  {Placement{AreaM2: 4e6}, "uspace_airspace_id", "not a feature of the current uspace_airspace"},
		"outside airspace":  {Placement{AreaM2: 4e6, AirspaceCurrent: true}, "uspace_airspace_id", "entirely outside"},
		"unknown and large": {Placement{AreaM2: 2 * MaxRestrictionAreaM2}, "feature.geometry", "km2"},
	} {
		p := CheckPlacement(c.p, "TSU001")
		if p == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		found := false
		for _, x := range p.List {
			found = found || (x.Field == c.field && strings.Contains(x.Reason, c.phrase))
		}
		if !found {
			t.Errorf("%s: %s", name, names(p))
		}
	}
	if MaxRestrictionAreaM2 != 10_000*1e6 || MaxRestrictionVertices != 1000 {
		t.Errorf("the F3548 limits changed: %v %v", MaxRestrictionAreaM2, MaxRestrictionVertices)
	}
}
