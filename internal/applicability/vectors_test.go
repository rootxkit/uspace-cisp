package applicability

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/ed269"
	"github.com/rootxkit/uspace-core/ed318"
	"github.com/rootxkit/uspace-core/vectors"
)

// zoneFromApplicability is an ED-318 zone around Tbilisi carrying an
// ED-269 applicability list, made the way a publisher migrating from
// ED-269 makes it: an ED-269 zone parsed by core and mapped by
// ed318.FromED269. The handler test publishes the same zone.
func zoneFromApplicability(t testing.TB, id string, applicability json.RawMessage) *ed318.FeatureCollection {
	t.Helper()
	zone := map[string]any{
		"identifier": id, "country": "GEO", "name": "Applicability vector " + id, "type": "COMMON",
		"restriction": "PROHIBITED", "reason": []any{"SENSITIVE"},
		"applicability": applicability,
		"zoneAuthority": []any{map[string]any{"name": "Test authority", "purpose": "AUTHORIZATION"}},
		"geometry": []any{map[string]any{
			"uomDimensions": "M", "lowerLimit": 0, "lowerVerticalReference": "AGL", "upperLimit": 120, "upperVerticalReference": "AGL",
			"horizontalProjection": map[string]any{"type": "Polygon", "coordinates": []any{[]any{
				[]any{44.80, 41.70}, []any{44.82, 41.70}, []any{44.82, 41.72}, []any{44.80, 41.72}, []any{44.80, 41.70},
			}}},
		}},
	}
	raw, err := json.Marshal(map[string]any{"features": []any{zone}})
	if err != nil {
		t.Fatal(err)
	}
	doc, probs := ed269.Parse(raw, ed269.Limits{})
	if probs != nil {
		t.Fatalf("ed269.Parse: %v", probs)
	}
	fc, err := ed318.FromED269(doc, ed318.Metadata{}, "en-GB")
	if err != nil {
		t.Fatalf("ed318.FromED269: %v", err)
	}
	return fc
}

// applicabilityCase is one zones_applicability.json case decoded.
type applicabilityCase struct {
	Applicability json.RawMessage
	At            time.Time
	Applies       bool
}

// decodeApplicabilityCase decodes c strictly; at is parsed as RFC 3339
// with its offset.
func decodeApplicabilityCase(t testing.TB, c vectors.Case) applicabilityCase {
	t.Helper()
	var in struct {
		Applicability json.RawMessage `json:"applicability"`
		At            string          `json:"at"`
	}
	var exp struct {
		Applies bool `json:"applies"`
	}
	c.Decode(t, &in, &exp)
	at, err := time.Parse(time.RFC3339Nano, in.At)
	if err != nil {
		t.Fatalf("at: %v", err)
	}
	return applicabilityCase{Applicability: in.Applicability, At: at, Applies: exp.Applies}
}

// TestVectorsZonesApplicability runs every zones_applicability.json case
// the cisp owns (32): the case's periods on a synthetic zone (mapped from
// ED-269 by core), At gives the expected verdict. internal/httpapi runs
// the same cases through GET /v1/zones?at=.
func TestVectorsZonesApplicability(t *testing.T) {
	f := vectors.Load(t, "zones_applicability.json")
	ran := 0
	f.RunOwned(t, "cisp", func(t *testing.T, c vectors.Case) {
		ran++
		vc := decodeApplicabilityCase(t, c)
		fc := zoneFromApplicability(t, "TAP001", vc.Applicability)
		got, err := At(&fc.Features[0], vc.At, ed318.NOAADaylight{})
		if err != nil {
			t.Fatalf("At: %v", err)
		}
		want := DoesNotApply
		if vc.Applies {
			want = Applies
		}
		if got != want {
			t.Errorf("At(%s) = %v, want %v", vc.At.Format(time.RFC3339), got, want)
		}
	})
	t.Logf("%d zones_applicability cases ran", ran)
}
