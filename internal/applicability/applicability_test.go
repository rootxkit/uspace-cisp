package applicability

import (
	"errors"
	"math"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed318"
)

func dt(t *testing.T, s string) *ed318.DateTime {
	t.Helper()
	at, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return &ed318.DateTime{Time: at, Text: s}
}

func str(s string) *string { return &s }

// square is a closed ring of side d degrees with its south-west corner
// at (lat, lon).
func square(lat, lon, d float64) []core.LatLon {
	return []core.LatLon{{LatDeg: lat, LonDeg: lon}, {LatDeg: lat, LonDeg: lon + d}, {LatDeg: lat + d, LonDeg: lon + d}, {LatDeg: lat + d, LonDeg: lon}, {LatDeg: lat, LonDeg: lon}}
}

func zone(g ed318.Geometry, periods ...ed318.TimePeriod) *ed318.Feature {
	return &ed318.Feature{Type: "Feature", Geometry: g, Properties: ed318.UASZone{Identifier: "TST001", LimitedApplicability: periods}}
}

func tbilisi() ed318.Geometry {
	return ed318.Geometry{Type: ed318.GeometryPolygon, Rings: [][]core.LatLon{square(41.70, 44.80, 0.02)}}
}

// A window applies inside and not outside (E-01: the refusal beside the
// acceptance); no periods at all applies always.
func TestAtWindow(t *testing.T) {
	window := ed318.TimePeriod{StartDateTime: dt(t, "2026-10-01T07:00:00Z"), EndDateTime: dt(t, "2026-10-01T10:00:00+02:00")}
	f := zone(tbilisi(), window)
	cases := []struct {
		at   string
		want Verdict
	}{
		{"2026-10-01T06:59:59Z", DoesNotApply},
		{"2026-10-01T07:00:00Z", Applies},
		{"2026-10-01T08:00:00Z", Applies},
		{"2026-10-01T12:00:01+04:00", DoesNotApply},
	}
	for _, c := range cases {
		at, _ := time.Parse(time.RFC3339, c.at)
		got, err := At(f, at, ed318.NOAADaylight{})
		if err != nil || got != c.want {
			t.Errorf("At(%s) = %v, %v; want %v", c.at, got, err, c.want)
		}
	}
	if got, err := At(zone(tbilisi()), time.Now(), nil); got != Applies || err != nil {
		t.Errorf("no periods: %v %v", got, err)
	}
}

// A daylight schedule at a polar latitude in polar night cannot be
// evaluated: Unknown with core's ErrNoEvent, never DoesNotApply. The same
// schedule at Tbilisi is evaluated both ways.
func TestAtDaylightUnknownAtThePole(t *testing.T) {
	daylight := ed318.TimePeriod{Schedule: []ed318.DailyPeriod{{Day: []string{"ANY"}, StartEvent: str(ed318.EventSR), EndEvent: str(ed318.EventSS)}}}
	polar := zone(ed318.Geometry{Type: ed318.GeometryPolygon, Rings: [][]core.LatLon{square(78.20, 15.60, 0.05)}}, daylight)
	winterNoon := time.Date(2026, 12, 21, 12, 0, 0, 0, time.UTC)
	got, err := At(polar, winterNoon, ed318.NOAADaylight{})
	if got != Unknown || !errors.Is(err, ed318.ErrNoEvent) {
		t.Errorf("polar night: %v %v", got, err)
	}
	if got.Annotation() != AnnotationUnknown {
		t.Errorf("annotation %q", got.Annotation())
	}
	tb := zone(tbilisi(), daylight)
	noon := time.Date(2026, 6, 21, 8, 0, 0, 0, time.UTC) // 12:00 at +04:00
	midnight := time.Date(2026, 6, 21, 20, 0, 0, 0, time.UTC)
	if got, err := At(tb, noon, ed318.NOAADaylight{}); got != Applies || err != nil {
		t.Errorf("Tbilisi noon: %v %v", got, err)
	}
	if got, err := At(tb, midnight, ed318.NOAADaylight{}); got != DoesNotApply || err != nil {
		t.Errorf("Tbilisi midnight: %v %v", got, err)
	}
	// No daylight source: the events cannot be resolved.
	if got, err := At(tb, midnight, nil); got != Unknown || err == nil {
		t.Errorf("no daylight source: %v %v", got, err)
	}
	// No place: a feature without geometry cannot resolve its events.
	if got, err := At(zone(ed318.Geometry{}, daylight), midnight, ed318.NOAADaylight{}); got != Unknown || err == nil {
		t.Errorf("no place: %v %v", got, err)
	}
	if got, err := At(nil, noon, nil); got != Unknown || !errors.Is(err, ErrNoFeature) {
		t.Errorf("nil feature: %v %v", got, err)
	}
}

func TestVerdictAnnotations(t *testing.T) {
	for v, want := range map[Verdict]string{Applies: "applies", DoesNotApply: "not_applicable", Unknown: "unknown", Verdict(99): "unknown"} {
		if v.String() != want {
			t.Errorf("%d: %q, want %q", int(v), v.String(), want)
		}
	}
	var zero Verdict
	if zero != Unknown {
		t.Error("the zero verdict is not Unknown")
	}
}

func near(t *testing.T, name string, got, want float64) {
	t.Helper()
	if math.Abs(got-want) > 1e-7 {
		t.Errorf("%s = %.12f, want %.12f", name, got, want)
	}
}

func TestCentroid(t *testing.T) {
	c, ok := Centroid(tbilisi())
	if !ok {
		t.Fatal("no centroid")
	}
	near(t, "square lat", c.LatDeg, 41.71)
	near(t, "square lon", c.LonDeg, 44.81)

	// A hole in the north-east quarter pulls the centroid south-west, and
	// the winding of either ring does not matter.
	outer := square(0, 0, 4)
	hole := square(2, 2, 2)
	reversed := []core.LatLon{hole[4], hole[3], hole[2], hole[1], hole[0]}
	for _, h := range [][]core.LatLon{hole, reversed} {
		c, ok := Centroid(ed318.Geometry{Type: ed318.GeometryPolygon, Rings: [][]core.LatLon{outer, h}})
		if !ok {
			t.Fatal("no centroid")
		}
		// The outer square weighs 16 at 2, the hole 4 at 3: 20 / 12.
		near(t, "holed lat", c.LatDeg, 5.0/3)
		near(t, "holed lon", c.LonDeg, 5.0/3)
	}

	r := 500.0
	circle := ed318.Geometry{Type: ed318.GeometryPoint, Center: &core.LatLon{LatDeg: 41.71, LonDeg: 44.81}, RadiusM: &r}
	if c, ok := Centroid(circle); !ok || c != *circle.Center {
		t.Errorf("circle: %v %v", c, ok)
	}

	// Two equal layers (ED-318's two-layer example) keep the centroid.
	coll := ed318.Geometry{Type: ed318.GeometryCollection, Geometries: []ed318.Geometry{tbilisi(), tbilisi()}}
	if c, ok := Centroid(coll); !ok {
		t.Error("collection: no centroid")
	} else {
		near(t, "collection lat", c.LatDeg, 41.71)
	}
	// A polygon and a far circle: weighed by area, between the two.
	mixed := ed318.Geometry{Type: ed318.GeometryCollection, Geometries: []ed318.Geometry{tbilisi(), circle}}
	if c, ok := Centroid(mixed); !ok || c.LatDeg != c.LatDeg {
		t.Errorf("mixed: %v %v", c, ok)
	}

	// A degenerate ring (a line): the mean of its positions.
	line := []core.LatLon{{LatDeg: 1, LonDeg: 1}, {LatDeg: 2, LonDeg: 2}, {LatDeg: 1, LonDeg: 1}}
	if c, ok := Centroid(ed318.Geometry{Type: ed318.GeometryPolygon, Rings: [][]core.LatLon{line}}); !ok {
		t.Error("degenerate: no centroid")
	} else {
		near(t, "degenerate lat", c.LatDeg, 4.0/3)
	}
	// Two zero-area parts: the mean of their centres.
	zero := 0.0
	dot := ed318.Geometry{Type: ed318.GeometryPoint, Center: &core.LatLon{LatDeg: 3, LonDeg: 3}, RadiusM: &zero}
	if c, ok := Centroid(ed318.Geometry{Type: ed318.GeometryCollection, Geometries: []ed318.Geometry{dot, {Type: ed318.GeometryPolygon, Rings: [][]core.LatLon{line}}}}); !ok {
		t.Error("zero-area parts: no centroid")
	} else {
		near(t, "zero-area lat", c.LatDeg, (3+4.0/3)/2)
	}

	// Nothing usable: no centroid, an invalid position.
	for name, g := range map[string]ed318.Geometry{
		"empty":           {},
		"empty ring":      {Type: ed318.GeometryPolygon, Rings: [][]core.LatLon{{}}},
		"invalid centre":  {Type: ed318.GeometryPoint, Center: &core.LatLon{LatDeg: 91, LonDeg: 0}, RadiusM: &r},
		"empty collation": {Type: ed318.GeometryCollection},
	} {
		if c, ok := Centroid(g); ok || c.Valid() {
			t.Errorf("%s: %v %v", name, c, ok)
		}
	}
}
