package outline

import (
	"encoding/json"
	"errors"
	"math"
	"testing"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed318"
	"github.com/rootxkit/uspace-core/geodesy"
)

// radiusToleranceM is how far from the published radius a written vertex
// may lie, measured by geodesy.Inverse: geodesy.Destination agrees with
// it to under 0.1 mm and the 1e-8 degree rounding adds about a
// millimetre.
const radiusToleranceM = 0.005

func checkRing(t *testing.T, centre core.LatLon, radiusM float64, ring []core.LatLon, n int) {
	t.Helper()
	if len(ring) != n+1 {
		t.Fatalf("ring has %d positions, want %d (closed)", len(ring), n+1)
	}
	if ring[0] != ring[n] {
		t.Fatalf("ring not closed: %v != %v", ring[0], ring[n])
	}
	prev := math.Inf(1)
	for i, p := range ring[:n] {
		d, az, _, err := geodesy.Inverse(centre, p)
		if err != nil {
			t.Fatalf("vertex %d: %v", i, err)
		}
		if math.Abs(d-radiusM) > radiusToleranceM {
			t.Errorf("vertex %d at %.4f m, want %v m within %v m", i, d, radiusM, radiusToleranceM)
		}
		wantAz := math.Mod(360-360*float64(i)/float64(n), 360)
		// The azimuth error as a distance along the circle, against the
		// same tolerance as the radius.
		if offM := radiusM * math.Abs(math.Remainder(az-wantAz, 360)) * math.Pi / 180; offM > radiusToleranceM {
			t.Errorf("vertex %d on azimuth %.6f, want %.6f (%.4f m off)", i, az, wantAz, offM)
		}
		// Counterclockwise: the azimuth falls from one vertex to the next.
		if i > 1 && az >= prev {
			t.Errorf("vertex %d azimuth %.4f does not fall after %.4f", i, az, prev)
		}
		prev = az
	}
}

func TestRingVerticesSitOnTheGeodesicCircle(t *testing.T) {
	cases := []struct {
		name    string
		centre  core.LatLon
		radiusM float64
	}{
		{"ed318 TSD001", core.LatLon{LatDeg: 41.7151, LonDeg: 44.8271}, 1500},
		{"ed318 TSN001, fractional radius", core.LatLon{LatDeg: 41.75, LonDeg: 44.9}, 250.5},
		{"one metre", core.LatLon{LatDeg: 41.7, LonDeg: 44.8}, 1},
		{"100 km", core.LatLon{LatDeg: 41.7, LonDeg: 44.8}, 100_000},
		{"far north", core.LatLon{LatDeg: 78.2, LonDeg: 15.6}, 5000},
		{"southern hemisphere", core.LatLon{LatDeg: -33.9, LonDeg: 151.2}, 3000},
		{"across the antimeridian", core.LatLon{LatDeg: 65, LonDeg: 179.99}, 2000},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ring, err := Ring(c.centre, c.radiusM, Vertices)
			if err != nil {
				t.Fatal(err)
			}
			checkRing(t, c.centre, c.radiusM, ring, Vertices)
		})
	}
}

func TestRingRefusesWhatItCannotDraw(t *testing.T) {
	ok := core.LatLon{LatDeg: 41.7, LonDeg: 44.8}
	for _, c := range []struct {
		name    string
		centre  core.LatLon
		radiusM float64
		n       int
		field   string
	}{
		{"zero radius", ok, 0, Vertices, "radius"},
		{"negative radius", ok, -1, Vertices, "radius"},
		{"NaN radius", ok, math.NaN(), Vertices, "radius"},
		{"radius past the bound", ok, maxRadiusM + 1, Vertices, "radius"},
		{"at the pole", core.LatLon{LatDeg: 89.5, LonDeg: 0}, 100, Vertices, "center"},
		{"invalid centre", core.LatLon{LatDeg: 91, LonDeg: 0}, 100, Vertices, "center"},
		{"two vertices", ok, 100, 2, "vertices"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := Ring(c.centre, c.radiusM, c.n)
			var fe *core.FieldError
			if !errors.As(err, &fe) || fe.Field != c.field {
				t.Fatalf("err = %v, want a field error on %q", err, c.field)
			}
		})
	}
	// The accepted twins at the bounds (E-01).
	if _, err := Ring(ok, maxRadiusM, Vertices); err != nil {
		t.Errorf("radius at the bound: %v", err)
	}
	if _, err := Ring(core.LatLon{LatDeg: 89, LonDeg: 0}, 100, 3); err != nil {
		t.Errorf("latitude at the bound, three vertices: %v", err)
	}
}

func parseOne(t *testing.T, geometry string) ed318.Geometry {
	t.Helper()
	doc := `{"type":"FeatureCollection","features":[{"type":"Feature","geometry":` + geometry +
		`,"properties":{"identifier":"T1","country":"GEO","type":"PROHIBITED","variant":"COMMON","zoneAuthority":[{"purpose":"INFORMATION"}]}}]}`
	fc, probs := ed318.Parse([]byte(doc), ed318.Limits{})
	if probs != nil {
		t.Fatalf("fixture does not parse: %v", probs)
	}
	return fc.Features[0].Geometry
}

type written struct {
	Type        string          `json:"type"`
	Coordinates [][][2]float64  `json:"coordinates"`
	Geometries  []written       `json:"geometries"`
	Layer       json.RawMessage `json:"layer"`
}

func TestDisplayDrawsACircleAsItsPolygon(t *testing.T) {
	g := parseOne(t, `{"type":"Point","coordinates":[44.8271,41.7151],"extent":{"subType":"Circle","radius":1500},"layer":{"lower":0,"lowerReference":"AGL","upper":2500,"upperReference":"AMSL","uom":"ft"}}`)
	raw, ok, err := Display(g)
	if err != nil || !ok {
		t.Fatalf("Display = %v, %v", ok, err)
	}
	var w written
	if err := json.Unmarshal(raw, &w); err != nil {
		t.Fatal(err)
	}
	if w.Type != "Polygon" || len(w.Coordinates) != 1 || w.Layer != nil {
		t.Fatalf("got %s", raw)
	}
	ring := make([]core.LatLon, 0, len(w.Coordinates[0]))
	for _, p := range w.Coordinates[0] {
		ring = append(ring, core.LatLon{LatDeg: p[1], LonDeg: p[0]})
	}
	checkRing(t, core.LatLon{LatDeg: 41.7151, LonDeg: 44.8271}, 1500, ring, Vertices)
}

func TestDisplayDrawsTheCirclesOfACollection(t *testing.T) {
	g := parseOne(t, `{"type":"GeometryCollection","geometries":[`+
		`{"type":"Polygon","coordinates":[[[44.85,41.73],[44.87,41.73],[44.87,41.75],[44.85,41.73]]],"layer":{"lower":0,"lowerReference":"AGL","upper":50,"upperReference":"AGL"}},`+
		`{"type":"Point","coordinates":[44.86,41.74],"extent":{"subType":"Circle","radius":300},"layer":{"lower":50,"lowerReference":"AGL","upper":150,"upperReference":"AGL"}}]}`)
	raw, ok, err := Display(g)
	if err != nil || !ok {
		t.Fatalf("Display = %v, %v", ok, err)
	}
	var w written
	if err := json.Unmarshal(raw, &w); err != nil {
		t.Fatal(err)
	}
	if w.Type != "GeometryCollection" || len(w.Geometries) != 2 {
		t.Fatalf("got %s", raw)
	}
	if got := w.Geometries[0].Coordinates[0]; len(got) != 4 || got[1] != [2]float64{44.87, 41.73} {
		t.Errorf("the polygon part is not as published: %v", got)
	}
	if got := len(w.Geometries[1].Coordinates[0]); got != Vertices+1 {
		t.Errorf("the circle part has %d positions, want %d", got, Vertices+1)
	}
}

func TestDisplayWritesNothingForAPolygon(t *testing.T) {
	g := parseOne(t, `{"type":"Polygon","coordinates":[[[44.7,41.65],[44.95,41.65],[44.95,41.8],[44.7,41.65]]]}`)
	raw, ok, err := Display(g)
	if err != nil || ok || raw != nil {
		t.Fatalf("Display = %s, %v, %v; want nothing", raw, ok, err)
	}
}

func TestDisplayPassesARefusalOn(t *testing.T) {
	g := parseOne(t, `{"type":"Point","coordinates":[0,89.5],"extent":{"subType":"Circle","radius":100}}`)
	if _, ok, err := Display(g); err == nil || ok {
		t.Fatalf("Display = %v, %v; want the centre refused", ok, err)
	}
}
