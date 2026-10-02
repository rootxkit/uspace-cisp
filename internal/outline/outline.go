// Package outline draws an ED-318 circle (a Point with extent.radius) as
// a polygon a map can render: the extendedProperties.cis_display_geometry
// member of a filtered read (docs/PLAN.md section 15 Q43).
//
// It is a drawing, never a judgement: consumers judge a circle as a
// circle through uspace-core (zones, ed318.ToZones), and nothing in the
// CISP tests a position against the outline. Every vertex is placed on
// the geodesic circle by uspace-core's geodesy: a tangent-plane first
// guess (geodesy.LocalOffsetM) refined until geodesy.Inverse (Vincenty on
// WGS84) puts it at the published radius on its azimuth.
//
// Pure: no I/O, no logging, no global state.
package outline

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed318"
	"github.com/rootxkit/uspace-core/geodesy"
)

// Member is the extendedProperties member a filtered read writes.
const Member = "cis_display_geometry"

// Vertices is the number of distinct vertices of a drawn circle. A
// display resolution, not a threshold: at 64 the chord between two
// vertices lies within 0.12 % of the radius inside the circle.
const Vertices = 64

const (
	// toleranceM is how close to its target (radius and azimuth, as an
	// offset on the ground) a vertex must come before it is placed.
	toleranceM = 1e-4
	// maxSteps bounds the refinement; a circle that does not settle is
	// an error, never a guess.
	maxSteps = 30
	// maxRadiusM bounds the circles drawn: the tangent-plane first guess
	// and its correction are made for zone sizes, not continents.
	maxRadiusM = 1_000_000
	// maxAbsLatDeg keeps the centre off the poles, where a degree of
	// longitude has no length.
	maxAbsLatDeg = 89
	// decimals is the precision of a written position: 1e-8 degree,
	// about a millimetre.
	decimals = 1e8
	// stepDeg is the offset used to read the local metres per degree.
	stepDeg = 1e-3
)

// ErrNoConvergence is returned when a vertex does not settle on the circle.
var ErrNoConvergence = errors.New("outline: a vertex did not settle on the circle")

// Ring is the closed ring of n vertices on the geodesic circle about
// centre: counterclockwise (RFC 7946 section 3.1.6), starting due north,
// the last position equal to the first.
func Ring(centre core.LatLon, radiusM float64, n int) ([]core.LatLon, error) {
	switch {
	case !centre.Valid():
		return nil, core.Fieldf("center", "not a valid WGS84 position (lat_deg %v, lon_deg %v)", centre.LatDeg, centre.LonDeg)
	case math.Abs(centre.LatDeg) > maxAbsLatDeg:
		return nil, core.Fieldf("center", "latitude %v is beyond %v degrees", centre.LatDeg, float64(maxAbsLatDeg))
	case math.IsNaN(radiusM) || radiusM <= 0 || radiusM > maxRadiusM:
		return nil, core.Fieldf("radius", "%v m is not in (0, %v]", radiusM, float64(maxRadiusM))
	case n < 3:
		return nil, core.Fieldf("vertices", "%d is fewer than 3", n)
	}
	mLat, mLon := metresPerDegree(centre)
	ring := make([]core.LatLon, 0, n+1)
	for k := range n {
		// Counterclockwise: azimuths decrease from north through west.
		azDeg := math.Mod(360-360*float64(k)/float64(n), 360)
		p, err := vertex(centre, radiusM, azDeg, mLat, mLon)
		if err != nil {
			return nil, err
		}
		ring = append(ring, p)
	}
	return append(ring, ring[0]), nil
}

// metresPerDegree reads the local scale at p from geodesy.LocalOffsetM.
func metresPerDegree(p core.LatLon) (perDegLat, perDegLon float64) {
	north, _ := geodesy.LocalOffsetM(p, core.LatLon{LatDeg: p.LatDeg + stepDeg, LonDeg: p.LonDeg})
	_, east := geodesy.LocalOffsetM(p, core.LatLon{LatDeg: p.LatDeg, LonDeg: p.LonDeg + stepDeg})
	return north / stepDeg, east / stepDeg
}

// vertex is the point at radiusM from centre on azimuth azDeg: refined
// until the geodesic from centre (geodesy.Inverse) ends within toleranceM
// of the target offset, then rounded to the written precision.
func vertex(centre core.LatLon, radiusM, azDeg, mLat, mLon float64) (core.LatLon, error) {
	az := azDeg * math.Pi / 180
	wantN, wantE := radiusM*math.Cos(az), radiusM*math.Sin(az)
	p := core.LatLon{LatDeg: centre.LatDeg + wantN/mLat, LonDeg: core.WrapLonDeg(centre.LonDeg + wantE/mLon)}
	for range maxSteps {
		d, bearing, _, err := geodesy.Inverse(centre, p)
		if err != nil {
			return core.LatLon{}, fmt.Errorf("outline: azimuth %v: %w", azDeg, err)
		}
		b := bearing * math.Pi / 180
		errN, errE := wantN-d*math.Cos(b), wantE-d*math.Sin(b)
		if math.Hypot(errN, errE) < toleranceM {
			return core.LatLon{
				LatDeg: math.Round(p.LatDeg*decimals) / decimals,
				LonDeg: math.Round(p.LonDeg*decimals) / decimals,
			}, nil
		}
		pLat, pLon := metresPerDegree(p)
		p = core.LatLon{LatDeg: p.LatDeg + errN/pLat, LonDeg: core.WrapLonDeg(p.LonDeg + errE/pLon)}
	}
	return core.LatLon{}, fmt.Errorf("%w (azimuth %v)", ErrNoConvergence, azDeg)
}

// geoJSON is a written geometry: a Polygon, or a GeometryCollection of
// them. It carries no ED-318 layer: a drawing has no vertical extent, and
// the limits stay in the published geometry.
type geoJSON struct {
	Type        string         `json:"type"`
	Coordinates [][][2]float64 `json:"coordinates,omitempty"`
	Geometries  []geoJSON      `json:"geometries,omitempty"`
}

// Display is the drawable geometry of g when g holds a circle: the circle
// as its polygon (Vertices vertices), alone or in a GeometryCollection
// with the other parts as published. ok is false when g has no circle:
// the published geometry is already drawable and nothing is written.
func Display(g ed318.Geometry) (raw json.RawMessage, ok bool, err error) {
	if !hasCircle(g) {
		return nil, false, nil
	}
	out, err := drawable(g)
	if err != nil {
		return nil, false, err
	}
	raw, err = json.Marshal(out)
	if err != nil {
		return nil, false, err
	}
	return raw, true, nil
}

func hasCircle(g ed318.Geometry) bool {
	if g.Center != nil && g.RadiusM != nil {
		return true
	}
	for i := range g.Geometries {
		if hasCircle(g.Geometries[i]) {
			return true
		}
	}
	return false
}

func drawable(g ed318.Geometry) (geoJSON, error) {
	switch {
	case g.Center != nil && g.RadiusM != nil:
		ring, err := Ring(*g.Center, *g.RadiusM, Vertices)
		if err != nil {
			return geoJSON{}, err
		}
		return geoJSON{Type: "Polygon", Coordinates: [][][2]float64{positions(ring)}}, nil
	case len(g.Geometries) > 0:
		parts := make([]geoJSON, 0, len(g.Geometries))
		for i := range g.Geometries {
			p, err := drawable(g.Geometries[i])
			if err != nil {
				return geoJSON{}, err
			}
			parts = append(parts, p)
		}
		return geoJSON{Type: "GeometryCollection", Geometries: parts}, nil
	default:
		rings := make([][][2]float64, 0, len(g.Rings))
		for _, r := range g.Rings {
			rings = append(rings, positions(r))
		}
		return geoJSON{Type: "Polygon", Coordinates: rings}, nil
	}
}

// positions writes a ring in GeoJSON order, [longitude, latitude].
func positions(r []core.LatLon) [][2]float64 {
	out := make([][2]float64, len(r))
	for i, p := range r {
		out[i] = [2]float64{p.LonDeg, p.LatDeg}
	}
	return out
}
