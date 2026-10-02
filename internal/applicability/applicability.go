// Package applicability answers whether an ED-318 zone applies at an
// instant, for the at= and applies_at= reads (docs/PLAN.md section 6.3,
// LESSONS T-09). It is a thin call into uspace-core's ed318.Applies: the
// judgement lives in core and is never re-implemented here. What this
// package adds is the place (the feature's centroid, where daylight
// events are resolved) and the third answer: a zone whose applicability
// cannot be evaluated is Unknown, never "does not apply", and the caller
// keeps it, marked (fail visible).
//
// It is pure: no database, no network, no logging. The caller counts an
// Unknown as applicability_unknown.
package applicability

import (
	"errors"
	"math"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed318"
)

// Verdict is the answer for one feature at one instant.
type Verdict int

// The verdicts. The zero value is Unknown, so a verdict nobody set is
// never read as "does not apply".
const (
	// Unknown: the applicability could not be evaluated (a daylight
	// event that does not occur that day, no place to resolve it at).
	Unknown Verdict = iota
	// Applies: the zone applies at the instant.
	Applies
	// DoesNotApply: the zone does not apply at the instant.
	DoesNotApply
)

// The annotations a read writes into extendedProperties.cis_applicability.
const (
	AnnotationApplies       = "applies"
	AnnotationNotApplicable = "not_applicable"
	AnnotationUnknown       = "unknown"
)

// Member is the extendedProperties member that carries the annotation.
const Member = "cis_applicability"

// Annotation is the cis_applicability value of v.
func (v Verdict) Annotation() string {
	switch v {
	case Applies:
		return AnnotationApplies
	case DoesNotApply:
		return AnnotationNotApplicable
	case Unknown:
		return AnnotationUnknown
	}
	return AnnotationUnknown
}

// String is the annotation.
func (v Verdict) String() string { return v.Annotation() }

// ErrNoFeature is returned (with Unknown) for a nil feature.
var ErrNoFeature = errors.New("applicability: no feature")

// At is whether f applies at the instant at: ed318.Applies over the
// feature's limitedApplicability, at its centroid (Centroid), with dl
// resolving daylight events. The instant is judged as the aware time it
// is (converted to UTC; T-09): a naive time cannot reach here, because
// the caller parses RFC 3339 with an offset. Any error from core is
// Unknown with that error; a nil feature is Unknown with ErrNoFeature.
func At(f *ed318.Feature, at time.Time, dl ed318.Daylight) (Verdict, error) {
	if f == nil {
		return Unknown, ErrNoFeature
	}
	// The place matters only to resolve daylight events; a feature
	// without a usable geometry passes an invalid place and core says
	// so if (and only if) it needs one.
	where, _ := Centroid(f.Geometry)
	return AtPlace(f.Properties.LimitedApplicability, at, where, dl)
}

// AtPlace is At for periods at a given place.
func AtPlace(periods []ed318.TimePeriod, at time.Time, where core.LatLon, dl ed318.Daylight) (Verdict, error) {
	ok, err := ed318.Applies(periods, at.UTC(), where, dl)
	switch {
	case err != nil:
		return Unknown, err
	case ok:
		return Applies, nil
	}
	return DoesNotApply, nil
}

// Degrees of latitude per metre on the mean sphere: only used to weigh
// a circle against polygons when a GeometryCollection mixes them.
const metresPerDegree = 111_320.0

// Centroid is the planar centroid of the geometry in longitude and
// latitude degrees, as PostGIS ST_Centroid computes it on the stored
// shape: a polygon's area centroid (outer ring less its holes), a
// circle's centre, and for a GeometryCollection the area-weighted mean
// of its parts (a circle weighed by its area in degrees). It only places
// the daylight events of ed318.Applies; it is never a judgement of where
// the zone is. false (and an invalid position) when the geometry has no
// usable part.
func Centroid(g ed318.Geometry) (core.LatLon, bool) {
	parts := []ed318.Geometry{g}
	if g.Type == ed318.GeometryCollection {
		parts = g.Geometries
	}
	var sumA, sumLat, sumLon float64
	var n int
	var meanLat, meanLon float64
	for i := range parts {
		c, area, ok := partCentroid(parts[i])
		if !ok {
			continue
		}
		n++
		meanLat += c.LatDeg
		meanLon += c.LonDeg
		sumA += area
		sumLat += area * c.LatDeg
		sumLon += area * c.LonDeg
	}
	if n == 0 {
		return core.LatLon{LatDeg: math.NaN(), LonDeg: math.NaN()}, false
	}
	var out core.LatLon
	if sumA > 0 {
		out = core.LatLon{LatDeg: sumLat / sumA, LonDeg: sumLon / sumA}
	} else {
		out = core.LatLon{LatDeg: meanLat / float64(n), LonDeg: meanLon / float64(n)}
	}
	return out, out.Valid()
}

// partCentroid is one part's centroid and area in square degrees.
func partCentroid(p ed318.Geometry) (core.LatLon, float64, bool) {
	if p.Center != nil {
		if !p.Center.Valid() {
			return core.LatLon{}, 0, false
		}
		area := 0.0
		if p.RadiusM != nil && *p.RadiusM > 0 && !math.IsInf(*p.RadiusM, 0) {
			rLat := *p.RadiusM / metresPerDegree
			rLon := rLat / math.Max(math.Cos(p.Center.LatDeg*math.Pi/180), 1e-9)
			area = math.Pi * rLat * rLon
		}
		return *p.Center, area, true
	}
	if len(p.Rings) == 0 {
		return core.LatLon{}, 0, false
	}
	var a, cx, cy float64
	for k, ring := range p.Rings {
		ra, rx, ry := ringMoments(ring)
		// The outer ring adds, holes take away, whatever their winding.
		want := 1.0
		if k > 0 {
			want = -1
		}
		ra, rx, ry = signed(ra, rx, ry, want)
		a += ra
		cx += rx
		cy += ry
	}
	if a <= 0 {
		// A degenerate polygon: the mean of its outer ring's positions.
		var lat, lon float64
		ring := p.Rings[0]
		if len(ring) == 0 {
			return core.LatLon{}, 0, false
		}
		for _, v := range ring {
			lat += v.LatDeg
			lon += v.LonDeg
		}
		c := core.LatLon{LatDeg: lat / float64(len(ring)), LonDeg: lon / float64(len(ring))}
		return c, 0, c.Valid()
	}
	c := core.LatLon{LatDeg: cy / a, LonDeg: cx / a}
	return c, a, c.Valid()
}

// signed returns the moments with the sign that makes the area take the
// sign of want (+1 for an outer ring, -1 for a hole).
func signed(a, x, y, want float64) (float64, float64, float64) {
	if (a < 0) != (want < 0) {
		return -a, -x, -y
	}
	return a, x, y
}

// ringMoments is the shoelace area of a ring (x = longitude, y =
// latitude) and its first moments (area times centroid).
func ringMoments(ring []core.LatLon) (area, mx, my float64) {
	n := len(ring)
	if n < 3 {
		return 0, 0, 0
	}
	for i := range n {
		p, q := ring[i], ring[(i+1)%n]
		cross := p.LonDeg*q.LatDeg - q.LonDeg*p.LatDeg
		area += cross
		mx += (p.LonDeg + q.LonDeg) * cross
		my += (p.LatDeg + q.LatDeg) * cross
	}
	return area / 2, mx / 6, my / 6
}
