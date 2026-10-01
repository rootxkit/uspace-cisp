package publication

import (
	"math"
	"time"

	"github.com/rootxkit/uspace-core/geodesy"
)

// Change is one change record (the changes table, the body of
// cis/change/v1): a dataset version and what it touched.
type Change struct {
	// ID is the change cursor, set by the store when the row is written.
	ID      int64
	Dataset Dataset
	Version int64
	// FeatureIDs is every identifier added, changed or removed, sorted.
	FeatureIDs []string
	// RemovedIDs is the identifiers removed, sorted.
	RemovedIDs []string
	Reason     Reason
	At         time.Time
	// BBox is the union bounding box of the touched features; nil is the
	// whole dataset (or nothing touched).
	BBox *geodesy.BBox
}

// ChangeOf is the change record of a version. rows should hold the
// previous and the next rows together, so that the box covers a changed
// feature where it was and where it is, and a removed one where it was.
func ChangeOf(dataset Dataset, version int64, d Diff, rows []FeatureRow, reason Reason, at time.Time) Change {
	c := Change{
		Dataset:    dataset,
		Version:    version,
		FeatureIDs: d.IDs(),
		RemovedIDs: append([]string{}, d.Removed...),
		Reason:     reason,
		At:         at.UTC(),
	}
	touched := make(map[string]bool, len(c.FeatureIDs))
	for _, id := range c.FeatureIDs {
		touched[id] = true
	}
	var box *geodesy.BBox
	for i := range rows {
		if !touched[rows[i].ID] {
			continue
		}
		for _, p := range rows[i].Geom {
			b, ok := partBBox(p)
			if !ok {
				continue
			}
			box = union(box, b)
		}
	}
	c.BBox = box
	return c
}

// partBBox is core's bounding box of one part; false for a part with no
// usable geometry.
func partBBox(p GeomPart) (geodesy.BBox, bool) {
	var b geodesy.BBox
	switch {
	case p.Circle():
		b = geodesy.Circle{Center: *p.Center, RadiusM: *p.RadiusM}.BBox()
	case len(p.Rings) > 0:
		rings := make([]geodesy.Ring, 0, len(p.Rings))
		for _, r := range p.Rings {
			rings = append(rings, geodesy.Ring(r))
		}
		b = geodesy.Polygon{Rings: rings}.BBox()
	default:
		return b, false
	}
	if !(b.MinLat <= b.MaxLat) || !(b.MinLon <= b.MaxLon) {
		return b, false // empty, or across the antimeridian (refused by ed318.Parse)
	}
	return b, true
}

func union(a *geodesy.BBox, b geodesy.BBox) *geodesy.BBox {
	if a == nil {
		return &b
	}
	return &geodesy.BBox{
		MinLat: math.Min(a.MinLat, b.MinLat),
		MinLon: math.Min(a.MinLon, b.MinLon),
		MaxLat: math.Max(a.MaxLat, b.MaxLat),
		MaxLon: math.Max(a.MaxLon, b.MaxLon),
	}
}
