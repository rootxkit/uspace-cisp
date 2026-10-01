package publication

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed318"
)

// MaxFeaturesPerPublication bounds one collection (E-10): a larger one is
// refused by Rows, never truncated.
const MaxFeaturesPerPublication = 50_000

// GeomPart is one geometry part of a feature as published: a polygon
// (Rings, exterior first) or a circle (Center and RadiusM). It is input
// for the store's SQL, which builds the drawing and prefilter shape; no
// shape is computed in Go.
type GeomPart struct {
	Rings   [][]core.LatLon
	Center  *core.LatLon
	RadiusM *float64
}

// Circle reports whether the part is a circle.
func (g GeomPart) Circle() bool { return g.Center != nil && g.RadiusM != nil }

// FeatureRow is one feature of a dataset version.
type FeatureRow struct {
	// ID is the ED-318 identifier.
	ID string
	// Canonical is the feature as published: ed318.Export's JSON of the
	// feature, compact, every object's keys sorted.
	Canonical []byte
	// SHA256 is the hash of Canonical.
	SHA256 [32]byte
	// Geom is every geometry part as published.
	Geom []GeomPart
	// Centroid is filled by the store from ST_Centroid when it reads rows
	// back; Rows leaves it zero.
	Centroid core.LatLon
	// LowerM and UpperM are the vertical limits in metres in LowerRef and
	// UpperRef; nil is the surface and unlimited.
	LowerM, UpperM     *float64
	LowerRef, UpperRef core.VerticalRef
	// ApplicableFrom and ApplicableTo bound limitedApplicability; nil is
	// open on that side.
	ApplicableFrom, ApplicableTo *time.Time
	// HasEvents is set when a daily period uses a daylight event.
	HasEvents bool
	// HasLayers is set for a GeometryCollection (several layers).
	HasLayers bool
	// PartIDs are the layer identifiers of a GeometryCollection
	// (ed318.PartIdentifier), reserved against collisions.
	PartIDs []string
}

// Rows makes one row per feature of an accepted collection. It refuses,
// with a *core.FieldError naming the field, a nil collection, more than
// MaxFeaturesPerPublication features, and an identifier that repeats or
// equals another feature's layer identifier.
func Rows(fc *ed318.FeatureCollection) ([]FeatureRow, error) {
	if fc == nil {
		return nil, core.Fieldf("$", "no feature collection")
	}
	if n := len(fc.Features); n > MaxFeaturesPerPublication {
		return nil, core.Fieldf("features", "has %d features; at most %d per publication", n, MaxFeaturesPerPublication)
	}
	rows := make([]FeatureRow, 0, len(fc.Features))
	taken := make(map[string]string, len(fc.Features)) // identifier -> the path that holds it
	for i := range fc.Features {
		f := &fc.Features[i]
		path := "features[" + strconv.Itoa(i) + "]"
		row, err := rowOf(f, path)
		if err != nil {
			return nil, err
		}
		ids := append([]string{row.ID}, row.PartIDs...)
		for k, id := range ids {
			where := path + ".properties.identifier"
			if k > 0 {
				where = path + ".geometry.geometries[" + strconv.Itoa(k-1) + "]"
			}
			if first, dup := taken[id]; dup {
				return nil, core.Fieldf(where, "makes the identifier %q, which %s holds; identifiers and layer identifiers are unique in a dataset", id, first)
			}
			taken[id] = where
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func rowOf(f *ed318.Feature, path string) (FeatureRow, error) {
	canonical, err := CanonicalFeature(f, path)
	if err != nil {
		return FeatureRow{}, err
	}
	row := FeatureRow{
		ID:        f.Properties.Identifier,
		Canonical: canonical,
		SHA256:    sha256.Sum256(canonical),
	}
	parts := []ed318.Geometry{f.Geometry}
	if f.Geometry.Type == ed318.GeometryCollection {
		parts = f.Geometry.Geometries
		row.HasLayers = true
		for k := range parts {
			row.PartIDs = append(row.PartIDs, ed318.PartIdentifier(row.ID, k))
		}
	}
	layers := make([]*ed318.Layer, 0, len(parts))
	for k := range parts {
		p := parts[k]
		row.Geom = append(row.Geom, GeomPart{Rings: p.Rings, Center: p.Center, RadiusM: p.RadiusM})
		l := p.Layer
		if l == nil {
			l = f.Geometry.Layer // a collection's layer applies to every member
		}
		layers = append(layers, l)
	}
	row.LowerM, row.LowerRef = bound(layers, true)
	row.UpperM, row.UpperRef = bound(layers, false)
	row.ApplicableFrom, row.ApplicableTo, row.HasEvents = applicability(f.Properties.LimitedApplicability)
	return row, nil
}

// bound is the lowest lower (lower) or the highest upper limit of the
// layers, in metres, with its reference. A layer without the limit is the
// surface or unlimited, which wins; layers in different references give
// nil and no reference: the CISP never compares heights across datums,
// and nil is the widest prefilter.
func bound(layers []*ed318.Layer, lower bool) (*float64, core.VerticalRef) {
	var best *float64
	var ref core.VerticalRef
	open := false
	for i, l := range layers {
		var v *float64
		var r core.VerticalRef
		if l != nil {
			if lower {
				v, r = l.LowerM(), l.LowerReference
			} else {
				v, r = l.UpperM(), l.UpperReference
			}
		}
		if i == 0 {
			ref = r
		} else if r != ref {
			return nil, ""
		}
		if v == nil {
			open = true
			continue
		}
		if best == nil || (lower && *v < *best) || (!lower && *v > *best) {
			best = v
		}
	}
	if open {
		return nil, ref
	}
	return best, ref
}

// applicability is the outer bounds of limitedApplicability and whether
// any daily period uses a daylight event.
func applicability(tps []ed318.TimePeriod) (from, to *time.Time, events bool) {
	if len(tps) == 0 {
		return nil, nil, false
	}
	openFrom, openTo := false, false
	for i := range tps {
		tp := &tps[i]
		if tp.StartDateTime == nil {
			openFrom = true
		} else if from == nil || tp.StartDateTime.Time.Before(*from) {
			t := tp.StartDateTime.Time.UTC()
			from = &t
		}
		if tp.EndDateTime == nil {
			openTo = true
		} else if to == nil || tp.EndDateTime.Time.After(*to) {
			t := tp.EndDateTime.Time.UTC()
			to = &t
		}
		for _, d := range tp.Schedule {
			if d.StartEvent != nil || d.EndEvent != nil {
				events = true
			}
		}
	}
	if openFrom {
		from = nil
	}
	if openTo {
		to = nil
	}
	return from, to, events
}

// CanonicalFeature is the feature as ed318.Export writes it, re-encoded
// compact with every object's keys sorted and numbers kept as written.
// path names the feature in a refusal.
func CanonicalFeature(f *ed318.Feature, path string) ([]byte, error) {
	b, err := ed318.Export(&ed318.FeatureCollection{Features: []ed318.Feature{*f}})
	if err != nil {
		return nil, core.Fieldf(path, "cannot be exported: %v", err)
	}
	var doc struct {
		Features []json.RawMessage `json:"features"`
	}
	if err := json.Unmarshal(b, &doc); err != nil || len(doc.Features) != 1 {
		return nil, core.Fieldf(path, "export is not one feature")
	}
	return Canonical(doc.Features[0])
}

// Canonical re-encodes JSON compact with every object's keys sorted,
// numbers as written and no HTML escaping. Two encodings of one value by
// ed318.Export give the same bytes.
func Canonical(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("canonical: %w", err)
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil { // maps encode with sorted keys
		return nil, fmt.Errorf("canonical: %w", err)
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}
