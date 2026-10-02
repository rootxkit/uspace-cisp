package dataset

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed269"
	"github.com/rootxkit/uspace-core/ed318"
	"github.com/rootxkit/uspace-core/f3548"

	"github.com/rootxkit/uspace-cisp/internal/publication"
)

// The F3548 constraint limits a restriction's outline is held to
// (uspace-core f3548; never retyped), so one restriction fits both the
// CIS and the DSS channel (docs/PLAN.md section 6.2).
const (
	// MaxRestrictionVertices bounds the outline (CstrMaxVertices).
	MaxRestrictionVertices = f3548.CstrMaxVertices
	// MaxRestrictionAreaM2 bounds the area (CstrMaxAreaKm2), in square
	// metres as PostGIS ST_Area on geography gives it.
	MaxRestrictionAreaM2 = float64(f3548.CstrMaxAreaKm2) * 1e6
)

// The JSON paths of a POST /v1/restrictions body the rules name.
const (
	fieldFeature          = "feature"
	fieldUspaceAirspaceID = "uspace_airspace_id"
	// cisPrefix starts the members the CISP writes itself
	// (cis_restriction, cis_applicability); a publisher never sends one.
	cisPrefix = "cis_"
)

// restrictionTypes are the zone types a DAR may have: a restriction
// closes or conditions airspace; NO_RESTRICTION and USPACE open it.
var restrictionTypes = map[core.ZoneType]bool{
	core.ZoneProhibited:       true,
	core.ZoneReqAuthorization: true,
	core.ZoneConditional:      true,
}

// RestrictionWindow is the window a restriction body declares
// (starts_at, ends_at); the feature's one TimePeriod must equal it.
type RestrictionWindow struct {
	StartsAt, EndsAt time.Time
}

// AcceptedRestriction is a restriction feature that passed the rules.
type AcceptedRestriction struct {
	// Feature is the feature as parsed (strict), unchanged.
	Feature *ed318.Feature
	// Row is its publication row: the identifier and the geometry parts
	// the store measures (area, intersection with the airspace).
	Row publication.FeatureRow
	// Warnings are what consumers can still judge safely.
	Warnings []Warning
}

// ValidateRestriction holds the feature of a restriction body to the DAR
// rules above ED-318 (docs/WORKPACKAGES/WP-5.md): a one-feature
// collection is built around it and ed318.Parse'd strictly; its reason
// holds DAR; its type is PROHIBITED, REQ_AUTHORIZATION or CONDITIONAL;
// limitedApplicability is exactly one TimePeriod whose startDateTime and
// endDateTime equal the window, with no daylight event; its outline has
// at most MaxRestrictionVertices vertices; no extendedProperties member
// starts with cis_ (those are the CISP's); and ed318.ToZones can build
// it. The identifier is held to ED-318's 7 characters by the parse;
// uniqueness across datasets and the placement (area, airspace) are the
// store's questions (CheckPlacement). Every problem is named by its path
// in the body ("feature.properties.reason[0]"); the feature is never
// changed.
func ValidateRestriction(feature json.RawMessage, w RestrictionWindow, lim ed318.Limits) (AcceptedRestriction, *ed269.Problems) {
	c := newCollector(lim)
	trimmed := bytes.TrimSpace(feature)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		c.add(fieldFeature, "is required: the restriction as one ED-318 UASZone feature")
		return AcceptedRestriction{}, c.result()
	}
	if !isObject(trimmed) {
		c.add(fieldFeature, "is "+describe(trimmed)+", not one ED-318 feature object")
		return AcceptedRestriction{}, c.result()
	}
	var b bytes.Buffer
	b.WriteString(`{"type":"FeatureCollection","features":[`)
	b.Write(trimmed)
	b.WriteString(`]}`)
	fc, probs := ed318.Parse(b.Bytes(), lim)
	if probs != nil {
		for _, p := range probs.List {
			c.add(rebaseFeature(p.Field), p.Reason)
		}
		c.more += probs.Truncated
		return AcceptedRestriction{}, c.result()
	}
	if len(fc.Features) != 1 {
		c.add(fieldFeature, "is not one feature")
		return AcceptedRestriction{}, c.result()
	}
	f := &fc.Features[0]
	path := fieldFeature
	darReason(f, path, c)
	darType(f, path, c)
	darPeriod(f, path, w, c)
	darVertices(f, path, c)
	cisMembers(f, path, c)
	var warnings []Warning
	if wn := judgeable(f, path, c); wn != nil {
		warnings = append(warnings, *wn)
	}
	if p := c.result(); p != nil {
		return AcceptedRestriction{}, p
	}
	rows, err := publication.Rows(fc)
	if err != nil {
		var fe *core.FieldError
		if errors.As(err, &fe) {
			c.add(rebaseFeature(fe.Field), fe.Reason)
		} else {
			c.add(fieldFeature, err.Error())
		}
		return AcceptedRestriction{}, c.result()
	}
	return AcceptedRestriction{Feature: f, Row: rows[0], Warnings: warnings}, nil
}

// rebaseFeature turns a path into the one-feature collection into the
// path of the body's feature member.
func rebaseFeature(field string) string {
	const one = "features[0]"
	if rest, ok := strings.CutPrefix(field, one); ok {
		return fieldFeature + rest
	}
	return fieldFeature
}

// darReason: the reason holds DAR.
func darReason(f *ed318.Feature, path string, c *collector) {
	for _, r := range f.Properties.Reason {
		if r == ReasonDAR {
			return
		}
	}
	c.add(join(path, "properties.reason"), "does not hold DAR: a dynamic restriction is published with the reason DAR")
}

// darType: a DAR restricts airspace.
func darType(f *ed318.Feature, path string, c *collector) {
	if restrictionTypes[f.Properties.Type] {
		return
	}
	c.add(join(path, "properties.type"), quote(string(f.Properties.Type))+
		" opens airspace or designates U-space; a dynamic restriction is PROHIBITED, REQ_AUTHORIZATION or CONDITIONAL")
}

// darPeriod: exactly one TimePeriod, equal to the window, no daylight
// event (a restriction's time is one truth, carried twice for ED-318
// consumers).
func darPeriod(f *ed318.Feature, path string, w RestrictionWindow, c *collector) {
	where := join(path, "properties.limitedApplicability")
	tps := f.Properties.LimitedApplicability
	switch len(tps) {
	case 0:
		c.add(where, "is required: one period from starts_at "+stamp(w.StartsAt)+" to ends_at "+stamp(w.EndsAt))
		return
	case 1:
	default:
		c.add(where, "has "+strconv.Itoa(len(tps))+" periods; a restriction has exactly one, from starts_at to ends_at")
		return
	}
	tp := &tps[0]
	period := index(where, 0)
	equal := func(name string, got *ed318.DateTime, want time.Time, body string) {
		switch {
		case got == nil:
			c.add(join(period, name), "is required and must equal "+body+" "+stamp(want))
		case !got.Time.Equal(want):
			c.add(join(period, name), quote(got.Text)+" is not "+body+" "+stamp(want)+"; the two must be the same instant")
		}
	}
	equal("startDateTime", tp.StartDateTime, w.StartsAt, "starts_at")
	equal("endDateTime", tp.EndDateTime, w.EndsAt, "ends_at")
	for k, d := range tp.Schedule {
		day := index(join(period, "schedule"), k)
		if d.StartEvent != nil {
			c.add(join(day, "startEvent"), "a restriction does not use daylight events; give clock times")
		}
		if d.EndEvent != nil {
			c.add(join(day, "endEvent"), "a restriction does not use daylight events; give clock times")
		}
	}
}

// darVertices: the outline within the F3548 vertex limit. A ring's
// closing position repeats its first and is not counted; a circle has no
// vertices.
func darVertices(f *ed318.Feature, path string, c *collector) {
	parts := []ed318.Geometry{f.Geometry}
	if f.Geometry.Type == ed318.GeometryCollection {
		parts = f.Geometry.Geometries
	}
	n := 0
	for i := range parts {
		for _, ring := range parts[i].Rings {
			n += max(0, len(ring)-1)
		}
	}
	if n > MaxRestrictionVertices {
		c.add(join(path, "geometry"), "has "+strconv.Itoa(n)+" vertices; at most "+strconv.Itoa(MaxRestrictionVertices)+" (F3548 CstrMaxVertices)")
	}
}

// cisMembers: the cis_* members are the CISP's own.
func cisMembers(f *ed318.Feature, path string, c *collector) {
	for k := range f.Properties.ExtendedProperties {
		if strings.HasPrefix(k, cisPrefix) {
			c.add(join(path, "properties.extendedProperties."+k), "cis_* members are written by the CISP, never by a publisher")
		}
	}
}

// Placement is what the store measured of a restriction's outline
// against the U-space airspace it names.
type Placement struct {
	// AreaM2 is ST_Area of the outline on geography.
	AreaM2 float64
	// AirspaceCurrent says uspace_airspace_id is a current feature of the
	// uspace_airspace dataset.
	AirspaceCurrent bool
	// Intersects says the outline intersects that feature's stored shape.
	Intersects bool
}

// CheckPlacement refuses a restriction larger than MaxRestrictionAreaM2,
// one naming no current U-space airspace, and one entirely outside the
// airspace it claims to modify (docs/PLAN.md section 15 Q6: strict on
// both sides).
func CheckPlacement(p Placement, uspaceAirspaceID string) *ed269.Problems {
	c := newCollector(ed318.Limits{})
	if p.AreaM2 > MaxRestrictionAreaM2 {
		c.add(join(fieldFeature, "geometry"), "covers "+strconv.FormatFloat(p.AreaM2/1e6, 'f', 1, 64)+
			" km2; at most "+strconv.Itoa(f3548.CstrMaxAreaKm2)+" km2 (F3548 CstrMaxAreaKm2)")
	}
	switch {
	case !p.AirspaceCurrent:
		c.add(fieldUspaceAirspaceID, quote(uspaceAirspaceID)+" is not a feature of the current uspace_airspace dataset; a restriction modifies a designated U-space airspace")
	case !p.Intersects:
		c.add(fieldUspaceAirspaceID, "the restriction lies entirely outside "+quote(uspaceAirspaceID)+", the U-space airspace it claims to modify")
	}
	return c.result()
}

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }
