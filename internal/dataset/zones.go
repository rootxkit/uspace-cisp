package dataset

import (
	"errors"
	"strings"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed269"
	"github.com/rootxkit/uspace-core/ed318"

	"github.com/rootxkit/uspace-cisp/internal/publication"
)

// ReasonDAR is the ED-318 reason of a dynamic airspace restriction,
// published by the ANSP (F2), never in an F1 dataset.
const ReasonDAR = "DAR"

// ed318Rules are the rules of zones (uspace false) and uspace_airspace
// (uspace true).
type ed318Rules struct{ uspace bool }

// Validate parses body with ed318.Parse and holds every feature to the
// dataset's rules, then builds the rows. A refusal at any step refuses
// the whole publication.
func (r ed318Rules) Validate(body []byte, lim ed318.Limits, _ time.Time) (Accepted, *ed269.Problems) {
	fc, probs := ed318.Parse(body, lim)
	if probs != nil {
		return Accepted{}, probs
	}
	c := newCollector(lim)
	ids := make(map[string]bool, len(fc.Features))
	for i := range fc.Features {
		ids[fc.Features[i].Properties.Identifier] = true
	}
	var warnings []Warning
	for i := range fc.Features {
		f := &fc.Features[i]
		path := index("features", i)
		r.typeRule(f, path, c)
		reasonRule(f, path, c)
		if w := judgeable(f, path, c); w != nil {
			warnings = append(warnings, *w)
		}
		if r.uspace && f.Properties.Type == core.ZoneUSpace {
			checkRequirements(f, path, ids, c)
		}
	}
	if p := c.result(); p != nil {
		return Accepted{}, p
	}
	rows, err := publication.Rows(fc)
	if err != nil {
		var fe *core.FieldError
		if errors.As(err, &fe) {
			c.add(fe.Field, fe.Reason)
		} else {
			c.add("$", err.Error())
		}
		return Accepted{}, c.result()
	}
	return Accepted{Collection: fc, Warnings: warnings, Rows: rows}, nil
}

// typeRule: no USPACE in zones; only USPACE in uspace_airspace.
func (r ed318Rules) typeRule(f *ed318.Feature, path string, c *collector) {
	isUSpace := f.Properties.Type == core.ZoneUSpace
	switch {
	case r.uspace && !isUSpace:
		c.add(join(path, "properties.type"), quote(string(f.Properties.Type))+
			": only USPACE features are published in uspace_airspace; geographical zones are published in the zones dataset")
	case !r.uspace && isUSpace:
		c.add(join(path, "properties.type"), "USPACE: U-space airspace is published in the uspace_airspace dataset")
	}
}

// reasonRule: no DAR reason in an F1 dataset.
func reasonRule(f *ed318.Feature, path string, c *collector) {
	for k, reason := range f.Properties.Reason {
		if reason == ReasonDAR {
			c.add(index(join(path, "properties.reason"), k), "DAR: dynamic restrictions are published by the ANSP")
		}
	}
}

// judgeable builds the feature alone with ed318.ToZones and NOAADaylight.
// A field error about the geometry, a layer, a radius or a limit refuses
// the feature at its path (a consumer that cannot build the zone would
// drop it); any other error is returned as a warning, because consumers
// can still judge the zone with ed318.Applies.
func judgeable(f *ed318.Feature, path string, c *collector) *Warning {
	one := &ed318.FeatureCollection{Type: "FeatureCollection", Features: []ed318.Feature{*f}}
	_, err := ed318.ToZones(one, ed318.NOAADaylight{})
	if err == nil {
		return nil
	}
	field, reason := path, err.Error()
	var fe *core.FieldError
	if errors.As(err, &fe) {
		field, reason = rebase(fe.Field, path), fe.Reason
	}
	if refusesBuild(field) {
		c.add(field, "the zone cannot be built for judgement (ed318.ToZones): "+reason)
		return nil
	}
	if !strings.Contains(reason, "ed318.Applies") {
		reason += "; consumers evaluate its applicability with ed318.Applies"
	}
	return &Warning{Field: field, Reason: "zone " + quote(f.Properties.Identifier) + " is accepted, but " + reason}
}

// rebase turns a path into the one-feature collection ("features[0]...")
// into the path of the feature in the publication.
func rebase(field, path string) string {
	const one = "features[0]"
	if strings.HasPrefix(field, one) {
		return path + strings.TrimPrefix(field, one)
	}
	return path
}

// refusesBuild reports whether a ToZones problem at field is about the
// geometry, a layer, a radius or a vertical limit.
func refusesBuild(field string) bool {
	for _, part := range []string{".geometry", ".layer", "radius", ".lower", ".upper"} {
		if strings.Contains(field, part) {
			return true
		}
	}
	return false
}
