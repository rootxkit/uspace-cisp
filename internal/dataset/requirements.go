package dataset

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/rootxkit/uspace-core/ed318"
)

// RequirementsMember is the extendedProperties member of a USPACE
// feature that holds its cis/uspace_requirements/v1 block (docs/PLAN.md
// section 15 Q6, Q32).
const RequirementsMember = "uspace_requirements"

// RequirementsSchema is the schema identifier of the block.
const RequirementsSchema = "cis/uspace_requirements/v1"

// The members of the block, in schema order.
const (
	memberUASRequirements       = "uas_requirements"
	memberServicePerformance    = "service_performance"
	memberOperationalConditions = "operational_conditions"
	memberAirspaceConstraints   = "airspace_constraints"
	memberServicesRequired      = "services_required"
	memberAdjacent              = "adjacent"
)

var requirementMembers = []string{
	memberUASRequirements, memberServicePerformance, memberOperationalConditions,
	memberAirspaceConstraints, memberServicesRequired, memberAdjacent,
}

// The U-space services a requirements block may name; the first four are
// mandatory in every U-space airspace (2021/664 Art. 3(3)).
var (
	mandatoryServices = []string{"NID", "GEO", "FA", "TI"}
	knownServices     = []string{"NID", "GEO", "FA", "TI", "WX", "CM"}
)

// performanceRates are the members of service_performance that must be
// numbers above 0; other members pass.
var performanceRates = []string{"nid_update_hz", "ti_update_hz", "cis_latency_s"}

// MaxAdjacent bounds adjacent (E-10).
const MaxAdjacent = 1000

// checkRequirements holds the requirements block of the USPACE feature
// f at path to cis/uspace_requirements/v1; ids are the identifiers of
// the publication, which adjacent must name.
func checkRequirements(f *ed318.Feature, path string, ids map[string]bool, c *collector) {
	ext := join(path, "properties.extendedProperties")
	raw, ok := f.Properties.ExtendedProperties[RequirementsMember]
	if !ok {
		c.add(join(ext, RequirementsMember), "is required on a USPACE feature: the Art. 3(4) requirements block ("+RequirementsSchema+")")
		return
	}
	here := join(ext, RequirementsMember)
	ms, err := members(raw)
	if err != nil {
		c.add(here, requirementsShape(err, raw))
		return
	}
	got := make(map[string]json.RawMessage, len(ms))
	for _, m := range ms {
		if !slices.Contains(requirementMembers, m.key) {
			c.add(join(here, m.key), "unknown member of "+RequirementsSchema)
			continue
		}
		got[m.key] = m.value
	}
	for _, name := range requirementMembers {
		v, present := got[name]
		where := join(here, name)
		if !present {
			c.add(where, "is required")
			continue
		}
		switch name {
		case memberUASRequirements, memberOperationalConditions:
			if !isObject(v) {
				c.add(where, "must be an object, not "+describe(v))
			}
		case memberServicePerformance:
			checkPerformance(v, where, c)
		case memberAirspaceConstraints:
			checkConstraints(v, where, c)
		case memberServicesRequired:
			checkServices(v, where, c)
		case memberAdjacent:
			checkAdjacent(v, where, ids, c)
		}
	}
}

// requirementsShape is the refusal of a block that is not an object.
func requirementsShape(err error, raw json.RawMessage) string {
	if r, ok := asRepeated(err); ok {
		return r.Error()
	}
	return "must be an object (" + RequirementsSchema + "), not " + describe(raw)
}

func checkPerformance(v json.RawMessage, where string, c *collector) {
	ms, err := members(v)
	if err != nil {
		c.add(where, requirementsShape(err, v))
		return
	}
	got := map[string]json.RawMessage{}
	for _, m := range ms {
		got[m.key] = m.value
	}
	for _, name := range performanceRates {
		raw, ok := got[name]
		if !ok {
			c.add(join(where, name), "is required")
			continue
		}
		if f, ok := numberValue(raw); !ok || f <= 0 {
			c.add(join(where, name), "must be a number above 0, not "+strings.TrimSpace(string(raw)))
		}
	}
}

func checkConstraints(v json.RawMessage, where string, c *collector) {
	ms, err := members(v)
	if err != nil {
		c.add(where, requirementsShape(err, v))
		return
	}
	for _, m := range ms {
		if m.key != "max_height_agl_m" {
			continue
		}
		if f, ok := numberValue(m.value); !ok || f <= 0 {
			c.add(join(where, m.key), "must be a number above 0, not "+describe(m.value))
		}
	}
}

func checkServices(v json.RawMessage, where string, c *collector) {
	list, err := elements(v)
	if err != nil {
		c.add(where, "must be an array of "+strings.Join(knownServices, ", ")+", not "+describe(v))
		return
	}
	if len(list) == 0 {
		c.add(where, "is empty; NID, GEO, FA and TI are always required")
		return
	}
	if len(list) > len(knownServices) {
		c.add(where, "names more services than exist")
		return
	}
	seen := map[string]int{}
	for k, raw := range list {
		s, ok := stringValue(raw)
		switch {
		case !ok:
			c.add(index(where, k), "must be a string, not "+describe(raw))
		case !slices.Contains(knownServices, s):
			c.add(index(where, k), quote(s)+" is not one of "+strings.Join(knownServices, ", "))
		default:
			if first, dup := seen[s]; dup {
				c.add(index(where, k), quote(s)+" repeats "+index(where, first))
				continue
			}
			seen[s] = k
		}
	}
	for _, m := range mandatoryServices {
		if _, ok := seen[m]; !ok {
			c.add(where, "lacks "+m+"; NID, GEO, FA and TI are always required")
		}
	}
}

func checkAdjacent(v json.RawMessage, where string, ids map[string]bool, c *collector) {
	list, err := elements(v)
	if err != nil {
		c.add(where, "must be an array of identifiers, not "+describe(v))
		return
	}
	if len(list) > MaxAdjacent {
		c.add(where, "names more than 1000 airspaces")
		return
	}
	for k, raw := range list {
		s, ok := stringValue(raw)
		switch {
		case !ok:
			c.add(index(where, k), "must be an identifier string, not "+describe(raw))
		case !ids[s]:
			c.add(index(where, k), quote(s)+" is not an identifier of this publication; adjacent names U-space airspaces published with it")
		}
	}
}
