package dataset

import (
	"testing"

	"github.com/rootxkit/uspace-cisp/internal/publication"
)

func publicationDataset(s string) publication.Dataset { return publication.Dataset(s) }

func block(d doc) doc {
	return props(d, 0)["extendedProperties"].(doc)[RequirementsMember].(doc)
}

const blockPath = "features[0].properties.extendedProperties." + RequirementsMember

// The uspace_airspace dataset: the USPACE feature with its block is
// accepted, and the flat members the vector carries beside it pass
// through as other extendedProperties.
func TestUSpaceAccepted(t *testing.T) {
	acc := mustAccept(t, KindUspaceAirspace, uspaceDoc(t))
	if len(acc.Rows) != 1 || acc.Rows[0].ID != "TSU001" {
		t.Fatalf("rows %+v", acc.Rows)
	}
	if _, ok := acc.Collection.Features[0].Properties.ExtendedProperties["services_required"]; !ok {
		t.Error("another extendedProperties member was dropped")
	}
}

// E-01 pairs for every rule of the requirements block.
func TestUSpaceRefusalPairs(t *testing.T) {
	cases := []struct {
		name          string
		breakIt, fix  func(d doc)
		field, phrase string
	}{
		{
			name:    "a zone type other than USPACE",
			breakIt: func(d doc) { props(d, 0)["type"] = "PROHIBITED" },
			fix:     func(d doc) { props(d, 0)["type"] = "USPACE" },
			field:   "features[0].properties.type", phrase: "only USPACE features",
		},
		{
			name:    "DAR in uspace_airspace",
			breakIt: func(d doc) { props(d, 0)["reason"] = []any{"DAR"} },
			fix:     func(d doc) { props(d, 0)["reason"] = []any{"AIR_TRAFFIC"} },
			field:   "features[0].properties.reason[0]", phrase: "ANSP",
		},
		{
			name:    "missing requirements block",
			breakIt: func(d doc) { delete(props(d, 0)["extendedProperties"].(doc), RequirementsMember) },
			fix:     func(d doc) { props(d, 0)["extendedProperties"].(doc)[RequirementsMember] = requirementsBlock(t) },
			field:   blockPath, phrase: "is required on a USPACE feature",
		},
		{
			name:    "the block is not an object",
			breakIt: func(d doc) { props(d, 0)["extendedProperties"].(doc)[RequirementsMember] = []any{} },
			fix:     func(d doc) { props(d, 0)["extendedProperties"].(doc)[RequirementsMember] = requirementsBlock(t) },
			field:   blockPath, phrase: "must be an object",
		},
		{
			name:    "unknown member under the block",
			breakIt: func(d doc) { block(d)["colour"] = "blue" },
			fix:     func(d doc) { delete(block(d), "colour") },
			field:   blockPath + ".colour", phrase: "unknown member",
		},
		{
			name:    "a required member missing",
			breakIt: func(d doc) { delete(block(d), "operational_conditions") },
			fix:     func(d doc) { block(d)["operational_conditions"] = doc{} },
			field:   blockPath + ".operational_conditions", phrase: "is required",
		},
		{
			name:    "uas_requirements not an object",
			breakIt: func(d doc) { block(d)["uas_requirements"] = "all" },
			fix:     func(d doc) { block(d)["uas_requirements"] = doc{"x": 1} },
			field:   blockPath + ".uas_requirements", phrase: "must be an object, not a string",
		},
		{
			name:    "a rate of zero",
			breakIt: func(d doc) { block(d)["service_performance"].(doc)["nid_update_hz"] = 0 },
			fix:     func(d doc) { block(d)["service_performance"].(doc)["nid_update_hz"] = 0.5 },
			field:   blockPath + ".service_performance.nid_update_hz", phrase: "above 0",
		},
		{
			name:    "a rate missing",
			breakIt: func(d doc) { delete(block(d)["service_performance"].(doc), "cis_latency_s") },
			fix:     func(d doc) { block(d)["service_performance"].(doc)["cis_latency_s"] = 2 },
			field:   blockPath + ".service_performance.cis_latency_s", phrase: "is required",
		},
		{
			name:    "service_performance not an object",
			breakIt: func(d doc) { block(d)["service_performance"] = 1 },
			fix:     func(d doc) { block(d)["service_performance"] = doc{"nid_update_hz": 1, "ti_update_hz": 1, "cis_latency_s": 1, "fa_s": 30} },
			field:   blockPath + ".service_performance", phrase: "must be an object",
		},
		{
			name:    "max_height_agl_m of zero",
			breakIt: func(d doc) { block(d)["airspace_constraints"] = doc{"max_height_agl_m": 0} },
			fix:     func(d doc) { block(d)["airspace_constraints"] = doc{} },
			field:   blockPath + ".airspace_constraints.max_height_agl_m", phrase: "above 0",
		},
		{
			name:    "airspace_constraints not an object",
			breakIt: func(d doc) { block(d)["airspace_constraints"] = []any{} },
			fix:     func(d doc) { block(d)["airspace_constraints"] = doc{"max_height_agl_m": 150, "note": "x"} },
			field:   blockPath + ".airspace_constraints", phrase: "must be an object",
		},
		{
			name:    "a mandatory service missing",
			breakIt: func(d doc) { block(d)["services_required"] = []any{"NID", "GEO", "FA"} },
			fix:     func(d doc) { block(d)["services_required"] = []any{"NID", "GEO", "FA", "TI"} },
			field:   blockPath + ".services_required", phrase: "lacks TI",
		},
		{
			name:    "an unknown service",
			breakIt: func(d doc) { block(d)["services_required"] = []any{"NID", "GEO", "FA", "TI", "XX"} },
			fix:     func(d doc) { block(d)["services_required"] = []any{"NID", "GEO", "FA", "TI", "WX", "CM"} },
			field:   blockPath + ".services_required[4]", phrase: "is not one of",
		},
		{
			name:    "a repeated service",
			breakIt: func(d doc) { block(d)["services_required"] = []any{"NID", "GEO", "FA", "TI", "NID"} },
			fix:     func(d doc) { block(d)["services_required"] = []any{"NID", "GEO", "FA", "TI"} },
			field:   blockPath + ".services_required[4]", phrase: "repeats",
		},
		{
			name:    "services_required empty",
			breakIt: func(d doc) { block(d)["services_required"] = []any{} },
			fix:     func(d doc) { block(d)["services_required"] = []any{"TI", "FA", "GEO", "NID"} },
			field:   blockPath + ".services_required", phrase: "is empty",
		},
		{
			name:    "services_required not an array",
			breakIt: func(d doc) { block(d)["services_required"] = "NID" },
			fix:     func(d doc) { block(d)["services_required"] = []any{"NID", "GEO", "FA", "TI"} },
			field:   blockPath + ".services_required", phrase: "must be an array",
		},
		{
			name:    "adjacent naming an identifier not in the publication",
			breakIt: func(d doc) { block(d)["adjacent"] = []any{"TSU999"} },
			fix: func(d doc) {
				secondUSpace(t, d, "TSU999")
				block(d)["adjacent"] = []any{"TSU999"}
			},
			field: blockPath + ".adjacent[0]", phrase: "not an identifier of this publication",
		},
		{
			name:    "adjacent not an array",
			breakIt: func(d doc) { block(d)["adjacent"] = "TSU001" },
			fix:     func(d doc) { block(d)["adjacent"] = []any{"TSU001"} },
			field:   blockPath + ".adjacent", phrase: "must be an array",
		},
		{
			name:    "an adjacent entry that is not a string",
			breakIt: func(d doc) { block(d)["adjacent"] = []any{7} },
			fix:     func(d doc) { block(d)["adjacent"] = []any{} },
			field:   blockPath + ".adjacent[0]", phrase: "must be an identifier string",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := uspaceDoc(t)
			c.breakIt(d)
			mustRefuse(t, KindUspaceAirspace, d, c.field, c.phrase)
			c.fix(d)
			mustAccept(t, KindUspaceAirspace, d)
		})
	}
}

// E-10: adjacent past its bound.
func TestAdjacentBound(t *testing.T) {
	d := uspaceDoc(t)
	list := make([]any, MaxAdjacent+1)
	for i := range list {
		list[i] = "TSU001"
	}
	block(d)["adjacent"] = list
	mustRefuse(t, KindUspaceAirspace, d, blockPath+".adjacent", "more than 1000")
	block(d)["adjacent"] = list[:MaxAdjacent]
	mustAccept(t, KindUspaceAirspace, d)
}

// A block that repeats a member is refused naming it (the CISP never
// picks one of two values): ed318.Parse refuses a repeated member
// anywhere in the document, before the dataset rules run.
func TestRequirementsRepeatedMember(t *testing.T) {
	d := uspaceDoc(t)
	raw := string(body(t, d))
	repeated := `"uspace_requirements":{"adjacent":[],"adjacent":[],`
	raw = replaceOnce(t, raw, `"uspace_requirements":{"adjacent":[],`, repeated)
	_, probs := For(KindUspaceAirspace).Validate([]byte(raw), edLimits(), testNow)
	if probs == nil || !hasField(probs, blockPath+".adjacent") {
		t.Fatalf("got %v", probs)
	}
}
