package httpapi

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/rootxkit/uspace-core/ed318"
	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/rootxkit/uspace-cisp/internal/bus"
	"github.com/rootxkit/uspace-cisp/internal/dataset"
)

// schemaExamples are the examples of the schemas this repository
// produces, by OpenAPI component (docs/PLAN.md sections 6.7, 10.4).
var schemaExamples = map[string]string{
	"UsspList":           "ussp_list",
	"UspaceRequirements": "uspace_requirements",
	"Change":             "change",
	"RestrictionCreate":  "restriction",
}

func components(t *testing.T) openapi3.Schemas {
	t.Helper()
	doc, err := openapi3.NewLoader().LoadFromFile(filepath.Join("..", "..", "api", "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return doc.Components.Schemas
}

// Every example validates against its OpenAPI component and is accepted
// by the Go validator; the twin with an unknown member is refused by both
// (E-01). The exported schema names its $id.
func TestSchemaExamples(t *testing.T) {
	schemas := components(t)
	for component, name := range schemaExamples {
		t.Run(name, func(t *testing.T) {
			s := schemas[component]
			if s == nil || s.Value == nil {
				t.Fatalf("no component %s", component)
			}
			files, err := filepath.Glob(filepath.Join("..", "..", "schemas", "cis", name, "examples", "*.json"))
			if err != nil || len(files) == 0 {
				t.Fatalf("no examples for %s: %v", name, err)
			}
			for _, f := range files {
				raw, err := os.ReadFile(f)
				if err != nil {
					t.Fatal(err)
				}
				var v any
				if err := json.Unmarshal(raw, &v); err != nil {
					t.Fatal(err)
				}
				if err := s.Value.VisitJSON(v); err != nil {
					t.Errorf("%s does not validate against %s: %v", filepath.Base(f), component, err)
				}
				if err := goAccepts(t, name, raw); err != "" {
					t.Errorf("%s refused by the Go validator: %s", filepath.Base(f), err)
				}
				// The twin with an unknown top-level member.
				v.(map[string]any)["colour"] = "red"
				twin, _ := json.Marshal(v)
				if err := s.Value.VisitJSON(v); err == nil {
					t.Errorf("%s with an unknown member validates against %s", filepath.Base(f), component)
				}
				if err := goAccepts(t, name, twin); err == "" {
					t.Errorf("%s with an unknown member accepted by the Go validator", filepath.Base(f))
				}
			}
			exported, err := os.ReadFile(filepath.Join("..", "..", "schemas", "cis", name, "v1.json"))
			if err != nil {
				t.Fatal(err)
			}
			var head struct {
				ID     string `json:"$id"`
				Schema string `json:"$schema"`
			}
			if err := json.Unmarshal(exported, &head); err != nil || head.ID != "https://schemas.uspace.ge/cis/"+name+"/v1.json" || !strings.Contains(head.Schema, "2020-12") {
				t.Errorf("exported schema head %+v %v", head, err)
			}
		})
	}
}

// goAccepts runs the dataset rules on an example: the USSP list as a
// publication, the requirements block inside the vector's USPACE feature.
func goAccepts(t *testing.T, name string, raw []byte) string {
	t.Helper()
	if name == "change" {
		// The Go type the bus, the change feed and the webhooks write.
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		var m bus.ChangeMessage
		if err := dec.Decode(&m); err != nil {
			return err.Error()
		}
		if m.Schema != bus.SchemaChange {
			return "schema " + m.Schema
		}
		return ""
	}
	if name == "restriction" {
		// The body parser and the DAR rules of POST /v1/restrictions.
		body, probs := dataset.ParseRestrictionBody(raw)
		if probs != nil {
			return probs.Error()
		}
		w := dataset.RestrictionWindow{StartsAt: body.StartsAt, EndsAt: body.EndsAt}
		if _, probs := dataset.ValidateRestriction(body.Feature, w, ed318.Limits{}); probs != nil {
			return probs.Error()
		}
		return ""
	}
	if name == "ussp_list" {
		if _, probs := dataset.ValidateUsspList(raw); probs != nil {
			return probs.Error()
		}
		return ""
	}
	d := uspaceDoc(t)
	var block any
	if err := json.Unmarshal(raw, &block); err != nil {
		t.Fatal(err)
	}
	fprops(d, 0)["extendedProperties"].(doc)[dataset.RequirementsMember] = block
	_, probs := dataset.For(dataset.KindUspaceAirspace).Validate(jsonBytes(t, d), edLimits(), testNow)
	if probs != nil {
		return probs.Error()
	}
	return ""
}

func edLimits() ed318.Limits { return ed318.Limits{} }

var testNow = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

// The producers a cis/change/v1 record may name: the CISP's own, and
// the ANSP process that delivers directly to /v1/cis/notifications
// while the CISP is unreachable (cross-plan M1, M5; uspace-ansp sends
// ansp/api). Any other system is refused, by the OpenAPI component and
// by the exported JSON Schema alike.
func TestChangeProducer(t *testing.T) {
	component := components(t)["Change"]
	if component == nil || component.Value == nil {
		t.Fatal("no component Change")
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "schemas", "cis", "change", "v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("change.json", doc); err != nil {
		t.Fatal(err)
	}
	exported, err := c.Compile("change.json")
	if err != nil {
		t.Fatal(err)
	}
	base, err := os.ReadFile(filepath.Join("..", "..", "schemas", "cis", "change", "examples", "ansp-direct-restriction-created.json"))
	if err != nil {
		t.Fatal(err)
	}
	record := func(producer string) any {
		var v map[string]any
		if err := json.Unmarshal(base, &v); err != nil {
			t.Fatal(err)
		}
		v["producer"] = producer
		return v
	}
	for _, p := range []string{"ansp/api", "ansp/manned-feed", "ansp-1/api-2", "uspace-cisp", "cisp/deliver-deliver-1"} {
		if err := component.Value.VisitJSON(record(p)); err != nil {
			t.Errorf("producer %q refused by the component: %v", p, err)
		}
		if err := exported.Validate(record(p)); err != nil {
			t.Errorf("producer %q refused by the exported schema: %v", p, err)
		}
	}
	for _, p := range []string{"ussp/api", "authority/api", "lab/api", "ansp", "ansp/", "ansp/API", "ansp-x/api", "ansp-1/api", "ansp/api/extra", "xansp/api", ""} {
		if err := component.Value.VisitJSON(record(p)); err == nil {
			t.Errorf("producer %q accepted by the component", p)
		}
		if err := exported.Validate(record(p)); err == nil {
			t.Errorf("producer %q accepted by the exported schema", p)
		}
	}
}
