//go:build ignore

// export-schemas writes the JSON Schemas this repository produces from
// their one source, the components of api/openapi.yaml (docs/PLAN.md
// section 6.7): schemas/cis/<name>/v1.json, JSON Schema 2020-12, with
// every referenced component under $defs. `make generate` runs it and
// `make generate-check` fails when the committed files differ, so the
// OpenAPI component and the exported schema cannot drift.
//
//	go run tools/export-schemas.go
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// exports maps a component to the schema it becomes.
var exports = []struct {
	component string
	name      string
	title     string
	// extra are components carried under $defs although the root does
	// not reference them (a schema that names two shapes).
	extra []string
}{
	{"UsspList", "ussp_list", "cis/ussp_list/v1: the national list of certified USSPs", nil},
	{"UspaceRequirements", "uspace_requirements", "cis/uspace_requirements/v1: the Art. 3(4) requirements of a U-space airspace", nil},
	{"Change", "change", "cis/change/v1: one change record of the change feed, the webhooks and the stream", nil},
	{"RestrictionCreate", "restriction", "cis/restriction/v1: a dynamic restriction from the ANSP (the POST /v1/restrictions body; $defs/CisRestriction is extendedProperties.cis_restriction of a served restriction)", []string{"CisRestriction"}},
}

const (
	specPath  = "api/openapi.yaml"
	refPrefix = "#/components/schemas/"
	idBase    = "https://schemas.uspace.ge/cis/"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "export-schemas:", err)
		os.Exit(1)
	}
}

func run() error {
	raw, err := os.ReadFile(specPath)
	if err != nil {
		return err
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("%s: %w", specPath, err)
	}
	components, _ := doc["components"].(map[string]any)
	schemas, _ := components["schemas"].(map[string]any)
	if schemas == nil {
		return fmt.Errorf("%s has no components.schemas", specPath)
	}
	for _, e := range exports {
		root, ok := schemas[e.component].(map[string]any)
		if !ok {
			return fmt.Errorf("component %s not found", e.component)
		}
		defs := map[string]any{}
		seen := map[string]bool{e.component: true}
		if err := collect(root, schemas, defs, seen); err != nil {
			return fmt.Errorf("%s: %w", e.component, err)
		}
		for _, name := range e.extra {
			if err := collect(map[string]any{"$ref": refPrefix + name}, schemas, defs, seen); err != nil {
				return fmt.Errorf("%s: %w", e.component, err)
			}
		}
		out := map[string]any{}
		for k, v := range rewrite(root).(map[string]any) {
			out[k] = v
		}
		out["$schema"] = "https://json-schema.org/draft/2020-12/schema"
		out["$id"] = idBase + e.name + "/v1.json"
		out["title"] = e.title
		if len(defs) > 0 {
			out["$defs"] = defs
		}
		body, err := marshal(out)
		if err != nil {
			return err
		}
		path := filepath.Join("schemas", "cis", e.name, "v1.json")
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, body, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// collect adds every component node references, transitively, to defs.
func collect(node any, schemas, defs map[string]any, seen map[string]bool) error {
	switch v := node.(type) {
	case map[string]any:
		if ref, ok := v["$ref"].(string); ok {
			name, ok := strings.CutPrefix(ref, refPrefix)
			if !ok {
				return fmt.Errorf("reference %s is not a component schema", ref)
			}
			if seen[name] {
				return nil
			}
			seen[name] = true
			target, ok := schemas[name].(map[string]any)
			if !ok {
				return fmt.Errorf("reference %s not found", ref)
			}
			defs[name] = rewrite(target)
			return collect(target, schemas, defs, seen)
		}
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if err := collect(v[k], schemas, defs, seen); err != nil {
				return err
			}
		}
	case []any:
		for _, e := range v {
			if err := collect(e, schemas, defs, seen); err != nil {
				return err
			}
		}
	}
	return nil
}

// rewrite copies node with component references pointing into $defs and
// the generator's x- extensions left out.
func rewrite(node any) any {
	switch v := node.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, e := range v {
			if strings.HasPrefix(k, "x-") {
				continue
			}
			if k == "$ref" {
				if s, ok := e.(string); ok {
					out[k] = "#/$defs/" + strings.TrimPrefix(s, refPrefix)
					continue
				}
			}
			out[k] = rewrite(e)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, e := range v {
			out[i] = rewrite(e)
		}
		return out
	}
	return node
}

// marshal is two-space indented JSON with sorted keys and a final
// newline, without HTML escaping.
func marshal(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
