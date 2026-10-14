package httpapi

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

// changelogSection is the body of the CHANGELOG's heading that starts
// with prefix, up to the next heading of the same level.
func changelogSection(t *testing.T, body, prefix, level string) string {
	t.Helper()
	start := strings.Index(body, "\n"+level+" "+prefix)
	if start < 0 {
		t.Fatalf("CHANGELOG.md has no %q heading", level+" "+prefix)
	}
	rest := body[start+1:]
	if end := strings.Index(rest[1:], "\n"+level+" "); end >= 0 {
		rest = rest[:end+1]
	}
	return rest
}

var backticked = regexp.MustCompile("`([a-z_]+)`")

// names is the backticked identifiers of s.
func names(s string) []string {
	var out []string
	for _, m := range backticked.FindAllStringSubmatch(s, -1) {
		out = append(out, m[1])
	}
	return out
}

// Q10's public subset is a 1.0.0 contract item (docs/PLAN.md section
// 15.2): the CHANGELOG's [1.0.0] Contract section names the members each
// USSP of /public/v1/ussp_list carries and the two it withholds. Within
// /v1 the public shape only grows (docs/RELEASING.md section 1), so
// every member the contract names is a property of PublicUssp and
// required, and the withheld ones are the full Ussp's and not served.
func TestPublicUsspIsARecordedContract(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "CHANGELOG.md"))
	if err != nil {
		t.Fatal(err)
	}
	release := changelogSection(t, string(raw), "[1.0.0]", "##")
	contract := changelogSection(t, release, "Contract", "###")
	start := strings.Index(contract, "/public/v1/ussp_list")
	if start < 0 {
		t.Fatalf("the 1.0.0 Contract section does not name /public/v1/ussp_list:\n%s", contract)
	}
	// The bullet that names it, whitespace collapsed.
	item := contract[strings.LastIndex(contract[:start], "\n- ")+1:]
	if end := strings.Index(item[1:], "\n- "); end >= 0 {
		item = item[:end+1]
	}
	item = strings.Join(strings.Fields(item), " ")
	for _, want := range []string{"Q10", "pending GCAA", "/public/v2"} {
		if !strings.Contains(item, want) {
			t.Errorf("the contract item does not say %q:\n%s", want, item)
		}
	}
	carried, withheld, ok := strings.Cut(item, "withholds")
	if !ok {
		t.Fatalf("the contract item names no withheld member:\n%s", item)
	}
	_, carried, ok = strings.Cut(carried, "the members")
	if !ok {
		t.Fatalf("the contract item names no member:\n%s", item)
	}
	carried, _, _ = strings.Cut(carried, "(`PublicUssp`")
	withheld, _, _ = strings.Cut(withheld, ".")
	members, hidden := names(carried), names(withheld)
	if len(members) == 0 || len(hidden) == 0 {
		t.Fatalf("members %v, withheld %v: the check below would compare nothing", members, hidden)
	}

	doc, err := openapi3.NewLoader().LoadFromFile(filepath.Join("..", "..", "api", "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	schema := func(name string) *openapi3.Schema {
		ref, ok := doc.Components.Schemas[name]
		if !ok || ref.Value == nil {
			t.Fatalf("api/openapi.yaml has no schema %s", name)
		}
		return ref.Value
	}
	public, full := schema("PublicUssp"), schema("Ussp")
	for _, m := range members {
		if _, ok := public.Properties[m]; !ok {
			t.Errorf("the 1.0.0 contract names %s, which PublicUssp no longer has: a removal within /v1", m)
		}
		if !slices.Contains(public.Required, m) {
			t.Errorf("the 1.0.0 contract names %s, which PublicUssp does not require", m)
		}
	}
	for _, h := range hidden {
		if _, ok := full.Properties[h]; !ok {
			t.Errorf("the contract withholds %s, which the USSP list does not have", h)
		}
		if slices.Contains(members, h) {
			t.Errorf("%s is both carried and withheld", h)
		}
	}
}
