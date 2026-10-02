package obs

import (
	"bufio"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const runbook = "../../docs/RUNBOOKS/observability.md"

// The runbook's table is the catalogue, row for row, and nothing else:
// every registered metric is documented and every documented metric is
// one the catalogue holds (both directions).
func TestRunbookIsTheCatalogue(t *testing.T) {
	f, err := os.Open(runbook)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	doc := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "| `cisp_") {
			continue
		}
		name, _, _ := strings.Cut(strings.TrimPrefix(line, "| `"), "`")
		if _, dup := doc[name]; dup {
			t.Errorf("%s is documented twice", name)
		}
		doc[name] = line
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if len(doc) == 0 {
		t.Fatal("the runbook has no metric rows; the check would be vacuous")
	}
	for _, m := range Catalogue {
		row, ok := doc[m.Name]
		switch {
		case !ok:
			t.Errorf("%s is registered but not in the runbook", m.Name)
		case row != CatalogueRow(m):
			t.Errorf("%s differs:\nrunbook   %s\ncatalogue %s", m.Name, row, CatalogueRow(m))
		}
		delete(doc, m.Name)
	}
	for name := range doc {
		t.Errorf("%s is in the runbook but not in the catalogue", name)
	}
}

// dynamicNames are catalogued names the code builds at run time from
// another system's constants (core's refusal reasons) or with a prefix,
// so no literal in this module spells them.
func dynamicNames() map[string]bool {
	out := map[string]bool{}
	for _, n := range tokenRefusals {
		out[counterName(n)] = true
	}
	for _, n := range prefixed("signature_", signatureOutcomes) {
		out[counterName(n)] = true
	}
	out[counterName("accepted")] = true
	return out
}

// codeMetrics reads every metric name this module's code spells: the
// string constants named Counter*, Gauge* and Metric*, the string
// literals passed to .Counter, .Gauge and core.Counters' .Inc and .Add,
// and the Name of a Prometheus metric's options. internal/jws counts
// under "signature_" + its names.
func codeMetrics(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	fset := token.NewFileSet()
	for _, root := range []string{"../../internal", "../../cmd"} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") ||
				strings.Contains(filepath.ToSlash(path), "/gen/") || strings.HasSuffix(filepath.ToSlash(path), "obs/catalogue.go") {
				return nil
			}
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			prefix := ""
			if strings.Contains(filepath.ToSlash(path), "internal/jws/") {
				prefix = "signature_"
			}
			where := filepath.ToSlash(path)
			ast.Inspect(file, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.ValueSpec:
					for i, name := range x.Names {
						if i >= len(x.Values) {
							continue
						}
						lit, ok := x.Values[i].(*ast.BasicLit)
						if !ok || lit.Kind != token.STRING {
							continue
						}
						v, _ := strconv.Unquote(lit.Value)
						switch {
						case strings.HasPrefix(name.Name, "Counter"):
							out[counterName(prefix+v)] = where
						case strings.HasPrefix(name.Name, "Gauge"):
							out[gaugeName(v)] = where
						case strings.HasPrefix(name.Name, "Metric") && strings.HasPrefix(v, "cisp_"):
							out[v] = where
						}
					}
				case *ast.CallExpr:
					sel, ok := x.Fun.(*ast.SelectorExpr)
					if !ok || len(x.Args) == 0 {
						return true
					}
					lit, ok := x.Args[0].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						return true
					}
					v, _ := strconv.Unquote(lit.Value)
					switch sel.Sel.Name {
					case "Counter", "Inc", "Add":
						if metricName.MatchString(v) {
							out[counterName(v)] = where
						}
					case "Gauge":
						out[gaugeName(v)] = where
					}
				case *ast.KeyValueExpr:
					if k, ok := x.Key.(*ast.Ident); ok && k.Name == "Name" {
						if lit, ok := x.Value.(*ast.BasicLit); ok && lit.Kind == token.STRING {
							if v, _ := strconv.Unquote(lit.Value); strings.HasPrefix(v, "cisp_") {
								out[v] = where
							}
						}
					}
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

// Every metric the code spells is catalogued, and every catalogued
// metric is spelt somewhere (or built from core's names): a metric added
// without its row, or a row left after its metric went, fails here.
func TestCodeRegistersOnlyCataloguedMetrics(t *testing.T) {
	code := codeMetrics(t)
	if len(code) < 50 {
		t.Fatalf("only %d metric names found in the code; the scan is broken", len(code))
	}
	var missing []string
	for name, where := range code {
		if !Catalogued(name) {
			missing = append(missing, name+" ("+where+")")
		}
	}
	sort.Strings(missing)
	for _, m := range missing {
		t.Errorf("not catalogued: %s", m)
	}
	dyn := dynamicNames()
	for _, m := range Catalogue {
		if _, ok := code[m.Name]; !ok && !dyn[m.Name] {
			t.Errorf("catalogued but spelt nowhere in the code: %s", m.Name)
		}
	}
}

// Every catalogue row is complete: a valid name with its kind's suffix,
// a help text, and a status-line metric labelled by component.
func TestCatalogueRowsComplete(t *testing.T) {
	for _, m := range Catalogue {
		short := strings.TrimPrefix(m.Name, "cisp_")
		if !strings.HasPrefix(m.Name, "cisp_") || !metricName.MatchString(short) || m.Help == "" {
			t.Errorf("row %+v", m)
		}
		if m.Kind == KindCounter && !strings.HasSuffix(m.Name, "_total") {
			t.Errorf("counter %s without _total", m.Name)
		}
	}
	if Catalogued("cisp_made_up_total") || !Catalogued("cisp_stream_clients_dropped_total") {
		t.Error("Catalogued answers wrong")
	}
	if got := CatalogueRow(Metric{Name: "cisp_x", Kind: KindGauge, Help: "h"}); got != "| `cisp_x` | gauge | — | h | — |" {
		t.Errorf("row %q", got)
	}
}
