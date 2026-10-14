// Command covergate fails when a package of internal/ or cmd/ has less
// statement coverage than the plan's bound (docs/PLAN.md sections 10.1
// and 13: 85 % of the owned packages, unit and integration together).
// It reads the profile `make integration` writes (every package built
// with the integration tag, so its unit tests run too) and prints one
// line per package, the ones below the bound marked.
//
//	go run ./tools/covergate -min 85 -profile coverage-integration.out \
//	    -exclude internal/store/relational,internal/httpapi/gen
//
// Excluded packages are generated code and test helpers, named one by
// one: a new package without tests fails the gate rather than passing
// unmeasured: a package with no test file is absent from the profile, so
// the packages `go list ./internal/... ./cmd/...` names are compared with
// the profile and any that is neither measured nor excluded fails. A
// profile that measures no package fails too.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"sort"
	"strconv"
	"strings"
)

// Module is this repository's module path: packages are named relative
// to it.
const Module = "github.com/rootxkit/uspace-cisp"

// Scopes are the trees the bound applies to.
var Scopes = []string{"internal/", "cmd/"}

// Package is one package's statements and those covered.
type Package struct {
	Path                string
	Statements, Covered int
}

// Percent is the coverage, 0 for a package with no statements.
func (p Package) Percent() float64 {
	if p.Statements == 0 {
		return 0
	}
	return 100 * float64(p.Covered) / float64(p.Statements)
}

// block is a profile line's position: a block that appears twice (two
// test binaries covering one package) is counted once, covered when
// either covered it.
type block struct {
	file, pos string
}

// Measure reads a coverage profile and returns the packages of the
// scopes, but the excluded ones, by path.
func Measure(r io.Reader, exclude []string) ([]Package, error) {
	skip := map[string]bool{}
	for _, e := range exclude {
		if e = strings.Trim(strings.TrimSpace(e), "/"); e != "" {
			skip[e] = true
		}
	}
	stmts := map[block]int{}
	covered := map[block]bool{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "mode:") {
			continue
		}
		// file:start,end numStatements count
		fields := strings.Fields(text)
		colon := strings.LastIndexByte(fields[0], ':')
		if len(fields) != 3 || colon < 0 {
			return nil, fmt.Errorf("profile line %d: %q is not file:range statements count", line, text)
		}
		n, err1 := strconv.Atoi(fields[1])
		c, err2 := strconv.Atoi(fields[2])
		if err1 != nil || err2 != nil || n < 0 || c < 0 {
			return nil, fmt.Errorf("profile line %d: %q has no counts", line, text)
		}
		b := block{file: fields[0][:colon], pos: fields[0][colon+1:]}
		stmts[b] = n
		covered[b] = covered[b] || c > 0
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("profile: %w", err)
	}
	byPath := map[string]*Package{}
	for b, n := range stmts {
		rel, ok := strings.CutPrefix(path.Dir(b.file), Module+"/")
		if !ok || skip[rel] || !inScope(rel) {
			continue
		}
		p := byPath[rel]
		if p == nil {
			p = &Package{Path: rel}
			byPath[rel] = p
		}
		p.Statements += n
		if covered[b] {
			p.Covered += n
		}
	}
	out := make([]Package, 0, len(byPath))
	for _, p := range byPath {
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func inScope(rel string) bool {
	for _, s := range Scopes {
		if strings.HasPrefix(rel, s) {
			return true
		}
	}
	return false
}

// Missing is the listed packages (import paths) that are in scope, not
// excluded and not in the profile's packages: they were never measured.
func Missing(pkgs []Package, listed, exclude []string) []string {
	have := map[string]bool{}
	for _, p := range pkgs {
		have[p.Path] = true
	}
	for _, e := range exclude {
		if e = strings.Trim(strings.TrimSpace(e), "/"); e != "" {
			have[e] = true
		}
	}
	var out []string
	for _, l := range listed {
		rel, ok := strings.CutPrefix(strings.TrimSpace(l), Module+"/")
		if ok && inScope(rel) && !have[rel] {
			out = append(out, rel)
		}
	}
	sort.Strings(out)
	return out
}

// goList names the packages of the scopes, as `go list` sees them. It is
// a variable so the tests can stand in for the go command.
var goList = func() ([]string, error) {
	args := append(make([]string, 0, 1+len(Scopes)), "list")
	for _, s := range Scopes {
		args = append(args, "./"+s+"...")
	}
	out, err := exec.Command("go", args...).Output() //nolint:gosec // the arguments are the package scopes above, constants
	if err != nil {
		return nil, fmt.Errorf("go list: %w", err)
	}
	return strings.Fields(string(out)), nil
}

// Below is the packages under min percent.
func Below(pkgs []Package, minPercent float64) []Package {
	var out []Package
	for _, p := range pkgs {
		if p.Percent() < minPercent {
			out = append(out, p)
		}
	}
	return out
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) //nolint:forbidigo // this is a main function: its exit status is the gate's verdict
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("covergate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	minPercent := fs.Float64("min", 85, "the least statement coverage of each package, percent")
	profile := fs.String("profile", "", "the coverage profile (go test -coverprofile)")
	exclude := fs.String("exclude", "", "comma-separated packages, relative to the module, left out (generated code, test helpers)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *profile == "" || *minPercent <= 0 || *minPercent > 100 {
		_, _ = fmt.Fprintln(stderr, "covergate: -profile is required and -min is in (0, 100]")
		return 2
	}
	f, err := os.Open(*profile)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "covergate: %v\n", err)
		return 2
	}
	defer func() { _ = f.Close() }()
	pkgs, err := Measure(f, strings.Split(*exclude, ","))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "covergate: %v\n", err)
		return 2
	}
	excluded := strings.Split(*exclude, ",")
	listed, err := goList()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "covergate: %v\n", err)
		return 2
	}
	if err := report(stdout, pkgs, *minPercent, Missing(pkgs, listed, excluded)); err != nil {
		_, _ = fmt.Fprintf(stderr, "covergate: %v\n", err)
		return 1
	}
	return 0
}

// errBelow is a gate that does not hold.
var errBelow = errors.New("below the bound")

// errMissing is a package that was never measured.
var errMissing = errors.New("unmeasured package")

// report prints every package and says whether the gate holds. missing
// are packages the profile does not measure at all.
func report(w io.Writer, pkgs []Package, minPercent float64, missing []string) error {
	if len(pkgs) == 0 {
		return errors.New("the profile measures no package of internal/ or cmd/: nothing was checked")
	}
	below := Below(pkgs, minPercent)
	for _, p := range pkgs {
		mark := ""
		if p.Percent() < minPercent {
			mark = "  BELOW"
		}
		_, _ = fmt.Fprintf(w, "%-40s %5.1f%% (%d of %d statements)%s\n", p.Path, p.Percent(), p.Covered, p.Statements, mark)
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: not in the profile (no test file?), neither measured nor excluded: %s", errMissing, strings.Join(missing, ", "))
	}
	if len(below) > 0 {
		names := make([]string, 0, len(below))
		for _, p := range below {
			names = append(names, fmt.Sprintf("%s %.1f%%", p.Path, p.Percent()))
		}
		return fmt.Errorf("%w of %.0f%%: %s", errBelow, minPercent, strings.Join(names, ", "))
	}
	_, _ = fmt.Fprintf(w, "coverage gate: %d packages at %.0f%% or more\n", len(pkgs), minPercent)
	return nil
}
