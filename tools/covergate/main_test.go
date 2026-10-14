package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A profile of three packages: store at 90 % (one block counted by two
// binaries, covered by one), deliver at 50 %, a generated package at 0 %,
// and a package outside the scopes.
const profile = `mode: atomic
github.com/rootxkit/uspace-cisp/internal/store/store.go:10.1,12.2 6 1
github.com/rootxkit/uspace-cisp/internal/store/store.go:14.1,16.2 3 0
github.com/rootxkit/uspace-cisp/internal/store/store.go:14.1,16.2 3 4
github.com/rootxkit/uspace-cisp/internal/store/store.go:18.1,19.2 1 0
github.com/rootxkit/uspace-cisp/cmd/deliver/main.go:1.1,2.2 2 1
github.com/rootxkit/uspace-cisp/cmd/deliver/main.go:3.1,4.2 2 0
github.com/rootxkit/uspace-cisp/internal/store/relational/q.go:1.1,9.2 50 0
github.com/rootxkit/uspace-cisp/tools/covergate/main.go:1.1,2.2 5 0
`

func TestMeasure(t *testing.T) {
	pkgs, err := Measure(strings.NewReader(profile), []string{"internal/store/relational"})
	if err != nil {
		t.Fatal(err)
	}
	want := []Package{{Path: "cmd/deliver", Statements: 4, Covered: 2}, {Path: "internal/store", Statements: 10, Covered: 9}}
	if len(pkgs) != len(want) {
		t.Fatalf("packages %+v, want %+v", pkgs, want)
	}
	for i := range want {
		if pkgs[i] != want[i] {
			t.Errorf("package %d %+v, want %+v", i, pkgs[i], want[i])
		}
	}
	// Without the exclusion the generated package is measured, at 0 %.
	all, err := Measure(strings.NewReader(profile), nil)
	if err != nil || len(all) != 3 || all[2].Path != "internal/store/relational" || all[2].Percent() != 0 {
		t.Errorf("without the exclusion %+v %v", all, err)
	}
}

func TestMeasureRefusesWhatIsNotAProfile(t *testing.T) {
	for _, in := range []string{"mode: set\nnot a profile line\n", "mode: set\nx.go:1.1,2.2 a b\n", "mode: set\nx.go 1 1\n"} {
		if _, err := Measure(strings.NewReader(in), nil); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

// The gate holds at a bound every package meets and fails, naming the
// package, at one a package does not; a profile that measures nothing
// fails rather than passing (E-01, E-02).
func TestRun(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "coverage.out")
	if err := os.WriteFile(file, []byte(profile), 0o600); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(dir, "empty.out")
	if err := os.WriteFile(empty, []byte("mode: set\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	exclude := "-exclude=internal/store/relational"
	cases := []struct {
		name     string
		args     []string
		code     int
		out, err string
	}{
		{"every package at the bound", []string{"-min=50", "-profile=" + file, exclude}, 0, "coverage gate: 2 packages at 50% or more", ""},
		{"one package below", []string{"-min=85", "-profile=" + file, exclude}, 1, "cmd/deliver", "below the bound of 85%: cmd/deliver 50.0%"},
		{"the generated package not excluded", []string{"-min=50", "-profile=" + file}, 1, "internal/store/relational", "internal/store/relational 0.0%"},
		{"nothing measured", []string{"-profile=" + empty}, 1, "", "nothing was checked"},
		{"no profile", []string{"-min=85"}, 2, "", "-profile is required"},
		{"a bound of 0", []string{"-min=0", "-profile=" + file}, 2, "", "-min is in"},
		{"a profile that is not there", []string{"-profile=" + filepath.Join(dir, "missing.out")}, 2, "", "missing.out"},
		{"a bad flag", []string{"-nope"}, 2, "", "nope"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if code := run(c.args, &out, &errOut); code != c.code {
				t.Errorf("exit %d, want %d: %s %s", code, c.code, out.String(), errOut.String())
			}
			if !strings.Contains(out.String(), c.out) || !strings.Contains(errOut.String(), c.err) {
				t.Errorf("out %q, err %q; want %q and %q", out.String(), errOut.String(), c.out, c.err)
			}
		})
	}
}
