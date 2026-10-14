// Package workflows checks when the jobs of .github/workflows/ci.yml
// run, by evaluating each job's `if:` against the events that start the
// workflow: the subset of the GitHub Actions expression language the
// file uses (==, !=, &&, ||, !, parentheses, startsWith, contains over a
// label list, string literals and context paths). An `if:` outside the
// subset fails the test rather than being guessed.
package workflows

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// jobIf is the `if:` of job name in the workflow file, "" when the job
// has none.
func jobIf(t *testing.T, file, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", file))
	if err != nil {
		t.Fatal(err)
	}
	in := false
	for _, line := range strings.Split(string(raw), "\n") {
		switch {
		case line == "  "+name+":":
			in = true
		case in && strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "   ") && strings.HasSuffix(line, ":"):
			return "" // the next job
		case in && strings.HasPrefix(line, "    if: "):
			return strings.TrimSpace(strings.TrimPrefix(line, "    if: "))
		}
	}
	if !in {
		t.Fatalf("%s has no job %s", file, name)
	}
	return ""
}

// event is the context an expression is evaluated in.
type event struct {
	name, ref, headRef string
	labels             []string
}

func (e event) path(p string) (any, error) {
	switch p {
	case "github.event_name":
		return e.name, nil
	case "github.ref":
		return e.ref, nil
	case "github.head_ref":
		return e.headRef, nil
	case "github.event.pull_request.labels.*.name":
		return e.labels, nil
	}
	return nil, fmt.Errorf("context %q is not modelled", p)
}

// eval evaluates expr in e.
func eval(expr string, e event) (bool, error) {
	toks, err := lex(expr)
	if err != nil {
		return false, err
	}
	p := &parser{toks: toks, e: e}
	v, err := p.or()
	if err != nil {
		return false, err
	}
	if p.i != len(p.toks) {
		return false, fmt.Errorf("trailing %q", p.toks[p.i])
	}
	return truthy(v), nil
}

func lex(s string) ([]string, error) {
	var out []string
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ':
			i++
		case c == '\'':
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				return nil, fmt.Errorf("unterminated string in %q", s)
			}
			out = append(out, s[i:i+j+2])
			i += j + 2
		case strings.HasPrefix(s[i:], "==") || strings.HasPrefix(s[i:], "!=") || strings.HasPrefix(s[i:], "&&") || strings.HasPrefix(s[i:], "||"):
			out = append(out, s[i:i+2])
			i += 2
		case strings.ContainsRune("(),!", rune(c)):
			out = append(out, string(c))
			i++
		default:
			j := i
			for j < len(s) && (s[j] == '_' || s[j] == '.' || s[j] == '*' || s[j] >= 'a' && s[j] <= 'z' || s[j] >= 'A' && s[j] <= 'Z' || s[j] >= '0' && s[j] <= '9') {
				j++
			}
			if j == i {
				return nil, fmt.Errorf("unexpected %q in %q", c, s)
			}
			out = append(out, s[i:j])
			i = j
		}
	}
	return out, nil
}

type parser struct {
	toks []string
	i    int
	e    event
}

func (p *parser) peek() string {
	if p.i < len(p.toks) {
		return p.toks[p.i]
	}
	return ""
}

func (p *parser) next() string {
	t := p.peek()
	p.i++
	return t
}

func (p *parser) or() (any, error) {
	l, err := p.and()
	for err == nil && p.peek() == "||" {
		p.next()
		var r any
		if r, err = p.and(); err == nil {
			l = truthy(l) || truthy(r)
		}
	}
	return l, err
}

func (p *parser) and() (any, error) {
	l, err := p.cmp()
	for err == nil && p.peek() == "&&" {
		p.next()
		var r any
		if r, err = p.cmp(); err == nil {
			l = truthy(l) && truthy(r)
		}
	}
	return l, err
}

func (p *parser) cmp() (any, error) {
	l, err := p.unary()
	if err != nil {
		return nil, err
	}
	if op := p.peek(); op == "==" || op == "!=" {
		p.next()
		r, err := p.unary()
		if err != nil {
			return nil, err
		}
		ls, lok := l.(string)
		rs, rok := r.(string)
		if !lok || !rok {
			return nil, fmt.Errorf("%s compares a non-string", op)
		}
		return (ls == rs) == (op == "=="), nil
	}
	return l, nil
}

func (p *parser) unary() (any, error) {
	switch t := p.next(); {
	case t == "!":
		v, err := p.unary()
		return !truthy(v), err
	case t == "(":
		v, err := p.or()
		if err == nil && p.next() != ")" {
			err = fmt.Errorf("unbalanced parentheses")
		}
		return v, err
	case strings.HasPrefix(t, "'"):
		return strings.Trim(t, "'"), nil
	case t == "startsWith" || t == "contains":
		if p.next() != "(" {
			return nil, fmt.Errorf("%s without arguments", t)
		}
		a, err := p.or()
		if err != nil {
			return nil, fmt.Errorf("%s: first argument: %w", t, err)
		}
		if p.next() != "," {
			return nil, fmt.Errorf("%s takes two arguments", t)
		}
		b, err := p.or()
		if err != nil {
			return nil, fmt.Errorf("%s: second argument: %w", t, err)
		}
		if p.next() != ")" {
			return nil, fmt.Errorf("%s takes two arguments", t)
		}
		bs, ok := b.(string)
		if !ok {
			return nil, fmt.Errorf("%s: the second argument is not a string", t)
		}
		switch av := a.(type) {
		case string:
			if t == "startsWith" {
				return strings.HasPrefix(av, bs), nil
			}
			return strings.Contains(av, bs), nil
		case []string:
			if t == "contains" {
				for _, x := range av {
					if x == bs {
						return true, nil
					}
				}
				return false, nil
			}
		}
		return nil, fmt.Errorf("%s over %T", t, a)
	case t == "":
		return nil, fmt.Errorf("unexpected end")
	default:
		return p.e.path(t)
	}
}

func truthy(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x != ""
	case []string:
		return true
	}
	return false
}

// The release pull request is proven by the lab's conformance suite
// before its merge commit is tagged (docs/RELEASING.md section 2): the
// job runs on main, on a pull request from a release/ branch, and on one
// labelled release; not on any other pull request, nor on a tag (whose
// commit main already proved).
func TestConformanceRunsOnTheReleasePullRequest(t *testing.T) {
	cond := jobIf(t, "ci.yml", "conformance")
	if cond == "" {
		t.Fatal("the conformance job has no if: it would run on every event")
	}
	pr := func(head string, labels ...string) event {
		return event{name: "pull_request", ref: "refs/pull/33/merge", headRef: head, labels: labels}
	}
	cases := []struct {
		name string
		e    event
		want bool
	}{
		{"a push to main", event{name: "push", ref: "refs/heads/main"}, true},
		{"the release pull request (release/ branch)", pr("release/v1.0.0-rc"), true},
		{"a pull request labelled release", pr("fix/conformance-c1", "release"), true},
		{"a release branch that is also labelled", pr("release/v1.1.0", "chaos", "release"), true},
		{"a feature pull request", pr("feat/WP-14-x"), false},
		{"a pull request labelled chaos only", pr("feat/WP-14-x", "chaos"), false},
		{"a branch that only contains release", pr("fix/release-notes"), false},
		{"a push of a tag", event{name: "push", ref: "refs/tags/v1.0.0"}, false},
		{"a push to another branch", event{name: "push", ref: "refs/heads/release/v1.0.0-rc"}, false},
	}
	for _, c := range cases {
		got, err := eval(cond, c.e)
		if err != nil {
			t.Fatalf("%s: %v (if: %s)", c.name, err, cond)
		}
		if got != c.want {
			t.Errorf("%s: runs %v, want %v (if: %s)", c.name, got, c.want, cond)
		}
	}
}

// The evaluator itself, on expressions with a known value: a wrong
// evaluator would make the test above prove nothing.
func TestEval(t *testing.T) {
	e := event{name: "pull_request", ref: "refs/pull/1/merge", headRef: "release/x", labels: []string{"a", "b"}}
	cases := map[string]bool{
		"github.event_name == 'pull_request'":                                                        true,
		"github.event_name != 'pull_request'":                                                        false,
		"!(github.event_name == 'push')":                                                             true,
		"startsWith(github.head_ref, 'release/')":                                                    true,
		"startsWith(github.head_ref, 'feat/')":                                                       false,
		"contains(github.event.pull_request.labels.*.name, 'b')":                                     true,
		"contains(github.event.pull_request.labels.*.name, 'c')":                                     false,
		"github.ref == 'x' || github.head_ref == 'release/x' && github.event_name == 'pull_request'": true,
		"(github.ref == 'x' || github.head_ref == 'release/x') && github.event_name == 'push'":       false,
	}
	for expr, want := range cases {
		got, err := eval(expr, e)
		if err != nil || got != want {
			t.Errorf("%s = %v (%v), want %v", expr, got, err, want)
		}
	}
	for _, bad := range []string{"github.secret == 'x'", "startsWith(github.ref)", "(github.ref == 'x'", "github.ref == 'x", "github.ref ~ 'x'"} {
		if _, err := eval(bad, e); err == nil {
			t.Errorf("%q evaluated", bad)
		}
	}
}
