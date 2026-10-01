package config

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rootxkit/uspace-core/core"
)

// FieldErrors is every configuration problem found at once, each naming
// the variable it is about.
type FieldErrors []*core.FieldError

// Error lists every problem, separated by "; ".
func (p FieldErrors) Error() string {
	parts := make([]string, 0, len(p))
	for _, fe := range p {
		parts = append(parts, fe.Error())
	}
	return strings.Join(parts, "; ")
}

// env is the typed loader: it reads values from an environment snapshot
// (os.Environ() form), falls back to the catalogue default, records the
// effective value of every variable read, and collects syntax problems
// instead of stopping at the first.
type env struct {
	vals  map[string]string
	used  map[string]string
	probs FieldErrors
}

func newEnv(environ []string) *env {
	e := &env{vals: map[string]string{}, used: map[string]string{}}
	for _, kv := range environ {
		name, value, ok := strings.Cut(kv, "=")
		if !ok || !strings.HasPrefix(name, "CISP_") {
			continue
		}
		e.vals[name] = value
	}
	return e
}

// unknown reports every CISP_* variable in the environment that is not in
// the catalogue: a typo must not silently leave the real variable at its
// default.
func (e *env) unknown() {
	names := make([]string, 0, len(e.vals))
	for name := range e.vals {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if strings.HasPrefix(name, TestPrefix) {
			continue
		}
		if _, ok := lookupVar(name); !ok {
			e.probs = append(e.probs, core.Fieldf(name, "unknown variable; check the spelling against deploy/.env.example"))
		}
	}
}

func (e *env) raw(name string) string {
	v, ok := lookupVar(name)
	if !ok {
		e.probs = append(e.probs, core.Fieldf(name, "not in the configuration catalogue"))
		return ""
	}
	value := strings.TrimSpace(e.vals[name])
	if value == "" {
		value = v.Default
	}
	e.used[name] = value
	return value
}

func (e *env) str(name string) string { return e.raw(name) }

func (e *env) integer(name string) int64 {
	s := e.raw(name)
	if s == "" {
		return 0
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		e.probs = append(e.probs, core.Fieldf(name, "%q is not an integer", s))
		// Continue with the default so the range check does not report
		// the same variable a second time.
		v, _ := lookupVar(name)
		def, _ := strconv.ParseInt(v.Default, 10, 64)
		return def
	}
	return n
}

func (e *env) seconds(name string) time.Duration {
	return time.Duration(e.integer(name)) * time.Second
}

func (e *env) boolean(name string) bool {
	s := e.raw(name)
	b, err := strconv.ParseBool(s)
	if err != nil {
		e.probs = append(e.probs, core.Fieldf(name, "%q is not true or false", s))
		return false
	}
	return b
}

func (e *env) list(name string) []string {
	s := e.raw(name)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, strings.TrimSpace(p))
	}
	return out
}
