package console

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// MaxDiffPaths bounds the paths one feature's diff lists
// (docs/WORKPACKAGES/WP-8.md: 200); past it the diff says truncated.
const MaxDiffPaths = 200

// maxDiffDepth bounds the nesting the diff walks (E-10); a deeper value
// is compared whole and reported at its path.
const maxDiffDepth = 64

// The path ops of a diff.
const (
	PathAdded   = "added"
	PathRemoved = "removed"
	PathChanged = "changed"
)

// PathChange is one changed path: a JSON Pointer (RFC 6901) into the
// feature and what happened at it.
type PathChange struct {
	Path string `json:"path"`
	Op   string `json:"op"`
}

// DiffPaths is the flat list of the paths at which b differs from a,
// computed in Go from the two canonical features: a member or an array
// element present in one only is added or removed; a scalar, or a value
// whose JSON type changed, is changed at its own path. Paths are in
// document order with object members sorted. At most limit paths are
// listed (MaxDiffPaths when limit <= 0); truncated says more differ.
// Two documents that do not parse are an error, never a panic.
func DiffPaths(a, b json.RawMessage, limit int) ([]PathChange, bool, error) {
	if limit <= 0 {
		limit = MaxDiffPaths
	}
	va, err := decode(a)
	if err != nil {
		return nil, false, fmt.Errorf("diff: the previous feature: %w", err)
	}
	vb, err := decode(b)
	if err != nil {
		return nil, false, fmt.Errorf("diff: the feature: %w", err)
	}
	d := &differ{limit: limit, out: []PathChange{}}
	d.walk("", va, vb, 0)
	return d.out, d.truncated, nil
}

func decode(raw json.RawMessage) (any, error) {
	if len(raw) == 0 {
		return nil, errors.New("empty")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

type differ struct {
	limit     int
	out       []PathChange
	truncated bool
}

func (d *differ) add(path, op string) {
	if len(d.out) >= d.limit {
		d.truncated = true
		return
	}
	if path == "" {
		path = "/"
	}
	d.out = append(d.out, PathChange{Path: path, Op: op})
}

func (d *differ) walk(path string, a, b any, depth int) {
	if d.truncated {
		return
	}
	if depth >= maxDiffDepth {
		if !equal(a, b) {
			d.add(path, PathChanged)
		}
		return
	}
	switch av := a.(type) {
	case map[string]any:
		bv, ok := b.(map[string]any)
		if !ok {
			d.add(path, PathChanged)
			return
		}
		keys := make([]string, 0, len(av)+len(bv))
		for k := range av {
			keys = append(keys, k)
		}
		for k := range bv {
			if _, in := av[k]; !in {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		for _, k := range keys {
			p := path + "/" + escape(k)
			x, inA := av[k]
			y, inB := bv[k]
			switch {
			case !inA:
				d.add(p, PathAdded)
			case !inB:
				d.add(p, PathRemoved)
			default:
				d.walk(p, x, y, depth+1)
			}
		}
	case []any:
		bv, ok := b.([]any)
		if !ok {
			d.add(path, PathChanged)
			return
		}
		for i := 0; i < max(len(av), len(bv)); i++ {
			p := path + "/" + strconv.Itoa(i)
			switch {
			case i >= len(av):
				d.add(p, PathAdded)
			case i >= len(bv):
				d.add(p, PathRemoved)
			default:
				d.walk(p, av[i], bv[i], depth+1)
			}
		}
	default:
		if !equal(a, b) {
			d.add(path, PathChanged)
		}
	}
}

// equal compares two decoded values; numbers compare as written.
func equal(a, b any) bool {
	x, errA := json.Marshal(a)
	y, errB := json.Marshal(b)
	return errA == nil && errB == nil && bytes.Equal(x, y)
}

// escape is RFC 6901's member escaping.
func escape(k string) string {
	return strings.ReplaceAll(strings.ReplaceAll(k, "~", "~0"), "/", "~1")
}
