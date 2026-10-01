package publication

import (
	"encoding/json"
	"sort"
)

// Op is what a version did to one feature against the previous version.
type Op string

// The ops (the features.op column).
const (
	OpAdded     Op = "added"
	OpChanged   Op = "changed"
	OpRemoved   Op = "removed"
	OpUnchanged Op = "unchanged"
)

// Diff is the difference between two versions of a dataset, by
// identifier. Added, Changed and Removed are sorted; Ops holds every
// identifier of either side, the unchanged ones included.
type Diff struct {
	Added, Changed, Removed []string
	Ops                     map[string]Op
}

// Empty reports whether nothing was added, changed or removed.
func (d Diff) Empty() bool {
	return len(d.Added) == 0 && len(d.Changed) == 0 && len(d.Removed) == 0
}

// IDs is every identifier the diff touches (added, changed, removed),
// sorted.
func (d Diff) IDs() []string {
	out := make([]string, 0, len(d.Added)+len(d.Changed)+len(d.Removed))
	out = append(out, d.Added...)
	out = append(out, d.Changed...)
	out = append(out, d.Removed...)
	sort.Strings(out)
	return out
}

// DiffRows compares prev and next by identifier: a feature is changed
// when its canonical hash differs. The result is deterministic.
func DiffRows(prev, next []FeatureRow) Diff {
	before := byID(prev)
	d := Diff{Ops: make(map[string]Op, len(prev)+len(next))}
	for i := range next {
		r := &next[i]
		old, ok := before[r.ID]
		switch {
		case !ok:
			d.Added = append(d.Added, r.ID)
			d.Ops[r.ID] = OpAdded
		case old.SHA256 != r.SHA256:
			d.Changed = append(d.Changed, r.ID)
			d.Ops[r.ID] = OpChanged
		default:
			d.Ops[r.ID] = OpUnchanged
		}
	}
	for i := range prev {
		if _, ok := d.Ops[prev[i].ID]; !ok {
			d.Removed = append(d.Removed, prev[i].ID)
			d.Ops[prev[i].ID] = OpRemoved
		}
	}
	sort.Strings(d.Added)
	sort.Strings(d.Changed)
	sort.Strings(d.Removed)
	return d
}

// Apply rebuilds the next version from prev and the diff, taking added
// and changed rows from next: Apply(a, b, DiffRows(a, b)) equals b sorted
// by identifier. The result is sorted by identifier.
func Apply(prev, next []FeatureRow, d Diff) []FeatureRow {
	out := byID(prev)
	for _, id := range d.Removed {
		delete(out, id)
	}
	after := byID(next)
	for _, id := range d.Added {
		out[id] = after[id]
	}
	for _, id := range d.Changed {
		out[id] = after[id]
	}
	return sorted(out)
}

// DatasetDelta is the answer to since_version: the features added and
// changed between two versions (canonical JSON) and the identifiers
// removed.
type DatasetDelta struct {
	FromVersion, ToVersion int64
	Added, Changed         []json.RawMessage
	Removed                []string
}

// Delta is the delta from fromRows (version fromV) to toRows (version
// toV), in identifier order.
func Delta(fromRows, toRows []FeatureRow, fromV, toV int64) DatasetDelta {
	d := DiffRows(fromRows, toRows)
	after := byID(toRows)
	out := DatasetDelta{
		FromVersion: fromV,
		ToVersion:   toV,
		Added:       make([]json.RawMessage, 0, len(d.Added)),
		Changed:     make([]json.RawMessage, 0, len(d.Changed)),
		Removed:     append([]string{}, d.Removed...),
	}
	for _, id := range d.Added {
		out.Added = append(out.Added, json.RawMessage(after[id].Canonical))
	}
	for _, id := range d.Changed {
		out.Changed = append(out.Changed, json.RawMessage(after[id].Canonical))
	}
	return out
}

func byID(rows []FeatureRow) map[string]FeatureRow {
	m := make(map[string]FeatureRow, len(rows))
	for i := range rows {
		m[rows[i].ID] = rows[i]
	}
	return m
}

func sorted(m map[string]FeatureRow) []FeatureRow {
	out := make([]FeatureRow, 0, len(m))
	for id := range m {
		out = append(out, m[id])
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// SortRows sorts rows by identifier in place.
func SortRows(rows []FeatureRow) {
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
}
