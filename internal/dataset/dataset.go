package dataset

import (
	"time"

	"github.com/rootxkit/uspace-core/ed269"
	"github.com/rootxkit/uspace-core/ed318"

	"github.com/rootxkit/uspace-cisp/internal/publication"
)

// Kind is a dataset the authority publishes whole (F1). Restrictions are
// the ANSP's and have their own rules (WP-5).
type Kind string

// The kinds; each equals its publication.Dataset name.
const (
	KindZones          Kind = Kind(publication.DatasetZones)
	KindUspaceAirspace Kind = Kind(publication.DatasetUSpaceAirspace)
	KindUsspList       Kind = Kind(publication.DatasetUSSPList)
)

// KindOf is the kind of dataset, and false for a dataset without
// publication rules here (restrictions, or no dataset at all).
func KindOf(ds publication.Dataset) (Kind, bool) {
	switch ds {
	case publication.DatasetZones:
		return KindZones, true
	case publication.DatasetUSpaceAirspace:
		return KindUspaceAirspace, true
	case publication.DatasetUSSPList:
		return KindUsspList, true
	case publication.DatasetRestrictions:
		return "", false
	}
	return "", false
}

// Rules validate one publication of a dataset.
type Rules interface {
	// Validate accepts body whole, or refuses it whole with every
	// problem by JSON path (capped at lim.MaxProblems, the rest counted
	// in Truncated). It never changes body. now is the instant of
	// receipt.
	Validate(body []byte, lim ed318.Limits, now time.Time) (Accepted, *ed269.Problems)
}

// Accepted is what an accepted publication holds.
type Accepted struct {
	// Collection is the parsed ED-318 collection; nil for ussp_list.
	Collection *ed318.FeatureCollection
	// UsspList is the parsed list; nil for the ED-318 datasets.
	UsspList *UsspList
	// Warnings are what consumers can still judge safely; they are
	// stored with the version and returned to the publisher.
	Warnings []Warning
	// Rows are the features of the version (publication.Rows); empty for
	// ussp_list.
	Rows []publication.FeatureRow
}

// Warning names something a consumer can still judge safely (a daylight
// schedule without end dates). Anything about geometry or limits is a
// refusal, never a warning.
type Warning struct {
	Field  string `json:"field"`
	Reason string `json:"reason"`
}

// For is the rules of kind. A kind without rules gets rules that refuse
// every body, naming the kind: never rules that accept.
func For(kind Kind) Rules {
	switch kind {
	case KindZones:
		return ed318Rules{uspace: false}
	case KindUspaceAirspace:
		return ed318Rules{uspace: true}
	case KindUsspList:
		return usspListRules{}
	}
	return refuseAll{kind: kind}
}

// refuseAll is the rules of an unknown kind.
type refuseAll struct{ kind Kind }

// Validate refuses body.
func (r refuseAll) Validate([]byte, ed318.Limits, time.Time) (Accepted, *ed269.Problems) {
	return Accepted{}, &ed269.Problems{List: []ed269.Problem{{Field: "$", Reason: "no publication rules for dataset " + quote(string(r.kind))}}}
}

// collector gathers problems in the order they are found, up to max;
// the rest are counted.
type collector struct {
	list []ed269.Problem
	more int
	max  int
}

func newCollector(lim ed318.Limits) *collector {
	limit := lim.MaxProblems
	if limit <= 0 {
		limit = ed269.DefaultLimits.MaxProblems
	}
	return &collector{max: limit}
}

func (c *collector) add(field, reason string) {
	if len(c.list) < c.max {
		c.list = append(c.list, ed269.Problem{Field: field, Reason: reason})
		return
	}
	c.more++
}

// result is nil when nothing was found.
func (c *collector) result() *ed269.Problems {
	if len(c.list) == 0 && c.more == 0 {
		return nil
	}
	return &ed269.Problems{List: c.list, Truncated: c.more}
}
