package dataset

import (
	"errors"
	"sort"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed269"
	"github.com/rootxkit/uspace-core/ed318"
)

// The ED-269 bridge (docs/WORKPACKAGES/WP-12.md, spec 02 F1): an ED-269
// publication of zones is read by uspace-core/ed269.Parse and mapped by
// uspace-core/ed318.FromED269; a stored ED-318 version is exported by
// ed318.ToED269 and ed269.Export. The mapping is core's: nothing here
// converts a unit, fixes a spelling or fills in a default (CLAUDE.md
// hard rule 2). What does not map is refused with core's reason.

// MediaTypeED269 is the content type of an ED-269 document, in a
// publication and in an export.
const MediaTypeED269 = "application/vnd.ed269+json"

// MappedFromED269 names the format an imported version was mapped from
// (PublicationResult.mapped_from), and MappedFromED318 the format an
// export was mapped from (X-CIS-Mapped-From).
const (
	MappedFromED269 = "ed269"
	MappedFromED318 = "ed318"
)

// DefaultED269Lang is the language of ED-269's single-string texts when
// the publisher names none: Georgian, the authority's language (WP-12).
const DefaultED269Lang = "ka"

// ED269Import is an ED-269 publication mapped onto ED-318.
type ED269Import struct {
	// Collection is the mapped collection, with metadata issued and
	// provider set.
	Collection *ed318.FeatureCollection
	// Body is ed318.Export(Collection): the bytes stored as the version.
	Body []byte
	// Warnings name every ED-269 member that has no ED-318 member and
	// travels under extendedProperties.ed269 (the mapping warnings).
	Warnings []Warning
}

// ED269Meta is what the CISP adds to a mapped collection: the instant of
// receipt (metadata.issued) and the publisher (metadata.provider, in
// English: a client id is not a text of the publisher's). Zero values
// add nothing (cispctl ed269 convert maps without metadata).
type ED269Meta struct {
	Issued   time.Time
	Provider string
	// Lang is the language of ED-269's single-string texts; empty is
	// DefaultED269Lang.
	Lang string
}

// FromED269 reads body strictly as an ED-269 document (core's limits,
// with maxBytes as the byte cap) and maps it onto ED-318 through core. A
// refusal names every ED-269 problem by its ED-269 path; a document that
// parses but does not map is refused with core's mapping reason, named
// by the path core gives. It never changes body.
func FromED269(body []byte, maxBytes int, meta ED269Meta) (ED269Import, *ed269.Problems) {
	doc, probs := ed269.Parse(body, ed269.Limits{MaxBytes: maxBytes})
	if probs != nil {
		return ED269Import{}, probs
	}
	lang := meta.Lang
	if lang == "" {
		lang = DefaultED269Lang
	}
	var m ed318.Metadata
	if !meta.Issued.IsZero() {
		m.Issued = &ed318.DateTime{Time: meta.Issued.UTC()}
	}
	if meta.Provider != "" {
		provider := meta.Provider
		m.Provider = []ed318.Text{{Text: &provider, Lang: "en"}}
	}
	fc, err := ed318.FromED269(doc, m, lang)
	if err != nil {
		return ED269Import{}, problemsOf(err)
	}
	out, err := ed318.Export(fc)
	if err != nil {
		return ED269Import{}, problemsOf(err)
	}
	return ED269Import{Collection: fc, Body: out, Warnings: carriedWarnings(fc)}, nil
}

// problemsOf is a mapping error as the report a refusal carries.
func problemsOf(err error) *ed269.Problems {
	var fe *core.FieldError
	if errors.As(err, &fe) {
		return &ed269.Problems{List: []ed269.Problem{{Field: fe.Field, Reason: fe.Reason}}}
	}
	return &ed269.Problems{List: []ed269.Problem{{Field: "$", Reason: err.Error()}}}
}

// carriedReason is the warning of a member carried under ED269Key.
const carriedReason = "the ED-269 member has no ED-318 member; it is carried here as published and returned on export"

// carriedWarnings names each member core carried under
// extendedProperties.ed269, in feature order and by name.
func carriedWarnings(fc *ed318.FeatureCollection) []Warning {
	var out []Warning
	for i := range fc.Features {
		raw, ok := fc.Features[i].Properties.ExtendedProperties[ed318.ED269Key]
		if !ok {
			continue
		}
		path := index("features", i) + ".properties.extendedProperties." + ed318.ED269Key
		ms, err := members(raw)
		if err != nil {
			// Core wrote the member; one that is not an object is still
			// named, never skipped.
			out = append(out, Warning{Field: path, Reason: carriedReason})
			continue
		}
		keys := make([]string, 0, len(ms))
		for _, m := range ms {
			keys = append(keys, m.key)
		}
		sort.Strings(keys)
		for _, k := range keys {
			out = append(out, Warning{Field: join(path, k), Reason: carriedReason})
		}
	}
	return out
}

// ToED269 exports an ED-318 collection (a stored version's body) as an
// ED-269 document through core, with the texts in lang (empty is
// DefaultED269Lang). A collection ED-269 cannot represent (USPACE, DAR,
// daylight events, two-layer zones) is a *core.FieldError naming the
// field; a body that does not parse as ED-318 is its *ed269.Problems (a
// stored version always parses).
func ToED269(body []byte, maxBytes int, lang string) ([]byte, error) {
	fc, probs := ed318.Parse(body, ed318.Limits{MaxBytes: maxBytes})
	if probs != nil {
		return nil, probs
	}
	if lang == "" {
		lang = DefaultED269Lang
	}
	doc, err := ed318.ToED269(fc, lang)
	if err != nil {
		return nil, err
	}
	return ed269.Export(doc)
}
