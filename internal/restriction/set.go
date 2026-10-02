package restriction

import (
	"bytes"
	"encoding/json"
	"sort"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed318"

	"github.com/rootxkit/uspace-cisp/internal/publication"
)

// MemberName is the extendedProperties member the CISP adds to each
// served restriction feature: the only place the CISP adds to a published
// feature (docs/PLAN.md D4; schema cis/restriction/v1).
const MemberName = "cis_restriction"

// Member is the cis_restriction member of a served feature.
type Member struct {
	ID               string    `json:"id"`
	AnspRef          string    `json:"ansp_ref"`
	AnspVersion      int64     `json:"ansp_version"`
	State            State     `json:"state"`
	StartsAt         time.Time `json:"starts_at"`
	EndsAt           time.Time `json:"ends_at"`
	EndedBy          *string   `json:"ended_by"`
	UspaceAirspaceID string    `json:"uspace_airspace_id"`
}

// MemberOf is the member of h, times in UTC.
func MemberOf(h Head) Member {
	return Member{
		ID: h.ID, AnspRef: h.AnspRef, AnspVersion: h.AnspVersion, State: h.State,
		StartsAt: h.StartsAt.UTC(), EndsAt: h.EndsAt.UTC(), EndedBy: h.EndedBy,
		UspaceAirspaceID: h.UspaceAirspaceID,
	}
}

// Stamp is a copy of f with extendedProperties.cis_restriction set to
// h's member; every other member stays as published, and f is not
// modified.
func Stamp(f ed318.Feature, h Head) (ed318.Feature, error) {
	raw, err := json.Marshal(MemberOf(h))
	if err != nil {
		return f, core.Fieldf(MemberName, "%v", err)
	}
	ext := make(map[string]json.RawMessage, len(f.Properties.ExtendedProperties)+1)
	for k, v := range f.Properties.ExtendedProperties {
		ext[k] = v
	}
	ext[MemberName] = raw
	out := f
	out.Properties.ExtendedProperties = ext
	return out, nil
}

// CurrentSet is the restrictions dataset after h's op: the stored
// current features (each a restriction as served) with h's feature left
// out, and, when h is still current (planned or active), h's feature put
// back stamped with its new member. published is the feature the op
// carries (a create or an extend); nil keeps the stored one. The set is
// ordered by identifier. It refuses a current head whose feature neither
// the op nor the stored set holds.
func CurrentSet(stored []ed318.Feature, h Head, published *ed318.Feature) (*ed318.FeatureCollection, error) {
	features := make([]ed318.Feature, 0, len(stored)+1)
	var kept *ed318.Feature
	for i := range stored {
		if stored[i].Properties.Identifier == h.FeatureID {
			kept = &stored[i]
			continue
		}
		features = append(features, stored[i])
	}
	if h.State.Current() {
		f := published
		if f == nil {
			f = kept
		}
		if f == nil {
			return nil, core.Fieldf("feature", "restriction %s (%s) is %s but the current set holds no feature %q", h.ID, h.AnspRef, h.State, h.FeatureID)
		}
		stamped, err := Stamp(*f, h)
		if err != nil {
			return nil, err
		}
		features = append(features, stamped)
	}
	sort.SliceStable(features, func(i, j int) bool {
		return features[i].Properties.Identifier < features[j].Properties.Identifier
	})
	return &ed318.FeatureCollection{Type: "FeatureCollection", Features: features}, nil
}

// ConflictError is a refused op whose request conflicts with what the
// CISP holds (409), beyond state and ansp_version: an extend whose
// feature differs from the published one.
type ConflictError struct{ *core.FieldError }

// Unwrap is the field error.
func (e *ConflictError) Unwrap() error { return e.FieldError }

// SameExceptEnd reports whether published is stored (the current feature
// of a restriction, as served) but for its one period's endDateTime: the
// only thing an extend may change. The stored cis_restriction member is
// the CISP's and is left out of the comparison; both are compared in
// their canonical form.
func SameExceptEnd(stored, published ed318.Feature) (bool, error) {
	s := stored
	ext := make(map[string]json.RawMessage, len(s.Properties.ExtendedProperties))
	for k, v := range s.Properties.ExtendedProperties {
		if k != MemberName {
			ext[k] = v
		}
	}
	if len(ext) == 0 {
		ext = nil
	}
	s.Properties.ExtendedProperties = ext
	p := published
	if len(p.Properties.LimitedApplicability) == 1 && len(s.Properties.LimitedApplicability) == 1 {
		la := []ed318.TimePeriod{p.Properties.LimitedApplicability[0]}
		la[0].EndDateTime = s.Properties.LimitedApplicability[0].EndDateTime
		p.Properties.LimitedApplicability = la
	}
	a, err := publication.CanonicalFeature(&s, "feature")
	if err != nil {
		return false, err
	}
	b, err := publication.CanonicalFeature(&p, "feature")
	if err != nil {
		return false, err
	}
	return bytes.Equal(a, b), nil
}
