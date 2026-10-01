package publication

import (
	"encoding/json"
	"maps"
	"strconv"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed318"
)

// The top-level members every served ED-318 collection carries
// (docs/PLAN.md section 6.3, Q1).
const (
	MemberDataset   = "cis_dataset"
	MemberVersion   = "cis_version"
	MemberUpdatedAt = "cis_updated_at"
)

// ProviderLang is the language tag of metadata.provider when the CISP
// writes the publisher there: the publisher is a client identifier, not
// a text in a language.
const ProviderLang = "en"

// Snapshot is the unfiltered GET /v1/{dataset} body of a version:
// ed318.Export of fc with metadata.issued = issued, metadata.provider =
// provider (left as published when provider is empty), and the top-level
// cis_dataset, cis_version and cis_updated_at. fc is not modified. The
// bytes are deterministic. It fails with a *core.FieldError for a nil
// collection or one ed318.Export refuses.
func Snapshot(dataset Dataset, version int64, issued time.Time, provider string, fc *ed318.FeatureCollection) ([]byte, error) {
	if fc == nil {
		return nil, core.Fieldf("$", "no feature collection")
	}
	out := *fc
	meta := ed318.Metadata{}
	if fc.Metadata != nil {
		meta = *fc.Metadata
	}
	at := issued.UTC()
	stamp := at.Format(time.RFC3339Nano)
	meta.Issued = &ed318.DateTime{Time: at, Text: stamp}
	if provider != "" {
		p := provider
		meta.Provider = []ed318.Text{{Text: &p, Lang: ProviderLang}}
	}
	out.Metadata = &meta

	out.Extra = make(map[string]json.RawMessage, len(fc.Extra)+3)
	maps.Copy(out.Extra, fc.Extra)
	ds, err := json.Marshal(string(dataset))
	if err != nil {
		return nil, core.Fieldf(MemberDataset, "%v", err)
	}
	ts, err := json.Marshal(stamp)
	if err != nil {
		return nil, core.Fieldf(MemberUpdatedAt, "%v", err)
	}
	out.Extra[MemberDataset] = ds
	out.Extra[MemberVersion] = json.RawMessage(strconv.FormatInt(version, 10))
	out.Extra[MemberUpdatedAt] = ts
	return ed318.Export(&out)
}
