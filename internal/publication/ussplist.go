package publication

import (
	"bytes"
	"encoding/json"
	"strconv"
	"time"

	"github.com/rootxkit/uspace-core/core"
)

// UsspListSnapshot is the unfiltered GET /v1/ussp_list body of a
// version (docs/WORKPACKAGES/WP-3.md): the canonical JSON of the
// published list (Canonical: compact, keys sorted, numbers as written)
// with the top-level members cis_dataset, cis_version and cis_updated_at
// added, as every ED-318 snapshot carries them (section 15 Q1). The
// published members are not changed. It fails with a *core.FieldError
// for a body that is not one JSON object.
func UsspListSnapshot(version int64, issued time.Time, body []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil || doc == nil {
		return nil, core.Fieldf("$", "the USSP list is not a JSON object")
	}
	doc[MemberDataset] = string(DatasetUSSPList)
	doc[MemberVersion] = json.Number(strconv.FormatInt(version, 10))
	doc[MemberUpdatedAt] = issued.UTC().Format(time.RFC3339Nano)
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, core.Fieldf("$", "%v", err)
	}
	return Canonical(raw)
}

// UsspListCanonical is the canonical form of a published list, the
// content two publications are compared by (D3): equal canonical bytes
// are the same list whatever the whitespace or member order.
func UsspListCanonical(body []byte) ([]byte, error) {
	out, err := Canonical(body)
	if err != nil {
		return nil, core.Fieldf("$", "%v", err)
	}
	return out, nil
}
