package bus

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-cisp/internal/publication"
)

func idsOf(prefix string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("%s%05d", prefix, i)
	}
	return out
}

func changeWith(features, removed []string) publication.Change {
	return publication.Change{
		ID: 9, Dataset: publication.DatasetZones, Version: 3, FeatureIDs: features, RemovedIDs: removed,
		Reason: publication.ReasonPublication, At: time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC),
	}
}

// A change whose lists fit is carried whole, with no summary members
// (the record is byte for byte what it was before the bound); one over
// the bound by count, and one over it by bytes, carries empty lists,
// ids_truncated and both counts instead, with the same pull_url (Q49).
func TestMessageOfBoundsTheIDLists(t *testing.T) {
	const base = "https://cisp.example.test"
	small := MessageOf(changeWith([]string{"ZA", "ZB"}, []string{"ZB"}), base)
	if len(small.FeatureIDs) != 2 || len(small.RemovedIDs) != 1 || small.IDsTruncated || small.FeatureCount != nil || small.RemovedCount != nil {
		t.Errorf("small change %+v", small)
	}
	raw, _ := json.Marshal(small)
	for _, member := range []string{"ids_truncated", "feature_count", "removed_count"} {
		if strings.Contains(string(raw), member) {
			t.Errorf("a listed change carries %s: %s", member, raw)
		}
	}

	atBound := idsOf("Z", MaxListedIDs)
	if m := MessageOf(changeWith(atBound, []string{}), base); m.IDsTruncated || len(m.FeatureIDs) != MaxListedIDs {
		t.Errorf("%d ids: truncated %v, %d listed", MaxListedIDs, m.IDsTruncated, len(m.FeatureIDs))
	}

	for name, c := range map[string]publication.Change{
		"one id over by count":   changeWith(idsOf("Z", MaxListedIDs+1), []string{}),
		"removed ids count too":  changeWith(idsOf("Z", MaxListedIDs/2+1), idsOf("Z", MaxListedIDs/2)),
		"5 000 zones":            changeWith(idsOf("Z", 5000), idsOf("Z", 40)),
		"long ids over by bytes": changeWith(idsOf(strings.Repeat("x", 60), 60), []string{}),
	} {
		t.Run(name, func(t *testing.T) {
			m := MessageOf(c, base)
			if !m.IDsTruncated || len(m.FeatureIDs) != 0 || len(m.RemovedIDs) != 0 || m.FeatureIDs == nil || m.RemovedIDs == nil {
				t.Fatalf("not summarised: truncated %v, %d and %d listed", m.IDsTruncated, len(m.FeatureIDs), len(m.RemovedIDs))
			}
			if m.FeatureCount == nil || *m.FeatureCount != len(c.FeatureIDs) || m.RemovedCount == nil || *m.RemovedCount != len(c.RemovedIDs) {
				t.Errorf("counts %v %v, want %d %d", m.FeatureCount, m.RemovedCount, len(c.FeatureIDs), len(c.RemovedIDs))
			}
			if m.PullURL != base+"/v1/zones?since_version=2" {
				t.Errorf("pull_url %q", m.PullURL)
			}
			raw, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			if len(raw) > 1024 {
				t.Errorf("summary is %d bytes", len(raw))
			}
			// What the bus carries, the consumer reads (the summary
			// members are part of the record, not unknown ones).
			if _, err := ReadChangeMessage(raw); err != nil {
				t.Errorf("read back: %v", err)
			}
		})
	}
}

// The ids a listed change carries never exceed MaxListedIDBytes encoded,
// whatever their length: the largest change that is still listed.
func TestListedIDsStayInsideTheByteBound(t *testing.T) {
	for _, n := range []int{1, 10, 50, 100, MaxListedIDs} {
		for idLen := 1; idLen <= 128; idLen *= 2 {
			ids := make([]string, n)
			for i := range ids {
				ids[i] = fmt.Sprintf("%0*d", idLen, i)
			}
			m := MessageOf(changeWith(ids, ids[:n/2]), "https://cisp.example.test")
			if m.IDsTruncated {
				continue
			}
			f, _ := json.Marshal(m.FeatureIDs)
			r, _ := json.Marshal(m.RemovedIDs)
			if len(f)+len(r) > MaxListedIDBytes {
				t.Errorf("%d ids of %d bytes listed in %d bytes", n, idLen, len(f)+len(r))
			}
		}
	}
}
