package dataset

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/ed269"
	"github.com/rootxkit/uspace-core/ed318"
)

// FuzzValidateUsspList: the hand-written validator never panics, and
// whatever it accepts it accepts again (the parse is a function of the
// bytes).
func FuzzValidateUsspList(f *testing.F) {
	example, err := os.ReadFile(filepath.Join("..", "..", "schemas", "cis", "ussp_list", "examples", "lab.json"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(example)
	f.Add([]byte(`{"schema":"cis/ussp_list/v1","issued":"2026-10-02T00:00:00Z","ussps":[]}`))
	f.Add([]byte(`{"ussps":[{"ussp_id":"A","ussp_id":"B"}]}`))
	f.Add([]byte(`[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[`))
	f.Add([]byte(`{"ussps":[{"base_url":"https://u:p@[::1"}]}`))
	f.Add([]byte{0xff, 0xfe})
	f.Fuzz(func(t *testing.T, body []byte) {
		list, probs := ValidateUsspList(body)
		if probs == nil && list == nil {
			t.Fatal("accepted without a list")
		}
		if probs != nil && len(probs.List) > ed269.DefaultLimits.MaxProblems {
			t.Fatalf("%d problems listed", len(probs.List))
		}
		if probs == nil {
			if _, again := ValidateUsspList(body); again != nil {
				t.Fatalf("accepted once, refused again: %v", again)
			}
		}
	})
}

// FuzzFromED269: the ED-269 bridge never panics on any body, lists at
// most MaxProblems problems, and what it accepts is ED-318 that core
// parses and that maps back to ED-269.
func FuzzFromED269(f *testing.F) {
	f.Add(oneZone(f, nil))
	f.Add(mustJSON(f, mappable(f)))
	f.Add(mustJSON(f, validED269(f)))
	f.Add([]byte(`{"features":[]}`))
	f.Add([]byte(`{"UASZoneList":{"features":[]}}`))
	f.Add([]byte(`[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[`))
	f.Add([]byte{0xff, 0xfe})
	f.Fuzz(func(t *testing.T, body []byte) {
		imp, probs := FromED269(body, 1<<20, ED269Meta{Issued: time.Unix(0, 0), Provider: "fuzz"})
		if probs != nil {
			if len(probs.List) == 0 || len(probs.List) > ed269.DefaultLimits.MaxProblems {
				t.Fatalf("%d problems listed", len(probs.List))
			}
			return
		}
		if _, p := ed318.Parse(imp.Body, ed318.Limits{}); p != nil {
			t.Fatalf("accepted, but the mapped body is refused: %v", p)
		}
		if _, err := ToED269(imp.Body, 1<<20, ""); err != nil {
			t.Fatalf("accepted, but the mapped body does not map back: %v", err)
		}
	})
}

// FuzzToED269: the export never panics on any body.
func FuzzToED269(f *testing.F) {
	imp, probs := FromED269(oneZone(f, nil), 1<<20, ED269Meta{})
	if probs != nil {
		f.Fatal(probs)
	}
	f.Add(imp.Body)
	f.Add([]byte(`{"type":"FeatureCollection","features":[]}`))
	f.Add([]byte(`{"type":"FeatureCollection"`))
	f.Fuzz(func(t *testing.T, body []byte) {
		out, err := ToED269(body, 1<<20, "ka")
		if err == nil {
			if _, p := ed269.Parse(out, ed269.Limits{}); p != nil {
				t.Fatalf("exported ED-269 that core refuses: %v", p)
			}
		}
	})
}
