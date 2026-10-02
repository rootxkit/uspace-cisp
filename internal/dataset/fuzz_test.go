package dataset

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rootxkit/uspace-core/ed269"
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
