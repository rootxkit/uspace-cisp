package publication

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

// The USSP list snapshot is the canonical list with the three cis_*
// members; the published members are kept as published, and the same
// list re-spaced gives the same bytes.
func TestUsspListSnapshot(t *testing.T) {
	body := []byte(`{"ussps":[{"ussp_id":"USSP-DEV","name":"<Lab> & co"}],
	  "schema":"cis/ussp_list/v1", "issued":"2026-10-02T08:00:00Z", "n": 1.50}`)
	at := time.Date(2026, 10, 2, 9, 0, 0, 123000000, time.FixedZone("GET", 4*3600))
	snap, err := UsspListSnapshot(7, at, body)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"cis_dataset":"ussp_list","cis_updated_at":"2026-10-02T05:00:00.123Z","cis_version":7,` +
		`"issued":"2026-10-02T08:00:00Z","n":1.50,"schema":"cis/ussp_list/v1","ussps":[{"name":"<Lab> & co","ussp_id":"USSP-DEV"}]}`
	if string(snap) != want {
		t.Fatalf("snapshot\n%s\nwant\n%s", snap, want)
	}
	respaced := append([]byte("\n  "), bytes.ReplaceAll(body, []byte(", "), []byte(","))...)
	again, err := UsspListSnapshot(7, at, respaced)
	if err != nil || !bytes.Equal(again, snap) {
		t.Errorf("re-spaced: %s %v", again, err)
	}
	a, err1 := UsspListCanonical(body)
	b, err2 := UsspListCanonical(respaced)
	if err1 != nil || err2 != nil || !bytes.Equal(a, b) {
		t.Errorf("canonical forms differ: %s / %s", a, b)
	}
	var doc map[string]any
	if err := json.Unmarshal(snap, &doc); err != nil {
		t.Fatal(err)
	}
	for _, refused := range [][]byte{[]byte(`[1]`), []byte(`null`), []byte(`{`), []byte(``)} {
		if _, err := UsspListSnapshot(1, at, refused); !isField(err, "$") {
			t.Errorf("%q: %v", refused, err)
		}
	}
	if _, err := UsspListCanonical([]byte(`{`)); !isField(err, "$") {
		t.Errorf("broken JSON canonical: %v", err)
	}
}
