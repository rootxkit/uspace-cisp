package dataset

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed269"
	"github.com/rootxkit/uspace-core/ed318"
	"github.com/rootxkit/uspace-core/vectors"
)

// validED269 is the document of ed269_parse.json's
// valid-file-round-trips-unchanged as a generic JSON tree.
func validED269(t testing.TB) map[string]any {
	t.Helper()
	f := vectors.Load(t, "ed269_parse.json")
	for _, c := range f.Cases {
		if c.Name != "valid-file-round-trips-unchanged" {
			continue
		}
		var in struct {
			Document map[string]any `json:"document"`
		}
		if err := json.Unmarshal(c.Input, &in); err != nil {
			t.Fatal(err)
		}
		return in.Document
	}
	t.Fatal("no valid-file-round-trips-unchanged case")
	return nil
}

// mappable is the valid file without TST003, the zone with no authority
// that ED-318 cannot hold.
func mappable(t testing.TB) map[string]any {
	t.Helper()
	d := validED269(t)
	var keep []any
	for _, z := range d["features"].([]any) {
		if z.(map[string]any)["identifier"] != "TST003" {
			keep = append(keep, z)
		}
	}
	d["features"] = keep
	return d
}

// oneZone is the mappable file's first zone alone, with edit applied.
func oneZone(t testing.TB, edit func(z map[string]any)) []byte {
	t.Helper()
	d := mappable(t)
	z := d["features"].([]any)[0].(map[string]any)
	if edit != nil {
		edit(z)
	}
	d["features"] = []any{z}
	return mustJSON(t, d)
}

func mustJSON(t testing.TB, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

const maxBytes = 32 << 20

func TestFromED269MapsAndCarries(t *testing.T) {
	issued := time.Date(2026, 10, 2, 8, 0, 0, 0, time.FixedZone("GET", 4*3600))
	imp, probs := FromED269(mustJSON(t, mappable(t)), maxBytes, ED269Meta{Issued: issued, Provider: "authority-01"})
	if probs != nil {
		t.Fatal(probs)
	}
	m := imp.Collection.Metadata
	if m == nil || m.Issued == nil || !m.Issued.Time.Equal(issued) || m.Issued.Time.Location() != time.UTC {
		t.Fatalf("metadata.issued = %+v, want %v in UTC", m, issued)
	}
	if len(m.Provider) != 1 || *m.Provider[0].Text != "authority-01" || m.Provider[0].Lang != "en" {
		t.Errorf("metadata.provider = %+v", m.Provider)
	}
	if got := imp.Collection.Features[0].Properties.Name; len(got) != 1 || got[0].Lang != DefaultED269Lang {
		t.Errorf("name = %+v, want one text in %s", got, DefaultED269Lang)
	}
	// The body is core's export of the collection, and parses.
	want, err := ed318.Export(imp.Collection)
	if err != nil || !bytes.Equal(want, imp.Body) {
		t.Fatalf("Body is not ed318.Export of Collection (%v)", err)
	}
	if _, p := ed318.Parse(imp.Body, ed318.Limits{}); p != nil {
		t.Fatalf("the mapped body does not parse: %v", p)
	}
	// TST002 carries ED-269 members ED-318 has no member for; each is
	// warned of by its path (E-01: TST001 carries none and has none).
	var tst001, tst002 int
	for _, w := range imp.Warnings {
		switch {
		case strings.HasPrefix(w.Field, "features[0].properties.extendedProperties.ed269."):
			tst001++
		case strings.HasPrefix(w.Field, "features[1].properties.extendedProperties.ed269."):
			tst002++
		}
		if w.Reason != carriedReason {
			t.Errorf("warning %+v", w)
		}
	}
	if tst001 != 0 || tst002 == 0 {
		t.Errorf("warnings %+v: want some on TST002 and none on TST001", imp.Warnings)
	}
}

func TestFromED269WithoutMetaAddsNone(t *testing.T) {
	imp, probs := FromED269(oneZone(t, nil), maxBytes, ED269Meta{Lang: "en-GB"})
	if probs != nil {
		t.Fatal(probs)
	}
	if imp.Collection.Metadata != nil {
		t.Errorf("metadata = %+v, want none", imp.Collection.Metadata)
	}
	if got := imp.Collection.Features[0].Properties.Name; len(got) != 1 || got[0].Lang != "en-GB" {
		t.Errorf("name = %+v, want one text in en-GB", got)
	}
	// The provider alone (E-01 twin of the issued time alone above).
	imp, probs = FromED269(oneZone(t, nil), maxBytes, ED269Meta{Provider: "p"})
	if probs != nil || imp.Collection.Metadata == nil || imp.Collection.Metadata.Issued != nil {
		t.Fatalf("provider only: %+v %v", imp.Collection.Metadata, probs)
	}
}

// Each refusal beside the acceptance that differs in one thing (E-01).
func TestFromED269RefusesByName(t *testing.T) {
	for _, c := range []struct {
		name          string
		refuse, admit func(z map[string]any)
		field, phrase string
	}{
		{
			name:   "the ED-318 spelling of REQ_AUTHORISATION",
			refuse: func(z map[string]any) { z["restriction"] = "REQ_AUTHORIZATION" },
			admit:  func(z map[string]any) { z["restriction"] = "REQ_AUTHORISATION" },
			field:  "features[0].restriction", phrase: "REQ_AUTHORISATION",
		},
		{
			name:   "a FOREIGN_TERRITORY reason, which ED-318 has not",
			refuse: func(z map[string]any) { z["reason"] = []any{"FOREIGN_TERRITORY"} },
			admit:  func(z map[string]any) { z["reason"] = []any{"SENSITIVE"} },
			field:  "features[0].reason[0]", phrase: "FOREIGN_TERRITORY has no ED-318 reason",
		},
		{
			name:   "a zone without an authority",
			refuse: func(z map[string]any) { z["zoneAuthority"] = []any{} },
			admit:  nil,
			field:  "features[0].zoneAuthority", phrase: "ED-318 requires",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, probs := FromED269(oneZone(t, c.refuse), maxBytes, ED269Meta{})
			if probs == nil {
				t.Fatal("accepted")
			}
			found := false
			for _, p := range probs.List {
				if strings.HasSuffix(p.Field, c.field) && strings.Contains(p.Reason, c.phrase) {
					found = true
				}
			}
			if !found {
				t.Fatalf("no problem %s with %q in %v", c.field, c.phrase, probs)
			}
			if _, probs := FromED269(oneZone(t, c.admit), maxBytes, ED269Meta{}); probs != nil {
				t.Fatalf("the twin is refused: %v", probs)
			}
		})
	}
}

// E-10: the byte cap is the caller's, exceeded by one byte.
func TestFromED269ByteCap(t *testing.T) {
	body := oneZone(t, nil)
	if _, probs := FromED269(body, len(body), ED269Meta{}); probs != nil {
		t.Fatalf("at the cap: %v", probs)
	}
	_, probs := FromED269(body, len(body)-1, ED269Meta{})
	if probs == nil || probs.List[0].Field != "$" || !strings.Contains(probs.List[0].Reason, "bytes") {
		t.Fatalf("past the cap: %v", probs)
	}
}

func TestFromED269RefusesABadLang(t *testing.T) {
	_, probs := FromED269(oneZone(t, nil), maxBytes, ED269Meta{Lang: "too-long"})
	if probs == nil || probs.List[0].Field != "lang" {
		t.Fatalf("got %v, want lang refused", probs)
	}
}

func TestCarriedWarnings(t *testing.T) {
	fc := &ed318.FeatureCollection{Features: []ed318.Feature{
		{Properties: ed318.UASZone{ExtendedProperties: map[string]json.RawMessage{ed318.ED269Key: json.RawMessage(`{"uSpaceClass":"X","title":"T"}`)}}},
		{Properties: ed318.UASZone{ExtendedProperties: map[string]json.RawMessage{ed318.ED269Key: json.RawMessage(`"not an object"`)}}},
		{Properties: ed318.UASZone{ExtendedProperties: map[string]json.RawMessage{"other": json.RawMessage(`{}`)}}},
	}}
	got := carriedWarnings(fc)
	want := []string{
		"features[0].properties.extendedProperties.ed269.title",
		"features[0].properties.extendedProperties.ed269.uSpaceClass",
		"features[1].properties.extendedProperties.ed269",
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i].Field != want[i] {
			t.Errorf("warning %d: %s, want %s", i, got[i].Field, want[i])
		}
	}
}

func TestProblemsOf(t *testing.T) {
	if p := problemsOf(core.Fieldf("a.b", "bad")); p.List[0] != (ed269.Problem{Field: "a.b", Reason: "bad"}) {
		t.Errorf("field error: %+v", p)
	}
	if p := problemsOf(errors.New("plain")); p.List[0] != (ed269.Problem{Field: "$", Reason: "plain"}) {
		t.Errorf("plain error: %+v", p)
	}
}

func TestToED269(t *testing.T) {
	src := oneZone(t, nil)
	imp, probs := FromED269(src, maxBytes, ED269Meta{Issued: time.Now(), Provider: "p"})
	if probs != nil {
		t.Fatal(probs)
	}
	out, err := ToED269(imp.Body, maxBytes, "")
	if err != nil {
		t.Fatal(err)
	}
	a, pa := ed269.Parse(src, ed269.Limits{})
	b, pb := ed269.Parse(out, ed269.Limits{})
	if pa != nil || pb != nil {
		t.Fatal(pa, pb)
	}
	ea, _ := ed269.Export(a)
	eb, _ := ed269.Export(b)
	if !sameJSON(t, ea, eb) {
		t.Errorf("round trip differs:\n in %s\nout %s", ea, eb)
	}

	// What ED-269 cannot hold is a field error naming it.
	uspace := strings.Replace(string(imp.Body), `"type":"PROHIBITED"`, `"type":"USPACE"`, 1)
	if uspace == string(imp.Body) {
		uspace = strings.Replace(string(imp.Body), `"type":"`+string(imp.Collection.Features[0].Properties.Type)+`"`, `"type":"USPACE"`, 1)
	}
	_, err = ToED269([]byte(uspace), maxBytes, "ka")
	var fe *core.FieldError
	if !errors.As(err, &fe) || !strings.HasSuffix(fe.Field, "properties.type") {
		t.Fatalf("USPACE: %v", err)
	}
	// A body that is not ED-318 is its problems.
	_, err = ToED269([]byte(`{"features":`), maxBytes, "ka")
	var ps *ed269.Problems
	if !errors.As(err, &ps) {
		t.Fatalf("not JSON: %v", err)
	}
}

func sameJSON(t *testing.T, a, b []byte) bool {
	t.Helper()
	var x, y any
	if err := json.Unmarshal(a, &x); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &y); err != nil {
		t.Fatal(err)
	}
	return bytes.Equal(mustJSON(t, x), mustJSON(t, y))
}
