package dataset

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/ed318"
)

var testNow = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

func edLimits() ed318.Limits { return ed318.Limits{} }

func replaceOnce(t *testing.T, s, old, repl string) string {
	t.Helper()
	if !strings.Contains(s, old) {
		t.Fatalf("%q not in %s", old, s)
	}
	return strings.Replace(s, old, repl, 1)
}

// exampleList is schemas/cis/ussp_list/examples/lab.json as maps.
func exampleList(t *testing.T) doc {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "schemas", "cis", "ussp_list", "examples", "lab.json"))
	if err != nil {
		t.Fatal(err)
	}
	var d doc
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	return d
}

func ussp(d doc, i int) doc { return d["ussps"].([]any)[i].(doc) }

func refuseList(t *testing.T, d doc, field, phrase string) {
	t.Helper()
	mustRefuse(t, KindUsspList, d, field, phrase)
}

func TestUsspListExampleAccepted(t *testing.T) {
	acc := mustAccept(t, KindUsspList, exampleList(t))
	l := acc.UsspList
	if l == nil || acc.Collection != nil || len(acc.Rows) != 0 {
		t.Fatalf("accepted %+v", acc)
	}
	if l.Schema != UsspListSchema || len(l.Ussps) != 2 || l.Ussps[0].UsspID != "USSP-DEV" || l.Ussps[1].Status != "limited" {
		t.Errorf("list %+v", l)
	}
	if c := l.Ussps[0].Contact; c.Email == nil || c.Phone == nil || c.URL == nil {
		t.Errorf("contact %+v", c)
	}
	if c := l.Ussps[1].Contact; c.Phone != nil || c.URL != nil {
		t.Errorf("absent contact members set: %+v", c)
	}
	if !l.Issued.Equal(time.Date(2026, 10, 2, 8, 0, 0, 0, time.UTC)) || len(l.Ussps[1].Services) != 6 {
		t.Errorf("issued %v services %v", l.Issued, l.Ussps[1].Services)
	}
	// The exported validator agrees.
	if _, probs := ValidateUsspList(body(t, exampleList(t))); probs != nil {
		t.Errorf("ValidateUsspList: %v", probs)
	}
}

// E-01 pairs: each refusal beside the list that differs in one thing.
func TestUsspListRefusalPairs(t *testing.T) {
	cases := []struct {
		name          string
		breakIt, fix  func(d doc)
		field, phrase string
	}{
		{"duplicate ussp_id names both indexes",
			func(d doc) { ussp(d, 1)["ussp_id"] = "USSP-DEV" },
			func(d doc) { ussp(d, 1)["ussp_id"] = "USSP-B2" },
			"ussps[1].ussp_id", "repeats ussps[0].ussp_id"},
		{"base_url with userinfo",
			func(d doc) { ussp(d, 0)["base_url"] = "https://user:pw@ussp.example.test" },
			func(d doc) { ussp(d, 0)["base_url"] = "https://ussp.example.test" },
			"ussps[0].base_url", "userinfo"},
		{"base_url over http",
			func(d doc) { ussp(d, 0)["base_url"] = "http://ussp.example.test" },
			func(d doc) { ussp(d, 0)["base_url"] = "https://ussp.example.test:8443/v1" },
			"ussps[0].base_url", "https"},
		{"base_url host over 253 characters",
			func(d doc) { ussp(d, 0)["base_url"] = "https://" + strings.Repeat("a", 254) },
			func(d doc) { ussp(d, 0)["base_url"] = "https://" + strings.Repeat("a", 253) },
			"ussps[0].base_url", "at most 253"},
		{"base_url without a host",
			func(d doc) { ussp(d, 0)["base_url"] = "https:opaque" },
			func(d doc) { ussp(d, 0)["base_url"] = "https://h.example.test" },
			"ussps[0].base_url", "no host"},
		{"unknown top-level member",
			func(d doc) { d["note"] = "x" },
			func(d doc) { delete(d, "note") },
			"note", "unknown member"},
		{"unknown entry member",
			func(d doc) { ussp(d, 0)["fax"] = "x" },
			func(d doc) { delete(ussp(d, 0), "fax") },
			"ussps[0].fax", "unknown member"},
		{"unknown contact member",
			func(d doc) { ussp(d, 0)["contact"].(doc)["fax"] = "x" },
			func(d doc) { delete(ussp(d, 0)["contact"].(doc), "fax") },
			"ussps[0].contact.fax", "unknown member"},
		{"a cis_ member is the CISP's",
			func(d doc) { d["cis_version"] = 3 },
			func(d doc) { delete(d, "cis_version") },
			"cis_version", "written by the CISP"},
		{"wrong schema",
			func(d doc) { d["schema"] = "cis/ussp_list/v2" },
			func(d doc) { d["schema"] = "cis/ussp_list/v1" },
			"schema", "must be"},
		{"issued without an offset",
			func(d doc) { d["issued"] = "2026-10-02T08:00:00" },
			func(d doc) { d["issued"] = "2026-10-02T08:00:00+04:00" },
			"issued", "RFC 3339"},
		{"issued not a string",
			func(d doc) { d["issued"] = 5 },
			func(d doc) { d["issued"] = "2026-10-02T08:00:00Z" },
			"issued", "must be an RFC 3339 date-time string"},
		{"a required member missing",
			func(d doc) { delete(d, "issued") },
			func(d doc) { d["issued"] = "2026-10-02T08:00:00Z" },
			"issued", "is required"},
		{"a required entry member missing",
			func(d doc) { delete(ussp(d, 1), "terms_url") },
			func(d doc) { ussp(d, 1)["terms_url"] = "https://second.example.test/terms" },
			"ussps[1].terms_url", "is required"},
		{"terms_url over http",
			func(d doc) { ussp(d, 1)["terms_url"] = "http://second.example.test/terms" },
			func(d doc) { ussp(d, 1)["terms_url"] = "https://second.example.test/terms" },
			"ussps[1].terms_url", "https"},
		{"a service outside Annex VI",
			func(d doc) { ussp(d, 0)["services"] = []any{"network_identification", "parcel_delivery"} },
			func(d doc) { ussp(d, 0)["services"] = []any{"network_identification"} },
			"ussps[0].services[1]", "must be one of"},
		{"services not an array",
			func(d doc) { ussp(d, 0)["services"] = "weather" },
			func(d doc) { ussp(d, 0)["services"] = []any{} },
			"ussps[0].services", "must be an array"},
		{"an unknown status",
			func(d doc) { ussp(d, 0)["status"] = "closed" },
			func(d doc) { ussp(d, 0)["status"] = "suspended" },
			"ussps[0].status", "must be one of"},
		{"valid_until before valid_from",
			func(d doc) { ussp(d, 0)["valid_until"] = "2026-09-01T00:00:00Z" },
			func(d doc) { ussp(d, 0)["valid_until"] = "2026-10-01T00:00:00Z" },
			"ussps[0].valid_until", "before valid_from"},
		{"an empty ussp_id",
			func(d doc) { ussp(d, 0)["ussp_id"] = "" },
			func(d doc) { ussp(d, 0)["ussp_id"] = "X" },
			"ussps[0].ussp_id", "at least 1"},
		{"a name over 200 characters",
			func(d doc) { ussp(d, 0)["name"] = strings.Repeat("ა", 201) },
			func(d doc) { ussp(d, 0)["name"] = strings.Repeat("ა", 200) },
			"ussps[0].name", "at most 200"},
		{"certificate_id not a string",
			func(d doc) { ussp(d, 0)["certificate_id"] = 1 },
			func(d doc) { ussp(d, 0)["certificate_id"] = "1" },
			"ussps[0].certificate_id", "must be a string"},
		{"an e-mail without @",
			func(d doc) { ussp(d, 0)["contact"].(doc)["email"] = "ops.example.test" },
			func(d doc) { ussp(d, 0)["contact"].(doc)["email"] = "ops@example.test" },
			"ussps[0].contact.email", "not an e-mail address"},
		{"a contact url over http",
			func(d doc) { ussp(d, 0)["contact"].(doc)["url"] = "http://x.example.test" },
			func(d doc) { ussp(d, 0)["contact"].(doc)["url"] = "https://x.example.test" },
			"ussps[0].contact.url", "https"},
		{"a phone over 50 characters",
			func(d doc) { ussp(d, 0)["contact"].(doc)["phone"] = strings.Repeat("1", 51) },
			func(d doc) { ussp(d, 0)["contact"].(doc)["phone"] = strings.Repeat("1", 50) },
			"ussps[0].contact.phone", "at most 50"},
		{"contact not an object",
			func(d doc) { ussp(d, 0)["contact"] = "ops" },
			func(d doc) { ussp(d, 0)["contact"] = doc{} },
			"ussps[0].contact", "must be a JSON object"},
		{"a limitation over 1000 characters",
			func(d doc) { ussp(d, 0)["certification_limitations"] = []any{strings.Repeat("x", 1001)} },
			func(d doc) { ussp(d, 0)["certification_limitations"] = []any{strings.Repeat("x", 1000)} },
			"ussps[0].certification_limitations[0]", "at most 1000"},
		{"an entry that is not an object",
			func(d doc) { d["ussps"].([]any)[1] = "USSP-B2" },
			func(d doc) { d["ussps"] = d["ussps"].([]any)[:1] },
			"ussps[1]", "must be a JSON object"},
		{"ussps not an array",
			func(d doc) { d["ussps"] = doc{} },
			func(d doc) { d["ussps"] = []any{} },
			"ussps", "must be an array"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := exampleList(t)
			c.breakIt(d)
			refuseList(t, d, c.field, c.phrase)
			c.fix(d)
			mustAccept(t, KindUsspList, d)
		})
	}
}

// E-10: 201 entries are refused, 200 accepted; 51 limitations refused, 50
// accepted.
func TestUsspListBounds(t *testing.T) {
	d := exampleList(t)
	tmpl, _ := json.Marshal(ussp(d, 0))
	entries := make([]any, MaxUssps+1)
	for i := range entries {
		var u doc
		_ = json.Unmarshal(tmpl, &u)
		u["ussp_id"] = "U" + strconv.Itoa(i)
		entries[i] = u
	}
	d["ussps"] = entries
	refuseList(t, d, "ussps", "has 201 entries; at most 200")
	d["ussps"] = entries[:MaxUssps]
	if acc := mustAccept(t, KindUsspList, d); len(acc.UsspList.Ussps) != MaxUssps {
		t.Errorf("%d entries", len(acc.UsspList.Ussps))
	}

	d = exampleList(t)
	lims := make([]any, MaxLimitations+1)
	for i := range lims {
		lims[i] = "limit"
	}
	ussp(d, 0)["certification_limitations"] = lims
	refuseList(t, d, "ussps[0].certification_limitations", "at most 50")
	ussp(d, 0)["certification_limitations"] = lims[:MaxLimitations]
	mustAccept(t, KindUsspList, d)
	ussp(d, 0)["services"] = []any{"weather", "weather", "weather", "weather", "weather", "weather", "weather"}
	refuseList(t, d, "ussps[0].services", "at most 6")
}

// Whole-document refusals: not UTF-8, not an object, a repeated member,
// trailing data.
func TestUsspListDocumentRefusals(t *testing.T) {
	good := body(t, exampleList(t))
	for name, c := range map[string]struct {
		in     []byte
		field  string
		phrase string
	}{
		"not UTF-8":        {append([]byte{0xff}, good...), "$", "not UTF-8"},
		"not an object":    {[]byte(`[1]`), "$", "must be a JSON object, not an array"},
		"repeated member":  {[]byte(replaceOnce(t, string(good), `"issued":`, `"issued":"x","issued":`)), "$", `repeats the member "issued"`},
		"trailing data":    {append(append([]byte{}, good...), []byte(` {}`)...), "$", "must be a JSON object"},
		"broken JSON":      {good[:len(good)-1], "$", "must be a JSON object"},
		"repeated in user": {[]byte(replaceOnce(t, string(good), `"ussp_id":"USSP-DEV"`, `"ussp_id":"USSP-DEV","ussp_id":"X"`)), "ussps[0]", "repeats the member"},
	} {
		t.Run(name, func(t *testing.T) {
			_, probs := ValidateUsspList(c.in)
			if probs == nil {
				t.Fatal("accepted")
			}
			found := false
			for _, p := range probs.List {
				found = found || (p.Field == c.field && strings.Contains(p.Reason, c.phrase))
			}
			if !found {
				t.Errorf("no %s %q in %v", c.field, c.phrase, probs)
			}
		})
	}
	if _, probs := ValidateUsspList(good); probs != nil {
		t.Errorf("the twin was refused: %v", probs)
	}
}

// The problem cap holds for the list too (E-10).
func TestUsspListProblemsCapped(t *testing.T) {
	d := exampleList(t)
	entries := make([]any, MaxUssps)
	for i := range entries {
		entries[i] = doc{"ussp_id": "U" + strconv.Itoa(i)}
	}
	d["ussps"] = entries
	_, probs := For(KindUsspList).Validate(body(t, d), ed318.Limits{MaxProblems: 10}, testNow)
	if probs == nil || len(probs.List) != 10 || probs.Truncated == 0 {
		t.Fatalf("got %v", probs)
	}
}

func TestQuoteCutsLongValues(t *testing.T) {
	if got := quote(strings.Repeat("x", 100)); len(got) != maxQuoted+5 {
		t.Errorf("quote = %s", got)
	}
	for raw, want := range map[string]string{`{}`: "an object", `[]`: "an array", `"s"`: "a string", `true`: "a boolean", `null`: "null", `1`: "a number", ``: "nothing"} {
		if got := describe(json.RawMessage(raw)); got != want {
			t.Errorf("describe(%s) = %s", raw, got)
		}
	}
	if _, ok := numberValue(json.RawMessage(`"1"`)); ok {
		t.Error("a string read as a number")
	}
	if _, ok := numberValue(json.RawMessage(`1e999`)); ok {
		t.Error("an infinite number accepted")
	}
}
