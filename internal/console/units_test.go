package console_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-cisp/internal/console"
	"github.com/rootxkit/uspace-cisp/internal/store"
)

// The TOTP secret is sealed per row: two seals of one secret differ,
// each opens for its own account and for no other; a tampered or short
// ciphertext is an error.
func TestSealer(t *testing.T) {
	s, err := console.NewSealer(k32())
	if err != nil {
		t.Fatal(err)
	}
	a, err := s.Seal("acc-1", []byte("JBSWY3DPEHPK3PXP"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.Seal("acc-2", []byte("JBSWY3DPEHPK3PXP"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) || bytes.Contains(a, []byte("JBSWY3DP")) {
		t.Fatalf("ciphertexts equal or clear: %x %x", a, b)
	}
	for id, sealed := range map[string][]byte{"acc-1": a, "acc-2": b} {
		pt, err := s.Open(id, sealed)
		if err != nil || string(pt) != "JBSWY3DPEHPK3PXP" {
			t.Errorf("%s: %q %v", id, pt, err)
		}
	}
	if _, err := s.Open("acc-2", a); err == nil {
		t.Error("a ciphertext opened for another account")
	}
	tampered := append([]byte{}, a...)
	tampered[len(tampered)-1] ^= 1
	if _, err := s.Open("acc-1", tampered); err == nil {
		t.Error("a tampered ciphertext opened")
	}
	if _, err := s.Open("acc-1", a[:10]); err == nil {
		t.Error("a short ciphertext opened")
	}
}

// CISP_SECRETS_KEY absent stops the start with a message naming it;
// a malformed one too, without repeating the value.
func TestSealerKey(t *testing.T) {
	if _, err := console.NewSealer(""); !errors.Is(err, console.ErrSecretsKeyMissing) || !strings.Contains(err.Error(), "CISP_SECRETS_KEY is not set") {
		t.Errorf("missing: %v", err)
	}
	const bad = "c2hvcnQta2V5" // "short-key"
	_, err := console.NewSealer(bad)
	if err == nil || !strings.Contains(err.Error(), "CISP_SECRETS_KEY must be 32 bytes") || strings.Contains(err.Error(), bad) {
		t.Errorf("malformed: %v", err)
	}
}

func TestDiffPaths(t *testing.T) {
	prev := json.RawMessage(`{"id":"Z1","properties":{"name":"A","lower":{"m":10},"tags":["x","y"],"a/b":1,"t~":1},"gone":true}`)
	next := json.RawMessage(`{"id":"Z1","properties":{"name":"B","lower":{"m":10},"tags":["x"],"a/b":2,"t~":"1","new":null}}`)
	got, truncated, err := console.DiffPaths(prev, next, 0)
	if err != nil || truncated {
		t.Fatal(err, truncated)
	}
	want := []console.PathChange{
		{Path: "/gone", Op: console.PathRemoved},
		{Path: "/properties/a~1b", Op: console.PathChanged},
		{Path: "/properties/name", Op: console.PathChanged},
		{Path: "/properties/new", Op: console.PathAdded},
		{Path: "/properties/tags/1", Op: console.PathRemoved},
		{Path: "/properties/t~0", Op: console.PathChanged},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
	// Equal documents: no path (the pair).
	same, _, err := console.DiffPaths(prev, prev, 0)
	if err != nil || len(same) != 0 {
		t.Errorf("equal documents: %+v %v", same, err)
	}
	// A whole value whose type changed, and an added array element.
	typ, _, _ := console.DiffPaths(json.RawMessage(`{"a":[1],"b":{"c":1}}`), json.RawMessage(`{"a":[1,2],"b":[1]}`), 0)
	if len(typ) != 2 || typ[0] != (console.PathChange{Path: "/a/1", Op: console.PathAdded}) || typ[1] != (console.PathChange{Path: "/b", Op: console.PathChanged}) {
		t.Errorf("type change %+v", typ)
	}
	root, _, _ := console.DiffPaths(json.RawMessage(`1`), json.RawMessage(`2`), 0)
	if len(root) != 1 || root[0].Path != "/" {
		t.Errorf("root %+v", root)
	}
	arr, _, _ := console.DiffPaths(json.RawMessage(`[1]`), json.RawMessage(`{"a":1}`), 0)
	if len(arr) != 1 || arr[0].Op != console.PathChanged {
		t.Errorf("array to object %+v", arr)
	}
	if _, _, err := console.DiffPaths(json.RawMessage(`{`), next, 0); err == nil {
		t.Error("a broken previous feature was diffed")
	}
	if _, _, err := console.DiffPaths(prev, nil, 0); err == nil {
		t.Error("an empty feature was diffed")
	}
}

// E-10: past 200 paths the list stops and says truncated; at 200 it
// does not.
func TestDiffPathsBound(t *testing.T) {
	doc := func(n, v int) json.RawMessage {
		var b strings.Builder
		b.WriteString("{")
		for i := 0; i < n; i++ {
			if i > 0 {
				b.WriteString(",")
			}
			b.WriteString(`"k` + strconv.Itoa(1000+i) + `":` + strconv.Itoa(v))
		}
		b.WriteString("}")
		return json.RawMessage(b.String())
	}
	at, truncated, err := console.DiffPaths(doc(console.MaxDiffPaths, 1), doc(console.MaxDiffPaths, 2), 0)
	if err != nil || truncated || len(at) != console.MaxDiffPaths {
		t.Errorf("at the bound: %d %v %v", len(at), truncated, err)
	}
	past, truncated, err := console.DiffPaths(doc(console.MaxDiffPaths+1, 1), doc(console.MaxDiffPaths+1, 2), 0)
	if err != nil || !truncated || len(past) != console.MaxDiffPaths {
		t.Errorf("past the bound: %d %v %v", len(past), truncated, err)
	}
	// Nesting deeper than the walk compares whole.
	deep := strings.Repeat(`{"a":`, 100) + "1" + strings.Repeat("}", 100)
	deeper := strings.Repeat(`{"a":`, 100) + "2" + strings.Repeat("}", 100)
	d, _, err := console.DiffPaths(json.RawMessage(deep), json.RawMessage(deeper), 0)
	if err != nil || len(d) != 1 || strings.Count(d[0].Path, "/a") != 64 {
		t.Errorf("deep: %+v %v", d, err)
	}
}

func chain(t *testing.T, n int) []store.AuditRow {
	t.Helper()
	var rows []store.AuditRow
	var prev []byte
	for i := 1; i <= n; i++ {
		r := store.AuditRow{
			ID: int64(i), TS: time.Date(2026, 10, 2, 12, 0, i, 0, time.UTC), ActorType: "account", ActorID: "acc-1",
			EventType: "console_republish", EntityType: "publication", EntityID: "P" + strconv.Itoa(i),
			Payload: json.RawMessage(`{"reason":"test","n":` + strconv.Itoa(i) + `}`), PrevHash: prev,
		}
		h, err := store.EventHash(prev, r.TS, r.ActorType, r.ActorID, r.EventType, r.EntityType, r.EntityID, r.Payload)
		if err != nil {
			t.Fatal(err)
		}
		r.Hash, prev = h, h
		rows = append(rows, r)
	}
	return rows
}

// A clean chain verifies row by row; an edited field and a removed row
// are each named by the first row that breaks (spec 06 T7).
func TestCheckRow(t *testing.T) {
	rows := chain(t, 4)
	var prev []byte
	for _, r := range rows {
		if err := console.CheckRow(prev, r); err != nil {
			t.Fatalf("clean chain: %v", err)
		}
		prev = r.Hash
	}
	edited := rows[2]
	edited.EntityID = "P-forged"
	var br *console.ChainBreakError
	if err := console.CheckRow(rows[1].Hash, edited); !errors.As(err, &br) || br.ID != 3 || !strings.Contains(br.Reason, "altered") {
		t.Errorf("edited: %v", err)
	}
	if err := console.CheckRow(rows[0].Hash, rows[2]); !errors.As(err, &br) || br.ID != 3 || !strings.Contains(br.Reason, "prev_hash") {
		t.Errorf("row 2 removed: %v", err)
	}
	if err := console.CheckRow(nil, rows[1]); !errors.As(err, &br) || !strings.Contains(br.Error(), "events row 2") {
		t.Errorf("no previous: %v", err)
	}
	bad := rows[0]
	bad.Payload = json.RawMessage(`{`)
	if err := console.CheckRow(nil, bad); !errors.As(err, &br) || !strings.Contains(br.Reason, "cannot be hashed") {
		t.Errorf("broken payload: %v", err)
	}
}

func TestExportLine(t *testing.T) {
	rows := chain(t, 2)
	line, err := console.ExportLine(rows[1])
	if err != nil || !bytes.HasSuffix(line, []byte("\n")) {
		t.Fatal(err)
	}
	var back console.ExportRow
	if err := json.Unmarshal(line, &back); err != nil {
		t.Fatal(err)
	}
	if back.ID != 2 || back.PrevHash == "" || back.Hash == "" || !strings.Contains(string(back.Payload), `"reason":"test"`) {
		t.Errorf("exported %+v", back)
	}
	first := rows[0]
	first.Payload = nil
	line, err = console.ExportLine(first)
	if err != nil || !strings.Contains(string(line), `"payload":{}`) || strings.Contains(string(line), "prev_hash") {
		t.Errorf("first row: %s %v", line, err)
	}
}
