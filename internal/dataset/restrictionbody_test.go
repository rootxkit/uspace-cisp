package dataset

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/ed318"
)

func createBody(t *testing.T) obj {
	t.Helper()
	return obj{
		"ansp_ref": "NOTAM-A0001/26", "ansp_version": 1, "uspace_airspace_id": "TSU001", "state": "active",
		"starts_at": darStart.Format(time.RFC3339), "ends_at": darEnd.Format(time.RFC3339),
		"feature": darFeature("DAR1A2B"),
	}
}

func hasBodyProblem(t *testing.T, raw json.RawMessage, probsList []string, field, phrase string) {
	t.Helper()
	for _, p := range probsList {
		if strings.HasPrefix(p, field+": ") && strings.Contains(p, phrase) {
			return
		}
	}
	t.Errorf("%s: no problem at %s with %q: %v", raw, field, phrase, probsList)
}

// The POST body: accepted whole, and each refusal beside it (E-01).
func TestParseRestrictionBody(t *testing.T) {
	b, probs := ParseRestrictionBody(raw(t, createBody(t)))
	if probs != nil {
		t.Fatalf("refused: %s", names(probs))
	}
	if b.AnspRef != "NOTAM-A0001/26" || b.AnspVersion != 1 || b.UspaceAirspaceID != "TSU001" || b.State != CreateActive ||
		!b.StartsAt.Equal(darStart) || !b.EndsAt.Equal(darEnd) || len(b.Feature) == 0 {
		t.Fatalf("parsed %+v", b)
	}
	if _, probs := ValidateRestriction(b.Feature, RestrictionWindow{StartsAt: b.StartsAt, EndsAt: b.EndsAt}, edLimitsZero()); probs != nil {
		t.Fatalf("the feature: %s", names(probs))
	}
	for _, c := range []struct {
		name   string
		edit   func(obj)
		field  string
		phrase string
	}{
		{"an unknown member", func(b obj) { b["version"] = 2 }, "version", "unknown member"},
		{"no ansp_ref", func(b obj) { delete(b, "ansp_ref") }, "ansp_ref", "required"},
		{"an empty ansp_ref", func(b obj) { b["ansp_ref"] = "" }, "ansp_ref", "at least 1"},
		{"a long ansp_ref", func(b obj) { b["ansp_ref"] = strings.Repeat("x", MaxAnspRefChars+1) }, "ansp_ref", "at most 128"},
		{"a control character", func(b obj) { b["ansp_ref"] = "A\nB" }, "ansp_ref", "control"},
		{"a negative ansp_version", func(b obj) { b["ansp_version"] = -1 }, "ansp_version", "integer"},
		{"a fractional ansp_version", func(b obj) { b["ansp_version"] = 1.5 }, "ansp_version", "integer"},
		{"ansp_version past int32", func(b obj) { b["ansp_version"] = int64(MaxAnspVersion) + 1 }, "ansp_version", "integer"},
		{"a string ansp_version", func(b obj) { b["ansp_version"] = "1" }, "ansp_version", "integer"},
		{"an 8-character airspace", func(b obj) { b["uspace_airspace_id"] = "TSU00001" }, "uspace_airspace_id", "at most 7"},
		{"state ended", func(b obj) { b["state"] = "ended" }, "state", "planned, active"},
		{"a naive starts_at", func(b obj) { b["starts_at"] = "2026-10-02T12:00:00" }, "starts_at", "offset"},
		{"no ends_at", func(b obj) { delete(b, "ends_at") }, "ends_at", "required"},
		{"no feature", func(b obj) { delete(b, "feature") }, "feature", "required"},
	} {
		body := createBody(t)
		c.edit(body)
		r := raw(t, body)
		_, probs := ParseRestrictionBody(r)
		if probs == nil {
			t.Errorf("%s: accepted", c.name)
			continue
		}
		hasBodyProblem(t, r, strings.Split(names(probs), "\n"), c.field, c.phrase)
	}
	// ansp_version at its bound is accepted.
	body := createBody(t)
	body["ansp_version"] = MaxAnspVersion
	if b, probs := ParseRestrictionBody(raw(t, body)); probs != nil || b.AnspVersion != MaxAnspVersion {
		t.Errorf("ansp_version %d: %s", b.AnspVersion, names(probs))
	}
	for name, r := range map[string]string{"not an object": "[]", "a repeated member": `{"ansp_ref":"a","ansp_ref":"b"}`, "not UTF-8": "{\"a\":\"\xff\"}"} {
		if _, probs := ParseRestrictionBody([]byte(r)); probs == nil || probs.List[0].Field != "$" {
			t.Errorf("%s: %s", name, names(probs))
		}
	}
}

// The PATCH body: each op accepted, ends_at and feature with an extend
// only (E-01).
func TestParseRestrictionPatch(t *testing.T) {
	for _, op := range []string{PatchActivate, PatchEnd, PatchCancel} {
		p, probs := ParseRestrictionPatch(raw(t, obj{"op": op, "ansp_version": 2}))
		if probs != nil || p.Op != op || p.AnspVersion != 2 || p.EndsAt != nil || p.Feature != nil {
			t.Errorf("%s: %+v %s", op, p, names(probs))
		}
		_, probs = ParseRestrictionPatch(raw(t, obj{"op": op, "ansp_version": 2, "ends_at": darEnd.Format(time.RFC3339)}))
		if probs == nil || !strings.Contains(names(probs), "ends_at: is carried by an extend only") {
			t.Errorf("%s with ends_at: %s", op, names(probs))
		}
		_, probs = ParseRestrictionPatch(raw(t, obj{"op": op, "ansp_version": 2, "feature": darFeature("DAR1A2B")}))
		if probs == nil || !strings.Contains(names(probs), "feature: is carried by an extend only") {
			t.Errorf("%s with a feature: %s", op, names(probs))
		}
	}
	ext := obj{"op": "extend", "ansp_version": 3, "ends_at": darEnd.Add(time.Hour).Format(time.RFC3339), "feature": darFeature("DAR1A2B")}
	p, probs := ParseRestrictionPatch(raw(t, ext))
	if probs != nil || p.Op != PatchExtend || p.EndsAt == nil || !p.EndsAt.Equal(darEnd.Add(time.Hour)) || len(p.Feature) == 0 {
		t.Fatalf("extend: %+v %s", p, names(probs))
	}
	for _, c := range []struct {
		name, field, phrase string
		body                obj
	}{
		{"an extend without ends_at", "ends_at", "required by an extend", obj{"op": "extend", "ansp_version": 3, "feature": darFeature("DAR1A2B")}},
		{"an extend without the feature", "feature", "required by an extend", obj{"op": "extend", "ansp_version": 3, "ends_at": darEnd.Format(time.RFC3339)}},
		{"no op", "op", "required", obj{"ansp_version": 3}},
		{"an unknown op", "op", "one of", obj{"op": "expire", "ansp_version": 3}},
		{"no ansp_version", "ansp_version", "required", obj{"op": "end"}},
		{"version instead of ansp_version", "version", "unknown member", obj{"op": "end", "ansp_version": 3, "version": 3}},
		{"a bad ends_at", "ends_at", "RFC 3339", obj{"op": "extend", "ansp_version": 3, "ends_at": 5, "feature": darFeature("DAR1A2B")}},
	} {
		r := raw(t, c.body)
		_, probs := ParseRestrictionPatch(r)
		if probs == nil {
			t.Errorf("%s: accepted", c.name)
			continue
		}
		hasBodyProblem(t, r, strings.Split(names(probs), "\n"), c.field, c.phrase)
	}
	if _, probs := ParseRestrictionPatch([]byte(`"end"`)); probs == nil || probs.List[0].Field != "$" {
		t.Errorf("not an object: %s", names(probs))
	}
}

func edLimitsZero() ed318.Limits { return ed318.Limits{} }
