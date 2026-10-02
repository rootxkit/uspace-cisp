package dataset

import (
	"bytes"
	"encoding/json"
	"math"
	"slices"
	"strconv"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/rootxkit/uspace-core/ed269"
	"github.com/rootxkit/uspace-core/ed318"
)

// Bounds of a restriction body (E-10).
const (
	// MaxAnspRefChars bounds ansp_ref.
	MaxAnspRefChars = 128
	// MaxAnspVersion is the largest ansp_version (restrictions.ansp_version
	// is a PostgreSQL integer).
	MaxAnspVersion = math.MaxInt32
	// MaxIdentifierChars is ED-318's identifier length, which a
	// uspace_airspace_id names.
	MaxIdentifierChars = 7
)

// The ops of PATCH /v1/restrictions/{id}.
const (
	PatchActivate = "activate"
	PatchExtend   = "extend"
	PatchEnd      = "end"
	PatchCancel   = "cancel"
)

// The states a create asks for.
const (
	CreatePlanned = "planned"
	CreateActive  = "active"
)

var (
	createMembers = []string{"ansp_ref", "ansp_version", "uspace_airspace_id", "state", "starts_at", "ends_at", "feature"}
	patchMembers  = []string{"op", "ansp_version", "ends_at", "feature"}
	patchOps      = []string{PatchActivate, PatchExtend, PatchEnd, PatchCancel}
	createStates  = []string{CreatePlanned, CreateActive}
)

// RestrictionBody is a POST /v1/restrictions body (cis/restriction/v1).
type RestrictionBody struct {
	AnspRef          string
	AnspVersion      int64
	UspaceAirspaceID string
	State            string
	StartsAt         time.Time
	EndsAt           time.Time
	// Feature is the ED-318 feature as published; ValidateRestriction
	// holds it to the DAR rules.
	Feature json.RawMessage
}

// RestrictionPatch is a PATCH /v1/restrictions/{id} body.
type RestrictionPatch struct {
	Op          string
	AnspVersion int64
	// EndsAt and Feature are an extend's (both required there, refused
	// elsewhere): the new ends_at, and the feature again with its period
	// ending at it, so the published period and ends_at stay one truth.
	EndsAt  *time.Time
	Feature json.RawMessage
}

// ParseRestrictionBody reads a POST body: a closed object (an unknown or
// repeated member is refused, never ignored: the ANSP's typo must not
// pass as an absent field), every member required and bounded. Every
// problem is named by its member.
func ParseRestrictionBody(raw []byte) (RestrictionBody, *ed269.Problems) {
	c := newCollector(ed318.Limits{})
	got := closedObject(raw, createMembers, c)
	if got == nil {
		return RestrictionBody{}, c.result()
	}
	var b RestrictionBody
	for _, name := range createMembers {
		if _, ok := got[name]; !ok {
			c.add(name, "is required")
		}
	}
	if v, ok := got["ansp_ref"]; ok {
		b.AnspRef = anspRef(v, c)
	}
	if v, ok := got["ansp_version"]; ok {
		b.AnspVersion = anspVersion(v, c)
	}
	if v, ok := got["uspace_airspace_id"]; ok {
		b.UspaceAirspaceID, _ = boundedString(v, "uspace_airspace_id", 1, MaxIdentifierChars, c)
	}
	if v, ok := got["state"]; ok {
		b.State = oneOf(v, "state", createStates, c)
	}
	if v, ok := got["starts_at"]; ok {
		b.StartsAt, _ = timeValue(v, "starts_at", c)
	}
	if v, ok := got["ends_at"]; ok {
		b.EndsAt, _ = timeValue(v, "ends_at", c)
	}
	b.Feature = got["feature"]
	return b, c.result()
}

// ParseRestrictionPatch reads a PATCH body: closed like the POST body;
// op and ansp_version required; ends_at and feature required by an
// extend and refused by every other op.
func ParseRestrictionPatch(raw []byte) (RestrictionPatch, *ed269.Problems) {
	c := newCollector(ed318.Limits{})
	got := closedObject(raw, patchMembers, c)
	if got == nil {
		return RestrictionPatch{}, c.result()
	}
	var p RestrictionPatch
	for _, name := range []string{"op", "ansp_version"} {
		if _, ok := got[name]; !ok {
			c.add(name, "is required")
		}
	}
	if v, ok := got["op"]; ok {
		p.Op = oneOf(v, "op", patchOps, c)
	}
	if v, ok := got["ansp_version"]; ok {
		p.AnspVersion = anspVersion(v, c)
	}
	if v, ok := got["ends_at"]; ok {
		if t, ok := timeValue(v, "ends_at", c); ok {
			p.EndsAt = &t
		}
	}
	p.Feature = got["feature"]
	if p.Op == "" {
		return p, c.result()
	}
	for _, name := range []string{"ends_at", "feature"} {
		_, present := got[name]
		switch {
		case p.Op == PatchExtend && !present:
			c.add(name, "is required by an extend")
		case p.Op != PatchExtend && present:
			c.add(name, "is carried by an extend only, not by "+p.Op)
		}
	}
	return p, c.result()
}

// closedObject reads raw as one JSON object of known members; nil after
// a refusal of the whole body.
func closedObject(raw []byte, known []string, c *collector) map[string]json.RawMessage {
	if !utf8.Valid(raw) {
		c.add("$", "not UTF-8")
		return nil
	}
	ms, err := members(bytes.TrimSpace(raw))
	if err != nil {
		c.add("$", objectRefusal(err, "the body", raw))
		return nil
	}
	got := make(map[string]json.RawMessage, len(ms))
	for _, m := range ms {
		if !slices.Contains(known, m.key) {
			c.add(m.key, "unknown member (a closed schema: a misspelt member is refused, never ignored)")
			continue
		}
		got[m.key] = m.value
	}
	return got
}

// anspRef is a 1-128 character reference without control characters.
func anspRef(raw json.RawMessage, c *collector) string {
	s, ok := boundedString(raw, "ansp_ref", 1, MaxAnspRefChars, c)
	if !ok {
		return ""
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			c.add("ansp_ref", "holds a control character")
			return ""
		}
	}
	return s
}

// anspVersion is an integer of 0 to MaxAnspVersion.
func anspVersion(raw json.RawMessage, c *collector) int64 {
	s := string(bytes.TrimSpace(raw))
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 || n > MaxAnspVersion {
		c.add("ansp_version", "must be an integer of 0 to "+strconv.Itoa(MaxAnspVersion)+", not "+quote(s))
		return 0
	}
	return n
}

// oneOf is raw as a string from allowed.
func oneOf(raw json.RawMessage, where string, allowed []string, c *collector) string {
	s, ok := stringValue(raw)
	if !ok || !slices.Contains(allowed, s) {
		c.add(where, "must be one of "+joinComma(allowed))
		return ""
	}
	return s
}

func joinComma(s []string) string {
	var b bytes.Buffer
	for i, x := range s {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(x)
	}
	return b.String()
}
