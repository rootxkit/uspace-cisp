package restriction

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed318"
	"github.com/rootxkit/uspace-core/f3548"

	"github.com/rootxkit/uspace-cisp/internal/publication"
)

var t0 = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

// head is a stored head in state s, version 3, window [t0, t0+2h].
func head(s State) Head {
	return Head{
		ID: "01JRESTRICTION0000000000AA", AnspRef: "NOTAM-1", AnspVersion: 3, UspaceAirspaceID: "TSU001",
		FeatureID: "DAR0A1B", State: s, StartsAt: t0, EndsAt: t0.Add(2 * time.Hour),
	}
}

// fresh is a proposed head (not stored) with the window [starts, ends].
func fresh(starts, ends time.Time) Head {
	h := head("")
	h.StartsAt, h.EndsAt = starts, ends
	return h
}

func req(op Op, v int64) Request {
	return Request{Op: op, AnspVersion: v, Now: t0.Add(time.Minute), Limits: F3548Limits()}
}

func at(t time.Time) *time.Time { return &t }

func field(t *testing.T, err error) string {
	t.Helper()
	var fe *core.FieldError
	if !errors.As(err, &fe) {
		t.Fatalf("not a *core.FieldError: %v", err)
	}
	return fe.Field
}

// The limits come from the F3548 constants, never retyped.
func TestF3548Limits(t *testing.T) {
	lim := F3548Limits()
	if lim.MaxDuration != time.Duration(f3548.CstrMaxDurationHours)*time.Hour ||
		lim.MaxHorizon != time.Duration(f3548.CstrMaxPlanningHorizonDays)*24*time.Hour ||
		lim.MaxActivationLead != ActivationLead {
		t.Errorf("limits %+v", lim)
	}
	if lim.MaxDuration != 24*time.Hour || lim.MaxHorizon != 56*24*time.Hour {
		t.Errorf("the F3548 values changed: %+v", lim)
	}
}

// Every row of the table, each refusal beside the accepted op that
// differs from it in one thing (E-01).
func TestTransitionTable(t *testing.T) {
	ext := at(t0.Add(3 * time.Hour))
	cases := []struct {
		name   string
		h      Head
		r      Request
		state  State
		reason publication.Reason
		field  string // a refusal names it
	}{
		{name: "create planned", h: fresh(t0.Add(time.Hour), t0.Add(2*time.Hour)), r: Request{Op: OpCreate, AnspVersion: 1, State: StatePlanned, Now: t0, Limits: F3548Limits()}, state: StatePlanned, reason: publication.ReasonRestrictionCreated},
		{name: "create active", h: fresh(t0, t0.Add(time.Hour)), r: Request{Op: OpCreate, AnspVersion: 1, State: StateActive, Now: t0, Limits: F3548Limits()}, state: StateActive, reason: publication.ReasonRestrictionActivated},
		{name: "create active starting 60 s ahead", h: fresh(t0.Add(time.Minute), t0.Add(time.Hour)), r: Request{Op: OpCreate, AnspVersion: 1, State: StateActive, Now: t0, Limits: F3548Limits()}, state: StateActive, reason: publication.ReasonRestrictionActivated},
		{name: "create active starting 61 s ahead is refused", h: fresh(t0.Add(61*time.Second), t0.Add(time.Hour)), r: Request{Op: OpCreate, AnspVersion: 1, State: StateActive, Now: t0, Limits: F3548Limits()}, field: FieldStartsAt},
		{name: "create planned starting 61 s ahead", h: fresh(t0.Add(61*time.Second), t0.Add(time.Hour)), r: Request{Op: OpCreate, AnspVersion: 1, State: StatePlanned, Now: t0, Limits: F3548Limits()}, state: StatePlanned, reason: publication.ReasonRestrictionCreated},
		{name: "create ended is refused", h: fresh(t0, t0.Add(time.Hour)), r: Request{Op: OpCreate, AnspVersion: 1, State: StateEnded, Now: t0, Limits: F3548Limits()}, field: FieldOp},
		{name: "create with a bad window is refused", h: fresh(t0.Add(time.Hour), t0), r: Request{Op: OpCreate, AnspVersion: 1, State: StatePlanned, Now: t0, Limits: F3548Limits()}, field: FieldEndsAt},
		{name: "activate before create is refused", h: fresh(t0, t0.Add(time.Hour)), r: Request{Op: OpActivate, AnspVersion: 1, Now: t0, Limits: F3548Limits()}, field: FieldState},
		{name: "create with ends_at in the request is refused", h: fresh(t0, t0.Add(time.Hour)), r: Request{Op: OpCreate, AnspVersion: 1, State: StatePlanned, EndsAt: ext, Now: t0, Limits: F3548Limits()}, field: FieldEndsAt},

		{name: "planned activate", h: head(StatePlanned), r: req(OpActivate, 4), state: StateActive, reason: publication.ReasonRestrictionActivated},
		{name: "planned cancel", h: head(StatePlanned), r: req(OpCancel, 4), state: StateCancelled, reason: publication.ReasonRestrictionCancelled},
		{name: "planned end is refused", h: head(StatePlanned), r: req(OpEnd, 4), field: FieldState},
		{name: "planned extend is refused", h: head(StatePlanned), r: Request{Op: OpExtend, AnspVersion: 4, EndsAt: ext, Now: t0, Limits: F3548Limits()}, field: FieldState},
		{name: "planned create again is refused", h: head(StatePlanned), r: Request{Op: OpCreate, AnspVersion: 4, State: StatePlanned, Now: t0, Limits: F3548Limits()}, field: FieldState},

		{name: "active extend", h: head(StateActive), r: Request{Op: OpExtend, AnspVersion: 4, EndsAt: ext, Now: t0, Limits: F3548Limits()}, state: StateActive, reason: publication.ReasonRestrictionExtended},
		{name: "active end", h: head(StateActive), r: req(OpEnd, 4), state: StateEnded, reason: publication.ReasonRestrictionEnded},
		{name: "active activate is refused", h: head(StateActive), r: req(OpActivate, 4), field: FieldState},
		{name: "active cancel is refused", h: head(StateActive), r: req(OpCancel, 4), field: FieldState},
		{name: "active end with ends_at is refused", h: head(StateActive), r: Request{Op: OpEnd, AnspVersion: 4, EndsAt: ext, Now: t0, Limits: F3548Limits()}, field: FieldEndsAt},

		{name: "ended anything new is refused", h: head(StateEnded), r: req(OpActivate, 4), field: FieldState},
		{name: "ended end again is refused", h: head(StateEnded), r: req(OpEnd, 4), field: FieldState},
		{name: "cancelled anything new is refused", h: head(StateCancelled), r: req(OpActivate, 4), field: FieldState},

		{name: "same ansp_version replays", h: head(StateActive), r: req(OpEnd, 3), state: StateActive},
		{name: "same ansp_version replays on an ended head", h: head(StateEnded), r: req(OpEnd, 3), state: StateEnded},
		{name: "lower ansp_version is refused", h: head(StateActive), r: req(OpEnd, 2), field: FieldAnspVersion},
		{name: "lower ansp_version on an ended head names ansp_version", h: head(StateEnded), r: req(OpEnd, 2), field: FieldAnspVersion},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, reason, err := Transition(c.h, c.r)
			if c.field != "" {
				if err == nil {
					t.Fatalf("accepted: %+v %s", got, reason)
				}
				if f := field(t, err); f != c.field {
					t.Fatalf("refusal names %q, want %q (%v)", f, c.field, err)
				}
				if got != c.h || reason != "" {
					t.Errorf("a refusal changed the head: %+v %s", got, reason)
				}
				return
			}
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if got.State != c.state || reason != c.reason {
				t.Errorf("got %s %q, want %s %q", got.State, reason, c.state, c.reason)
			}
			if reason == "" {
				if got != c.h {
					t.Errorf("a replay changed the head: %+v", got)
				}
				return
			}
			if got.AnspVersion != c.r.AnspVersion {
				t.Errorf("ansp_version %d, want %d", got.AnspVersion, c.r.AnspVersion)
			}
		})
	}
}

// ansp_version equal, lower and higher on one head: replay, 409, the op.
func TestTransitionAnspVersion(t *testing.T) {
	h := head(StateActive)
	for _, c := range []struct {
		v      int64
		reason publication.Reason
		field  string
	}{{3, "", ""}, {2, "", FieldAnspVersion}, {0, "", FieldAnspVersion}, {4, publication.ReasonRestrictionEnded, ""}, {1 << 40, publication.ReasonRestrictionEnded, ""}} {
		got, reason, err := Transition(h, req(OpEnd, c.v))
		if c.field != "" {
			if err == nil || field(t, err) != c.field || !Conflict(field(t, err)) {
				t.Errorf("v%d: %v", c.v, err)
			}
			continue
		}
		if err != nil || reason != c.reason {
			t.Errorf("v%d: %q %v", c.v, reason, err)
		}
		if c.reason != "" && (got.EndedBy == nil || *got.EndedBy != EndedByANSP) {
			t.Errorf("v%d: ended_by %v", c.v, got.EndedBy)
		}
	}
}

// Conflict is 409 for state and ansp_version only.
func TestConflict(t *testing.T) {
	for f, want := range map[string]bool{FieldState: true, FieldAnspVersion: true, FieldEndsAt: false, FieldStartsAt: false, FieldLimits: false, FieldOp: false} {
		if Conflict(f) != want {
			t.Errorf("Conflict(%s) = %v", f, !want)
		}
	}
}

// An extend: the new ends_at after the old, the window within 24 h, and
// after now; each refusal beside its acceptance one second away.
func TestTransitionExtendBounds(t *testing.T) {
	h := head(StateActive) // [t0, t0+2h]
	maxEnd := t0.Add(24 * time.Hour)
	for _, c := range []struct {
		name  string
		end   *time.Time
		now   time.Time
		field string
	}{
		{"one second after the old ends_at", at(h.EndsAt.Add(time.Second)), t0, ""},
		{"equal to the old ends_at", at(h.EndsAt), t0, FieldEndsAt},
		{"the window exactly 24 h", at(maxEnd), t0, ""},
		{"the window 24 h and 1 s", at(maxEnd.Add(time.Second)), t0, FieldEndsAt},
		{"no ends_at", nil, t0, FieldEndsAt},
		{"after now on a head past its ends_at", at(t0.Add(3 * time.Hour)), t0.Add(3*time.Hour - time.Second), ""},
		{"not after now on a head past its ends_at", at(t0.Add(3 * time.Hour)), t0.Add(3 * time.Hour), FieldEndsAt},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, reason, err := Transition(h, Request{Op: OpExtend, AnspVersion: 4, EndsAt: c.end, Now: c.now, Limits: F3548Limits()})
			if c.field != "" {
				if err == nil || field(t, err) != c.field {
					t.Fatalf("got %v %v", reason, err)
				}
				return
			}
			if err != nil || reason != publication.ReasonRestrictionExtended || !got.EndsAt.Equal(*c.end) || got.State != StateActive {
				t.Fatalf("%+v %q %v", got, reason, err)
			}
		})
	}
	// Zero limits refuse an extension (E-15), beside the same extension
	// with the limits.
	if _, _, err := Transition(h, Request{Op: OpExtend, AnspVersion: 4, EndsAt: at(h.EndsAt.Add(time.Hour)), Now: t0}); err == nil || field(t, err) != FieldLimits {
		t.Errorf("zero limits: %v", err)
	}
}

// ValidateWindow at every bound, one second inside and outside.
func TestValidateWindowBounds(t *testing.T) {
	lim := F3548Limits()
	now := t0
	horizon := now.Add(56 * 24 * time.Hour)
	for _, c := range []struct {
		name         string
		starts, ends time.Time
		field        string
	}{
		{"ordinary", now, now.Add(time.Hour), ""},
		{"ends one second after starts", now, now.Add(time.Second), ""},
		{"ends at starts", now.Add(time.Hour), now.Add(time.Hour), FieldEndsAt},
		{"ends before starts", now.Add(time.Hour), now.Add(time.Hour - time.Second), FieldEndsAt},
		{"exactly 24 h", now, now.Add(24 * time.Hour), ""},
		{"24 h and 1 s", now, now.Add(24*time.Hour + time.Second), FieldEndsAt},
		{"starts exactly 56 d ahead", horizon, horizon.Add(time.Hour), ""},
		{"starts 56 d and 1 s ahead", horizon.Add(time.Second), horizon.Add(time.Hour), FieldStartsAt},
		{"ends one second after now", now.Add(-time.Hour), now.Add(time.Second), ""},
		{"ends at now", now.Add(-time.Hour), now, FieldEndsAt},
		{"ends one second before now", now.Add(-time.Hour), now.Add(-time.Second), FieldEndsAt},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateWindow(c.starts, c.ends, now, lim)
			if c.field == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || field(t, err) != c.field {
				t.Fatalf("got %v, want a refusal of %s", err, c.field)
			}
		})
	}
}

// A zero limit refuses (E-15), beside the same window with the limits.
func TestValidateWindowZeroLimitsRefuse(t *testing.T) {
	if err := ValidateWindow(t0, t0.Add(time.Hour), t0, F3548Limits()); err != nil {
		t.Fatalf("the ordinary window: %v", err)
	}
	for name, lim := range map[string]Limits{
		"all zero":          {},
		"duration zero":     {MaxHorizon: time.Hour},
		"horizon zero":      {MaxDuration: time.Hour},
		"duration negative": {MaxDuration: -time.Hour, MaxHorizon: time.Hour},
	} {
		if err := ValidateWindow(t0, t0.Add(time.Minute), t0, lim); err == nil || field(t, err) != FieldLimits {
			t.Errorf("%s: %v", name, err)
		}
	}
	// An active create with a zero activation lead refuses; a planned one
	// with the same limits passes.
	lim := Limits{MaxDuration: time.Hour * 24, MaxHorizon: time.Hour * 24}
	if _, _, err := Transition(fresh(t0, t0.Add(time.Hour)), Request{Op: OpCreate, AnspVersion: 1, State: StateActive, Now: t0, Limits: lim}); err == nil || field(t, err) != FieldLimits {
		t.Errorf("zero lead: %v", err)
	}
	if _, _, err := Transition(fresh(t0, t0.Add(time.Hour)), Request{Op: OpCreate, AnspVersion: 1, State: StatePlanned, Now: t0, Limits: lim}); err != nil {
		t.Errorf("planned with no lead: %v", err)
	}
}

// Expiry happens at ends_at, never before (E-01: one second each side).
func TestExpire(t *testing.T) {
	h := head(StateActive)
	if got, ok := Expire(h, h.EndsAt.Add(-time.Second)); ok || got != h {
		t.Errorf("one second before ends_at: expired %+v", got)
	}
	got, ok := Expire(h, h.EndsAt)
	if !ok || got.State != StateEnded || got.EndedBy == nil || *got.EndedBy != EndedByExpiry || got.AnspVersion != h.AnspVersion {
		t.Errorf("at ends_at: %v %+v", ok, got)
	}
	if got, ok := Expire(h, h.EndsAt.Add(time.Second)); !ok || got.State != StateEnded {
		t.Errorf("one second after: %v %+v", ok, got)
	}
	for _, s := range []State{StatePlanned, StateEnded, StateCancelled} {
		if got, ok := Expire(head(s), h.EndsAt.Add(time.Hour)); ok || got.State != s {
			t.Errorf("%s expired: %+v", s, got)
		}
	}
	// Through Transition, with the reason; ansp_version plays no part.
	got, reason, err := Transition(h, Request{Op: OpExpire, Now: h.EndsAt.Add(time.Second)})
	if err != nil || reason != publication.ReasonRestrictionExpired || got.State != StateEnded {
		t.Errorf("Transition expire: %+v %q %v", got, reason, err)
	}
	if _, _, err := Transition(h, Request{Op: OpExpire, Now: h.EndsAt.Add(-time.Second)}); err == nil || field(t, err) != FieldEndsAt {
		t.Errorf("Transition expire early: %v", err)
	}
}

func TestStates(t *testing.T) {
	for s, want := range map[State][2]bool{StatePlanned: {true, false}, StateActive: {true, false}, StateEnded: {false, true}, StateCancelled: {false, true}} {
		if s.Current() != want[0] || s.Terminal() != want[1] {
			t.Errorf("%s current %v terminal %v", s, s.Current(), s.Terminal())
		}
	}
}

func feature(id string, ext map[string]json.RawMessage) ed318.Feature {
	return ed318.Feature{Type: "Feature", Properties: ed318.UASZone{Identifier: id, ExtendedProperties: ext}}
}

func member(t *testing.T, f ed318.Feature) Member {
	t.Helper()
	var m Member
	if err := json.Unmarshal(f.Properties.ExtendedProperties[MemberName], &m); err != nil {
		t.Fatalf("%s: %v", f.Properties.Identifier, err)
	}
	return m
}

// The current set: a current head is stamped and kept in identifier
// order, a terminal one leaves, a published feature replaces the stored
// one, and the stored feature is not touched.
func TestCurrentSet(t *testing.T) {
	other := feature("DAR0000", map[string]json.RawMessage{"source": json.RawMessage(`"ansp"`)})
	stored := []ed318.Feature{feature("DARZZZZ", nil), other}

	h := head(StateActive)
	h.FeatureID = "DARZZZZ"
	fc, err := CurrentSet(stored, h, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(fc.Features) != 2 || fc.Features[0].Properties.Identifier != "DAR0000" || fc.Features[1].Properties.Identifier != "DARZZZZ" {
		t.Fatalf("set %+v", fc.Features)
	}
	m := member(t, fc.Features[1])
	if m.State != StateActive || m.AnspVersion != 3 || m.ID != h.ID || m.EndedBy != nil || !m.EndsAt.Equal(h.EndsAt) || m.UspaceAirspaceID != "TSU001" {
		t.Errorf("member %+v", m)
	}
	if _, ok := stored[0].Properties.ExtendedProperties[MemberName]; ok {
		t.Error("the stored feature was modified")
	}
	if string(fc.Features[0].Properties.ExtendedProperties["source"]) != `"ansp"` {
		t.Error("another restriction's members changed")
	}

	// A new restriction's published feature joins the set.
	n := head(StatePlanned)
	n.FeatureID = "DAR1A2B"
	pub := feature("DAR1A2B", map[string]json.RawMessage{"note": json.RawMessage(`1`)})
	fc, err = CurrentSet(stored, n, &pub)
	if err != nil || len(fc.Features) != 3 || fc.Features[1].Properties.Identifier != "DAR1A2B" {
		t.Fatalf("create: %v %+v", err, fc)
	}
	if member(t, fc.Features[1]).State != StatePlanned || string(fc.Features[1].Properties.ExtendedProperties["note"]) != "1" {
		t.Errorf("created feature %+v", fc.Features[1].Properties.ExtendedProperties)
	}

	// An ended head leaves the set (beside the active one that stays).
	h.State = StateEnded
	fc, err = CurrentSet(stored, h, nil)
	if err != nil || len(fc.Features) != 1 || fc.Features[0].Properties.Identifier != "DAR0000" {
		t.Fatalf("ended: %v %+v", err, fc)
	}

	// A current head whose feature is nowhere is refused.
	lost := head(StateActive)
	lost.FeatureID = "DARLOST"
	if _, err := CurrentSet(stored, lost, nil); err == nil || !strings.Contains(err.Error(), "DARLOST") {
		t.Errorf("lost feature: %v", err)
	}
}
