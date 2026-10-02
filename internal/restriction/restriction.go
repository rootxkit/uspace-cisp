package restriction

import (
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/f3548"

	"github.com/rootxkit/uspace-cisp/internal/publication"
)

// State is a restriction's lifecycle state.
type State string

// The states (docs/PLAN.md section 5.1, restrictions.state).
const (
	StatePlanned   State = "planned"
	StateActive    State = "active"
	StateEnded     State = "ended"
	StateCancelled State = "cancelled"
)

// Current reports whether a head in state s is in the current set of the
// restrictions dataset (planned and active; ended and cancelled leave it
// and stay in history by version).
func (s State) Current() bool { return s == StatePlanned || s == StateActive }

// Terminal reports whether no op changes a head in state s.
func (s State) Terminal() bool { return s == StateEnded || s == StateCancelled }

// Op is one lifecycle operation.
type Op string

// The operations: the ANSP's (create by POST, the rest by PATCH) and the
// CISP's expiry.
const (
	OpCreate   Op = "create"
	OpActivate Op = "activate"
	OpExtend   Op = "extend"
	OpEnd      Op = "end"
	OpCancel   Op = "cancel"
	OpExpire   Op = "expire"
)

// Who ended a restriction (restrictions.ended_by).
const (
	EndedByANSP   = "ansp"
	EndedByExpiry = "expiry"
)

// The fields a refusal names.
const (
	FieldState       = "state"
	FieldAnspVersion = "ansp_version"
	FieldStartsAt    = "starts_at"
	FieldEndsAt      = "ends_at"
	FieldLimits      = "limits"
	FieldOp          = "op"
)

// Conflict reports whether a refusal naming field is a conflict with the
// stored head (409: ansp_version or state) rather than a fault of the
// request (400).
func Conflict(field string) bool { return field == FieldState || field == FieldAnspVersion }

// Head is the lifecycle head of one restriction.
type Head struct {
	// ID is the CISP's ULID.
	ID string
	// AnspRef and AnspVersion are the ANSP's reference and version: the
	// idempotency key is the pair.
	AnspRef     string
	AnspVersion int64
	// UspaceAirspaceID is the USPACE feature the restriction modifies.
	UspaceAirspaceID string
	// FeatureID is the restriction's ED-318 identifier (at most 7
	// characters; never a prefix rule).
	FeatureID string
	// State is empty for a head that is not stored yet (a create).
	State            State
	StartsAt, EndsAt time.Time
	// EndedBy is ansp or expiry once Ended; nil otherwise.
	EndedBy *string
	// BodySHA256 is the hash of the body of the ANSP's op that set
	// AnspVersion: the same version is a replay only with the same bytes.
	BodySHA256 [32]byte
}

// Limits bound a restriction's window.
type Limits struct {
	// MaxDuration bounds ends_at - starts_at (F3548 CstrMaxDurationHours).
	MaxDuration time.Duration
	// MaxHorizon bounds starts_at - now (F3548 CstrMaxPlanningHorizonDays).
	MaxHorizon time.Duration
	// MaxActivationLead bounds starts_at - now of a create in state
	// active (ActivationLead).
	MaxActivationLead time.Duration
}

// ActivationLead is how far ahead of now an active create may start:
// an active restriction applies now, not later (a later start is a
// planned create).
const ActivationLead = 60 * time.Second

// F3548Limits are the limits from the F3548 constants (never retyped)
// and ActivationLead.
func F3548Limits() Limits {
	return Limits{
		MaxDuration:       time.Duration(f3548.CstrMaxDurationHours) * time.Hour,
		MaxHorizon:        time.Duration(f3548.CstrMaxPlanningHorizonDays) * 24 * time.Hour,
		MaxActivationLead: ActivationLead,
	}
}

// Request is one operation on a head.
type Request struct {
	Op Op
	// AnspVersion is the request's ansp_version (unused by OpExpire).
	AnspVersion int64
	// State is the state a create asks for: planned or active.
	State State
	// EndsAt is an extend's new ends_at; any other op refuses it.
	EndsAt *time.Time
	// BodySHA256 is the hash of the request body as received.
	BodySHA256 [32]byte
	// Now is the instant of receipt.
	Now    time.Time
	Limits Limits
}

// ValidateWindow checks a window against lim: starts_at before ends_at,
// at most MaxDuration long, starting at most MaxHorizon after now, and
// ending after now. A zero or negative limit refuses (E-15).
func ValidateWindow(startsAt, endsAt, now time.Time, lim Limits) error {
	if lim.MaxDuration <= 0 || lim.MaxHorizon <= 0 {
		return core.Fieldf(FieldLimits, "a zero or negative window limit refuses every restriction (duration %v, horizon %v)", lim.MaxDuration, lim.MaxHorizon)
	}
	if !startsAt.Before(endsAt) {
		return core.Fieldf(FieldEndsAt, "%s is not after starts_at %s", stamp(endsAt), stamp(startsAt))
	}
	if d := endsAt.Sub(startsAt); d > lim.MaxDuration {
		return core.Fieldf(FieldEndsAt, "the window is %v long; at most %v (F3548 CstrMaxDurationHours)", d, lim.MaxDuration)
	}
	if startsAt.After(now.Add(lim.MaxHorizon)) {
		return core.Fieldf(FieldStartsAt, "%s is more than %v ahead of now %s (F3548 CstrMaxPlanningHorizonDays)", stamp(startsAt), lim.MaxHorizon, stamp(now))
	}
	if !endsAt.After(now) {
		return core.Fieldf(FieldEndsAt, "%s is not after now %s: the window has passed", stamp(endsAt), stamp(now))
	}
	return nil
}

// Transition applies r to h and returns the new head and the reason of
// the version it makes. An empty reason with a nil error is an
// idempotent replay: h unchanged, nothing to write. A refusal is a
// *core.FieldError naming state or ansp_version (Conflict) or the field
// of the request at fault.
func Transition(h Head, r Request) (Head, publication.Reason, error) {
	if r.Op == OpExpire {
		return expire(h, r.Now)
	}
	if r.EndsAt != nil && r.Op != OpExtend {
		return h, "", core.Fieldf(FieldEndsAt, "is carried by an extend only, not by %s", r.Op)
	}
	if h.State == "" {
		return create(h, r)
	}
	switch {
	case r.AnspVersion == h.AnspVersion && r.BodySHA256 == h.BodySHA256:
		return h, "", nil // replay: the pair is the idempotency key, the bytes the same
	case r.AnspVersion == h.AnspVersion:
		return h, "", core.Fieldf(FieldAnspVersion, "%d was accepted with another body; a new op needs a higher ansp_version", r.AnspVersion)
	case r.AnspVersion < h.AnspVersion:
		return h, "", core.Fieldf(FieldAnspVersion, "%d is below the stored %d; every accepted op raises it", r.AnspVersion, h.AnspVersion)
	case h.State.Terminal():
		return h, "", core.Fieldf(FieldState, "the restriction is %s; nothing changes it any more", h.State)
	}
	next := h
	next.AnspVersion, next.BodySHA256 = r.AnspVersion, r.BodySHA256
	switch {
	case r.Op == OpActivate && h.State == StatePlanned:
		next.State = StateActive
		return next, publication.ReasonRestrictionActivated, nil
	case r.Op == OpCancel && h.State == StatePlanned:
		next.State = StateCancelled
		return next, publication.ReasonRestrictionCancelled, nil
	case r.Op == OpEnd && h.State == StateActive:
		next.State = StateEnded
		by := EndedByANSP
		next.EndedBy = &by
		return next, publication.ReasonRestrictionEnded, nil
	case r.Op == OpExtend && h.State == StateActive:
		if err := extendable(h, r); err != nil {
			return h, "", err
		}
		next.EndsAt = r.EndsAt.UTC()
		return next, publication.ReasonRestrictionExtended, nil
	case r.Op == OpCreate:
		return h, "", core.Fieldf(FieldState, "ansp_ref %q already names a restriction in state %s; change it with PATCH", h.AnspRef, h.State)
	}
	return h, "", core.Fieldf(FieldState, "%s is not an op of a %s restriction", r.Op, h.State)
}

// create is the first op of a head.
func create(h Head, r Request) (Head, publication.Reason, error) {
	if r.Op != OpCreate {
		return h, "", core.Fieldf(FieldState, "%s needs a stored restriction; create it first", r.Op)
	}
	if r.State != StatePlanned && r.State != StateActive {
		// Named op, not state: a bad request, never a conflict (409).
		return h, "", core.Fieldf(FieldOp, "a create asks for planned or active, not %q", r.State)
	}
	if err := ValidateWindow(h.StartsAt, h.EndsAt, r.Now, r.Limits); err != nil {
		return h, "", err
	}
	next := h
	next.State = r.State
	next.AnspVersion, next.BodySHA256 = r.AnspVersion, r.BodySHA256
	next.StartsAt, next.EndsAt = h.StartsAt.UTC(), h.EndsAt.UTC()
	next.EndedBy = nil
	if r.State == StatePlanned {
		return next, publication.ReasonRestrictionCreated, nil
	}
	if r.Limits.MaxActivationLead <= 0 {
		return h, "", core.Fieldf(FieldLimits, "a zero or negative activation lead refuses every active create")
	}
	if h.StartsAt.After(r.Now.Add(r.Limits.MaxActivationLead)) {
		return h, "", core.Fieldf(FieldStartsAt, "%s is more than %v ahead of now %s: a restriction that starts later is created planned and activated", stamp(h.StartsAt), r.Limits.MaxActivationLead, stamp(r.Now))
	}
	return next, publication.ReasonRestrictionActivated, nil
}

// extendable checks an extend's new ends_at.
func extendable(h Head, r Request) error {
	if r.Limits.MaxDuration <= 0 {
		return core.Fieldf(FieldLimits, "a zero or negative duration limit refuses every extension")
	}
	if r.EndsAt == nil {
		return core.Fieldf(FieldEndsAt, "is required by an extend")
	}
	end := *r.EndsAt
	if !end.After(h.EndsAt) {
		return core.Fieldf(FieldEndsAt, "%s is not after the current ends_at %s", stamp(end), stamp(h.EndsAt))
	}
	if d := end.Sub(h.StartsAt); d > r.Limits.MaxDuration {
		return core.Fieldf(FieldEndsAt, "the window would be %v long; at most %v (F3548 CstrMaxDurationHours)", d, r.Limits.MaxDuration)
	}
	if !end.After(r.Now) {
		return core.Fieldf(FieldEndsAt, "%s is not after now %s", stamp(end), stamp(r.Now))
	}
	return nil
}

// Expire ends an Active head whose ends_at is not after now, with
// ended_by expiry; any other head is returned unchanged with false.
func Expire(h Head, now time.Time) (Head, bool) {
	next, _, err := expire(h, now)
	return next, err == nil
}

func expire(h Head, now time.Time) (Head, publication.Reason, error) {
	if h.State != StateActive {
		return h, "", core.Fieldf(FieldState, "only an active restriction expires; this one is %q", h.State)
	}
	if h.EndsAt.After(now) {
		return h, "", core.Fieldf(FieldEndsAt, "%s is after now %s: a restriction expires at its ends_at, never before", stamp(h.EndsAt), stamp(now))
	}
	next := h
	next.State = StateEnded
	by := EndedByExpiry
	next.EndedBy = &by
	return next, publication.ReasonRestrictionExpired, nil
}

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
