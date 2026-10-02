// Package restriction is the lifecycle of a dynamic airspace restriction
// (spec 02 F2, docs/PLAN.md D4, D5, section 6.2): the state machine the
// ANSP drives with ansp_version, the expiry the CISP applies at ends_at,
// the F3548 window limits, and the current set of the restrictions
// dataset with the cis_restriction member stamped on each feature. It is
// pure: no database, no network, no logging.
//
//	func Transition(h Head, r Request) (Head, publication.Reason, error)
//	func Expire(h Head, now time.Time) (Head, bool)
//	func ValidateWindow(startsAt, endsAt, now time.Time, lim Limits) error
//	func CurrentSet(stored []ed318.Feature, h Head, published *ed318.Feature) (*ed318.FeatureCollection, error)
//
// # The state machine
//
//	from       op                    to         reason
//	-          create (planned)      Planned    restriction_created
//	-          create (active)       Active     restriction_activated
//	Planned    activate              Active     restriction_activated
//	Planned    cancel                Cancelled  restriction_cancelled
//	Active     extend                Active     restriction_extended
//	Active     end                   Ended      restriction_ended (ended_by ansp)
//	Planned    expire (time)         Ended      restriction_expired (ended_by expiry)
//	Active     expire (time)         Ended      restriction_expired (ended_by expiry)
//
// The ANSP is the master of a restriction's state (D5): every accepted op
// carries a strictly higher ansp_version. The same ansp_version with the
// same body bytes is an idempotent replay (the stored head, no reason,
// nothing written); the same ansp_version with another body, and a lower
// one, are refused naming ansp_version; anything on an Ended or
// Cancelled head, and any op the table does not list, is refused naming
// state. A refusal is a *core.FieldError naming ansp_version or state
// (the handler answers 409) or the request field at fault (400).
//
// The CISP moves a restriction itself only by Expire: a planned or active
// head whose ends_at is not after now becomes Ended with ended_by expiry
// (a planned window that has passed never applies again). Nothing else
// ends a restriction: not a silent ANSP, not a planned head past its
// starts_at but before its ends_at (it stays planned, docs/PLAN.md
// section 15 Q2).
//
// # Limits
//
// The window limits are the F3548 constraint limits the ANSP mirrors to
// the DSS (uspace-core f3548 CstrMaxDurationHours and
// CstrMaxPlanningHorizonDays), so one restriction fits both channels, and
// the 60 s lead of an active create. A zero or negative limit refuses
// every window (LESSONS E-15: a zero threshold refuses, never disarms).
package restriction
