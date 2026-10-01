// Package dataset holds the rules each published dataset applies above
// its format (docs/PLAN.md D1, D8, section 6.1): which zone types and
// reasons a dataset may hold, whether every zone can be built for
// judgement, the 2021/664 Art. 3(4) requirements block of a U-space
// airspace, and the closed national USSP list schema. It is pure: no
// database, no network, no logging.
//
//	func For(kind Kind) Rules
//	func (Rules) Validate(body []byte, lim ed318.Limits, now time.Time) (Accepted, *ed269.Problems)
//
// A publication is accepted whole or refused whole (spec 06 T9, LESSONS
// Z-01, Z-02): Validate returns every problem by JSON path, capped at
// lim.MaxProblems (100) with the count of the rest, in document order,
// and never changes a byte of the body. The ED-318 datasets are parsed
// by uspace-core/ed318.Parse with ed318's own limits (the byte cap
// raised to the publication cap by the caller) and built by
// ed318.ToZones; nothing here re-implements a parse or a judgement.
//
// # zones
//
// Every feature is held to: its type is not USPACE (U-space airspace is
// the uspace_airspace dataset's), its reason does not hold DAR (dynamic
// restrictions are the ANSP's, F2), and ed318.ToZones can build it with
// NOAADaylight. A *core.FieldError from ToZones about the geometry, a
// layer, a radius or a limit refuses the feature at that path, because a
// consumer that cannot build the zone would drop it silently; any other
// (a daylight schedule without end dates, more than ed318.MaxEventDays
// of events) is a Warning: consumers judge such a zone with
// ed318.Applies. Repeated identifiers and layer identifiers
// (ed318.PartIdentifier) are refused by ed318.Parse and
// publication.Rows. Uniqueness across datasets (D8) is the store's
// question: the caller asks it with the identifiers of Accepted.Rows
// before it publishes.
//
// # uspace_airspace
//
// As zones, but every feature is USPACE and carries the
// cis/uspace_requirements/v1 block in extendedProperties under
// RequirementsMember: uas_requirements, operational_conditions and
// airspace_constraints objects (airspace_constraints.max_height_agl_m,
// when given, a number above 0), service_performance with
// nid_update_hz, ti_update_hz and cis_latency_s numbers above 0,
// services_required of NID, GEO, FA, TI, WX, CM without repeats and with
// the four mandatory ones, and adjacent naming identifiers of this same
// publication. An unknown member of the block is refused; other
// extendedProperties members pass through.
//
// # ussp_list
//
// A hand-written, bounded validator of the closed schema
// cis/ussp_list/v1 (no third-party schema library, docs/PLAN.md section
// 4): every member known, no member repeated, at most MaxUssps entries,
// ussp_id unique (a repeat names both indexes), https URLs without
// userinfo, the Annex VI service names, RFC 3339 times. Accepted.Rows is
// empty for the list (it has no geometry).
package dataset
