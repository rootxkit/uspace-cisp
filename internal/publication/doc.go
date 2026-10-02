// Package publication is the CISP's version model (docs/PLAN.md D2, D3,
// D6, D8): it turns an accepted ED-318 collection into one canonical row
// per feature, diffs two versions of a dataset, builds the change record
// and the delta between versions, and materialises the unfiltered
// snapshot body. It is pure: no database, no network, no logging. The
// store (internal/store) writes what it returns in one transaction.
//
// # Datasets and kinds
//
// Dataset names the four published datasets (zones, uspace_airspace,
// ussp_list, restrictions); Kind says whether a dataset is ED-318
// (KindED318) or the USSP list (KindUsspList). Reason is why a version
// or a change record exists (publication, the restriction lifecycle,
// republished, subscription_test).
//
// # Rows
//
//	func Rows(fc *ed318.FeatureCollection) ([]FeatureRow, error)
//
// One FeatureRow per feature, keyed by the ED-318 identifier. Canonical
// is the feature as ed318.Export writes it, re-encoded compact with every
// object's keys sorted, and SHA256 its hash: two versions of a feature
// are the same when the hashes are. A GeometryCollection stays one row
// (the feature as published) whose geometry parts are all in Geom and
// whose layer identifiers (ed318.PartIdentifier) are listed in PartIDs and
// reserved: Rows refuses a collection where an identifier repeats or
// equals another feature's part identifier, with a *core.FieldError.
// Rows refuses more than MaxFeaturesPerPublication features.
//
// Geom carries the parts as published (rings, or a circle's centre and
// radius). The store turns a circle into its prefilter buffer in SQL and
// computes Centroid there (LESSONS Z-11); Rows leaves Centroid zero. The
// one circle outline drawn in Go is a read's cis_display_geometry
// (internal/outline), a drawing for maps on uspace-core geodesy. LowerM and UpperM come
// from ed318.Layer.LowerM and UpperM (feet converted by core); for a
// GeometryCollection they are the lowest lower and the highest upper of
// the layers when the layers share a reference, and nil (the surface,
// unlimited: the widest prefilter) when they do not, with HasLayers set.
// ApplicableFrom and ApplicableTo are the earliest start and the latest
// end of limitedApplicability, nil when any period is open on that side
// or there is none; HasEvents when a daily period uses a daylight event.
// They are prefilter hints: the judgement is ed318.Applies.
//
// # Diff, apply and delta
//
//	func DiffRows(prev, next []FeatureRow) Diff
//	func Apply(prev, next []FeatureRow, d Diff) []FeatureRow
//	func Delta(fromRows, toRows []FeatureRow, fromV, toV int64) DatasetDelta
//
// DiffRows compares by identifier: Added, Changed (the hash differs) and
// Removed, each sorted, and Ops with every identifier of either side
// including OpUnchanged. Apply rebuilds next from prev and the diff
// (property: Apply(a, b, DiffRows(a, b)) equals b sorted by identifier;
// DiffRows(a, a) is empty). Delta is the since_version answer: the
// canonical features added and changed and the identifiers removed.
//
// # Change records, snapshots and ETags
//
//	func ChangeOf(dataset Dataset, version int64, d Diff, rows []FeatureRow, reason Reason, at time.Time) Change
//	func Snapshot(dataset Dataset, version int64, issued time.Time, provider string, fc *ed318.FeatureCollection) ([]byte, error)
//	func ETag(dataset Dataset, version int64) string
//
// ChangeOf lists the added, changed and removed identifiers and the
// bounding box of every row they name in rows (pass the previous and the
// next rows together, so a moved or removed feature is covered where it
// was and where it is); BBox is nil when nothing changed. Snapshot is
// the unfiltered GET /v1/{dataset} body: ed318.Export of the collection
// with metadata.issued set to the version's time, metadata.provider to
// the publisher (kept as published when provider is empty), and the
// top-level members cis_dataset, cis_version and cis_updated_at
// (docs/PLAN.md section 6.3, Q1); the same input always gives the same
// bytes, and ed318.Parse reads them back. ETag is `"<dataset>:<version>"`.
package publication
