# WP-1: store, migrations and the version model

Branch `feat/WP-1-store-versions`. Milestone C-M1. Owns exclusively:
`migrations/relational/` (from `0002`), `migrations/timeseries/` (from
`0002`), `internal/store/` (pgx, sqlc, transactions, goose runner,
snapshot cache), `internal/publication/` (version model, diff,
materialisation, delta, change records), `internal/bus/` (minimal:
connect, ensure stream, publish with ack), `cispctl migrate`,
`cispctl rebuild-current`. Depends on WP-0. On the critical path: WP-3,
WP-4, WP-5, WP-6 and WP-8 all write through this package, so open the
PR as soon as the integration tests pass and keep the exported API of
§"What to build" stable.

## Read first

1. `CLAUDE.md`, `docs/PLAN.md §1.3` (D2, D3, D6, D8, D9), `§5`, `§7`,
   `§9`, `§10.3`.
2. Spec `03` preamble and `§2` (the CISP entities), `02 F1` (full
   replacement, diffed by the CISP), `02 F3` (`ETag` = version,
   `since_version`), `05 §4` (retention), LESSONS B-05, B-15, E-10,
   Z-11 (a circle is its centre and radius; any polygon is for drawing).
3. `uspace-core/ed318`: `Feature`, `Geometry` (`Rings`, `Center`,
   `RadiusM`, `Layer`, `Geometries`), `UASZone`, `Export`, `Parse`,
   `PartIdentifier`, `ToZones` (what a consumer builds; your
   `features_current` must give it a collision-free set).
4. Reference only: `utm/api/zone_routes.py` (zone versions),
   `utm/airspace/zones.py` (`geozone_from_row`: what the predecessor
   stored for a circle).

## What to build

### Migrations (`migrations/relational/0002..`, `migrations/timeseries/0002..`)

Every table of `docs/PLAN.md §5.1` and `§5.2` with the indexes named
there, one file per table group, `Up` and `Down` both tested. Rules:

- `features_current` has `UNIQUE (dataset, feature_id)` **and** a
  partial unique index on `feature_id` where `dataset IN ('zones',
  'uspace_airspace', 'restrictions')` (D8).
- `geom` is `geometry(Geometry, 4326)` with a GiST index; `centroid`
  `geometry(Point, 4326)`.
- `publications`, `publication_attempts`, `changes`, `events` are
  insert-only for `cisp_api` (`REVOKE UPDATE, DELETE`), and the
  migration that creates them says so in a comment with the threat
  (`06` T7).
- `events` is partitioned by month (`PARTITION BY RANGE (ts)`) with a
  `cispctl` subcommand later creating partitions; the migration creates
  the current and next month.
- `delivery_attempts` is a hypertable (`create_hypertable`, 1-day
  chunks), with the compression policy (7 days, `segmentby
  subscription_id`, `orderby at DESC`) and the retention policy (90
  days; the number comes from a `cispctl` flag at migration time? No:
  policies are data, set by `cispctl set-retention --days`, defaulting
  to 90 in `0002`; document).

`internal/store/migrate.go`: `embed.FS` per tree, `Up(ctx, db, tree)`,
`Pending(ctx, db, tree) ([]string, error)`, `Status`. `api` and
`deliver` call `Pending` at start and refuse to run with pending
migrations (print them, exit 2). `cispctl migrate relational|timeseries
[--down-to N]`.

### Store (`internal/store`)

- `pgxpool` per database with `CISP_DATABASE_URL`, `CISP_TIMESERIES_URL`;
  `application_name` set per process; statement timeout 10 s; pool
  sizes from config (defaults 8 / 2).
- sqlc (`sqlc.yaml` with two packages `relational` and `timeseries`,
  engine `postgresql`, `pgx/v5`), queries in `internal/store/queries/*.sql`,
  generated code committed and checked by `make generate-check`.
  Queries for every table of §5.1 that WP-1 owns the shape of; later WPs
  add their own query files under their names (`restrictions.sql`,
  `subscriptions.sql`, `console.sql`) without editing WP-1's.
- `Tx(ctx, func(q *relational.Queries) error)` with the serialisation
  rule: the publication path takes `pg_advisory_xact_lock(hash(dataset))`
  so two concurrent publications of one dataset serialise and the
  version and cursor stay monotonic.
- `SnapshotCache`: per instance, bounded (`MaxBytes` default 128 MiB,
  `MaxVersionsPerDataset` 2), holds `snapshots` rows (`etag`,
  `body_gz`, `cisp_signature`, `built_at`) and the `datasets.current_version`
  map; `Current(dataset)` and `Get(dataset, version)` return from memory
  or load; `Refresh(ctx)` re-reads `datasets` every 5 s and on a bus
  change; **when the database is unreachable it keeps serving what it
  holds and reports `Stale() (since time.Time, ok bool)`** — the degraded
  branch WP-4 surfaces as `X-CIS-Stale` (E-02: tested by closing the pool
  under it).

### Version model (`internal/publication`, pure)

```go
type Dataset string   // zones, uspace_airspace, ussp_list, restrictions
type Kind string      // KindED318, KindUsspList
type FeatureRow struct{ ID string; Canonical []byte (compact JSON of the Feature, keys sorted); SHA256 [32]byte; Geom ...; Centroid core.LatLon; LowerM, UpperM *float64; LowerRef, UpperRef core.VerticalRef; ApplicableFrom, ApplicableTo *time.Time; HasEvents bool }
func Rows(fc *ed318.FeatureCollection) ([]FeatureRow, error)       // one row per feature; a GeometryCollection stays ONE row (the feature as published) with the union geometry, but its part identifiers (PartIdentifier) are reserved against collisions
type Op string        // OpAdded, OpChanged, OpRemoved, OpUnchanged
type Diff struct{ Added, Changed, Removed []string; Ops map[string]Op }
func DiffRows(prev, next []FeatureRow) Diff                         // by ID; Changed when SHA256 differs; deterministic order (sorted IDs)
func Apply(prev []FeatureRow, next []FeatureRow, d Diff) []FeatureRow // for the property test apply(prev, diff) == next
type Change struct{ Dataset Dataset; Version int64; FeatureIDs, RemovedIDs []string; Reason Reason; At time.Time; BBox *geodesy.BBox }
func ChangeOf(dataset Dataset, version int64, d Diff, rows []FeatureRow, reason Reason, at time.Time) Change
func Snapshot(dataset Dataset, version int64, issued time.Time, provider string, fc *ed318.FeatureCollection) ([]byte, error)  // the unfiltered response body of GET /v1/{dataset}: ed318.Export with metadata.issued/provider and the cis_* top-level members (PLAN §6.3, Q1); deterministic bytes
func ETag(dataset Dataset, version int64) string                    // `"<dataset>:<version>"`
func Delta(fromRows, toRows []FeatureRow, fromV, toV int64) DatasetDelta
```

Geometry for the row: a Polygon as published; a circle as
`ST_Buffer(ST_SetSRID(ST_Point(lng, lat), 4326)::geography, radius_m)::geometry`
computed in SQL at insert (never in Go), **marked in the column comment
as a drawing and prefilter shape** (Z-11); a GeometryCollection as the
union of its parts. The centroid is `ST_Centroid` of that. `lower_m` and
`upper_m` from `Layer.LowerM()/UpperM()` (feet already converted by
core); for a GeometryCollection the row stores the min lower and max
upper across layers and `HasLayers = true`.

Applicability bounds: `ApplicableFrom/To` are the min `startDateTime`
and max `endDateTime` across the zone's `limitedApplicability`; nil when
unbounded; `HasEvents` when any `DailyPeriod` uses an event. These are
prefilter hints for WP-4's `at=`; the judgement is `ed318.Applies`.

### Publication transaction (`internal/store.PublishTx`)

One function every writer calls, in one transaction:

1. advisory lock on the dataset; read `current_version`;
2. insert `publications` (bytes, signature, counts, warnings, reason);
3. insert `features` rows with `op` from the diff, by `pgx.CopyFrom`;
4. replace `features_current` for the dataset (delete + copy, inside
   the same transaction so readers never see a gap);
5. insert `snapshots` (built by `publication.Snapshot`, gzip, signed by
   a `Signer` interface the caller passes — WP-2 provides it; WP-1 ships
   a `NoopSigner` for tests that sets an empty signature and is refused
   by the production config);
6. insert `changes` (returning the cursor);
7. update `datasets.current_version`;
8. insert the `events` row (`publication_accepted`, actor = client);
9. commit; **then** `bus.Publish(change)`; a publish error is counted
   (`bus_publish_failed`) and logged, never returned to the caller
   (D6).

Idempotency: when `DiffRows` is empty against the current version and
the dataset is already at ≥ 1, return `ErrUnchanged` with the current
version and insert nothing (the caller answers 200).

`cispctl rebuild-current --dataset X`: rebuilds `features_current` and
`snapshots` from `publications.body` through the same Go code (for a
migration that changes the row shape), inside a transaction, printing
counts before and after.

### Bus (`internal/bus`, minimal)

`Connect(ctx, cfg)` with `nats.RetryOnFailedConnect(true)`,
`MaxReconnects(-1)`, `ReconnectWait(2 s)`, credentials file; `EnsureStream`
creating `CIS_CHANGES` (subjects `cis.v1.change.*`, file, 30 d, 1 GiB,
`Duplicates` 2 min) idempotently; `Publish(ctx, change) error` with
`Nats-Msg-Id` = change id and `PublishAsync` + ack wait 5 s. WP-7 adds
the subscribe side and the degraded start; WP-1 makes `Connect` return a
usable handle even when the broker is down (reconnecting) and exposes
`Status()`.

## Tests

- Unit (`internal/publication`): rows from the `ed318_roundtrip.json`
  accepted collections; diff E-01 pairs (added/changed/removed beside
  unchanged); property test with random feature sets (`apply(prev,
  diff) == next`, `diff(a, a)` empty); snapshot bytes deterministic across
  two runs and parseable by `ed318.Parse` (round trip: `Parse(Snapshot(fc))`
  equals `fc` plus the `cis_*` extras); `ETag` format.
- Integration (`-tags integration`): both trees up from empty and down
  to zero and up again; `PublishTx` atomic (inject a failure after step
  4 and prove no row of the version exists); two goroutines publishing
  the same dataset get versions N and N+1 and cursors in order; the
  cross-dataset unique index refuses a `restrictions` feature with a
  `zones` identifier; a circle's stored `geom` contains the published
  centre and `ST_Area(geography)` matches `pi r^2` within 1 %;
  `SnapshotCache` serves after the pool is closed and reports `Stale`
  (E-02); the hypertable has the compression and retention policies
  (`timescaledb_information.jobs`); bus publish with and without the
  broker (the failure counted, the call returning).
- Bounds (E-10): the snapshot cache evicts past `MaxBytes` and counts;
  `Rows` refuses a collection over `MaxFeaturesPerPublication` (50 000)
  with a `*core.FieldError`.

## Done when

- [ ] `make lint`, `make race`, `make integration` green; the
  integration job in CI ran a non-zero count (paste the line).
- [ ] Coverage ≥ 85 % in `internal/publication`, ≥ 80 % in
  `internal/store` (generated code excluded).
- [ ] `cispctl migrate relational && cispctl migrate timeseries` against
  `make dev-deps` prints the applied versions; `/readyz` turns ready
  (paste it).
- [ ] The exported API above is documented in each package's `doc.go`.
- [ ] CHANGELOG line; PR body with outputs (E-04).

## Safety notes

The circle buffer is the one place where the CISP computes a shape it did
not receive. It must never be served as the zone's geometry: the served
feature is the verbatim JSON in `feature`. A test asserts that `GET`
bodies (WP-4) never contain the buffer; WP-1 asserts that the `feature`
column equals the published feature byte for byte after canonicalisation.

## Commits

`feat(store): relational and timeseries migrations with insert-only audit tables [WP-1 C-M1]`,
`feat(publication): canonical feature rows, diff, snapshot and change records [WP-1 C-M1]`,
`feat(store): the publication transaction with advisory locking and the snapshot cache [WP-1 C-M1]`,
`feat(bus): connect, ensure the change stream and publish with ack [WP-1 C-M1]`,
`feat(cispctl): migrate and rebuild-current [WP-1 C-M1]`,
`test(store): integration tests against PostgreSQL, TimescaleDB and NATS [WP-1 C-M1]`.
