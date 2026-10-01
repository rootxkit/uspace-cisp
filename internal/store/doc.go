// Package store is the CISP's database adapter (docs/PLAN.md sections 3
// and 5): the two pgx pools, the goose runner for the two migration
// trees, the sqlc queries, the publication transaction and the bounded
// snapshot cache.
//
// # Pools
//
//	func OpenPool(ctx context.Context, cfg PoolConfig) (*pgxpool.Pool, error)
//
// One pool per database (CISP_DATABASE_URL, CISP_TIMESERIES_URL) with
// application_name per process, statement_timeout 10 s and a size from
// configuration (8 relational, 2 timeseries by default).
//
// # Migrations
//
//	func Up(ctx context.Context, db *sql.DB, tree Tree) ([]MigrationResult, error)
//	func DownTo(ctx context.Context, db *sql.DB, tree Tree, version int64) ([]MigrationResult, error)
//	func Pending(ctx context.Context, db *sql.DB, tree Tree) ([]string, error)
//	func Status(ctx context.Context, db *sql.DB, tree Tree) ([]MigrationStatus, error)
//
// The trees are embedded (package migrations) and run by goose with one
// version table each (goose_db_version_relational,
// goose_db_version_timeseries; D11) under a PostgreSQL session lock. A
// tree run against the database that holds the other tree's version
// table fails with ErrWrongDatabase. api and deliver call Pending at
// start and refuse to run while it is not empty; only `cispctl migrate`
// applies migrations.
//
// # Queries and transactions
//
// sqlc generates package relational (internal/store/queries/*.sql) and
// package timeseries (internal/store/queries/timeseries/*.sql); later
// work packages add their own query files. Store.Tx runs a function in
// one transaction:
//
//	func (s *Store) Tx(ctx context.Context, fn func(q *relational.Queries) error) error
//
// # The publication transaction
//
//	func (s *Store) PublishTx(ctx context.Context, in PublishInput, signer Signer) (PublishResult, error)
//
// Every writer calls PublishTx. In one transaction it takes the
// dataset's advisory lock (two publications of one dataset serialise, so
// versions and the change cursor stay monotonic), reads the current
// version, inserts the publication (verbatim body and publisher
// signature), the version's features with their ops by pgx.CopyFrom
// (removed ones carrying their last form), replaces features_current,
// inserts the snapshot (publication.Snapshot, gzip, signed by signer),
// the change record, the new current version and the chained audit row
// (AppendEvent); then it commits and publishes the change to the bus. A
// bus failure is counted as bus_publish_failed and logged, never
// returned (D6). An unchanged publication of a dataset already at a
// version writes nothing and returns ErrUnchanged with the current
// version. Geometry is built in SQL from the published coordinates: a
// circle's buffer on geography is a drawing and prefilter shape only
// (Z-11), and the feature column holds the feature as published. NoopSigner
// (empty signature) is refused unless Options.AllowNoopSigner, which
// only tests set.
//
//	func (s *Store) RebuildCurrent(ctx context.Context, ds publication.Dataset, signer Signer) (RebuildReport, error)
//
// rebuilds features_current and the current snapshot from the current
// publication's body through the same Go code (cispctl rebuild-current).
//
// # The snapshot cache
//
//	func NewSnapshotCache(src SnapshotSource, cfg CacheConfig) *SnapshotCache
//	func (c *SnapshotCache) Current(ctx context.Context, ds publication.Dataset) (Snapshot, error)
//	func (c *SnapshotCache) Get(ctx context.Context, ds publication.Dataset, version int64) (Snapshot, error)
//	func (c *SnapshotCache) Refresh(ctx context.Context) error
//	func (c *SnapshotCache) Stale() (since time.Time, ok bool)
//
// Per instance and bounded: at most MaxBytes (128 MiB) and
// MaxVersionsPerDataset (2) versions of each dataset; evictions are
// counted as snapshot_cache_evicted and a snapshot larger than the whole
// cache is served but not held (snapshot_cache_oversize). Run refreshes
// the current versions every 5 s and on a bus change. When the database
// is unreachable the cache keeps serving what it holds and Stale says
// since when: the X-CIS-Stale branch WP-4 surfaces.
//
// # The delivery log
//
// Policies lists the TimescaleDB jobs on delivery_attempts and
// SetRetention replaces its retention policy (cispctl set-retention).
package store
