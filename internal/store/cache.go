package store

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/store/relational"
)

// Snapshot is one stored snapshot: the unfiltered body of a dataset
// version, gzip, with the CISP's signature over the uncompressed bytes.
type Snapshot struct {
	Dataset       publication.Dataset
	Version       int64
	ETag          string
	BodyGz        []byte
	CISPSignature string
	BuiltAt       time.Time
	// ReceivedAt is the version's received_at (metadata.issued and
	// Last-Modified) and Publisher its publisher's client id; the Store
	// fills both.
	ReceivedAt time.Time
	Publisher  string
}

func (s *Snapshot) size() int64 { return int64(len(s.BodyGz) + len(s.CISPSignature) + len(s.ETag)) }

// SnapshotSource is where the cache loads from (the Store).
type SnapshotSource interface {
	CurrentVersions(ctx context.Context) (map[publication.Dataset]int64, error)
	Snapshot(ctx context.Context, ds publication.Dataset, version int64) (Snapshot, error)
}

// ErrNoVersion is returned when the dataset has never been published.
var ErrNoVersion = errors.New("snapshot: the dataset has no version yet")

// CurrentVersions is datasets.current_version of every dataset.
func (s *Store) CurrentVersions(ctx context.Context) (map[publication.Dataset]int64, error) {
	rows, err := relational.New(s.pool).ListDatasets(ctx)
	if err != nil {
		return nil, fmt.Errorf("datasets: %w", err)
	}
	out := make(map[publication.Dataset]int64, len(rows))
	for _, r := range rows {
		out[publication.Dataset(r.Name)] = r.CurrentVersion
	}
	return out, nil
}

// Snapshot reads one stored snapshot with its version's received_at and
// publisher.
func (s *Store) Snapshot(ctx context.Context, ds publication.Dataset, version int64) (Snapshot, error) {
	r, err := relational.New(s.pool).GetSnapshotForRead(ctx, relational.GetSnapshotForReadParams{Dataset: string(ds), Version: version})
	if err != nil {
		return Snapshot{}, fmt.Errorf("snapshot %s:%d: %w", ds, version, err)
	}
	return Snapshot{
		Dataset: ds, Version: r.Version, ETag: r.Etag, BodyGz: r.BodyGz, CISPSignature: r.CispSignature, BuiltAt: r.BuiltAt,
		ReceivedAt: r.ReceivedAt, Publisher: r.PublisherClientID,
	}, nil
}

// Cache defaults (docs/PLAN.md section 9).
const (
	DefaultCacheMaxBytes              = 128 << 20
	DefaultCacheMaxVersionsPerDataset = 2
	DefaultCacheRefreshEvery          = 5 * time.Second
)

// CacheConfig bounds a SnapshotCache. Zero fields take the defaults.
type CacheConfig struct {
	MaxBytes              int64
	MaxVersionsPerDataset int
	RefreshEvery          time.Duration
	Now                   func() time.Time
	// Counters receive snapshot_cache_evicted, snapshot_cache_oversize
	// and snapshot_cache_refresh_failed; nil makes a private set.
	Counters *core.Counters
}

type cacheKey struct {
	ds      publication.Dataset
	version int64
}

type cacheEntry struct {
	snap Snapshot
	used uint64 // recency tick
}

// SnapshotCache is the per-instance, bounded cache of snapshots and of
// the current version of each dataset. When the database is unreachable
// it keeps serving what it holds and Stale reports since when (the
// X-CIS-Stale branch, E-02).
type SnapshotCache struct {
	src SnapshotSource
	cfg CacheConfig

	mu         sync.Mutex
	entries    map[cacheKey]*cacheEntry
	bytes      int64
	tick       uint64
	current    map[publication.Dataset]int64
	updated    map[publication.Dataset]time.Time
	loaded     bool
	staleSince time.Time
	// refreshed is when the current versions were last read.
	refreshed time.Time
}

// NewSnapshotCache is an empty cache over src.
func NewSnapshotCache(src SnapshotSource, cfg CacheConfig) *SnapshotCache {
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = DefaultCacheMaxBytes
	}
	if cfg.MaxVersionsPerDataset <= 0 {
		cfg.MaxVersionsPerDataset = DefaultCacheMaxVersionsPerDataset
	}
	if cfg.RefreshEvery <= 0 {
		cfg.RefreshEvery = DefaultCacheRefreshEvery
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Counters == nil {
		cfg.Counters = &core.Counters{}
	}
	return &SnapshotCache{
		src: src, cfg: cfg, entries: map[cacheKey]*cacheEntry{},
		current: map[publication.Dataset]int64{}, updated: map[publication.Dataset]time.Time{},
	}
}

// Counters are the cache's counters.
func (c *SnapshotCache) Counters() *core.Counters { return c.cfg.Counters }

// DatasetState is a dataset's current version and when it was set.
type DatasetState struct {
	Version   int64
	UpdatedAt time.Time
}

// StateSource is a SnapshotSource that also reports when each current
// version was set (the Store); the cache then serves both.
type StateSource interface {
	CurrentStates(ctx context.Context) (map[publication.Dataset]DatasetState, error)
}

// CurrentStates is datasets.current_version and updated_at of every
// dataset.
func (s *Store) CurrentStates(ctx context.Context) (map[publication.Dataset]DatasetState, error) {
	rows, err := relational.New(s.pool).ListDatasets(ctx)
	if err != nil {
		return nil, fmt.Errorf("datasets: %w", err)
	}
	out := make(map[publication.Dataset]DatasetState, len(rows))
	for _, r := range rows {
		out[publication.Dataset(r.Name)] = DatasetState{Version: r.CurrentVersion, UpdatedAt: r.UpdatedAt}
	}
	return out, nil
}

func (c *SnapshotCache) read(ctx context.Context) (map[publication.Dataset]int64, map[publication.Dataset]time.Time, error) {
	if st, ok := c.src.(StateSource); ok {
		states, err := st.CurrentStates(ctx)
		if err != nil {
			return nil, nil, err
		}
		cur := make(map[publication.Dataset]int64, len(states))
		upd := make(map[publication.Dataset]time.Time, len(states))
		for ds, s := range states {
			cur[ds] = s.Version
			if !s.UpdatedAt.IsZero() {
				upd[ds] = s.UpdatedAt
			}
		}
		return cur, upd, nil
	}
	cur, err := c.src.CurrentVersions(ctx)
	return cur, map[publication.Dataset]time.Time{}, err
}

// Refresh re-reads the current version of every dataset. On failure the
// map it holds stays and the cache is stale from the first failure.
func (c *SnapshotCache) Refresh(ctx context.Context) error {
	cur, upd, err := c.read(ctx)
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		c.markStale()
		c.cfg.Counters.Inc("snapshot_cache_refresh_failed")
		return err
	}
	c.current = cur
	c.updated = upd
	c.loaded = true
	c.staleSince = time.Time{}
	c.refreshed = c.cfg.Now()
	return nil
}

// Refreshed is when the current versions were last read from the
// source; zero before the first read.
func (c *SnapshotCache) Refreshed() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.refreshed
}

// Versions is the current version and update time of every dataset as
// last refreshed (nothing before the first refresh).
func (c *SnapshotCache) Versions() (map[publication.Dataset]int64, map[publication.Dataset]time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v := make(map[publication.Dataset]int64, len(c.current))
	u := make(map[publication.Dataset]time.Time, len(c.updated))
	for k, x := range c.current {
		v[k] = x
	}
	for k, x := range c.updated {
		u[k] = x
	}
	return v, u
}

func (c *SnapshotCache) markStale() {
	if c.staleSince.IsZero() {
		c.staleSince = c.cfg.Now()
	}
}

// Stale reports whether the last refresh or load failed, and since when.
func (c *SnapshotCache) Stale() (since time.Time, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.staleSince, !c.staleSince.IsZero()
}

// CurrentVersion is the dataset's current version as last refreshed (0
// when never published), refreshing first when nothing was loaded yet.
func (c *SnapshotCache) CurrentVersion(ctx context.Context, ds publication.Dataset) (int64, error) {
	c.mu.Lock()
	loaded := c.loaded
	c.mu.Unlock()
	if !loaded {
		if err := c.Refresh(ctx); err != nil {
			return 0, err
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.current[ds], nil
}

// Current is the snapshot of the dataset's current version.
func (c *SnapshotCache) Current(ctx context.Context, ds publication.Dataset) (Snapshot, error) {
	v, err := c.CurrentVersion(ctx, ds)
	if err != nil {
		return Snapshot{}, err
	}
	if v == 0 {
		return Snapshot{}, ErrNoVersion
	}
	return c.Get(ctx, ds, v)
}

// Get is the snapshot of one version, from memory or loaded.
func (c *SnapshotCache) Get(ctx context.Context, ds publication.Dataset, version int64) (Snapshot, error) {
	k := cacheKey{ds, version}
	c.mu.Lock()
	if e, ok := c.entries[k]; ok {
		c.tick++
		e.used = c.tick
		snap := e.snap
		c.mu.Unlock()
		return snap, nil
	}
	c.mu.Unlock()

	snap, err := c.src.Snapshot(ctx, ds, version)
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		c.markStale()
		return Snapshot{}, err
	}
	c.put(k, snap)
	return snap, nil
}

// put stores an entry and evicts past the bounds; called with mu held.
func (c *SnapshotCache) put(k cacheKey, snap Snapshot) {
	if snap.size() > c.cfg.MaxBytes {
		c.cfg.Counters.Inc("snapshot_cache_oversize") // served, never held
		return
	}
	if _, ok := c.entries[k]; ok {
		return
	}
	c.tick++
	c.entries[k] = &cacheEntry{snap: snap, used: c.tick}
	c.bytes += snap.size()

	// At most MaxVersionsPerDataset versions of a dataset: the oldest go.
	var versions []int64
	for key := range c.entries {
		if key.ds == k.ds {
			versions = append(versions, key.version)
		}
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i] < versions[j] })
	for len(versions) > c.cfg.MaxVersionsPerDataset {
		c.evict(cacheKey{k.ds, versions[0]})
		versions = versions[1:]
	}
	// At most MaxBytes: the least recently used go.
	for c.bytes > c.cfg.MaxBytes {
		var oldest cacheKey
		var oldestUsed uint64
		first := true
		for key, e := range c.entries {
			if first || e.used < oldestUsed {
				oldest, oldestUsed, first = key, e.used, false
			}
		}
		c.evict(oldest)
	}
}

func (c *SnapshotCache) evict(k cacheKey) {
	e, ok := c.entries[k]
	if !ok {
		return
	}
	c.bytes -= e.snap.size()
	delete(c.entries, k)
	c.cfg.Counters.Inc("snapshot_cache_evicted")
}

// Bytes is the size the cache holds.
func (c *SnapshotCache) Bytes() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.bytes
}

// Len is the number of snapshots the cache holds.
func (c *SnapshotCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// Run refreshes every RefreshEvery and whenever changed receives (a bus
// change), until ctx ends. Refresh errors are reported through Stale.
func (c *SnapshotCache) Run(ctx context.Context, changed <-chan struct{}) {
	t := time.NewTicker(c.cfg.RefreshEvery)
	defer t.Stop()
	for {
		_ = c.Refresh(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-changed:
		}
	}
}
