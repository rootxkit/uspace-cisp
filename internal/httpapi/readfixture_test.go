package httpapi

import (
	"bytes"
	"compress/gzip"
	"context"
	"log/slog"
	"sort"
	"time"

	"github.com/rootxkit/uspace-core/geodesy"

	"github.com/rootxkit/uspace-cisp/internal/obs"
	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/store"
)

// The fake store's side of the reads (WP-4): what PublishTx keeps for
// them, and ReadStore and the snapshot source over it.

// fakeSnapshot is what PublishTx stores as the version's snapshot: the
// same bytes publication.Snapshot (or UsspListSnapshot) builds, signed
// with signer and gzip.
func fakeSnapshot(ctx context.Context, in store.PublishInput, version int64, signer store.Signer) (store.Snapshot, error) {
	var body []byte
	var err error
	if in.Collection != nil {
		body, err = publication.Snapshot(in.Dataset, version, in.ReceivedAt, in.PublisherClientID, in.Collection)
	} else {
		body, err = publication.UsspListSnapshot(version, in.ReceivedAt, in.Body)
	}
	if err != nil {
		return store.Snapshot{}, err
	}
	sig, err := signer.Sign(ctx, body)
	if err != nil {
		return store.Snapshot{}, err
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write(body); err != nil {
		return store.Snapshot{}, err
	}
	if err := zw.Close(); err != nil {
		return store.Snapshot{}, err
	}
	return store.Snapshot{
		Dataset: in.Dataset, Version: version, ETag: publication.ETag(in.Dataset, version), BodyGz: gz.Bytes(),
		CISPSignature: sig, BuiltAt: in.ReceivedAt, ReceivedAt: in.ReceivedAt, Publisher: in.PublisherClientID,
	}, nil
}

// record keeps a new version for the reads; called with f.mu held.
func (f *fakeStore) record(in store.PublishInput, version int64, rows []publication.FeatureRow, diff publication.Diff, snap store.Snapshot, sum []byte) {
	ds := in.Dataset
	if f.snaps[ds] == nil {
		f.snaps[ds] = map[int64]store.Snapshot{}
		f.rowsAt[ds] = map[int64][]publication.FeatureRow{}
		f.heads[ds] = map[int64]store.StoredPublication{}
	}
	f.snaps[ds][version] = snap
	f.rowsAt[ds][version] = append([]publication.FeatureRow{}, rows...)
	f.heads[ds][version] = store.StoredPublication{
		Dataset: ds, Version: version, Body: append([]byte{}, in.Body...), BodySHA256: sum, ContentType: in.ContentType,
		PublisherClientID: in.PublisherClientID, PublisherSignature: in.PublisherSignature, SignatureKID: in.SignatureKID,
		ReceivedAt: in.ReceivedAt,
	}
	f.updated[ds] = in.ReceivedAt
	c := publication.ChangeOf(ds, version, diff, rows, in.Reason, in.ReceivedAt)
	c.ID = int64(len(f.changes) + 1)
	f.changes = append(f.changes, c)
}

// CurrentVersions implements store.SnapshotSource.
func (f *fakeStore) CurrentVersions(ctx context.Context) (map[publication.Dataset]int64, error) {
	states, err := f.CurrentStates(ctx)
	if err != nil {
		return nil, err
	}
	out := map[publication.Dataset]int64{}
	for ds, s := range states {
		out[ds] = s.Version
	}
	return out, nil
}

// CurrentStates implements store.StateSource.
func (f *fakeStore) CurrentStates(context.Context) (map[publication.Dataset]store.DatasetState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return nil, errFakeDown
	}
	out := map[publication.Dataset]store.DatasetState{}
	for _, ds := range publication.Datasets {
		out[ds] = store.DatasetState{Version: f.version[ds], UpdatedAt: f.updated[ds]}
	}
	return out, nil
}

// Snapshot implements store.SnapshotSource.
func (f *fakeStore) Snapshot(_ context.Context, ds publication.Dataset, version int64) (store.Snapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return store.Snapshot{}, errFakeDown
	}
	s, ok := f.snaps[ds][version]
	if !ok {
		return store.Snapshot{}, store.ErrNotFound
	}
	return s, nil
}

func storedOf(rows []publication.FeatureRow) []store.StoredFeature {
	out := make([]store.StoredFeature, 0, len(rows))
	for i := range rows {
		sum := rows[i].SHA256
		out = append(out, store.StoredFeature{ID: rows[i].ID, Feature: rows[i].Canonical, SHA256: sum[:]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// rowBox is the bounding box of a row's parts by core's geodesy: what
// the fake prefilters on (PostGIS's && on the stored shape in the real
// store).
func rowBox(r publication.FeatureRow) (geodesy.BBox, bool) {
	var out geodesy.BBox
	first := true
	for _, p := range r.Geom {
		var b geodesy.BBox
		switch {
		case p.Circle():
			b = geodesy.Circle{Center: *p.Center, RadiusM: *p.RadiusM}.BBox()
		case len(p.Rings) > 0:
			rings := make([]geodesy.Ring, 0, len(p.Rings))
			for _, ring := range p.Rings {
				rings = append(rings, geodesy.Ring(ring))
			}
			b = geodesy.Polygon{Rings: rings}.BBox()
		default:
			continue
		}
		if first {
			out, first = b, false
			continue
		}
		out = geodesy.BBox{MinLat: min(out.MinLat, b.MinLat), MinLon: min(out.MinLon, b.MinLon), MaxLat: max(out.MaxLat, b.MaxLat), MaxLon: max(out.MaxLon, b.MaxLon)}
	}
	return out, !first
}

func overlaps(a geodesy.BBox, b store.BBox) bool {
	return a.MinLon <= b.MaxLon && b.MinLon <= a.MaxLon && a.MinLat <= b.MaxLat && b.MinLat <= a.MaxLat
}

// ReadCurrent implements ReadStore.
func (f *fakeStore) ReadCurrent(_ context.Context, ds publication.Dataset, box *store.BBox) (store.CurrentRead, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return store.CurrentRead{}, errFakeDown
	}
	v := f.version[ds]
	out := store.CurrentRead{Dataset: ds, Version: v}
	if v == 0 {
		return out, nil
	}
	head := f.heads[ds][v]
	out.ReceivedAt, out.Publisher = head.ReceivedAt, head.PublisherClientID
	var rows []publication.FeatureRow
	for i := range f.current[ds] {
		r := f.current[ds][i]
		if box != nil {
			b, ok := rowBox(r)
			if !ok || !overlaps(b, *box) {
				continue
			}
		}
		rows = append(rows, r)
	}
	out.Features = storedOf(rows)
	return out, nil
}

// ReadDelta implements ReadStore.
func (f *fakeStore) ReadDelta(_ context.Context, ds publication.Dataset, from, maxBack int64) (store.DeltaRead, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return store.DeltaRead{}, errFakeDown
	}
	cur := f.version[ds]
	switch {
	case from > cur:
		return store.DeltaRead{}, store.ErrVersionAhead
	case cur-from > maxBack:
		return store.DeltaRead{}, &store.DeltaUnavailableError{From: from, Current: cur, Max: maxBack}
	}
	out := store.DeltaRead{From: from, To: cur}
	if from == cur {
		return out, nil
	}
	if from > 0 {
		out.FromFeatures = storedOf(f.rowsAt[ds][from])
	}
	out.ToFeatures = storedOf(f.current[ds])
	return out, nil
}

// Publication implements ReadStore.
func (f *fakeStore) Publication(_ context.Context, ds publication.Dataset, version int64) (store.StoredPublication, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return store.StoredPublication{}, errFakeDown
	}
	p, ok := f.heads[ds][version]
	if !ok {
		return store.StoredPublication{}, store.ErrNotFound
	}
	p.Body = append([]byte{}, p.Body...)
	return p, nil
}

// Changes implements ReadStore.
func (f *fakeStore) Changes(_ context.Context, since int64, ds *publication.Dataset, limit int) ([]publication.Change, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return nil, errFakeDown
	}
	var out []publication.Change
	for i := range f.changes {
		c := f.changes[i]
		if c.ID > since && (ds == nil || c.Dataset == *ds) && len(out) < limit {
			out = append(out, c)
		}
	}
	return out, nil
}

// Publishers implements ReadStore: the heartbeats recorded, and any row
// a test set.
func (f *fakeStore) Publishers(context.Context) ([]store.Publisher, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return nil, errFakeDown
	}
	out := append([]store.Publisher{}, f.publishers...)
	for _, b := range f.beats {
		at := b.ReceivedAt
		out = append(out, store.Publisher{ClientID: b.ClientID, Kind: b.Kind, LastHeartbeatAt: &at, StaleAfterS: 60, Enabled: true})
	}
	return out, nil
}

// readSource is a store that serves the reads and the snapshot cache.
type readSource interface {
	ReadStore
	store.SnapshotSource
}

// withReads gives the harness the reads when its store serves them: the
// snapshot cache, refreshed after every accepted PUT so a test reads its
// own write at once, the handlers and the status over both, and the
// public rate limiter (at a rate no test reaches unless it means to).
func (h *pubHarness) withReads(st PublicationStore, server *Server, status *obs.Status, logger *slog.Logger) {
	h.limiter = NewRateLimiter(RateLimiterConfig{RPM: 1_000_000, Component: status.Component("ratelimit")})
	rs, ok := st.(readSource)
	if !ok {
		return
	}
	h.cache = store.NewSnapshotCache(rs, store.CacheConfig{})
	h.reads = &Reads{
		Store: rs, Cache: h.cache, Signer: KeyRingSigner{Keys: h.ring}, MaxAge: time.Minute,
		PublicBaseURL: "https://uspace-cisp.example.test", Status: status, Logger: logger,
	}
	h.limiter = NewRateLimiter(RateLimiterConfig{RPM: 1_000_000, Component: status.Component("ratelimit"), Cheap: h.reads.NotModified})
	h.pubs.OnPublished = func() { _ = h.cache.Refresh(context.Background()) }
	server.Reads = h.reads
	server.Status.Cache = h.cache
	server.Status.Publishers = rs.Publishers
}
