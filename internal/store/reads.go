package store

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/rootxkit/uspace-core/geodesy"

	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/store/relational"
)

// BBox is a query envelope in WGS84 degrees, minimum corner first.
type BBox struct{ MinLon, MinLat, MaxLon, MaxLat float64 }

// StoredFeature is one stored feature: its identifier, the feature as
// stored (jsonb text, not byte-equal to the canonical form it was
// written from) and the hash of its canonical form.
type StoredFeature struct {
	ID      string
	Feature []byte
	SHA256  []byte
}

// Row is the feature as a publication.FeatureRow for Delta: the
// identifier, the canonical bytes (re-encoded from the stored JSON) and
// the stored hash.
func (f StoredFeature) Row() (publication.FeatureRow, error) {
	canonical, err := publication.Canonical(f.Feature)
	if err != nil {
		return publication.FeatureRow{}, fmt.Errorf("feature %s: %w", f.ID, err)
	}
	r := publication.FeatureRow{ID: f.ID, Canonical: canonical}
	copy(r.SHA256[:], f.SHA256)
	return r, nil
}

// CurrentRead is a dataset's current version and its current features
// (all, or those in a box), read in one snapshot of the database.
type CurrentRead struct {
	Dataset publication.Dataset
	// Version is the current version; 0 when the dataset has none.
	Version int64
	// ReceivedAt and Publisher are the version's (zero for version 0).
	ReceivedAt time.Time
	Publisher  string
	Features   []StoredFeature
}

// readOnly runs fn in one read-only, repeatable-read transaction: every
// query sees the same committed state.
func (s *Store) readOnly(ctx context.Context, fn func(q *relational.Queries) error) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if err := fn(relational.New(tx)); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// ReadCurrent is the dataset's current version and its features, all of
// them or (box not nil) those whose stored shape's bounding box overlaps
// box: a prefilter (LESSONS Z-06, Z-11).
func (s *Store) ReadCurrent(ctx context.Context, ds publication.Dataset, box *BBox) (CurrentRead, error) {
	out := CurrentRead{Dataset: ds}
	err := s.readOnly(ctx, func(q *relational.Queries) error {
		d, err := q.GetDataset(ctx, string(ds))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("dataset %s: %w", ds, err)
		}
		out.Version = d.CurrentVersion
		if out.Version == 0 {
			return nil
		}
		head, err := q.GetVersionHead(ctx, relational.GetVersionHeadParams{Dataset: string(ds), Version: out.Version})
		if err != nil {
			return fmt.Errorf("version %s:%d: %w", ds, out.Version, err)
		}
		out.ReceivedAt, out.Publisher = head.ReceivedAt, head.PublisherClientID
		if box == nil {
			rows, err := q.ListCurrentFeatureBodies(ctx, string(ds))
			if err != nil {
				return fmt.Errorf("current features: %w", err)
			}
			for _, r := range rows {
				out.Features = append(out.Features, StoredFeature{ID: r.FeatureID, Feature: r.Feature, SHA256: r.FeatureSha256})
			}
			return nil
		}
		rows, err := q.ListCurrentFeaturesInBBox(ctx, relational.ListCurrentFeaturesInBBoxParams{
			Dataset: string(ds), MinLon: box.MinLon, MinLat: box.MinLat, MaxLon: box.MaxLon, MaxLat: box.MaxLat,
		})
		if err != nil {
			return fmt.Errorf("current features in box: %w", err)
		}
		for _, r := range rows {
			out.Features = append(out.Features, StoredFeature{ID: r.FeatureID, Feature: r.Feature, SHA256: r.FeatureSha256})
		}
		return nil
	})
	if err != nil {
		return CurrentRead{}, err
	}
	return out, nil
}

// ErrVersionAhead is returned by ReadDelta for a from version above the
// current one.
var ErrVersionAhead = errors.New("store: the version is above the current version")

// DeltaUnavailableError is returned by ReadDelta when from is more than
// Max versions behind Current: the client pulls the dataset whole.
type DeltaUnavailableError struct{ From, Current, Max int64 }

func (e *DeltaUnavailableError) Error() string {
	return "store: version " + strconv.FormatInt(e.From, 10) + " is more than " + strconv.FormatInt(e.Max, 10) +
		" versions behind the current " + strconv.FormatInt(e.Current, 10)
}

// DeltaRead is what a delta is made of: the features of version From
// and of the current version To, read in one snapshot.
type DeltaRead struct {
	From, To     int64
	FromFeatures []StoredFeature
	ToFeatures   []StoredFeature
}

// ReadDelta reads the features of version from (none for 0) and of the
// current version. It refuses a from above the current version
// (ErrVersionAhead) and one more than maxBack versions behind it
// (*DeltaUnavailableError).
func (s *Store) ReadDelta(ctx context.Context, ds publication.Dataset, from, maxBack int64) (DeltaRead, error) {
	out := DeltaRead{From: from}
	err := s.readOnly(ctx, func(q *relational.Queries) error {
		d, err := q.GetDataset(ctx, string(ds))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("dataset %s: %w", ds, err)
		}
		out.To = d.CurrentVersion
		switch {
		case from > out.To:
			return ErrVersionAhead
		case out.To-from > maxBack:
			return &DeltaUnavailableError{From: from, Current: out.To, Max: maxBack}
		case from == out.To:
			return nil
		}
		if from > 0 {
			rows, err := q.ListVersionFeatures(ctx, relational.ListVersionFeaturesParams{Dataset: string(ds), Version: from})
			if err != nil {
				return fmt.Errorf("features of %s:%d: %w", ds, from, err)
			}
			for _, r := range rows {
				out.FromFeatures = append(out.FromFeatures, StoredFeature{ID: r.FeatureID, Feature: r.Feature, SHA256: r.FeatureSha256})
			}
		}
		rows, err := q.ListCurrentFeatureBodies(ctx, string(ds))
		if err != nil {
			return fmt.Errorf("current features: %w", err)
		}
		for _, r := range rows {
			out.ToFeatures = append(out.ToFeatures, StoredFeature{ID: r.FeatureID, Feature: r.Feature, SHA256: r.FeatureSha256})
		}
		return nil
	})
	if err != nil {
		return DeltaRead{}, err
	}
	return out, nil
}

// StoredPublication is one version as published: the verbatim body and
// what came with it.
type StoredPublication struct {
	Dataset            publication.Dataset
	Version            int64
	Body               []byte
	BodySHA256         []byte
	ContentType        string
	PublisherClientID  string
	PublisherSignature *string
	SignatureKID       *string
	ReceivedAt         time.Time
	// SourceBody, SourceSHA256 and SourceContentType are what the
	// publisher sent when Body was mapped from another format (ED-269,
	// WP-12); nil otherwise. PublisherSignature then covers SourceBody.
	SourceBody        []byte
	SourceSHA256      []byte
	SourceContentType *string
}

// Publication is one stored version; ErrNotFound when there is none.
func (s *Store) Publication(ctx context.Context, ds publication.Dataset, version int64) (StoredPublication, error) {
	p, err := relational.New(s.pool).GetPublication(ctx, relational.GetPublicationParams{Dataset: string(ds), Version: version})
	if errors.Is(err, pgx.ErrNoRows) {
		return StoredPublication{}, ErrNotFound
	}
	if err != nil {
		return StoredPublication{}, fmt.Errorf("publication %s:%d: %w", ds, version, err)
	}
	return StoredPublication{
		Dataset: ds, Version: p.Version, Body: p.Body, BodySHA256: p.BodySha256, ContentType: p.ContentType,
		PublisherClientID: p.PublisherClientID, PublisherSignature: p.PublisherSignature, SignatureKID: p.SignatureKid,
		ReceivedAt: p.ReceivedAt, SourceBody: p.SourceBody, SourceSHA256: p.SourceSha256, SourceContentType: p.SourceContentType,
	}, nil
}

// Changes is the change feed after the cursor since, in cursor order, at
// most limit, of one dataset when ds is not nil.
func (s *Store) Changes(ctx context.Context, since int64, ds *publication.Dataset, limit int) ([]publication.Change, error) {
	var dsArg *string
	if ds != nil {
		v := string(*ds)
		dsArg = &v
	}
	rows, err := relational.New(s.pool).ListChanges(ctx, relational.ListChangesParams{SinceID: since, Dataset: dsArg, MaxRows: int32(min(limit, 1<<20))})
	if err != nil {
		return nil, fmt.Errorf("changes: %w", err)
	}
	out := make([]publication.Change, 0, len(rows))
	for i := range rows {
		r := &rows[i]
		c := publication.Change{
			ID: r.ID, Dataset: publication.Dataset(r.Dataset), Version: r.Version,
			FeatureIDs: r.FeatureIds, RemovedIDs: r.RemovedIds, Reason: publication.Reason(r.Reason), At: r.At.UTC(),
		}
		if r.HasBbox {
			c.BBox = &geodesy.BBox{MinLon: r.MinLon, MinLat: r.MinLat, MaxLon: r.MaxLon, MaxLat: r.MaxLat}
		}
		out = append(out, c)
	}
	return out, nil
}

// Publisher is one row of publishers.
type Publisher struct {
	ClientID          string
	Kind              string
	LastHeartbeatAt   *time.Time
	LastPublicationAt *time.Time
	StaleAfterS       int32
	Enabled           bool
}

// Publishers is every row of publishers.
func (s *Store) Publishers(ctx context.Context) ([]Publisher, error) {
	rows, err := relational.New(s.pool).ListPublishers(ctx)
	if err != nil {
		return nil, fmt.Errorf("publishers: %w", err)
	}
	out := make([]Publisher, 0, len(rows))
	for _, r := range rows {
		out = append(out, Publisher{
			ClientID: r.ClientID, Kind: r.Kind, LastHeartbeatAt: r.LastHeartbeatAt, LastPublicationAt: r.LastPublicationAt,
			StaleAfterS: r.StaleAfterS, Enabled: r.Enabled,
		})
	}
	return out, nil
}
