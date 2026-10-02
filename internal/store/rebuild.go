package store

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/jackc/pgx/v5"
	"github.com/rootxkit/uspace-core/ed318"

	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/store/relational"
)

// RebuildReport is what RebuildCurrent did.
type RebuildReport struct {
	Dataset         publication.Dataset
	Version         int64
	FeaturesBefore  int64
	FeaturesAfter   int64
	SnapshotRebuilt bool
}

// ErrNeedsSigner is returned when the rebuilt snapshot differs from the
// stored one and no signer was given to sign it; nothing was changed.
var ErrNeedsSigner = errors.New("rebuild: the snapshot bytes changed and no signer is available")

// insertStagedCurrent fills features_current from the staging tables
// with the same shape SQL as a publication (Z-11).
const insertStagedCurrent = `WITH parts AS (
    SELECT feature_id, part,
           CASE WHEN polygon IS NOT NULL
                THEN ST_SetSRID(ST_GeomFromGeoJSON(polygon), 4326)
                ELSE ST_Buffer(ST_SetSRID(ST_MakePoint(lng, lat), 4326)::geography, radius_m)::geometry
           END AS g
    FROM cisp_stage_parts
), shapes AS (
    SELECT feature_id,
           CASE WHEN count(*) = 1 THEN (array_agg(g))[1] ELSE ST_Union(g) END AS geom
    FROM parts
    GROUP BY feature_id
)
INSERT INTO features_current (
    dataset, feature_id, version, feature, feature_sha256, geom, centroid,
    lower_m, lower_ref, upper_m, upper_ref, applicable_from, applicable_to,
    has_events, has_layers
)
SELECT $1, s.feature_id, $2, s.feature, s.feature_sha256, sh.geom, ST_Centroid(sh.geom),
       s.lower_m, s.lower_ref, s.upper_m, s.upper_ref, s.applicable_from, s.applicable_to,
       s.has_events, s.has_layers
FROM cisp_stage_features s
JOIN shapes sh USING (feature_id)`

// RebuildCurrent rebuilds features_current and the current snapshot of a
// dataset from the current publication's verbatim body, through
// ed318.Parse, publication.Rows and publication.Snapshot: the code a
// publication runs, never SQL that reinterprets ED-318 (docs/PLAN.md
// section 5.3). It runs in one transaction under the dataset's
// publication lock. A rebuilt snapshot equal to the stored one keeps its
// signature; a different one is signed with signer, and without a signer
// the rebuild fails with ErrNeedsSigner and changes nothing. The
// restrictions dataset is composed by its lifecycle (WP-5), not by one
// body, and is refused.
func (s *Store) RebuildCurrent(ctx context.Context, ds publication.Dataset, signer Signer) (RebuildReport, error) {
	rep := RebuildReport{Dataset: ds}
	if !ds.Valid() {
		return rep, fmt.Errorf("rebuild: %q is not a dataset", string(ds))
	}
	if ds == publication.DatasetRestrictions {
		return rep, errors.New("rebuild: restrictions is composed by its lifecycle (WP-5), not from one publication body")
	}
	err := s.tx(ctx, func(tx pgx.Tx, q *relational.Queries) error {
		if err := q.LockDataset(ctx, string(ds)); err != nil {
			return fmt.Errorf("lock: %w", err)
		}
		d, err := q.GetDataset(ctx, string(ds))
		if err != nil {
			return fmt.Errorf("dataset: %w", err)
		}
		rep.Version = d.CurrentVersion
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM features_current WHERE dataset = $1", string(ds)).Scan(&rep.FeaturesBefore); err != nil {
			return fmt.Errorf("count: %w", err)
		}
		if d.CurrentVersion == 0 {
			rep.FeaturesAfter = rep.FeaturesBefore
			return nil
		}
		pub, err := q.GetPublication(ctx, relational.GetPublicationParams{Dataset: string(ds), Version: d.CurrentVersion})
		if err != nil {
			return fmt.Errorf("publication: %w", err)
		}
		var body []byte
		switch ds.Kind() {
		case publication.KindUsspList:
			// The list's snapshot is its canonical form with the cis_*
			// members; an ED-318 body never goes through it.
			if body, err = publication.UsspListSnapshot(d.CurrentVersion, pub.ReceivedAt, pub.Body); err != nil {
				return fmt.Errorf("snapshot: %w", err)
			}
		case publication.KindED318:
			fc, probs := ed318.Parse(pub.Body, ed318.Limits{MaxBytes: len(pub.Body) + 1})
			if probs != nil {
				return fmt.Errorf("the stored body of version %d no longer parses: %w", d.CurrentVersion, probs)
			}
			rows, err := publication.Rows(fc)
			if err != nil {
				return err
			}
			if _, err := q.DeleteCurrentFeatures(ctx, string(ds)); err != nil {
				return fmt.Errorf("clear features_current: %w", err)
			}
			if err := stageRows(ctx, tx, rows, publication.DiffRows(nil, rows)); err != nil {
				return err
			}
			tag, err := tx.Exec(ctx, insertStagedCurrent, string(ds), d.CurrentVersion)
			if err != nil {
				return fmt.Errorf("fill features_current: %w", err)
			}
			rep.FeaturesAfter = tag.RowsAffected()
			if body, err = publication.Snapshot(ds, d.CurrentVersion, pub.ReceivedAt, pub.PublisherClientID, fc); err != nil {
				return fmt.Errorf("snapshot: %w", err)
			}
		}

		stored, err := q.GetSnapshot(ctx, relational.GetSnapshotParams{Dataset: string(ds), Version: d.CurrentVersion})
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("stored snapshot: %w", err)
		}
		if err == nil {
			old, gzErr := gunzip(stored.BodyGz)
			if gzErr == nil && bytes.Equal(old, body) {
				return nil // same bytes: the stored signature still signs them
			}
		}
		if signer == nil {
			return ErrNeedsSigner
		}
		if _, noop := signer.(NoopSigner); noop && !s.opts.AllowNoopSigner {
			return ErrNoopSigner
		}
		if _, err := q.DeleteSnapshot(ctx, relational.DeleteSnapshotParams{Dataset: string(ds), Version: d.CurrentVersion}); err != nil {
			return fmt.Errorf("delete snapshot: %w", err)
		}
		if err := s.insertSnapshot(ctx, q, ds, d.CurrentVersion, body, signer, s.opts.Now().UTC()); err != nil {
			return err
		}
		rep.SnapshotRebuilt = true
		_, err = AppendEvent(ctx, q, Event{
			TS: s.opts.Now(), ActorType: ActorSystem, ActorID: "cispctl", EventType: "snapshot_rebuilt",
			EntityType: "dataset", EntityID: string(ds), Payload: map[string]any{"version": d.CurrentVersion},
		})
		return err
	})
	return rep, err
}

func gunzip(b []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("gunzip: %w", err)
	}
	defer func() { _ = r.Close() }()
	out, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("gunzip: %w", err)
	}
	return out, nil
}
