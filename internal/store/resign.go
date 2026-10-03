package store

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/store/relational"
)

// EventSnapshotResigned is the events row of a re-signature.
const EventSnapshotResigned = "snapshot_resigned"

// maxResignBytes bounds the snapshot body ResignCurrent decompresses:
// far above any publication cap, so a corrupt body cannot exhaust
// memory (E-10).
const maxResignBytes = 1 << 30

// ResignReport is what ResignCurrent did.
type ResignReport struct {
	Dataset publication.Dataset
	// Version is the current version re-signed; 0 when the dataset has
	// never been published (nothing was written).
	Version   int64
	KID       string
	Signature string
}

// ResignCurrent signs the stored bytes of the dataset's current
// snapshot again with signer (whose active key is kid) and appends the
// signature to snapshot_signatures with an events row, in one
// transaction (docs/PLAN.md section 15 Q50). The bytes, the ETag and
// snapshots.cisp_signature are untouched; the read path serves the
// newest signature of these exact bytes from then on (after the api
// reloads the snapshot: a restart).
func (s *Store) ResignCurrent(ctx context.Context, ds publication.Dataset, signer Signer, kid string, now time.Time) (ResignReport, error) {
	rep := ResignReport{Dataset: ds, KID: kid}
	if !ds.Valid() {
		return rep, fmt.Errorf("resign: %q is not a dataset", string(ds))
	}
	if signer == nil || kid == "" {
		return rep, errors.New("resign: a signer and its kid are required")
	}
	err := s.tx(ctx, func(_ pgx.Tx, q *relational.Queries) error {
		if err := q.LockDataset(ctx, string(ds)); err != nil {
			return fmt.Errorf("lock: %w", err)
		}
		d, err := q.GetDataset(ctx, string(ds))
		if err != nil {
			return fmt.Errorf("dataset: %w", err)
		}
		if d.CurrentVersion == 0 {
			return nil
		}
		snap, err := q.GetSnapshot(ctx, relational.GetSnapshotParams{Dataset: string(ds), Version: d.CurrentVersion})
		if err != nil {
			return fmt.Errorf("snapshot of version %d: %w", d.CurrentVersion, err)
		}
		zr, err := gzip.NewReader(bytes.NewReader(snap.BodyGz))
		if err != nil {
			return fmt.Errorf("snapshot of version %d: %w", d.CurrentVersion, err)
		}
		body, err := io.ReadAll(io.LimitReader(zr, maxResignBytes+1))
		if err != nil {
			return fmt.Errorf("snapshot of version %d: %w", d.CurrentVersion, err)
		}
		if len(body) > maxResignBytes {
			return fmt.Errorf("snapshot of version %d is over %d bytes", d.CurrentVersion, maxResignBytes)
		}
		sig, err := signer.Sign(ctx, body)
		if err != nil {
			return fmt.Errorf("sign: %w", err)
		}
		if sig == "" {
			return errors.New("sign: the signer returned no signature")
		}
		sum := sha256.Sum256(snap.BodyGz)
		at := now.UTC()
		if err := q.InsertSnapshotSignature(ctx, relational.InsertSnapshotSignatureParams{
			Dataset: string(ds), Version: d.CurrentVersion, Kid: kid, Signature: sig, BodyGzSha256: sum[:], SignedAt: at,
		}); err != nil {
			return fmt.Errorf("record signature: %w", err)
		}
		if _, err := AppendEvent(ctx, q, Event{
			TS: at, ActorType: ActorSystem, ActorID: "cispctl", EventType: EventSnapshotResigned,
			EntityType: "dataset", EntityID: string(ds),
			Payload: map[string]any{"version": d.CurrentVersion, "kid": kid, "etag": snap.Etag},
		}); err != nil {
			return err
		}
		rep.Version, rep.Signature = d.CurrentVersion, sig
		return nil
	})
	if err != nil {
		return ResignReport{Dataset: ds, KID: kid}, err
	}
	return rep, nil
}
