package store

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed318"

	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/store/relational"
)

// Signer signs a snapshot body (the uncompressed bytes) with the CISP's
// key and returns the compact detached JWS. WP-2 provides the real one.
type Signer interface {
	Sign(ctx context.Context, body []byte) (string, error)
}

// NoopSigner signs nothing: the signature is empty. PublishTx refuses it
// unless Options.AllowNoopSigner is set, which only tests do.
type NoopSigner struct{}

// Sign returns an empty signature.
func (NoopSigner) Sign(context.Context, []byte) (string, error) { return "", nil }

var (
	// ErrUnchanged is returned when the publication's canonical
	// features equal the current version's (D3); nothing was written
	// and PublishResult carries the current version.
	ErrUnchanged = errors.New("publication: identical to the current version")
	// ErrNoopSigner is returned for a NoopSigner outside tests.
	ErrNoopSigner = errors.New("publication: the no-op signer is refused outside tests")
	// ErrVersionMismatch is returned when PublishInput.ExpectedVersion is
	// not the current version once the dataset is locked (If-Match, WP-3);
	// nothing was written and PublishResult carries the current version.
	ErrVersionMismatch = errors.New("publication: the dataset is not at the expected version")
)

// PublishInput is one accepted publication.
type PublishInput struct {
	Dataset publication.Dataset
	// Body is the verbatim request body, stored as received (D2).
	Body        []byte
	ContentType string
	// PublisherClientID is the token subject of the publisher.
	PublisherClientID string
	// PublisherSignature and SignatureKID are the publisher's detached
	// JWS and its key id; nil for versions the CISP makes (expiry).
	PublisherSignature, SignatureKID *string
	// Collection is the whole dataset at the new version (ED-318
	// datasets); nil for ussp_list, whose snapshot is Body.
	Collection *ed318.FeatureCollection
	// Warnings are stored with the version (a JSON array; nil is []).
	Warnings json.RawMessage
	Reason   publication.Reason
	// ReceivedAt is metadata.issued of the version; zero is now.
	ReceivedAt time.Time
	// ActorType and ActorID name the actor in the audit row; empty is
	// the client PublisherClientID.
	ActorType, ActorID string
	// ExpectedVersion, when set, is the version the publisher read
	// (If-Match): checked under the dataset lock, so two publishers
	// racing on one version cannot both win (ErrVersionMismatch).
	ExpectedVersion *int64
}

// PublishResult is what PublishTx committed (or, with ErrUnchanged, the
// current version).
type PublishResult struct {
	PublicationID string
	Version       int64
	ETag          string
	Diff          publication.Diff
	Change        publication.Change
}

// The steps of the publication transaction (docs/WORKPACKAGES/WP-1.md).
const (
	stepLocked = iota + 1
	stepPublication
	stepFeatures
	stepCurrent
	stepSnapshot
	stepChange
	stepDatasetVersion
	stepEvent
)

func (in *PublishInput) validate() error {
	switch {
	case !in.Dataset.Valid():
		return core.Fieldf("dataset", "%q is not a dataset", string(in.Dataset))
	case !in.Reason.VersionReason():
		return core.Fieldf("reason", "%q is not a version reason", string(in.Reason))
	case len(in.Body) == 0:
		return core.Fieldf("body", "is empty")
	case in.ContentType == "":
		return core.Fieldf("content_type", "is empty")
	case in.PublisherClientID == "":
		return core.Fieldf("publisher_client_id", "is empty")
	case in.Dataset.Kind() == publication.KindED318 && in.Collection == nil:
		return core.Fieldf("collection", "an ED-318 dataset needs the parsed collection")
	case in.Dataset.Kind() == publication.KindUsspList && in.Collection != nil:
		return core.Fieldf("collection", "ussp_list is not ED-318")
	}
	if len(in.Warnings) > 0 && !json.Valid(in.Warnings) {
		return core.Fieldf("warnings", "not JSON")
	}
	return nil
}

// PublishTx is the publication transaction every writer calls: lock the
// dataset, insert the publication, its features with their ops, replace
// features_current, insert the signed snapshot, the change record, the
// new current version and the audit row, commit, and then publish the
// change to the bus. A bus failure is counted (bus_publish_failed) and
// logged, never returned (D6). When the features equal the current
// version's and the dataset has one, nothing is written and the error
// is ErrUnchanged with the current version in the result.
func (s *Store) PublishTx(ctx context.Context, in PublishInput, signer Signer) (PublishResult, error) {
	if err := in.validate(); err != nil {
		return PublishResult{}, err
	}
	if signer == nil {
		return PublishResult{}, errors.New("publication: no signer")
	}
	if _, noop := signer.(NoopSigner); noop && !s.opts.AllowNoopSigner {
		return PublishResult{}, ErrNoopSigner
	}
	var next []publication.FeatureRow
	if in.Collection != nil {
		rows, err := publication.Rows(in.Collection)
		if err != nil {
			return PublishResult{}, err
		}
		next = rows
	}
	now := s.opts.Now().UTC().Truncate(time.Microsecond)
	received := in.ReceivedAt.UTC().Truncate(time.Microsecond)
	if in.ReceivedAt.IsZero() {
		received = now
	}
	bodySHA := sha256.Sum256(in.Body)
	// The USSP list is compared by its canonical content (D3), so a
	// re-publication that differs only in whitespace or member order is
	// unchanged.
	var canonicalList []byte
	if in.Dataset.Kind() == publication.KindUsspList {
		c, err := publication.UsspListCanonical(in.Body)
		if err != nil {
			return PublishResult{}, err
		}
		canonicalList = c
	}

	var res PublishResult
	err := s.tx(ctx, func(tx pgx.Tx, q *relational.Queries) error {
		ds := string(in.Dataset)
		if err := q.LockDataset(ctx, ds); err != nil {
			return fmt.Errorf("lock %s: %w", ds, err)
		}
		d, err := q.GetDataset(ctx, ds)
		if err != nil {
			return fmt.Errorf("dataset %s: %w", ds, err)
		}
		if err := s.fail(stepLocked); err != nil {
			return err
		}
		current := d.CurrentVersion
		if in.ExpectedVersion != nil && *in.ExpectedVersion != current {
			res = PublishResult{Version: current, ETag: publication.ETag(in.Dataset, current)}
			return ErrVersionMismatch
		}

		var prev []publication.FeatureRow
		if in.Collection != nil {
			hashes, err := q.CurrentFeatureHashes(ctx, ds)
			if err != nil {
				return fmt.Errorf("current features: %w", err)
			}
			for _, h := range hashes {
				r := publication.FeatureRow{ID: h.FeatureID}
				copy(r.SHA256[:], h.FeatureSha256)
				prev = append(prev, r)
			}
		}
		diff := publication.DiffRows(prev, next)
		if current >= 1 {
			unchanged := diff.Empty()
			if in.Collection == nil {
				p, err := q.GetPublication(ctx, relational.GetPublicationParams{Dataset: ds, Version: current})
				if err != nil {
					return fmt.Errorf("current publication: %w", err)
				}
				unchanged = bytes.Equal(p.BodySha256, bodySHA[:])
				if prev, err := publication.UsspListCanonical(p.Body); err == nil && canonicalList != nil {
					unchanged = bytes.Equal(prev, canonicalList)
				}
			}
			if unchanged {
				res = PublishResult{Version: current, ETag: publication.ETag(in.Dataset, current), Diff: diff}
				return ErrUnchanged
			}
		}
		version := current + 1
		pubID := newID(now)

		// The previous form of what changed or went, for the change's box;
		// read before features_current is replaced.
		touchedPrev, err := s.previousRows(ctx, q, ds, append(append([]string{}, diff.Changed...), diff.Removed...))
		if err != nil {
			return err
		}

		// 2. the publication.
		var supersedes *int64
		if current > 0 {
			supersedes = &current
		}
		warnings := in.Warnings
		if len(warnings) == 0 {
			warnings = json.RawMessage("[]")
		}
		if err := q.InsertPublication(ctx, relational.InsertPublicationParams{
			ID: pubID, Dataset: ds, Version: version, PublisherClientID: in.PublisherClientID,
			ReceivedAt: received, Body: in.Body, BodySha256: bodySHA[:], ContentType: in.ContentType,
			PublisherSignature: in.PublisherSignature, SignatureKid: in.SignatureKID,
			FeatureCount: int32(len(next)), Added: int32(len(diff.Added)),
			Changed: int32(len(diff.Changed)), Removed: int32(len(diff.Removed)),
			SupersedesVersion: supersedes, Warnings: warnings, Reason: string(in.Reason),
		}); err != nil {
			return fmt.Errorf("insert publication: %w", err)
		}
		if err := s.fail(stepPublication); err != nil {
			return err
		}

		// 3. the features of the version, with their ops.
		if in.Collection != nil {
			if err := insertFeatures(ctx, tx, pubID, next, diff); err != nil {
				return err
			}
			if len(diff.Removed) > 0 {
				if _, err := q.InsertRemovedFeatures(ctx, relational.InsertRemovedFeaturesParams{PublicationID: pubID, Dataset: ds, Ids: diff.Removed}); err != nil {
					return fmt.Errorf("insert removed features: %w", err)
				}
			}
		}
		if err := s.fail(stepFeatures); err != nil {
			return err
		}

		// 4. replace features_current in this transaction: readers see the
		// old set or the new one, never a gap.
		if in.Collection != nil {
			if _, err := q.DeleteCurrentFeatures(ctx, ds); err != nil {
				return fmt.Errorf("clear features_current: %w", err)
			}
			if _, err := q.InsertCurrentFromPublication(ctx, relational.InsertCurrentFromPublicationParams{Dataset: ds, Version: version, PublicationID: pubID}); err != nil {
				return fmt.Errorf("fill features_current: %w", err)
			}
		}
		if err := s.fail(stepCurrent); err != nil {
			return err
		}

		// 5. the signed snapshot.
		var body []byte
		if in.Collection != nil {
			body, err = publication.Snapshot(in.Dataset, version, received, in.PublisherClientID, in.Collection)
		} else {
			body, err = publication.UsspListSnapshot(version, received, in.Body)
		}
		if err != nil {
			return fmt.Errorf("snapshot: %w", err)
		}
		if err := s.insertSnapshot(ctx, q, in.Dataset, version, body, signer, now); err != nil {
			return err
		}
		if err := s.fail(stepSnapshot); err != nil {
			return err
		}

		// 6. the change record (the outbox, D6).
		rows := append(append([]publication.FeatureRow{}, touchedPrev...), next...)
		change := publication.ChangeOf(in.Dataset, version, diff, rows, in.Reason, now)
		if len(touchedPrev) < len(diff.Changed)+len(diff.Removed) {
			change.BBox = nil // a previous shape is unknown: the whole dataset
			s.opts.Counters.Inc("change_bbox_unavailable")
		}
		if change.ID, err = insertChange(ctx, q, change, &pubID); err != nil {
			return err
		}
		if err := s.fail(stepChange); err != nil {
			return err
		}

		// 7. the current version.
		if err := q.SetDatasetVersion(ctx, relational.SetDatasetVersionParams{Name: ds, Version: version, UpdatedAt: now}); err != nil {
			return fmt.Errorf("dataset version: %w", err)
		}
		if err := s.fail(stepDatasetVersion); err != nil {
			return err
		}

		// 8. the audit row.
		actorType, actorID := in.ActorType, in.ActorID
		if actorType == "" {
			actorType, actorID = ActorClient, in.PublisherClientID
		}
		if _, err := AppendEvent(ctx, q, Event{
			TS: now, ActorType: actorType, ActorID: actorID, EventType: "publication_accepted",
			EntityType: "publication", EntityID: pubID,
			Payload: map[string]any{
				"dataset": ds, "version": version, "reason": string(in.Reason), "change_id": change.ID,
				"added": len(diff.Added), "changed": len(diff.Changed), "removed": len(diff.Removed),
			},
		}); err != nil {
			return err
		}
		if err := s.fail(stepEvent); err != nil {
			return err
		}
		res = PublishResult{PublicationID: pubID, Version: version, ETag: publication.ETag(in.Dataset, version), Diff: diff, Change: change}
		return nil
	})
	if errors.Is(err, ErrUnchanged) || errors.Is(err, ErrVersionMismatch) {
		return res, err
	}
	if err != nil {
		return PublishResult{}, err
	}

	// 9. after the commit: the bus. The change is already durable; a lost
	// publish costs deliver's scan interval, never a notification.
	s.publish(ctx, res.Change)
	return res, nil
}

func (s *Store) fail(step int) error {
	if s.failAfter == nil {
		return nil
	}
	return s.failAfter(step)
}

func (s *Store) publish(ctx context.Context, c publication.Change) {
	if s.opts.Bus == nil {
		s.opts.Counters.Inc("bus_publish_skipped")
		return
	}
	if err := s.opts.Bus.Publish(ctx, c); err != nil {
		s.opts.Counters.Inc("bus_publish_failed")
		s.opts.Logger.WarnContext(ctx, "change committed but not published to the bus; deliver's scan will send it",
			"dataset", string(c.Dataset), "version", c.Version, "change_id", c.ID, "error", err.Error())
	}
}

// previousRows rebuilds the current rows of ids from their stored
// features, through ed318.Parse and publication.Rows (the same code as a
// publication). A feature that does not parse is left out; the caller
// sees fewer rows than ids.
func (s *Store) previousRows(ctx context.Context, q *relational.Queries, ds string, ids []string) ([]publication.FeatureRow, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	stored, err := q.CurrentFeaturesByID(ctx, relational.CurrentFeaturesByIDParams{Dataset: ds, Ids: ids})
	if err != nil {
		return nil, fmt.Errorf("previous features: %w", err)
	}
	features := make([][]byte, 0, len(stored))
	for _, f := range stored {
		features = append(features, f.Feature)
	}
	rows, err := RowsFromFeatures(features)
	if err != nil {
		return nil, nil //nolint:nilerr // an unparseable stored feature costs the change its box, counted by the caller
	}
	return rows, nil
}

// RowsFromFeatures parses stored canonical features back into rows with
// ed318.Parse and publication.Rows.
func RowsFromFeatures(features [][]byte) ([]publication.FeatureRow, error) {
	var b bytes.Buffer
	b.WriteString(`{"type":"FeatureCollection","features":[`)
	b.Write(bytes.Join(features, []byte(",")))
	b.WriteString(`]}`)
	fc, probs := ed318.Parse(b.Bytes(), ed318.Limits{})
	if probs != nil {
		return nil, fmt.Errorf("stored features do not parse: %w", probs)
	}
	return publication.Rows(fc)
}

func (s *Store) insertSnapshot(ctx context.Context, q *relational.Queries, ds publication.Dataset, version int64, body []byte, signer Signer, now time.Time) error {
	sig, err := signer.Sign(ctx, body)
	if err != nil {
		return fmt.Errorf("sign snapshot: %w", err)
	}
	gz, err := gzipBytes(body)
	if err != nil {
		return err
	}
	if err := q.InsertSnapshot(ctx, relational.InsertSnapshotParams{
		Dataset: string(ds), Version: version, Etag: publication.ETag(ds, version),
		BodyGz: gz, CispSignature: sig, BuiltAt: now,
	}); err != nil {
		return fmt.Errorf("insert snapshot: %w", err)
	}
	return nil
}

func gzipBytes(body []byte) ([]byte, error) {
	var b bytes.Buffer
	w, err := gzip.NewWriterLevel(&b, gzip.BestCompression)
	if err != nil {
		return nil, fmt.Errorf("gzip: %w", err)
	}
	if _, err := w.Write(body); err != nil {
		return nil, fmt.Errorf("gzip: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("gzip: %w", err)
	}
	return b.Bytes(), nil
}

func insertChange(ctx context.Context, q *relational.Queries, c publication.Change, pubID *string) (int64, error) {
	p := relational.InsertChangeParams{
		Dataset: string(c.Dataset), Version: c.Version, PublicationID: pubID,
		FeatureIds: nonNil(c.FeatureIDs), RemovedIds: nonNil(c.RemovedIDs), Reason: string(c.Reason), At: c.At,
	}
	if c.BBox != nil {
		p.HasBbox = true
		p.MinLon, p.MinLat, p.MaxLon, p.MaxLat = c.BBox.MinLon, c.BBox.MinLat, c.BBox.MaxLon, c.BBox.MaxLat
	}
	id, err := q.InsertChange(ctx, p)
	if err != nil {
		return 0, fmt.Errorf("insert change: %w", err)
	}
	return id, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// The staging tables of one publication transaction (dropped at commit
// or rollback). The parts are published coordinates and radii; SQL
// builds the drawing and prefilter shape from them (Z-11), Go never does.
const (
	createStageFeatures = `CREATE TEMP TABLE IF NOT EXISTS cisp_stage_features (
    feature_id      text,
    feature         jsonb,
    feature_sha256  bytea,
    lower_m         double precision,
    lower_ref       text,
    upper_m         double precision,
    upper_ref       text,
    applicable_from timestamptz,
    applicable_to   timestamptz,
    has_events      boolean,
    has_layers      boolean,
    op              text
) ON COMMIT DROP`
	createStageParts = `CREATE TEMP TABLE IF NOT EXISTS cisp_stage_parts (
    feature_id text,
    part       integer,
    polygon    text,
    lng        double precision,
    lat        double precision,
    radius_m   double precision
) ON COMMIT DROP`
	// A circle is its centre and radius (Z-11): the buffer on geography
	// is for bbox prefilters and drawing only. Several parts are unioned.
	insertStagedFeatures = `WITH parts AS (
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
INSERT INTO features (
    publication_id, feature_id, feature, feature_sha256, geom, centroid,
    lower_m, lower_ref, upper_m, upper_ref, applicable_from, applicable_to,
    has_events, has_layers, op
)
SELECT $1, s.feature_id, s.feature, s.feature_sha256, sh.geom, ST_Centroid(sh.geom),
       s.lower_m, s.lower_ref, s.upper_m, s.upper_ref, s.applicable_from, s.applicable_to,
       s.has_events, s.has_layers, s.op
FROM cisp_stage_features s
JOIN shapes sh USING (feature_id)`
)

var (
	stageFeatureColumns = []string{"feature_id", "feature", "feature_sha256", "lower_m", "lower_ref", "upper_m", "upper_ref", "applicable_from", "applicable_to", "has_events", "has_layers", "op"}
	stagePartColumns    = []string{"feature_id", "part", "polygon", "lng", "lat", "radius_m"}
)

// insertFeatures stages the rows with pgx.CopyFrom and inserts them into
// features with their ops and SQL-built shapes.
func insertFeatures(ctx context.Context, tx pgx.Tx, pubID string, rows []publication.FeatureRow, d publication.Diff) error {
	if len(rows) == 0 {
		return nil
	}
	if err := stageRows(ctx, tx, rows, d); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, insertStagedFeatures, pubID)
	if err != nil {
		return fmt.Errorf("insert features: %w", err)
	}
	if tag.RowsAffected() != int64(len(rows)) {
		return fmt.Errorf("insert features: %d of %d rows written", tag.RowsAffected(), len(rows))
	}
	return nil
}

// stageRows copies rows and their geometry parts into the staging
// tables of this transaction.
func stageRows(ctx context.Context, tx pgx.Tx, rows []publication.FeatureRow, d publication.Diff) error {
	for _, stmt := range []string{createStageFeatures, createStageParts, "TRUNCATE cisp_stage_features, cisp_stage_parts"} {
		if _, err := tx.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("staging: %w", err)
		}
	}
	feats := make([][]any, 0, len(rows))
	var parts [][]any
	for i := range rows {
		r := &rows[i]
		feats = append(feats, []any{
			r.ID, json.RawMessage(r.Canonical), r.SHA256[:], r.LowerM, refOrNil(r.LowerRef), r.UpperM, refOrNil(r.UpperRef),
			r.ApplicableFrom, r.ApplicableTo, r.HasEvents, r.HasLayers, string(d.Ops[r.ID]),
		})
		for k, p := range r.Geom {
			if p.Circle() {
				parts = append(parts, []any{r.ID, int32(k), nil, p.Center.LonDeg, p.Center.LatDeg, *p.RadiusM})
				continue
			}
			parts = append(parts, []any{r.ID, int32(k), polygonGeoJSON(p.Rings), nil, nil, nil})
		}
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"cisp_stage_features"}, stageFeatureColumns, pgx.CopyFromRows(feats)); err != nil {
		return fmt.Errorf("stage features: %w", err)
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"cisp_stage_parts"}, stagePartColumns, pgx.CopyFromRows(parts)); err != nil {
		return fmt.Errorf("stage geometry parts: %w", err)
	}
	return nil
}

func refOrNil(r core.VerticalRef) *string {
	if r == "" {
		return nil
	}
	s := string(r)
	return &s
}

// polygonGeoJSON writes rings as a GeoJSON Polygon, [longitude,
// latitude], numbers in their shortest exact form: an encoding of the
// published coordinates, not a computed shape.
func polygonGeoJSON(rings [][]core.LatLon) string {
	var b strings.Builder
	b.WriteString(`{"type":"Polygon","coordinates":[`)
	for i, ring := range rings {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('[')
		for k, p := range ring {
			if k > 0 {
				b.WriteByte(',')
			}
			b.WriteByte('[')
			b.WriteString(strconv.FormatFloat(p.LonDeg, 'g', -1, 64))
			b.WriteByte(',')
			b.WriteString(strconv.FormatFloat(p.LatDeg, 'g', -1, 64))
			b.WriteByte(']')
		}
		b.WriteByte(']')
	}
	b.WriteString(`]}`)
	return b.String()
}
