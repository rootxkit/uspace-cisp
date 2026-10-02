package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed318"

	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/restriction"
	"github.com/rootxkit/uspace-cisp/internal/store/relational"
)

// The actors of restriction events and the publisher of the versions
// the CISP makes itself (expiry).
const (
	// SystemActor is the actor of an event the CISP caused (the expiry).
	SystemActor = "system"
	// SystemPublisher is publications.publisher_client_id of a version the
	// CISP made itself: the producer name of its change records.
	SystemPublisher = "uspace-cisp"
)

// restrictionsFeatureIDKey is the unique constraint on
// restrictions.feature_id (migration 0003): an identifier names one
// restriction for ever.
const restrictionsFeatureIDKey = "restrictions_feature_id_key"

// IsRestrictionIdentifierTaken reports whether err is the backstop of a
// restriction identifier already held by another restriction (a create
// that raced the lookup).
func IsRestrictionIdentifierTaken(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "23505" && pg.ConstraintName == restrictionsFeatureIDKey
}

// RestrictionEvent is one restriction_events row.
type RestrictionEvent struct {
	At            time.Time
	Op            restriction.Op
	AnspVersion   int64
	PublicationID *string
	Actor         string
}

// RestrictionRecord is a stored head with its times and events.
type RestrictionRecord struct {
	restriction.Head
	CreatedAt, UpdatedAt  time.Time
	LastPublisherClientID string
	Events                []RestrictionEvent
}

// RestrictionDecision is what RestrictionWrite.Decide makes of the stored
// head: the head to write, the op and the reason of the version, and the
// whole current set of the restrictions dataset after it. An empty Reason
// is a replay (or, for the expiry, nothing to do): nothing is written.
type RestrictionDecision struct {
	Head       restriction.Head
	Op         restriction.Op
	Reason     publication.Reason
	Collection *ed318.FeatureCollection
}

// RestrictionWrite is one lifecycle event of a restriction, written with
// its version of the restrictions dataset in one transaction.
type RestrictionWrite struct {
	// ID names the head; when empty, AnspRef does (a create, or the ANSP
	// addressing by ansp_ref).
	ID, AnspRef string
	// Decide runs under the restrictions dataset's lock with the stored
	// head (nil when none) and the current features of the dataset as
	// stored (each a restriction as served). Its error is returned as it
	// is, after the rollback.
	Decide func(head *restriction.Head, current []StoredFeature) (RestrictionDecision, error)
	// Body is the request body, stored verbatim as the version's
	// publication with the publisher's signature (nil for the CISP's own
	// versions).
	Body               []byte
	ContentType        string
	PublisherClientID  string
	PublisherSignature *string
	SignatureKID       *string
	ReceivedAt         time.Time
	// Actor is the event's actor: the client id, or SystemActor.
	Actor string
}

// RestrictionResult is what ApplyRestriction did.
type RestrictionResult struct {
	Head restriction.Head
	// Replay is set when Decide wrote nothing (the same ansp_version):
	// Version is then the current version.
	Replay        bool
	Version       int64
	ETag          string
	PublicationID string
	Reason        publication.Reason
	Change        publication.Change
}

// replayError carries a replay out of the publication transaction (which
// it rolls back: nothing is written).
type replayError struct {
	head    restriction.Head
	current int64
}

func (e *replayError) Error() string { return "restriction: replay, nothing written" }

// ApplyRestriction writes one lifecycle event: under the restrictions
// dataset's lock it reads the head and the current features, asks
// Decide, and writes the head, its event, and the new version of the
// dataset (publication, features, snapshot, change, audit row) in one
// transaction through PublishTx; then the change goes to the bus. A
// replay writes nothing and returns the stored head with the current
// version.
func (s *Store) ApplyRestriction(ctx context.Context, w RestrictionWrite, signer Signer) (RestrictionResult, error) {
	if w.Decide == nil {
		return RestrictionResult{}, errors.New("restriction: no decision")
	}
	actor := w.Actor
	if actor == "" {
		actor = w.PublisherClientID
	}
	var out RestrictionResult
	in := PublishInput{
		Dataset: publication.DatasetRestrictions, Body: w.Body, ContentType: w.ContentType,
		PublisherClientID: w.PublisherClientID, PublisherSignature: w.PublisherSignature, SignatureKID: w.SignatureKID,
		ReceivedAt: w.ReceivedAt,
	}
	if actor == SystemActor {
		in.ActorType, in.ActorID = ActorSystem, SystemActor
	}
	in.Before = func(ctx context.Context, tx BeforeTx) (Prepared, error) {
		q := tx.Queries
		head, err := findHead(ctx, q, w.ID, w.AnspRef)
		if err != nil {
			return Prepared{}, err
		}
		rows, err := q.ListCurrentFeatureBodies(ctx, string(publication.DatasetRestrictions))
		if err != nil {
			return Prepared{}, fmt.Errorf("current restrictions: %w", err)
		}
		current := make([]StoredFeature, 0, len(rows))
		for _, r := range rows {
			current = append(current, StoredFeature{ID: r.FeatureID, Feature: r.Feature, SHA256: r.FeatureSha256})
		}
		var stored *restriction.Head
		if head != nil {
			h := head.Head
			stored = &h
		}
		d, err := w.Decide(stored, current)
		if err != nil {
			return Prepared{}, err
		}
		if d.Reason == "" {
			h := restriction.Head{}
			if stored != nil {
				h = *stored
			}
			return Prepared{}, &replayError{head: h, current: tx.Current}
		}
		if err := writeHead(ctx, q, head, d.Head, tx.Now, w.PublisherClientID); err != nil {
			return Prepared{}, err
		}
		pubID := tx.PublicationID
		if err := q.InsertRestrictionEvent(ctx, relational.InsertRestrictionEventParams{
			RestrictionID: d.Head.ID, At: tx.Now, Op: string(d.Op), AnspVersion: int32(d.Head.AnspVersion),
			PublicationID: &pubID, Actor: actor,
		}); err != nil {
			return Prepared{}, fmt.Errorf("restriction event: %w", err)
		}
		out.Head, out.Reason = d.Head, d.Reason
		return Prepared{Collection: d.Collection, Reason: d.Reason}, nil
	}
	res, err := s.PublishTx(ctx, in, signer)
	var replay *replayError
	switch {
	case errors.As(err, &replay):
		return RestrictionResult{
			Head: replay.head, Replay: true, Version: replay.current,
			ETag: publication.ETag(publication.DatasetRestrictions, replay.current),
		}, nil
	case errors.Is(err, ErrUnchanged):
		// Every accepted op changes the stamped member, so an unchanged set
		// is a fault: the transaction rolled back the head with it.
		return RestrictionResult{}, fmt.Errorf("restriction %s: the op left the dataset unchanged: %w", out.Head.ID, err)
	case err != nil:
		return RestrictionResult{}, err
	}
	out.Version, out.ETag, out.PublicationID, out.Change = res.Version, res.ETag, res.PublicationID, res.Change
	return out, nil
}

// findHead reads the head by id, else by ansp_ref; nil when none.
func findHead(ctx context.Context, q *relational.Queries, id, anspRef string) (*RestrictionRecord, error) {
	var row relational.GetRestrictionByIDRow
	var err error
	switch {
	case id != "":
		row, err = q.GetRestrictionByID(ctx, id)
	case anspRef != "":
		var r relational.GetRestrictionByAnspRefRow
		r, err = q.GetRestrictionByAnspRef(ctx, anspRef)
		row = relational.GetRestrictionByIDRow(r)
	default:
		return nil, core.Fieldf("id", "a restriction is named by its id or its ansp_ref")
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("restriction head: %w", err)
	}
	rec := recordOf(row)
	return &rec, nil
}

// writeHead inserts a new head or updates the stored one.
func writeHead(ctx context.Context, q *relational.Queries, stored *RestrictionRecord, h restriction.Head, now time.Time, publisher string) error {
	if stored == nil {
		if err := q.InsertRestriction(ctx, relational.InsertRestrictionParams{
			ID: h.ID, AnspRef: h.AnspRef, AnspVersion: int32(h.AnspVersion),
			UspaceAirspaceID: h.UspaceAirspaceID, FeatureID: h.FeatureID, State: string(h.State),
			StartsAt: h.StartsAt.UTC(), EndsAt: h.EndsAt.UTC(), EndedBy: h.EndedBy,
			CreatedAt: now, UpdatedAt: now, LastPublisherClientID: publisher, LastBodySha256: h.BodySHA256[:],
		}); err != nil {
			return fmt.Errorf("insert restriction: %w", err)
		}
		return nil
	}
	n, err := q.UpdateRestriction(ctx, relational.UpdateRestrictionParams{
		ID: h.ID, AnspVersion: int32(h.AnspVersion), State: string(h.State),
		EndsAt: h.EndsAt.UTC(), EndedBy: h.EndedBy, UpdatedAt: now, LastPublisherClientID: publisher,
		LastBodySha256: h.BodySHA256[:],
	})
	if err != nil {
		return fmt.Errorf("update restriction: %w", err)
	}
	if n != 1 {
		return fmt.Errorf("update restriction %s: %d rows", h.ID, n)
	}
	return nil
}

func recordOf(r relational.GetRestrictionByIDRow) RestrictionRecord {
	var sum [32]byte
	copy(sum[:], r.LastBodySha256)
	return RestrictionRecord{
		Head: restriction.Head{
			ID: r.ID, AnspRef: r.AnspRef, AnspVersion: int64(r.AnspVersion), UspaceAirspaceID: r.UspaceAirspaceID,
			FeatureID: r.FeatureID, State: restriction.State(r.State), StartsAt: r.StartsAt.UTC(), EndsAt: r.EndsAt.UTC(),
			EndedBy: r.EndedBy, BodySHA256: sum,
		},
		CreatedAt: r.CreatedAt.UTC(), UpdatedAt: r.UpdatedAt.UTC(), LastPublisherClientID: r.LastPublisherClientID,
	}
}

// Restriction is the head named by id (or, byAnspRef, by its ansp_ref)
// with its events; ErrNotFound when there is none.
func (s *Store) Restriction(ctx context.Context, ref string, byAnspRef bool) (RestrictionRecord, error) {
	q := relational.New(s.pool)
	var rec *RestrictionRecord
	var err error
	if byAnspRef {
		rec, err = findHead(ctx, q, "", ref)
	} else {
		rec, err = findHead(ctx, q, ref, "")
	}
	if err != nil {
		return RestrictionRecord{}, err
	}
	if rec == nil {
		return RestrictionRecord{}, ErrNotFound
	}
	list := []RestrictionRecord{*rec}
	if err := withEvents(ctx, q, list); err != nil {
		return RestrictionRecord{}, err
	}
	return list[0], nil
}

// RestrictionByFeatureID is the head that holds the identifier;
// ErrNotFound when none does.
func (s *Store) RestrictionByFeatureID(ctx context.Context, featureID string) (RestrictionRecord, error) {
	r, err := relational.New(s.pool).GetRestrictionByFeatureID(ctx, featureID)
	if errors.Is(err, pgx.ErrNoRows) {
		return RestrictionRecord{}, ErrNotFound
	}
	if err != nil {
		return RestrictionRecord{}, fmt.Errorf("restriction by identifier: %w", err)
	}
	return recordOf(relational.GetRestrictionByIDRow(r)), nil
}

// RestrictionFilter selects heads; nil members do not filter.
type RestrictionFilter struct {
	State    *restriction.State
	Airspace *string
	// At keeps the heads whose window [starts_at, ends_at) holds it.
	At    *time.Time
	Limit int
}

// Restrictions are the heads the filter selects, newest window first,
// each with its events.
func (s *Store) Restrictions(ctx context.Context, f RestrictionFilter) ([]RestrictionRecord, error) {
	q := relational.New(s.pool)
	p := relational.ListRestrictionsParams{Airspace: f.Airspace, MaxRows: int32(min(max(f.Limit, 0), 1<<20))}
	if f.State != nil {
		st := string(*f.State)
		p.State = &st
	}
	if f.At != nil {
		at := f.At.UTC()
		p.At = &at
	}
	rows, err := q.ListRestrictions(ctx, p)
	if err != nil {
		return nil, fmt.Errorf("restrictions: %w", err)
	}
	out := make([]RestrictionRecord, 0, len(rows))
	for i := range rows {
		out = append(out, recordOf(relational.GetRestrictionByIDRow(rows[i])))
	}
	if err := withEvents(ctx, q, out); err != nil {
		return nil, err
	}
	return out, nil
}

// withEvents fills the events of every record with one query.
func withEvents(ctx context.Context, q *relational.Queries, recs []RestrictionRecord) error {
	if len(recs) == 0 {
		return nil
	}
	ids := make([]string, 0, len(recs))
	at := make(map[string]int, len(recs))
	for i := range recs {
		ids = append(ids, recs[i].ID)
		at[recs[i].ID] = i
		recs[i].Events = []RestrictionEvent{}
	}
	rows, err := q.ListRestrictionEvents(ctx, ids)
	if err != nil {
		return fmt.Errorf("restriction events: %w", err)
	}
	for _, r := range rows {
		i, ok := at[r.RestrictionID]
		if !ok {
			continue
		}
		recs[i].Events = append(recs[i].Events, RestrictionEvent{
			At: r.At.UTC(), Op: restriction.Op(r.Op), AnspVersion: int64(r.AnspVersion), PublicationID: r.PublicationID, Actor: r.Actor,
		})
	}
	return nil
}

// ExpiredRestrictions are the ids of the active heads whose ends_at is
// not after now, at most limit, soonest first.
func (s *Store) ExpiredRestrictions(ctx context.Context, now time.Time, limit int) ([]string, error) {
	ids, err := relational.New(s.pool).ListExpiredRestrictions(ctx, relational.ListExpiredRestrictionsParams{
		Now: now.UTC(), MaxRows: int32(min(max(limit, 0), 1<<20)),
	})
	if err != nil {
		return nil, fmt.Errorf("expired restrictions: %w", err)
	}
	return ids, nil
}

// ActiveRestrictionRefs are the ansp_refs of the active heads, sorted.
func (s *Store) ActiveRestrictionRefs(ctx context.Context) ([]string, error) {
	refs, err := relational.New(s.pool).ListActiveRestrictionRefs(ctx)
	if err != nil {
		return nil, fmt.Errorf("active restriction refs: %w", err)
	}
	return refs, nil
}

// CountActiveRestrictions is the number of active heads.
func (s *Store) CountActiveRestrictions(ctx context.Context) (int64, error) {
	n, err := relational.New(s.pool).CountActiveRestrictions(ctx)
	if err != nil {
		return 0, fmt.Errorf("active restrictions: %w", err)
	}
	return n, nil
}

// PublisherRefs is a publisher's heartbeat as stored with its declared
// active references.
type PublisherRefs struct {
	ClientID        string
	Kind            string
	LastHeartbeatAt *time.Time
	StaleAfterS     int
	// ActiveRefs is nil when the last heartbeat declared none.
	ActiveRefs []string
}

// PublishersRefs is every publisher with its declared active references.
func (s *Store) PublishersRefs(ctx context.Context) ([]PublisherRefs, error) {
	rows, err := relational.New(s.pool).ListPublisherRefs(ctx)
	if err != nil {
		return nil, fmt.Errorf("publishers: %w", err)
	}
	out := make([]PublisherRefs, 0, len(rows))
	for i := range rows {
		r := &rows[i]
		p := PublisherRefs{ClientID: r.ClientID, Kind: r.Kind, LastHeartbeatAt: r.LastHeartbeatAt, StaleAfterS: int(r.StaleAfterS)}
		if len(r.ActiveRefs) > 0 && string(r.ActiveRefs) != "null" {
			if err := json.Unmarshal(r.ActiveRefs, &p.ActiveRefs); err != nil {
				return nil, fmt.Errorf("publisher %s active_refs: %w", r.ClientID, err)
			}
		}
		out = append(out, p)
	}
	return out, nil
}

// JobRun is the last run of a leader-elected job.
type JobRun struct {
	Name     string
	RanAt    time.Time
	Instance string
	Count    int
}

// LastJobRun is the job's last run; ErrNotFound before the first.
func (s *Store) LastJobRun(ctx context.Context, name string) (JobRun, error) {
	r, err := relational.New(s.pool).GetJobRun(ctx, name)
	if errors.Is(err, pgx.ErrNoRows) {
		return JobRun{}, ErrNotFound
	}
	if err != nil {
		return JobRun{}, fmt.Errorf("job run %s: %w", name, err)
	}
	return JobRun{Name: r.Name, RanAt: r.LastRunAt.UTC(), Instance: r.LastInstance, Count: int(r.LastCount)}, nil
}

// RunJob runs fn as the one leader of the job name for this run: it
// takes the job's transaction-scoped advisory lock without waiting (a
// replica that does not get it skips the run, ran false) and, when fn
// succeeds, records the run in job_runs with fn's count. The lock is held
// until the record commits, so two replicas never run the job at once.
// fn does its own writes in its own transactions.
func (s *Store) RunJob(ctx context.Context, name, instance string, now time.Time, fn func(ctx context.Context) (int, error)) (bool, error) {
	ran := false
	err := s.tx(ctx, func(_ pgx.Tx, q *relational.Queries) error {
		locked, err := q.TryJobLock(ctx, name)
		if err != nil {
			return fmt.Errorf("job lock %s: %w", name, err)
		}
		if !locked {
			return nil
		}
		n, err := fn(ctx)
		if err != nil {
			return err
		}
		ran = true
		return q.RecordJobRun(ctx, relational.RecordJobRunParams{
			Name: name, RanAt: now.UTC(), Instance: instance, Count: int32(min(max(n, 0), 1<<30)),
		})
	})
	if err != nil {
		return false, err
	}
	return ran, nil
}

// restrictionPlacement measures a restriction's outline: its area on
// geography, whether the named U-space airspace is a current feature,
// and whether the outline intersects that feature's stored shape. The
// outline is built in SQL from the published parts (a circle as
// ST_Buffer of its centre and radius on geography, LESSONS Z-11), as the
// publication transaction builds every stored shape.
const restrictionPlacement = `WITH parts AS (
    SELECT ST_SetSRID(ST_GeomFromGeoJSON(p), 4326) AS g FROM unnest($1::text[]) AS p
    UNION ALL
    SELECT ST_Buffer(ST_SetSRID(ST_MakePoint(c.lng, c.lat), 4326)::geography, c.r)::geometry
    FROM unnest($2::float8[], $3::float8[], $4::float8[]) AS c(lng, lat, r)
), shape AS (
    SELECT ST_Union(g) AS geom FROM parts
), airspace AS (
    SELECT geom FROM features_current WHERE dataset = 'uspace_airspace' AND feature_id = $5
)
SELECT COALESCE(ST_Area(shape.geom::geography), 0)::float8 AS area_m2,
       EXISTS (SELECT 1 FROM airspace) AS airspace_current,
       COALESCE((SELECT bool_or(ST_Intersects(a.geom, shape.geom)) FROM airspace a), false) AS intersects
FROM shape`

// Placement is a restriction outline's area and its relation to the
// U-space airspace it names (dataset.CheckPlacement judges the numbers).
type Placement struct {
	AreaM2          float64
	AirspaceCurrent bool
	Intersects      bool
}

// RestrictionPlacement measures the outline parts against the current
// uspace_airspace feature uspaceID.
func (s *Store) RestrictionPlacement(ctx context.Context, uspaceID string, parts []publication.GeomPart) (Placement, error) {
	var polygons []string
	var lngs, lats, radii []float64
	for _, p := range parts {
		if p.Circle() {
			lngs, lats, radii = append(lngs, p.Center.LonDeg), append(lats, p.Center.LatDeg), append(radii, *p.RadiusM)
			continue
		}
		polygons = append(polygons, polygonGeoJSON(p.Rings))
	}
	if len(polygons)+len(lngs) == 0 {
		return Placement{}, core.Fieldf("feature.geometry", "has no part to place")
	}
	var out Placement
	err := s.pool.QueryRow(ctx, restrictionPlacement, nonNil(polygons), nonNilF(lngs), nonNilF(lats), nonNilF(radii), uspaceID).
		Scan(&out.AreaM2, &out.AirspaceCurrent, &out.Intersects)
	if err != nil {
		return Placement{}, fmt.Errorf("restriction placement: %w", err)
	}
	return out, nil
}

func nonNilF(s []float64) []float64 {
	if s == nil {
		return []float64{}
	}
	return s
}

// NewID is a ULID for a row the caller names before writing it (a
// restriction head).
func NewID(t time.Time) string { return newID(t) }
