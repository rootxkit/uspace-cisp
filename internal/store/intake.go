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

	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/store/relational"
)

// The outcomes of a publication attempt.
const (
	OutcomeAccepted = "accepted"
	OutcomeRefused  = "refused"
)

// crossDatasetIndex is the unique index of D8 (migration 0002).
const crossDatasetIndex = "features_current_cross_dataset_uq"

// ErrNotFound is returned for a row that does not exist.
var ErrNotFound = errors.New("store: not found")

// IsIdentifierConflict reports whether err is the D8 backstop: the
// unique index on features_current refused an identifier another
// dataset's current version holds (a publication that raced the
// Reserved lookup).
func IsIdentifierConflict(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "23505" && pg.ConstraintName == crossDatasetIndex
}

// Unavailable reports whether err means the database could not be asked
// (no connection, a closed pool, a network failure), as opposed to a
// refusal by the database itself or by the store's own checks: the
// write answers 503 and the publisher retries (docs/PLAN.md section 2).
func Unavailable(err error) bool {
	if err == nil {
		return false
	}
	var pg *pgconn.PgError
	var fe *core.FieldError
	switch {
	case errors.As(err, &pg), errors.As(err, &fe),
		errors.Is(err, ErrUnchanged), errors.Is(err, ErrVersionMismatch),
		errors.Is(err, ErrNoopSigner), errors.Is(err, ErrNotFound):
		return false
	}
	return true
}

// CurrentVersion is the dataset's current version (0 before the first).
func (s *Store) CurrentVersion(ctx context.Context, ds publication.Dataset) (int64, error) {
	d, err := relational.New(s.pool).GetDataset(ctx, string(ds))
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("dataset %s: %w", ds, err)
	}
	return d.CurrentVersion, nil
}

// Reserved is, of ids, those the current version of another dataset of
// zones, uspace_airspace and restrictions holds, with that dataset (D8).
func (s *Store) Reserved(ctx context.Context, ds publication.Dataset, ids []string) (map[string]publication.Dataset, error) {
	out := map[string]publication.Dataset{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := relational.New(s.pool).ReservedFeatureIDs(ctx, relational.ReservedFeatureIDsParams{Dataset: string(ds), Ids: ids})
	if err != nil {
		return nil, fmt.Errorf("reserved identifiers: %w", err)
	}
	for _, r := range rows {
		out[r.FeatureID] = publication.Dataset(r.Dataset)
	}
	return out, nil
}

// AttemptProblem is one problem of a refused attempt.
type AttemptProblem struct {
	Field  string `json:"field"`
	Reason string `json:"reason"`
}

// Attempt is one publication attempt (Annex III A(5)).
type Attempt struct {
	ID                string
	Dataset           publication.Dataset
	PublisherClientID string
	ReceivedAt        time.Time
	Outcome           string
	// PublicationID is set for an accepted attempt only.
	PublicationID *string
	// Problems are the listed problems (at most 100) of a refusal and
	// Truncated how many more were found.
	Problems  []AttemptProblem
	Truncated int
	// BodySHA256 is the hash of the body received; nil when none was read.
	BodySHA256 []byte
	Bytes      int64
}

// storedProblems is the problems column of a refused attempt.
type storedProblems struct {
	Errors    []AttemptProblem `json:"errors"`
	Truncated int              `json:"truncated"`
}

// InsertAttempt records an attempt (insert-only) and returns its id.
func (s *Store) InsertAttempt(ctx context.Context, a Attempt) (string, error) {
	if a.Outcome != OutcomeAccepted && a.Outcome != OutcomeRefused {
		return "", core.Fieldf("outcome", "%q is neither accepted nor refused", a.Outcome)
	}
	if (a.Outcome == OutcomeAccepted) != (a.PublicationID != nil) {
		return "", core.Fieldf("publication_id", "is set exactly for an accepted attempt")
	}
	problems := []byte("[]")
	if a.Outcome == OutcomeRefused {
		list := a.Problems
		if list == nil {
			list = []AttemptProblem{}
		}
		raw, err := json.Marshal(storedProblems{Errors: list, Truncated: a.Truncated})
		if err != nil {
			return "", fmt.Errorf("attempt problems: %w", err)
		}
		problems = raw
	}
	at := a.ReceivedAt.UTC().Truncate(time.Microsecond)
	if a.ReceivedAt.IsZero() {
		at = s.opts.Now().UTC().Truncate(time.Microsecond)
	}
	id := newID(at)
	err := relational.New(s.pool).InsertPublicationAttempt(ctx, relational.InsertPublicationAttemptParams{
		ID: id, Dataset: string(a.Dataset), PublisherClientID: a.PublisherClientID, ReceivedAt: at,
		Outcome: a.Outcome, PublicationID: a.PublicationID, Problems: problems,
		BodySha256: a.BodySHA256, Bytes: a.Bytes,
	})
	if err != nil {
		return "", fmt.Errorf("insert attempt: %w", err)
	}
	return id, nil
}

// RefusedAttempts are the publisher's refused attempts on ds received
// after since, newest first, at most limit.
func (s *Store) RefusedAttempts(ctx context.Context, ds publication.Dataset, publisher string, since time.Time, limit int) ([]Attempt, error) {
	rows, err := relational.New(s.pool).ListRefusedAttempts(ctx, relational.ListRefusedAttemptsParams{
		PublisherClientID: publisher, Dataset: string(ds), Since: since, MaxRows: int32(limit),
	})
	if err != nil {
		return nil, fmt.Errorf("attempts: %w", err)
	}
	out := make([]Attempt, 0, len(rows))
	for _, r := range rows {
		a := Attempt{
			ID: r.ID, Dataset: publication.Dataset(r.Dataset), PublisherClientID: r.PublisherClientID,
			ReceivedAt: r.ReceivedAt, Outcome: r.Outcome, PublicationID: r.PublicationID,
			BodySHA256: r.BodySha256, Bytes: r.Bytes,
		}
		var sp storedProblems
		if err := json.Unmarshal(r.Problems, &sp); err == nil {
			a.Problems, a.Truncated = sp.Errors, sp.Truncated
		} else if err := json.Unmarshal(r.Problems, &a.Problems); err != nil {
			return nil, fmt.Errorf("attempt %s problems: %w", r.ID, err)
		}
		out = append(out, a)
	}
	return out, nil
}

// Version is one entry of a dataset's history, without the body.
type Version struct {
	ID                string
	Dataset           publication.Dataset
	Version           int64
	PublisherClientID string
	ReceivedAt        time.Time
	BodySHA256        []byte
	Bytes             int64
	ContentType       string
	SignatureKID      *string
	FeatureCount      int
	Added             int
	Changed           int
	Removed           int
	SupersedesVersion *int64
	// Warnings is the stored JSON array of the version's warnings.
	Warnings json.RawMessage
	Reason   publication.Reason
}

// Versions are the versions of ds below before (all when before is 0),
// newest first, at most limit.
func (s *Store) Versions(ctx context.Context, ds publication.Dataset, before int64, limit int) ([]Version, error) {
	if before <= 0 {
		before = 1<<63 - 1
	}
	rows, err := relational.New(s.pool).ListPublicationVersions(ctx, relational.ListPublicationVersionsParams{
		Dataset: string(ds), BeforeVersion: before, MaxRows: int32(limit),
	})
	if err != nil {
		return nil, fmt.Errorf("versions: %w", err)
	}
	out := make([]Version, 0, len(rows))
	for _, r := range rows {
		out = append(out, Version{
			ID: r.ID, Dataset: publication.Dataset(r.Dataset), Version: r.Version,
			PublisherClientID: r.PublisherClientID, ReceivedAt: r.ReceivedAt, BodySHA256: r.BodySha256,
			Bytes: r.Bytes, ContentType: r.ContentType, SignatureKID: r.SignatureKid,
			FeatureCount: int(r.FeatureCount), Added: int(r.Added), Changed: int(r.Changed), Removed: int(r.Removed),
			SupersedesVersion: r.SupersedesVersion, Warnings: r.Warnings, Reason: publication.Reason(r.Reason),
		})
	}
	return out, nil
}

// Heartbeat is one publisher heartbeat.
type Heartbeat struct {
	ClientID string
	// Kind is authority or ansp.
	Kind string
	// ReceivedAt is the CISP's clock; staleness is judged on it.
	ReceivedAt time.Time
	// SentAt is the publisher's sent_at as declared.
	SentAt time.Time
	// ActiveRefs are stored verbatim; nil stores null.
	ActiveRefs []string
}

// RecordHeartbeat upserts the publisher's heartbeat.
func (s *Store) RecordHeartbeat(ctx context.Context, h Heartbeat) error {
	var refs []byte
	if h.ActiveRefs != nil {
		raw, err := json.Marshal(h.ActiveRefs)
		if err != nil {
			return fmt.Errorf("active_refs: %w", err)
		}
		refs = raw
	}
	received, sent := h.ReceivedAt.UTC(), h.SentAt.UTC()
	if err := relational.New(s.pool).UpsertPublisherHeartbeat(ctx, relational.UpsertPublisherHeartbeatParams{
		ClientID: h.ClientID, Kind: h.Kind, ReceivedAt: &received, SentAt: &sent, ActiveRefs: refs,
	}); err != nil {
		return fmt.Errorf("heartbeat: %w", err)
	}
	return nil
}

// PublisherState is a publisher's row.
type PublisherState struct {
	ClientID            string
	Kind                string
	LastHeartbeatAt     *time.Time
	LastHeartbeatSentAt *time.Time
	// ActiveRefs is nil when the publisher declared none.
	ActiveRefs []string
	StaleAfterS int
}

// Publisher is the row of clientID, or ErrNotFound.
func (s *Store) Publisher(ctx context.Context, clientID string) (PublisherState, error) {
	p, err := relational.New(s.pool).GetPublisher(ctx, clientID)
	if errors.Is(err, pgx.ErrNoRows) {
		return PublisherState{}, ErrNotFound
	}
	if err != nil {
		return PublisherState{}, fmt.Errorf("publisher: %w", err)
	}
	out := PublisherState{
		ClientID: p.ClientID, Kind: p.Kind, LastHeartbeatAt: p.LastHeartbeatAt,
		LastHeartbeatSentAt: p.LastHeartbeatSentAt, StaleAfterS: int(p.StaleAfterS),
	}
	if len(p.ActiveRefs) > 0 && string(p.ActiveRefs) != "null" {
		if err := json.Unmarshal(p.ActiveRefs, &out.ActiveRefs); err != nil {
			return PublisherState{}, fmt.Errorf("publisher active_refs: %w", err)
		}
	}
	return out, nil
}
