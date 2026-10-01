package store

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/store/relational"
)

// Actor types of the events table.
const (
	ActorClient  = "client"
	ActorAccount = "account"
	ActorSystem  = "system"
)

// Event is one audit row before it is chained.
type Event struct {
	TS         time.Time
	ActorType  string
	ActorID    string
	EventType  string
	EntityType string
	EntityID   string
	Payload    map[string]any
}

// EventHash is the hash of an audit row: SHA-256 over the previous row's
// hash (nothing for the first row) followed by the canonical JSON of the
// row's fields (ts in RFC 3339 with microseconds, UTC). Anyone holding
// the table can recompute the chain.
func EventHash(prev []byte, ts time.Time, actorType, actorID, eventType, entityType, entityID string, payload []byte) ([]byte, error) {
	doc := map[string]any{
		"ts":          ts.UTC().Format("2006-01-02T15:04:05.000000Z07:00"),
		"actor_type":  actorType,
		"actor_id":    actorID,
		"event_type":  eventType,
		"entity_type": entityType,
		"entity_id":   entityID,
		"payload":     json.RawMessage(payload),
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("event hash: %w", err)
	}
	canonical, err := publication.Canonical(raw)
	if err != nil {
		return nil, fmt.Errorf("event hash: %w", err)
	}
	h := sha256.New()
	h.Write(prev)
	h.Write(canonical)
	return h.Sum(nil), nil
}

// AppendEvent writes one audit row chained to the previous one, inside
// the caller's transaction, and returns its id.
func AppendEvent(ctx context.Context, q *relational.Queries, e Event) (int64, error) {
	if err := q.LockEventChain(ctx); err != nil {
		return 0, fmt.Errorf("event chain lock: %w", err)
	}
	prev, err := q.LastEventHash(ctx)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return 0, fmt.Errorf("last event: %w", err)
	}
	payload := []byte("{}")
	if e.Payload != nil {
		if payload, err = json.Marshal(e.Payload); err != nil {
			return 0, fmt.Errorf("event payload: %w", err)
		}
		if payload, err = publication.Canonical(payload); err != nil {
			return 0, fmt.Errorf("event payload: %w", err)
		}
	}
	ts := e.TS.UTC().Truncate(time.Microsecond) // PostgreSQL's precision
	hash, err := EventHash(prev, ts, e.ActorType, e.ActorID, e.EventType, e.EntityType, e.EntityID, payload)
	if err != nil {
		return 0, err
	}
	id, err := q.InsertEvent(ctx, relational.InsertEventParams{
		Ts: ts, ActorType: e.ActorType, ActorID: e.ActorID, EventType: e.EventType,
		EntityType: e.EntityType, EntityID: e.EntityID, Payload: payload, PrevHash: prev, Hash: hash,
	})
	if err != nil {
		return 0, fmt.Errorf("insert event: %w", err)
	}
	return id, nil
}
