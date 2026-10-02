package console

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rootxkit/uspace-cisp/internal/store"
)

// ChainBreakError is the first audit row whose chain does not hold (spec 06
// T7): its prev_hash is not the previous row's hash (a row before it was
// removed or altered), or its own hash is not the hash of its fields (it
// was altered).
type ChainBreakError struct {
	ID     int64
	Reason string
}

func (b *ChainBreakError) Error() string {
	return fmt.Sprintf("events row %d breaks the hash chain: %s", b.ID, b.Reason)
}

// CheckRow verifies one row against the hash of the row before it in the
// chain (nil for the chain's first row).
func CheckRow(prev []byte, r store.AuditRow) error {
	if !bytes.Equal(r.PrevHash, prev) {
		return &ChainBreakError{ID: r.ID, Reason: fmt.Sprintf("prev_hash %s is not the previous row's hash %s", short(r.PrevHash), short(prev))}
	}
	want, err := store.EventHash(r.PrevHash, r.TS, r.ActorType, r.ActorID, r.EventType, r.EntityType, r.EntityID, r.Payload)
	if err != nil {
		return &ChainBreakError{ID: r.ID, Reason: "its fields cannot be hashed: " + err.Error()}
	}
	if !bytes.Equal(want, r.Hash) {
		return &ChainBreakError{ID: r.ID, Reason: fmt.Sprintf("hash %s is not the hash of its fields %s (the row was altered)", short(r.Hash), short(want))}
	}
	return nil
}

func short(b []byte) string {
	if len(b) == 0 {
		return "(none)"
	}
	s := hex.EncodeToString(b)
	if len(s) > 16 {
		s = s[:16] + "..."
	}
	return s
}

// ExportRow is one line of cispctl export-audit: the events row with
// its chain hashes in hex.
type ExportRow struct {
	ID         int64           `json:"id"`
	TS         time.Time       `json:"ts"`
	ActorType  string          `json:"actor_type"`
	ActorID    string          `json:"actor_id"`
	EventType  string          `json:"event_type"`
	EntityType string          `json:"entity_type"`
	EntityID   string          `json:"entity_id"`
	Payload    json.RawMessage `json:"payload"`
	PrevHash   string          `json:"prev_hash,omitempty"`
	Hash       string          `json:"hash"`
}

// ExportLine is r as one newline-terminated JSON line.
func ExportLine(r store.AuditRow) ([]byte, error) {
	payload := r.Payload
	if len(payload) == 0 {
		payload = json.RawMessage("{}")
	}
	b, err := json.Marshal(ExportRow{
		ID: r.ID, TS: r.TS.UTC(), ActorType: r.ActorType, ActorID: r.ActorID, EventType: r.EventType,
		EntityType: r.EntityType, EntityID: r.EntityID, Payload: payload,
		PrevHash: hex.EncodeToString(r.PrevHash), Hash: hex.EncodeToString(r.Hash),
	})
	if err != nil {
		return nil, fmt.Errorf("events row %d: %w", r.ID, err)
	}
	return append(b, '\n'), nil
}
