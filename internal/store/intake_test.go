package store

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/rootxkit/uspace-core/core"
)

// The D8 backstop is recognised by its index, and only by it.
func TestIsIdentifierConflict(t *testing.T) {
	hit := fmt.Errorf("fill features_current: %w", &pgconn.PgError{Code: "23505", ConstraintName: crossDatasetIndex})
	if !IsIdentifierConflict(hit) {
		t.Error("the cross-dataset unique violation was not recognised")
	}
	for _, miss := range []error{
		&pgconn.PgError{Code: "23505", ConstraintName: "features_current_dataset_feature_id_key"},
		&pgconn.PgError{Code: "23503", ConstraintName: crossDatasetIndex},
		errors.New("23505 " + crossDatasetIndex),
		nil,
	} {
		if IsIdentifierConflict(miss) {
			t.Errorf("%v recognised as the D8 conflict", miss)
		}
	}
}

// Unavailable is true for an error that is not the database's or the
// store's own answer, false for those.
func TestUnavailable(t *testing.T) {
	for _, down := range []error{
		errors.New("dial tcp 127.0.0.1:5432: connect: connection refused"),
		fmt.Errorf("begin: %w", &pgconn.ConnectError{}),
		context.Canceled,
	} {
		if !Unavailable(down) {
			t.Errorf("%v: not unavailable", down)
		}
	}
	for _, answered := range []error{
		nil,
		&pgconn.PgError{Code: "23505"},
		fmt.Errorf("x: %w", ErrUnchanged),
		ErrVersionMismatch,
		ErrNoopSigner,
		ErrNotFound,
		core.Fieldf("body", "is empty"),
	} {
		if Unavailable(answered) {
			t.Errorf("%v: unavailable", answered)
		}
	}
}

// InsertAttempt refuses an attempt whose outcome and publication id
// disagree, before the database is asked.
func TestInsertAttemptRefusesInconsistentRows(t *testing.T) {
	s := New(nil, Options{})
	id := "01J"
	for name, a := range map[string]Attempt{
		"unknown outcome":            {Outcome: "maybe"},
		"accepted without its id":    {Outcome: OutcomeAccepted},
		"refused with a publication": {Outcome: OutcomeRefused, PublicationID: &id},
	} {
		if _, err := s.InsertAttempt(context.Background(), a); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
