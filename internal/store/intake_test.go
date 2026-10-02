package store

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
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

// Unavailable is true for connectivity failures only; everything else,
// a database refusal included, is a fault (500), not a retry (503).
func TestUnavailable(t *testing.T) {
	for _, down := range []error{
		fmt.Errorf("begin: %w", &pgconn.ConnectError{}),
		fmt.Errorf("query: %w", &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}),
		fmt.Errorf("query: %w", io.ErrUnexpectedEOF),
		io.EOF,
	} {
		if !Unavailable(down) {
			t.Errorf("%v: not unavailable", down)
		}
	}
	for _, fault := range []error{
		nil,
		&pgconn.PgError{Code: "23505"},
		fmt.Errorf("insert: %w", &pgconn.PgError{Code: "42P01"}),
		errors.New("closed pool"),
		errors.New("ERROR: something unexpected"),
		fmt.Errorf("x: %w", ErrUnchanged),
		ErrVersionMismatch,
		ErrNotFound,
		context.Canceled,
		fmt.Errorf("q: %w", context.DeadlineExceeded),
		core.Fieldf("body", "is empty"),
	} {
		if Unavailable(fault) {
			t.Errorf("%v: unavailable", fault)
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
