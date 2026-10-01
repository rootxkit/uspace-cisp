package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"

	"github.com/rootxkit/uspace-cisp/migrations"
)

// Tree is one of the two migration trees (docs/PLAN.md D11). They are
// never merged: each has its own database and its own version table.
type Tree string

// The trees.
const (
	TreeRelational Tree = "relational"
	TreeTimeseries Tree = "timeseries"
)

// ParseTree reads a tree name; it fails for anything but relational and
// timeseries.
func ParseTree(s string) (Tree, error) {
	switch Tree(s) {
	case TreeRelational, TreeTimeseries:
		return Tree(s), nil
	}
	return "", fmt.Errorf("unknown migration tree %q: relational or timeseries", s)
}

// VersionTable is the goose version table of the tree.
func (t Tree) VersionTable() string { return "goose_db_version_" + string(t) }

func (t Tree) other() Tree {
	if t == TreeRelational {
		return TreeTimeseries
	}
	return TreeRelational
}

func (t Tree) files() (fs.FS, error) {
	switch t {
	case TreeRelational:
		return fs.Sub(migrations.Relational, string(t))
	case TreeTimeseries:
		return fs.Sub(migrations.Timeseries, string(t))
	}
	return nil, fmt.Errorf("unknown migration tree %q", t)
}

// ErrWrongDatabase is returned when a tree is run against the database of
// the other tree (its version table is there).
var ErrWrongDatabase = errors.New("this database holds the other migration tree")

// OpenSQL is a database/sql handle on the pool, for goose. Closing it
// does not close the pool.
func OpenSQL(pool *pgxpool.Pool) *sql.DB { return stdlib.OpenDBFromPool(pool) }

// MigrationStatus is one migration file and whether it is applied.
type MigrationStatus struct {
	Version   int64
	File      string
	Applied   bool
	AppliedAt time.Time
}

// MigrationResult is one migration applied or rolled back.
type MigrationResult struct {
	Version  int64
	File     string
	Duration time.Duration
}

func provider(ctx context.Context, db *sql.DB, tree Tree) (*goose.Provider, error) {
	var foreign bool
	if err := db.QueryRowContext(ctx, "SELECT to_regclass($1) IS NOT NULL", tree.other().VersionTable()).Scan(&foreign); err != nil {
		return nil, fmt.Errorf("migrate %s: %w", tree, err)
	}
	if foreign {
		return nil, fmt.Errorf("migrate %s: %w (%s exists)", tree, ErrWrongDatabase, tree.other().VersionTable())
	}
	fsys, err := tree.files()
	if err != nil {
		return nil, err
	}
	locker, err := lock.NewPostgresSessionLocker()
	if err != nil {
		return nil, fmt.Errorf("migrate %s: %w", tree, err)
	}
	p, err := goose.NewProvider(goose.DialectPostgres, db, fsys,
		goose.WithTableName(tree.VersionTable()),
		goose.WithDisableGlobalRegistry(true),
		goose.WithSessionLocker(locker),
	)
	if err != nil {
		return nil, fmt.Errorf("migrate %s: %w", tree, err)
	}
	return p, nil
}

func results(rs []*goose.MigrationResult) []MigrationResult {
	out := make([]MigrationResult, 0, len(rs))
	for _, r := range rs {
		out = append(out, MigrationResult{Version: r.Source.Version, File: path.Base(r.Source.Path), Duration: r.Duration})
	}
	return out
}

// Up applies every pending migration of the tree and returns what it
// applied (empty when nothing was pending).
func Up(ctx context.Context, db *sql.DB, tree Tree) ([]MigrationResult, error) {
	p, err := provider(ctx, db, tree)
	if err != nil {
		return nil, err
	}
	rs, err := p.Up(ctx)
	if err != nil {
		return results(rs), fmt.Errorf("migrate %s up: %w", tree, err)
	}
	return results(rs), nil
}

// DownTo rolls the tree back to version (0 is empty) and returns what it
// rolled back, newest first.
func DownTo(ctx context.Context, db *sql.DB, tree Tree, version int64) ([]MigrationResult, error) {
	if version < 0 {
		return nil, fmt.Errorf("migrate %s down: version %d is negative", tree, version)
	}
	p, err := provider(ctx, db, tree)
	if err != nil {
		return nil, err
	}
	rs, err := p.DownTo(ctx, version)
	if err != nil {
		return results(rs), fmt.Errorf("migrate %s down to %d: %w", tree, version, err)
	}
	return results(rs), nil
}

// Status lists every migration file of the tree and whether it is
// applied, oldest first.
func Status(ctx context.Context, db *sql.DB, tree Tree) ([]MigrationStatus, error) {
	p, err := provider(ctx, db, tree)
	if err != nil {
		return nil, err
	}
	st, err := p.Status(ctx)
	if err != nil {
		return nil, fmt.Errorf("migrate %s status: %w", tree, err)
	}
	out := make([]MigrationStatus, 0, len(st))
	for _, s := range st {
		out = append(out, MigrationStatus{
			Version:   s.Source.Version,
			File:      path.Base(s.Source.Path),
			Applied:   s.State == goose.StateApplied,
			AppliedAt: s.AppliedAt,
		})
	}
	return out, nil
}

// Pending is the files of the tree not yet applied, oldest first. api
// and deliver refuse to start while it is not empty; they never migrate
// on their own (docs/PLAN.md section 5.3).
func Pending(ctx context.Context, db *sql.DB, tree Tree) ([]string, error) {
	st, err := Status(ctx, db, tree)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, s := range st {
		if !s.Applied {
			out = append(out, s.File)
		}
	}
	return out, nil
}
