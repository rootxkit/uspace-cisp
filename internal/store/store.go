package store

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/store/relational"
)

// Pool defaults (docs/PLAN.md section 11; the sizes are configuration:
// CISP_DATABASE_MAX_CONNS and CISP_TIMESERIES_MAX_CONNS).
const (
	DefaultRelationalMaxConns = 8
	DefaultTimeseriesMaxConns = 2
	DefaultStatementTimeout   = 10 * time.Second
)

// PoolConfig is one database pool.
type PoolConfig struct {
	// URL is the postgres:// URL (CISP_DATABASE_URL or CISP_TIMESERIES_URL).
	URL string
	// ApplicationName is set per process ("uspace-cisp-api", ...).
	ApplicationName string
	// MaxConns bounds the pool; 0 takes DefaultRelationalMaxConns.
	MaxConns int32
	// StatementTimeout is the server-side statement_timeout; 0 takes
	// DefaultStatementTimeout.
	StatementTimeout time.Duration
}

// OpenPool builds a pool with application_name and statement_timeout
// set on every connection. It does not connect: an unreachable database
// is an error at first use, never a hang at start.
func OpenPool(ctx context.Context, cfg PoolConfig) (*pgxpool.Pool, error) {
	pc, err := pgxpool.ParseConfig(cfg.URL)
	if err != nil {
		// The error may repeat the URL with its password; it is not wrapped.
		return nil, errors.New("database URL does not parse")
	}
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = DefaultRelationalMaxConns
	}
	if cfg.StatementTimeout <= 0 {
		cfg.StatementTimeout = DefaultStatementTimeout
	}
	pc.MaxConns = cfg.MaxConns
	if cfg.ApplicationName != "" {
		pc.ConnConfig.RuntimeParams["application_name"] = cfg.ApplicationName
	}
	pc.ConnConfig.RuntimeParams["statement_timeout"] = strconv.FormatInt(cfg.StatementTimeout.Milliseconds(), 10)
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		return nil, fmt.Errorf("database pool: %w", err)
	}
	return pool, nil
}

// ChangePublisher sends a committed change record to the bus
// (internal/bus implements it).
type ChangePublisher interface {
	Publish(ctx context.Context, c publication.Change) error
}

// Options configure a Store.
type Options struct {
	// Bus receives every committed change; nil leaves the change to
	// deliver's reconciliation scan (D6), counted as bus_publish_skipped.
	Bus ChangePublisher
	// Counters receive bus_publish_failed, bus_publish_skipped and
	// change_bbox_unavailable; nil makes a private set (see Counters).
	Counters *core.Counters
	// Logger records a bus publish failure; nil discards.
	Logger *slog.Logger
	// Now is the clock; nil is time.Now.
	Now func() time.Time
	// AllowNoopSigner lets PublishTx sign snapshots with NoopSigner. Only
	// tests set it; the production configuration never does.
	AllowNoopSigner bool
}

// Store is the relational database adapter: the publication
// transaction, the reads behind the snapshot cache, and Tx for the
// queries later work packages add.
type Store struct {
	pool *pgxpool.Pool
	opts Options

	// failAfter, when set (tests only), is called after each numbered
	// step of PublishTx; an error aborts the transaction there.
	failAfter func(step int) error
}

// New is a Store on pool.
func New(pool *pgxpool.Pool, opts Options) *Store {
	if opts.Counters == nil {
		opts.Counters = &core.Counters{}
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Store{pool: pool, opts: opts}
}

// Pool is the store's pool.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Counters are the store's counters.
func (s *Store) Counters() *core.Counters { return s.opts.Counters }

// Tx runs fn in one transaction: committed when fn returns nil, rolled
// back otherwise (and when ctx ends).
func (s *Store) Tx(ctx context.Context, fn func(q *relational.Queries) error) error {
	return s.tx(ctx, func(_ pgx.Tx, q *relational.Queries) error { return fn(q) })
}

func (s *Store) tx(ctx context.Context, fn func(tx pgx.Tx, q *relational.Queries) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	if err := fn(tx, relational.New(tx)); err != nil {
		_ = tx.Rollback(context.WithoutCancel(ctx))
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// newID is a ULID (26 characters of Crockford base32: 48 bits of
// milliseconds, 80 random bits), sortable by time.
func newID(t time.Time) string {
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	var b [16]byte
	ms := uint64(t.UnixMilli())
	for i := 5; i >= 0; i-- {
		b[i] = byte(ms)
		ms >>= 8
	}
	_, _ = rand.Read(b[6:]) // crypto/rand.Read never fails (Go 1.24+)
	var out [26]byte
	// 128 bits into 26 groups of 5 bits, the first group holding 3 bits.
	var acc uint64
	bits := 0
	idx := 25
	for i := 15; i >= 0; i-- {
		acc |= uint64(b[i]) << bits
		bits += 8
		for bits >= 5 && idx >= 0 {
			out[idx] = alphabet[acc&31]
			acc >>= 5
			bits -= 5
			idx--
		}
	}
	if idx >= 0 {
		out[idx] = alphabet[acc&31]
	}
	return string(out[:])
}
