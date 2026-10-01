package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Retention bounds (docs/PLAN.md section 15 Q15: the figure is the
// DPO's, a configuration value; 90 days until answered).
const (
	DefaultDeliveryLogRetentionDays = 90
	MaxDeliveryLogRetentionDays     = 3650
)

// Policy is one TimescaleDB background job on delivery_attempts.
type Policy struct {
	JobID  int64
	Proc   string // policy_compression, policy_retention
	Config string // the job's JSON configuration
}

// Policies lists the jobs on the delivery_attempts hypertable.
func Policies(ctx context.Context, ts *pgxpool.Pool) ([]Policy, error) {
	rows, err := ts.Query(ctx, `SELECT job_id, proc_name, config::text
FROM timescaledb_information.jobs
WHERE hypertable_name = 'delivery_attempts'
ORDER BY job_id`)
	if err != nil {
		return nil, fmt.Errorf("policies: %w", err)
	}
	defer rows.Close()
	var out []Policy
	for rows.Next() {
		var p Policy
		if err := rows.Scan(&p.JobID, &p.Proc, &p.Config); err != nil {
			return nil, fmt.Errorf("policies: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("policies: %w", err)
	}
	return out, nil
}

// SetRetention replaces the delivery log's retention policy with days
// (cispctl set-retention), in one transaction.
func SetRetention(ctx context.Context, ts *pgxpool.Pool, days int) error {
	if days < 1 || days > MaxDeliveryLogRetentionDays {
		return fmt.Errorf("set retention: %d days is outside 1..%d", days, MaxDeliveryLogRetentionDays)
	}
	tx, err := ts.Begin(ctx)
	if err != nil {
		return fmt.Errorf("set retention: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if _, err := tx.Exec(ctx, `SELECT remove_retention_policy('delivery_attempts', if_exists => true)`); err != nil {
		return fmt.Errorf("set retention: %w", err)
	}
	if _, err := tx.Exec(ctx, `SELECT add_retention_policy('delivery_attempts', make_interval(days => $1))`, days); err != nil {
		return fmt.Errorf("set retention: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("set retention: %w", err)
	}
	return nil
}
