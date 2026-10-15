-- Relational tree: the index behind the console overview's failed
-- deliveries (GET /v1/console/summary, docs/PLAN.md section 15 Q52).
--
-- deliveries holds one row per subscription and change and is never
-- emptied (an expired delivery stays a row, hard rule 4), so counting
-- the recent failures must not read it whole. This partial index holds
-- only the failed and expired rows, ordered by their last attempt: the
-- count of the last 24 hours is a range scan of that index, bounded by
-- the window, however long the table grows.

-- +goose Up
CREATE INDEX deliveries_failed_recent_idx ON deliveries (last_attempt_at)
    WHERE state IN ('failed', 'expired');

-- +goose Down
DROP INDEX deliveries_failed_recent_idx;
