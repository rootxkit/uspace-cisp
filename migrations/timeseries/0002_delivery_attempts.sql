-- Timeseries tree: the delivery log, the CISP's one time series
-- (docs/PLAN.md section 5.2, D9). Written by deliver only; read by api
-- through the read-only grant of deploy/postgres/init.sql.
--
-- Policies: 1-day chunks; compressed after 7 days, segmented by
-- subscription and ordered by time descending; dropped after 90 days.
-- The retention is data, not code: 90 is the default this migration
-- installs (docs/PLAN.md section 15 Q15, owner-only), and
-- `cispctl set-retention --days N` replaces the policy afterwards.

-- +goose Up
CREATE TABLE delivery_attempts (
    at               timestamptz NOT NULL,
    delivery_id      text        NOT NULL,
    subscription_id  text        NOT NULL,
    change_id        bigint      NOT NULL,
    attempt          integer     NOT NULL CHECK (attempt >= 1),
    status_code      integer,
    error            text,
    latency_ms       integer     NOT NULL CHECK (latency_ms >= 0),
    payload_bytes    integer     NOT NULL CHECK (payload_bytes >= 0),
    deliver_instance text        NOT NULL
);
SELECT create_hypertable('delivery_attempts', by_range('at', INTERVAL '1 day'));
CREATE INDEX delivery_attempts_subscription_idx ON delivery_attempts (subscription_id, at DESC);

ALTER TABLE delivery_attempts SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'subscription_id',
    timescaledb.compress_orderby = 'at DESC'
);
SELECT add_compression_policy('delivery_attempts', INTERVAL '7 days');
SELECT add_retention_policy('delivery_attempts', INTERVAL '90 days');

-- +goose Down
SELECT remove_retention_policy('delivery_attempts', if_exists => true);
SELECT remove_compression_policy('delivery_attempts', if_exists => true);
DROP TABLE delivery_attempts;
