-- Relational tree: subscriptions and the per-(subscription, change)
-- delivery state (docs/PLAN.md section 5.1, D7). The shapes are WP-1's;
-- the queries are WP-6's. deliver reads and writes these two tables
-- (deploy/postgres/init.sql leaves the grant to the migration that
-- creates them).

-- +goose Up
CREATE TABLE subscriptions (
    id                   text        PRIMARY KEY,
    client_id            text        NOT NULL,
    callback_url         text        NOT NULL,
    datasets             text[]      NOT NULL CHECK (cardinality(datasets) >= 1),
    bbox                 geometry(Polygon, 4326),
    status               text        NOT NULL CHECK (status IN ('pending_verification', 'active', 'suspended', 'deleted')),
    created_at           timestamptz NOT NULL,
    verified_at          timestamptz,
    suspended_reason     text,
    consecutive_failures integer     NOT NULL DEFAULT 0 CHECK (consecutive_failures >= 0),
    last_success_at      timestamptz
);
CREATE INDEX subscriptions_client_idx ON subscriptions (client_id);
CREATE INDEX subscriptions_bbox_gist ON subscriptions USING gist (bbox);

CREATE TABLE deliveries (
    id               text        PRIMARY KEY,
    subscription_id  text        NOT NULL REFERENCES subscriptions (id),
    change_id        bigint      NOT NULL,
    state            text        NOT NULL CHECK (state IN ('queued', 'delivering', 'delivered', 'failed', 'expired')),
    attempts         integer     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    first_attempt_at timestamptz,
    last_attempt_at  timestamptz,
    next_retry_at    timestamptz,
    delivered_at     timestamptz,
    last_status_code integer,
    last_error       text,
    UNIQUE (subscription_id, change_id)
);
CREATE INDEX deliveries_next_retry_idx ON deliveries (next_retry_at) WHERE next_retry_at IS NOT NULL;

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cisp_deliver') THEN
        GRANT SELECT, UPDATE ON subscriptions TO cisp_deliver;
        GRANT SELECT, INSERT, UPDATE ON deliveries TO cisp_deliver;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE deliveries;
DROP TABLE subscriptions;
