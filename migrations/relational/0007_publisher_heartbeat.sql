-- Relational tree: what the publisher heartbeat records (WP-3,
-- docs/PLAN.md section 6.1, section 15 Q3). POST
-- /v1/publishers/heartbeat upserts the caller's row: last_heartbeat_at
-- is the CISP's clock when the heartbeat arrived (staleness is judged on
-- it, never on the publisher's clock), last_heartbeat_sent_at the
-- publisher's sent_at as declared, and active_refs the declared active
-- ansp_refs verbatim (a JSON array of at most 1000 strings; null when
-- the publisher sends none, as the authority does). WP-5 compares
-- active_refs with its heads and never acts on them.

-- +goose Up
ALTER TABLE publishers
    ADD COLUMN last_heartbeat_sent_at timestamptz,
    ADD COLUMN active_refs jsonb CHECK (active_refs IS NULL OR jsonb_typeof(active_refs) = 'array');

-- +goose Down
ALTER TABLE publishers
    DROP COLUMN active_refs,
    DROP COLUMN last_heartbeat_sent_at;
