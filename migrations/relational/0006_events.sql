-- Relational tree: the business audit log (docs/PLAN.md section 5.1).
--
-- THREAT (spec 06 T7, repudiation and tampering with the audit trail):
-- every state change writes one events row in its own transaction, and
-- each row carries the hash of the previous one (prev_hash, hash), so a
-- removed or edited row breaks the chain. The table is insert-only for
-- the application role cisp_api: UPDATE, DELETE and TRUNCATE are revoked
-- on the parent and on every partition, so the api process can append
-- but never rewrite (CLAUDE.md hard rule 5).
--
-- Partitioned by month on ts. This migration creates the partitions of
-- the current and the next month (UTC); a cispctl subcommand creates
-- later ones ahead of time. An insert past the last partition fails
-- loudly rather than landing somewhere unaudited.

-- +goose Up
CREATE TABLE events (
    id          bigserial   NOT NULL,
    ts          timestamptz NOT NULL,
    actor_type  text        NOT NULL CHECK (actor_type IN ('client', 'account', 'system')),
    actor_id    text        NOT NULL,
    event_type  text        NOT NULL,
    entity_type text        NOT NULL,
    entity_id   text        NOT NULL,
    payload     jsonb       NOT NULL DEFAULT '{}'::jsonb,
    prev_hash   bytea       CHECK (length(prev_hash) = 32),
    hash        bytea       NOT NULL CHECK (length(hash) = 32),
    PRIMARY KEY (id, ts)
) PARTITION BY RANGE (ts);
CREATE INDEX events_entity_idx ON events (entity_type, entity_id, ts);
COMMENT ON TABLE events IS 'Append-only audit log with a per-row hash chain (06 T7); partitioned by month; insert-only for cisp_api.';

-- +goose StatementBegin
DO $$
DECLARE
    m     date;
    part  text;
BEGIN
    FOR i IN 0..1 LOOP
        m := (date_trunc('month', now() AT TIME ZONE 'UTC') + make_interval(months => i))::date;
        part := format('events_y%sm%s', to_char(m, 'YYYY'), to_char(m, 'MM'));
        EXECUTE format(
            'CREATE TABLE %I PARTITION OF events FOR VALUES FROM (%L) TO (%L)',
            part, m::timestamp AT TIME ZONE 'UTC', (m + interval '1 month')::timestamp AT TIME ZONE 'UTC');
        EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON %I FROM PUBLIC, cisp_api', part);
    END LOOP;
END $$;
-- +goose StatementEnd

REVOKE UPDATE, DELETE, TRUNCATE ON events FROM PUBLIC;
REVOKE UPDATE, DELETE, TRUNCATE ON events FROM cisp_api;

-- +goose Down
DROP TABLE events;
