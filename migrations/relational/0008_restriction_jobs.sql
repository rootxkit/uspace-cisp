-- Relational tree: what the restrictions lifecycle needs beyond WP-1's
-- tables (WP-5, docs/PLAN.md sections 5.1 and 6.2).
--
-- job_runs: when a leader-elected job of the api last ran, shared by
-- every replica. The restriction expiry ticks every 5 s on whichever
-- replica holds its advisory lock; every replica's GET /v1/status and
-- status line read the last run here, so a dead ticker is visible from
-- any instance (E-02), and a replica that is not the leader never
-- reports the job as stopped.
--
-- restriction_events joins the insert-only record (06 T7): it is the
-- per-restriction history beside publications and changes, and is never
-- rewritten. restrictions itself is the mutable lifecycle head.

-- +goose Up
-- The hash of the body of the ANSP op that set ansp_version: the same
-- ansp_version is a replay only with the same bytes; another body under
-- it is a conflict (409), never a silent replay.
ALTER TABLE restrictions
    ADD COLUMN last_body_sha256 bytea CHECK (last_body_sha256 IS NULL OR length(last_body_sha256) = 32);

CREATE TABLE job_runs (
    name          text        PRIMARY KEY,
    last_run_at   timestamptz NOT NULL,
    last_instance text        NOT NULL,
    -- What the last run did (for the expiry: restrictions expired).
    last_count    integer     NOT NULL DEFAULT 0 CHECK (last_count >= 0)
);
COMMENT ON TABLE job_runs IS 'The last run of each leader-elected api job (restriction_expiry), shared by the replicas.';

REVOKE UPDATE, DELETE, TRUNCATE ON restriction_events FROM PUBLIC;
REVOKE UPDATE, DELETE, TRUNCATE ON restriction_events FROM cisp_api;
COMMENT ON TABLE restriction_events IS 'Every lifecycle event of every restriction with its version''s publication; insert-only.';

-- +goose Down
GRANT UPDATE, DELETE, TRUNCATE ON restriction_events TO cisp_api;
COMMENT ON TABLE restriction_events IS NULL;
DROP TABLE job_runs;
ALTER TABLE restrictions DROP COLUMN last_body_sha256;
