-- Relational tree: dynamic restrictions and publishers (docs/PLAN.md
-- section 5.1, D4, D5). The shapes are WP-1's; the queries are WP-5's.

-- +goose Up
CREATE TABLE restrictions (
    id                       text        PRIMARY KEY,
    -- With ansp_version the idempotency key (section 6.2).
    ansp_ref                 text        NOT NULL UNIQUE,
    ansp_version             integer     NOT NULL CHECK (ansp_version >= 0),
    uspace_airspace_id       text        NOT NULL,
    -- The DAR zone identifier: at most 7 characters, never a prefix rule (Q17).
    feature_id               text        NOT NULL UNIQUE CHECK (length(feature_id) BETWEEN 1 AND 7),
    state                    text        NOT NULL CHECK (state IN ('planned', 'active', 'ended', 'cancelled')),
    starts_at                timestamptz NOT NULL,
    ends_at                  timestamptz NOT NULL,
    ended_by                 text        CHECK (ended_by IN ('ansp', 'expiry')),
    created_at               timestamptz NOT NULL,
    updated_at               timestamptz NOT NULL,
    last_publisher_client_id text        NOT NULL,
    source_stale_since       timestamptz
);
CREATE INDEX restrictions_state_ends_idx ON restrictions (state, ends_at);

CREATE TABLE restriction_events (
    restriction_id text        NOT NULL REFERENCES restrictions (id),
    at             timestamptz NOT NULL,
    op             text        NOT NULL,
    ansp_version   integer     NOT NULL,
    publication_id text,
    actor          text        NOT NULL
);
CREATE INDEX restriction_events_restriction_idx ON restriction_events (restriction_id, at);

CREATE TABLE publishers (
    client_id           text        PRIMARY KEY,
    kind                text        NOT NULL CHECK (kind IN ('authority', 'ansp')),
    mtls_subject        text,
    last_heartbeat_at   timestamptz,
    last_publication_at timestamptz,
    stale_after_s       integer     NOT NULL DEFAULT 60 CHECK (stale_after_s > 0),
    enabled             boolean     NOT NULL DEFAULT true
);

-- +goose Down
DROP TABLE publishers;
DROP TABLE restriction_events;
DROP TABLE restrictions;
