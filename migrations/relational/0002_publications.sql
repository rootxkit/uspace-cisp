-- Relational tree: the version model (docs/PLAN.md section 5.1, D2, D3,
-- D6, D8): publications, publication_attempts, features,
-- features_current, snapshots and changes.
--
-- THREAT (spec 06 T7, repudiation and tampering with the record):
-- publications, publication_attempts, features and changes are the
-- record of what was published, by whom and when. They are insert-only
-- for the application role cisp_api: UPDATE, DELETE and TRUNCATE are
-- revoked below, so a compromised or buggy api process can add a version
-- but cannot rewrite or erase one (CLAUDE.md hard rule 5, spec 05
-- section 4: kept indefinitely). features_current and snapshots are
-- materialisations rebuilt from publications.body and stay writable.
--
-- No foreign key points at an insert-only table: PostgreSQL checks a
-- foreign key with SELECT ... FOR KEY SHARE as the referenced table's
-- owner, which needs UPDATE on it, and the revoke below removes exactly
-- that. publication_id columns (here, restriction_events) and
-- deliveries.change_id are held by the transactions that write both
-- rows together; references to datasets stay foreign keys.

-- +goose Up
CREATE TABLE publications (
    id                  text        PRIMARY KEY,
    dataset             text        NOT NULL REFERENCES datasets (name),
    version             bigint      NOT NULL CHECK (version >= 1),
    publisher_client_id text        NOT NULL,
    received_at         timestamptz NOT NULL,
    body                bytea       NOT NULL,
    body_sha256         bytea       NOT NULL CHECK (length(body_sha256) = 32),
    content_type        text        NOT NULL,
    -- The publisher's detached JWS over body; null for versions the
    -- CISP made itself (expiry, republication).
    publisher_signature text,
    signature_kid       text,
    feature_count       integer     NOT NULL CHECK (feature_count >= 0),
    added               integer     NOT NULL CHECK (added >= 0),
    changed             integer     NOT NULL CHECK (changed >= 0),
    removed             integer     NOT NULL CHECK (removed >= 0),
    supersedes_version  bigint      CHECK (supersedes_version >= 0),
    warnings            jsonb       NOT NULL DEFAULT '[]'::jsonb,
    reason              text        NOT NULL CHECK (reason IN (
                            'publication', 'restriction_created', 'restriction_activated',
                            'restriction_extended', 'restriction_ended', 'restriction_cancelled',
                            'restriction_expired', 'republished')),
    UNIQUE (dataset, version)
);
COMMENT ON TABLE publications IS 'Every accepted version with the verbatim body and the publisher signature; insert-only, kept for ever (06 T7, 05 section 4).';

CREATE TABLE publication_attempts (
    id                  text        PRIMARY KEY,
    dataset             text        NOT NULL REFERENCES datasets (name),
    publisher_client_id text        NOT NULL,
    received_at         timestamptz NOT NULL,
    outcome             text        NOT NULL CHECK (outcome IN ('accepted', 'refused')),
    publication_id      text,
    problems            jsonb       NOT NULL DEFAULT '[]'::jsonb,
    body_sha256         bytea       CHECK (length(body_sha256) = 32),
    bytes               bigint      NOT NULL CHECK (bytes >= 0),
    CHECK ((outcome = 'accepted') = (publication_id IS NOT NULL))
);
CREATE INDEX publication_attempts_publisher_idx ON publication_attempts (publisher_client_id, dataset, received_at DESC);
COMMENT ON TABLE publication_attempts IS 'Every publication attempt with its outcome and problems (Annex III A(5)); insert-only.';

CREATE TABLE features (
    publication_id  text        NOT NULL,
    feature_id      text        NOT NULL,
    feature         jsonb       NOT NULL,
    feature_sha256  bytea       NOT NULL CHECK (length(feature_sha256) = 32),
    geom            geometry(Geometry, 4326) NOT NULL,
    centroid        geometry(Point, 4326)    NOT NULL,
    lower_m         double precision,
    lower_ref       text        CHECK (lower_ref IN ('AGL', 'AMSL', 'WGS84')),
    upper_m         double precision,
    upper_ref       text        CHECK (upper_ref IN ('AGL', 'AMSL', 'WGS84')),
    applicable_from timestamptz,
    applicable_to   timestamptz,
    has_events      boolean     NOT NULL,
    has_layers      boolean     NOT NULL,
    op              text        NOT NULL CHECK (op IN ('added', 'changed', 'removed', 'unchanged')),
    PRIMARY KEY (publication_id, feature_id)
);
CREATE INDEX features_geom_gist ON features USING gist (geom);
COMMENT ON TABLE features IS 'The features of every version, with op against the previous one; removed rows carry the last feature. Insert-only.';
COMMENT ON COLUMN features.feature IS 'The feature as published (canonical compact JSON); the only geometry ever served.';
COMMENT ON COLUMN features.geom IS 'DRAWING AND PREFILTER SHAPE ONLY (LESSONS Z-11): a polygon as published; a circle as ST_Buffer of its centre and radius on geography; a GeometryCollection as the union of its parts. Never served as the zone and never judged against.';

CREATE TABLE features_current (
    dataset         text        NOT NULL REFERENCES datasets (name),
    feature_id      text        NOT NULL,
    version         bigint      NOT NULL CHECK (version >= 1),
    feature         jsonb       NOT NULL,
    feature_sha256  bytea       NOT NULL CHECK (length(feature_sha256) = 32),
    geom            geometry(Geometry, 4326) NOT NULL,
    centroid        geometry(Point, 4326)    NOT NULL,
    lower_m         double precision,
    lower_ref       text        CHECK (lower_ref IN ('AGL', 'AMSL', 'WGS84')),
    upper_m         double precision,
    upper_ref       text        CHECK (upper_ref IN ('AGL', 'AMSL', 'WGS84')),
    applicable_from timestamptz,
    applicable_to   timestamptz,
    has_events      boolean     NOT NULL,
    has_layers      boolean     NOT NULL,
    UNIQUE (dataset, feature_id)
);
-- D8: a consumer merges zones, uspace_airspace and restrictions into one
-- zones.Index, and ed318.ToZones refuses a colliding key, so an
-- identifier is unique across the three datasets together.
CREATE UNIQUE INDEX features_current_cross_dataset_uq ON features_current (feature_id)
    WHERE dataset IN ('zones', 'uspace_airspace', 'restrictions');
CREATE INDEX features_current_geom_gist ON features_current USING gist (geom);
COMMENT ON TABLE features_current IS 'The materialised current version of each dataset; replaced inside the publication transaction.';
COMMENT ON COLUMN features_current.geom IS 'DRAWING AND PREFILTER SHAPE ONLY (LESSONS Z-11): a circle is its centre and radius; this buffer exists for bbox prefilters and drawing and is never served as the zone.';

CREATE TABLE snapshots (
    dataset        text        NOT NULL REFERENCES datasets (name),
    version        bigint      NOT NULL CHECK (version >= 1),
    etag           text        NOT NULL,
    body_gz        bytea       NOT NULL,
    cisp_signature text        NOT NULL,
    built_at       timestamptz NOT NULL,
    PRIMARY KEY (dataset, version)
);
COMMENT ON TABLE snapshots IS 'The unfiltered GET /v1/{dataset} body of each version, gzip, with the CISP compact detached JWS over the uncompressed body.';

CREATE TABLE changes (
    id             bigserial   PRIMARY KEY,
    dataset        text        NOT NULL REFERENCES datasets (name),
    version        bigint      NOT NULL CHECK (version >= 1),
    publication_id text,
    feature_ids    text[]      NOT NULL,
    removed_ids    text[]      NOT NULL,
    reason         text        NOT NULL CHECK (reason IN (
                       'publication', 'restriction_created', 'restriction_activated',
                       'restriction_extended', 'restriction_ended', 'restriction_cancelled',
                       'restriction_expired', 'republished', 'subscription_test')),
    at             timestamptz NOT NULL,
    -- Union envelope of the changed features; null = the whole dataset.
    bbox           geometry(Polygon, 4326)
);
CREATE INDEX changes_dataset_idx ON changes (dataset, id);
COMMENT ON TABLE changes IS 'The change feed and the outbox (D6): id is the cursor; written in the publication transaction. Insert-only.';

-- Insert-only for the application role (06 T7; see the header).
REVOKE UPDATE, DELETE, TRUNCATE ON publications, publication_attempts, features, changes FROM PUBLIC;
REVOKE UPDATE, DELETE, TRUNCATE ON publications, publication_attempts, features, changes FROM cisp_api;

-- deliver reads the change feed past its watermark (D6).
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cisp_deliver') THEN
        GRANT SELECT ON datasets, changes TO cisp_deliver;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE changes;
DROP TABLE snapshots;
DROP TABLE features_current;
DROP TABLE features;
DROP TABLE publication_attempts;
DROP TABLE publications;
