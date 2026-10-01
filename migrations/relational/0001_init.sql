-- Relational tree (PostgreSQL 16 + PostGIS 3.4), database cisp.
-- goose version table: goose_db_version_relational (docs/PLAN.md D11).
-- Never run against cisp_ts; the two trees are never merged.

-- +goose Up
CREATE EXTENSION IF NOT EXISTS postgis;

-- One row per dataset; current_version is the ETag source and 0 until
-- the first publication (docs/PLAN.md section 5.1).
CREATE TABLE datasets (
    name            text        PRIMARY KEY
                    CHECK (name IN ('zones', 'uspace_airspace', 'ussp_list', 'restrictions')),
    kind            text        NOT NULL CHECK (kind IN ('ed318', 'ussp_list')),
    current_version bigint      NOT NULL DEFAULT 0 CHECK (current_version >= 0),
    publisher_kind  text        NOT NULL CHECK (publisher_kind IN ('authority', 'ansp')),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

INSERT INTO datasets (name, kind, publisher_kind) VALUES
    ('zones',           'ed318',     'authority'),
    ('uspace_airspace', 'ed318',     'authority'),
    ('ussp_list',       'ussp_list', 'authority'),
    ('restrictions',    'ed318',     'ansp');

-- +goose Down
DROP TABLE datasets;
-- The extension stays: it is created by deploy/postgres/init.sql as the
-- superuser, and other objects may depend on it.
