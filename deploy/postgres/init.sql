-- uspace-cisp database bootstrap, run once by the postgres container's
-- entrypoint (mounted into /docker-entrypoint-initdb.d/) or by CI with
-- psql as the superuser. It creates the two databases of the two
-- migration trees, their extensions (superuser-only), and the two
-- application roles:
--
--   cisp_api      owns cisp (relational, read/write: it runs the
--                 relational migrations and is the only writer of the
--                 business tables); reads cisp_ts through default
--                 privileges, never writes it.
--   cisp_deliver  owns cisp_ts (timeseries, read/write); connects to
--                 cisp, where it may only read and write deliveries and
--                 subscriptions: those grants are added by the migration
--                 that creates the tables (WP-1/WP-6), because a grant
--                 cannot name a table that does not exist yet.
--
-- The login passwords come from the environment (psql \getenv), never
-- from this file: PG_CISP_API_PASSWORD and PG_CISP_DELIVER_PASSWORD.

\set ON_ERROR_STOP on

\getenv api_password PG_CISP_API_PASSWORD
\getenv deliver_password PG_CISP_DELIVER_PASSWORD

\if :{?api_password}
\else
  DO $$ BEGIN RAISE EXCEPTION 'PG_CISP_API_PASSWORD is not set'; END $$;
\endif
\if :{?deliver_password}
\else
  DO $$ BEGIN RAISE EXCEPTION 'PG_CISP_DELIVER_PASSWORD is not set'; END $$;
\endif
SELECT length(:'api_password') = 0 OR length(:'deliver_password') = 0 AS empty_password \gset
\if :empty_password
  DO $$ BEGIN RAISE EXCEPTION 'PG_CISP_API_PASSWORD and PG_CISP_DELIVER_PASSWORD must not be empty'; END $$;
\endif

CREATE ROLE cisp_api LOGIN PASSWORD :'api_password';
CREATE ROLE cisp_deliver LOGIN PASSWORD :'deliver_password';

CREATE DATABASE cisp OWNER cisp_api;
CREATE DATABASE cisp_ts OWNER cisp_deliver;
REVOKE ALL ON DATABASE cisp FROM PUBLIC;
REVOKE ALL ON DATABASE cisp_ts FROM PUBLIC;

-- Relational: PostgreSQL + PostGIS.
\connect cisp
CREATE EXTENSION IF NOT EXISTS postgis;
GRANT CONNECT ON DATABASE cisp TO cisp_deliver;
GRANT USAGE ON SCHEMA public TO cisp_deliver;

-- Timeseries: TimescaleDB.
\connect cisp_ts
CREATE EXTENSION IF NOT EXISTS timescaledb;
GRANT CONNECT ON DATABASE cisp_ts TO cisp_api;
GRANT USAGE ON SCHEMA public TO cisp_api;
ALTER DEFAULT PRIVILEGES FOR ROLE cisp_deliver IN SCHEMA public GRANT SELECT ON TABLES TO cisp_api;
