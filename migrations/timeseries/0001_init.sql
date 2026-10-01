-- Timeseries tree (TimescaleDB), database cisp_ts.
-- goose version table: goose_db_version_timeseries (docs/PLAN.md D11).
-- Never run against cisp; the two trees are never merged.

-- +goose Up
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- +goose Down
-- Nothing to undo: the extension is created by deploy/postgres/init.sql
-- as the superuser and outlives this tree's tables.
SELECT 1;
