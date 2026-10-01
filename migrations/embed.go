// Package migrations embeds the two goose migration trees (docs/PLAN.md
// section 5, D11): relational/ for PostgreSQL + PostGIS (database cisp)
// and timeseries/ for TimescaleDB (database cisp_ts). The trees are
// never merged and each has its own goose version table;
// internal/store runs them.
package migrations

import "embed"

// Relational is the relational tree (relational/*.sql).
//
//go:embed relational/*.sql
var Relational embed.FS

// Timeseries is the timeseries tree (timeseries/*.sql).
//
//go:embed timeseries/*.sql
var Timeseries embed.FS
