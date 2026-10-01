# Changelog

All notable changes to `uspace-cisp`. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
semantic versioning, and the published API `api/openapi.yaml` changes
additively within `/v1`.

## [Unreleased]

### Added

- WP-0 scaffold: the Go module pinned to `uspace-core` v1.0.0; the `api`
  process (`/healthz`, `/readyz` that reports the WP-1 migrations as
  pending, `/metrics`, the OpenAPI-generated router answering 501
  `not_implemented` as `problem+json`), the idle `deliver` process and
  `cispctl` (`version`, `config check`); the `CISP_*` configuration with
  validation, unknown-variable refusal and redaction; structured logging,
  the Prometheus registry, the periodic status line and OpenTelemetry;
  the OpenAPI 3.1 skeleton with `oapi-codegen`; the goose migration
  trees; the Makefile, the CI workflow, the Dockerfile and the reference
  deployment (`deploy/`).
- WP-1 store and versions: every table of the plan's data model in the
  two goose trees (insert-only `publications`, `publication_attempts`,
  `features`, `changes` and monthly-partitioned, hash-chained `events`;
  `features_current` unique across `zones`, `uspace_airspace` and
  `restrictions`; the `delivery_attempts` hypertable with its compression
  and 90-day retention policies); `internal/publication` (canonical
  feature rows, diff, apply, delta, change records, the deterministic
  snapshot body, ETags); `internal/store` (pools, the embedded goose
  runner, sqlc queries, the publication transaction with the per-dataset
  advisory lock, the bounded snapshot cache that serves stale when the
  database is gone); `internal/bus` (connect without giving up, the
  `CIS_CHANGES` stream, publish with acknowledgement and deduplication);
  `cispctl migrate`, `migrate status`, `rebuild-current` and
  `set-retention`; `api` and `deliver` refuse to start with pending
  migrations; `CISP_DATABASE_MAX_CONNS` and `CISP_TIMESERIES_MAX_CONNS`.
- WP-2 machine authentication and signatures, on `uspace-core` v1.1.0:
  `internal/auth` (one core token verifier per process with
  `CISP_AUDIENCES`, the optional lab issuer and `StrictSessionClaims`;
  a JWKS disk copy, `CISP_JWKS_CACHE_FILE`, that lets the api start on
  the last good keys while an issuer is down and says
  `jwks: stale since T` until it answers; `RequireScopes`,
  `RequireAnyScope`, `RequirePublisher`, `RequireMTLSSubject` refusing
  with `unauthenticated`, `forbidden`, `not_a_publisher` and
  `mtls_required` problems, counted per reason); `internal/jws` (the
  CISP's RSA-3072 key ring and its JWKS, one detached-signature verifier
  per publisher, and the middleware that verifies a body before it is
  parsed); `GET /.well-known/jwks.json`; `GET /v1/status` now needs a
  `cis.read` token; `cispctl rotate-key`, `sign` and `verify-signature`;
  `tools/jws-smoke.sh`; the configuration `CISP_LAB_ISSUER`,
  `CISP_LAB_JWKS_URL`, `CISP_SIGNING_KID_PREV`,
  `CISP_PUBLISHER_SIGNATURE_MAX_SKEW_S`. `CISP_TOKEN_ISSUER`,
  `CISP_TOKEN_JWKS_URL`, `CISP_AUDIENCES` and (in mTLS mode `required`)
  `CISP_ANSP_MTLS_SUBJECT` are now required.
- WP-3 publication intake (F1): `PUT /v1/publications/{dataset}` for
  `zones`, `uspace_airspace` and `ussp_list` (the dataset's publish
  scope, the authority binding, `application/geo+json` or
  `application/json`, the authority's detached signature before the body
  is read, `If-Match` checked again under the dataset lock, accepted
  whole or refused whole with every problem by path, a refused attempt
  row and `publications_refused{dataset}`, `200 unchanged` for an equal
  body, `201` with the capped `added`/`changed`/`removed` and
  `warnings`); `GET /v1/publications/{dataset}` (history),
  `GET /v1/publications/{dataset}/attempts` (the publisher's refusals)
  and `POST /v1/publishers/heartbeat` (`active_refs` at most 1000, the
  ANSP bound to its certificate subject); `internal/dataset` (no USPACE
  in zones, only USPACE in `uspace_airspace`, no `DAR`, every zone
  buildable by `ed318.ToZones`, open-ended daylight schedules as
  warnings, the `cis/uspace_requirements/v1` block, the closed
  `cis/ussp_list/v1` validator); `schemas/cis/ussp_list/v1.json` and
  `schemas/cis/uspace_requirements/v1.json` exported from the OpenAPI
  components with examples; migration `0007_publisher_heartbeat`; the
  USSP list snapshot is its canonical form with the `cis_*` members; the
  api publishes committed changes through `internal/bus`.
