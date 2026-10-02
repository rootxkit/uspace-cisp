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
- WP-4 the read API (F3 pull) and the public subset: `GET|HEAD
  /v1/{dataset}` (the signed snapshot from the bounded per-instance
  cache, gzip as stored, `ETag`, `Last-Modified`, `Cache-Control`,
  `X-CIS-Version`, `If-None-Match` 304; `bbox` on the GiST prefilter,
  `at` keeping and marking what cannot be evaluated, `applies_at`
  annotating `cis_applicability`, `since_version` deltas within 1000
  versions; served stale with `X-CIS-Stale`, `X-CIS-Age-S` and
  `no-store` when the database is gone, filtered reads 503 `cis_stale`);
  `GET /v1/{dataset}/versions` and `/versions/{v}` (verbatim bytes, the
  publisher's signature and kid, the CISP's signature made once per
  version, `body_sha256` re-checked: 500 `integrity`); `GET /v1/changes`
  (`cis/change/v1`, exported to `schemas/cis/change/v1.json`);
  `GET /v1/status` (datasets, publisher staleness, degraded components
  with since-times, `mtls_mode`); `GET|HEAD /public/v1/{dataset}`
  without a token, the USSP list without `base_url` and
  `certificate_id`, rate-limited per client address (`CISP_PUBLIC_RPM`,
  burst 10, HEAD and 304 at ten times, 10 000 clients LRU,
  `CISP_TRUSTED_PROXY_CIDR` for `X-Forwarded-For`);
  `internal/applicability` (`ed318.Applies` at the feature's centroid,
  unknown kept); the dataset-first routes registered per dataset;
  `golang.org/x/time` for the token buckets.
- WP-5 dynamic restrictions from the ANSP (F2): `POST /v1/restrictions`
  and `PATCH /v1/restrictions/{id}` (`?by=ansp_ref`) behind the ANSP's
  publish scope, client id, client certificate subject and detached
  signature verified with the ANSP's own JWKS (256 KiB,
  `CISP_MAX_RESTRICTION_BYTES`); the idempotency key is the body pair
  `(ansp_ref, ansp_version)` (a replay is 200 and no version; a lower
  version 409 `ansp_version`; `Idempotency-Key` ignored); the lifecycle
  state machine of `internal/restriction` (planned, active, ended,
  cancelled; the F3548 `Cstr*` window limits imported from core; zero
  limits refuse); the DAR rules of `internal/dataset` (strict one-feature
  parse, DAR reason, restricting types, one period equal to the window,
  no daylight events, 1000 vertices, 10 000 km2 and intersection with a
  current U-space airspace measured by PostGIS, identifiers checked for
  length and uniqueness only); every accepted op a version of the
  `restrictions` dataset with its reason and change record in the same
  transaction as the head (`PublishTx` takes a `Before` hook); the
  served feature stamped with `extendedProperties.cis_restriction`;
  `GET /v1/restrictions/heads` and `GET /v1/restrictions/{id}` with
  events; the expiry ticker (`CISP_RESTRICTION_EXPIRY_INTERVAL_S`,
  leader-elected per run, `restrictions_expired`, `restrictions_active`,
  last run in `job_runs` and `/v1/status`, an error line after
  `CISP_RESTRICTION_EXPIRY_STALE_AFTER_S`); the ANSP's staleness as
  `cis_publisher_stale_since` on the heads and the dataset and a
  warning-level status line, and its heartbeat `active_refs` compared
  with the active heads (counted and listed, never acted on);
  migration `0008_restriction_jobs`; `schemas/cis/restriction/v1.json`;
  a warning tier in the status line.
- WP-6 subscriptions and signed webhook delivery (F3 push):
  `POST|GET /v1/subscriptions`, `GET|PATCH|DELETE /v1/subscriptions/{id}`,
  `GET /v1/subscriptions/{id}/deliveries` (with the delivery log read
  from the timeseries database) and `POST .../deliveries/{id}/retry`,
  all `cis.read` and audited; `internal/subscription` (the callback URL
  policy and the address rule of the SSRF guard, dataset and box
  matching, the 1 s to 300 s retry schedule for 24 h, suspension after
  50 failures over an hour); `internal/deliver` and the `deliver`
  process (the durable JetStream consumer `deliver`, the 10 s
  reconciliation scan counted `deliveries_from_scan`, leased
  `SKIP LOCKED` claims shared by every instance, at most 64 attempts in
  flight, compact JWS by core's `SignCompact` with `aud` the callback
  host, a 2 s timeout, no redirects, 1 KiB read, the dial-time address
  guard counted `ssrf_refused`, `cisp_delivery_first_attempt_seconds`,
  `cisp_delivery_result_total{code}`, and the status line's
  "0 queued, 0 due" summary); migration `0009_deliver`;
  `cis/change/v1` takes the webhook's producer and the
  `subscription_test` record, with two examples; `test/e2e/` (the
  reference subscriber container and the compose-driven latency,
  kill-the-subscriber, NATS-outage and restriction latency tests, a CI
  job); the api reads `CISP_ALLOW_PRIVATE_CALLBACKS`,
  `CISP_ALLOW_INSECURE_CALLBACKS` and `CISP_TIMESERIES_URL`; deliver
  needs `CISP_SIGNING_KEY_FILE`, `CISP_SIGNING_KID`, `CISP_ISSUER_URL`
  and `CISP_PUBLIC_BASE_URL` with a database.
- WP-7 the WS change stream, bus resilience and observability, on
  `uspace-core` v1.2.0: `WS /v1/stream?datasets=` (`internal/stream`):
  every frame the lab's common envelope (`envelope/v1`) around
  `console/status/v1` (on connect, every 2 s and at once after the bus
  returns, with `nats`, `degraded[]`, dataset versions, `cis_age_s`,
  publishers and `resync_since`) or `cis/change/v1`; at most
  `CISP_STREAM_MAX_CLIENTS` per instance (503 `stream_full`), a
  64-frame queue per client (`dropped_frames`, 1013 when it stays
  full), the per-IP limiter on the upgrade, an `Origin` allow-list
  (403 `origin`), the `uspace_session` cookie verified by the shared
  verifier and 4401 on a non-public stream (`CISP_STREAM_PUBLIC`).
  `internal/bus`: `Connect` returns within `CISP_NATS_CONNECT_TIMEOUT_S`
  with the broker absent (`never connected`), `State` with since-times,
  `Watch`, `Subscribe` for the hub with a resync on every return of the
  connection, slow-consumer errors counted and never fatal; `deliver`
  under the same policy. `internal/obs`: the metrics catalogue
  (`docs/RUNBOOKS/observability.md`, tested both ways and against the
  code), `obs.Once`, the status line's counters since the previous
  line and its `start` line, uncatalogued metrics warned, the store's
  counters mirrored, `cisp_publication_seconds`,
  `restriction_expiry_job_age_s`, `publisher_stale`, `nats_degraded_s`;
  spans `validate`, `publish_tx`, `bus_publish` and `delivery_attempt`
  (`claim`, `sign`, `post`) with the change id, only with
  `CISP_OTEL_ENDPOINT`. Integration tests stop and start a real broker
  (`internal/natstest`, docker).
