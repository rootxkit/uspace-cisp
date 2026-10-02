# uspace-cisp implementation plan

Status: plan for implementation by independent agents, one work package
per PR. Branch `plan/initial`. Inputs: the spec at `uspace-lab/docs/spec/`
(`00 §3, §6.1, §7`, `01 §2`, `02 F1-F3, §3 cisp`, `03 §2`, `04 §3.4`,
`05 §2-§6`, `06`, `07` Phase 2, `08`, `09`), the knowledge base at
`uspace-lab/knowledge/` (`LESSONS.md`, `scenarios.md` SC-12, SC-13,
`vectors/`), the shared library `rootxkit/uspace-core` (`docs/PLAN.md`,
`ed318`, `ed269`, `zones`, `geodesy`, `auth`, `vectors` public APIs at
`v1.0.0`), the cross-plan reconciliation of 2026-10-02 (decisions M1-M38
and §2, applied throughout and recorded in §15) and the predecessor `rootxkit/utm`
(`airspace/ed269.py`, `api/zone_routes.py`, U-03, U-04, U-09; read-only
reference for behaviour, never for architecture).

Sections: 1 scope and role boundary; 2 architecture; 3 package layout;
4 third-party dependencies; 5 data model and migrations; 6 the published
API; 7 events on the bus; 8 security; 9 performance budgets; 10 testing
strategy; 11 deployment; 12 milestones; 13 work packages and waves;
14 engineering standards; 15 open questions and decisions.

---

## 1. Scope and role boundary

`uspace-cisp` is the single, state-run Common Information Service
Provider of 2021/664 Art. 5 (spec `00 §3`, `01 §2`; the state-run choice
is the owner's, `08` Q7). It is one Go module
(`github.com/rootxkit/uspace-cisp`), two long-running processes (`api`,
`deliver`), one operations tool (`cispctl`), one PostgreSQL + PostGIS
database with a TimescaleDB companion, one NATS JetStream cluster, one
Next.js UI under `web/`, and one published OpenAPI 3.1 file
(`api/openapi.yaml`) that is the national CIS publication API.

### 1.1 What it does (spec `01 §2` C1-C6)

| Obligation | How this plan meets it |
|---|---|
| C1 online, open, scalable, non-discriminatory, same quality for authorities, ATS, USSPs and operators; a public subset | one REST API (`/v1/*`, scope `cis.read`) for every authenticated consumer, an identical read path at `/public/v1/*` without a token, rate-limited and cached (§6.4) |
| C2 carry U-space airspace limits and Art. 3(4) requirements, adjacency, geo-zones, static and dynamic restrictions, the USSP list with terms (from the authority); ATS.OR.127 data and ATS.TR.237 reconfigurations (from the ANSP) | four datasets `zones`, `uspace_airspace`, `ussp_list` (F1, authority) and `restrictions` (F2, ANSP); ATS operational data as a fifth dataset once its format is agreed (§15 Q4) |
| C3 verification and validation on receipt, metadata preserved, authenticated transfer, error reporting, every version retrievable | `ed318.Parse` on every publication (accept whole or refuse whole, never repair), the publisher's detached JWS kept and served with the version, refused attempts recorded and readable by the publisher, every version kept for ever with its verbatim bytes (§5, §6.1) |
| C4 encryption in transit and at rest, protocol protection, risk assessment, insider risk, threat detection | TLS at Caddy, signed webhooks, scoped tokens, mTLS for the ANSP, append-only audit, the threat model of `06 §2` applied in §8 |
| C5 notify subscribers within the authority's latency; never require polling to learn of a restriction | signed webhook push from a JetStream work queue within 1 s (p99 ≤ 2 s) plus a change cursor feed and a WS stream; the subscriber's 60 s reconciliation pull is a cheap `HEAD` on the `ETag` (§6.3, §9) |
| C6 certified and audited | the publication log and the audit log are the evidence; `cispctl export-audit` produces the oversight export |

### 1.2 What it does NOT do

- **Author or edit zones, U-space airspace, the USSP list or restrictions.**
  The authority is the master of the first three (`01` A2-A5, F1), the
  ANSP of dynamic restrictions (`01` N1, F2). The CISP validates, versions,
  signs, stores and serves. A publication is accepted whole or refused
  whole with every problem named; nothing is corrected, normalised or
  filled in (`06` T9, LESSONS Z-01, Z-02). Console users, including
  `admin`, have no write path to content: they manage accounts,
  subscriptions, re-deliveries and re-publications of what a publisher
  sent.
- **Hold operator PII, telemetry, flights, intents or alerts.** Airspace
  information only (`01 §2` MUST NOT). The only personal data are the
  console accounts of CISP staff and the contact fields the authority
  chooses to publish inside ED-318 `zoneAuthority` and the USSP list.
- **Judge airspace.** No zone judgement, CPA, conformance or identification
  runs here. The CISP evaluates applicability only to answer `at=`
  queries, through `uspace-core/ed318.Applies`, and never raises an alert
  (`00 §6` hard rule, `06` T12).
- **Be the sole copy.** The authority and the ANSP keep their masters; a
  CISP outage degrades subscribers to their caches (`02 F3` failure
  rule), it never loses a master.
- **Command an aircraft** (INV-01). There is no path from this repository
  to a vehicle, and nothing here talks to a USSP's operator-facing
  services.
- **Host the DSS.** The InterUSS DSS "hosted alongside the CISP" (`08` Q7)
  is a deployment decision for the droplet's compose files, not code in
  this repository; the ANSP writes its own F3548 constraints (`02 F2`).
- **Know which USSP or CISP is ours.** Every consumer of F3 is a client
  with scope `cis.read`; the only configured addresses are the authority's
  token service and JWKS, the ANSP's mTLS CA and the two publisher client
  ids (`00 §7`).

### 1.3 Decisions taken in this plan

| # | Decision | Why |
|---|---|---|
| D1 | The zone model, parse, export, ED-269 mapping, applicability and daylight events come from `uspace-core/ed318` and `ed269`; this repository has no package named `ed318` (spec `00 §6.1` lists one; §15 Q19). | Judgement and validation live once (`00 §6`). The CISP's own package is `internal/dataset`: the per-dataset rules that sit *above* the standard (which zone types a dataset may hold, cross-dataset identifier uniqueness, the Art. 3(4) requirements block). |
| D2 | Every publication is stored twice: the verbatim bytes with the publisher's detached signature, and the parsed features in a queryable table. Reads of a full version serve the verbatim bytes. | Provenance survives the CISP (`06` T4, Annex III A(4)) only if the bytes the authority signed are the bytes a consumer can fetch. Filtered reads are built from the parsed features and signed by the CISP. |
| D3 | Versions are per dataset, monotonic integers, one per accepted publication or restriction lifecycle event. A full-replacement publication whose canonical features equal the current version creates no version (idempotent re-PUT). | `02 F1` ("full replacement, diffed by the CISP"), `02 F3` (`ETag` = version). |
| D4 | The `restrictions` dataset is ED-318 too: each restriction is a `UASZone` feature with `reason` `DAR`, and its lifecycle state travels in `extendedProperties.cis_restriction`. Consumers read restrictions with the same code path as zones. | `02 F2` says the payload is an ED-318 `UASZone`; ED-318 has no state member and `extendedProperties` is its extension mechanism (`04 §4`). |
| D5 | The ANSP is the master of a restriction's state. The CISP mirrors `planned`, `active`, `ended`, `cancelled` as declared, accepts only a higher `ansp_version` per `ansp_ref`, and itself moves an `active` (or, WP-5 review, a never-activated `planned`) restriction to `ended` with `ended_by: expiry` when `ends_at` passes without word from the ANSP. | `03 §4` (ANSP `restrictions` O), `02 F2` failure rule ("active restrictions stay active until their `endDateTime`"). §15 Q2. |
| D6 | Change notification is an outbox: the `changes` row is committed in the same transaction as the version, then published to JetStream; `deliver` also scans `changes` past its watermark every 10 s, so a lost publish costs at most 10 s, never a missed notification. | LESSONS E-02 (run the branch that says nothing is wrong), B-05. |
| D7 | Deliveries are independent per (subscription, change): a failed delivery never blocks a newer one, because a notification is a hint and the subscriber pulls the delta by `since_version`. | `02 F3`. Ordering guarantees would cost a per-subscriber queue for no safety gain. |
| D8 | Identifiers are unique across `zones`, `uspace_airspace` and `restrictions` together, not only within a dataset. | A consumer merges the three into one `zones.Index`; `ed318.ToZones` refuses a colliding key. A collision at the CISP would break every USSP's cache. §15 Q17. |
| D9 | The TimescaleDB database holds one hypertable, `delivery_attempts`; everything else is relational. `deliver` is the only writer of the hypertable, `api` the only writer of the relational database. | `03` preamble (one database pair per system, two migration trees never merged, LESSONS B-15); the delivery log is the CISP's only time series. §15 Q12. |
| D10 | The console's accounts are local (argon2id), roles `viewer`, `publisher_admin`, `admin`; the session is an RS256 JWT issued by the CISP's own key and carried in an `HttpOnly` cookie by the Next.js BFF; verified by the same `uspace-core/auth.Verifier` as ecosystem tokens, with the console issuer allow-listed and a static key set. | `01 §2` users, `06 §3`, `00 §6.2` (one verifier). |
| D11 | Migrations use `goose` (embedded), not `golang-migrate` as `03` says; the version tables are `goose_db_version_relational` and `goose_db_version_timeseries` (one name per tree, the same in every repo). | The owner's stack decision; recorded as a deviation in §15 Q21. A tree run against the wrong database fails on the table name (cross-plan M36). |
| D12 | No H3, no partitioning, no hot-path process. The CISP's rates are human-scale (`02 F1-F3`); subscription matching is a PostGIS `&&`. | `05 §2`: the CISP's only sub-second path is `deliver`. |

---

## 2. Architecture

```
                 authority (F1)                    ANSP (F2)
        PUT /v1/publications/{dataset}       POST|PATCH /v1/restrictions
        detached JWS, If-Match               mTLS + token, ansp_ref/ansp_version
                   |                                   |
                   v                                   v
   +---------------------------------------------------------------+
   | cmd/api  (stateless, N replicas behind Caddy)                 |
   |  validate (core/ed318) -> dataset rules -> diff -> version    |
   |  -> features_current + snapshot bytes -> changes row  (one tx)|
   |  -> JetStream cis.v1.change.<dataset>                         |
   |  reads: GET/HEAD /v1/{dataset} ETag, bbox, at, since_version  |
   |         /versions, /changes, /public/v1/*, WS /v1/stream      |
   |  subscriptions, status, console, JWKS, health, metrics        |
   +------------------+------------------------+-------------------+
                      |                        |
             PostgreSQL+PostGIS          NATS JetStream
             (relational tree)          CIS_CHANGES (30 d)
                      |                        |
                      |                        v
   +------------------+------------------------+-------------------+
   | cmd/deliver (1..N, durable consumer)                          |
   |  match subscriptions (datasets, bbox) -> sign cis/change/v1   |
   |  -> POST callback (2 s timeout) -> retry schedule (24 h)      |
   |  -> delivery_attempts (TimescaleDB), deliveries (PostgreSQL)  |
   |  reconciliation scan of changes every 10 s                    |
   +---------------------------------------------------------------+
                      |
                      v
        USSPs, authority, ANSP (F3): webhook + pull by since_version
        public map and consoles (web/): /public/v1/*, WS /v1/stream
```

Process rules (spec `00 §6.1`, `05 §2`):

- `api` is horizontally stateless: sessions are cookies, long work is in
  JetStream, the snapshot cache is per instance and rebuilt from the
  database. It is the only writer of the relational database.
- `deliver` holds no state beyond its JetStream consumer position and a
  bounded in-flight set; two instances share the work through the durable
  consumer. It is the only writer of the timeseries database.
- `cispctl` runs migrations (`migrate relational|timeseries`), creates
  console accounts, rotates the signing key, exports audit, converts
  ED-269 files and re-publishes a stored version to the bus. It is never
  long-running and never on the request path.
- `web` (Next.js) renders. Its API routes are the BFF under `/_bff/*`
  (login cookie exchange, CSRF, token forwarding) and nothing else: no
  database, no NATS, no geometry library, no judgement (`00 §6.2`; lint
  rules in WP-9).
- A failed dependency degrades visibly, never silently: database down,
  reads continue from the in-memory snapshot with `X-CIS-Stale: true` and
  `X-CIS-Age-S`, writes answer 503 with `Retry-After`; NATS down, writes
  still commit and `deliver` catches up by scan; JWKS unreachable, cached
  keys serve for their TTL and the status endpoint says so (`02 §1`
  failure rule, `05 §6`, LESSONS B-08).

---

## 3. Package layout and responsibilities

```
github.com/rootxkit/uspace-cisp
├── cmd/api/                 HTTP API process (WP-0 stub; every WP adds routes)
├── cmd/deliver/             webhook fan-out process (WP-0 stub; WP-6)
├── cmd/cispctl/             migrations, accounts, keys, audit export, ed269 convert, republish
├── api/openapi.yaml         the published national API, spec-first (WP-0 skeleton; each WP adds its paths)
├── api/README.md            how the spec is edited, generated and verified
├── schemas/cis/             JSON Schemas this repo produces: change/v1, ussp_list/v1, uspace_requirements/v1, restriction/v1 (+ examples/)
├── migrations/relational/   goose, embedded, PostgreSQL + PostGIS   (WP-1)
├── migrations/timeseries/   goose, embedded, TimescaleDB            (WP-1)
├── internal/config/         env parsing, validation, redaction for logs (WP-0)
├── internal/obs/            slog JSON, Prometheus registry, OpenTelemetry, the periodic status line (WP-0, WP-7)
├── internal/httpapi/        generated server (gen/), handlers per group, middleware: request id, body caps, auth, scopes, rate limit, problem+json errors (WP-0 base; WP-3..8 handlers)
├── internal/auth/           core/auth verifier wiring, scope table, publisher client binding, mTLS subject check, console sessions (WP-2, WP-8)
├── internal/jws/            detached JWS verify (RFC 7797 b64=false) and compact JWS sign, key ring, JWKS document (WP-2)
├── internal/dataset/        the datasets and their rules above ED-318: kinds, allowed zone types and reasons, identifier uniqueness, Art. 3(4) block, USSP list schema (WP-3, WP-5)
├── internal/publication/    version model, canonical feature diff, snapshot materialisation, delta, change records (WP-1)
├── internal/restriction/    lifecycle state machine, ansp_version rule, expiry job, publisher heartbeat and staleness (WP-5)
├── internal/applicability/  ed318.Applies at the feature's place with NOAADaylight; "unknown" never "no" (WP-4)
├── internal/subscription/   model, dataset and bbox matching, callback URL policy (SSRF guard), limits (WP-6)
├── internal/deliver/        JetStream consumer, signer, sender, retry schedule, reconciliation scan, counters (WP-6)
├── internal/store/          pgx pool, sqlc queries (relational/, timeseries/), transactions, goose runner, the snapshot cache (WP-1)
├── internal/bus/            nats.go JetStream: stream and consumer definitions, publish with ack, reconnect-forever policy, degraded start (WP-1 minimal; WP-7)
├── internal/stream/         WS hub for /v1/stream fed from the bus (WP-7)
├── internal/console/        console read models, accounts, audit queries, actions (WP-8)
├── web/                     Next.js App Router, uspace-ui, ka/en (WP-9, WP-10, WP-11)
├── deploy/                  compose.yml, caddy/Caddyfile.snippet (reference copy), .env.example, images (WP-0)
├── test/integration/        build tag `integration`: real PostgreSQL/Timescale and NATS (WP-1 onward)
├── test/e2e/                compose-driven scenarios: kill the subscriber, kill NATS, kill the database (WP-6, WP-13)
└── docs/                    this plan, WORKPACKAGES/, RUNBOOKS/ (WP-13 adds runbooks)
```

Dependency rules: `internal/dataset`, `internal/publication`,
`internal/restriction`, `internal/subscription` and `internal/applicability`
are pure (no database, no network, no logging; they return values and
`*core.FieldError`/`*ed269.Problems`, and count into `core.Counters`).
`internal/store`, `internal/bus`, `internal/jws` are the adapters.
`internal/httpapi` and `internal/deliver` compose them. Nothing imports
`cmd/`. `web/` imports nothing from Go; its types are generated from
`api/openapi.yaml`.

---

## 4. Third-party dependencies

The owner fixed the stack; each module below is pinned in `go.mod`, with
the version recorded in the commit that adds it, and nothing with cgo.
Everything else is the standard library.

| Module | Used by | Why |
|---|---|---|
| `github.com/rootxkit/uspace-core` (by tag; `v1.1.0` from WP-2: the JWS helpers of core WP-14, §15 Q20; `v1.3.0` from WP-12: `geodesy.Destination` for the circle outline, §15 Q43) | everywhere | the ED-318/ED-269 model, parse, export, mapping, applicability and daylight; the JWT verifier and issuer; geodesy; the vector harness (`00 §6.3`) |
| `github.com/oapi-codegen/oapi-codegen/v2` (tool, `go tool`) and `github.com/oapi-codegen/runtime` | `internal/httpapi/gen` | server and client types generated from `api/openapi.yaml`, strict-server mode, committed and verified offline in CI (owner's decision) |
| `github.com/getkin/kin-openapi` (test only) | `internal/httpapi` tests | request and response validation against the spec in handler tests, so the spec is the contract, not a comment |
| `github.com/jackc/pgx/v5` | `internal/store` | PostgreSQL driver and pool (owner's decision) |
| `github.com/sqlc-dev/sqlc` (tool) | `internal/store` | typed queries generated from SQL, committed, verified in CI (owner's decision) |
| `github.com/pressly/goose/v3` | `internal/store`, `cispctl` | embedded migrations, two trees (owner's decision) |
| `github.com/nats-io/nats.go` | `internal/bus` | JetStream publish, durable pull consumers, KV not used here (owner's decision) |
| `github.com/lestrrat-go/jwx/v3` (`jwk` only) | `internal/auth`, `internal/jws`, tests | building the static `jwk.Set` that core's `auth.IssuerConfig.Keys` takes: the JWKS disk copy read back at start (`internal/auth.JWKSCache`) and the keys tests generate. Every JWS is signed and verified by `uspace-core/auth` (`KeyRing.SignDetached`, `DetachedVerifier`, `KeyRing.SignCompact`, `Verifier`); WP-2 landed on core `v1.1.0` directly, so the interim own implementation of M27 never existed (§15 Q20). The module is the one core already uses, so one JOSE implementation per binary |
| `github.com/prometheus/client_golang` | `internal/obs` | metrics (owner's decision) |
| `go.opentelemetry.io/otel` (+ `sdk`, `exporters/otlp/otlptrace/otlptracehttp`, `contrib/instrumentation/net/http/otelhttp`) | `internal/obs`, `internal/httpapi` | tracing (owner's decision); exporter off unless `CISP_OTEL_ENDPOINT` is set |
| `golang.org/x/crypto` (argon2) | `internal/auth` | console password hashing (`06 §3` argon2id) |
| `github.com/pquerna/otp` | `internal/auth` | TOTP for console `admin` MFA (`06 §3`); pure Go |
| `github.com/coder/websocket` | `internal/stream` | WS server for `/v1/stream`; pure Go, context-aware, no `gorilla` maintenance risk |
| `golang.org/x/time/rate` | `internal/httpapi` | per-client and per-IP token buckets |
| `github.com/google/go-cmp` (test only) | tests | readable diffs of feature collections |
| `github.com/santhosh-tekuri/jsonschema/v6` (test only) | `internal/stream` tests | every stream frame validated against the lab's JSON Schema 2020-12 files (`envelope/v1`, `console/status/v1` with its cross-file `$ref`s), the validator the lab's own contract tests use |

Rejected: any GeoJSON or geometry library (`uspace-core/geodesy` and
PostGIS do the work; a TypeScript geometry import is a lint failure); an
ORM; `gorilla/websocket` (archived); `go-chi` or `gin` (`net/http` routing
since Go 1.22 is the owner's choice); a JSON Schema validator in Go for
the USSP list (the OpenAPI schema plus `kin-openapi` in tests covers it;
runtime validation is hand-written and bounded, WP-3).

Web (`web/package.json`): `next`, `react`, `typescript` (strict),
`tailwindcss`, `@rootxkit/uspace-ui` (shadcn/ui theme, MapLibre
components, symbology, ka/en, BFF helpers), `maplibre-gl` (through the
kit), `openapi-typescript` (dev), `eslint` with the kit's config and the
two project rules (no geometry import, no server-side business logic),
`vitest` for unit tests of pure helpers, `@playwright/test` for one smoke
test of the public map, and the kit's optional form peers
`react-hook-form` and `zod` (its `ConfirmDialog`, §15 Q44). Package manager `pnpm` with `packageManager`
pinned in `package.json` and `pnpm-lock.yaml` frozen (`pnpm install
--frozen-lockfile`), as every `web/` in the ecosystem (cross-plan M34).
`@rootxkit/uspace-ui` comes from one GitHub Release tarball URL, exact
pin with the lockfile's integrity, starting on the kit's `0.1.0-rc` and
bumped to `0.1.0` (M33; §15 Q14 as amended by the owner on 2026-10-02).
The kit's peers that the web lists itself: `typescript-eslint`,
`eslint-plugin-react-hooks`, `eslint-plugin-jsx-a11y` (its ESLint config)
and `@tailwindcss/postcss` (Tailwind v4 under Next.js).

---

## 5. Data model and migrations

Conventions (`03` preamble): units in column names, `TIMESTAMPTZ` UTC,
geometry `SRID 4326`, distance on `geography`; the relational tree and
the timeseries tree are separate goose trees with separate version
tables (`goose_db_version_relational` in `cisp`,
`goose_db_version_timeseries` in `cisp_ts`; D11) and are never merged
(LESSONS B-15).

### 5.1 Relational (PostgreSQL 16 + PostGIS 3.4), `migrations/relational/`

| Table | Columns (key ones) | Notes |
|---|---|---|
| `datasets` | `name` PK (`zones`, `uspace_airspace`, `ussp_list`, `restrictions`), `kind` (`ed318`, `ussp_list`), `current_version` (0 when never published), `publisher_kind` (`authority`, `ansp`), `updated_at` | one row per dataset, seeded by migration; `current_version` is the `ETag` source |
| `publications` | `id` ULID, `dataset`, `version` (unique per dataset, monotonic), `publisher_client_id`, `received_at`, `body` bytea (verbatim), `body_sha256`, `content_type`, `publisher_signature` text (detached JWS, nullable for CISP-made versions such as expiry), `signature_kid`, `feature_count`, `added`, `changed`, `removed` ints, `supersedes_version`, `warnings` jsonb, `reason` (`publication`, `restriction_created`, `restriction_activated`, `restriction_extended`, `restriction_ended`, `restriction_cancelled`, `restriction_expired`, `republished`) | `03 §2 publications`; the snapshot of record. Never updated, never deleted (`05 §4`: indefinite). |
| `publication_attempts` | `id`, `dataset`, `publisher_client_id`, `received_at`, `outcome` (`accepted` → `publication_id`, `refused`), `problems` jsonb (path + reason, capped as `ed269.Problems`), `body_sha256`, `bytes` | Annex III A(5) error reporting: a publisher reads its own refusals (`GET /v1/publications/{dataset}/attempts`) |
| `features` | `publication_id`, `feature_id` (ED-318 `identifier`; `PartIdentifier` for layers), `feature` jsonb (the feature as published, compact), `geom` geometry(Geometry,4326) (polygon as published; a circle stored as `ST_Buffer(geography)` **for bbox and drawing only**, LESSONS Z-11), `centroid` geometry(Point,4326), `lower_m`, `lower_ref`, `upper_m`, `upper_ref`, `applicable_from`, `applicable_to` (nullable; the outer bounds of `limitedApplicability`), `has_events` bool, `op` (`added`, `changed`, `removed`, `unchanged` vs the previous version) | every version's features; `removed` rows carry the last feature for the delta; GiST on `geom`, btree on (`publication_id`, `feature_id`) |
| `features_current` | `dataset`, `feature_id`, `version`, `feature` jsonb, `geom`, `centroid`, limits, applicability bounds | the materialised current version; replaced in the publication transaction; what every filtered read hits; GiST on `geom`, unique (`dataset`, `feature_id`), and a unique index on `feature_id` **across** `zones`, `uspace_airspace`, `restrictions` (D8) |
| `snapshots` | `dataset`, `version`, `etag`, `body_gz` bytea (the response body of an unfiltered `GET /v1/{dataset}` at that version, gzip), `cisp_signature` text (compact detached JWS by the CISP's key over the uncompressed body), `built_at` | built in the publication transaction; served verbatim with `Content-Encoding` negotiation |
| `restrictions` | `id` ULID, `ansp_ref` (unique; with `ansp_version` the idempotency key, §6.2), `ansp_version` int, `uspace_airspace_id` (the USPACE feature identifier), `feature_id` (the DAR zone identifier, ≤ 7 chars), `state` (`planned`, `active`, `ended`, `cancelled`), `starts_at`, `ends_at`, `ended_by` (`ansp`, `expiry`, null), `created_at`, `updated_at`, `last_publisher_client_id`, `source_stale_since` nullable | the lifecycle head; every change also becomes a `publications` row of dataset `restrictions` (D4) |
| `restriction_events` | `restriction_id`, `at`, `op`, `ansp_version`, `publication_id`, `actor` | the per-restriction history the console shows |
| `publishers` | `client_id` PK, `kind` (`authority`, `ansp`), `mtls_subject` nullable, `last_heartbeat_at`, `last_publication_at`, `stale_after_s` (60), `enabled` | seeded from env at start (`CISP_PUBLISHERS`), heartbeat updated by `POST /v1/publishers/heartbeat` (§15 Q3) |
| `subscriptions` | `id` ULID, `client_id`, `callback_url`, `datasets` text[], `bbox` geometry(Polygon,4326) nullable, `status` (`pending_verification`, `active`, `suspended`, `deleted`), `created_at`, `verified_at`, `suspended_reason`, `consecutive_failures`, `last_success_at` | `03 §2`; at most `CISP_MAX_SUBSCRIPTIONS_PER_CLIENT` (20) per client |
| `deliveries` | `id` ULID, `subscription_id`, `change_id`, `state` (`queued`, `delivering`, `delivered`, `failed`, `expired`), `attempts`, `first_attempt_at`, `last_attempt_at`, `next_retry_at`, `delivered_at`, `last_status_code`, `last_error` | the current state per (subscription, change); unique on the pair; the retry scheduler's queue (`next_retry_at` index) |
| `changes` | `id` bigserial (the cursor), `dataset`, `version`, `publication_id`, `feature_ids` text[] (added+changed+removed), `removed_ids` text[], `reason`, `at`, `bbox` geometry(Polygon,4326) (union envelope of the changed features; null = whole dataset) | `03 §2 changes`; written in the publication transaction (D6); the body of `cis/change/v1` |
| `accounts` | `id`, `username` (unique, lower), `password_hash` (argon2id, params in the hash), `role` (`viewer`, `publisher_admin`, `admin`), `totp_secret_enc` nullable, `mfa_required` bool, `status`, `created_at`, `last_login_at`, `failed_logins`, `locked_until` | console users (`01 §2`); no PII beyond a username and the optional display name |
| `sessions` | `jti` PK, `account_id`, `issued_at`, `expires_at`, `revoked_at` | revocation list for console JWTs |
| `events` | `id` bigserial, `ts`, `actor_type` (`client`, `account`, `system`), `actor_id`, `event_type`, `entity_type`, `entity_id`, `payload` jsonb, `prev_hash`, `hash` | append-only audit with a per-row hash chain (`06` T7); partitioned by month; application role has INSERT and SELECT only |

Not stored, deliberately: anything from a USSP, any telemetry, any
operator record. There is no projected entity (`03 §2`: "Projected:
nothing").

### 5.2 Timeseries (TimescaleDB), `migrations/timeseries/`

| Hypertable | Columns | Policy |
|---|---|---|
| `delivery_attempts` | `at` (time), `delivery_id`, `subscription_id`, `change_id`, `attempt`, `status_code` nullable, `error` text nullable, `latency_ms`, `payload_bytes`, `deliver_instance` | 1-day chunks, compressed after 7 days (`segmentby subscription_id`, `orderby at`), dropped after `CISP_DELIVERY_LOG_RETENTION_DAYS` (default 90; §15 Q15) |

Written by `deliver` only; read by `api` for the console and for
`GET /v1/subscriptions/{id}/deliveries`.

### 5.3 Migration rules

- One goose SQL file per change, `NNNN_<slug>.sql` with `-- +goose Up` and
  `-- +goose Down`, embedded with `embed.FS`; `cispctl migrate relational`
  and `cispctl migrate timeseries` apply them (the one-shot `migrate`
  compose service runs both); `api` and `deliver` refuse to start when
  their tree has pending migrations (they print which) and never migrate
  on their own (zero-downtime rule, predecessor S-31). This is the
  pattern every system in the ecosystem adopted (M36): a `migrate`
  subcommand, a one-shot compose service, no `*_MIGRATE_ON_START` flag.
- A migration touching `features_current` or `snapshots` is written so the
  rebuild runs from `publications.body` through the same Go code
  (`cispctl rebuild-current`), never by hand-written SQL that reinterprets
  ED-318.
- The relational tree is the only one `api` connects to; the timeseries
  tree the only one `deliver` writes; `api` reads the timeseries database
  through a read-only role (`03` preamble).

---

## 6. The published API (`api/openapi.yaml`)

Spec-first. The file is the contract: an endpoint that is not in it does
not exist (`00 §7`). `oapi-codegen` generates the strict server interface
and the client types into `internal/httpapi/gen/`; `openapi-typescript`
generates `web/src/api/types.ts`; both are committed and CI fails when a
regeneration differs. Conventions (`02 §1`): path version `/v1`; JSON;
RFC 3339 UTC with `Z`; GeoJSON `[lng, lat]`; unknown request fields
ignored within a major; errors as `application/problem+json` (RFC 9457)
in the shape every backend in the ecosystem shares (M28): `{type, title,
status, detail, instance, errors: [{field, reason}], truncated?}`, where
`errors[]` carries the field problems of a refused publication (`field`
= the JSON path as `core.FieldError`/`ed269.Problems` write it, capped
at 100 with `truncated: true`) and `type` =
`https://schemas.uspace.ge/problems/<slug>` (the same domain as the
schema `$id`s; `slug` = the counter or refusal name: `unauthenticated`,
`forbidden`, `signature`, `not_a_publisher`, `precondition_failed`,
`cis_stale`, `ansp_version`, `state`, ...). The schema `problem/v1`
lives in `uspace-lab/schemas/common/` (M14).

Scopes and roles are in §8.2. Every request carries `X-Request-Id`
(generated when absent) and every response echoes it.

### 6.1 Publication intake (`02 F1`)

| Method and path | Spec | Auth | Behaviour |
|---|---|---|---|
| `PUT /v1/publications/{dataset}` (`zones`, `uspace_airspace`, `ussp_list`) | `02 F1`, `01` C3 | scope `cis.publish:zones` / `cis.publish:uspace` / `cis.publish:ussp_list`; `sub` must be the configured authority client id | body ≤ `CISP_MAX_PUBLICATION_BYTES` (32 MiB; `02 F1` says < 20 MB); `If-Match: "<dataset>:<current_version>"` required (412 on mismatch, 428 when absent); `X-JWS-Signature` detached JWS over the exact body bytes required (403 `signature`, §15 Q30); validation per dataset (WP-3) accepts whole or refuses whole (400 with `errors[]`); a body whose canonical features equal the current version returns 200 with the current version and no new row; otherwise 201 `{dataset, version, etag, received_at, feature_count, added[], changed[], removed[], warnings[]}` |
| `GET /v1/publications/{dataset}` | `02 F3` history | `cis.read` or the publisher | versions with publisher, time, counts, reason |
| `GET /v1/publications/{dataset}/attempts?since=` | Annex III A(5) | the publisher (its own) or console `admin` | refused attempts with their problems |
| `POST /v1/publishers/heartbeat` | `02 F2` failure rule (undefined there; §15 Q3, decided: M3) | any `cis.publish:*` scope | body `{sent_at, active_refs?: []}`, sent **every 15 s** by every publisher (the ANSP fills `active_refs` with its `ansp_ref`s; the authority sends none); the CISP records `last_heartbeat_at` and, for the ANSP, the declared active set (a declared `ansp_ref` the CISP does not hold as `active` is counted `heartbeat_ref_unknown` and shown in status, never acted on); a publisher silent for `stale_after_s` (60 s = three misses) is `source_stale` in `GET /v1/status` and on its datasets' `metadata` |

### 6.2 Dynamic restrictions (`02 F2`)

| Method and path | Spec | Auth | Behaviour |
|---|---|---|---|
| `POST /v1/restrictions` | `02 F2`, `04 §3.4` | `cis.publish:restrictions`, `sub` = the ANSP client id, mTLS subject = the configured one (§8.3) | body `cis/restriction/v1`: `{ansp_ref, ansp_version, uspace_airspace_id, state (planned|active), starts_at, ends_at, feature (ED-318 Feature, reason DAR)}` (the field is `ansp_version`, never `version`; M4); **the idempotency key is the body pair `(ansp_ref, ansp_version)`**: the same pair → 200 with the stored state, a lower `ansp_version` → 409 `ansp_version`; an `Idempotency-Key` header may be sent and is ignored (nothing depends on it); validation: `ed318.Parse` of a one-feature collection, `reason` contains `DAR`, `limitedApplicability` present and within `[starts_at, ends_at]`, `uspace_airspace_id` is a current `USPACE` feature (strict on both sides; the lab publishes a designation for every demo, M9, §15 Q6), identifier ≤ 7 characters and unique across datasets (D8; the CISP enforces length and uniqueness only, never a prefix; the ANSP mints `DAR` + 4 base-36, §15 Q17), `ends_at - starts_at ≤ 24 h` and `starts_at ≤ now + 56 d` (the F3548 `Cstr*` limits the ANSP mirrors to the DSS, so one restriction fits both channels); creates a `restrictions` version (reason `restriction_created` or `restriction_activated`) and a change |
| `PATCH /v1/restrictions/{id}` | `02 F2` (end, extend) | same | `{op: activate|extend|end|cancel, ansp_version, ends_at? and feature? (extend, §15 Q36)}`; transitions `planned→active`, `planned→cancelled`, `active→ended`, `active→active (extend)`; anything else 409 `state`; each accepted op is a new version and a change with the matching reason |
| `GET /v1/restrictions/{id}` | `02 F3` | `cis.read` | the head plus `events[]` |
| `GET /v1/restrictions/heads?state=&airspace=&at=` | `02 F3` | `cis.read` | list of heads; the dataset read `GET /v1/restrictions` below is the ED-318 view of the same rows (§15 Q35) |

Reads of `restrictions` as a dataset (§6.3) serve each restriction as an
ED-318 feature with `extendedProperties.cis_restriction = {id, ansp_ref,
ansp_version, state, starts_at, ends_at, ended_by, uspace_airspace_id}`
(D4; schema `cis/restriction/v1`). `ended` and `cancelled` restrictions
leave `features_current` (they are in history by version).

### 6.3 Reads, history and the change feed (`02 F3` pull)

| Method and path | Spec | Auth | Behaviour |
|---|---|---|---|
| `GET` / `HEAD /v1/{dataset}` (`zones`, `uspace_airspace`, `ussp_list`, `restrictions`) | `02 F3` | `cis.read` | `ETag: "<dataset>:<version>"`, `Last-Modified`, `Cache-Control: public, max-age=<CISP_READ_MAX_AGE_S>`; `If-None-Match` → 304; without filters the stored snapshot bytes are served (and `X-CIS-Signature` carries the CISP's detached JWS over them); `?bbox=minlng,minlat,maxlng,maxlat` filters by `features_current.geom &&` (circles by their stored buffer; LESSONS Z-11: a prefilter, never a judgement); `?at=<RFC 3339>` keeps the features that apply at that instant through `ed318.Applies` at the feature's centroid with `NOAADaylight`, **and keeps** any feature whose applicability cannot be evaluated, marked `extendedProperties.cis_applicability: "unknown"` (fail visible); `?applies_at=<RFC 3339>` **annotates without filtering** (M17): every feature is returned with `extendedProperties.cis_applicability` ∈ `applies` / `not_applicable` / `unknown` evaluated at that instant, so a console can dim "not applicable now" in one fetch without judging (`at=` and `applies_at=` together are 400 `filter_conflict`); `?since_version=<v>` returns `DatasetDelta {dataset, from_version, to_version, added: FeatureCollection, changed: FeatureCollection, removed: [ids]}` (400 when `v` is newer than current, 410 when older than the retained delta window of 1000 versions: pull the full dataset). Every ED-318 response carries `metadata.issued` = the version's `received_at` and the top-level members `cis_dataset`, `cis_version`, `cis_updated_at` (§15 Q1). `ussp_list` is `cis/ussp_list/v1`, not ED-318. |
| `GET /v1/{dataset}/versions?limit=&before=` | `02 F3` history | `cis.read` | version list with `etag`, `received_at`, counts, reason, `publisher` |
| `GET /v1/{dataset}/versions/{v}` | `02 F3` history, `06` T4 | `cis.read` | the verbatim published bytes with `X-Publisher-Signature` (the authority's or the ANSP's detached JWS and its `kid`) when the version came from a publisher, and `X-CIS-Signature` always; `?format=ed269` on `zones` and `restrictions` exports through `ed318.ToED269` (406 with the refusing field when the version holds what ED-269 cannot: USPACE, DAR, events) |
| `GET /v1/changes?since=<cursor>&dataset=&limit=` | `02 F3` | `cis.read` | `{changes: [cis/change/v1...], next: <cursor>}` in cursor order; `since=0` is the beginning; at most 500 |
| `GET /v1/status` | `02 §1` failure rule, `05 §6` | `cis.read` | per dataset `current_version`, `updated_at`; per publisher `last_heartbeat_at`, `stale`; `degraded[]` (`database`, `nats`, `jwks`) with since-times; the CISP's `now` |
| `GET /.well-known/jwks.json` | `02 F3` (webhook signing), `06` T4 | none | the CISP's signing public keys (`use: sig`, `kid`), current and previous during rotation |
| `GET /healthz`, `GET /readyz` | — | none (internal) | liveness; readiness = database reachable and migrations current (NATS down is "ready, degraded") |
| `GET /metrics` | — | internal network only (Caddy does not route it) | Prometheus |

### 6.4 Public subset (`01` C1, `02 §3 cisp`)

`GET` / `HEAD /public/v1/{dataset}` with the same filters and headers as
§6.3 but no token, no `since_version`, no `/versions/{v}`, no
`/changes`, and `X-CIS-Signature` on unfiltered responses. Served by
`api`, cached by Caddy (`Cache-Control` as above, keyed on the full URL),
rate-limited per IP (`CISP_PUBLIC_RPM`, default 60 for full-dataset GETs,
600 for `HEAD` and 304s). Content: the full `zones`, `uspace_airspace`
and `restrictions` datasets, and the USSP list without `base_url` and
`certificate_id` (§15 Q10 proposes this; the owner decides). The public
map (WP-10) reads only this surface and `WS /v1/stream`.

### 6.5 Subscriptions and push (`02 F3` push)

| Method and path | Auth | Behaviour |
|---|---|---|
| `POST /v1/subscriptions` | `cis.read` | `{callback_url, datasets[], bbox?}`; `callback_url` must be `https://` (plain `http://` only to `localhost`/`127.0.0.1` when `CISP_ALLOW_INSECURE_CALLBACKS=true`), must not resolve to a private, loopback, link-local or multicast address unless `CISP_ALLOW_PRIVATE_CALLBACKS=true` (lab), host length ≤ 253, no userinfo; at most 20 per client; created `pending_verification`, then `deliver` POSTs a `cis/change/v1` with `reason: subscription_test` and the subscription becomes `active` on a 2xx (within 60 s; else stays pending and the response to a later `GET` says why) |
| `GET /v1/subscriptions`, `GET /v1/subscriptions/{id}` | owner client or console | state, counters, `last_success_at`, `consecutive_failures` |
| `PATCH /v1/subscriptions/{id}` | owner client | datasets, bbox; a changed callback_url re-runs verification |
| `DELETE /v1/subscriptions/{id}` | owner client or console `admin` | soft delete; queued deliveries expire |
| `GET /v1/subscriptions/{id}/deliveries?since=` | owner client or console | deliveries with their attempts (from the hypertable) |
| `POST /v1/subscriptions/{id}/deliveries/{delivery_id}/retry` | owner client or console `publisher_admin` | re-queue now (audited) |
| `WS /v1/stream?datasets=` | none (public) or the session cookie on a same-origin upgrade with an `Origin` allow-list (M22) | every frame is the common envelope (`schema`, `msg_id`, `producer`, `ts`, `rx_ts`, `captured_at`, `time_source`, `backlog`) + `body` named by `schema`, the one console frame every browser-facing WebSocket in the ecosystem uses (M29; schemas in `uspace-lab/schemas/common/`): `console/status/v1` on connect and every 2 s (`connection_id`, `server_ts`, `policy_version`, `stale_after_s`, `live_max_age_s`, `dropped_frames`, `degraded[]`, `sources[]`, plus the CISP extras `datasets{name: version}`, `cis_age_s`, `nats`, and `resync_since` after a bus reconnect: a client that sees `resync_since` re-pulls by `HEAD`/`since_version`); `cis/change/v1` bodies as changes are committed; no history (use `/v1/changes`); no `console/snapshot/v1` and no `console/subscribe/v1` here (the stream has no picture; `?datasets=` on the upgrade is the subscription); connection cap per instance |

Webhook delivery (`deliver`): `POST <callback_url>`, `Content-Type:
application/jose`, body = compact JWS (RS256, the CISP's `kid`) whose
payload is the `cis/change/v1` record plus `iss` (the CISP's issuer URL),
`aud` (**the host of the subscription's `callback_url`**, M19: the
audience rule of M18 applied to webhooks; never the client id), `iat`,
`jti` (= delivery id), `sub` (= subscription id); the subscriber
verifies against `/.well-known/jwks.json` and answers 2xx within 2 s.
Every receiver in the ecosystem exposes the same path,
`POST /v1/cis/notifications` (M1), but the CISP posts to the registered
`callback_url` and never assumes it. Receivers acknowledge `204` without
pulling for `reason` ∈ {`subscription_test`, `republished`} and for any
reason they do not know (M5, M16), and honour `pull_url` only when its
host is the CISP's configured base host, so `pull_url` is always built
on `CISP_PUBLIC_BASE_URL`. Retry on anything
else or a timeout: 1, 2, 4, 8 … s doubling, capped at 300 s, until 24 h
after the change (`02 F3`), then `expired`. A subscription with 50
consecutive failures over ≥ 1 h is `suspended` (its client sees why and
re-activates by `PATCH`); the delivery log keeps every attempt. The
subscriber's own 60 s reconciliation `HEAD` is mandatory on their side;
this plan never relies on a delivered webhook for correctness (D7).

### 6.6 Console (`01 §2` users)

| Method and path | Role | Behaviour |
|---|---|---|
| `POST /v1/console/session` | — | username, password, TOTP when `mfa_required`; 5 failures lock 15 min (predecessor S-15); returns the session JWT the BFF stores in the cookie |
| `DELETE /v1/console/session` | any | revoke `jti` |
| `GET /v1/console/me` | any | account, role, MFA state |
| `GET /v1/console/accounts`, `POST`, `PATCH /{id}` (role, status, reset MFA) | `admin` | no self-demotion of the last admin |
| `GET /v1/console/publications?dataset=`, `GET /v1/console/publications/{id}/diff` | `viewer`+ | versions and per-feature diffs (added, changed with a JSON diff, removed) |
| `GET /v1/console/restrictions` | `viewer`+ | heads, events, publisher staleness |
| `GET /v1/console/subscriptions`, `/{id}/deliveries` | `viewer`+ | all clients' subscriptions |
| `POST /v1/console/subscriptions/{id}/suspend`, `/resume`, `/deliveries/{delivery_id}/retry` | `publisher_admin`+ | audited actions |
| `POST /v1/console/publications/{id}/republish` | `publisher_admin`+ | emits a new change record `reason: republished` for the **current** version only (never changes content) |
| `GET /v1/console/audit?since=&actor=&type=` | `admin` | the `events` table |
| `GET /v1/console/status` | `viewer`+ | §6.3 status plus counters |

The Next.js BFF (`web/app/_bff/*`) exchanges the login for the
`uspace_session` cookie (`HttpOnly; Secure; SameSite=Strict`) and
forwards it as a bearer to `/v1/console/*`; CSRF by the double-submit
`uspace_csrf` cookie and `X-CSRF-Token` header (M21: the names every
console in the ecosystem uses, so the kit's BFF helpers need no
configuration); no credential in browser JavaScript (`06 §3`). The
WebSocket is not proxied by the BFF: the browser upgrades `WS
/v1/stream` same-origin with the cookie and `api` verifies it with the
shared verifier and an `Origin` allow-list; a `4401` close means
"re-login" (M22; no ticket route, because a ticket in a query string is
logged).

The session JWT has one shape across the ecosystem (M20), verified by
the same `core/auth.Verifier` as machine tokens: `iss` =
`CISP_CONSOLE_ISSUER`, `aud` = the CISP's own host (one of
`CISP_AUDIENCES`), `sub` = account id, `scope = "session"`, `roles:
[<role>]` (one element here), `realm: "console"`, `jti` = session id,
`exp` ≤ 12 h, `kid`. The role is read from `roles[]`, never from
`scope`.

### 6.7 Schemas this repository produces (`schemas/cis/`)

| `$id` | Carried by | Content |
|---|---|---|
| `https://schemas.uspace.ge/cis/change/v1.json` | webhooks, `/v1/changes`, `/v1/stream` | `schema`, `msg_id`, `producer`, `dataset`, `version`, `etag`, `feature_ids[]`, `removed_ids[]`, `reason` (`publication`, `restriction_created`, `restriction_activated`, `restriction_extended`, `restriction_ended`, `restriction_cancelled`, `restriction_expired`, `republished`, `subscription_test`), `at`, `pull_url`, `bbox?` (`04 §3.4`) |
| `https://schemas.uspace.ge/cis/ussp_list/v1.json` | `ussp_list` dataset | `{schema, issued, ussps: [{ussp_id, name, contact {email, phone, url}, certificate_id, base_url, services[] (Annex VI names), certification_limitations[], valid_from, valid_until, terms_url, status}]}` (`02 F1`; §15 Q5) |
| `https://schemas.uspace.ge/cis/uspace_requirements/v1.json` | `extendedProperties` of `USPACE` features | `{uas_requirements, service_performance {nid_update_hz, ti_update_hz, cis_latency_s, ...}, operational_conditions, airspace_constraints, services_required[], adjacent[]}` (`02 F1`, `03 §1 uspace_airspaces`; §15 Q6) |
| `https://schemas.uspace.ge/cis/restriction/v1.json` | `POST /v1/restrictions` body and `extendedProperties.cis_restriction` | as in §6.2 |

Each schema has `examples/` that CI validates against the schema and
round-trips through the Go types; `uspace-lab/schemas/` mirrors them
(KT-2). Ownership follows the cross-plan rule (M14): an HTTP body is
owned by the repository whose `api/openapi.yaml` carries it, so the four
`cis/*` schemas are the CISP's even though the authority produces
`ussp_list` and the `uspace_requirements` block; the authority validates
its output against a pinned copy of these schemas in its CI (M7). Shapes
produced by several systems (`envelope/v1`, `console/status/v1`,
`problem/v1`) are consumed from `uspace-lab/schemas/common/` and never
redefined here. Until the lab aggregate exists (lab WP-L1), siblings
copy this repository's `api/openapi.yaml` into their `api/clients/cisp.yaml`
with a `SOURCE` commit and a CI diff (M11): the WP-0 skeleton is what
they copy, so it lands first.

---

## 7. Events on the bus

One NATS JetStream cluster for the CISP, on its own network, per-process
credentials, no JWT inside (`00 §6.2`), no cross-system subject ever
(`02 §1`).

| Subject | Stream and retention | Producer | Consumers | Payload |
|---|---|---|---|---|
| `cis.v1.change.<dataset>` | `CIS_CHANGES`, JetStream file, 30 d, max 1 GiB, dedupe on `Nats-Msg-Id` = change id (2 min window) | `api`, after the transaction that wrote `changes` commits (D6) | `deliver` (durable pull consumer `deliver`, explicit ack, `max_ack_pending` 256, ack wait 30 s); `api` stream hub (ephemeral, per instance) | `cis/change/v1` |

That is the whole bus. The retry scheduler, the heartbeat state and the
console read from PostgreSQL, not from NATS: NATS is used only where it
decouples processes (`00 §6.1`). The spec's `cis.v1.<dataset>` subject and
`KV cis_current` (`05 §3`) are what *consumers* of the CIS run inside
their own clusters; they do not exist here.

Bus policy (LESSONS B-08): `nats.Connect` with `RetryOnFailedConnect`,
`MaxReconnects(-1)` and a bounded initial wait; `api` starts without NATS
(degraded, `GET /v1/status` says `nats` since when; the WS stream is
empty but connected; changes are still committed); `deliver` starts
without NATS too and runs on its reconciliation scan alone until the
broker returns. A publish failure after commit is counted
(`bus_publish_failed`) and logged once per interval; nothing is retried
at the publish site because the scan covers it.

---

## 8. Security

### 8.1 Threats applied (`06 §2`)

| Threat | Control here | Test that proves it (E-01 pairs) |
|---|---|---|
| T4 impersonation of a publisher | token `aud` ∈ `CISP_AUDIENCES` (the CISP's host), `sub` ∈ configured publisher ids, scope per dataset, detached JWS by the publisher's own signing key (the authority's from the authority's JWKS, the ANSP's from the ANSP's JWKS; §15 Q8), `iat` in the JWS protected header within 5 min, body hash bound by the signature; ANSP additionally by mTLS subject | accepted publication beside: wrong `aud`, wrong `sub`, right `sub` wrong scope, valid token no signature, signature by an unknown `kid`, stale `iat`, body altered after signing, mTLS subject mismatch |
| T4 impersonation of the CISP towards subscribers | compact JWS with `iss`, `aud`, `jti`, `iat`; JWKS with rotation overlap | the lab's subscriber simulator verifies and refuses a token signed by another key |
| T7 tamper of records | `publications` and `events` are insert-only for the application role; `events` hash-chained monthly; `body_sha256` checked when serving a version | a `cispctl verify-audit` run over a tampered row fails and names it |
| T8 denial of service | body caps (publications 32 MiB, restrictions and subscriptions 256 KiB, console 64 KiB), `ed269.Limits` (depth, ring vertices 5000, problems 100), per-client and per-IP rate limits, connection caps on the WS hub, Caddy cache on the public surface, a 10 s handler deadline | each cap exceeded by one test (E-10) |
| T9 malicious or faulty publisher | `ed318.Parse` validates and never repairs; refusal lists every problem; a publication that `ToZones` cannot build is refused for geometry and limit errors (so no USSP can be handed a zone it cannot judge) and warned for the rest; identifier collisions across datasets refused (D8) | the `ed318_roundtrip.json` refusals through `PUT` |
| SSRF through `callback_url` | scheme, host and resolved-address policy (§6.5), no redirects followed, 2 s timeout, response body discarded after 1 KiB, outbound only from `deliver` | each refused URL class beside an accepted one; a redirecting callback counts as failure |
| T10 supply chain, public repository | `gitleaks` in CI; `.env.example` only; keys generated at run time into `local/`; `go.sum` and `pnpm-lock.yaml` frozen; `govulncheck`; images built in CI from pinned bases, SBOM and cosign signature; Dependabot | CI |
| T12 duplicated safety logic | no zone judgement here; `web/` lint forbids geometry imports and server-side logic beyond the BFF; `internal/applicability` is a thin call into `ed318.Applies` | lint rules in WP-9; code review checklist in `CLAUDE.md` |
| Insider (Annex III B(5)) | console cannot edit content; every console action is an `events` row with the actor; `admin` needs TOTP | role matrix tests: every mutating console route refuses `viewer`, every content route refuses `admin` |

### 8.2 Scopes and roles

| Caller | Credential | May |
|---|---|---|
| authority (machine) | ecosystem JWT, scopes `cis.publish:zones`, `cis.publish:uspace`, `cis.publish:ussp_list`, `cis.read`; `sub` = `CISP_AUTHORITY_CLIENT_ID` (`authority-01`) | publish the three datasets, read its attempts, read everything, subscribe, heartbeat |
| ANSP (machine) | ecosystem JWT, scope `cis.publish:restrictions`, `cis.read`; `sub` = `CISP_ANSP_CLIENT_ID` (`ansp-01`); mTLS subject = `CISP_ANSP_MTLS_SUBJECT` | restrictions lifecycle, read everything, subscribe, heartbeat |
| USSPs and any other certified consumer | ecosystem JWT, scope `cis.read`; `sub` = `ussp-<code>-01`, `lab-01`, ... | read, history, changes, subscriptions |
| public | none | `/public/v1/*`, `WS /v1/stream`, JWKS |
| console `viewer` | session cookie (`roles: ["viewer"]`) | read console views |
| console `publisher_admin` | session cookie (`roles: ["publisher_admin"]`) | plus suspend/resume subscriptions, retry deliveries, republish the current version |
| console `admin` | session cookie (`roles: ["admin"]`) + TOTP | plus accounts, audit |

Client ids are one per calling system (`<system>-<nn>`, or
`ussp-<code>-<nn>` with the certificate code), never one per
caller-target pair (M24); audiences are chosen per token request. The
scope catalogue is held by the authority (its WP-2): `06 §3` plus
`ansp.coordination`, `ansp.requests`, `dp.observe` and the reserved
`cis.publish:ats_data` (M23); a new `cis.*` scope is a PR there first.

Token verification is `uspace-core/auth.Verifier` with
`Issuers = {CISP_TOKEN_ISSUER: {JWKSURL}}` for ecosystem tokens (the lab
issuer of lab WP-L2 is a second allow-listed entry until the authority's
token service exists, so nothing here waits for authority WP-2) and
`{CISP_CONSOLE_ISSUER: {Keys: own JWKS}}` for sessions, `Audiences =
CISP_AUDIENCES` (§15 Q7, decided: M18. **`aud` is the host of the
target's published base URL** for every machine token in the ecosystem,
`uspace-cisp.chikox.net` for this one; `CISP_AUDIENCES` is the list of
accepted values: the public host plus a lab alias such as the compose
service name), `MaxSkew` 30 s, JWKS cached 24 h, refresh on an unknown
`kid` rate-limited by core (LESSONS E-14). Every refusal is a counter
and a log line with the claim named; every token issuance (console
sessions) is an `events` row.

### 8.3 mTLS for the ANSP

Caddy terminates TLS with `client_auth { mode verify_if_given,
trusted_ca_cert_file <the mTLS CA> }` on the CISP host, forwards the
verified subject in `X-Client-Cert-Subject` and strips that header from
every request that did not present a certificate and from every other
route. The Go middleware enforces presence and the subject binding only
on the mTLS routes (`/v1/restrictions*`, `/v1/publishers/heartbeat` when
the caller is the ANSP): `api` accepts a restriction write only when the
header equals `CISP_ANSP_MTLS_SUBJECT`. The flag is
**`CISP_MTLS_MODE = required | off`**, the one name and the two values
every repo uses (M25): `required` in production; `off` on the staging
droplet and in the lab (the lab's simulated ANSP has no certificate),
where the status line says so at error level every period. The Caddy
rule lives in the deployment repository (`uspace-deploy`, D1 of the
reconciliation); `deploy/caddy/` here keeps a reference copy of the
snippet that WP-13's Caddy profile test runs. §15 Q11.

### 8.4 Keys

The CISP's signing key is an RSA-3072 PEM at `CISP_SIGNING_KEY_FILE`
with `CISP_SIGNING_KID`; a previous key at `CISP_SIGNING_KEY_PREV_FILE`
stays in the JWKS for the rotation window (`cispctl rotate-key` writes
the new pair into `local/` in dev; production custody is the owner's,
§15 Q16). The console session key is separate
(`CISP_SESSION_KEY_FILE`). Nothing under `local/` or `*.pem` is ever
committed (`.gitignore`, `gitleaks`).

### 8.5 Data protection

No operator or pilot data exists here. Console accounts are the only
personal data: username, optional display name, argon2id hash, TOTP
secret encrypted at rest under `CISP_SECRETS_KEY_FILE`. The audit log records
actors by id. Retention: publications and audit indefinite (`05 §4`),
delivery log 90 days (§15 Q15).

---

## 9. Performance budgets (from `05`)

The CISP's volumes are independent of the drone count (`02 F1-F3`). The
budgets below are what the work packages test against; the lab's L-M2
load run is the proof.

| Path | Load (100 / 1000 drones; same) | Budget | How it is met |
|---|---|---|---|
| `PUT /v1/publications/zones`, 5 000 zones, 20 MB | tens per month | accepted and visible on `GET` within 10 s p95; `ed318.Parse` ≤ 2 s (core's `ed269.Parse` budget is 50 ms per Luxembourg-sized file; 5 000 zones ≈ 25×), diff ≤ 200 ms, `COPY` into `features` and `features_current` ≤ 3 s, snapshot build and sign ≤ 1 s | streaming body into memory once (32 MiB cap), features inserted with `pgx.CopyFrom`, canonical JSON of each feature hashed once |
| `POST /v1/restrictions` → change committed | a few per day, bursts of tens | ≤ 100 ms p99 server time | one-feature parse, single transaction, snapshot delta rebuilt from `features_current` of the `restrictions` dataset (≤ 100 features) |
| change committed → webhook POSTed | same | **≤ 1 s p50, ≤ 2 s p99** to the first attempt for every active subscription (`01` C5 design target) | JetStream publish ≤ 10 ms; `deliver` fan-out concurrent (64 in flight per instance), per-request timeout 2 s; p99 is bounded by the slowest subscriber, which is reported per subscription |
| `HEAD /v1/{dataset}` (60 s reconciliation per subscriber) | 100 subscribers → 2 rps; consoles and public map 10 rps | ≤ 5 ms p99 | `datasets.current_version` read from the per-instance cache refreshed by the bus and every 5 s |
| `GET /v1/zones` full, 20 MB | public map and new subscribers; ≤ 1 rps sustained, bursts of 10 | ≤ 50 ms server time + transfer | gzip snapshot served from the bounded cache (last 2 versions per dataset, ≤ 128 MiB total) |
| `GET /v1/zones?bbox=` | consoles at 10 / 30 / 60 concurrent, ≤ 2 rps each | ≤ 100 ms p99 with 5 000 features | GiST on `features_current.geom`; `at=` evaluated only on the bbox hits |
| `GET /v1/changes?since=` | every subscriber after a webhook; ≤ 10 rps in bursts | ≤ 20 ms p99 | btree on the cursor |
| `WS /v1/stream` | ≤ 1 000 connections per `api` instance | ≤ 100 ms from commit to frame | one bus subscription per instance fanned out in memory; slow clients dropped with a counted reason |
| memory | the droplet: 2 vCPU / 3.8 GB shared by five systems today (the sum of every system's budget already exceeds it; resizing is the owner's, §15 Q26) | `api` ≤ 256 MiB RSS, `deliver` ≤ 64 MiB, `web` ≤ 256 MiB; PostgreSQL `shared_buffers` 128 MiB | bounded caches (E-10), no per-request allocation of a whole dataset except for the publication path |
| storage | publications indefinite | ≤ 1 GB per year at 50 publications per month of 20 MB (bodies gzip-compressed in `bytea`; `features` rows per version kept, ≈ 5 MB per version) | TOAST compression; `features` of old versions are kept but not indexed by geometry beyond the version's own index |

Every counter named in this plan (`bus_publish_failed`,
`deliveries_expired`, `publications_refused`, `rate_limited`,
`stream_clients_dropped`, `applicability_unknown`, …) is a Prometheus
counter and appears in the periodic status line (E-09). Latency
histograms: `cisp_publication_seconds`, `cisp_delivery_first_attempt_seconds`
(from `changes.at`), `cisp_http_request_seconds` by route.

---

## 10. Testing strategy

### 10.1 Unit (pure packages, every WP)

Table tests per rule with E-01 pairs (every refusal beside the acceptance
that differs in one thing), E-02 (the success and the degraded branch
both exercised and their output read), E-10 (every bound exceeded), E-11
(`-shuffle=on`, `-race`). `internal/publication`'s diff is property-tested:
`diff(a, a)` is empty, `apply(a, diff(a, b)) == b` for random feature
sets. Coverage ≥ 85 % statements in `internal/`, with every branch that
produces a distinct counter, reason or problem covered by a named test.

### 10.2 Knowledge vectors (`uspace-core/vectors`)

CI runs `go test -run 'Vectors|Manifest|Version'
github.com/rootxkit/uspace-core/...` from this module (proves the pinned
core passes its own vectors inside this build), and this repository's
own `RunOwned(t, "cisp", ...)` adapter tests for the files that name
`cisp`:

| File | Adapter under test |
|---|---|
| `ed318_roundtrip.json` | `PUT /v1/publications/zones` with the vector's collections: accepted ones read back equal by value from `/v1/zones/versions/{v}` (bytes) and from `/v1/zones` (features); refused ones return the vector's problems by path and phrase |
| `ed269_parse.json` | `cispctl ed269 convert` and `PUT` with `Content-Type: application/vnd.ed269+json` (WP-12): accepted files map and export back identical; refusals name the path |
| `zones_applicability.json` | `GET /v1/zones?at=` keeps and drops the right zones |
| `geodesy.json` (`in_polygon`, `in_circle`) | `?bbox=` prefilter never excludes a zone that contains the point (the bbox is conservative) |
| `jwt_verify.json` | the auth middleware: each case's token → 200 or 401 with the claim named |
| `alert_lifecycle.json` | the CISP raises no alert; the cases that name `cisp` are run by core in the step above and no adapter exists here (§15 Q18 asks the lab to drop `cisp` from that file's owners) |

### 10.3 Integration (real PostgreSQL + PostGIS + TimescaleDB and NATS)

Build tag `integration`, under `test/integration/` and beside the store
and bus packages. Locally `make dev-deps` starts
`timescale/timescaledb-ha:pg16` (which ships PostGIS) and `nats:2-alpine
-js` from `deploy/compose.dev.yml`; CI runs the same images as job
`services`. The job fails when zero integration tests ran (E-02: a
skipped suite is not a green suite). Covered: both migration trees up and
down from empty; publication transaction atomicity (a failure after
`features_current` leaves no partial version); `features_current`
uniqueness across datasets; snapshot bytes equal the published bytes;
change cursor monotonic across concurrent publications (advisory lock
per dataset); JetStream dedupe on the change id; `deliver` reconciliation
with NATS stopped; the retry schedule against a fake subscriber that
fails N times; `delivery_attempts` compression and retention policies
exist.

### 10.4 Contract (the OpenAPI is the contract)

Every handler test wraps the request and the response in
`kin-openapi`'s `openapi3filter` validation against `api/openapi.yaml`;
a response the spec does not describe fails the test. `make generate`
reproduces `internal/httpapi/gen/`, `internal/store/*/` (sqlc) and
`web/src/api/types.ts`; CI runs it offline (tools from the module cache
and `node_modules`) and fails on a diff. `schemas/cis/*/examples/*.json`
validate against their schema and unmarshal into the Go types strictly.

### 10.5 End-to-end and scenarios

`test/e2e/` drives `deploy/compose.yml` (built images) with the lab's
contracts as a test client would: the authority-role client publishes
the `ed318_roundtrip` base collection and a U-space airspace; a
subscriber container receives the signed change within 1 s (measured,
printed); the subscriber is killed during a restriction activation and
reconciles by `HEAD` within 60 s of restart (C-M3 done-when); NATS is
stopped for 60 s during a publication and the delivery arrives by scan;
PostgreSQL is stopped and `GET /v1/zones` keeps serving with
`X-CIS-Stale: true` while `PUT` answers 503; `deliver` is killed
mid-batch and no delivery is lost or duplicated (JetStream redelivery +
`deliveries` unique key). Scenarios from `knowledge/scenarios.md` the
CISP owns: SC-12 (applicability windows: the `at=` filter and the
console show the window state for the zone of the run) and SC-13 (an
AGL PROHIBITED zone with no DEM is published without complaint; the
warning belongs to the consumer). INV-02 (SITL) does not apply to the
CISP, which raises no alert; the restriction → USSP alert within one
tick is N-M1's and S-M4's done-when, exercised by the lab against this
system's image.

### 10.6 Conformance hooks (`uspace-lab/conformance/`, L-M4)

`make conformance` runs the lab's ED-318 publication tests (schema,
vertical references, applicability, versioning, change feed) against a
local compose stack when `LAB_DIR` points at a checkout; it is a CI job
on `main` only when the lab suite exists (path `conformance/cisp/`),
otherwise skipped **visibly** with a step summary line. `api/openapi.yaml`
is what `uspace-lab/api/` aggregates; a third-party CISP must pass the
same suite behind the same contract (`00 §7`).

### 10.7 Web

`pnpm install --frozen-lockfile`, `next lint` (kit config + the two
project rules), `tsc --noEmit`, generated types up to date (through the
kit's `uspace-ui-gen-api`), `vitest` for pure helpers (date
and version formatting, the ka/en catalogue completeness check), one
Playwright smoke test (the public map loads against a mocked
`/public/v1/*`, both locales render Georgian glyphs). Playwright runs
only on `web/**` changes.

---

## 11. Deployment

- **Images**, built in CI on `main` and on tags, pushed to
  `ghcr.io/rootxkit/uspace-cisp` (one Go image with `api`, `deliver`,
  `cispctl` as entrypoints; `distroless/static`, non-root) and
  `ghcr.io/rootxkit/uspace-cisp-web` (Next.js standalone output; never
  built on the server). Tagged by short SHA and by git tag; `latest` is
  never deployed (predecessor S-21). SBOM (`syft`) attached, cosign
  keyless signature, verified by the deploy script (`06 §4`).
- **Compose** (`deploy/compose.yml`): project `uspace-cisp` on its own
  network; services `postgres` (`timescale/timescaledb-ha:pg16`, two
  databases `cisp` and `cisp_ts`, a 10 GB volume: one container per
  system holding both databases is the droplet layout every system
  adopted, M37; two hosts only when a system outgrows it), `nats` (`-js`, file
  store, 2 GB), `api` (×1 on the droplet; `--scale api=2` elsewhere),
  `deliver`, `web`, and `migrate` (a one-shot `cispctl migrate` the
  others depend on). Resource limits per §9. Health checks on
  `/readyz`. Daily `pg_dump` of both databases to the droplet's backup
  volume with 14-day rotation and a weekly restore test
  (`cispctl verify-backup`): predecessor S-22, S-23.
- **Caddy** (shared, composed by the private deployment repository
  `uspace-deploy` from each system's snippet; D1): `uspace-cisp.chikox.net`
  routes `/v1/*`, `/public/*`, `/.well-known/*`, `/healthz` → `api`;
  `/v1/stream` with WebSocket upgrade; `/_bff/*` and everything else →
  `web`; `/metrics` not routed; public cache on `/public/*`; mTLS
  `client_auth verify_if_given` with the subject header forwarded on the
  ANSP routes and stripped elsewhere (§8.3); `/basemap/*` served by
  `file_server` from the shared read-only basemap volume the lab builds
  (M38: one copy for five systems; the kit's map loads it from
  `/basemap/`, and every `web/` sets the kit's CSP so no third-party
  tile or font request ever leaves the browser). The snippet in
  `deploy/caddy/Caddyfile.snippet` is the reference copy the deployment
  repository composes; nothing here hardcodes a hostname (`06 §4`):
  `CISP_PUBLIC_BASE_URL` and `CISP_ISSUER_URL` are environment.
- **Configuration** (`deploy/.env.example`, every variable documented,
  validated at start, secrets redacted in logs): `CISP_DATABASE_URL`,
  `CISP_TIMESERIES_URL`, `CISP_NATS_URL` and credentials file,
  `CISP_TOKEN_ISSUER`, `CISP_TOKEN_JWKS_URL`, `CISP_AUDIENCES`
  (comma-separated hosts), `CISP_AUTHORITY_CLIENT_ID`,
  `CISP_ANSP_CLIENT_ID`, `CISP_ANSP_JWKS_URL` (the ANSP's publication
  key), `CISP_ANSP_MTLS_SUBJECT`, `CISP_MTLS_MODE` (`required|off`),
  `CISP_SIGNING_KEY_FILE`,
  `CISP_SIGNING_KID`, `CISP_SIGNING_KEY_PREV_FILE`,
  `CISP_SESSION_KEY_FILE`, `CISP_SECRETS_KEY_FILE`, `CISP_PUBLIC_BASE_URL`,
  `CISP_ISSUER_URL`, `CISP_READ_MAX_AGE_S` (60), `CISP_PUBLIC_RPM`,
  `CISP_MAX_PUBLICATION_BYTES`, `CISP_MAX_SUBSCRIPTIONS_PER_CLIENT`,
  `CISP_DELIVERY_LOG_RETENTION_DAYS`, `CISP_ALLOW_PRIVATE_CALLBACKS`,
  `CISP_ALLOW_INSECURE_CALLBACKS`, `CISP_OTEL_ENDPOINT`, `CISP_LOG_LEVEL`,
  `CISP_BRANDING_FILE` (console name, logo path, contact: branding is
  configuration), `NEXT_PUBLIC_API_BASE_URL` for `web`.
- **Production** is separate state infrastructure; the compose file is
  the demo. A third-party CISP replaces this one behind the same
  `api/openapi.yaml` and the lab suite (`00 §7`).

---

## 12. Milestones (spec `07` Phase 2)

| Milestone | Done when (spec) | Work packages |
|---|---|---|
| **C-M1 Publish and read** (first demo) | the authority-role test client publishes an ED-318 zone set and a U-space airspace with its Art. 3(4) requirements, adjacency and a USSP list with terms; `GET /v1/zones?bbox=` returns them with `ETag` and update time; a second publication yields a diff in `/v1/changes`; a webhook subscriber receives the signed change within 1 s; the public map shows the zones; an ED-269 file round-trips through the import mapping | WP-0, 1, 2, 3, 4, 6, 9, 10, 12 |
| **C-M2 Restrictions** | ANSP-role client activates a restriction; subscribers notified within 1 s; `ended` and `cancelled` lifecycle; history by version and `at=`; (the same restriction as an F3548 constraint in the lab DSS is the ANSP's and the lab's work, consumed here as an end-to-end check) | WP-5, 7 |
| **C-M3 Hardening** | 60 s reconciliation pull proven by killing the subscriber during a change; delivery log; rate-limited public API; CISP console (publications, subscriptions, deliveries) | WP-8, 11, 13 |
| **U-M1 `uspace-ui` first release** (external, with C-M1) | the CISP public map and console are built on the kit and nothing else | WP-9 consumes it from npmjs, starting on the kit's `0.1.0-rc` (ui WP-13a) and pinning `0.1.0` at U-M1; §15 Q14 |

Tagging: `v0.1.0` at C-M1, `v0.2.0` at C-M2, `v1.0.0` at C-M3 with the
OpenAPI `/v1` declared stable (additive changes only thereafter, `00 §7`).

---

## 13. Work packages and waves

Each WP has a brief in `docs/WORKPACKAGES/WP-<k>.md` that is complete on
its own: branch, milestone, exclusive ownership, dependencies, read-first
list, what to build, done-when, safety notes, commits. Sized so one
agent finishes it in one PR. Done-when always includes: `make lint`
clean with the pinned linters, `go test -race -shuffle=on ./...` green,
the integration job green, the OpenAPI and generated code in sync,
coverage ≥ 85 % of the owned packages, every new counter in the status
line, `CHANGELOG.md` line, PR body with the commands run and their last
lines (E-04).

| WP | Slug | Owns (exclusively) | Depends on | Milestone |
|---|---|---|---|---|
| WP-0 | `scaffold` | `go.mod`, `cmd/*` stubs, `internal/config`, `internal/obs` (base), `internal/httpapi` (base, health), `api/openapi.yaml` (skeleton), `Makefile`, `.golangci.yml`, `.gitleaks.toml`, `.github/workflows/`, `deploy/`, `Dockerfile`, `migrations/*/0001_init.sql`, `SECURITY.md`, `CHANGELOG.md` | — | C-M1 |
| WP-1 | `store-versions` | `migrations/relational/`, `migrations/timeseries/`, `internal/store/`, `internal/publication/`, `internal/bus/` (minimal publish), `cispctl migrate|rebuild-current` | WP-0 | C-M1 |
| WP-2 | `auth-jws` | `internal/auth/` (machine side), `internal/jws/`, `/.well-known/jwks.json`, `cispctl rotate-key` | WP-0 | C-M1 |
| WP-3 | `publications` | `internal/dataset/` (zones, uspace_airspace, ussp_list rules), `PUT /v1/publications/*`, attempts, heartbeat, `schemas/cis/ussp_list`, `schemas/cis/uspace_requirements` | WP-1, WP-2 | C-M1 |
| WP-4 | `read-api` | `GET/HEAD /v1/{dataset}`, `/versions`, `/changes`, `/status`, `/public/v1/*`, `internal/applicability/`, the snapshot cache and stale serving | WP-1, WP-2 | C-M1 |
| WP-5 | `restrictions` | `internal/restriction/`, `/v1/restrictions*`, the `restrictions` dataset rules in `internal/dataset`, expiry job, publisher staleness, `schemas/cis/restriction` | WP-1, WP-2 (and WP-3's heartbeat endpoint, taken over) | C-M2 |
| WP-6 | `subscriptions-deliver` | `internal/subscription/`, `internal/deliver/`, `cmd/deliver`, `/v1/subscriptions*`, `schemas/cis/change`, `test/e2e/subscriber` | WP-1, WP-2 | C-M1 |
| WP-7 | `stream-status` | `internal/stream/`, `WS /v1/stream`, `internal/bus/` (reconnect policy, degraded start), `internal/obs/` (status line, metrics catalogue, tracing wiring) | WP-6 | C-M2 |
| WP-8 | `console-api` | `internal/console/`, `internal/auth/` (sessions, argon2id, TOTP), `/v1/console/*`, `cispctl create-account|export-audit|verify-audit` | WP-1, WP-2 | C-M3 |
| WP-9 | `web-scaffold` | `web/` (Next.js, kit, i18n, generated types, BFF, lint rules, CI job) | WP-0, `uspace-ui` U-M1 | C-M1 |
| WP-10 | `web-public-map` | `web/app/(public)/*`, map layers and legend, version banner, WS live refresh | WP-9, WP-4 | C-M1 |
| WP-11 | `web-console` | `web/app/(console)/*`: login, publications and diff, restrictions, subscriptions and deliveries, status, audit | WP-9, WP-8 (and WP-6 for deliveries) | C-M3 |
| WP-12 | `ed269-bridge` | `application/vnd.ed269+json` intake mapping, `?format=ed269` export, `cispctl ed269 convert` | WP-3, WP-4 | C-M1 |
| WP-13 | `hardening-release` | rate limits and Caddy cache verified, response signing on filtered reads (if kept), chaos e2e, `make conformance`, SBOM and cosign in CI, Dependabot, `docs/RUNBOOKS/`, `v1.0.0` | every other WP | C-M3 |

Waves (what runs in parallel):

```
wave 1 (1 agent):          WP-0
wave 2 (3 agents):         WP-1   WP-2   WP-9 (starts on the kit's 0.1.0-rc from npmjs; pins 0.1.0 at U-M1)
wave 3 (5 agents):         WP-3   WP-4   WP-5   WP-6   WP-8      (all need 1 and 2)
wave 4 (4 agents):         WP-7 (6)   WP-10 (9, 4)   WP-11 (9, 8, 6)   WP-12 (3, 4)
tag v0.1.0 = C-M1 when WP-0..4, 6, 9, 10, 12 are merged and the e2e webhook latency is printed
tag v0.2.0 = C-M2 when WP-5 and WP-7 are merged
wave 5 (1 agent):          WP-13 -> v1.0.0 = C-M3
```

Critical path: **WP-0 → WP-1 → WP-3 → WP-4 → WP-10** for the first demo,
with **WP-6** (webhook ≤ 1 s) beside it from wave 3; `uspace-ui` U-M1 →
WP-9 → WP-10 is the external leg. WP-1 is reviewed first: `publication`
and `store` are what every later package writes through.

Conflicts are avoided by exclusive ownership. Shared files:
`api/openapi.yaml` (each WP adds its own paths under its own tag; merges
are append-only and the generate check catches a stale regeneration),
`CHANGELOG.md` (one line per WP under Unreleased), `internal/httpapi/routes.go`
(one registration line per WP), `deploy/.env.example` (one block per WP).

---

## 14. Engineering standards

### 14.1 Lint and format
`gofmt -l .` empty; `go vet ./...`; `staticcheck` and `golangci-lint`
pinned to the versions `uspace-core` pins (v0.8.1, v2.14.0) with a
`.golangci.yml` derived from core's: `errorlint`, `exhaustive`,
`forbidigo` (no `panic` on data paths, no `fmt.Print*` outside `cmd/`,
no `log.*`: `slog` only, no `os.Exit` outside `main`), `gosec`,
`gocritic`, `revive` exported-doc rules, `misspell` UK, `nolintlint`,
`unparam`, `prealloc`. Generated code (`gen/`, `*.sql.go`) exempt from
style linters, never from `vet`. `go mod tidy` a no-op. `make tools`
installs exactly the pinned versions; `make lint` refuses another.

### 14.2 Naming and units
Units and datums in every name (E-13): `lower_m`, `lower_ref`,
`starts_at`, `stale_after_s`, `latency_ms`; in Go `LowerM`, `StaleAfterS`
or `time.Duration`. GeoJSON order converted at the parser boundary only
(core does it). AMSL and AGL never meet; the CISP never computes a
height.

### 14.3 Errors and logging
`*core.FieldError` and `*ed269.Problems` for everything untrusted; HTTP
errors as `problem+json` with the field path. `log/slog` JSON with
`request_id`, `client_id`, `dataset`, `version`, `subscription_id` as
context; the first occurrence of a refusal logged, then at most one line
per interval per key with the count (E-09). A library package never
logs.

### 14.4 Bounds and no panics
Every bounded structure (snapshot cache, stream hub clients, in-flight
deliveries, nonce-like `jti` memory for console sessions, problem lists)
has an explicit limit and a test past it (E-10). Request bodies are
capped with `http.MaxBytesReader`. `forbidigo` forbids `panic`.

### 14.5 Time
`time.Now` injected (`Clock` interface) in every package that reasons
about time; tests never sleep for real time beyond 100 ms; applicability
is evaluated at the instant asked (`at=`) in UTC with an aware time
(T-09).

### 14.6 Testing rules
E-01 (presence beside absence), E-02 (run the branch that says nothing is
wrong: the healthy status line, the degraded one, the empty dataset),
E-04 (a PR says what was run and seen; a skipped job is reported as
skipped), E-10, E-11. Vector adapter tests are `TestVectors<File>` in
`<pkg>/vectors_test.go` using `vectors.Load` and `RunOwned(t, "cisp",
...)`.

### 14.7 Git
Branch per WP `feat/WP-<k>-<slug>`; Conventional Commits with the WP and
milestone in brackets: `feat(publication): diff a dataset against its
previous version [WP-1 C-M1]`; scopes are the package or process names
(`api`, `deliver`, `store`, `publication`, `dataset`, `restriction`,
`subscription`, `jws`, `auth`, `web`, `deploy`, `ci`); one logical change
per commit; a dependency with its reason in the body; **no AI attribution
of any kind**; never force-push a shared branch; the owner merges.

---

## 15. Open questions and decisions

Where the spec is silent or disagrees with the code that exists, the
plan proceeds on the answer below and marks it. The cross-plan
reconciliation of 2026-10-02 (its §1 mismatches M1-M38 and §2
decisions) settled every question a coordinator could settle; those
rows are **decided** and the plan body already applies them. The rows
marked **open** need a human (GCAA, the DPO, the owner's money) and
stay open: the plan builds on the stated demo default, which is a
placeholder, never the policy answer.

### 15.1 Decided

| # | Gap | Decision | Reason |
|---|---|---|---|
| Q1 | `02 F1`/`04 §3.4` name ED-318 collection metadata `{creationDateTime, updateDateTime, originator}`; `uspace-core/ed318.Metadata` has `validFrom, validTo, issued, provider, description`. Where do "time of update" and "version number" (Art. 9(2), `02 F3`) travel? | **Follow core** (M15). Every served collection sets `metadata.issued` = the version's `received_at` and `metadata.provider` = the publisher, and carries top-level `cis_dataset`, `cis_version`, `cis_updated_at` (core keeps them in `Extra`); `ETag` and `X-CIS-Version` say the same. The authority's export uses the same names. Spec erratum for `02`/`04` (lab WP-L4). | Core is the parser everyone runs; the spec names are ED-269-era text. |
| Q2 | `02 F2` lists restriction states but not who flips them. | The ANSP declares states; the CISP only expires `active → ended (ended_by: expiry)` at `ends_at` and emits `restriction_expired`. A `planned` restriction past `starts_at` without an `activate` stays `planned` (consumers judge `limitedApplicability` themselves) and the console flags it (D5). | The ANSP is the master (`03 §4`); the CISP never edits content. |
| Q3 | `02 F2` failure rule flags "source stale" after 60 s of missed ANSP heartbeat, but no heartbeat endpoint is specified. | `POST /v1/publishers/heartbeat` `{sent_at, active_refs?: []}` **every 15 s** by every publisher, stale after 60 s (three misses); staleness per publisher in `/v1/status` and in the dataset metadata (`cis_publisher_stale_since`). The authority adds the job to its WP-6; the ANSP sends `active_refs` (M3). | One endpoint for both publishers; three misses = the spec's 60 s. |
| Q5 | The USSP list is produced by the authority but its shape is defined nowhere. | The CISP owns `cis/ussp_list/v1` (`api/openapi.yaml` + `schemas/cis/ussp_list/v1.json`); the authority validates its output against a pinned copy in CI (M7, M14). `ussp_id` is the authority's `certificates.code` (≤ 8 upper-case alphanumerics, unique, assigned at issue; `USSP-DEV` in the lab), which is also the USSP's `USSP_SYSTEM_ID` (M8). | API-owner rule: the body belongs to the repo whose OpenAPI carries it. |
| Q6 | The Art. 3(4) requirements block inside `USPACE` `extendedProperties` has no schema; and a restriction must name a U-space airspace that may not be designated. | The CISP owns `cis/uspace_requirements/v1` and validates the four blocks plus `services_required` and `adjacent`. A restriction whose `uspace_airspace_id` matches no current `USPACE` feature is refused; the ANSP's `require_uspace_airspace=false` option is dropped and **the lab publishes a designation for every demo** (C-M2, N-M1) (M9). | API-owner rule; ATS.TR.237 applies inside U-space airspace; strict on both sides. |
| Q7 | The exact `aud` string for the CISP and the client id values. | **`aud` = the host of the target's published base URL** for every machine token in the ecosystem (`uspace-cisp.chikox.net` here); the verifier accepts the list `CISP_AUDIENCES` (public host + a lab alias). Client ids are one per calling system: `authority-01`, `ansp-01`, `ussp-<code>-01`, `lab-01`; the CISP binds publishers by `sub` ∈ configured ids as planned (M18, M24). | InterUSS convention (F3411/F3548 discovery yields only a `uss_base_url`; DSS `accepted_jwt_audiences` are hosts); one client per calling system. |
| Q8 | Detached JWS for F1: header name, encoding, which key. | `X-JWS-Signature: <protected>..<signature>` per RFC 7515 Appendix F with RFC 7797 `b64:false` over the exact body bytes; protected header `alg RS256`, `kid`, `iat` (≤ 5 min skew), `crit: ["b64"]`. **Key = the publisher's own signing key from that system's `/.well-known/jwks.json`**: the authority's token-service JWKS for the authority (`use: sig`, distinguished by `kid`), **the ANSP's own JWKS for the ANSP's restriction bodies** (`CISP_ANSP_JWKS_URL`). Adopted by the authority and the ANSP (M26). | Standard detached JWS; provenance survives the CISP. |
| Q9 | Webhook JWS claims (`02 F3`: "receivers verify `iss` and `aud`"). | Compact JWS, `Content-Type: application/jose`, payload = `cis/change/v1` + `iss` (the CISP's issuer URL), **`aud` = the host of the `callback_url`**, `sub` = subscription id, `iat`, `jti` = delivery id (M19). Receivers (all at `POST /v1/cis/notifications`, M1) allow-list the CISP and the ANSP as issuers, honour `pull_url` only on the issuer's host, and acknowledge `subscription_test`, `republished` and unknown reasons with `204` without pulling (M5, M16). | RFC 7515; one verifier; the audience rule of Q7 applied to webhooks. |
| Q11 | mTLS for the ANSP: at Caddy or in Go. | At Caddy (`client_auth verify_if_given` + the mTLS CA) with the subject forwarded in a stripped header; Go binds it on the mTLS routes. `CISP_MTLS_MODE = required | off`, the one flag name every repo uses; `off` on the staging droplet and in the lab, printed at error level every period. The Caddy rule is composed by `uspace-deploy`; `deploy/caddy/` keeps a reference copy (M25). | Shared Caddy terminates TLS; `api` must not. |
| Q12 | TimescaleDB at the CISP: the stack mandates it, the CISP has one time series. | Keep the database pair (D9); on the droplet one `timescale/timescaledb-ha:pg16` container holds both databases, the layout every system adopted (M37). | Uniform layout and tooling; `delivery_attempts` is a true time series. |
| Q13 | `01 §2`: `publisher_admin` "cannot edit content, only manage subscriptions and re-publish". What does re-publish mean? | A new change record `reason: republished` for the **current** version so subscribers re-pull; never a content change. Receivers acknowledge it without pulling (M16). | `01 §2` role text. |
| Q14 | `uspace-ui` is not released; WP-9 is its first consumer. How is it distributed? | **npmjs only**, exact pins, no git-tag installs. The kit publishes `0.1.0-rc.N` as soon as its WP-0..WP-5 merge (ui WP-13a); WP-9 starts on the rc and bumps to `0.1.0` at U-M1. `RestrictionLayer` ships in the kit's `0.1.0`, so the CISP pins ≥ 0.1 throughout (M32, M33). | A git-tag dependency needs a `prepare` build with full devDependencies inside every Docker image. **Amended by the owner on 2026-10-02** (the kit's D10): the kit is a GitHub Release tarball, not on npmjs; the web pins the asset URL exactly (`…/releases/download/v0.1.0-rc.1/rootxkit-uspace-ui-0.1.0-rc.1.tgz`), the lockfile pins its integrity, and the tarball is built output (no `prepare`), so the objection to a git dependency does not apply. |
| Q17 | `03 §6` says DAR identifiers are prefixed `DAR-`, but ED-318 caps `identifier` at 7 characters (core enforces). | The ANSP mints **`DAR` + 4 base-36** (no hyphen; 1.6 M ids; the prefix stays readable). **The CISP enforces only `≤ 7` and uniqueness across datasets (D8), never a prefix.** Spec erratum for `03 §6` (M10). The `D` + 6 scheme proposed earlier is withdrawn. | 7-char cap in ED-318; one scheme across the ANSP and the CISP. |
| Q18 | `alert_lifecycle.json` lists `cisp` among its owners; the CISP has no monitor. | The lab drops `cisp` from that file's owners (lab WP-L4; an editorial vector change, no behaviour change) and keeps `cisp` on `ed269_parse`, `zones_applicability`, `geodesy`, `jwt_verify`, `ed318_roundtrip`. | The CISP raises no alert. |
| Q19 | `00 §6.1` lists a CISP package `ed318`. | D1: no such package here; `uspace-core/ed318` is used and the dataset rules live in `internal/dataset`. Spec table updated by lab WP-L4. | Judgement once, in core. |
| Q20 | Detached-JWS verification and compact-JWS signing are not in `uspace-core/auth`. | Core `v1.1.0` (core WP-14, additive) ships `auth.KeyRing`, `SignDetached`, `VerifyDetached`, `SignCompact`, `VerifyCompact`. **WP-2 may land first on `internal/jws`** (it is on the critical path) and a follow-up switches to core and removes the direct `jwx` import; the ANSP and the authority wait for core (M27). | One JOSE implementation; the CISP's first demo does not wait. Applied: WP-2 built `internal/jws` on core `v1.1.0` from the start (a thin adapter: PEM loading, the 3072-bit floor, JWKS bytes and ETag, one verifier per publisher), so no follow-up switch is needed. |
| Q21 | `03` preamble says `golang-migrate`; the owner's stack says goose. | goose (D11); version tables `goose_db_version_relational` / `goose_db_version_timeseries` in every repo; a `migrate` subcommand plus a one-shot compose service; long-running processes never migrate (M36). Spec erratum for `03`. | Owner's stack; the table name is the wrong-database guard. |
| Q22 | Response signing of filtered reads (`bbox`, `at`, `since_version`) by the CISP's key. | Unfiltered responses are signed (the stored snapshot); filtered ones carry `ETag` and version and are unsigned in C-M1; WP-13 adds on-the-fly signing **only if the owner asks**. | Annex III A(4) is met by the signed full dataset the consumer can always fetch. |
| Q23 | `02 §3 cisp` lists `/v1/stream` under `api`; `05 §2` lists only `deliver` as the hot path. | The WS hub stays in `api`; per-instance state is acceptable because the stream has no history. | Low rate, no history. |
| Q24 | `01` C1: operators read the CIS directly or through their USSP? | Operators read `/public/v1/*` or their USSP's geo-awareness; no operator client id exists at the CISP. | `01 §2` users table. |
| Q25 (from ui Q3) | A console wants to dim a zone that does not apply now; `?at=` filters, so that needs two fetches. | `?applies_at=<RFC 3339>` annotates `extendedProperties.cis_applicability` ∈ `applies` / `not_applicable` / `unknown` without filtering, beside the filtering `?at=`; additive; the authority adds the same to `GET /v1/zones/export` (M17). | A console must show "not applicable now" without judging. |

Cross-cutting decisions applied in this plan that no CISP question
asked: the problem body `{type, title, status, detail, instance,
errors: [{field, reason}], truncated?}` with `type` slug URIs (M28,
§6); the common envelope and `console/status/v1` on every browser-facing
WebSocket frame (M29, §6.5); the session JWT shape `scope = "session"`,
`roles[]`, `realm`, `aud` = own host (M20) and the cookie names
`uspace_session` / `uspace_csrf` (M21, §6.6); cookie on the same-origin
WS upgrade, no ticket (M22); the scope catalogue held by the authority
(M23, §8.2); `pnpm` (M34, §4); schema ownership and the lab's
`schemas/common/` (M14, §6.7); the sibling-copy mechanism `api/clients/cisp.yaml`
+ `SOURCE` until the lab aggregate (M11, M31); the shared basemap volume
and the kit's CSP (M38, §11).

### 15.2 Open (owner-only; the plan builds on the demo default)

| # | Gap | Demo default until answered | Who answers, and why only they can |
|---|---|---|---|
| Q4 | ATS.OR.127 operational data items (`02 F2`, `01` C2) have no format or scope. | Reserve the dataset name `ats_operational_data` and the scope `cis.publish:ats_data` (in the authority's catalogue, M23); **no code** until the SLA names the items; a later WP after C-M2, so nothing assumes it. | GCAA and Sakaeronavigatsia: the Annex V SLA. |
| Q10 | What the public subset excludes (`01` C1). | Full `zones`, `uspace_airspace`, `restrictions`; `ussp_list` without `base_url` and `certificate_id`; no history, no change cursor, no subscriptions (§6.4). | GCAA decides what is public. |
| Q15 | Retention of the delivery log and of refused attempts. | 90 days `delivery_attempts` (Timescale retention policy), 1 year `publication_attempts`; publications and audit indefinite (`05 §4`); every figure a configuration value. | The DPO (`08` Q8): legal retention. |
| Q16 | Signing-key custody (`06` T4: HSM/KMS, 90-day rotation). | File-mounted PEM on the droplet with `cispctl rotate-key` and a two-key JWKS overlap; the code reads a PEM path and nothing else. | The state: production custody. |
| Q26 (cross-plan, new) | Droplet sizing: five systems, the InterUSS DSS with its datastore and a lab stack on 2 vCPU / 3.8 GB; the per-system budgets (CISP ≤ 0.6 GB among them) already exceed it. | The CISP keeps its §9 budget; the lab's L-M1 waits for a resize to ≥ 4 vCPU / 8 GB or a second droplet for the DSS and the lab. | The owner: money. |
| Q27 (spec Q16) | When production domains and state hosting take over from `*.chikox.net`. | Staging on the droplet until A-M5; `CISP_PUBLIC_BASE_URL` and `CISP_ISSUER_URL` are the only places a hostname lives. | GCAA. |
| Q28 (WP-1, proposed) | The plan names the members of `cis/change/v1` (section 6.7) but not their values on the bus, and `schemas/cis/change/v1.json` does not exist yet. | WP-1 publishes `schema: "cis/change/v1"`, `msg_id` = the change cursor in decimal (also the `Nats-Msg-Id`), `producer: "uspace-cisp"`, `etag` as in the `ETag` header, `pull_url` = `<CISP_PUBLIC_BASE_URL>/v1/<dataset>?since_version=<version - 1>`, `bbox` = `[min lng, min lat, max lng, max lat]` (GeoJSON order) and absent for the whole dataset. WP-6 writes the schema and may change any of these before C-M1 closes. | The bus body exists from WP-1; the webhook body is WP-6's and must equal it. |
| Q29 (WP-1, decided in code) | `REVOKE UPDATE` on the insert-only tables makes a foreign key into them impossible: PostgreSQL checks a reference with `SELECT ... FOR KEY SHARE` as the referenced table's owner, which needs `UPDATE`. | No foreign key points at `publications` or `changes` (`features`, `publication_attempts`, `changes`, `restriction_events`, `deliveries`); the transactions that write both rows hold the reference. References to writable tables (`datasets`, `restrictions`, `subscriptions`, `accounts`) stay foreign keys. | Insert-only (06 T7) is the stronger guarantee; a column-level `UPDATE` grant to allow the lock would reopen updates. |
| Q30 (WP-2, proposed) | The HTTP status of a publication body whose `X-JWS-Signature` is missing or does not verify; the brief does not name it. | **403** `problem+json`, slug `signature` (M28 names the slug), `errors[0].field` = the part core named (`header`, `alg`, `b64`, `crit`, `kid`, `signature`, `iat`, `body`). The caller is already authenticated by its token, so no `WWW-Authenticate` challenge applies; 503 `signature_unavailable` when the publisher's JWKS is not configured. | The authority and the ANSP read the slug, not the status; WP-3 and WP-5 may change the status before C-M1 closes. WP-3 kept 403 (its brief said 401): the guard is WP-2's and shared with WP-5's routes, and a 401 would invite a token retry that cannot help. |
| Q31 (WP-2, decided in code) | Two configuration names the WP-2 brief leaves open: the skew variable is named `CISP_PUBLISHER_SIGNATURE_MAX_SKEW` without a unit, and the JWKS disk copy (`local/jwks-cache.json`) has no variable. | `CISP_PUBLISHER_SIGNATURE_MAX_SKEW_S` (seconds, default 300; hard rule 7: units in every name) and `CISP_JWKS_CACHE_FILE` (default `local/jwks-cache.json`). In the read-only container of `deploy/compose.yml` the copy cannot be written; each failed write is counted (`jwks_cache_write_failed`) and WP-13 mounts a writable path for it. | Units in names; a path is configuration (hard rule 6). |
| Q32 (WP-3, proposed) | Where the `cis/uspace_requirements/v1` block sits in a USPACE feature: the brief says `extendedProperties` "must hold the block", refuses unknown members "under that block" and lets "other `extendedProperties` members pass through", which only works for a nested block; core's `ed318_roundtrip` vector carries the same members flat in `extendedProperties`. | The block is the member **`extendedProperties.uspace_requirements`** (no `cis_` prefix: the authority writes it, the CISP does not add it); flat members beside it pass through untouched. The vector test builds the nested block from the vector's flat members. The authority's export (its WP for zones) writes the nested member and validates it against the pinned `schemas/cis/uspace_requirements/v1.json`. | A closed block needs a boundary; `cis_*` members are the CISP's own (`cis_restriction`, `cis_applicability`). |
| Q33 (WP-3, decided in code) | Three things the WP-3 brief needs that the WP-1 schema and store did not have. | (1) Migration `0007_publisher_heartbeat` adds `publishers.last_heartbeat_sent_at` and `active_refs` (jsonb array; null when none): `last_heartbeat_at` is the CISP's clock on receipt and staleness is judged on it. The heartbeat upserts the caller's row; no audit row (one every 15 s per publisher). (2) `PublishInput.ExpectedVersion` makes `If-Match` hold under the dataset lock (`ErrVersionMismatch` → 412). (3) The `ussp_list` snapshot is the canonical list with `cis_dataset`, `cis_version`, `cis_updated_at`, and a re-publication is unchanged when the canonical lists are equal (WP-1 had used the body for both). In the vector test a `DAR` feature is first refused in `zones` naming its reason and then published without `DAR`: dynamic restrictions are the ANSP's dataset (WP-5). | A migration number may collide with WP-5's (renumber on merge); the rest are additive. |
| Q34 (WP-4, decided in code; the owner may change any before C-M1 closes) | What the WP-4 brief leaves open about the reads. | (1) `net/http`'s `ServeMux` refuses `/v1/{dataset}...` beside `/v1/publications/{dataset}` and `/v1/status` (neither pattern is more specific), so the router registers the dataset-first operations once per dataset and keys authentication, caps, logs and metrics on the operation; an unknown dataset is the router's 404 `not_found`. (2) A dataset never published is 404 `no_version` with `ETag: "<dataset>:0"`. (3) `since_version` on `ussp_list` (no features to diff) answers the whole list after the version check; `since_version` with `bbox`, `at` or `applies_at` is 400 `filter_conflict`; HEAD takes no filter. (4) The public USSP list is a projection, so it carries no `X-CIS-Signature` (Q22: derived reads are unsigned in C-M1). (5) `Last-Modified` is the version's `received_at`; `X-CIS-Age-S` is the seconds since the instance last read the current versions. (6) Status: a publisher is stale when its last heartbeat is older than its row's `stale_after_s` (60 s), `stale_since` = that heartbeat plus `stale_after_s`; a configured publisher never heard from is stale without `stale_since`; with the database down no publisher is listed and `database` is degraded. (7) The rate limit is per client address (an IPv6 address whole, not its /64); behind a proxy in `CISP_TRUSTED_PROXY_CIDR` (a comma-separated list) the client is the rightmost `X-Forwarded-For` entry that is not a trusted proxy; HEAD and 304 have their own bucket at ten times the rate and the burst. The brief's "61st full GET in a minute → 429" does not hold with a burst of 10 (a minute allows 60 plus the burst); the tests assert the bucket arithmetic instead. (8) The feature's place for daylight events is the planar area centroid PostGIS's `ST_Centroid` computes, computed in `internal/applicability` from the parsed geometry; it places events, it judges nothing. (9) `schemas/cis/change/v1.json` is exported from the OpenAPI `Change` component with the members of §6.7 and the values of Q28; WP-6 adopts it. | The routes are the brief's; the rest are what the brief needs and does not say. |
| Q35 (WP-5, decided in code) | The brief puts the list of restriction heads at `GET /v1/restrictions?state=&airspace=&at=`, but that method and path is already the WP-4 dataset read of `restrictions` (registered per dataset, Q34), which every consumer reads as it reads zones (D4). | The heads are at **`GET /v1/restrictions/heads`**; `GET /v1/restrictions` stays the ED-318 dataset read. `GET /v1/restrictions/{id}` sits beside the dataset-first `GET /v1/restrictions/versions`: the server's router prefers the dataset route (its literal segment), so a restriction is never named `versions` or `heads` by its ULID, and an `ansp_ref` spelt so is reached by `PATCH ?by=ansp_ref` but not by `GET ?by=ansp_ref`. The test harness routes the spec the same way (OpenAPI routers that prefer the first literal segment would pick `{id}`). | One method and path is one operation; the dataset read is the published contract. |
| Q36 (WP-5, proposed; a contract with the ANSP, to the cross-plan reconciliation) | `PATCH` extend carries only `ends_at` in the brief, but the restriction's time is carried twice (`ends_at` and the feature's one `limitedApplicability` period), and consumers judge the feature with `ed318.Applies`: after an extend the published period would still end at the old `ends_at`, and the CISP may not edit a published feature (hard rule 2). | **An extend carries `ends_at` and the feature again**, its one period ending at the new `ends_at`, held to the same DAR rules and placement checks, and equal to the published feature but for that period's `endDateTime` (any other difference, the identifier included, is 409 `feature_changed`); an extend without it, and any other op with `ends_at` or a feature, is 400. The ANSP's planner adopts it. | A restriction that consumers drop before its `ends_at` is the hazard this system exists to prevent; republishing is the only way that keeps the bytes the ANSP's. |
| Q37 (WP-5, decided in code) | What the WP-5 brief needs and does not say. | (1) The restriction bodies are closed: an unknown member is 400 naming it (a misspelt `ends_at` must not read as absent), unlike the general "unknown request fields ignored" (§6). (2) Migration `0008_restriction_jobs` adds `job_runs` (the expiry's last run, read by every replica's status, so a replica that is not the leader never reports the job dead) and makes `restriction_events` insert-only. (3) The expiry's leader election is `pg_try_advisory_xact_lock` per run (transaction-scoped: a crashed leader never keeps the lock); what has expired, the `job_runs` time and the run's age are the database's `now()`, never a replica's clock; a `planned` restriction whose `ends_at` has passed is expired too (its window never applies again, so it leaves the current set); a run that cannot expire a restriction leaves it active, counts `restriction_expiry_failed` and degrades the component until a clean run. (4) The expiry's version body is the CISP's own `{op: expire, restriction_id, at}` with publisher `uspace-cisp`, no publisher signature, event actor `system`. (5) `cis_publisher_stale_since` is present only while the ANSP is stale, `null` when it has never been heard from; it is added to the unfiltered dataset read (re-signed at serve time, `no-store`) and the filtered one, never to a delta (`DatasetDelta` is closed) or a HEAD. (6) The status line gains a warning level (`internal/obs` `SetWarning`): the ANSP's staleness warns, never errs. (7) A refused restriction op is a `publication_attempts` row of `restrictions` (Annex III A(5)); a 404 is not. (8) WP-6 is not merged, so `test/e2e/restriction_latency_test.go` with its subscriber container is not written; the CIS side of C5 is measured from the commit to a subscriber of the bus in the integration suite, printed and held under 2 s. | The routes and the rules are the brief's; the rest are what they need. |
| Q38 (WP-6, decided in code; the webhook contract goes to the cross-plan reconciliation) | What the WP-6 brief needs and does not say, and where it and core disagree. | (1) **The webhook JWS is core's compact delivery form**: `KeyRing.SignCompact` writes the payload `{iss, aud, sub, iat, jti, body}` with the `cis/change/v1` record in `body`, not beside the claims, and **no `exp`** (core: a delivery is single use, `jti` is its id, and `CompactVerifier` refuses an `iat` older than 5 min, which bounds it as the brief's `exp = iat + 5 min` would). Receivers verify with core's `CompactVerifier`. (2) `aud` is the callback URL's host name, lower-case, without its port (`https://ussp.example.ge:8443/...` and `https://ussp.example.ge/...` both give `ussp.example.ge`). (3) In a webhook `producer` is `cisp/deliver-<instance>` (host and pid); the bus, `/v1/changes` and the stream keep `uspace-cisp`; the `Change` schema takes both (a pattern instead of the `const`). (4) The verification ping is a delivery of no change: `deliveries.change_id` is nullable and `delivery_attempts.change_id` is `0` (migration `0009_deliver`); its `cis/change/v1` record has `msg_id` = the delivery id (a ULID), `dataset` = the subscription's first, `version` and `etag` its current version (`0` before the first, so `version` takes `minimum: 0`), empty `feature_ids` and `removed_ids`, `at` = when it was queued; `version` and `msg_id` widen within v1 (Q28 let WP-6 change them before C-M1 closes). (5) `PATCH` replaces the members given, `bbox: []` removes the box; a changed `callback_url` and any `PATCH` of a suspended subscription return it to `pending_verification` with a new ping; `DELETE` answers 200 with the deleted subscription and expires its open deliveries; another client's or a deleted subscription is 404; a retry is 202, 409 `delivering` while an attempt is in flight; the deliveries list says whether its attempts were read (`log`: `complete`, `unavailable`, `not_configured`). (6) Registration judges the URL as written and, unless `CISP_ALLOW_PRIVATE_CALLBACKS`, every address its host resolves to now (a host that does not resolve is accepted and its ping says why); `deliver` checks the URL's shape again before each POST and judges the address it connects to at dial time; plain `http` needs `CISP_ALLOW_INSECURE_CALLBACKS` and a localhost target, single-label and `.local`, `.internal`, `.localhost` names need `CISP_ALLOW_PRIVATE_CALLBACKS`. (7) `deliver`'s consumer starts from the newest message on first creation (what came before is the scan's); the scan runs at start and every 10 s, looks at changes older than 2 s (the bus's head start) and moves its watermark only past changes older than 30 s (a change committed late under a lower cursor is still found); a claim leases its row for 30 s, so a killed instance's rows are sent by another; the sender polls every 250 ms and is woken by its intake. (8) The api reads the delivery log as `cisp_api` through `CISP_TIMESERIES_URL`, and reads `CISP_ALLOW_PRIVATE_CALLBACKS` and `CISP_ALLOW_INSECURE_CALLBACKS`; with `CISP_DATABASE_URL` set, `deliver` requires `CISP_SIGNING_KEY_FILE`, `CISP_SIGNING_KID`, `CISP_ISSUER_URL` and `CISP_PUBLIC_BASE_URL`. (9) The status line's components carry a one-line `summary` (`internal/obs` `SetSummary`): `deliver` prints "N queued, N due, oldest due N s, N in flight, broker S", the healthy "0 queued, 0 due" included. (10) The e2e (`test/e2e`, `make e2e`, its own CI job) runs PostgreSQL, NATS and the reference subscriber in compose and the api, `deliver` and `cispctl` as processes built from the checkout (their status lines are read and a JWKS on 127.0.0.1 serves the test issuer, which `CISP_TOKEN_JWKS_URL` accepts over plain http only on loopback); WP-13's chaos e2e drives the built images. WP-5's `test/e2e/restriction_latency_test.go` (Q37 (8)) is written here. | The routes and the rules are the brief's; core is the one JOSE implementation (Q20), so its compact form is the wire format. |
| Q39 (WP-7, decided in code; the frame extras go to the cross-plan reconciliation) | What the WP-7 brief needs and does not say, and where it and the lab's published `schemas/common` (lab commit `e62f076`) disagree. | (1) **The frames follow the lab's schemas**, copied read-only under `internal/stream/testdata/common` with the commit in `UPSTREAM`: `degraded[]` is slugs (`database`, `nats`, `jwks`, `publisher_stale`), not objects, and their since-times are the extra `degraded_since` (unknown members are ignored within a major); `nats` is a slug (`connected`, `reconnecting`, `never_connected`, `closed`, `not_configured`) with the extra `nats_since`; `datasets` is `{name: {version, age_s}}` with the version in decimal (`"0"` before the first); `sources[]` is empty, because the closed `source` enum has no CIS publisher, and the publishers with their heartbeat ages are the extra `publishers[]`; `producer` is `cisp/api` (the lab's pattern takes numbered instances only on both sides, `cisp-<n>/api-<n>`, so the brief's `cisp/api-<instance>` would fail it); `time_source` is `system`; `msg_id` is a ULID per frame. (2) **The hub reads the bus by a core NATS subscription on `cis.v1.change.*`** (it receives what JetStream stores, replays nothing and holds no consumer state) rather than an ordered consumer; the client re-subscribes on every reconnect, and `resync_since` is when the connection was lost (when the process started trying, for a first connection), or the last message received after a slow-consumer drop. (3) A frame that does not fit a client's queue is dropped and counted in its `dropped_frames`; a client still full at the next status tick is closed with 1013 and counted `stream_clients_dropped`. (4) Configuration: `CISP_NATS_CONNECT_TIMEOUT_S` (5, 0..60, `api` and `deliver`), `CISP_STREAM_MAX_CLIENTS` (1000), `CISP_STREAM_SEND_BUFFER_FRAMES` (64), `CISP_STREAM_STATUS_INTERVAL_S` (2), `CISP_STREAM_WRITE_TIMEOUT_S` (5), `CISP_STREAM_LIVE_MAX_AGE_S` (6, at least the status period), `CISP_STREAM_ALLOWED_ORIGINS` and `CISP_STREAM_PUBLIC` (true; the brief's "non-public deployment" as a flag). (5) The cookie counts only on an upgrade with an allowed `Origin`, and is verified by the shared verifier (`StrictSessionClaims`) with `scope` exactly `session`, `realm` `console` and a role; revocation is WP-8's (`stream.SessionVerifier` is the seam); on a public stream an invalid cookie is served as public and counted. An upgrade without `Origin` is not a browser's and is served. Refusals before the upgrade: 426 `upgrade_required`, 400 `bad_request` (`datasets`), 403 `origin`, 503 `stream_full`, 429 `rate_limited`. (6) `GET /v1/stream` is served by `Options.RouteHandlers` in place of the strict handler (the upgrade needs the connection), inside the whole chain and behind its fail-closed entry `httpapi.StreamAuth` (the per-IP limiter); without a hub the operation answers 503 `stream_unavailable`. (7) `policy_version` is `cfg-` and 12 hex digits of the SHA-256 of the redacted configuration. (8) The status line's counters are the counts since the previous line (Prometheus keeps the totals); the first line carries `start: true` and the `datasets` and `publishers` summaries; a metric outside `obs.Catalogue` is a warning naming it; the store's counters (`bus_publish_failed`, ...) are mirrored into Prometheus. (9) Spans start only under a recording server span (or from `deliver`'s own tracer), so with `CISP_OTEL_ENDPOINT` unset nothing is allocated; a delivery's `delivery_attempt` span starts at its claim. (10) The broker-outage integration tests run a `nats:2-alpine` container the test creates, stops and starts (`internal/natstest`); they skip, and say so, without docker. A publish that timed out while the broker was down may still be stored after the reconnect (the client buffers it); its change id deduplicates it. | The lab's schemas are the contract once published (the brief: "until the lab publishes them"); the rest is the brief's, with each bound a configuration value. |
| Q40 (WP-8, decided in code; the session shape is M20's, the rest is the CISP's own) | What the WP-8 brief needs and does not say. | (1) **The console is configured by `CISP_SESSION_KEY_FILE`, `CISP_CONSOLE_ISSUER` (new) and `CISP_SECRETS_KEY_FILE` together** (any one requires the others and `CISP_DATABASE_URL`; a session key without `CISP_SECRETS_KEY_FILE` refuses to start naming it). `CISP_SECRETS_KEY_FILE` holds one key per line (32 bytes, base64 or hex), the first sealing, all opening; a key's id is the first 8 bytes of its SHA-256 in hex (as uspace-ansp), and every sealed secret is `kid || nonce || ciphertext` with the kid and the account id as associated data, so a key rotates without re-encrypting (the single-key `CISP_SECRETS_KEY` and its kid-less format were never released, so nothing reads them: a development database sealed under them resets the accounts' MFA); with none set the api starts, every `/v1/console/*` operation answers 503 `console_unavailable` and the status line warns. The session key is RSA ≥ 3072 bits like the signing key; its `kid` is `session-` and 16 hex digits of the SHA-256 of its public key, so no kid variable is needed. (2) The TOTP replay memory is one integer per account, `accounts.totp_last_step` (migration `0010_console`), read and written under the account row's `FOR UPDATE`; a wrong or reused code counts towards the lockout, a missing one does not (`mfa_required`). An unknown or disabled username is 401 `invalid_credentials` after the same argon2id work; argon2id runs in at most 4 slots at once (503 `busy` past the request's deadline). The login limit (20 per address per 15 min) is the WP-4 limiter, per instance, through `CISP_TRUSTED_PROXY_CIDR`; the lockout is in the database. (3) Revocation: every replica reloads the revoked, unexpired jtis every 10 s (at most 10 000); past the bound, before the first load or 30 s after the last good one each check asks the database, and a session the database cannot answer for is 503 `session_check_unavailable`; a revoked, expired or unknown jti is 401 `session_revoked`, and so is a session unused for 30 minutes (idle end, M20): `sessions.last_seen_at` (migration `0011_session_idle`) moves on use, on the database's clock, at most once a minute per session and replica, and only while the session is live, so an idle session ends for good; a use that cannot be recorded is 503 `session_check_unavailable`. A changed role or status revokes the account's open sessions (the role travels in the token). (4) The login is `x-role: none`; every other console operation carries `x-role` and `security: consoleSession`; a machine token on a console route and a console session on a machine route are both 403. `GET /v1/status` stays machine-only; consoles read `GET /v1/console/status` (the status document and the instance's counters since start). (5) Resume returns a suspended subscription to `pending_verification` with a new ping (WP-6's rule for a suspended subscription); suspend takes an active or pending one; both are 409 `subscription_state` otherwise. Republish takes only the current version's publication id (409 `not_current`) and writes a change with no feature ids and no box (the whole dataset). The `reason` (1-500 characters) is required on the four actions; account changes are audited with the actor and the change, without a reason. (6) The diff lists at most 1000 features (`limit`, ≤ 5000) and 200 JSON Pointer paths per feature; the USSP list, which has no features, gets `body_paths`. (7) `cispctl export-audit` signs the exported file's bytes with the CISP's key ring (detached JWS, RFC 7797, in `<out>.jws`); `verify-audit --from --to` checks every row from the first in the range to the last by id (the chain is by id) and the link to the row before it. `cispctl partitions --ensure-months N` (default 3) is run monthly. | The session shape and the cookie names are the ecosystem's (M20, M21); the rest is what the brief needs. |
| Q41 (WP-9, decided in code; item (3) decided in code as proposed, the kit's and the authority's contract, additive within `/v1`) | What the WP-9 brief needs and does not say, and where it and the kit's `0.1.0-rc.1` disagree. | (1) **The BFF routes are the kit's**: `/_bff/login`, `/_bff/logout` and `/_bff/api/*` (the kit's `BFF_API_PREFIX`; its proxy refuses any other prefix), not the brief's `/_bff/proxy/*`; the proxy may reach `/v1/console/*` only and forwards the path as written (`/_bff/api/v1/console/me` → `/v1/console/me`). The App Router ignores `_` folders, so the routes live in `app/%5Fbff/`, configured by one module, `src/bff/handlers.ts`; `no-server-business-logic` allows a route file that module, the kit's `auth/server`, `next/server` and `src/api/types`, and the module the same less itself. (2) **Logout is composed from the kit's parts**: the kit's own logout POSTs, the CISP revokes with `DELETE /v1/console/session`, so `logout` is the kit's `checkCsrf`, its `forward` of a `DELETE` with the cookie as the bearer, and `clearSession` (the cookies are cleared whatever the API answers). (3) **MFA at sign-in: two steps (decided in code, the proposed answer, additive within `/v1`).** The kit's `LoginForm` and `login` send `{username, password}` and, when the API answers `{mfa_token, expires_at}`, `{mfa_token, code}` to `apiMfaPath` (the authority's shape). So `POST /v1/console/session` without `totp`, for an account with `mfa_required` and an authenticator, answers 200 `{mfa_token, expires_at}` and no session, and `POST /v1/console/session/mfa` `{mfa_token, code}` answers the session (201) as the one-step login does; `totp` in the one request still signs in, and an account with `mfa_required` and no authenticator stays 401 `mfa_required`. The challenge follows the reviewed uspace-authority `internal/authz` contract (`login_challenges`): 256 random bits, base64url, stored only as its SHA-256 hex, bound to the account, single use (`used_at`), expiring after `console.DefaultChallengeTTL` (5 min) on the database's clock, at most `DefaultMaxChallengeAttempts` (5) wrong codes; an unknown, used, expired or exhausted challenge, or one whose account was disabled since, is 401 `challenge_invalid` (field `mfa_token`), audited as `login_failed` when its account is known. The CISP's per-account lockout stays the judge of codes: a wrong or reused code through a challenge is 401 `invalid_totp`/`totp_reused`, counts on the challenge and towards the five-failure lockout (423 `locked`, even for a challenge opened before the lock), and the password step resets no count, so re-entering the password does not buy more guesses. Both steps run under `FOR UPDATE` in one order, the account's row and then the challenge's (the code step reads the challenge's account unlocked first), so the password step's delete of the account's spent and expired challenges (which bounds the table, E-10) cannot deadlock against a code step (an integration test reverses the order once and sees 40P01). The address limiter (20 per 15 min) counts both steps together; both are in the fail-closed route map with `x-role: none` (503 `console_unavailable` without the console). The BFF passes `apiMfaPath` and `mfaChallengeSecret` from `CISP_WEB_MFA_CHALLENGE_SECRET` (at least the kit's 32 bytes; `WEB_MFA_CHALLENGE_SECRET` in compose, empty by default); without it every `/_bff/*` route answers 503 `bff_unavailable` naming the variable, so there is no sign-in path that skips the step. The Playwright fixture server answers the two console endpoints and `me` in the spec's shapes and sets Caddy's `X-Forwarded-Proto` and `-Host` (one trusted hop) for the BFF's Origin check. (4) Next.js 16 names the middleware `proxy.ts`; the CSP carries a per-request nonce, so it is set there (`src/csp.ts`: `connect-src 'self'`, `font-src 'self'`, `worker-src blob:`, nonce on `script-src` and `style-src`, no third-party source), and `next.config.ts` sets the other security headers. (5) `/healthz` is the static file `public/healthz` (a `route.ts` outside `_bff` is a lint failure); Caddy routes the public `/healthz` to `api`, so the web's is the container's own. (6) The generated types are `src/api/generated/openapi.d.ts`, the kit generator's path, re-exported by `src/api/types.ts`. (7) The web's environment: `CISP_API_INTERNAL_URL`, `NEXT_PUBLIC_API_BASE_URL` (read at request time and handed to the page, so the image built in CI is configured at start; empty is same-origin), `CISP_BRANDING_FILE` (JSON `name`, `short_name`, `logo_url`, `contact`, `accent`; unknown members refused), `CISP_WEB_SESSION_MAX_AGE_S` (43200), `CISP_WEB_UPSTREAM_TIMEOUT_MS` (10000), `CISP_WEB_TRUSTED_PROXY_HOPS`, `CISP_WEB_MFA_CHALLENGE_SECRET` (item (3)). Compose maps them from `WEB_*` names in `deploy/.env`, because the Go processes refuse unknown `CISP_*` names. | The routes and the cookie contract are the kit's (M21, M22); the rest is what the brief needs. |
| Q42 (WP-10, decided in code; items (1) and (2) proposed, to the cross-plan reconciliation with the kit) | What the WP-10 brief needs and does not say, and where it, the API and the kit's `0.1.0-rc.1` do not meet. | (1) **Circles are drawn from the CISP's outline (Q43).** ED-318 sends a circle as a `Point` with `extent.radius` and a geometry library in `web/` fails lint, so the map draws the `extendedProperties.cis_display_geometry` a filtered read carries; a circle served without one is listed as "not drawn on the map" with its radius, never hidden. (2) **Proposed: an unknown style in the kit.** The kit has no style for `cis_applicability: unknown`; its rule draws `applies: null` in full and never dims it, which is the safe reading, so the map does that, and the list and the panel say "could not be evaluated" and why. (3) The kit's view model holds limits in metres, so a limit published in feet reaches the kit as null (its hover card shows a dash) and is shown in feet by the panel, never converted. (4) The brief's "the `at=` control hides a zone outside its window" conflicts with its own "nothing hidden": the map annotates with `applies_at` and dims what does not apply; nothing is filtered. (5) `NEXT_PUBLIC_MAP_CENTER` (`"lng,lat"`) and `NEXT_PUBLIC_MAP_ZOOM` are read at request time and have no default: unset or invalid, the map area names the variable instead of choosing a place (INV-03); `CISP_WEB_POLL_INTERVAL_S` (60) is the `HEAD` period while the stream is not live. (6) Display-only constants: "now" is asked to the minute (so the browser cache can answer within it), the read's bbox is the view padded by a quarter, widened to a 0.05 degree grid and read 300 ms after the map settles (spec 05 section 5, the kit's `useBBoxSubscription`). (7) Live means a `console/status/v1` younger than the `live_max_age_s` it announced; then a moved `datasets{}` version, a new `resync_since` or a `cis/change/v1` frame refetches. Otherwise the page polls `HEAD` on each dataset (at once when the stream is down) and refetches on a changed `ETag`; "disconnected" when a `HEAD` round cannot reach the API. A dataset that cannot be read keeps what was shown and is "unavailable since" the first failure. (8) The list of every served feature, by layer, is the keyboard path to the panel. (9) The Playwright fixture server's applicability verdicts are fixed per feature (TSR001 by its weekday window, TSD001 unknown), not an evaluation. | The pages and the rules are the brief's; the rest is what they need. |
| Q43 (WP-10 review, decided in code; an additive member of the published API) | A zone missing from the public map is a safety gap, and the API sent circles only as centre and radius (Q42 (1)). | Every filtered read (`bbox`, `at`, `applies_at`) writes `extendedProperties.cis_display_geometry` into the copy of a feature that holds a circle: the circle as a GeoJSON `Polygon` of 64 vertices on the geodesic circle, counterclockwise from due north and closed, and in a `GeometryCollection` the other parts copied as published (no `layer`). `internal/outline` places each vertex with uspace-core's direct geodesic solver `geodesy.Destination` (core `v1.3.0`, Vincenty on WGS84, within 0.1 mm of `geodesy.Inverse`), then writes it to 1e-8 degree; the tests measure every written vertex within 5 mm of the radius by `geodesy.Inverse`. The CISP's own refinement (a `LocalOffsetM` guess iterated against `Inverse`) was removed when core shipped the solver (WP-12). A circle that cannot be drawn (radius outside (0, 1000 km], centre beyond 89 degrees) is served without the member and counted (`outline_failed`). Unfiltered reads serve the published, signed bytes and carry no outline; the stored row never does. A drawing, never a judgement: consumers judge the circle as published. The 64 vertices are a display resolution, not a threshold. | The map must draw every zone; the CISP may add `cis_*` members to its served copy, never to content. |
| Q44 (WP-11, decided in code; items (2) and (3) proposed, additive within `/v1` in the console tag) | What the WP-11 brief needs and does not say, and where it and the console API (WP-8) do not meet. | (1) **The console reaches `/v1/console/*` through the kit's `/_bff/api/*`** (Q41 (1); the brief's `/_bff/proxy/*`), **`WS /v1/stream`** for the stream indicator, and **`GET /public/v1/{dataset}`** for the map previews: the console's diff and restriction heads carry identifiers only, so the version page and the restrictions page draw the named features from the public read of the current version (with `applies_at`, so a circle carries its outline, Q43), say which are drawn and which are not, and draw nothing for a superseded version. `test/console-paths.test.ts` fails on any other API path in the console's source and on any method but GET on `/public/`; the content routes are named nowhere. (2) **Proposed: `warnings` and `signature_kid` on `ConsolePublicationVersion`**, as `PublicationVersion` has them, and (3) **proposed: `GET /v1/console/publications/attempts?dataset=&limit=`** (`x-role: viewer`, `PublicationAttemptList`), so the console shows a version's warnings, its signature `kid` and the refused attempts with their problems; until WP-8's tag adds them the publications page says they are not served. (4) Account changes take no reason (Q40 (5)): their dialogs spell out the consequence and ask none; republish, suspend, resume and retry require one (1-500 characters). (5) Times are rendered in the viewer's zone with the UTC value as the title; the audit's `since` filter is typed as a UTC wall clock (the kit's UTC box) and says so. (6) Display-only bounds: a changed feature shows its first 20 paths until "show every path" (the API's own 200-path and `limit` truncations are always said); the status strip reads `GET /v1/console/status` every 10 s; a subscription's page finds it in at most 20 pages of 500 of the list (the API has no single-subscription console read) and says so when it does not. (7) The kit's `ConfirmDialog` lives in its `form` module, which imports its optional peers `react-hook-form` and `zod`; the web lists both. (8) Opening the kit's `0.1.0-rc.1` `AlertDialog` makes the browser report an inline-style CSP violation (a style the kit injects without the nonce; the dialog works, its scroll lock does not apply): to the kit. | The pages and the rules are the brief's; the rest is what they need. |
