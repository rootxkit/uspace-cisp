# WP-0: scaffold, CI and deploy

Branch `feat/WP-0-scaffold`. Milestone C-M1. Owns exclusively: `go.mod`,
`go.sum`, `cmd/api`, `cmd/deliver`, `cmd/cispctl` (stubs), `internal/config`,
`internal/obs` (base), `internal/httpapi` (base: router, middleware,
health, problem+json, generated package), `api/openapi.yaml` (skeleton),
`api/README.md`, `Makefile`, `.golangci.yml`, `.gitleaks.toml`,
`.gitattributes`, `.gitignore`, `.github/workflows/`, `Dockerfile`,
`deploy/`, `migrations/relational/0001_init.sql`,
`migrations/timeseries/0001_init.sql`, `SECURITY.md`, `CHANGELOG.md`,
`tools/` (generate scripts). Depends on nothing. Every other WP depends
on it: open the PR as soon as `make ci` is green.

## Read first

1. `CLAUDE.md`, `docs/PLAN.md §2, §3, §4, §9 (memory), §11, §14`.
2. `uspace-core` at its newest tag: `CLAUDE.md`, `Makefile`,
   `.golangci.yml`, `.gitleaks.toml`, `.gitattributes`,
   `.github/workflows/ci.yml` (copy the shape: pinned linter versions,
   `cancel-in-progress`, `GOTOOLCHAIN: local`, `go.mod` as the Go
   version source, gitleaks, govulncheck).
3. Spec `00 §6.1`, `00 §6.2`, `05 §6` (deployment), `06 §4`
   (public-repository constraints), `07` KT-3 (the common layout).
4. LESSONS E-02, E-04, E-09, E-12, B-08.

## What to build

### Module and processes

- `go.mod`: `module github.com/rootxkit/uspace-cisp`, `go 1.27`,
  `require github.com/rootxkit/uspace-core <newest tag>` (`v1.0.0` if
  tagged, else `v0.2.0`; the commit body says which and why),
  `tool` directives for `oapi-codegen`, `sqlc` and `goose` so CI and
  `make generate` run them from the module cache, offline.
- `cmd/api/main.go`, `cmd/deliver/main.go`, `cmd/cispctl/main.go`:
  parse config, build the logger, start, stop cleanly on SIGTERM
  within 10 s (in-flight requests finish, listeners close). `api` serves
  `/healthz` (always 200 while the process runs), `/readyz` (200 only
  when the database is reachable and migrations are current; stubbed to
  "not configured" until WP-1, and that state is **reported**, not
  faked), `/metrics` (Prometheus, with the Go and process collectors),
  and the OpenAPI-generated router with every operation returning 501
  `not_implemented` as `problem+json`. `deliver` runs an idle loop with
  the status line. `cispctl` has `version` and `config check` only.
- `internal/config`: one struct per process, loaded from `CISP_*`
  environment variables through a small typed loader (stdlib `os`,
  `strconv`, `time.ParseDuration`); `Validate()` returns every problem
  at once as `*core.FieldError` list; `Redacted()` for the startup log
  (secrets replaced by `***`, file paths kept). Every variable of
  `docs/PLAN.md §11` exists with its default, documented in
  `deploy/.env.example`. Unknown `CISP_*` variables are an error (a typo
  must not silently take a default).
- `internal/obs`: `slog` JSON handler with `request_id` and the
  process name; the Prometheus registry; a `Status` struct that every
  component registers counters and gauges into and that the periodic
  status line (every 30 s) prints at `info`, or at `error` when any
  component reports `degraded`; OpenTelemetry tracer provider with the
  OTLP HTTP exporter enabled only when `CISP_OTEL_ENDPOINT` is set (and
  a no-op provider otherwise; both branches tested).
- `internal/httpapi`: `net/http` `ServeMux` with method+path patterns;
  middleware chain: recover (a panic becomes 500 `problem+json` and a
  counter, never a crash), request id, `otelhttp`, request logging at
  the end with status and duration, `http.MaxBytesReader` with a
  per-route cap (default 64 KiB; routes raise it), a 10 s handler
  deadline through the request context; `problem.go` with
  `WriteProblem(w, status, type, title, detail, fields...)`. The
  generated code lives in `internal/httpapi/gen/` (`oapi-codegen`
  strict server interface and types, `//go:generate` in `gen.go`,
  config `api/oapi-codegen.yaml`).

### OpenAPI skeleton (`api/openapi.yaml`)

OpenAPI 3.1, `info.version: 0.1.0`, servers `/`, tags `health`,
`publications`, `restrictions`, `datasets`, `subscriptions`, `stream`,
`console`, `status`; `components.securitySchemes`: `ecosystemToken`
(http bearer, JWT) and `consoleSession` (http bearer); the `Problem`
schema (`application/problem+json`, the ecosystem-wide shape of
`docs/PLAN.md §6`: `type` (`https://schemas.uspace.ge/problems/<slug>`),
`title`, `status`, `detail`, `instance`, `errors[] {field, reason}`,
`truncated?`; the same shape as `uspace-lab/schemas/common/problem/v1`
once it exists, and `WriteProblem` takes `errors` not `problems`);
`GET /healthz`, `GET /readyz` (`{status, checks: {database, migrations,
nats}}`), `GET /v1/status` (stub of `docs/PLAN.md §6.3`). Other WPs add
their paths under their tags; `api/README.md` says how (edit the YAML,
`make generate`, commit the output, never edit `gen/`). This skeleton
is what the authority and the ANSP copy into their `api/clients/cisp.yaml`
with a `SOURCE` commit and a CI diff until the lab aggregate exists
(`docs/PLAN.md §6.7`, M11): merge it first, and keep every later
change to the file additive.

### Makefile and tooling

Targets, each a one-liner CI also runs: `build`, `vet`, `fmt-check`,
`lint` (refuses an unpinned golangci-lint, as core), `tools`, `test`,
`race`, `cover`, `generate` (oapi-codegen, sqlc, openapi-typescript),
`generate-check` (runs `generate` and `git diff --exit-code`),
`integration` (build tag; needs `CISP_TEST_DATABASE_URL`,
`CISP_TEST_TIMESERIES_URL`, `CISP_TEST_NATS_URL`; **fails when zero
tests ran**), `vectors` (core's vector tests from this module plus
`-run 'Vectors'` here), `secrets` (gitleaks), `vulncheck`, `dev-deps`
(`docker compose -f deploy/compose.dev.yml up -d`), `dev-deps-down`,
`image`, `ci`. Linter and tool versions pinned in one place
(`Makefile`) and mirrored in the workflow.

### CI (`.github/workflows/ci.yml`)

Jobs on `push` to `main`, tags `v*`, and `pull_request`, with
`concurrency: ci-${{ github.ref }}` and `cancel-in-progress: true`,
`timeout-minutes` on every job (10; integration 15), Go cache on:

1. `build-vet-lint` (gofmt, build, vet, tidy clean, staticcheck,
   golangci-lint pinned).
2. `generate-check` (`make generate-check`; tools from the module
   cache and `pnpm install --frozen-lockfile` only when `web/` exists).
3. `test-race` (`go test -race -count=1 -shuffle=on -coverprofile`;
   coverage summary in the step summary).
4. `integration` with `services:` `timescale/timescaledb-ha:pg16` (two
   databases created by an init step) and `nats:2-alpine` with `-js`;
   runs `make integration`; path-filtered to `**/*.go`, `migrations/**`,
   `go.mod`, `go.sum`, `.github/workflows/ci.yml`.
5. `vectors` (`make vectors`; the log uploaded).
6. `govulncheck`, `gitleaks` (fetch-depth 0), as core.
7. `image` on `main` and tags only: build the two images with
   `docker/build-push-action` (BuildKit cache to GHA), push to GHCR
   with the short SHA and the tag; the `web` image step is conditional
   on `web/package.json` existing (WP-9 enables it). SBOM and cosign are
   WP-13.

No scheduled job. Branch protection (owner): jobs 1-6 required.

### Deploy

- `Dockerfile` (Go): multi-stage, `golang:1.27` builder with
  `CGO_ENABLED=0`, `-trimpath -ldflags "-s -w -X main.version="`, three
  binaries, final `gcr.io/distroless/static:nonroot`; entrypoint
  selected by the compose `command`.
- `deploy/compose.yml`: the services of `docs/PLAN.md §11` with
  resource limits, health checks, the `migrate` one-shot, named volumes,
  an isolated network, every secret from the environment file; `web`
  service present but `profiles: [web]` until WP-9.
  `deploy/compose.dev.yml`: only `postgres` and `nats` on published
  ports for `make dev-deps`. `deploy/postgres/init.sql` creates `cisp`
  and `cisp_ts` with the PostGIS and TimescaleDB extensions and the
  `cisp_api` (relational read/write; timeseries read-only) and
  `cisp_deliver` (timeseries read/write; relational read/write on
  `deliveries` and `subscriptions` only) roles.
- `deploy/caddy/Caddyfile.snippet`: the routes of `docs/PLAN.md §11`
  (including `client_auth verify_if_given` with the subject header
  forwarded on the mTLS routes and stripped elsewhere, and `/basemap/*`
  from the shared volume), with placeholders, never a real hostname. It
  is a reference copy: the deployment repository `uspace-deploy`
  composes the real Caddyfile from every system's snippet (M25, D1).
- `deploy/.env.example`: every variable, its default, one line of
  meaning, grouped by process.

### Migrations trees

`migrations/relational/0001_init.sql` (`CREATE EXTENSION IF NOT EXISTS
postgis;` and the `datasets` table seeded with the four rows) and
`migrations/timeseries/0001_init.sql` (`CREATE EXTENSION IF NOT EXISTS
timescaledb;`), each with `-- +goose Down`; goose is configured with
the version table `goose_db_version_relational` for the first tree and
`goose_db_version_timeseries` for the second (D11). `internal/store/migrate.go`
with `embed.FS` per tree and `Pending(ctx, db, tree)` for `/readyz` is
WP-1's; WP-0 ships only the files and the `cispctl migrate` stub that
says "WP-1".

### Repository hygiene

`.gitattributes` (LF everywhere, as core), `.gitignore` (`local/`,
`*.pem`, `*.key`, `.env`, `.env.*` except `.env.example`, `web/.next`,
`node_modules`, coverage), `.gitleaks.toml` (default rules; no global
allowlist), `SECURITY.md` (core's text adapted: a service, not a
library), `CHANGELOG.md` (Unreleased with the WP-0 line).

## Tests

- `internal/config`: every variable's default, every validation
  failure beside its success, unknown variable refused, `Redacted()`
  never prints a secret (test greps the output for the secret value).
- `internal/httpapi`: health endpoints; a handler panic becomes a 500
  problem and increments `handler_panics`; a body over the cap is 413
  with `problem+json`; deadline exceeded is 503; request id echoed and
  generated.
- `internal/obs`: the status line at `info` when nothing is degraded
  and at `error` when a component is (E-02: both read back from a
  buffer handler); the tracer provider with and without the endpoint.
- `cmd/*`: a start/stop test per process (`go test` builds and runs
  the binary with a free port, hits `/healthz`, sends SIGTERM, expects
  exit 0 within 10 s).
- The `integration` job proves that both databases accept the extension
  creation and that `nats` answers `-js` (a `JetStream()` call) — the
  only integration test of WP-0, so the job runs a non-zero count.

## Done when

- [ ] `make ci` green locally and in CI; every job of the workflow ran
  (paste the Actions summary) and the `image` job pushed two tags on
  `main` (or was correctly skipped on the PR: say which).
- [ ] `api` starts with `deploy/.env.example` values against
  `make dev-deps`, answers `/healthz` 200, `/readyz` with
  `{database: ok, migrations: pending (WP-1), nats: ok}` — read it,
  paste it.
- [ ] `golangci-lint` and `staticcheck` versions equal core's; `make
  lint` refuses another version (prove it with a wrong version in PATH).
- [ ] `api/openapi.yaml` validates (`oapi-codegen` and `openapi-typescript`
  both accept it); `make generate-check` passes.
- [ ] `CLAUDE.md`'s command list matches the Makefile.
- [ ] CHANGELOG line; PR body with the commands run and their last
  lines (E-04).

## Safety notes

Nothing here touches data. The one trap is `/readyz`: it must report
"migrations pending" as not ready, never pretend; and the status line's
`error` branch must have run in a test before you say it works (E-02).

## Commits

`build: create the module, pin uspace-core and the tools [WP-0 C-M1]`,
`feat(api): serve health, readiness, metrics and the generated router [WP-0 C-M1]`,
`feat(obs): structured logging, metrics registry and the status line [WP-0 C-M1]`,
`ci: lint, race, generate check, integration services, vectors, images [WP-0 C-M1]`,
`build(deploy): compose, Caddy snippet, Dockerfile and env example [WP-0 C-M1]`,
`docs: security policy, changelog and the OpenAPI editing guide [WP-0 C-M1]`.
