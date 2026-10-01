# uspace-cisp: rules for every contributor and agent

`uspace-cisp` is the single, state-run Common Information Service
Provider of the Georgian U-space system-of-systems (Reg. (EU) 2021/664
Art. 5): it validates, versions, signs, stores and serves the airspace
information the authority and the ANSP publish (ED-318 geo-zones,
U-space airspace with its requirements, dynamic restrictions, the USSP
list), and tells subscribers when it changes. Go module
`github.com/rootxkit/uspace-cisp`, processes `api`, `deliver`, tool
`cispctl`, UI under `web/`. Read `docs/PLAN.md` before changing anything;
a work package brief is in `docs/WORKPACKAGES/`. The system-of-systems
spec is `uspace-lab/docs/spec/` (`01 §2` is this system's role) and the
knowledge base is `uspace-lab/knowledge/`.

## Hard rules

1. **Nothing here commands an aircraft.** No code, dependency, socket or
   configuration has a send path towards a vehicle (LESSONS INV-01).
   The CISP talks to publishers and subscribers; it never talks to a
   flight controller, an operator's client or a USSP's operator-facing
   service.
2. **The CISP never authors, edits, repairs or normalises content.** A
   publication is accepted whole or refused whole with every problem
   named by path, through `uspace-core/ed318.Parse` (spec `06` T9,
   LESSONS Z-01, Z-02). The bytes stored are the bytes received. No
   console role has a write path to content; every console action is
   about subscriptions, deliveries, accounts or re-notification.
3. **No judgement lives here.** Zone containment, vertical limits, CPA,
   conformance and identification are the consumers' Go code on
   `uspace-core`. The CISP evaluates applicability only through
   `ed318.Applies` to answer `at=`, and keeps what it cannot evaluate
   marked `unknown`, never dropped. A TypeScript import of a geometry
   library fails lint.
4. **Fail visible, never silent.** A stale snapshot is served with
   `X-CIS-Stale`; a silent publisher is flagged, never ended; a dead
   broker is a status-line error, never a hang; a delivery that cannot
   be made is a row and a counter, never a deletion; a disabled
   safeguard (`CISP_MTLS_MODE=off`) is printed at error level every
   period (LESSONS B-04, B-08, B-11, E-02, E-09).
5. **Every published version is kept for ever with its publisher's
   signature**, and every state change is one transaction with its
   change record (spec `01` C3, `05 §4`). Never update or delete a row
   of `publications`, `features`, `changes` or `events`.
6. **Thresholds, limits, addresses and credentials are configuration**
   (`CISP_*` environment, validated at start, redacted in logs), never
   literals (INV-03). Signing keys are PEM files outside the repository;
   nothing under `local/`, `*.pem`, `*.key` or `.env` is ever committed
   (spec `06 §4`; `gitleaks` runs in CI).
7. **Units and datums in every name** (E-13): `lower_m`, `lower_ref`,
   `stale_after_s`, `latency_ms`; in Go `LowerM`, `StaleAfterS` or
   `time.Duration`. GeoJSON order is converted only by core at the
   parser boundary. The CISP never computes a height.
8. **No panics on untrusted input.** Every request body, header,
   token, signature and URL is untrusted; refusals are
   `*core.FieldError`, `*ed269.Problems` or `problem+json` with the
   field named; every bound (bodies, caches, hub clients, in-flight
   deliveries) is explicit and tested past it (E-10). `forbidigo`
   forbids `panic` on data paths.
9. **English only** in code, comments, commits, logs and docs. Every
   user-facing string in `web/` goes through the `ka`/`en` catalogues
   from the first commit.
10. **Dependencies**: the owner's stack (`docs/PLAN.md §4`) and the
    standard library. Anything else needs a one-line reason in the
    commit body and a row in `docs/PLAN.md §4`. Nothing with cgo.

## Cross-system contracts

- `api/openapi.yaml` is the national CIS publication API. An endpoint
  that is not in it does not exist; generated server, client and
  TypeScript types are committed and verified offline in CI; changes
  within `/v1` are additive only (spec `00 §7`, `02 §1`).
- Inbound: the authority publishes `zones`, `uspace_airspace`,
  `ussp_list` (F1); the ANSP publishes `restrictions` (F2). Both sign
  bodies with a detached JWS; tokens come from the authority's token
  service and are verified by `uspace-core/auth`.
- Outbound: pull by `ETag` and `since_version`, the change cursor, the
  WS stream, and signed webhooks (F3). Nothing assumes the subscriber is
  `uspace-ussp` or `uspace-authority`; any client with `cis.read` is a
  subscriber.
- Schemas this repository produces live in `schemas/cis/` and are
  mirrored read-only in `uspace-lab/schemas/`.
- Where the spec is silent, `docs/PLAN.md §15` holds the proposed
  answer. Do not invent a contract silently: add a row there and say so
  in the PR.

## Testing rules (from utm, LESSONS E-01 to E-04, E-10, E-11)

- **E-01 Test presence, not only absence.** Every test that asserts
  something does not happen (no version, no delivery, no refusal, no
  alert, empty) is paired with the test that makes it happen. Every
  refusal has its acceptance twin that differs in one thing.
- **E-02 Run the branch that says nothing is wrong.** Exercise the
  healthy status line, the empty dataset, the successful delivery, and
  then take the dependency away for real (stop PostgreSQL, stop NATS,
  kill the subscriber) and read the exact degraded output and counter.
  A mock that returns an error is not the dependency being absent.
- **E-03 Never write a wire format from memory.** ED-318 and ED-269
  field names come from `uspace-core` (which pins them to the schema and
  `uas_standards`); JWS and JWT shapes from the RFCs and `jwx`; HTTP
  caching headers from RFC 9110/9111. Field names in this repository's
  own schemas are written once in `api/openapi.yaml` and generated
  everywhere else.
- **E-04 Never report an inference as an observation.** A PR says what
  was run and what it printed; "the integration job passed" means it
  ran a non-zero count and you read the line. A skipped suite is
  reported as skipped. A tool error is not evidence about the thing
  checked.
- **E-10** every bounded structure has a test that exceeds its bound.
- **E-11** tests restore global state and pass under `-shuffle=on` and
  `-race`; time is injected, never slept past 100 ms.
- Vector adapter tests are `TestVectors<File>` in
  `<pkg>/vectors_test.go`, using `vectors.Load` and
  `RunOwned(t, "cisp", ...)` from `uspace-core/vectors`; CI also runs
  core's own vector tests from this module.
- Handler tests validate every request and response against
  `api/openapi.yaml` (`kin-openapi`). A response the spec does not
  describe is a failing test.
- Coverage: a work package is done at ≥ 85 % statement coverage of its
  packages, with every branch that produces a distinct counter, reason
  or problem covered by a named test.

## Commands

```
make tools            # once per machine: the pinned linters and tools
make dev-deps         # PostgreSQL+PostGIS+TimescaleDB and NATS in docker
make lint             # gofmt, vet, staticcheck, golangci-lint (pinned; refuses another version)
make race             # go test -race -shuffle=on ./...
make integration      # real databases and broker; fails when zero tests ran
make vectors          # core's vector tests from this module + RunOwned("cisp") adapters
make generate-check   # oapi-codegen, sqlc, openapi-typescript reproduce the committed output
make secrets vulncheck
make ci               # what CI runs
cd web && npm ci && npm run lint && npm run typecheck && npm test && npm run build
```

Run `make lint` locally before every push, not only at the end; CI
runs the same pinned versions (`Makefile` and `.github/workflows/ci.yml`
change together in one `ci:` commit).

## Git conventions

- Branch per work package: `feat/WP-<k>-<slug>` (the slug is in the
  brief). Plan and docs branches: `plan/<slug>`, `docs/<slug>`.
- Conventional Commits, one logical change per commit, imperative
  subject under 72 characters, the work package and milestone in
  brackets at the end: `feat(publication): diff a dataset against its
  previous version [WP-1 C-M1]`, `fix(deliver): refuse a redirecting
  callback [WP-6 C-M1]`, `test(api): run the 22 ED-318 round-trip
  vectors through PUT [WP-3 C-M1]`. Types: `feat`, `fix`, `test`,
  `refactor`, `perf`, `docs`, `build`, `ci`, `chore`. Scope is the
  package or process (`api`, `deliver`, `cispctl`, `store`,
  `publication`, `dataset`, `restriction`, `subscription`, `jws`,
  `auth`, `stream`, `bus`, `obs`, `web`, `deploy`, `schemas`).
- A commit that adds a dependency says why in the body.
- **No AI attribution of any kind**: no `Co-Authored-By`, no "generated
  by", no tool names in commits, PRs or code.
- Never force-push a shared branch; never commit to `main` directly.
- Do not push unless asked. The owner merges.

## Before you say a work package is done

Run, in this order, and paste the last lines of each into the PR:

```
make lint
make race
make integration
make vectors
make generate-check
```

and for `web/` the npm sequence above. Then check the brief's done-when
list item by item. If the brief needs a contract the spec does not
define, stop, add the question to `docs/PLAN.md §15` with a proposed
answer, and say so in the PR; do not invent it silently.
