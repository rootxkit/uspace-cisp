# WP-5: dynamic restrictions (F2)

Branch `feat/WP-5-restrictions`. Milestone C-M2. Owns exclusively:
`internal/restriction/`, `internal/dataset/restrictions.go`, the
`restrictions` tag of `api/openapi.yaml` (`POST /v1/restrictions`,
`PATCH /v1/restrictions/{id}`, `GET /v1/restrictions`, `GET
/v1/restrictions/{id}`), `internal/httpapi/restrictions.go`, the expiry
job and the publisher-staleness rule (takes over
`POST /v1/publishers/heartbeat` semantics from WP-3),
`schemas/cis/restriction/v1.json`. Depends on WP-1, WP-2 (and WP-3's
heartbeat endpoint and `uspace_airspace` dataset for tests; seed
through the store until it merges). Peers: WP-3, WP-4, WP-6, WP-8.

## Read first

1. `CLAUDE.md`, `docs/PLAN.md §1.3` (D4, D5, D8), `§6.2`, `§8.3`, `§15`
   Q2, Q3, Q6, Q11, Q17.
2. Spec `01 §2` C2, C5 (1 s target), `01 §4` N1 (ATS.TR.237:
   activation, deactivation, temporary limitation), `02 F2` (payload,
   states, idempotency key, ANSP-side version, the degraded path,
   source stale after 60 s), `03 §4` (ANSP `restrictions` fields and
   the F3548 `Cstr*` limits), `04 §3.4` (`restriction/state/v1`), `07`
   C-M2 and N-M1.
3. `uspace-core/ed318` (`Parse`, `UASZone.Reason`, `LimitedApplicability`,
   `TimePeriod`), `f3548` constants `CstrMaxDurationHours`,
   `CstrMaxPlanningHorizonDays`, `CstrMaxAreaKm2`, `CstrMaxVertices`
   (import them; never retype the numbers).
4. LESSONS Z-12 (restrictions must be pushed within one tick), B-04
   ("unreachable" is not "lost"), B-11 (disabled/stale is not silent),
   E-15 (a zero threshold refuses, never disarms).

## What to build

### State machine (`internal/restriction`, pure)

```go
type State string   // Planned, Active, Ended, Cancelled
type Op string      // OpCreate, OpActivate, OpExtend, OpEnd, OpCancel, OpExpire
type Head struct{ ID, AnspRef string; AnspVersion int64; UspaceAirspaceID, FeatureID string; State State; StartsAt, EndsAt time.Time; EndedBy *string }
type Request struct{ Op Op; AnspVersion int64; EndsAt *time.Time (extend); Now time.Time }
func Transition(h Head, r Request) (Head, publication.Reason, error)   // the table below; *core.FieldError on a refused transition naming "state" or "ansp_version" or "ends_at"
func Expire(h Head, now time.Time) (Head, bool)                        // Active with EndsAt <= now -> Ended, EndedBy "expiry"
type Limits struct{ MaxDuration time.Duration; MaxHorizon time.Duration }   // from f3548 constants; zero refuses (E-15)
func ValidateWindow(startsAt, endsAt, now time.Time, lim Limits) error
```

| From | Op | To | Reason | Rule |
|---|---|---|---|---|
| — | create (`state: planned`) | Planned | `restriction_created` | `starts_at < ends_at`; `ends_at - starts_at ≤ 24 h`; `starts_at ≤ now + 56 d`; `ends_at > now` |
| — | create (`state: active`) | Active | `restriction_activated` | same, and `starts_at ≤ now + 60 s` |
| Planned | activate | Active | `restriction_activated` | — |
| Planned | cancel | Cancelled | `restriction_cancelled` | — |
| Active | extend | Active | `restriction_extended` | new `ends_at` > old, total ≤ 24 h |
| Active | end | Ended | `restriction_ended` | `ended_by: ansp` |
| Active | (time) | Ended | `restriction_expired` | `ended_by: expiry`, by the job |
| any | same `ansp_version` | unchanged | — | 200 with the stored head (idempotent) |
| any | lower `ansp_version` | refused | — | 409 `ansp_version` |
| Ended, Cancelled | anything new | refused | — | 409 `state` |

`ansp_version` must increase strictly on every accepted op.

### Dataset rules (`internal/dataset/restrictions.go`)

The `feature` in the request body: a one-feature ED-318 collection is
built around it and `ed318.Parse`d (strict); then `reason` contains
`DAR`; `type` ∈ `PROHIBITED | REQ_AUTHORIZATION | CONDITIONAL` (a DAR
that opens airspace is not a restriction: refuse `NO_RESTRICTION` and
`USPACE`); `limitedApplicability` present with exactly one `TimePeriod`
whose `startDateTime`/`endDateTime` equal `starts_at`/`ends_at` (a
restriction's time is one truth, carried twice for ED-318 consumers);
no daylight events; identifier ≤ 7 characters and not reserved by any
dataset (D8, Q17); outline ≤ `CstrMaxVertices` and area ≤
`CstrMaxAreaKm2` (`ST_Area(geography)` in the handler's store lookup);
`uspace_airspace_id` must be a current `uspace_airspace` feature and the
restriction's geometry must intersect it (PostGIS `ST_Intersects` on
the stored shapes; a restriction entirely outside the airspace it
claims to modify is refused `uspace_airspace_id`). Served feature:
`extendedProperties.cis_restriction = {id, ansp_ref, ansp_version,
state, starts_at, ends_at, ended_by, uspace_airspace_id}` added by the
CISP (the only place the CISP adds to a published feature; documented
in the OpenAPI and `schemas/cis/restriction/v1.json`).

### Handlers (`internal/httpapi/restrictions.go`)

Middleware: `RequireScopes(cis.publish:restrictions)`,
`RequirePublisher(ansp)`, `RequireMTLSSubject()`, body cap 256 KiB,
`X-JWS-Signature` detached verification over the body (the same scheme as
F1; the ANSP's key from the authority's JWKS — Q8).

`POST /v1/restrictions`: validate; `ansp_ref` lookup; `Transition`;
`store.PublishTx` on dataset `restrictions` with the new current set
(the current heads in `Planned`/`Active` as features; `Ended`/`Cancelled`
leave the current set), `reason` from the transition, the body's
signature kept; insert `restrictions` head and `restriction_events`;
201 with the head and `{dataset: restrictions, version, etag}`; 200 on
an idempotent replay. All inside one transaction with `PublishTx`
(extend `PublishTx` with a `Before(tx)` hook rather than a second
transaction).

`PATCH /v1/restrictions/{id}` `{op, ansp_version, ends_at?}`: the same
path; 404 unknown id (ids are ULIDs; the ANSP may also address by
`ansp_ref` via `?by=ansp_ref`).

`GET /v1/restrictions?state=&airspace=&at=&limit=` and
`GET /v1/restrictions/{id}`: heads with `events[]`; `cis.read`.

### Expiry job and staleness

In `api`, a ticker every 5 s (leader-elected by
`pg_try_advisory_lock(hash("restriction_expiry"))` so replicas do not
race): `Expire` every `Active` head past `ends_at`, each through
`PublishTx` with `reason: restriction_expired`, `publisher_signature`
null, `events` actor `system`. The tick is a counter and a gauge
(`restrictions_active`, `restrictions_expired_total`); the job's last
run time is in `/v1/status` and the status line flags a job older than
30 s at error level (E-02: a dead ticker must be visible).

Staleness: a publisher of kind `ansp` with `now - last_heartbeat_at >
stale_after_s` (60) or never heard is `stale`; `GET /v1/restrictions`
and the `restrictions` dataset responses carry
`cis_publisher_stale_since` at the top level, `/v1/status` lists it, the
status line prints it at **warning** level (not error: active restrictions
stay active until their `ends_at`, `02 F2`; the ANSP's absence is the
ANSP's alarm). Nothing is ended or hidden because the ANSP is silent
(B-04, B-11).

## Tests

- `Transition` table: every row above, E-01 paired (each refusal beside
  the accepted op that differs by one field); `ansp_version` equal,
  lower, higher; `ValidateWindow` at every bound (±1 s) and with zero
  limits (refused, E-15).
- Dataset rules: each refusal beside an accepted DAR feature (reason
  without DAR, `NO_RESTRICTION`, two periods, period not equal to the
  window, a daylight event, 8-char identifier, identifier taken by a
  zone, 1 001 vertices, > 10 000 km², outside its airspace, unknown
  airspace).
- Handlers (integration): create planned → activate → extend → end; a
  replay of each op returns 200 with the same head and **no new
  version** (assert `datasets.current_version`); each accepted op is a
  new version with the right `reason` in `changes`; `GET /v1/restrictions`
  (WP-4 path) shows the feature with `cis_restriction`; an ended
  restriction leaves the current set and is in `/versions/{v}` history;
  `at=` inside and outside the window.
- Expiry (E-02 both branches): an `Active` head 1 s past `ends_at`
  expires on the next tick with `ended_by: expiry`, emits
  `restriction_expired`, and the tick gauge moves; with the ticker
  stopped for 31 s the status line goes to error (read it back).
- Staleness: heartbeat present → not stale; 61 s without → stale in
  `/v1/status` and on the dataset; heartbeat returns → clear. Nothing
  else changes (assert versions unchanged).
- mTLS: `header` mode with the wrong subject → 403; `off` mode passes
  and the error-level line appears.
- e2e (`test/e2e/restriction_latency_test.go`, with WP-6's subscriber
  container): `POST` active → the subscriber's receipt time minus
  `changes.at` printed; assert < 2 s on CI (the 1 s target is reported
  as measured, not asserted on a shared runner — E-04).

## Done when

- [ ] Lint, race, integration green; coverage ≥ 90 % in
  `internal/restriction`, ≥ 85 % in the handler and dataset files.
- [ ] C-M2 done-when items that are the CISP's: activate, end, cancel
  lifecycle; history by version and `at=`; subscribers notified (the
  measured latency line pasted).
- [ ] The staleness and expiry transcripts pasted (E-02).
- [ ] `docs/PLAN.md §15` Q2, Q6, Q17 answers stated in the OpenAPI
  descriptions.
- [ ] CHANGELOG line; outputs pasted (E-04).

## Safety notes

A restriction is the one CIS item whose absence endangers a flight. The
rules that matter: the CISP never ends a restriction early (only
`ends_at` or the ANSP does); a silent ANSP never hides one; every state
change is a new version and a change record within the same
transaction; an idempotent replay never creates a version (so a retry
storm from a degraded ANSP cannot flood subscribers). The one-feature
parse is strict: a restriction the CISP cannot validate is refused with
its path, never stored "for later".

## Commits

`feat(restriction): the lifecycle state machine with ANSP versions and expiry [WP-5 C-M2]`,
`feat(dataset): DAR restriction rules above ED-318 and the F3548 constraint limits [WP-5 C-M2]`,
`feat(api): restrictions lifecycle endpoints with mTLS and signed bodies [WP-5 C-M2]`,
`feat(api): expire restrictions on time and flag a stale publisher [WP-5 C-M2]`,
`test(api): restriction lifecycle, replay, expiry and staleness [WP-5 C-M2]`.
