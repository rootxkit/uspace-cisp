# WP-3: publication intake (F1)

Branch `feat/WP-3-publications`. Milestone C-M1. Owns exclusively:
`internal/dataset/` (kinds and rules for `zones`, `uspace_airspace`,
`ussp_list`; WP-5 adds `restrictions` in its own file), the
`publications` tag of `api/openapi.yaml` (`PUT /v1/publications/{dataset}`,
`GET /v1/publications/{dataset}`, `GET /v1/publications/{dataset}/attempts`,
`POST /v1/publishers/heartbeat`), their handlers in
`internal/httpapi/publications.go`, `schemas/cis/ussp_list/v1.json`,
`schemas/cis/uspace_requirements/v1.json` with examples. Depends on
WP-1 (`store.PublishTx`, `publication`), WP-2 (middleware, detached
verifier). Peers: WP-4, WP-5, WP-6, WP-8.

## Read first

1. `CLAUDE.md`, `docs/PLAN.md §1.2`, `§1.3` (D1, D2, D3, D8), `§6.1`,
   `§6.7`, `§8.1` (T9), `§9` (the 20 MB budget), `§15` Q1, Q3, Q5, Q6,
   Q17.
2. Spec `01 §2` C2, C3 (verification on receipt, error reporting), `02
   F1` (the ED-318 field list, the USSP list fields, the import
   mapping), `03 §1` (`uspace_airspaces` fields, which the requirements
   block mirrors), `04 §3.4`, `04 §4` (`extendedProperties` is the
   extension mechanism), `06` T9 ("validated by `uspace-core/ed318` on
   receipt and rejected, never repaired").
3. `uspace-core/ed318`: `Parse`, `Limits`, `FeatureCollection`,
   `UASZone` (`Type`, `Reason`, `ExtendedProperties`), `ToZones`,
   `NOAADaylight`, `PartIdentifier`; `ed269.Problems`.
   `vectors/testdata/ed318_roundtrip.json` (22 cases): every accepted
   collection and every refusal.
4. LESSONS Z-01, Z-02, Z-04, Z-06, E-01, E-09, E-10, E-15.

## What to build

### Dataset rules (`internal/dataset`, pure)

```go
type Kind string; const (KindZones, KindUspaceAirspace, KindUsspList)
type Rules interface {
    Validate(body []byte, lim ed318.Limits, now time.Time) (Accepted, *ed269.Problems)
}
type Accepted struct{ Collection *ed318.FeatureCollection (nil for ussp_list); UsspList *UsspList; Warnings []Warning; Rows []publication.FeatureRow }
type Warning struct{ Field, Reason string }
func For(kind Kind) Rules
```

- `zones`: `ed318.Parse` with `DefaultLimits` (bytes cap raised to the
  publication cap); then per feature: `Type != USPACE` ("U-space
  airspace is published in the uspace_airspace dataset"), `reason`
  without `DAR` ("dynamic restrictions are published by the ANSP"),
  identifier not already present in another dataset's current version
  (D8; the store answers the question through a `Reserved(ids)` lookup
  the handler performs before `PublishTx`, and `PublishTx`'s unique
  index is the backstop), `PartIdentifier` reservations for
  GeometryCollections. Then **judgeability**: `ed318.ToZones` on a
  one-feature collection with `NOAADaylight{}`; a `*core.FieldError`
  whose `Field` is under `geometry` or `layer` or names `radius`,
  `lower`, `upper` refuses with that path; any other error (daylight
  events on an open-ended schedule, `MaxEventDays`) becomes a `Warning`
  on the publication (the zone is still publishable; consumers use
  `Applies`). Problems are listed by path, capped at 100 with the
  truncated count, in a stable order.
- `uspace_airspace`: as `zones` but every feature `Type == USPACE`, and
  `extendedProperties` must hold the `cis/uspace_requirements/v1`
  block: `uas_requirements` (object), `service_performance` (object with
  at least `nid_update_hz`, `ti_update_hz`, `cis_latency_s` numbers > 0),
  `operational_conditions` (object), `airspace_constraints` (object;
  optional `max_height_agl_m` > 0), `services_required` (non-empty array
  of `NID|GEO|FA|TI|WX|CM` with the four mandatory present),
  `adjacent` (array of identifiers that exist **in the same
  publication**); unknown members under that block are refused; other
  `extendedProperties` members pass through.
- `ussp_list`: a hand-written bounded JSON validator (no third-party
  schema library) for `cis/ussp_list/v1`: `schema == "cis/ussp_list/v1"`,
  `issued` RFC 3339, `ussps[]` ≤ 200 entries each with `ussp_id` (≤ 64),
  `name` (≤ 200), `contact {email?, phone?, url?}`, `certificate_id`
  (≤ 64), `base_url` (https URL, no userinfo, ≤ 253 host), `services[]`
  ⊆ the Annex VI names (`network_identification`, `geo_awareness`,
  `flight_authorisation`, `traffic_information`, `weather`,
  `conformance_monitoring`), `certification_limitations[]` strings,
  `valid_from`, `valid_until`, `terms_url` (https), `status`
  (`operating|suspended|limited`); duplicate `ussp_id` refused naming
  both indexes; unknown members refused (the list is a closed national
  schema). `Rows` is empty for this kind (no geometry); the snapshot is
  the canonical JSON of the list with `cis_*` members.

### Handlers (`internal/httpapi/publications.go`)

`PUT /v1/publications/{dataset}`:

1. middleware: `RequireScopes` per dataset, `RequirePublisher(authority)`,
   body cap `CISP_MAX_PUBLICATION_BYTES`, `Content-Type:
   application/geo+json` or `application/json` (415 otherwise);
2. read the body once; `DetachedVerifier.Verify(X-JWS-Signature, body)`
   — 401 `signature` before anything else (WP-2 safety note);
3. `If-Match` required (428 `precondition_required`) and must equal the
   current `ETag` (412 `precondition_failed` with the current `etag` in
   the problem);
4. `dataset.For(kind).Validate(body)`; on problems: insert a
   `publication_attempts` row (`refused`), count
   `publications_refused{dataset}`, answer 400 with `problems[]`;
5. `store.PublishTx` with `reason: publication`, the signature and
   `kid`, the warnings; `ErrUnchanged` → 200 `{dataset, version, etag,
   unchanged: true}`; else 201 with the counts and `added[]`, `changed[]`,
   `removed[]` ids (capped at 1 000 each with a `truncated` count) and
   `warnings[]`;
6. `events` row is written by `PublishTx`; the attempt row `accepted`
   is written here with the `publication_id`.

`GET /v1/publications/{dataset}?limit=&before=`: versions list
(`cis.read` or the publisher). `GET /v1/publications/{dataset}/attempts?since=`:
the publisher's own refusals (403 for another client; console `admin`
through WP-8 later). `POST /v1/publishers/heartbeat` `{sent_at}` with any
`cis.publish:*` scope: upserts `publishers.last_heartbeat_at` for the
caller's `sub`; 403 when `sub` is not a configured publisher. (WP-5 reads
it for staleness.)

Snapshot signing: `PublishTx` takes the `jws.KeyRing` as its `Signer`.

### OpenAPI

Add the four operations with full request and response schemas
(`PublicationResult`, `PublicationVersion`, `PublicationAttempt`,
`UsspList` and `UspaceRequirements` as components referenced by `$ref`
from `schemas/cis/*` copies — the OpenAPI holds the canonical component,
`schemas/cis/*.json` is generated from it by `tools/export-schemas.go`
and checked by `make generate-check`, so there is one source).

## Tests

- `TestVectorsED318Roundtrip` (`internal/httpapi/vectors_test.go`,
  `RunOwned("cisp")`): every accepted collection `PUT` → 201; `GET
  /v1/zones/versions/{v}` (through the store until WP-4's handler
  lands: call `store` directly and compare bytes) equals the input bytes;
  every refusal → 400 whose `problems[]` contain the vector's path and
  phrase. Collections with `USPACE` go to `uspace_airspace` and are
  given the requirements block by the test (document which cases).
- E-01 pairs for every rule above (each refusal beside an acceptance
  that differs in one thing): USPACE in zones, DAR in zones, duplicate
  identifier within a publication (core refuses; assert the path),
  identifier reserved by another dataset, missing requirements block,
  `adjacent` naming an identifier not in the publication, a USSP list
  with a duplicate `ussp_id`, `base_url` with userinfo, unknown member,
  201 entries.
- Idempotent re-PUT returns 200 `unchanged`; a re-PUT with one feature
  changed returns 201 with that id in `changed[]`.
- `If-Match` absent → 428; stale → 412 with the current etag; the
  unsigned-and-invalid body → 401 naming only the signature.
- Warnings path (E-02): a zone with an open-ended sunrise/sunset
  schedule is accepted with a warning naming the feature; read the
  warning back from `GET /v1/publications/zones`.
- A 20 MB, 5 000-zone synthetic publication (generated in the test,
  Tbilisi area, polygons of 20 vertices) completes under the §9 budget
  on the CI runner (log the duration; fail above 30 s).
- Refusal counters and the status line (`publications_refused{dataset}`)
  read back.
- `FuzzValidateUsspList(body)` never panics.

## Done when

- [ ] 22/22 `ed318_roundtrip` cases pass through `PUT`; lint, race,
  integration green; coverage ≥ 85 % in `internal/dataset` and the
  handler file.
- [ ] `make generate-check` passes with the four operations and the
  exported schemas.
- [ ] The 5 000-zone timing line pasted in the PR.
- [ ] CHANGELOG line; outputs pasted (E-04).

## Safety notes

Accept whole or refuse whole; never store a partially valid publication
(Z-02). Never "fix" a feature: no trimming, no default vertical
reference, no re-ordering of coordinates. The only bytes stored are the
bytes received. A warning is for things a consumer can still judge
safely (open-ended daylight schedules); anything about geometry or
limits is a refusal, because a USSP that cannot build the zone would
otherwise silently drop it.

## Commits

`feat(dataset): rules for zones, uspace_airspace and the USSP list above ED-318 [WP-3 C-M1]`,
`feat(api): accept signed full-dataset publications with If-Match and refusal reports [WP-3 C-M1]`,
`feat(api): publisher heartbeat and publication history [WP-3 C-M1]`,
`test(api): run the 22 ED-318 round-trip vectors through PUT [WP-3 C-M1]`,
`docs(schemas): ussp_list/v1 and uspace_requirements/v1 with examples [WP-3 C-M1]`.
