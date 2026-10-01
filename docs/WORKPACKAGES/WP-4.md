# WP-4: the read API (F3 pull) and the public subset

Branch `feat/WP-4-read-api`. Milestone C-M1. Owns exclusively: the
`datasets` and `status` tags of `api/openapi.yaml` (`GET|HEAD
/v1/{dataset}`, `/v1/{dataset}/versions`, `/v1/{dataset}/versions/{v}`,
`/v1/changes`, `/v1/status`, `/public/v1/*`), their handlers in
`internal/httpapi/datasets.go`, `public.go`, `status.go`,
`internal/applicability/`, the rate limiter in
`internal/httpapi/ratelimit.go`. Depends on WP-1 (store, snapshot cache,
`publication.Delta`), WP-2 (middleware). Peers: WP-3 (its publications
are your test data; until it merges, seed through `store.PublishTx`
directly), WP-5, WP-6, WP-8. WP-10 (public map) and WP-12 (ED-269
export) build on this: open the PR early.

## Read first

1. `CLAUDE.md`, `docs/PLAN.md §1.3` (D2, D7), `§6.3`, `§6.4`, `§9`,
   `§15` Q1, Q10, Q22.
2. Spec `01 §2` C1 (same quality for everyone; a public subset), `02 §1`
   (Versioning, Failure rule), `02 F3` (pull API, `ETag`, `since_version`,
   60 s reconciliation `HEAD`), `05 §5` (webhooks and the public map
   from cache), `05 §6` (CISP down: subscribers run on cache), `06` T8.
3. `uspace-core/ed318`: `Applies`, `NOAADaylight`, `Export`,
   `FeatureCollection.Extra`; `vectors/testdata/zones_applicability.json`
   (32 cases, `cisp` owns), `geodesy.json` (`in_polygon`, `in_circle`).
4. LESSONS T-09 (applicability at the asked instant, UTC, aware), Z-06
   (bbox prefilter), Z-11, E-02, E-10.

## What to build

### Applicability (`internal/applicability`, thin)

```go
type Verdict int  // Applies, DoesNotApply, Unknown
func At(f *ed318.Feature, at time.Time, dl ed318.Daylight) (Verdict, error)   // ed318.Applies with the feature's centroid (from Geometry; a GeometryCollection uses the union centroid); error → Unknown, counted applicability_unknown
```

`Unknown` is **kept** in every filtered response, with
`extendedProperties.cis_applicability: "unknown"` added to that feature's
copy (never to the stored row). A zone that cannot be evaluated is never
dropped (fail visible).

### Reads (`internal/httpapi/datasets.go`)

`GET|HEAD /v1/{dataset}` (`cis.read`):

- `dataset` ∈ the four; 404 otherwise. `ETag: "<dataset>:<version>"`,
  `Last-Modified`, `Cache-Control: public, max-age=CISP_READ_MAX_AGE_S`,
  `X-CIS-Version`, `Vary: Accept-Encoding`. `If-None-Match` with the
  current etag → 304 (also for `HEAD`). `HEAD` never touches the
  database beyond the cache.
- No filter: the snapshot bytes from the cache (gzip served as-is when
  the client accepts it, inflated otherwise), `X-CIS-Signature` = the
  stored CISP detached JWS.
- `bbox=minlng,minlat,maxlng,maxlat` (validated: finite, in range,
  min ≤ max; an antimeridian-crossing box is refused 400 for now, say so
  in the OpenAPI): `features_current` rows whose `geom && envelope`,
  assembled into a `FeatureCollection` by `publication.Snapshot`'s
  builder with the same `cis_*` members; `X-CIS-Filtered: bbox`.
- `at=` (RFC 3339 with an offset; a naive time is 400): on the rows
  after the bbox prefilter (or all), keep `Applies` and `Unknown`
  (marked), drop `DoesNotApply`; `X-CIS-Filtered: at`.
- `since_version=v`: `publication.Delta` between `v` and current from
  the `features` rows (`op` per version, walked forward; at most 1 000
  versions back, else 410 `delta_unavailable` telling the client to pull
  the full dataset); 400 when `v` > current; response `DatasetDelta` with
  `Content-Type: application/json`.
- `ussp_list` ignores `bbox`/`at` (400 `filter_not_applicable`).
- Degraded: when the snapshot cache reports `Stale`, unfiltered reads
  serve the held snapshot with `X-CIS-Stale: true` and `X-CIS-Age-S`,
  `Cache-Control: no-store`; filtered reads answer 503 with
  `Retry-After: 5` and the problem says the database is unreachable
  since when. Both branches tested by closing the pool (E-02).

`GET /v1/{dataset}/versions?limit=&before=` and
`GET /v1/{dataset}/versions/{v}`: the verbatim `publications.body` with
`Content-Type` as received, `X-Publisher-Signature` and
`X-Publisher-Kid` when present, `X-CIS-Signature` always (the CISP signs
the stored bytes at serve time through the key ring, cached per
version), `body_sha256` re-checked before serving (a mismatch is 500
`integrity` and an error log: T7). `?format=ed269` is WP-12's.

`GET /v1/changes?since=&dataset=&limit=`: cursor feed from `changes`,
`limit` ≤ 500, `{changes: [cis/change/v1], next}`; `since` absent =
from 0; the record shape is WP-6's schema (`schemas/cis/change/v1.json`):
until WP-6 merges, this WP writes the schema file with the fields of
`docs/PLAN.md §6.7` and WP-6 adopts it (coordinate in the PRs).

`GET /v1/status`: per dataset `{current_version, updated_at, etag}`;
per publisher `{client_id, kind, last_heartbeat_at, last_publication_at,
stale: bool, stale_since}` (from `publishers`, which WP-3 writes; WP-5
defines the staleness rule, so here `stale` = `now - last_heartbeat_at >
stale_after_s`); `degraded: [{component, since}]` from the status
registry; `now`.

### Public subset (`internal/httpapi/public.go`)

`GET|HEAD /public/v1/{dataset}` = the same handler without the token
middleware, without `since_version`, with the `ussp_list` projection
(drop `base_url`, `certificate_id`; Q10), and with the per-IP rate
limiter: `golang.org/x/time/rate` buckets keyed by client IP (from
`X-Forwarded-For` only when the request came from the configured
Caddy address, `CISP_TRUSTED_PROXY_CIDR`; else the peer address), full
`GET` at `CISP_PUBLIC_RPM`/60 per second with a burst of 10, `HEAD` and
304 at 10×; 429 with `Retry-After`; the bucket map is bounded (10 000
entries, LRU, counted). `/public/v1/*/versions*` and `/public/v1/changes`
do not exist (404).

## Tests

- `TestVectorsZonesApplicability` (`internal/applicability/vectors_test.go`,
  `RunOwned("cisp")`): each case's periods on a synthetic feature, `At`
  gives the expected verdict; and through the handler: a dataset with
  the case's zone, `GET /v1/zones?at=` includes or excludes it.
- `TestVectorsGeodesy` (`in_polygon`, `in_circle` cases): publish a
  zone with the case's ring or circle, query `?bbox=` of a tiny box
  around the point; the zone is returned whenever `inside` is true (the
  prefilter is conservative; it may also return it when false — assert
  only the presence direction and say so).
- E-01 pairs: `If-None-Match` hit/miss; `bbox` inside/outside;
  `at` inside/outside window plus the `Unknown` case (a daylight
  schedule at a polar latitude gives `cis_applicability: unknown` and
  the feature is present); `since_version` with 0, 1, N changes, `v` >
  current (400), too old (410); unknown dataset (404); `ussp_list` with
  a filter (400).
- Degraded (E-02): pool closed → unfiltered 200 with `X-CIS-Stale`,
  filtered 503 with `Retry-After`; pool back → headers gone.
- Integrity: corrupt `publications.body` in the test database → 500
  `integrity` and the error log line; the snapshot is unaffected.
- Rate limiter: 61st full `GET` in a minute → 429; `HEAD` still 200;
  10 001 distinct IPs evict and count (E-10).
- Response validation against the OpenAPI in every handler test
  (`kin-openapi`).
- Benchmarks: `BenchmarkGetZonesBBox` (5 000 features, box with ~50
  hits; target 100 ms p99 → ns/op budget 50 ms), `BenchmarkHeadDataset`
  (target 5 ms), `BenchmarkGetChanges`.

## Done when

- [ ] 32/32 `zones_applicability` and the geodesy containment cases
  pass through the handlers; lint, race, integration green; coverage
  ≥ 85 % of the owned files.
- [ ] A `curl -I` against `make dev-deps` + a seeded dataset shows the
  headers of `docs/PLAN.md §6.3` (paste).
- [ ] The degraded serving transcript pasted (stop PostgreSQL, `GET`,
  start it, `GET`).
- [ ] CHANGELOG line; outputs pasted (E-04).

## Safety notes

Serving an old version as if current is the CISP's worst failure: a
USSP would authorise against a restriction that no longer exists, or
miss one that does. `X-CIS-Stale` is therefore mandatory on every
degraded response, `Cache-Control: no-store` prevents Caddy from
caching it, and a test asserts both. Never answer `bbox`/`at` from a
stale cache: a filtered answer cannot carry a whole-dataset version
honestly when the rows may be newer than the snapshot.

## Commits

`feat(applicability): evaluate ED-318 applicability at an instant, unknown kept [WP-4 C-M1]`,
`feat(api): read datasets with ETag, bbox, at and since_version [WP-4 C-M1]`,
`feat(api): version history with publisher signatures, the change cursor and status [WP-4 C-M1]`,
`feat(api): the public read subset with per-IP rate limits [WP-4 C-M1]`,
`test(api): run the applicability and geodesy vectors through the read API [WP-4 C-M1]`.
