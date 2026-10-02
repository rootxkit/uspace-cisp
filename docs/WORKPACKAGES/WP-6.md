# WP-6: subscriptions and the `deliver` process (F3 push)

Branch `feat/WP-6-subscriptions-deliver`. Milestone C-M1. Owns
exclusively: `internal/subscription/`, `internal/deliver/`,
`cmd/deliver` (replaces the WP-0 stub), the `subscriptions` tag of
`api/openapi.yaml` and `internal/httpapi/subscriptions.go`,
`schemas/cis/change/v1.json` (adopting WP-4's draft if it merged first),
`test/e2e/subscriber/` (a small Go subscriber container used by every
e2e test), `internal/bus/` consumer side (durable pull consumer; WP-7
owns the reconnect and degraded-start policy). Depends on WP-1, WP-2.
Peers: WP-3, WP-4, WP-5, WP-8.

## Read first

1. `CLAUDE.md`, `docs/PLAN.md §1.3` (D6, D7), `§6.5`, `§6.7`, `§7`,
   `§8.1` (SSRF row, T4 towards subscribers), `§9` (the 1 s / 2 s
   budget), `§10.5`, `§15` Q9, Q13 (decided).
2. Spec `01 §2` C5, `02 F3` (push: registration, signed notification,
   retry 24 h, delivery log, the subscriber's mandatory 60 s pull), `04
   §3.4` (`cis/change/v1`), `05 §5` (bounded retry queue per
   subscriber), `05 §6`, `06` T4, T8.
3. `uspace-core/auth.Issuer` (for the shape of a compact JWS with
   claims; you sign with `internal/jws.KeyRing.SignCompact`),
   `nats.go` JetStream pull consumers (`Fetch`, `Ack`, `Nak` with delay,
   `max_ack_pending`), `net/http` client with a custom `DialContext`
   that refuses private addresses at dial time (the SSRF guard must run
   on the **resolved** address, not only on the hostname).
4. LESSONS B-05 (persist before you acknowledge), B-07 (bounded,
   counted), B-08, E-02, E-09, E-10, E-14.

## What to build

### Subscription model (`internal/subscription`, pure)

```go
type Subscription struct{ ID, ClientID, CallbackURL string; Datasets []publication.Dataset; BBox *geodesy.BBox; Status Status }
type Status string   // PendingVerification, Active, Suspended, Deleted
func ValidateCallbackURL(raw string, pol URLPolicy) error              // https only (http to localhost when pol.AllowInsecure), no userinfo, no fragment, host <= 253, no literal IP unless pol.AllowPrivate, not a .local/.internal/.localhost name unless AllowPrivate
func Matches(s Subscription, c publication.Change) bool               // dataset in Datasets, and (c.BBox == nil || s.BBox == nil || intersect)
func AllowedAddress(ip net.IP, pol URLPolicy) bool                    // refuses loopback, private (RFC 1918, ULA), link-local, multicast, unspecified, CGNAT 100.64/10 unless AllowPrivate
type Retry struct{ Base, Max, Window time.Duration }                  // 1 s, 300 s, 24 h
func NextAttempt(attempt int, changeAt, now time.Time, r Retry) (time.Time, bool)   // doubling from Base, capped at Max, jitter ±10 %, false once now > changeAt + Window
const MaxConsecutiveFailures = 50; const SuspendAfter = time.Hour
```

### Endpoints (`internal/httpapi/subscriptions.go`)

As `docs/PLAN.md §6.5`: create (`cis.read`; ≤ 20 per client, 409
`limit`), get, list (own; console sees all through WP-8), patch, delete,
deliveries list (joins `deliveries` with `delivery_attempts` from the
timeseries database through the read-only role), retry (re-queues:
`state: queued`, `next_retry_at: now`, audited). A new subscription is
`pending_verification`; the handler inserts a `deliveries` row for a
synthetic change `reason: subscription_test` (not in `changes`, `change_id`
null) and `deliver` activates the subscription on the first 2xx. `GET`
on a pending subscription says `pending_verification` with the last
attempt's error.

### `deliver` (`internal/deliver`, `cmd/deliver`)

- **Intake**: durable pull consumer `deliver` on `CIS_CHANGES`
  (`AckExplicit`, `MaxAckPending` 256, `AckWait` 30 s, `MaxDeliver` 20
  then a counted `bus_poison` and ack). For each change: load active
  and pending subscriptions, `Matches`, insert one `deliveries` row per
  match (`queued`, `next_retry_at: now`) in one transaction — `ON
  CONFLICT (subscription_id, change_id) DO NOTHING` makes redelivery
  idempotent (B-05) — then ack.
- **Reconciliation scan** every 10 s: `changes` rows with `id >
  watermark` that have no `deliveries` row for a matching active
  subscription get one (covers a lost publish, D6); the watermark is the
  max cursor seen, persisted in a `deliver_state` row. The scan is
  counted (`deliveries_from_scan`) so a non-zero count after a NATS
  outage is readable (E-02).
- **Sender** loop: claim due rows (`SELECT ... WHERE next_retry_at <= now
  AND state IN (queued, failed) ORDER BY next_retry_at FOR UPDATE SKIP
  LOCKED LIMIT 64`), mark `delivering`, build the body: the
  `cis/change/v1` record (`schema`, `msg_id` = change id, `producer` =
  `cisp/deliver-<instance>`, `dataset`, `version`, `etag`,
  `feature_ids`, `removed_ids`, `reason`, `at`, `pull_url` =
  `CISP_PUBLIC_BASE_URL + /v1/{dataset}?since_version=<prev>` — always
  on the CISP's configured base host, because receivers honour a
  `pull_url` only when its host is the issuer's, M5), `bbox?`), signed
  `SignCompact` as core writes a compact delivery: the payload is
  `{iss, aud, sub, iat, jti, body}` with the record in `body`, `iss`
  (`CISP_ISSUER_URL`), **`aud` = the host of the subscription's
  `callback_url`** without its port (M19; the audience rule of
  `docs/PLAN.md §8.2` applied to webhooks, never the client id), `sub`
  (subscription id), `iat`, `jti` (delivery id). There is no `exp`: a
  delivery is single use, core's `CompactVerifier` refuses an `iat`
  more than 5 min old, and the receiver's store keyed on `jti` is the
  replay guard (`docs/PLAN.md §15 Q38`); `POST` with `Content-Type:
  application/jose`, `User-Agent: uspace-cisp/<version>`,
  `X-CIS-Delivery-Id`, `X-CIS-Attempt`; the client: 2 s total timeout,
  no redirects (a 3xx is a failure), response body read to 1 KiB then
  discarded, TLS 1.2+, the SSRF `DialContext`, 64 in flight per instance
  (a semaphore; E-10). 2xx → `delivered`, `delivered_at`, and
  `subscriptions.last_success_at`, `consecutive_failures = 0`; anything
  else → `failed`, `attempts++`, `next_retry_at` from `NextAttempt`
  or `expired` after the window; `consecutive_failures++` and
  `suspended` after 50 over ≥ 1 h (`suspended_reason` says since when
  and the last error). Every attempt is one `delivery_attempts` row
  (`latency_ms`, `status_code`, `error`, `payload_bytes`, instance).
- **Metrics**: `cisp_delivery_first_attempt_seconds` histogram (from
  `changes.at` to the first attempt's end), `cisp_delivery_result_total{code}`,
  `deliveries_queued` gauge, `deliveries_expired_total`,
  `subscriptions_suspended`, `deliveries_from_scan_total`, in-flight
  gauge; the status line prints queue depth, oldest due, instance in
  flight, broker state.
- **Lifecycle**: SIGTERM stops claiming, finishes in-flight within 5 s,
  `Nak`s unacked intake, exits 0; two instances share the work (SKIP
  LOCKED + durable consumer) — tested.

Delivery reasons and the receivers (M5, M16): the `reason` enumeration
of `cis/change/v1` includes `subscription_test` and `republished`.
Every receiver in the ecosystem acknowledges these two, and any reason
it does not know, with `204` **without pulling** (the additive-enum
rule of `04 §4`); only the publication and restriction reasons trigger
a pull. Say so in the schema's description and in `api/README.md`, so a
subscriber author reads it where the contract is. The receivers' path
is `POST /v1/cis/notifications` everywhere (M1), but `deliver` posts to
the registered `callback_url` and never assumes a path.

### Subscriber container (`test/e2e/subscriber/`)

A 150-line Go program: listens on `:8080` at `/v1/cis/notifications`
(the ecosystem path, M1), verifies each JWS against `CISP_JWKS_URL`
(through `uspace-core/auth`-style `jwk.Cache`) with `aud` = its own
host, records `{received_at, delivery_id, change_id, reason, verified,
pulled}` to stdout as JSON lines and to `GET /received`, answers 2xx,
and pulls `pull_url` only for a publication or restriction reason and
only when its host equals `CISP_PUBLIC_BASE_URL`'s (the reference
reading of M5 for every sibling); `FAIL_FIRST=n` makes it fail the
first n attempts with 500; `SLOW_MS` delays. Built into an image by the
e2e compose. The lab may reuse it.

## Tests

- Unit: `ValidateCallbackURL` and `AllowedAddress` E-01 pairs for every
  class (https ok; http localhost with and without `AllowInsecure`;
  userinfo; fragment; 254-char host; literal public IP vs private;
  `.local`); `Matches` with and without bbox on both sides and a
  touching box; `NextAttempt` sequence 1, 2, 4 … 300 s with jitter
  bounds, and `false` exactly past the window; `MaxConsecutiveFailures`
  boundary.
- Sender against `httptest.Server`s: 200, 500 then 200 (retry
  schedule honoured, attempts logged), 301 (failure), a 3 s handler
  (timeout at 2 s), a server on a private address refused at dial
  (counted `ssrf_refused`), a 1 MiB response body (only 1 KiB read).
  JWS verified by the test with the key ring's JWKS: `iss`, `aud` (=
  the callback host, asserted against a `callback_url` with a port and
  one without), `sub`, `jti`, `iat` present and no `exp` (an `iat` more
  than 5 min old refused by `CompactVerifier`); a signature by another key
  is refused by the subscriber helper (T4 pair); the helper does not
  pull on `subscription_test` and `republished` and does pull on
  `publication` (E-01 pair), and refuses a `pull_url` on another host.
- Integration: intake creates one row per matching subscription and is
  idempotent on redelivery (publish the same `Nats-Msg-Id` twice; the
  change twice through the consumer); the scan creates rows for a
  change that never reached NATS (write `changes` directly) and counts
  them; two `deliver` instances deliver each row exactly once; SIGTERM
  mid-batch loses nothing; `subscription_test` ping activates a
  subscription on 2xx and leaves it pending on 500 with the error
  visible on `GET`.
- e2e (`test/e2e/webhook_latency_test.go`): compose up; the
  authority-role test client (a `cispctl sign`-based helper) publishes
  a zone set; the subscriber container's `received_at - changes.at`
  printed per subscription; assert `< 2 s`, report p50/p99 of 20
  publications in the step summary (C-M1: "within 1 s" is reported as
  measured). Kill the subscriber for one publication, restart it: the
  retry delivers; the subscriber's own `HEAD` reconciliation (simulated
  by the test) sees the new `ETag` within 60 s — the C-M3 proof, run
  here first.

## Done when

- [ ] Lint, race, integration green; coverage ≥ 85 % in
  `internal/subscription` and `internal/deliver`.
- [ ] The e2e latency summary pasted (p50, p99 over 20 publications).
- [ ] The NATS-outage transcript pasted: broker stopped, publication
  accepted, `deliveries_from_scan_total` increments, delivery arrives
  (E-02).
- [ ] `schemas/cis/change/v1.json` with examples validated in CI;
  `uspace-lab/schemas/` mirror proposed in the PR body.
- [ ] CHANGELOG line; outputs pasted (E-04).

## Safety notes

The webhook is the regulatory channel for a restriction (`02 F2`); its
latency is the CISP's one real-time promise. Never let a slow or dead
subscriber slow another (per-row claiming, per-request timeout, a
bounded in-flight set); never drop a delivery silently (every outcome is
a row and a counter; expiry is a state, not a deletion); never trust a
subscriber's URL (the SSRF guard at dial time, no redirects). And the
branch that says nothing is wrong: a healthy run must print "0 queued,
0 due" and the test must read that line.

## Commits

`feat(subscription): callback policy, matching and the retry schedule [WP-6 C-M1]`,
`feat(api): subscription registration, verification ping, deliveries and retry [WP-6 C-M1]`,
`feat(deliver): fan out signed change notifications from JetStream with a reconciliation scan [WP-6 C-M1]`,
`docs(schemas): cis/change/v1 with examples [WP-6 C-M1]`,
`test(e2e): a verifying subscriber container and the webhook latency measurement [WP-6 C-M1]`.
