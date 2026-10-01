# WP-7: the WS change stream, bus resilience and observability

Branch `feat/WP-7-stream-status`. Milestone C-M2. Owns exclusively:
`internal/stream/`, `WS /v1/stream` (the `stream` tag of
`api/openapi.yaml` — documented as an operation with the frame schema
even though OpenAPI 3.1 has no WS verb; a `x-websocket: true` extension
and `GET` with `101`), `internal/bus/` (reconnect policy, degraded
start, subscribe side for the hub; WP-6's consumer code moves under its
policy), `internal/obs/` (the metrics catalogue, the status line
completed, tracing spans on the publication and delivery paths),
`docs/RUNBOOKS/observability.md`. Depends on WP-6 (the bus consumer) and
WP-5 (status items). Peers: WP-10, WP-11, WP-12.

## Read first

1. `CLAUDE.md`, `docs/PLAN.md §2` (the degraded rules), `§6.3`
   (`/v1/status`), `§6.5` (the stream), `§7`, `§9`, `§15` Q23.
2. Spec `02 F3` (`WS /v1/stream` for consoles and the public map; change
   events only, low rate), `05 §5` (console WS throttle, `dropped_frames`
   visible), `05 §6` (NATS down: consoles freeze with age shown).
3. `github.com/coder/websocket` (context-aware accept, `CloseRead`,
   write with a per-message deadline), `nats.go` reconnect options
   (`RetryOnFailedConnect`, `MaxReconnects(-1)`, `DisconnectErrHandler`,
   `ReconnectHandler`, `ClosedHandler`).
4. LESSONS B-08 (reconnect forever; start degraded), E-02 (the console
   must not hang on a dead bus — the exact failure the predecessor had),
   E-09, E-10.

## What to build

### Bus policy (`internal/bus`)

- `Connect` returns within `CISP_NATS_CONNECT_TIMEOUT` (5 s) whether or
  not the broker answered: with `RetryOnFailedConnect` the handle keeps
  trying in the background; `Status()` reports `connected | reconnecting
  since T | never connected`; handlers register state changes into the
  status registry (`nats` degraded since). `api` and `deliver` both
  start in every state and say which in the first status line.
- `Subscribe(ctx, subjects, handler)` for the hub: an ephemeral,
  per-instance push subscription (core NATS delivery of the JetStream
  stream via an ordered consumer) that replays nothing; on reconnect it
  re-subscribes and emits a `stream_resync` event the hub forwards to
  clients (so a console knows it may have missed changes and should
  `HEAD` the datasets).
- Slow-consumer handling: the NATS slow-consumer error is counted and
  logged once per interval, never fatal.

### Stream hub (`internal/stream`)

- `Hub` with bounded clients (`CISP_STREAM_MAX_CLIENTS` per instance,
  default 1 000; the 1 001st gets 503), a per-client send buffer of 64
  frames; a client that cannot keep up is closed with code 1013 and
  counted `stream_clients_dropped`; a server heartbeat frame every 20 s
  with `{type: heartbeat, now, nats: <status>, datasets: {name: version}}`
  so a client can detect staleness and resync; frames `{type: change,
  change: cis/change/v1}` and `{type: resync, since}`.
- `WS /v1/stream?datasets=a,b`: no auth (public) with the per-IP rate
  limiter from WP-4 applied to the upgrade; the console cookie accepted
  too (WP-8's middleware, when present, marks the client as console; no
  difference in content). Origin check: allowed origins from
  `CISP_PUBLIC_BASE_URL` and `CISP_STREAM_ALLOWED_ORIGINS`.
- The hub never queries the database; it forwards what the bus gives
  it. On a bus outage clients receive heartbeats with `nats:
  reconnecting` and no changes; when the bus returns they receive
  `resync`.

### Observability (`internal/obs`)

- The metrics catalogue in `docs/RUNBOOKS/observability.md`: every
  counter, gauge and histogram named in `docs/PLAN.md` with its labels
  and the alert threshold the owner should set (`deliveries_queued` >
  100 for 5 min; `cisp_delivery_first_attempt_seconds` p99 > 2 s;
  `nats` degraded > 60 s; `restriction_expiry_job_age_s` > 30;
  `publisher_stale`), implemented and linted by a test that every
  registered metric is in the document and vice versa.
- Status line finished: one JSON line every 30 s per process with
  every component's state and counters since the last line; at `error`
  when degraded; the first line after start says what was found
  (migrations current, NATS state, JWKS state, mTLS mode, datasets and
  versions, publishers and heartbeat ages). Rate-limited logging helper
  (`obs.Once(key, interval)`) used by every refusal path (E-09).
- Tracing: spans on `PUT /v1/publications`, `POST /v1/restrictions`
  (validate, publish tx, bus publish) and on the delivery attempt
  (claim, sign, post), with the change id as an attribute, exported only
  when `CISP_OTEL_ENDPOINT` is set; the no-op path tested to allocate
  nothing per request beyond the span handle.

## Tests

- Hub: 1 000 clients receive one change each (fan-out order
  irrelevant); the 1 001st is refused; a client that stops reading is
  closed with 1013 within the heartbeat period and counted; heartbeat
  content includes the dataset versions.
- Bus: start `api` with the broker down → the first status line says
  `nats: never connected`, `/readyz` is ready-degraded, a `WS` client
  gets heartbeats with `nats: reconnecting`; start the broker → the
  client gets `resync`, then a change. Stop the broker mid-run → the
  same, with the time since. (Integration, with a NATS process the test
  starts and stops: `nats-server` binary from the module cache, or the
  compose service with `docker stop`; say which.)
- E-02 explicitly: the healthy status line read back and checked field
  by field; the degraded one too.
- Catalogue test: every metric registered appears in the runbook
  table; every table row is registered.
- Benchmarks: `BenchmarkHubFanout1000`.

## Done when

- [ ] Lint, race, integration green; coverage ≥ 85 % in
  `internal/stream`, `internal/bus`, `internal/obs`.
- [ ] The two transcripts (broker down at start; broker stopped during
  a run) pasted, with the status lines.
- [ ] `docs/RUNBOOKS/observability.md` complete; the catalogue test
  green.
- [ ] CHANGELOG line; outputs pasted (E-04).

## Safety notes

The predecessor's console hung for minutes on a dead bus because the
`except` branch had never run (LESSONS E-02). Every process here must
start, serve and say "degraded" with the broker absent, and that must
be a test that actually removes the broker, not a mock that returns an
error. A WS client must be able to tell "no changes" from "no
connection to the bus" from the heartbeat alone.

## Commits

`feat(bus): reconnect forever, start degraded and report the broker state [WP-7 C-M2]`,
`feat(stream): a bounded WS change stream with heartbeats and resync [WP-7 C-M2]`,
`feat(obs): the metrics catalogue, the finished status line and tracing spans [WP-7 C-M2]`,
`docs(runbooks): observability [WP-7 C-M2]`,
`test(bus): start and run with the broker absent [WP-7 C-M2]`.
