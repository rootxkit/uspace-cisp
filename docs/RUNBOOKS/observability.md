# Runbook: observability

What `api` and `deliver` say about themselves, where it is said, and
what the owner should alert on. The CISP fails visible, never silent
(CLAUDE.md hard rule 4): every dependency that is down is named in the
status line, in `GET /v1/status`, in `/readyz` and, for the bus, in
every frame of `WS /v1/stream`.

## Where to look

| Surface | Who reads it | What it says |
|---|---|---|
| The status line (stdout, JSON, `"msg":"status"`) | operators, log search | one line per process every `CISP_STATUS_INTERVAL_S` (30 s): every component with its counters **since the previous line**, its gauges, a one-line `summary`, a `warning` and a `degraded` reason. Level `INFO` when nothing is wrong, `WARN` when a component warns (a silent publisher), `ERROR` when anything is degraded (a dependency down, a disabled safeguard such as `CISP_MTLS_MODE=off`, a metric outside this catalogue is a warning). The first line after a start carries `"start": true` and is the line that says what the process found: migrations, `nats` (connected / `never connected (trying since T)`), `jwks`, `mtls`, `datasets` (each dataset's current version), `publishers` (each publisher's heartbeat age). |
| `GET /metrics` (internal network only) | Prometheus | every metric in the catalogue below, with totals, plus the Go runtime and process collectors (`go_*`, `process_*`). |
| `GET /readyz` | the orchestrator | ready = the database answers and its migrations are current; `nats` is reported and never decides (an instance without the bus is ready, degraded). |
| `GET /v1/status` (`cis.read`) | consumers, consoles | per dataset `current_version`, per publisher `last_heartbeat_at` and `stale`, `degraded[]` with since-times. |
| `WS /v1/stream` `console/status/v1` | consoles, the public map | every 2 s: `nats` (`connected`, `reconnecting`, `never_connected`, `not_configured`) with `nats_since`, `degraded[]` (`database`, `nats`, `jwks`, `publisher_stale`) with `degraded_since`, each dataset's version and age, `cis_age_s`, and `resync_since` once after the bus returns. A client tells "no changes" (statuses keep arriving, `nats: connected`) from "no connection to the bus" (`nats: reconnecting`) from "no connection to the CISP" (no status for `live_max_age_s`). |
| Traces (only when `CISP_OTEL_ENDPOINT` is set) | the owner's collector | spans `validate`, `publish_tx` and `bus_publish` under the server span of `PUT /v1/publications/{dataset}` and `POST /v1/restrictions`, and one `delivery_attempt` span per webhook attempt with `claim`, `sign` and `post` under it, each with the change id (`cisp.change_id`). With the variable unset nothing is started: the path allocates nothing beyond the request's context. |

Refusal paths log through `obs.Once(key, interval)`: the first refusal
of a kind is logged at once, then at most one line a minute with the
number held back (`also_refused_since_last_line`); the counters count
every one.

## The broker (NATS)

Both processes start with the broker absent: they wait at most
`CISP_NATS_CONNECT_TIMEOUT_S` (5 s), then start degraded
(`nats: never connected`) and keep reconnecting for ever (LESSONS
B-08). Writes still commit while the broker is down; `deliver`'s scan
queues their webhooks; the stream's clients are told
`nats: reconnecting since T` and get no changes; when the broker
returns they get a status with `resync_since` = the instant the
connection was lost and should `HEAD` the datasets and pull by
`since_version`. A NATS slow-consumer error is counted
(`cisp_nats_slow_consumer_total`), logged once a minute and answered
with a resync; it is never fatal.

## The WS stream

At most `CISP_STREAM_MAX_CLIENTS` (1 000) clients per `api` instance;
the next upgrade is `503 stream_full` (`cisp_stream_refused_capacity_total`).
Each client has a queue of `CISP_STREAM_SEND_BUFFER_FRAMES` (64)
frames: a frame that does not fit is dropped and shows in the client's
`dropped_frames`; a client still full at the next status period is
closed with 1013 (`cisp_stream_clients_dropped_total`). An upgrade from
an Origin outside the allow-list (`CISP_PUBLIC_BASE_URL`'s origin and
`CISP_STREAM_ALLOWED_ORIGINS`) is `403 origin`. With
`CISP_STREAM_PUBLIC=false` a client without a valid `uspace_session`
cookie is closed with 4401 (re-login).

## The metrics catalogue

Every metric the processes register. Counters registered through the
status line (`component` label = the status line's component) are
`cisp_<name>_total`; its gauges are `cisp_<name>`. `internal/obs`
holds the same table (`obs.Catalogue`); a test fails when the two
differ, and another when the code registers a metric the table does
not hold. A process that registers one anyway says so in its status
line (`metrics_uncatalogued`, warning).

The alert column is what the owner should set; `—` is no alert (the
metric is for diagnosis). Thresholds are the plan's (docs/PLAN.md
section 9) where it names one.

| Metric | Kind | Labels | Meaning | Alert |
|---|---|---|---|---|
| `cisp_accepted_total` | counter | `component` | Authentication outcomes: accepted (component auth: bearer tokens; signature: see signature_*). | — |
| `cisp_applicability_unknown_total` | counter | `component` | Dataset reads. | — |
| `cisp_attempt_record_failed_total` | counter | `component` | Refused publication or restriction attempts that could not be recorded. | any increase |
| `cisp_bus_change_unreadable_total` | counter | `component` | Bus messages on cis.v1.change.* that are not a cis/change/v1 record (dropped by the stream). | any increase |
| `cisp_bus_poison_total` | counter | `component` | Bus messages deliver could not read (acknowledged and dropped; the scan covers the change). | any increase |
| `cisp_bus_publish_failed_total` | counter | `component` | Committed changes whose bus publish failed (deliver's scan covers them). | any increase |
| `cisp_bus_publish_skipped_total` | counter | `component` | Committed changes not published because no bus is configured. | — |
| `cisp_change_bbox_unavailable_total` | counter | `component` | Changes committed without a bbox (the whole dataset is announced). | — |
| `cisp_console_actions_total` | counter | `component` | Console actions written (accounts, subscriptions, retries, republications). | — |
| `cisp_console_logins_refused_total` | counter | `component` | Console logins refused (wrong credentials, locked, TOTP, challenge). | a burst (password guessing) |
| `cisp_console_logins_total` | counter | `component` | Console sessions issued. | — |
| `cisp_console_mfa_challenges_total` | counter | `component` | Console MFA challenges opened (passwords accepted for an account with MFA). | — |
| `cisp_deliveries_delivered_total` | counter | `component` | Webhook delivery outcomes. | — |
| `cisp_deliveries_due` | gauge | `component` | Deliveries due now. | — |
| `cisp_deliveries_expired_total` | counter | `component` | Deliveries given up 24 h after their change. | any increase |
| `cisp_deliveries_failed_total` | counter | `component` | Webhook delivery outcomes. | — |
| `cisp_deliveries_from_bus_total` | counter | `component` | Webhook delivery intake. | — |
| `cisp_deliveries_from_scan_total` | counter | `component` | Webhook delivery intake. | — |
| `cisp_deliveries_in_flight` | gauge | `component` | Webhook POSTs in flight on this instance. | — |
| `cisp_deliveries_oldest_due_s` | gauge | `component` | Seconds the oldest due delivery has waited. | above 60 |
| `cisp_deliveries_queued` | gauge | `component` | Deliveries queued and not yet delivered. | above 100 for 5 min |
| `cisp_deliveries_requeued_total` | counter | `component` | Subscriptions. | — |
| `cisp_delivery_claim_failed_total` | counter | `component` | Delivery bookkeeping failures. | — |
| `cisp_delivery_first_attempt_seconds` | histogram | — | From a change's commit (changes.at) to its first webhook attempt. | p99 above 2 s for 10 min |
| `cisp_delivery_log_read_failed_total` | counter | `component` | Delivery-log reads that failed (the list says unavailable). | — |
| `cisp_delivery_log_write_failed_total` | counter | `component` | Delivery bookkeeping failures. | — |
| `cisp_delivery_payload_too_large_total` | counter | `component` | Webhooks not sent because the signed token is over CISP_WEBHOOK_MAX_TOKEN_BYTES (expired; the subscriber is not charged). | any increase |
| `cisp_delivery_record_failed_total` | counter | `component` | Delivery bookkeeping failures. | — |
| `cisp_delivery_result_total` | counter | `code` | Webhook attempts by result code (2xx, 4xx, 5xx, timeout, refused, ...). | — |
| `cisp_delivery_scan_failed_total` | counter | `component` | Reconciliation scans that failed. | any increase for 1 min |
| `cisp_delivery_scans_total` | counter | `component` | Webhook delivery intake. | — |
| `cisp_delivery_sign_failed_total` | counter | `component` | Delivery bookkeeping failures. | — |
| `cisp_ed269_exported_total` | counter | `component` | Versions exported as ED-269 through uspace-core (format=ed269). | — |
| `cisp_ed269_not_representable_total` | counter | `component` | ED-269 exports refused 406 because the version holds what ED-269 cannot. | — |
| `cisp_expiry_last_tick_failures` | gauge | `component` | Restrictions the last expiry tick could not expire. | above 0 |
| `cisp_expiry_ticks_not_leader_total` | counter | `component` | Expiry ticks. | — |
| `cisp_expiry_ticks_total` | counter | `component` | Expiry ticks. | — |
| `cisp_handler_panics_total` | counter | `component` | Handler panics turned into 500 responses. | any increase |
| `cisp_heartbeat_ref_missing_total` | counter | `component` | Active restrictions the ANSP's heartbeat does not declare (shown, never acted on). | — |
| `cisp_heartbeat_ref_unknown_total` | counter | `component` | ansp_refs the ANSP declares active that the CISP does not hold as active (shown, never acted on). | — |
| `cisp_heartbeat_rejected_not_publisher_total` | counter | `component` | Publisher heartbeats. | — |
| `cisp_heartbeats_total` | counter | `component` | Publisher heartbeats. | — |
| `cisp_http_request_seconds` | histogram | `route`, `code` | HTTP request duration by operation and status. | p99 of route="GET /v1/{dataset}" with a 304 above 0.005 s for 10 min (the HEAD budget, docs/PLAN.md section 9) |
| `cisp_intake_failed_total` | counter | `component` | Bus messages deliver could not queue (redelivered). | any increase for 5 min |
| `cisp_integrity_failed_total` | counter | `component` | Stored versions whose body hash did not match when served. | any increase |
| `cisp_jwks_cache_write_failed_total` | counter | `component` | JWKS disk copy writes that failed (the previous copy stays). | any increase |
| `cisp_jwks_cache_written_total` | counter | `component` | JWKS disk copy writes. | — |
| `cisp_mtls_off_passed_total` | counter | `component` | Requests passed without a client certificate because CISP_MTLS_MODE=off. | any increase in production |
| `cisp_nats_degraded_s` | gauge | `component` | Seconds the broker connection has been down (0 when connected). | above 60 |
| `cisp_nats_reconnects_total` | counter | `component` | Reconnections to the broker after a loss. | — |
| `cisp_nats_slow_consumer_total` | counter | `component` | NATS slow-consumer errors on this process's subscriptions (messages dropped by the client). | any increase |
| `cisp_outline_failed_total` | counter | `component` | Circles served without cis_display_geometry because no outline could be drawn. | any increase |
| `cisp_publication_seconds` | histogram | `dataset`, `outcome` | PUT /v1/publications/{dataset} from the body read to the answer, by outcome (accepted, unchanged, refused, failed). | p95 of outcome="accepted" above 10 s (docs/PLAN.md section 9) |
| `cisp_publications_accepted_total` | counter | `component` | Publication intake outcomes (component = the dataset). | — |
| `cisp_publications_refused_total` | counter | `component` | Publication intake outcomes (component = the dataset). | — |
| `cisp_publications_unchanged_total` | counter | `component` | Publication intake outcomes (component = the dataset). | — |
| `cisp_publisher_stale` | gauge | `component` | Configured publishers whose last heartbeat is older than stale_after_s (or never heard). | above 0 (warning: the publisher is silent; nothing is ended) |
| `cisp_rate_limit_clients_evicted_total` | counter | `component` | Public reads limited per client. | — |
| `cisp_rate_limit_forwarded_for_unreadable_total` | counter | `component` | Public reads limited per client. | — |
| `cisp_rate_limited_total` | counter | `component` | Public reads limited per client. | — |
| `cisp_rejected_algorithm_total` | counter | `component` | Bearer tokens refused, by core's reason (component auth). | — |
| `cisp_rejected_audience_total` | counter | `component` | Bearer tokens refused, by core's reason (component auth). | — |
| `cisp_rejected_claims_total` | counter | `component` | Bearer tokens refused, by core's reason (component auth). | — |
| `cisp_rejected_expired_total` | counter | `component` | Bearer tokens refused, by core's reason (component auth). | — |
| `cisp_rejected_issuer_total` | counter | `component` | Bearer tokens refused, by core's reason (component auth). | — |
| `cisp_rejected_kid_total` | counter | `component` | Bearer tokens refused, by core's reason (component auth). | — |
| `cisp_rejected_malformed_total` | counter | `component` | Bearer tokens refused, by core's reason (component auth). | — |
| `cisp_rejected_mtls_missing_total` | counter | `component` | Bearer tokens refused by the CISP's own rules (component auth). | — |
| `cisp_rejected_mtls_subject_total` | counter | `component` | Bearer tokens refused by the CISP's own rules (component auth). | — |
| `cisp_rejected_no_token_total` | counter | `component` | Bearer tokens refused by the CISP's own rules (component auth). | — |
| `cisp_rejected_not_yet_valid_total` | counter | `component` | Bearer tokens refused, by core's reason (component auth). | — |
| `cisp_rejected_publisher_binding_total` | counter | `component` | Bearer tokens refused by the CISP's own rules (component auth). | — |
| `cisp_rejected_scope_total` | counter | `component` | Bearer tokens refused by the CISP's own rules (component auth). | — |
| `cisp_rejected_signature_total` | counter | `component` | Bearer tokens refused, by core's reason (component auth). | — |
| `cisp_rejected_too_large_total` | counter | `component` | Bearer tokens refused, by core's reason (component auth). | — |
| `cisp_restriction_expiry_failed_total` | counter | `component` | Restrictions the expiry could not expire. | any increase |
| `cisp_restriction_expiry_job_age_s` | gauge | `component` | Seconds since the restriction expiry last ran (the database's clock). | above 30 |
| `cisp_restrictions_accepted_total` | counter | `component` | Dynamic restrictions. | — |
| `cisp_restrictions_active` | gauge | `component` | Active restrictions. | — |
| `cisp_restrictions_expired_total` | counter | `component` | Dynamic restrictions. | — |
| `cisp_restrictions_refused_total` | counter | `component` | Dynamic restrictions. | — |
| `cisp_restrictions_replayed_total` | counter | `component` | Dynamic restrictions. | — |
| `cisp_session_accepted_total` | counter | `component` | Console sessions verified on a console route. | — |
| `cisp_session_check_failed_total` | counter | `component` | Console requests refused 503 because the revocation list could not be read or a session's use could not be recorded (fail closed). | any increase |
| `cisp_session_rejected_idle_total` | counter | `component` | Console sessions refused by the console's rules (component console_auth). | — |
| `cisp_session_rejected_not_session_total` | counter | `component` | Console sessions refused by the console's rules (component console_auth). | — |
| `cisp_session_rejected_realm_total` | counter | `component` | Console sessions refused by the console's rules (component console_auth). | — |
| `cisp_session_rejected_revoked_total` | counter | `component` | Console sessions refused by the console's rules (component console_auth). | — |
| `cisp_session_rejected_role_too_low_total` | counter | `component` | Console sessions refused by the console's rules (component console_auth). | — |
| `cisp_session_rejected_role_total` | counter | `component` | Console sessions refused by the console's rules (component console_auth). | — |
| `cisp_session_revocation_cache_bypassed_total` | counter | `component` | Session checks that asked the database because the revocation cache was full or stale. | sustained increase |
| `cisp_signature_accepted_total` | counter | `component` | Publisher body signatures by outcome. | — |
| `cisp_signature_cache_evicted_total` | counter | `component` | Version signatures evicted from the bounded cache. | — |
| `cisp_signature_rejected_algorithm_total` | counter | `component` | Publisher body signatures by outcome. | — |
| `cisp_signature_rejected_crit_total` | counter | `component` | Publisher body signatures by outcome. | — |
| `cisp_signature_rejected_empty_total` | counter | `component` | Publisher body signatures by outcome. | — |
| `cisp_signature_rejected_iat_total` | counter | `component` | Publisher body signatures by outcome. | — |
| `cisp_signature_rejected_kid_total` | counter | `component` | Publisher body signatures by outcome. | — |
| `cisp_signature_rejected_malformed_total` | counter | `component` | Publisher body signatures by outcome. | — |
| `cisp_signature_rejected_publisher_binding_total` | counter | `component` | Publisher body signatures by outcome. | — |
| `cisp_signature_rejected_publisher_total` | counter | `component` | Publisher body signatures by outcome. | — |
| `cisp_signature_rejected_signature_total` | counter | `component` | Publisher body signatures by outcome. | — |
| `cisp_signature_rejected_too_large_total` | counter | `component` | Publisher body signatures by outcome. | — |
| `cisp_snapshot_cache_evicted_total` | counter | `component` | Snapshot cache. | — |
| `cisp_snapshot_cache_oversize_total` | counter | `component` | Snapshot cache. | — |
| `cisp_snapshot_cache_refresh_failed_total` | counter | `component` | Snapshot cache refreshes that failed (reads carry X-CIS-Stale). | any increase for 1 min |
| `cisp_ssrf_refused_total` | counter | `component` | Callback dials refused by the address policy. | — |
| `cisp_stale_publisher_served_total` | counter | `component` | Dataset reads. | — |
| `cisp_stale_refused_total` | counter | `component` | Dataset reads. | — |
| `cisp_stale_served_total` | counter | `component` | Dataset reads. | — |
| `cisp_stream_changes_total` | counter | `component` | cis/change/v1 records the hub received from the bus. | — |
| `cisp_stream_clients` | gauge | `component` | WS /v1/stream clients connected to this instance. | above 900 (90 % of CISP_STREAM_MAX_CLIENTS) |
| `cisp_stream_clients_dropped_total` | counter | `component` | Stream clients closed with 1013 because their send buffer was full. | — |
| `cisp_stream_frames_dropped_total` | counter | `component` | Frames not queued for a client whose send buffer was full (its dropped_frames). | — |
| `cisp_stream_frames_sent_total` | counter | `component` | Frames written to stream clients. | — |
| `cisp_stream_refused_capacity_total` | counter | `component` | Stream upgrades refused 503 at CISP_STREAM_MAX_CLIENTS. | any increase |
| `cisp_stream_refused_origin_total` | counter | `component` | Stream upgrades refused 403 for an Origin outside the allow-list. | — |
| `cisp_stream_refused_request_total` | counter | `component` | Stream upgrades refused 400 (an unknown dataset, not a WebSocket upgrade). | — |
| `cisp_stream_resyncs_total` | counter | `component` | Bus reconnections the hub announced with resync_since. | — |
| `cisp_stream_session_ignored_total` | counter | `component` | Session cookies on a public stream that did not verify (served as public). | — |
| `cisp_stream_session_refused_total` | counter | `component` | Stream clients closed with 4401 (no or an invalid session on a non-public stream). | — |
| `cisp_stream_sessions_total` | counter | `component` | Stream clients whose session cookie verified (console clients). | — |
| `cisp_subscriptions_changed_total` | counter | `component` | Subscriptions. | — |
| `cisp_subscriptions_created_total` | counter | `component` | Subscriptions. | — |
| `cisp_subscriptions_deleted_total` | counter | `component` | Subscriptions. | — |
| `cisp_subscriptions_refused_total` | counter | `component` | Subscriptions. | — |
| `cisp_subscriptions_suspended` | gauge | `component` | Subscriptions suspended now. | — |
| `cisp_subscriptions_suspended_total_total` | counter | `component` | Subscriptions suspended after 50 consecutive failures over 1 h. | — |
| `cisp_subscriptions_verified_total` | counter | `component` | Webhook delivery outcomes. | — |

The alerts in one place (the brief's set): `cisp_deliveries_queued`
above 100 for 5 min; `cisp_delivery_first_attempt_seconds` p99 above
2 s; `cisp_nats_degraded_s` above 60 (the broker down for a minute);
`cisp_restriction_expiry_job_age_s` above 30; `cisp_publisher_stale`
above 0 (a warning: a silent publisher is flagged, never ended).
