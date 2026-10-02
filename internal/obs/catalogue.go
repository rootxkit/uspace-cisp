package obs

import (
	"sort"
	"strings"
)

// Kind is a metric's Prometheus type.
type Kind string

// The metric kinds.
const (
	KindCounter   Kind = "counter"
	KindGauge     Kind = "gauge"
	KindHistogram Kind = "histogram"
)

// Metric is one row of the metrics catalogue: the Prometheus name, its
// type, labels, meaning and the alert the owner should set ("" when
// none). docs/RUNBOOKS/observability.md holds the same rows, and a test
// keeps the two equal.
type Metric struct {
	Name   string
	Kind   Kind
	Labels []string
	Help   string
	Alert  string
}

// counterName and gaugeName are the Prometheus names of a Status
// counter or gauge (Component.Counter, Component.Gauge).
func counterName(short string) string { return "cisp_" + short + "_total" }
func gaugeName(short string) string   { return "cisp_" + short }

var componentLabel = []string{"component"}

func counters(help string, names ...string) []Metric {
	out := make([]Metric, 0, len(names))
	for _, n := range names {
		out = append(out, Metric{Name: counterName(n), Kind: KindCounter, Labels: componentLabel, Help: help})
	}
	return out
}

func counter(name, help, alert string) Metric {
	return Metric{Name: counterName(name), Kind: KindCounter, Labels: componentLabel, Help: help, Alert: alert}
}

func gauge(name, help, alert string) Metric {
	return Metric{Name: gaugeName(name), Kind: KindGauge, Labels: componentLabel, Help: help, Alert: alert}
}

// tokenRefusals are the reasons core's verifier names a refused bearer
// token by (uspace-core/auth Counter*), counted by the auth guard.
var tokenRefusals = []string{
	"rejected_algorithm", "rejected_audience", "rejected_claims", "rejected_expired", "rejected_issuer",
	"rejected_kid", "rejected_malformed", "rejected_not_yet_valid", "rejected_signature", "rejected_too_large",
}

// signatureOutcomes are the outcomes of a publisher's detached body
// signature (internal/jws SignatureGuard counts them as signature_<x>).
var signatureOutcomes = []string{
	"accepted", "rejected_algorithm", "rejected_crit", "rejected_empty", "rejected_iat", "rejected_kid",
	"rejected_malformed", "rejected_publisher", "rejected_publisher_binding", "rejected_signature", "rejected_too_large",
}

func prefixed(prefix string, names []string) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, prefix+n)
	}
	return out
}

// Catalogue is every metric the CISP's processes register beside the
// Go runtime and process collectors (go_*, process_*). Status refuses a
// counter or gauge outside it once CheckCatalogue is on (the processes
// turn it on): the status line then warns and names it.
var Catalogue = buildCatalogue()

func buildCatalogue() []Metric {
	var m []Metric
	add := func(ms ...Metric) { m = append(m, ms...) }

	// HTTP and the publication path.
	add(Metric{Name: "cisp_http_request_seconds", Kind: KindHistogram, Labels: []string{"route", "code"},
		Help: "HTTP request duration by operation and status.", Alert: `p99 of route="GET /v1/{dataset}" with a 304 above 0.005 s for 10 min (the HEAD budget, docs/PLAN.md section 9)`})
	add(Metric{Name: "cisp_publication_seconds", Kind: KindHistogram, Labels: []string{"dataset", "outcome"},
		Help: "PUT /v1/publications/{dataset} from the body read to the answer, by outcome (accepted, unchanged, refused, failed).", Alert: `p95 of outcome="accepted" above 10 s (docs/PLAN.md section 9)`})
	add(counter("handler_panics", "Handler panics turned into 500 responses.", "any increase"))
	add(counters("Publication intake outcomes (component = the dataset).", "publications_accepted", "publications_refused", "publications_unchanged")...)
	add(counter("attempt_record_failed", "Refused publication or restriction attempts that could not be recorded.", "any increase"))
	add(counters("Publisher heartbeats.", "heartbeats", "heartbeat_rejected_not_publisher")...)
	add(counter("heartbeat_ref_unknown", "ansp_refs the ANSP declares active that the CISP does not hold as active (shown, never acted on).", ""))
	add(counter("heartbeat_ref_missing", "Active restrictions the ANSP's heartbeat does not declare (shown, never acted on).", ""))
	add(gauge("publisher_stale", "Configured publishers whose last heartbeat is older than stale_after_s (or never heard).", "above 0 (warning: the publisher is silent; nothing is ended)"))

	// Reads.
	add(counters("Dataset reads.", "applicability_unknown", "stale_publisher_served", "stale_refused", "stale_served")...)
	add(counter("integrity_failed", "Stored versions whose body hash did not match when served.", "any increase"))
	add(counter("signature_cache_evicted", "Version signatures evicted from the bounded cache.", ""))
	add(counters("Public reads limited per client.", "rate_limited", "rate_limit_clients_evicted", "rate_limit_forwarded_for_unreadable")...)

	// Restrictions.
	add(counters("Dynamic restrictions.", "restrictions_accepted", "restrictions_refused", "restrictions_replayed", "restrictions_expired")...)
	add(gauge("restrictions_active", "Active restrictions.", ""))
	add(counter("restriction_expiry_failed", "Restrictions the expiry could not expire.", "any increase"))
	add(counters("Expiry ticks.", "expiry_ticks", "expiry_ticks_not_leader")...)
	add(gauge("expiry_last_tick_failures", "Restrictions the last expiry tick could not expire.", "above 0"))
	add(gauge("restriction_expiry_job_age_s", "Seconds since the restriction expiry last ran (the database's clock).", "above 30"))

	// Subscriptions (api).
	add(counters("Subscriptions.", "subscriptions_created", "subscriptions_refused", "subscriptions_changed", "subscriptions_deleted", "deliveries_requeued")...)
	add(counter("delivery_log_read_failed", "Delivery-log reads that failed (the list says unavailable).", ""))

	// Authentication.
	add(counter("accepted", "Authentication outcomes: accepted (component auth: bearer tokens; signature: see signature_*).", ""))
	add(counters("Bearer tokens refused, by core's reason (component auth).", tokenRefusals...)...)
	add(counters("Bearer tokens refused by the CISP's own rules (component auth).",
		"rejected_no_token", "rejected_scope", "rejected_publisher_binding", "rejected_mtls_missing", "rejected_mtls_subject")...)
	add(counter("mtls_off_passed", "Requests passed without a client certificate because CISP_MTLS_MODE=off.", "any increase in production"))
	add(counters("Publisher body signatures by outcome.", prefixed("signature_", signatureOutcomes)...)...)
	add(counters("JWKS disk copy writes.", "jwks_cache_written")...)
	add(counter("jwks_cache_write_failed", "JWKS disk copy writes that failed (the previous copy stays).", "any increase"))

	// Console sessions (WP-8; component console_auth) and the console.
	add(counter("session_accepted", "Console sessions verified on a console route.", ""))
	add(counters("Console sessions refused by the console's rules (component console_auth).",
		"session_rejected_not_session", "session_rejected_realm", "session_rejected_role", "session_rejected_revoked", "session_rejected_role_too_low")...)
	add(counter("session_check_failed", "Console requests refused 503 because the revocation list could not be read (fail closed).", "any increase"))
	add(counter("session_revocation_cache_bypassed", "Session checks that asked the database because the revocation cache was full or stale.", "sustained increase"))
	add(counter("console_logins", "Console sessions issued.", ""))
	add(counter("console_logins_refused", "Console logins refused (wrong credentials, locked, TOTP).", "a burst (password guessing)"))
	add(counter("console_actions", "Console actions written (accounts, subscriptions, retries, republications).", ""))

	// Store counters mirrored into Prometheus.
	add(counter("bus_publish_failed", "Committed changes whose bus publish failed (deliver's scan covers them).", "any increase"))
	add(counter("bus_publish_skipped", "Committed changes not published because no bus is configured.", ""))
	add(counter("change_bbox_unavailable", "Changes committed without a bbox (the whole dataset is announced).", ""))
	add(counters("Snapshot cache.", "snapshot_cache_evicted", "snapshot_cache_oversize")...)
	add(counter("snapshot_cache_refresh_failed", "Snapshot cache refreshes that failed (reads carry X-CIS-Stale).", "any increase for 1 min"))

	// The bus.
	add(counter("nats_slow_consumer", "NATS slow-consumer errors on this process's subscriptions (messages dropped by the client).", "any increase"))
	add(counter("nats_reconnects", "Reconnections to the broker after a loss.", ""))
	add(counter("bus_change_unreadable", "Bus messages on cis.v1.change.* that are not a cis/change/v1 record (dropped by the stream).", "any increase"))
	add(gauge("nats_degraded_s", "Seconds the broker connection has been down (0 when connected).", "above 60"))

	// The WS stream.
	add(gauge("stream_clients", "WS /v1/stream clients connected to this instance.", "above 900 (90 % of CISP_STREAM_MAX_CLIENTS)"))
	add(counter("stream_clients_dropped", "Stream clients closed with 1013 because their send buffer was full.", ""))
	add(counter("stream_refused_capacity", "Stream upgrades refused 503 at CISP_STREAM_MAX_CLIENTS.", "any increase"))
	add(counter("stream_refused_origin", "Stream upgrades refused 403 for an Origin outside the allow-list.", ""))
	add(counter("stream_refused_request", "Stream upgrades refused 400 (an unknown dataset, not a WebSocket upgrade).", ""))
	add(counter("stream_session_refused", "Stream clients closed with 4401 (no or an invalid session on a non-public stream).", ""))
	add(counter("stream_session_ignored", "Session cookies on a public stream that did not verify (served as public).", ""))
	add(counter("stream_sessions", "Stream clients whose session cookie verified (console clients).", ""))
	add(counter("stream_frames_sent", "Frames written to stream clients.", ""))
	add(counter("stream_frames_dropped", "Frames not queued for a client whose send buffer was full (its dropped_frames).", ""))
	add(counter("stream_changes", "cis/change/v1 records the hub received from the bus.", ""))
	add(counter("stream_resyncs", "Bus reconnections the hub announced with resync_since.", ""))

	// deliver.
	add(Metric{Name: "cisp_delivery_first_attempt_seconds", Kind: KindHistogram, Labels: nil,
		Help: "From a change's commit (changes.at) to its first webhook attempt.", Alert: "p99 above 2 s for 10 min"})
	add(Metric{Name: "cisp_delivery_result_total", Kind: KindCounter, Labels: []string{"code"},
		Help: "Webhook attempts by result code (2xx, 4xx, 5xx, timeout, refused, ...).", Alert: ""})
	add(counters("Webhook delivery intake.", "deliveries_from_bus", "deliveries_from_scan", "delivery_scans")...)
	add(counter("delivery_scan_failed", "Reconciliation scans that failed.", "any increase for 1 min"))
	add(counter("bus_poison", "Bus messages deliver could not read (acknowledged and dropped; the scan covers the change).", "any increase"))
	add(counter("intake_failed", "Bus messages deliver could not queue (redelivered).", "any increase for 5 min"))
	add(counters("Webhook delivery outcomes.", "deliveries_delivered", "deliveries_failed", "subscriptions_verified")...)
	add(counter("deliveries_expired", "Deliveries given up 24 h after their change.", "any increase"))
	add(counter("ssrf_refused", "Callback dials refused by the address policy.", ""))
	add(counter("subscriptions_suspended_total", "Subscriptions suspended after 50 consecutive failures over 1 h.", ""))
	add(counters("Delivery bookkeeping failures.", "delivery_log_write_failed", "delivery_record_failed", "delivery_sign_failed", "delivery_claim_failed")...)
	add(gauge("deliveries_queued", "Deliveries queued and not yet delivered.", "above 100 for 5 min"))
	add(gauge("deliveries_due", "Deliveries due now.", ""))
	add(gauge("deliveries_oldest_due_s", "Seconds the oldest due delivery has waited.", "above 60"))
	add(gauge("deliveries_in_flight", "Webhook POSTs in flight on this instance.", ""))
	add(gauge("subscriptions_suspended", "Subscriptions suspended now.", ""))

	sort.Slice(m, func(i, j int) bool { return m[i].Name < m[j].Name })
	return m
}

// catalogued is the set of catalogue names.
var catalogued = func() map[string]Metric {
	out := make(map[string]Metric, len(Catalogue))
	for _, m := range Catalogue {
		out[m.Name] = m
	}
	return out
}()

// Catalogued reports whether name (a full Prometheus name) is in the
// catalogue.
func Catalogued(name string) bool {
	_, ok := catalogued[name]
	return ok
}

// CatalogueRow is the runbook table row of m, as
// docs/RUNBOOKS/observability.md writes it.
func CatalogueRow(m Metric) string {
	labels := "—"
	if len(m.Labels) > 0 {
		labels = "`" + strings.Join(m.Labels, "`, `") + "`"
	}
	alert := "—"
	if m.Alert != "" {
		alert = m.Alert
	}
	return "| `" + m.Name + "` | " + string(m.Kind) + " | " + labels + " | " + m.Help + " | " + alert + " |"
}
