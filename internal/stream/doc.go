// Package stream is WS /v1/stream (docs/PLAN.md section 6.5, WP-7): a
// hub in each api instance that fans the bus's committed changes out to
// its WebSocket clients, with a console/status/v1 frame on connect and
// every status period.
//
// Every frame is the common envelope of uspace-lab's
// schemas/common/envelope/v1 around one of two bodies (M29):
// console/status/v1 (connection_id, server_ts, policy_version,
// stale_after_s, live_max_age_s, dropped_frames, degraded[], sources[],
// and the CISP extras datasets, cis_age_s, nats, resync_since) and
// cis/change/v1 (the record the change feed and the webhook carry).
// There is no snapshot and no subscribe frame: ?datasets= on the upgrade
// is the subscription, and the stream has no history.
//
// The hub never queries a database. Changes come from the bus
// (bus.Subscribe); the status comes from a StatusSource that answers
// from memory. When the bus is down the clients keep their status
// frames, with nats reconnecting and degraded naming it, and no
// changes; when it returns, the next status carries resync_since, the
// instant from which a client may have missed changes and should HEAD
// the datasets.
//
// Bounds (E-10): at most MaxClients clients per instance (the next
// upgrade is 503 stream_full), and a send buffer of SendBuffer frames
// per client: a frame that does not fit is dropped (dropped_frames), and
// a client still full at the next status tick is closed with 1013 and
// counted stream_clients_dropped. Each write has its own deadline.
//
// The upgrade is public, rate-limited per client address by the route
// (WP-4's limiter), and judged here: an Origin outside the allow-list is
// 403; the uspace_session cookie of a same-origin upgrade is verified
// by the shared verifier and marks the client as a console (the content
// is the same); on a non-public stream a missing or invalid session is
// closed with 4401 ("re-login", M22).
package stream
