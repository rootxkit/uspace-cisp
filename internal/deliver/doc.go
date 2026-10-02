// Package deliver is the F3 push of the CISP (docs/PLAN.md sections 6.5,
// 7 and 9, D6, D7; docs/WORKPACKAGES/WP-6.md): it turns committed
// changes into signed webhook notifications for the subscriptions that
// match them, within 1 s of the commit (p99 2 s).
//
// Three loops share one Service, and two or more deliver instances share
// the work through the database and the durable consumer:
//
//   - Intake (RunConsumer): the durable pull consumer "deliver" on
//     CIS_CHANGES (explicit ack, 256 unacknowledged, 30 s ack wait, 20
//     deliveries). Each change is matched against the active and pending
//     subscriptions (subscription.Matches) and one deliveries row per
//     match is written in one transaction before the message is
//     acknowledged; a redelivered message writes nothing (the unique
//     (subscription, change) pair, B-05). A message that cannot be read,
//     or that fails its 20th delivery, is counted bus_poison and
//     acknowledged: the change is in the changes table and the scan
//     covers it.
//   - Reconciliation (RunScan): every 10 s the changes past the
//     watermark get the rows a lost publish never wrote (D6); the count
//     is deliveries_from_scan, so a scan that did the bus's work is
//     visible (E-02). The watermark (deliver_state) only passes changes
//     older than ScanSettle, so a change committed late under a lower
//     cursor is still scanned.
//   - Sender (RunSender): claims due rows (FOR UPDATE SKIP LOCKED, leased
//     for Lease so a killed process loses nothing), signs each as a
//     compact JWS through core's SignCompact (payload {iss, aud, sub,
//     iat, jti, body}: aud the callback's host, sub the subscription, jti
//     the delivery, body the cis/change/v1 record) and POSTs it with a
//     2 s timeout, no redirects, the response read to 1 KiB, TLS 1.2+,
//     and a dialer that refuses a non-public resolved address unless
//     CISP_ALLOW_PRIVATE_CALLBACKS (the SSRF guard runs on the address
//     connected to, not on the name). At most MaxInFlight (64) attempts
//     run at once, each with its own timeout, so a slow subscriber never
//     delays another. Every attempt is a delivery_attempts row; a 2xx is
//     delivered (and activates a pending subscription), anything else is
//     failed with the next retry from subscription.NextAttempt, or
//     expired past the 24 h window, and 50 consecutive failures over an
//     hour suspend the subscription.
//
// Nothing is dropped silently: every outcome is a row and a counter, and
// expiry is a state. The status line prints the queue ("0 queued, 0 due,
// oldest due 0 s, 0 in flight") on every tick, the healthy one included.
package deliver
