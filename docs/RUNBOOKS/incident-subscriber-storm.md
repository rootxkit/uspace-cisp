# Runbook: incident, a subscriber storm

A **storm** is one subscriber making the CISP work for nothing: its
callback failing every delivery (so every change becomes a retry chain
of up to 24 h), or the client hammering the reads and the stream. The
CISP bounds each (64 deliveries in flight per deliver instance, the
2 s callback timeout, the per-client and per-address rate limits, the
stream's client cap, at most `CISP_MAX_SUBSCRIPTIONS_PER_CLIENT`
subscriptions per client), so a storm degrades that subscriber, not the
others. This runbook is how a person ends it.

## Recognise it

| Signal | Where |
|---|---|
| deliver's status line: `N queued, N due, oldest due N s` growing while other subscribers are fine | `docker compose logs deliver \| grep '"msg":"status"'` |
| one subscription with a large `consecutive_failures` and a `last_error` (`no answer within 2s`, `status 5xx`, `status 401`, `redirect`) | console, subscriptions page; `GET /v1/console/subscriptions` |
| `cisp_deliveries_expired_total` increasing | metrics (`observability.md`) |
| `rate_limited` counter, or `stream_clients_dropped` with one origin | api status line, access log by address |

A subscription that fails 50 times in a row over at least an hour is
suspended by deliver itself (`suspended_reason` says since when and
why). The steps below are for acting before that, or for a client that
storms the reads.

## Act

1. **Suspend** the subscription from the console (role
   `publisher_admin`): subscriptions page, the subscription, *Suspend*,
   with the reason ("callback answers 503 since 10:40, storm"). The
   action is audited with the reason before it happens. Deliveries stop;
   nothing is deleted: the open deliveries stay as rows, and the
   delivery log keeps every attempt.
2. **Notify the client**: its operator (USSP duty officer, the lab, the
   authority) from the subscription's client id. Say what failed (the
   `last_error`, the first and last attempt time), that the subscription
   is suspended, and that it must reconcile by `HEAD` and
   `GET /v1/changes?since=` when it is back (nothing is pushed while
   suspended; the 60 s reconciliation is the subscriber's own duty).
3. For a client storming the **reads**, nothing is suspended: the rate
   limit already answers 429 with `Retry-After`. Confirm in the access
   log that it is one client (`client_id`) or one address, tell its
   operator, and if a token is being abused ask the authority to revoke
   the client (the CISP does not issue machine tokens).
4. **Resume** when the client says its receiver is fixed: console,
   *Resume*, with the reason. The subscription returns to
   `pending_verification` and gets a `subscription_test` ping; it is
   active again only when that ping is answered 2xx. If the ping fails,
   it stays pending: go back to step 2.
5. Deliveries that expired meanwhile are not resent: the client
   reconciles by pull. Deliveries still open can be retried one by one
   from the console (*Retry*), audited.

## Never

- Delete a subscription or a delivery row to make the counters quiet.
- Raise `CISP_ALLOW_PRIVATE_CALLBACKS` or the timeout to make a broken
  receiver pass.
- Restart deliver as a fix: the queue is in the database and comes back.
