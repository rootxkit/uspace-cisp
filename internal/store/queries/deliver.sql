-- WP-6: deliver's queries (docs/PLAN.md sections 6.5 and D6, D7). deliver
-- connects as cisp_deliver: SELECT on datasets and changes, SELECT and
-- UPDATE on subscriptions, SELECT, INSERT and UPDATE on deliveries and
-- deliver_state (the grants of migrations 0002, 0004 and 0009).

-- name: ListReceivingSubscriptions :many
-- Every subscription that is sent notifications: active and pending.
SELECT id, client_id, callback_url, datasets, status, created_at,
       (bbox IS NOT NULL)::boolean AS has_bbox,
       COALESCE(ST_XMin(bbox), 0)::float8 AS min_lon, COALESCE(ST_YMin(bbox), 0)::float8 AS min_lat,
       COALESCE(ST_XMax(bbox), 0)::float8 AS max_lon, COALESCE(ST_YMax(bbox), 0)::float8 AS max_lat
FROM subscriptions
WHERE status IN ('active', 'pending_verification')
ORDER BY id;

-- name: InsertChangeDelivery :execrows
-- One delivery of a change to a subscription, due now. Redelivery of the
-- change (JetStream, the scan, a second instance) inserts nothing (B-05).
INSERT INTO deliveries (id, subscription_id, change_id, state, next_retry_at, created_at)
VALUES (sqlc.arg(id), sqlc.arg(subscription_id), sqlc.arg(change_id)::bigint, 'queued', sqlc.arg(now)::timestamptz, sqlc.arg(now)::timestamptz)
ON CONFLICT (subscription_id, change_id) DO NOTHING;

-- name: GetWatermark :one
SELECT watermark FROM deliver_state WHERE name = $1;

-- name: AdvanceWatermark :exec
-- Never moves back: two instances may write it.
INSERT INTO deliver_state (name, watermark, updated_at)
VALUES (sqlc.arg(name), sqlc.arg(watermark), sqlc.arg(now))
ON CONFLICT (name) DO UPDATE
SET watermark = GREATEST(deliver_state.watermark, EXCLUDED.watermark), updated_at = EXCLUDED.updated_at;

-- name: ListChangesForScan :many
-- The changes after the watermark committed before a cut-off (the bus
-- has had its chance at the newer ones), in cursor order.
SELECT id, dataset, version, feature_ids, removed_ids, reason, at,
       (bbox IS NOT NULL)::boolean AS has_bbox,
       COALESCE(ST_XMin(bbox), 0)::float8 AS min_lon, COALESCE(ST_YMin(bbox), 0)::float8 AS min_lat,
       COALESCE(ST_XMax(bbox), 0)::float8 AS max_lon, COALESCE(ST_YMax(bbox), 0)::float8 AS max_lat
FROM changes
WHERE id > sqlc.arg(since_id) AND at < sqlc.arg(before)
ORDER BY id
LIMIT sqlc.arg(max_rows);

-- name: GetChangesByID :many
SELECT id, dataset, version, feature_ids, removed_ids, reason, at,
       (bbox IS NOT NULL)::boolean AS has_bbox,
       COALESCE(ST_XMin(bbox), 0)::float8 AS min_lon, COALESCE(ST_YMin(bbox), 0)::float8 AS min_lat,
       COALESCE(ST_XMax(bbox), 0)::float8 AS max_lon, COALESCE(ST_YMax(bbox), 0)::float8 AS max_lat
FROM changes
WHERE id = ANY(sqlc.arg(ids)::bigint[]);

-- name: ListDatasetVersions :many
SELECT name, current_version FROM datasets;

-- name: ClaimDeliveries :many
-- The due deliveries of receiving subscriptions, oldest due first, each
-- locked against every other instance (SKIP LOCKED) and leased: the row
-- is delivering until lease_until, and a lease that runs out (a process
-- killed mid-attempt) makes it due again, so nothing is lost. A
-- subscription gets at most max_per_subscription rows in flight, those
-- already delivering under a live lease included, so one slow
-- subscriber never takes every slot (D7).
WITH busy AS (
    SELECT subscription_id, count(*) AS n
    FROM deliveries
    WHERE state = 'delivering' AND next_retry_at > sqlc.arg(now)::timestamptz
    GROUP BY subscription_id
), ranked AS (
    SELECT d.id, d.next_retry_at,
           row_number() OVER (PARTITION BY d.subscription_id ORDER BY d.next_retry_at, d.id) AS rn,
           COALESCE(b.n, 0) AS busy
    FROM deliveries d
    JOIN subscriptions s ON s.id = d.subscription_id
    LEFT JOIN busy b ON b.subscription_id = d.subscription_id
    WHERE d.next_retry_at <= sqlc.arg(now)::timestamptz
      AND d.state IN ('queued', 'failed', 'delivering')
      AND s.status IN ('active', 'pending_verification')
), due AS (
    SELECT d.id
    FROM deliveries d
    JOIN ranked r ON r.id = d.id
    -- The due conditions again, on d itself: a row another instance
    -- claimed and committed while this one waited is rechecked against
    -- its new version (its lease) and skipped, never claimed twice.
    WHERE r.rn + r.busy <= sqlc.arg(max_per_subscription)::bigint
      AND d.next_retry_at <= sqlc.arg(now)::timestamptz
      AND d.state IN ('queued', 'failed', 'delivering')
    ORDER BY r.next_retry_at
    LIMIT sqlc.arg(max_rows)
    FOR UPDATE OF d SKIP LOCKED
)
UPDATE deliveries d
SET state = 'delivering', next_retry_at = sqlc.arg(lease_until)::timestamptz
FROM due, subscriptions s
WHERE d.id = due.id AND s.id = d.subscription_id
RETURNING d.id, d.subscription_id, d.change_id, d.attempts, d.created_at,
          s.callback_url, s.datasets, s.status;

-- name: FinishDelivered :one
UPDATE deliveries SET
    state = 'delivered',
    attempts = attempts + 1,
    first_attempt_at = COALESCE(first_attempt_at, sqlc.arg(at)::timestamptz),
    last_attempt_at = sqlc.arg(at)::timestamptz,
    delivered_at = sqlc.arg(at)::timestamptz,
    last_status_code = sqlc.arg(status_code),
    last_error = NULL,
    next_retry_at = NULL
WHERE id = sqlc.arg(id)
RETURNING attempts;

-- name: FinishFailed :one
-- A failed attempt: failed and due again at next_retry_at, or expired
-- (the window has passed, or the subscription was deleted meanwhile).
UPDATE deliveries d SET
    state = CASE WHEN sqlc.arg(expire)::boolean
                   OR (SELECT s.status FROM subscriptions s WHERE s.id = d.subscription_id) = 'deleted'
                 THEN 'expired' ELSE 'failed' END,
    attempts = d.attempts + 1,
    first_attempt_at = COALESCE(d.first_attempt_at, sqlc.arg(at)::timestamptz),
    last_attempt_at = sqlc.arg(at)::timestamptz,
    last_status_code = sqlc.narg(status_code)::integer,
    last_error = sqlc.arg(error)::text,
    next_retry_at = CASE WHEN sqlc.arg(expire)::boolean THEN NULL ELSE sqlc.narg(next_retry_at)::timestamptz END
WHERE d.id = sqlc.arg(id)
RETURNING d.attempts, d.state;

-- name: SubscriptionSucceeded :one
-- A 2xx: the failure run ends, and a pending subscription is verified.
UPDATE subscriptions SET
    last_success_at = sqlc.arg(at)::timestamptz,
    consecutive_failures = 0,
    failing_since = NULL,
    verified_at = CASE WHEN status = 'pending_verification' THEN sqlc.arg(at)::timestamptz ELSE verified_at END,
    status = CASE WHEN status = 'pending_verification' THEN 'active' ELSE status END
WHERE id = sqlc.arg(id)
RETURNING status, COALESCE(verified_at = sqlc.arg(at)::timestamptz, false)::boolean AS verified_now;

-- name: SubscriptionFailed :one
UPDATE subscriptions SET
    consecutive_failures = consecutive_failures + 1,
    failing_since = COALESCE(failing_since, sqlc.arg(at)::timestamptz)
WHERE id = sqlc.arg(id)
RETURNING status, consecutive_failures, failing_since;

-- name: SuspendSubscription :execrows
UPDATE subscriptions SET status = 'suspended', suspended_reason = sqlc.arg(reason)
WHERE id = sqlc.arg(id) AND status = 'active';

-- name: QueueStats :one
-- What the status line prints: deliveries waiting (queued or failed) and
-- in flight for receiving subscriptions, those due now, the oldest due
-- time's age in seconds (0 when none is due), and the suspended
-- subscriptions.
SELECT
    count(*) FILTER (WHERE d.state IN ('queued', 'failed'))::bigint AS queued,
    count(*) FILTER (WHERE d.state IN ('queued', 'failed') AND d.next_retry_at <= sqlc.arg(now)::timestamptz)::bigint AS due,
    count(*) FILTER (WHERE d.state = 'delivering')::bigint AS delivering,
    COALESCE(EXTRACT(EPOCH FROM (sqlc.arg(now)::timestamptz - min(d.next_retry_at) FILTER (
        WHERE d.state IN ('queued', 'failed') AND d.next_retry_at <= sqlc.arg(now)::timestamptz))), 0)::float8 AS oldest_due_age_s,
    (SELECT count(*) FROM subscriptions WHERE status = 'suspended')::bigint AS suspended
FROM deliveries d
JOIN subscriptions s ON s.id = d.subscription_id
WHERE d.state IN ('queued', 'failed', 'delivering') AND s.status IN ('active', 'pending_verification');
