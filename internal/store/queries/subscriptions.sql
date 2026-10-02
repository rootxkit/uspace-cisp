-- WP-6: the subscriptions and their deliveries as the api reads and
-- writes them (docs/PLAN.md section 6.5). The bounding box is stored as
-- a polygon (SRID 4326) and read back as its four edges.

-- name: LockClientSubscriptions :exec
-- Serialises the creates of one client, so two at once cannot both pass
-- the limit.
SELECT pg_advisory_xact_lock(hashtext('cisp.subscriptions.' || sqlc.arg(client_id)::text)::bigint);

-- name: CountClientSubscriptions :one
-- The client's subscriptions that count against its limit (every one
-- but the deleted).
SELECT count(*)::bigint FROM subscriptions WHERE client_id = $1 AND status <> 'deleted';

-- name: InsertSubscription :exec
INSERT INTO subscriptions (id, client_id, callback_url, datasets, bbox, status, created_at)
VALUES (
    sqlc.arg(id), sqlc.arg(client_id), sqlc.arg(callback_url), sqlc.arg(datasets)::text[],
    CASE WHEN sqlc.arg(has_bbox)::boolean
         THEN ST_MakeEnvelope(sqlc.arg(min_lon)::float8, sqlc.arg(min_lat)::float8,
                              sqlc.arg(max_lon)::float8, sqlc.arg(max_lat)::float8, 4326)
    END,
    sqlc.arg(status), sqlc.arg(created_at)
);

-- name: GetSubscription :one
SELECT id, client_id, callback_url, datasets, status, created_at, verified_at, suspended_reason,
       consecutive_failures, last_success_at, failing_since,
       (bbox IS NOT NULL)::boolean AS has_bbox,
       COALESCE(ST_XMin(bbox), 0)::float8 AS min_lon, COALESCE(ST_YMin(bbox), 0)::float8 AS min_lat,
       COALESCE(ST_XMax(bbox), 0)::float8 AS max_lon, COALESCE(ST_YMax(bbox), 0)::float8 AS max_lat
FROM subscriptions
WHERE id = $1;

-- name: ListClientSubscriptions :many
-- The client's subscriptions but the deleted, oldest first.
SELECT id, client_id, callback_url, datasets, status, created_at, verified_at, suspended_reason,
       consecutive_failures, last_success_at, failing_since,
       (bbox IS NOT NULL)::boolean AS has_bbox,
       COALESCE(ST_XMin(bbox), 0)::float8 AS min_lon, COALESCE(ST_YMin(bbox), 0)::float8 AS min_lat,
       COALESCE(ST_XMax(bbox), 0)::float8 AS max_lon, COALESCE(ST_YMax(bbox), 0)::float8 AS max_lat
FROM subscriptions
WHERE client_id = $1 AND status <> 'deleted'
ORDER BY created_at, id
LIMIT sqlc.arg(max_rows);

-- name: UpdateSubscription :exec
-- A PATCH: the callback, datasets and box as given; status and the
-- failure run as the handler decided (a re-verification resets them).
UPDATE subscriptions SET
    callback_url = sqlc.arg(callback_url),
    datasets = sqlc.arg(datasets)::text[],
    bbox = CASE WHEN sqlc.arg(has_bbox)::boolean
                THEN ST_MakeEnvelope(sqlc.arg(min_lon)::float8, sqlc.arg(min_lat)::float8,
                                     sqlc.arg(max_lon)::float8, sqlc.arg(max_lat)::float8, 4326)
           END,
    status = sqlc.arg(status),
    suspended_reason = sqlc.narg(suspended_reason),
    consecutive_failures = sqlc.arg(consecutive_failures),
    failing_since = sqlc.narg(failing_since)
WHERE id = sqlc.arg(id);

-- name: MarkSubscriptionDeleted :exec
UPDATE subscriptions SET status = 'deleted' WHERE id = $1;

-- name: ExpireOpenDeliveries :execrows
-- A deleted subscription's queued, failed and stranded deliveries
-- expire: a state, never a deletion.
UPDATE deliveries SET state = 'expired', next_retry_at = NULL
WHERE subscription_id = $1 AND state IN ('queued', 'failed', 'delivering');

-- name: InsertPingDelivery :exec
-- The verification ping of a subscription: a delivery of no change,
-- due now.
INSERT INTO deliveries (id, subscription_id, change_id, state, next_retry_at, created_at)
VALUES (sqlc.arg(id), sqlc.arg(subscription_id), NULL, 'queued', sqlc.arg(created_at)::timestamptz, sqlc.arg(created_at)::timestamptz);

-- name: LatestPingDelivery :one
SELECT id, subscription_id, change_id, state, attempts, first_attempt_at, last_attempt_at, next_retry_at,
       delivered_at, last_status_code, last_error, created_at
FROM deliveries
WHERE subscription_id = $1 AND change_id IS NULL
ORDER BY created_at DESC, id DESC
LIMIT 1;

-- name: ListSubscriptionDeliveries :many
-- A subscription's deliveries queued at or after since, newest first,
-- with the reason of their change (subscription_test for a ping).
SELECT d.id, d.subscription_id, d.change_id, d.state, d.attempts, d.first_attempt_at, d.last_attempt_at,
       d.next_retry_at, d.delivered_at, d.last_status_code, d.last_error, d.created_at,
       COALESCE(c.reason, 'subscription_test')::text AS reason
FROM deliveries d
LEFT JOIN changes c ON c.id = d.change_id
WHERE d.subscription_id = sqlc.arg(subscription_id) AND d.created_at >= sqlc.arg(since)
ORDER BY d.created_at DESC, d.id DESC
LIMIT sqlc.arg(max_rows);

-- name: GetSubscriptionDelivery :one
SELECT d.id, d.subscription_id, d.change_id, d.state, d.attempts, d.first_attempt_at, d.last_attempt_at,
       d.next_retry_at, d.delivered_at, d.last_status_code, d.last_error, d.created_at,
       COALESCE(c.reason, 'subscription_test')::text AS reason
FROM deliveries d
LEFT JOIN changes c ON c.id = d.change_id
WHERE d.id = sqlc.arg(id) AND d.subscription_id = sqlc.arg(subscription_id);

-- name: RequeueDelivery :execrows
-- A retry: due now, whatever it was, unless an attempt is in flight.
UPDATE deliveries SET state = 'queued', next_retry_at = sqlc.arg(now)::timestamptz
WHERE id = sqlc.arg(id) AND subscription_id = sqlc.arg(subscription_id) AND state <> 'delivering';
