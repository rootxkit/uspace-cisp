-- WP-1: the delivery log (written by deliver only, WP-6).

-- name: InsertDeliveryAttempt :exec
INSERT INTO delivery_attempts (
    at, delivery_id, subscription_id, change_id, attempt, status_code, error,
    latency_ms, payload_bytes, deliver_instance
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);

-- name: ListDeliveryAttempts :many
SELECT at, delivery_id, subscription_id, change_id, attempt, status_code, error,
       latency_ms, payload_bytes, deliver_instance
FROM delivery_attempts
WHERE subscription_id = sqlc.arg(subscription_id) AND at < sqlc.arg(before)
ORDER BY at DESC
LIMIT sqlc.arg(max_rows);

-- name: ListAttemptsOfDeliveries :many
-- WP-6: every attempt of some deliveries of one subscription (the
-- deliveries list joins them to the relational rows), oldest first.
SELECT at, delivery_id, subscription_id, change_id, attempt, status_code, error,
       latency_ms, payload_bytes, deliver_instance
FROM delivery_attempts
WHERE subscription_id = sqlc.arg(subscription_id) AND delivery_id = ANY(sqlc.arg(delivery_ids)::text[])
ORDER BY at, attempt;
