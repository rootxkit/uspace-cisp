-- WP-1: the audit log and its hash chain (06 T7).

-- name: LockEventChain :exec
-- Serialises appends so each row's prev_hash is the previous row's hash.
SELECT pg_advisory_xact_lock(hashtext('cisp.events')::bigint);

-- name: LastEventHash :one
SELECT hash FROM events ORDER BY id DESC LIMIT 1;

-- name: InsertEvent :one
INSERT INTO events (ts, actor_type, actor_id, event_type, entity_type, entity_id, payload, prev_hash, hash)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING id;

-- name: ListEvents :many
SELECT id, ts, actor_type, actor_id, event_type, entity_type, entity_id, payload, prev_hash, hash
FROM events
WHERE id > sqlc.arg(after_id)
ORDER BY id
LIMIT sqlc.arg(max_rows);
