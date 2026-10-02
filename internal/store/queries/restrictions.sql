-- WP-5: dynamic restrictions (docs/WORKPACKAGES/WP-5.md): the lifecycle
-- heads, their events, the expiry's leader lock and last run, and the
-- active references the ANSP's heartbeat is compared with.

-- name: GetRestrictionByID :one
SELECT id, ansp_ref, ansp_version, uspace_airspace_id, feature_id, state, starts_at, ends_at,
       ended_by, created_at, updated_at, last_publisher_client_id
FROM restrictions
WHERE id = $1;

-- name: GetRestrictionByAnspRef :one
SELECT id, ansp_ref, ansp_version, uspace_airspace_id, feature_id, state, starts_at, ends_at,
       ended_by, created_at, updated_at, last_publisher_client_id
FROM restrictions
WHERE ansp_ref = $1;

-- name: GetRestrictionByFeatureID :one
SELECT id, ansp_ref, ansp_version, uspace_airspace_id, feature_id, state, starts_at, ends_at,
       ended_by, created_at, updated_at, last_publisher_client_id
FROM restrictions
WHERE feature_id = $1;

-- name: InsertRestriction :exec
INSERT INTO restrictions (
    id, ansp_ref, ansp_version, uspace_airspace_id, feature_id, state, starts_at, ends_at,
    ended_by, created_at, updated_at, last_publisher_client_id
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12);

-- name: UpdateRestriction :execrows
UPDATE restrictions
SET ansp_version = sqlc.arg(ansp_version), state = sqlc.arg(state), ends_at = sqlc.arg(ends_at),
    ended_by = sqlc.narg(ended_by), updated_at = sqlc.arg(updated_at),
    last_publisher_client_id = sqlc.arg(last_publisher_client_id)
WHERE id = sqlc.arg(id);

-- name: InsertRestrictionEvent :exec
INSERT INTO restriction_events (restriction_id, at, op, ansp_version, publication_id, actor)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: ListRestrictionEvents :many
-- The events of the heads, oldest first per head.
SELECT restriction_id, at, op, ansp_version, publication_id, actor
FROM restriction_events
WHERE restriction_id = ANY(sqlc.arg(ids)::text[])
ORDER BY restriction_id, at, ansp_version;

-- name: ListRestrictions :many
-- The heads, newest window first, filtered by state, by U-space airspace
-- and by an instant inside the window [starts_at, ends_at).
SELECT id, ansp_ref, ansp_version, uspace_airspace_id, feature_id, state, starts_at, ends_at,
       ended_by, created_at, updated_at, last_publisher_client_id
FROM restrictions
WHERE (sqlc.narg(state)::text IS NULL OR state = sqlc.narg(state)::text)
  AND (sqlc.narg(airspace)::text IS NULL OR uspace_airspace_id = sqlc.narg(airspace)::text)
  AND (sqlc.narg(at)::timestamptz IS NULL
       OR (starts_at <= sqlc.narg(at)::timestamptz AND ends_at > sqlc.narg(at)::timestamptz))
ORDER BY starts_at DESC, id DESC
LIMIT sqlc.arg(max_rows);

-- name: ListExpiredRestrictions :many
-- The active heads whose ends_at is not after now: the expiry's work.
SELECT id
FROM restrictions
WHERE state = 'active' AND ends_at <= sqlc.arg(now)
ORDER BY ends_at, id
LIMIT sqlc.arg(max_rows);

-- name: ListActiveRestrictionRefs :many
SELECT ansp_ref
FROM restrictions
WHERE state = 'active'
ORDER BY ansp_ref;

-- name: CountActiveRestrictions :one
SELECT count(*)::bigint FROM restrictions WHERE state = 'active';

-- name: TryJobLock :one
-- Leader election per run: one replica holds the lock until its
-- transaction ends; the others skip the run.
SELECT pg_try_advisory_xact_lock(hashtext('cisp.job.' || sqlc.arg(name)::text)::bigint) AS locked;

-- name: RecordJobRun :exec
INSERT INTO job_runs (name, last_run_at, last_instance, last_count)
VALUES (sqlc.arg(name), sqlc.arg(ran_at), sqlc.arg(instance), sqlc.arg(count))
ON CONFLICT (name) DO UPDATE
SET last_run_at = EXCLUDED.last_run_at, last_instance = EXCLUDED.last_instance, last_count = EXCLUDED.last_count;

-- name: GetJobRun :one
SELECT name, last_run_at, last_instance, last_count
FROM job_runs
WHERE name = $1;

-- name: ListPublisherRefs :many
-- The publishers with what their last heartbeat declared.
SELECT client_id, kind, last_heartbeat_at, stale_after_s, active_refs
FROM publishers
ORDER BY client_id;
