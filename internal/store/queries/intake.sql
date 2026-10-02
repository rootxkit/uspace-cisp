-- WP-3: publication intake (docs/WORKPACKAGES/WP-3.md): the
-- cross-dataset identifier lookup, the version history with warnings,
-- the publisher's refused attempts and the publisher heartbeat.

-- name: ReservedFeatureIDs :many
-- D8: which of ids the current version of another dataset already holds
-- (zones, uspace_airspace and restrictions share one identifier space).
SELECT feature_id, dataset
FROM features_current
WHERE dataset <> sqlc.arg(dataset)
  AND dataset IN ('zones', 'uspace_airspace', 'restrictions')
  AND feature_id = ANY(sqlc.arg(ids)::text[])
ORDER BY feature_id;

-- name: ListPublicationVersions :many
-- The version history, newest first, below a version, with warnings and
-- the body size; no bodies.
SELECT id, dataset, version, publisher_client_id, received_at, body_sha256,
       octet_length(body)::bigint AS bytes, content_type, signature_kid,
       feature_count, added, changed, removed, supersedes_version, warnings, reason
FROM publications
WHERE dataset = sqlc.arg(dataset) AND version < sqlc.arg(before_version)
ORDER BY version DESC
LIMIT sqlc.arg(max_rows);

-- name: ListRefusedAttempts :many
-- A publisher's refused attempts on a dataset after an instant, newest
-- first.
SELECT id, dataset, publisher_client_id, received_at, outcome, publication_id,
       problems, body_sha256, bytes
FROM publication_attempts
WHERE publisher_client_id = sqlc.arg(publisher_client_id)
  AND dataset = sqlc.arg(dataset)
  AND outcome = 'refused'
  AND received_at > sqlc.arg(since)
ORDER BY received_at DESC, id DESC
LIMIT sqlc.arg(max_rows);

-- name: UpsertPublisherHeartbeat :exec
INSERT INTO publishers (client_id, kind, last_heartbeat_at, last_heartbeat_sent_at, active_refs)
VALUES (sqlc.arg(client_id), sqlc.arg(kind), sqlc.arg(received_at), sqlc.arg(sent_at), sqlc.narg(active_refs))
ON CONFLICT (client_id) DO UPDATE
SET kind                   = EXCLUDED.kind,
    last_heartbeat_at      = EXCLUDED.last_heartbeat_at,
    last_heartbeat_sent_at = EXCLUDED.last_heartbeat_sent_at,
    active_refs            = EXCLUDED.active_refs;

-- name: GetPublisher :one
SELECT client_id, kind, mtls_subject, last_heartbeat_at, last_publication_at,
       stale_after_s, enabled, last_heartbeat_sent_at, active_refs
FROM publishers
WHERE client_id = $1;
