-- WP-1: datasets, publications, publication attempts, features,
-- features_current, snapshots and changes. Later work packages add their
-- own files beside this one and do not edit it.

-- name: LockDataset :exec
-- Serialises the publications of one dataset until the transaction
-- ends, so its version and the change cursor stay monotonic.
SELECT pg_advisory_xact_lock(hashtext('cisp.publication.' || sqlc.arg(dataset)::text)::bigint);

-- name: GetDataset :one
SELECT name, kind, current_version, publisher_kind, updated_at
FROM datasets
WHERE name = $1;

-- name: ListDatasets :many
SELECT name, kind, current_version, publisher_kind, updated_at
FROM datasets
ORDER BY name;

-- name: SetDatasetVersion :exec
UPDATE datasets
SET current_version = sqlc.arg(version), updated_at = sqlc.arg(updated_at)
WHERE name = sqlc.arg(name);

-- name: InsertPublication :exec
INSERT INTO publications (
    id, dataset, version, publisher_client_id, received_at, body, body_sha256,
    content_type, publisher_signature, signature_kid, feature_count, added,
    changed, removed, supersedes_version, warnings, reason, source_body,
    source_sha256, source_content_type
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17,
    $18, $19, $20
);

-- name: GetPublication :one
SELECT id, dataset, version, publisher_client_id, received_at, body, body_sha256,
       content_type, publisher_signature, signature_kid, feature_count, added,
       changed, removed, supersedes_version, warnings, reason, source_body,
       source_sha256, source_content_type
FROM publications
WHERE dataset = $1 AND version = $2;

-- name: ListPublications :many
-- The version history without bodies, newest first, below a version.
SELECT id, dataset, version, publisher_client_id, received_at, body_sha256,
       content_type, signature_kid, feature_count, added, changed, removed,
       supersedes_version, reason
FROM publications
WHERE dataset = sqlc.arg(dataset) AND version < sqlc.arg(before_version)
ORDER BY version DESC
LIMIT sqlc.arg(max_rows);

-- name: InsertPublicationAttempt :exec
INSERT INTO publication_attempts (
    id, dataset, publisher_client_id, received_at, outcome, publication_id,
    problems, body_sha256, bytes
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: ListPublicationAttempts :many
SELECT id, dataset, publisher_client_id, received_at, outcome, publication_id,
       problems, body_sha256, bytes
FROM publication_attempts
WHERE publisher_client_id = sqlc.arg(publisher_client_id) AND dataset = sqlc.arg(dataset)
ORDER BY received_at DESC
LIMIT sqlc.arg(max_rows);

-- name: CurrentFeatureHashes :many
SELECT feature_id, feature_sha256
FROM features_current
WHERE dataset = $1
ORDER BY feature_id;

-- name: CurrentFeaturesByID :many
SELECT feature_id, feature
FROM features_current
WHERE dataset = sqlc.arg(dataset) AND feature_id = ANY(sqlc.arg(ids)::text[])
ORDER BY feature_id;

-- name: InsertRemovedFeatures :execrows
-- A removed feature keeps its last published form in the new version,
-- for the delta.
INSERT INTO features (
    publication_id, feature_id, feature, feature_sha256, geom, centroid,
    lower_m, lower_ref, upper_m, upper_ref, applicable_from, applicable_to,
    has_events, has_layers, op
)
SELECT sqlc.arg(publication_id), feature_id, feature, feature_sha256, geom, centroid,
       lower_m, lower_ref, upper_m, upper_ref, applicable_from, applicable_to,
       has_events, has_layers, 'removed'
FROM features_current
WHERE dataset = sqlc.arg(dataset) AND feature_id = ANY(sqlc.arg(ids)::text[]);

-- name: DeleteCurrentFeatures :execrows
DELETE FROM features_current WHERE dataset = $1;

-- name: InsertCurrentFromPublication :execrows
INSERT INTO features_current (
    dataset, feature_id, version, feature, feature_sha256, geom, centroid,
    lower_m, lower_ref, upper_m, upper_ref, applicable_from, applicable_to,
    has_events, has_layers
)
SELECT sqlc.arg(dataset), feature_id, sqlc.arg(version), feature, feature_sha256, geom, centroid,
       lower_m, lower_ref, upper_m, upper_ref, applicable_from, applicable_to,
       has_events, has_layers
FROM features
WHERE publication_id = sqlc.arg(publication_id) AND op <> 'removed';

-- name: ListCurrentFeatures :many
SELECT feature_id, version, feature, feature_sha256,
       ST_Y(centroid)::float8 AS centroid_lat, ST_X(centroid)::float8 AS centroid_lon,
       lower_m, lower_ref, upper_m, upper_ref, applicable_from, applicable_to,
       has_events, has_layers
FROM features_current
WHERE dataset = $1
ORDER BY feature_id;

-- name: ListPublicationFeatures :many
SELECT feature_id, feature, feature_sha256, op
FROM features
WHERE publication_id = $1
ORDER BY feature_id;

-- name: InsertSnapshot :exec
INSERT INTO snapshots (dataset, version, etag, body_gz, cisp_signature, built_at)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: GetSnapshot :one
SELECT dataset, version, etag, body_gz, cisp_signature, built_at
FROM snapshots
WHERE dataset = $1 AND version = $2;

-- name: DeleteSnapshot :execrows
DELETE FROM snapshots WHERE dataset = $1 AND version = $2;

-- name: InsertChange :one
INSERT INTO changes (dataset, version, publication_id, feature_ids, removed_ids, reason, at, bbox)
VALUES (
    sqlc.arg(dataset), sqlc.arg(version), sqlc.narg(publication_id), sqlc.arg(feature_ids)::text[],
    sqlc.arg(removed_ids)::text[], sqlc.arg(reason), sqlc.arg(at),
    CASE WHEN sqlc.arg(has_bbox)::boolean
         THEN ST_MakeEnvelope(sqlc.arg(min_lon)::float8, sqlc.arg(min_lat)::float8,
                              sqlc.arg(max_lon)::float8, sqlc.arg(max_lat)::float8, 4326)
    END
)
RETURNING id;

-- name: ListChanges :many
-- The change feed after a cursor, optionally for one dataset.
SELECT id, dataset, version, publication_id, feature_ids, removed_ids, reason, at,
       (bbox IS NOT NULL)::boolean AS has_bbox,
       COALESCE(ST_XMin(bbox), 0)::float8 AS min_lon, COALESCE(ST_YMin(bbox), 0)::float8 AS min_lat,
       COALESCE(ST_XMax(bbox), 0)::float8 AS max_lon, COALESCE(ST_YMax(bbox), 0)::float8 AS max_lat
FROM changes
WHERE id > sqlc.arg(since_id) AND (sqlc.narg(dataset)::text IS NULL OR dataset = sqlc.narg(dataset))
ORDER BY id
LIMIT sqlc.arg(max_rows);
