-- WP-4: the reads (docs/WORKPACKAGES/WP-4.md): the snapshot with its
-- version's time and publisher, the current features by bounding box,
-- the features of a past version for since_version, and the publishers
-- for GET /v1/status.

-- name: GetSnapshotForRead :one
-- One stored snapshot with the received_at (metadata.issued and
-- Last-Modified) and the publisher of its version.
SELECT s.dataset, s.version, s.etag, s.body_gz, s.cisp_signature, s.built_at,
       p.received_at, p.publisher_client_id
FROM snapshots s
JOIN publications p ON p.dataset = s.dataset AND p.version = s.version
WHERE s.dataset = $1 AND s.version = $2;

-- name: GetVersionHead :one
-- When a version was received and from whom; no body.
SELECT received_at, publisher_client_id
FROM publications
WHERE dataset = $1 AND version = $2;

-- name: ListCurrentFeatureBodies :many
-- Every current feature of a dataset as stored.
SELECT feature_id, version, feature, feature_sha256
FROM features_current
WHERE dataset = $1
ORDER BY feature_id;

-- name: ListCurrentFeaturesInBBox :many
-- The current features whose stored shape's bounding box overlaps the
-- envelope: a prefilter on the GiST index, never a judgement (Z-06,
-- Z-11; a circle is its stored buffer).
SELECT feature_id, version, feature, feature_sha256
FROM features_current
WHERE dataset = sqlc.arg(dataset)
  AND geom && ST_MakeEnvelope(sqlc.arg(min_lon)::float8, sqlc.arg(min_lat)::float8,
                              sqlc.arg(max_lon)::float8, sqlc.arg(max_lat)::float8, 4326)
ORDER BY feature_id;

-- name: ListVersionFeatures :many
-- Every feature a past version held (the removed rows of that version
-- are what it dropped, so they are left out).
SELECT f.feature_id, f.feature, f.feature_sha256
FROM features f
JOIN publications p ON p.id = f.publication_id
WHERE p.dataset = sqlc.arg(dataset) AND p.version = sqlc.arg(version) AND f.op <> 'removed'
ORDER BY f.feature_id;

-- name: ListPublishers :many
SELECT client_id, kind, last_heartbeat_at, last_publication_at, stale_after_s, enabled
FROM publishers
ORDER BY client_id;
