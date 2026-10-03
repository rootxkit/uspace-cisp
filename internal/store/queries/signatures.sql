-- Re-signatures of a stored snapshot (retro-audit S5, docs/PLAN.md
-- section 15 Q50; migration 0014).

-- name: InsertSnapshotSignature :exec
INSERT INTO snapshot_signatures (dataset, version, kid, signature, body_gz_sha256, signed_at)
VALUES ($1, $2, $3, $4, $5, $6);
