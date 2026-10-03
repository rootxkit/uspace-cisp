-- Relational tree: signatures of a stored snapshot made after it was
-- built (retro-audit S5, docs/PLAN.md section 15 Q50).
--
-- After a key rotation forced by a compromise, every current snapshot's
-- stored X-CIS-Signature names the dropped key. cispctl resign-current
-- signs the snapshot's stored bytes again under the active key and
-- appends a row here; the bytes, the ETag and snapshots.cisp_signature
-- (the signature the version was published with) never change. The read
-- path serves the newest row whose body_gz_sha256 is the hash of the
-- snapshot's body_gz, and the stored signature otherwise, so the record
-- of which key signed what survives.
--
-- Append-only for the application role, like publications (0002).

-- +goose Up
CREATE TABLE snapshot_signatures (
    id             bigserial   PRIMARY KEY,
    dataset        text        NOT NULL REFERENCES datasets (name),
    version        bigint      NOT NULL CHECK (version >= 1),
    kid            text        NOT NULL CHECK (kid <> ''),
    signature      text        NOT NULL CHECK (signature <> ''),
    body_gz_sha256 bytea       NOT NULL CHECK (length(body_gz_sha256) = 32),
    signed_at      timestamptz NOT NULL
);
CREATE INDEX snapshot_signatures_version_idx ON snapshot_signatures (dataset, version, signed_at DESC, id DESC);
COMMENT ON TABLE snapshot_signatures IS 'Re-signatures of a stored snapshot under a later key (cispctl resign-current); the newest whose body_gz_sha256 matches is served. Append-only.';

REVOKE UPDATE, DELETE, TRUNCATE ON snapshot_signatures FROM PUBLIC;
REVOKE UPDATE, DELETE, TRUNCATE ON snapshot_signatures FROM cisp_api;

-- +goose Down
DROP TABLE snapshot_signatures;
