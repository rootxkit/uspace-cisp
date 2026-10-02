-- Relational tree: the source bytes of a publication mapped from another
-- format (WP-12, the ED-269 bridge; docs/PLAN.md section 5.1).
--
-- An ED-269 publication of zones is mapped onto ED-318 by uspace-core
-- (ed318.FromED269); publications.body holds the mapped ED-318, which is
-- what every consumer reads and judges, and these columns keep the bytes
-- the authority sent and signed, verbatim, as the evidence of what it
-- published. publisher_signature covers source_body when it is set, and
-- body otherwise. The three columns are all set or all null: null for a
-- version published as ED-318 or made by the CISP.
--
-- publications stays insert-only for cisp_api (0002): the columns are
-- written once, in the publication's INSERT.

-- +goose Up
ALTER TABLE publications
    ADD COLUMN source_body         bytea,
    ADD COLUMN source_sha256       bytea CHECK (length(source_sha256) = 32),
    ADD COLUMN source_content_type text  CHECK (source_content_type IN ('application/vnd.ed269+json')),
    ADD CONSTRAINT publications_source_all_or_none CHECK (
        (source_body IS NULL) = (source_sha256 IS NULL)
        AND (source_body IS NULL) = (source_content_type IS NULL)
    );
COMMENT ON COLUMN publications.source_body IS 'The publisher''s bytes when the version was mapped from another format (ED-269, WP-12); body holds the mapped ED-318. The publisher signature covers these bytes.';

-- +goose Down
ALTER TABLE publications
    DROP CONSTRAINT publications_source_all_or_none,
    DROP COLUMN source_content_type,
    DROP COLUMN source_sha256,
    DROP COLUMN source_body;
