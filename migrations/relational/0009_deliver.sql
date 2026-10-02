-- Relational tree: what subscriptions and deliver need beyond WP-1's
-- tables (WP-6, docs/PLAN.md sections 5.1, 6.5 and D6).
--
-- deliveries.change_id becomes nullable: the verification ping of a new
-- subscription (reason subscription_test) is a delivery of no change
-- (it is never a changes row). The unique pair (subscription_id,
-- change_id) still makes the fan-out of a change idempotent (B-05);
-- PostgreSQL treats null change ids as distinct, so a subscription may
-- be pinged again after its callback changes.
--
-- deliveries.created_at is when the row was queued: the start of the
-- 24 h retry window of a ping, and the order of the deliveries list.
--
-- subscriptions.failing_since is the first failure of the current run
-- of consecutive failures (null after a success): a subscription is
-- suspended after 50 consecutive failures over at least one hour, and
-- its suspended_reason says since when.
--
-- deliver_state holds deliver's reconciliation watermark (D6): the
-- highest change cursor its scan has settled, shared by every deliver
-- instance; GREATEST keeps it monotonic when two instances write it.

-- +goose Up
ALTER TABLE deliveries ALTER COLUMN change_id DROP NOT NULL;
ALTER TABLE deliveries ADD COLUMN created_at timestamptz NOT NULL DEFAULT now();
CREATE INDEX deliveries_subscription_idx ON deliveries (subscription_id, created_at DESC);
CREATE INDEX deliveries_open_idx ON deliveries (state) WHERE state IN ('queued', 'delivering', 'failed');
COMMENT ON COLUMN deliveries.change_id IS 'The changes.id delivered; null for the subscription_test ping of a new or changed callback.';

ALTER TABLE subscriptions ADD COLUMN failing_since timestamptz;

CREATE TABLE deliver_state (
    name       text        PRIMARY KEY,
    watermark  bigint      NOT NULL DEFAULT 0 CHECK (watermark >= 0),
    updated_at timestamptz NOT NULL
);
COMMENT ON TABLE deliver_state IS 'deliver''s reconciliation watermark (D6): changes up to it have their deliveries.';

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cisp_deliver') THEN
        GRANT SELECT, INSERT, UPDATE ON deliver_state TO cisp_deliver;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE deliver_state;
ALTER TABLE subscriptions DROP COLUMN failing_since;
DROP INDEX deliveries_open_idx;
DROP INDEX deliveries_subscription_idx;
ALTER TABLE deliveries DROP COLUMN created_at;
DELETE FROM deliveries WHERE change_id IS NULL;
ALTER TABLE deliveries ALTER COLUMN change_id SET NOT NULL;
