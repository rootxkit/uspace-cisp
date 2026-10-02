-- Relational tree: what the console needs beyond WP-1's accounts and
-- sessions (WP-8, docs/PLAN.md sections 5.1, 6.6, 8.2).
--
-- accounts.totp_last_step is the RFC 6238 time step of the last TOTP
-- code accepted for the account: a code whose step is not above it is
-- refused, so a code is never accepted twice within its window. The
-- replay memory is one integer per account, in the database, read and
-- written under the account row's FOR UPDATE lock (E-10: bounded).
--
-- The failed-login counter and the lockout (failed_logins,
-- locked_until) are WP-1's columns; they are judged on the database's
-- clock.
--
-- The indexes serve the revocation list every replica reloads every
-- 10 s (sessions revoked and not yet expired) and the audit query's
-- filters (actor, type).

-- +goose Up
ALTER TABLE accounts ADD COLUMN totp_last_step bigint CHECK (totp_last_step >= 0);
COMMENT ON COLUMN accounts.totp_last_step IS 'RFC 6238 step of the last accepted TOTP code; a code at or below it is a replay.';
COMMENT ON COLUMN accounts.totp_secret_enc IS 'TOTP secret, AES-256-GCM under a key of CISP_SECRETS_KEY_FILE: 8-byte key id || 12-byte nonce || ciphertext, the key id and the account id as associated data.';

CREATE INDEX sessions_revoked_idx ON sessions (expires_at) WHERE revoked_at IS NOT NULL;
CREATE INDEX events_actor_idx ON events (actor_id, id);
CREATE INDEX events_type_idx ON events (event_type, id);

-- +goose Down
DROP INDEX events_type_idx;
DROP INDEX events_actor_idx;
DROP INDEX sessions_revoked_idx;
ALTER TABLE accounts DROP COLUMN totp_last_step;
