-- Relational tree: the console sessions' idle end (WP-8, the ecosystem
-- session contract M20: at most 12 h, idle 30 min).
--
-- sessions.last_seen_at is when the session was last used, on the
-- database's clock. A use moves it only while the session is live (not
-- revoked, not expired, last seen within the idle timeout), so a session
-- left idle past the timeout ends for good: nothing moves it again.
-- The api writes it at most once a minute per session and replica
-- (internal/auth.Activity), not on every request.
--
-- Existing rows start from issued_at, so a session issued before this
-- migration and unused since is already idle.

-- +goose Up
ALTER TABLE sessions ADD COLUMN last_seen_at timestamptz;
UPDATE sessions SET last_seen_at = issued_at;
ALTER TABLE sessions ALTER COLUMN last_seen_at SET NOT NULL;
COMMENT ON COLUMN sessions.last_seen_at IS 'Last use of the session (database clock), written at most once a minute; idle past the timeout ends it.';

-- +goose Down
ALTER TABLE sessions DROP COLUMN last_seen_at;
