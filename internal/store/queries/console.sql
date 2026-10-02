-- WP-8: console accounts, sessions, the console's read models and its
-- audited actions (docs/PLAN.md section 6.6). Nothing here writes
-- publications, features, features_current, snapshots or restrictions.

-- name: ConsoleNow :one
-- The database's clock: lockouts, session expiry and TOTP steps are
-- judged on it, never on a replica's clock.
SELECT now()::timestamptz AS now;

-- name: GetAccountByUsernameForUpdate :one
-- The login's row lock: the failed-login counter, the lockout and the
-- TOTP replay step are read and written under it.
SELECT id, username, password_hash, role, totp_secret_enc, mfa_required, status, created_at,
       last_login_at, failed_logins, locked_until, totp_last_step
FROM accounts
WHERE username = $1
FOR UPDATE;

-- name: GetAccountForUpdate :one
SELECT id, username, password_hash, role, totp_secret_enc, mfa_required, status, created_at,
       last_login_at, failed_logins, locked_until, totp_last_step
FROM accounts
WHERE id = $1
FOR UPDATE;

-- name: GetAccount :one
SELECT id, username, password_hash, role, totp_secret_enc, mfa_required, status, created_at,
       last_login_at, failed_logins, locked_until, totp_last_step
FROM accounts
WHERE id = $1;

-- name: ListAccounts :many
SELECT id, username, password_hash, role, totp_secret_enc, mfa_required, status, created_at,
       last_login_at, failed_logins, locked_until, totp_last_step
FROM accounts
ORDER BY username
LIMIT sqlc.arg(max_rows);

-- name: LockActiveAdmins :many
-- The last-admin invariant: every active admin row locked, so two
-- demotions at once cannot both see another admin left.
SELECT id FROM accounts WHERE role = 'admin' AND status = 'active' ORDER BY id FOR UPDATE;

-- name: InsertAccount :exec
INSERT INTO accounts (id, username, password_hash, role, totp_secret_enc, mfa_required, status, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: UpdateAccountLogin :exec
-- A login's outcome: the counter, the lockout, the last login, a
-- re-hashed password and the last TOTP step.
UPDATE accounts SET
    failed_logins = sqlc.arg(failed_logins),
    locked_until = sqlc.narg(locked_until),
    last_login_at = sqlc.narg(last_login_at),
    password_hash = sqlc.arg(password_hash),
    totp_last_step = sqlc.narg(totp_last_step)
WHERE id = sqlc.arg(id);

-- name: UpdateAccount :exec
-- An admin's change: role, status and MFA.
UPDATE accounts SET
    role = sqlc.arg(role),
    status = sqlc.arg(status),
    mfa_required = sqlc.arg(mfa_required),
    totp_secret_enc = sqlc.narg(totp_secret_enc),
    totp_last_step = sqlc.narg(totp_last_step)
WHERE id = sqlc.arg(id);

-- name: InsertSession :exec
INSERT INTO sessions (jti, account_id, issued_at, expires_at) VALUES ($1, $2, $3, $4);

-- name: GetSession :one
SELECT jti, account_id, issued_at, expires_at, revoked_at FROM sessions WHERE jti = $1;

-- name: RevokeSession :execrows
UPDATE sessions SET revoked_at = now() WHERE jti = $1 AND revoked_at IS NULL;

-- name: RevokeAccountSessions :many
-- Every open session of an account (a role change, a disable).
UPDATE sessions SET revoked_at = now()
WHERE account_id = $1 AND revoked_at IS NULL AND expires_at > now()
RETURNING jti;

-- name: ListRevokedSessions :many
-- The revocation list every replica reloads: revoked and not expired.
SELECT jti FROM sessions
WHERE revoked_at IS NOT NULL AND expires_at > now()
ORDER BY expires_at DESC
LIMIT sqlc.arg(max_rows);

-- name: SessionRevoked :one
SELECT (revoked_at IS NOT NULL OR expires_at <= now())::boolean AS revoked FROM sessions WHERE jti = $1;

-- name: ListAuditEvents :many
-- The audit query, newest first, paged by id.
SELECT id, ts, actor_type, actor_id, event_type, entity_type, entity_id, payload, prev_hash, hash
FROM events
WHERE id < sqlc.arg(before_id)
  AND ts >= sqlc.arg(since)
  AND (sqlc.narg(actor)::text IS NULL OR actor_id = sqlc.narg(actor))
  AND (sqlc.narg(event_type)::text IS NULL OR event_type = sqlc.narg(event_type))
ORDER BY id DESC
LIMIT sqlc.arg(max_rows);

-- name: EventIDBounds :one
-- The first and last id of the rows in [from, to): the chain is by id.
SELECT COALESCE(min(id), 0)::bigint AS first_id, COALESCE(max(id), 0)::bigint AS last_id
FROM events
WHERE ts >= sqlc.arg(from_ts) AND ts < sqlc.arg(to_ts);

-- name: ListEventsByID :many
-- Rows from id first_id up to last_id, in chain order.
SELECT id, ts, actor_type, actor_id, event_type, entity_type, entity_id, payload, prev_hash, hash
FROM events
WHERE id >= sqlc.arg(first_id) AND id <= sqlc.arg(last_id)
ORDER BY id
LIMIT sqlc.arg(max_rows);

-- name: EventHashBefore :one
-- The hash of the row just before id in the chain.
SELECT hash FROM events WHERE id < $1 ORDER BY id DESC LIMIT 1;

-- name: GetPublicationByID :one
SELECT id, dataset, version, publisher_client_id, received_at, body, feature_count, added,
       changed, removed, supersedes_version, reason
FROM publications
WHERE id = $1;

-- name: GetPublicationIDByVersion :one
SELECT id FROM publications WHERE dataset = $1 AND version = $2;

-- name: ListFeaturesByIDs :many
SELECT feature_id, feature FROM features
WHERE publication_id = sqlc.arg(publication_id) AND feature_id = ANY(sqlc.arg(ids)::text[]);

-- name: ListChangedFeatures :many
-- A version's added, changed and removed features (unchanged ones
-- left out), at most max_rows.
SELECT feature_id, feature, op FROM features
WHERE publication_id = sqlc.arg(publication_id) AND op <> 'unchanged'
ORDER BY feature_id
LIMIT sqlc.arg(max_rows);

-- name: ListAllSubscriptions :many
-- Every client's subscriptions, deleted ones only when asked, oldest
-- first, paged by id.
SELECT id, client_id, callback_url, datasets, status, created_at, verified_at, suspended_reason,
       consecutive_failures, last_success_at, failing_since,
       (bbox IS NOT NULL)::boolean AS has_bbox,
       COALESCE(ST_XMin(bbox), 0)::float8 AS min_lon, COALESCE(ST_YMin(bbox), 0)::float8 AS min_lat,
       COALESCE(ST_XMax(bbox), 0)::float8 AS max_lon, COALESCE(ST_YMax(bbox), 0)::float8 AS max_lat
FROM subscriptions
WHERE id > sqlc.arg(after_id)
  AND (sqlc.arg(include_deleted)::boolean OR status <> 'deleted')
  AND (sqlc.narg(status)::text IS NULL OR status = sqlc.narg(status))
ORDER BY id
LIMIT sqlc.arg(max_rows);

-- name: DeliverySummaries :many
-- Per subscription and state, the number of deliveries.
SELECT subscription_id, state, count(*)::bigint AS n
FROM deliveries
WHERE subscription_id = ANY(sqlc.arg(ids)::text[])
GROUP BY subscription_id, state;

-- name: GetSubscriptionStatusForUpdate :one
SELECT status FROM subscriptions WHERE id = $1 FOR UPDATE;

-- name: ConsoleSuspendSubscription :exec
UPDATE subscriptions SET status = 'suspended', suspended_reason = sqlc.arg(reason) WHERE id = sqlc.arg(id);

-- name: ConsoleResumeSubscription :exec
-- Back to pending_verification with a new ping (WP-6: a suspended
-- subscription is verified again before it receives).
UPDATE subscriptions SET status = 'pending_verification', suspended_reason = NULL,
    consecutive_failures = 0, failing_since = NULL
WHERE id = $1;
