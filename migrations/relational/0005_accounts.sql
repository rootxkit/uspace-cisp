-- Relational tree: console accounts and the session revocation list
-- (docs/PLAN.md section 5.1, D10). The shapes are WP-1's; the queries
-- are WP-8's. No PII beyond a username.

-- +goose Up
CREATE TABLE accounts (
    id              text        PRIMARY KEY,
    username        text        NOT NULL UNIQUE CHECK (username = lower(username)),
    password_hash   text        NOT NULL,
    role            text        NOT NULL CHECK (role IN ('viewer', 'publisher_admin', 'admin')),
    totp_secret_enc bytea,
    mfa_required    boolean     NOT NULL DEFAULT false,
    status          text        NOT NULL CHECK (status IN ('active', 'disabled')),
    created_at      timestamptz NOT NULL,
    last_login_at   timestamptz,
    failed_logins   integer     NOT NULL DEFAULT 0 CHECK (failed_logins >= 0),
    locked_until    timestamptz
);

CREATE TABLE sessions (
    jti        text        PRIMARY KEY,
    account_id text        NOT NULL REFERENCES accounts (id),
    issued_at  timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz
);
CREATE INDEX sessions_account_idx ON sessions (account_id);

-- +goose Down
DROP TABLE sessions;
DROP TABLE accounts;
