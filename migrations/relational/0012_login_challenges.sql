-- Relational tree: the console's two-step sign-in (docs/PLAN.md section
-- 15 Q41 (3); the uspace-authority internal/authz contract, M20).
--
-- login_challenges are the short, single-use MFA challenges between the
-- password step (POST /v1/console/session) and the code step (POST
-- /v1/console/session/mfa) of an account with mfa_required. A row is
-- stored by the SHA-256 of its token, never the token; it is bound to
-- one account, expires on the database's clock, counts the wrong codes
-- sent with it, and is spent once (used_at). The per-account lockout
-- stays on accounts (failed_logins, locked_until): a wrong code through
-- a challenge counts there as a wrong code in one request does.
--
-- Bounded (E-10): a new challenge deletes its account's spent and
-- expired ones in the same transaction, so an account holds at most the
-- live challenges of its last ChallengeTTL, and the per-address login
-- limiter bounds those.

-- +goose Up
CREATE TABLE login_challenges (
    token_hash text        PRIMARY KEY CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    account_id text        NOT NULL REFERENCES accounts (id),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    attempts   integer     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    used_at    timestamptz,
    CONSTRAINT login_challenges_expiry CHECK (expires_at > created_at)
);
CREATE INDEX login_challenges_account_idx ON login_challenges (account_id);
COMMENT ON TABLE login_challenges IS 'Single-use, expiring MFA challenges between the console''s password and code steps, by the SHA-256 of the token.';

-- +goose Down
DROP TABLE login_challenges;
