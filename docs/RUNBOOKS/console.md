# Runbook: the console's accounts and the audit log

The console is the insider surface (Annex III B(5)): its users manage
accounts, subscriptions, re-deliveries and re-publications, and no
console route writes content. Every action is an `events` row with the
actor, the role, the target and the reason, written before the action
in the same transaction.

## Configuration

Set the three together (`docs/PLAN.md` section 15 Q40); with none set
the api starts and every `/v1/console/*` operation answers 503
`console_unavailable`, and the status line warns `console: not
configured`.

| Variable | What |
|---|---|
| `CISP_SESSION_KEY_FILE` | RSA private key (PEM, at least 3072 bits) that signs console sessions; separate from the signing key. Its `kid` is derived from the key (`session-<16 hex>`), printed at start (`console ready`). Generate one with `cispctl rotate-key --out local/ --kid session` and point the variable at the file. |
| `CISP_CONSOLE_ISSUER` | the `iss` of console sessions, a URL of this CISP's own (for example `https://uspace-cisp.chikox.net/console`), never the ecosystem issuer. |
| `CISP_SECRETS_KEY` | 32 random bytes in standard base64 (`openssl rand -base64 32`); encrypts the TOTP secrets at rest. Losing it means every admin's MFA must be reset. |

## The first admin of a fresh deployment

```
cispctl migrate relational
cispctl create-account --username <name> --role admin
```

It prints the one-time password and the otpauth URL of the TOTP secret,
each once: enrol the URL in an authenticator at once. Log in through
the console (`POST /v1/console/session` with the username, the
password and the six-digit code); the admin then creates the other
accounts from the console. An admin always has MFA; the last active
admin cannot be demoted or disabled.

A locked account (five failed attempts) opens again 15 minutes after
the last failure; an admin can also reset its MFA (`PATCH
/v1/console/accounts/{id}` with `reset_mfa`). Disabling an account or
changing its role revokes its sessions on every replica within 10 s.

A session ends at 12 h, or for good once it has been unused for 30
minutes (the ecosystem's session contract): `sessions.last_seen_at`
records the last use on the database's clock, written at most once a
minute per session and replica, and an idle session answers 401
`session_revoked` (counted as `cisp_session_rejected_idle_total`). The
user signs in again.

## The audit log

`events` is insert-only for `cisp_api` and hash-chained (06 T7).

- **Monthly**: create the next partitions before the month starts (an
  insert past the last partition fails loudly). On the droplet, a cron
  entry for the first of each month:

  ```
  0 3 1 * * docker compose -f deploy/compose.yml run --rm migrate cispctl partitions --ensure-months 3
  ```

  It prints `partitions: created events_yYYYYmMM` or that every
  partition exists, and is safe to run any number of times.
- **Verify** the chain over a range (exit 0 with the count verified, 1
  naming the first row that breaks it):

  ```
  cispctl verify-audit --from 2026-10-01T00:00:00Z --to 2026-11-01T00:00:00Z
  ```

- **Export** a range for an auditor: JSON lines with the chain hashes,
  and a detached JWS of the file by the CISP's signing key beside it
  (`<out>.jws`; verify it with the CISP's JWKS):

  ```
  cispctl export-audit --from 2026-10-01T00:00:00Z --to 2026-11-01T00:00:00Z --out audit-2026-10.jsonl
  ```

## Metrics

`docs/RUNBOOKS/observability.md` lists them; the ones to watch here are
`cisp_console_logins_refused_total` (a burst is password guessing; the
per-address limit answers 429 after 20 attempts in 15 minutes),
`cisp_session_check_failed_total` (sessions refused because the
revocation list could not be read) and
`cisp_session_revocation_cache_bypassed_total`.
