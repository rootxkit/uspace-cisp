# WP-8: console accounts, sessions and the console API

Branch `feat/WP-8-console-api`. Milestone C-M3. Owns exclusively:
`internal/console/`, `internal/auth/` session files (`sessions.go`,
`password.go`, `totp.go`), the `console` tag of `api/openapi.yaml` and
`internal/httpapi/console.go`, `cispctl create-account`, `cispctl
export-audit`, `cispctl verify-audit`, `cispctl partitions` (monthly
`events` partitions). Depends on WP-1, WP-2. Peers: WP-3, WP-4, WP-5,
WP-6 (deliveries views read its tables; stub until it merges). WP-11
(the console UI) builds on this: open the PR early.

## Read first

1. `CLAUDE.md`, `docs/PLAN.md §1.2` (no write path to content), `§1.3`
   (D10), `§6.6` (the session shape and cookie names), `§8.1` (insider
   row, T7), `§8.2`, `§8.5`, `§15` Q13 (decided).
2. Spec `01 §2` users (`viewer`, `publisher_admin`, `admin`; publishers
   cannot edit content), `06 §3` (local accounts argon2id, MFA for
   admin roles, the BFF cookie, CSRF), `06 §2` T6, T7, `06 §5`
   (accountability: every PII view audited — here every account change
   and every action).
3. `uspace-core/auth`: `Issuer` (RS256 session tokens with `jti`),
   `Verifier` with a static `IssuerConfig.Keys` for the console issuer
   beside the ecosystem issuer in one `Config.Issuers` map.
4. `golang.org/x/crypto/argon2` (`IDKey`; parameters 64 MiB, 3
   iterations, 4 lanes; encoded in the PHC string), `github.com/pquerna/otp/totp`.
5. LESSONS E-01, E-10, E-11; predecessor S-15 (login limits), S-16 (UTC
   parameters).

## What to build

### Accounts and sessions (`internal/auth`, `internal/console`)

- `HashPassword`, `VerifyPassword` (argon2id, PHC format, constant-time
  compare, parameters upgradable: a hash with older parameters is
  re-hashed on the next successful login).
- `POST /v1/console/session` `{username, password, totp?}`: 5 failed
  attempts per account lock it 15 min (`locked_until`), and 20 per IP
  per 15 min through the WP-4 limiter; `mfa_required` accounts need a
  valid TOTP (30 s step, ±1 step skew, a used code not accepted twice
  within its window: bounded memory, E-10); on success issue an RS256
  JWT with `core/auth.Issuer` in the one session shape every console in
  the ecosystem uses (M20, `docs/PLAN.md §6.6`): `iss` =
  `CISP_CONSOLE_ISSUER`, `aud` = the CISP's own host (the first entry of
  `CISP_AUDIENCES`), `sub` = account id, **`scope = "session"`, `roles =
  [<role>]`, `realm = "console"`**, `jti`, `kid`, TTL 12 h (idle 30 min
  through the BFF's refresh); insert `sessions`, `events` row
  `session_issued`; the response body carries the token once; the BFF
  (WP-9) stores it in the `uspace_session` cookie. No `console:<role>`
  scope: the role is read from `roles[]`.
- `RequireRole(role)` middleware: verifies through the shared
  `Verifier` (console issuer allow-listed with the static key set,
  `scope` must be exactly `session`), checks `sessions.revoked_at IS
  NULL` (a bounded in-memory negative cache of revoked `jti`s refreshed
  every 10 s), reads the role from `roles[]` (exactly one element here;
  more than one or an unknown role → 403) and orders `viewer <
  publisher_admin < admin`; 401/403 as the machine side. A machine
  token on a console route (`scope` without `session`) is 403.
- `DELETE /v1/console/session` revokes; `GET /v1/console/me`.
- Accounts (`admin`): list, create (`username`, `role`, a one-time
  initial password returned once; `mfa_required` forced true for
  `admin`), patch (role, status, reset MFA → a new TOTP secret returned
  once as an otpauth URL), with the invariant "at least one active
  admin" enforced in the transaction. TOTP secrets encrypted at rest
  with `CISP_SECRETS_KEY` (AES-256-GCM, key from env, nonce per row).

### Console read models and actions (`internal/console`, handlers)

As `docs/PLAN.md §6.6`: publications per dataset with per-feature
diffs (`features` rows of two versions joined by id; the JSON diff is a
flat list of changed paths computed in Go from the two canonical
features, bounded at 200 paths), restriction heads with events and the
publisher staleness, all subscriptions with delivery summaries,
deliveries with attempts, status (WP-4's plus counters), audit query
with filters and paging (`admin`). Actions (`publisher_admin`+): suspend
and resume a subscription, retry a delivery (reuses WP-6's queueing),
republish the current version of a dataset (a new `changes` row with
`reason: republished`, no `publications` row, through the same
transaction helper so the bus publish and the scan cover it). Every
action is an `events` row with actor, role, target and reason text (a
required `reason` field in the body, ≤ 500 characters).

No endpoint under `/v1/console/*` writes to `publications`,
`features*`, `snapshots` or `restrictions`. A test enumerates the
OpenAPI operations under the `console` tag and asserts their handlers
hold no reference to the publish transaction (a lint-style test over
the handler file: `PublishTx` must not appear).

### Audit tooling (`cispctl`)

- `create-account --username u --role r` (prints the one-time password;
  used for the first admin on a fresh deployment).
- `export-audit --from --to --out file.jsonl` (`events` rows, newline
  JSON, with the chain hashes; signed with the key ring as a detached
  JWS written beside the file).
- `verify-audit` recomputes the hash chain over a range and names the
  first row that breaks it (T7); exit 1 on a break, 0 with the count
  verified (E-02: both printed in the test).
- `partitions --ensure-months 3` creates the next `events` partitions;
  documented as a monthly cron on the droplet.

### OpenAPI

All console operations under the `console` tag with `security:
consoleSession`; role in each operation's description and in an
`x-role` extension the role test reads.

## Tests

- Password: hash/verify pair, a wrong password, parameter upgrade on
  login (old parameters re-hashed; read the stored hash back).
- Login: success; wrong password ×5 → locked (6th with the right
  password still 423 `locked`); IP limit; TOTP required and valid,
  invalid, reused (E-01 pairs); revoked session refused within 10 s.
- Roles: a table-driven test over every console operation from the
  OpenAPI (`x-role`): each role below the required one gets 403, the
  required role 200/204, an ecosystem machine token gets 403 everywhere
  under `/v1/console/*` (a USSP's `cis.read` token must not open the
  console), and a console cookie gets 403 on `/v1/publications/*` and
  `/v1/restrictions/*` (no content writes from humans).
- Last-admin invariant; TOTP secret ciphertext differs per row and
  decrypts; `CISP_SECRETS_KEY` absent → the process refuses to start
  with a clear message.
- Diff view: added/changed/removed features and the bounded path list.
- Republish: a new change with `republished` and no new version;
  subscribers (WP-6's test subscriber) receive it.
- Audit: every action produces an `events` row (assert count before and
  after per action); `verify-audit` on a clean range (prints the count)
  and on a tampered row (names it).

## Done when

- [ ] Lint, race, integration green; coverage ≥ 85 % in
  `internal/console` and the session files.
- [ ] The role matrix test output pasted (every operation × every
  caller kind).
- [ ] `cispctl create-account` → login → `GET /v1/console/me`
  transcript pasted; `verify-audit` clean and tampered outputs pasted.
- [ ] CHANGELOG line; outputs pasted (E-04).

## Safety notes

The console is the insider surface (Annex III B(5)). Its whole value is
that no human can change what the authority or the ANSP published:
enforce that in code (no handler reaches `PublishTx`), in the role
matrix test, and in the OpenAPI descriptions. A console action that
affects subscribers (suspend, republish) is audited with a reason
before it happens, never after.

## Commits

`feat(auth): argon2id accounts, TOTP and RS256 console sessions through the shared verifier [WP-8 C-M3]`,
`feat(api): console session, accounts and role middleware [WP-8 C-M3]`,
`feat(console): publications with diffs, restrictions, subscriptions, deliveries, status and audit [WP-8 C-M3]`,
`feat(console): suspend, resume, retry and republish as audited actions [WP-8 C-M3]`,
`feat(cispctl): create-account, export-audit, verify-audit and partitions [WP-8 C-M3]`,
`test(api): the console role matrix over every operation [WP-8 C-M3]`.
