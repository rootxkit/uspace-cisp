# WP-2: machine authentication and signatures

Branch `feat/WP-2-auth-jws`. Milestone C-M1. Owns exclusively:
`internal/auth/` (machine side: verifier wiring, scope table, publisher
binding, mTLS subject check; WP-8 adds console sessions in separate
files), `internal/jws/`, `GET /.well-known/jwks.json`, `cispctl
rotate-key`, `cispctl sign` (a dev helper that signs a body with a local
key for tests and the lab). Depends on WP-0. WP-3, WP-4, WP-5, WP-6 and
WP-8 use its middleware: open the PR as soon as the `jwt_verify`
adapter test passes.

## Read first

1. `CLAUDE.md`, `docs/PLAN.md §8` (all), `§15` Q7, Q8, Q9, Q11, Q16,
   Q20 (all decided; the plan body applies them).
2. Spec `00 §6.2` (JWT), `02 §1` Auth, `02 F1` (detached JWS), `02 F2`
   (mTLS), `02 F3` (webhook JWS, JWKS), `06 §2` T4, T5, T10, `06 §3`,
   `06 §4` (no test keys committed).
3. `uspace-core/auth`: `Config`, `IssuerConfig`, `NewVerifier`,
   `Verifier.Verify`, `Claims`, `HasScope`, `RequireScope`, `TokenError`,
   `Issuer`, `NewIssuer`, `Issue`, `JWKS`, the counters. Read
   `auth/doc.go` and `jwt.go` for the exact refusal reasons.
4. `uspace-core/vectors/testdata/jwt_verify.json` (16 cases; `cisp` is
   an owner).
5. RFC 7515 Appendix F (detached content), RFC 7797 (`b64: false`,
   `crit`), `lestrrat-go/jwx/v3` `jws` package (`jws.Verify` with
   `jws.WithDetachedPayload`, `jws.WithKeySet`, `jws.WithKey`;
   `jws.Sign` with protected headers).
6. LESSONS E-01, E-10, E-14 (shared work never on a caller's context:
   core's verifier already does this; your JWKS endpoint and key ring
   must not undo it).

## What to build

### Token verification middleware (`internal/auth`)

- `NewMachineVerifier(ctx, cfg)`: `core/auth.Config{Issuers:
  {cfg.TokenIssuer: {JWKSURL: cfg.TokenJWKSURL}, cfg.LabIssuer (optional):
  {JWKSURL}}, Audiences: cfg.Audiences, MaxSkew: 30 s, JWKSCacheTTL:
  24 h}`. `Audiences` is the list `CISP_AUDIENCES` (the CISP's public
  host plus a lab alias; `aud` is a host everywhere in the ecosystem,
  `docs/PLAN.md §8.2`, M18); if core's `Config` takes a single
  `Audience`, wrap it so a token is accepted when its `aud` matches any
  configured value, and say so in `doc.go`. The optional second issuer
  is the lab's token issuer (lab WP-L2), so the CISP never waits for
  the authority's token service. One instance per process, created
  at start; a JWKS fetch failure at start is **not** fatal when a cached
  copy exists on disk (`local/jwks-cache.json`, written on every
  successful refresh) and is fatal otherwise — both branches tested and
  the degraded one reported in the status line (`jwks: stale since T`).
- `RequireScopes(scopes ...string) Middleware` and
  `RequireAnyScope(...)`: 401 `problem+json` with `type:
  https://schemas.uspace.ge/problems/unauthenticated` and the claim
  core named (`exp`, `aud`, `kid`, `alg`, `iss`, `signature`, `jti`) in
  `errors[0].field`, 403 `.../forbidden` with the missing scope;
  counters per refusal reason mirror core's.
- `Caller` in the request context: `{Kind: machine|console, ClientID,
  Scopes, Claims}`; `CallerFrom(ctx)`.
- Publisher binding: `RequirePublisher(kind)`: the `sub` must equal
  `cfg.AuthorityClientID` (kind authority; `authority-01`) or
  `cfg.ANSPClientID` (kind ansp; `ansp-01`); 403 `.../not_a_publisher`
  otherwise, counted `rejected_publisher_binding`. Client ids are one
  per calling system (M24); the values are configuration.
- mTLS binding: `RequireMTLSSubject()`: in mode `required`, the request
  must carry `X-Client-Cert-Subject` equal to `cfg.ANSPMTLSSubject`
  (constant-time compare; absent → 403 `.../mtls_required`); in mode
  `off` the middleware passes and the status line prints `mtls: off` at
  **error** level every period (LESSONS Z-09 style: a disabled
  safeguard is never quiet). Caddy runs `client_auth verify_if_given`
  and strips the header on every other route and on every request that
  presented no certificate (`deploy/caddy/Caddyfile.snippet`, WP-0;
  this WP adds the test that a forged header on a non-ANSP route is
  ignored by `api` too: the middleware runs only on the mTLS routes,
  `/v1/restrictions*` and the ANSP's `/v1/publishers/heartbeat`).

### Signatures (`internal/jws`)

```go
type KeyRing struct{...}   // current + previous RSA keys with kids
func LoadKeyRing(currentPEM, currentKID string, prevPEM, prevKID string) (*KeyRing, error)   // refuses < 3072 bits, missing kid, duplicate kid
func (k *KeyRing) JWKS() []byte                                        // the public set, cached bytes, ETag
func (k *KeyRing) SignDetached(body []byte, now time.Time) (string, error)   // "<protected>..<sig>", RS256, b64:false, crit:["b64"], kid, iat
func (k *KeyRing) SignCompact(payload []byte, now time.Time) (string, error) // compact JWS for webhooks (WP-6 adds the claims)
type DetachedVerifier struct{...}
func NewDetachedVerifier(keys KeySource, maxSkew time.Duration) *DetachedVerifier   // KeySource: a publisher's JWKS through core's cached fetch (one verifier per publisher: the authority's JWKS, the ANSP's JWKS), or a static set for tests
func (v *DetachedVerifier) Verify(header string, body []byte, now time.Time) (kid string, err error)   // refuses: malformed, alg != RS256, b64 != false or crit missing it, unknown kid, bad signature, iat outside skew, empty body
func (v *DetachedVerifier) Counters() *core.Counters
```

The JWKS source for inbound signatures is **the publisher's own**
`/.well-known/jwks.json` (Q8, M26): the authority's token-service JWKS
(`CISP_TOKEN_JWKS_URL`; the publication key is distinguished by `kid`
and `use: sig`) for F1 bodies, and the ANSP's JWKS (`CISP_ANSP_JWKS_URL`)
for F2 bodies. Reuse core's `jwk.Cache`-backed fetch by asking the core
verifier for its key set if it exposes one; if not, hold a `jwk.Cache`
per publisher in `internal/jws` with the same 24 h TTL and rate-limited
refresh on an unknown `kid`, on a context of its own (E-14). Say in
`doc.go` which it is. Core `v1.1.0` (core WP-14) ships `auth.KeyRing`,
`SignDetached`, `VerifyDetached`, `SignCompact`, `VerifyCompact` with
these semantics (Q20, M27): this WP may land first on `internal/jws`
because it is on the C-M1 critical path; the PR body names the
follow-up that switches to core and removes the direct `jwx` import,
and the `internal/jws` API above is kept close to core's names so the
switch is mechanical.

`GET /.well-known/jwks.json`: the `KeyRing.JWKS()` bytes with
`Cache-Control: public, max-age=3600` and `ETag`; no auth.

`cispctl rotate-key --out local/`: generates RSA-3072, writes
`signing-<kid>.pem` (0600) and prints the env lines to set; refuses to
write outside `local/` unless `--force`. `cispctl sign --key file --kid
k < body`: prints the detached header for a body (lab and tests).

### Configuration (`deploy/.env.example` block)

`CISP_TOKEN_ISSUER`, `CISP_TOKEN_JWKS_URL` (https only, except
`localhost`), `CISP_LAB_ISSUER`, `CISP_LAB_JWKS_URL` (optional; the lab
issuer), `CISP_AUDIENCES` (comma-separated hosts; no default: the
public host is deployment configuration, the lab alias is the compose
service name; refused empty), `CISP_AUTHORITY_CLIENT_ID` (`authority-01`
in the lab), `CISP_ANSP_CLIENT_ID` (`ansp-01`), `CISP_ANSP_JWKS_URL`,
`CISP_ANSP_MTLS_SUBJECT`, `CISP_MTLS_MODE` (`required|off`; default
`required`), `CISP_SIGNING_KEY_FILE`,
`CISP_SIGNING_KID`, `CISP_SIGNING_KEY_PREV_FILE`, `CISP_SIGNING_KID_PREV`,
`CISP_PUBLISHER_SIGNATURE_MAX_SKEW` (5 m).

## Tests

- `TestVectorsJWTVerify` (`internal/auth/vectors_test.go`): each case's
  token through the middleware against a handler that returns 204;
  expected `accepted` → 204, else 401 with the case's claim in the
  problem `detail`; `RequireScope` cases → 403. Uses
  `vectors.Load(t, "jwt_verify.json")` and `RunOwned(t, "cisp", ...)`;
  the fixture JWKS as a static `IssuerConfig.Keys`.
- E-01 pairs for every refusal of §8.1 T4 row one (wrong `aud`, wrong
  `sub`, right `sub` wrong scope, no signature, unknown `kid`, stale
  `iat`, altered body, mTLS subject mismatch, a body signed with the
  authority's key on the ANSP route and vice versa) beside the accepted
  request; `aud` accepted for each value of a two-entry `CISP_AUDIENCES`
  and refused for a third; keys generated with `rsa.GenerateKey` at
  test time, never committed (`06 §4`; `gitleaks` would catch a PEM
  anyway).
- `DetachedVerifier` refuses `b64:true`, a missing `crit`, `alg none`,
  HS256 with the public key as secret (the confusion attack), an `iat`
  31 s... no: `maxSkew` is 5 min here; test at ±(5 min ± 1 s).
- Key ring: < 3072 bits refused; previous key verifies after rotation;
  JWKS carries both `kid`s; a signature by a key no longer in the ring
  is refused.
- JWKS cache on disk: start with the issuer down and a cache present
  (degraded, serves), with the issuer down and no cache (fatal, says
  so), with the issuer up (healthy status line read back) — E-02.
- `FuzzVerifyDetached(header, body)` never panics.
- Benchmarks `BenchmarkVerifyDetached20MB` (one RSA verify + SHA-256 of
  20 MB: budget 100 ms) and `BenchmarkSignCompact`.

## Done when

- [ ] 16/16 `jwt_verify` cases pass through the middleware; lint, race
  green; coverage ≥ 90 % in `internal/jws`, ≥ 85 % in `internal/auth`.
- [ ] `mtls: off` appears at error level in the status line when set
  (paste one line); `required` mode refuses a wrong subject and a
  missing header (paste the problem bodies).
- [ ] `cispctl rotate-key` output used by `cispctl sign` verifies through
  `DetachedVerifier` in an end-to-end shell test (`tools/jws-smoke.sh`).
- [ ] The PR body names the follow-up that switches `internal/jws` to
  core `v1.1.0`'s helpers (`docs/PLAN.md §15` Q20).
- [ ] CHANGELOG line; outputs pasted (E-04).

## Safety notes

A signature failure must never be downgraded to a warning: an unsigned
or badly signed publication is refused before any byte is parsed
(cheaper, and the publication path cannot be used to probe the parser
without a key). Verify the detached signature over the raw body
**before** `ed318.Parse`, and test that ordering with a body that is
both unsigned and invalid: the problem must name the signature only.

## Commits

`feat(auth): verify ecosystem tokens with core, scopes and publisher binding [WP-2 C-M1]`,
`feat(jws): detached JWS verification and signing with a rotating key ring [WP-2 C-M1]`,
`feat(api): publish the signing JWKS [WP-2 C-M1]`,
`feat(cispctl): rotate-key and sign [WP-2 C-M1]`,
`test(auth): run the 16 jwt_verify vectors through the middleware [WP-2 C-M1]`.
