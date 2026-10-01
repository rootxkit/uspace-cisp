// Package auth is the machine side of the CISP's authentication: the
// wiring of uspace-core/auth's token verifier, the scope table, the
// publisher binding and the mTLS subject check, as net/http middleware
// that refuses with problem+json. WP-8 adds console sessions in separate
// files.
//
// # Tokens
//
// NewMachineVerifier builds one uspace-core/auth.Verifier per process,
// at start, with the issuers CISP_TOKEN_ISSUER and, when set,
// CISP_LAB_ISSUER (the lab's token issuer, so the CISP never waits for
// the authority's token service), MaxSkew 30 s, a 24 h JWKS cache and
// StrictSessionClaims on (a roles or realm claim of the wrong type is
// refused, as every uspace system does). Audiences is the list
// CISP_AUDIENCES: core v1.1.0's Config.Audiences accepts a token whose
// aud contains any one of them (M18: aud is a host everywhere in the
// ecosystem), so no wrapping is needed here; Config.Audience is set to
// the first entry because core requires it, and it is also in the list.
//
// Core fetches every JWKS at start and refuses to start when one cannot
// be fetched. The CISP adds a disk copy (JWKSCache, CISP_JWKS_CACHE_FILE,
// default local/jwks-cache.json) written on every successful fetch,
// start-up and refresh alike, through the HTTP client core is given. When
// a JWKS is unreachable at start and a copy exists, the verifier starts
// on the copy as a static key set and the status line says
// "jwks: stale since T" at error level (Reloading); it retries the issuer
// every period and swaps in a URL-configured verifier as soon as the
// issuer answers. With no copy the start fails and says so. Once running,
// core's own cache serves through an outage (06 section 2 T5); every
// fetch, core's included, runs on a context of its own (E-14), never a
// caller's.
//
// # Middleware
//
// Guard holds the verifier and the bindings. RequireScopes and
// RequireAnyScope authenticate the bearer token (401 unauthenticated,
// with the claim core named in errors[0].field and in detail) and check
// the scope (403 forbidden, naming the missing scope). RequirePublisher
// binds sub to the configured client id of the authority or the ANSP
// (403 not_a_publisher). RequireMTLSSubject binds the ANSP's certificate
// subject that Caddy forwards in X-Client-Cert-Subject (403
// mtls_required), and passes everything in CISP_MTLS_MODE=off, which the
// status line reports at error level every period. The middleware runs
// only on the routes that need it: a header that Caddy should have
// stripped is never read anywhere else. Every refusal is a counter in the
// status line's auth component, named after core's counter where core
// refused, and a rate-limited log line.
//
// The verified caller is in the request context (CallerFrom).
package auth
