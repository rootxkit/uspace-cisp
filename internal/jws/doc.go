// Package jws is the CISP's adapter to uspace-core/auth's JWS helpers
// (core v1.1.0, docs/PLAN.md section 15 Q20): it never implements JOSE
// itself. It holds:
//
//   - KeyRing: the CISP's own signing keys (CISP_SIGNING_KEY_FILE and,
//     during a rotation, CISP_SIGNING_KEY_PREV_FILE) loaded from PEM into
//     a core auth.KeyRing, with the 3072-bit floor of docs/PLAN.md
//     section 8.4 (core's own floor is 2048), and the public JWKS as
//     cached bytes with a strong ETag for GET /.well-known/jwks.json.
//     SignDetached and SignCompact are core's.
//   - DetachedVerifier: core's detached JWS verifier (X-JWS-Signature,
//     RFC 7515 Appendix F with RFC 7797 b64 false, alg RS256, kid, iat,
//     crit ["b64"]) bound to one publisher. The key source is the
//     publisher's own JWKS (Q8, M26): the authority's token-service JWKS
//     (CISP_TOKEN_JWKS_URL, its publication key distinguished by kid) for
//     F1 bodies, the ANSP's JWKS (CISP_ANSP_JWKS_URL) for F2 bodies. The
//     fetch and the cache are core's own (jwk sets cached 24 h, refresh on
//     an unknown kid rate-limited, every fetch on a context of its own,
//     E-14); the CISP adds only the disk copy for start-up, through
//     internal/auth.Reloading. iat may be CISP_PUBLISHER_SIGNATURE_MAX_SKEW_S
//     old or ahead, and an empty body is refused here, before core.
//   - RequireSignature: middleware that reads the raw body (bounded),
//     verifies its signature before any byte is parsed, and hands the
//     same bytes on. A signature failure is never a warning: the request
//     is refused with problem+json slug "signature", so an unsigned
//     publication cannot probe the parser.
//
// The direct import of lestrrat-go/jwx/v3 is jwk only: core's
// IssuerConfig.Keys is a jwk.Set, which a static key set (tests, the disk
// copy) has to build.
package jws
