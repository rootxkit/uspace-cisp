// The Content Security Policy every web/ in the ecosystem sets (uspace-ui
// PLAN §7, §11; M38): the API, the stream and the basemap are same-origin
// (`connect-src 'self'`), fonts are self-hosted (`font-src 'self'`),
// MapLibre's workers come from blobs (`worker-src blob:`), and nothing
// is fetched from a third party. Scripts and the kit's injected styles
// carry the per-request nonce. Development adds what the dev server's
// hot reload needs and nothing more.
export function contentSecurityPolicy(nonce: string, dev: boolean): string {
  return [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${dev ? " 'unsafe-eval'" : ""}`,
    dev ? "style-src 'self' 'unsafe-inline'" : `style-src 'self' 'nonce-${nonce}'`,
    "img-src 'self' data: blob:",
    "font-src 'self'",
    "connect-src 'self'",
    "worker-src blob:",
    "child-src blob:",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join("; ");
}
