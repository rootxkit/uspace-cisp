# web/: the CISP's public map and console

Next.js (App Router, `output: 'standalone'`) on the shared kit
[`uspace-ui`](https://github.com/rootxkit/uspace-ui), pinned to one
GitHub Release tarball. It renders what `api/openapi.yaml` serves and
judges nothing: no geometry library, no database, no NATS, no key
(`docs/PLAN.md` §1.2, §2; the two lint rules in `eslint-rules/` and the
bundle check enforce it).

```
app/[locale]/(public)/   the public map (WP-10)
app/[locale]/(console)/  the console (WP-11)
app/%5Fbff/              the three BFF routes: /_bff/login, /_bff/logout, /_bff/api/*
src/api/                 generated types (uspace-ui-gen-api) and the typed client
src/bff/handlers.ts      the BFF, on the kit's auth/server helpers
src/i18n/                ka.json, en.json (every display string)
src/branding.ts          CISP_BRANDING_FILE
proxy.ts                 locale routing (/ka, /en) and the per-request CSP
test/mock-api.mjs        the Playwright fixture server (stands in for Caddy)
```

## Commands

Node 22 and pnpm through corepack (`corepack enable`; the version is
`packageManager` in `package.json`).

```
pnpm install --frozen-lockfile
pnpm gen:api        # regenerate src/api/generated from ../api/openapi.yaml; commit the result
pnpm lint           # the kit's ESLint config + cisp/no-geometry-import + cisp/no-server-business-logic
pnpm typecheck
pnpm test           # vitest: catalogues, BFF, lint rules, branding, bundle check, no hardcoded strings
pnpm build
pnpm check:bundle   # the server bundle names no database, NATS or key variable
pnpm e2e            # Playwright: next start behind test/mock-api.mjs (run pnpm build first;
                    # `pnpm exec playwright install chromium` once)
```

## Running locally

Against the real API (`make dev-deps`, then the `api` process on
`:8080`, see the repository README):

```
CISP_DEV_API_URL=http://127.0.0.1:8080 CISP_API_INTERNAL_URL=http://127.0.0.1:8080 \
  NEXT_PUBLIC_MAP_CENTER=44.82,41.72 NEXT_PUBLIC_MAP_ZOOM=10 pnpm dev
```

`CISP_DEV_API_URL` rewrites `/public/*`, `/v1/*` and `/.well-known/*` to
the api in `pnpm dev` only, as Caddy does in a deployment; a build never
has rewrites. A rewrite does not carry the WebSocket, so under `pnpm dev`
the map shows "polling" and follows changes by `HEAD`. Without an API, the fixture server serves `/public/v1/*` in
front of a built app: `pnpm build`, then
`pnpm exec next start --port 3100` and
`MOCK_UPSTREAM=http://127.0.0.1:3100 node test/mock-api.mjs`, and open
`http://127.0.0.1:3000/ka` (set `NEXT_PUBLIC_MAP_CENTER=44.82,41.72` and
`NEXT_PUBLIC_MAP_ZOOM=10` on `next start` for the fixture collection).
The fixture server also serves `WS /v1/stream`; `POST
/__mock/state {"stream": false}` turns it off to see the map poll.

## Configuration

Read at start or at request time, never at build (the image is built
once in CI):

| Variable | Meaning |
|---|---|
| `CISP_API_INTERNAL_URL` | the API as the BFF reaches it (`http://api:8080` in compose); unset, the BFF answers 503 |
| `NEXT_PUBLIC_API_BASE_URL` | where the browser reaches the API; empty is same-origin (behind Caddy) |
| `CISP_BRANDING_FILE` | JSON `{name, short_name, logo_url, contact, accent}`; unset uses the code-name defaults; an unknown member fails the page naming it |
| `CISP_WEB_SESSION_MAX_AGE_S` | ceiling of the session cookie's `Max-Age` (43200); the API's `expires_at` shortens it |
| `CISP_WEB_UPSTREAM_TIMEOUT_MS` | timeout of each BFF call to the API (10000) |
| `CISP_WEB_TRUSTED_PROXY_HOPS` | reverse proxies in front of Next.js that append to `X-Forwarded-For` (1 behind Caddy) |
| `NEXT_PUBLIC_MAP_CENTER`, `NEXT_PUBLIC_MAP_ZOOM` | the public map's first view, `"lng,lat"` and a zoom; unset, the page names the variable instead of choosing a place |
| `CISP_WEB_POLL_INTERVAL_S` | the public map's `HEAD` poll period while the stream is not live (60) |

`deploy/compose.yml` sets them from `WEB_*` names in `deploy/.env`
(`deploy/.env.example`): the Go processes refuse unknown `CISP_*` names.

## Fonts and basemap

The fonts are the kit's Noto Sans and Noto Sans Georgian through
`next/font/local`, built into the image; no font is fetched at run time.
The map reads the self-hosted PMTiles bundle at `/basemap/`, which the
deployment's Caddy serves from the shared read-only volume the lab builds
(`docs/PLAN.md` §11, M38); the image holds no tiles. For a local stack,
download the basemap release artefact of `uspace-lab` into a directory
and serve it at `/basemap/` beside the app (Caddy's `handle_path
/basemap/*` with `file_server`, as `deploy/caddy/Caddyfile.snippet`
does). The CSP (`src/csp.ts`) allows `connect-src 'self'`,
`font-src 'self'` and `worker-src blob:` only, so no tile, font or
script request can leave the origin; the Playwright smoke run asserts it.

## Sessions

The BFF follows the kit's contract: `uspace_session` (`HttpOnly; Secure;
SameSite=Strict`) holds the API's session token and `uspace_csrf` is the
double-submit cookie, sent back as `X-CSRF-Token` on every unsafe
request. The proxy reaches `/v1/console/*` only. The WebSocket
`/v1/stream` is not proxied: the browser opens it same-origin and the
cookie rides the upgrade; a `4401` close means "sign in again". An
account with `mfa_required` cannot yet sign in on the web
(`docs/PLAN.md` §15 Q41 (3)).
