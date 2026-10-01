# WP-9: the web scaffold (Next.js on `uspace-ui`)

Branch `feat/WP-9-web-scaffold`. Milestone C-M1 (with U-M1). Owns
exclusively: `web/` (everything), the `web` CI job in
`.github/workflows/ci.yml` (added as its own job with a `web/**` path
filter), the `web` service in `deploy/compose.yml` (enabling the
profile) and `deploy/Dockerfile.web`. Depends on WP-0 and on
`uspace-ui`'s first release (U-M1); may start against a pre-release tag
and bump it. WP-10 and WP-11 build pages on this scaffold: open the PR
as soon as `npm run build` passes in CI.

## Read first

1. `CLAUDE.md`, `docs/PLAN.md §1.2` (render only), `§2` (the `web`
   rules), `§4` (web dependencies), `§6.6` (the BFF), `§8.1` (T12),
   `§10.7`, `§11` (images never built on the server), `§15` Q14.
2. Spec `00 §6` (Next.js only renders; API routes are at most a BFF;
   a geometry import fails lint; TypeScript types generated from the
   OpenAPI, never hand-written), `00 §6.2` (web → backend rules, the
   cookie), `00 §6.3` (`uspace-ui` contents), `06 §3` (`HttpOnly`,
   `SameSite=Strict`, CSRF, no credential in browser JS), `07` KT-3
   (CI rules for Next.js: lint, build, generated types up to date,
   no-geometry-import and no-server-side-business-logic rules), `08`
   Q15 (ka and en; branding as configuration).
3. `uspace-ui` at its tag: README, the exported components (theme
   provider, map, legends, i18n provider, BFF helpers), its ESLint
   config and the Georgian font setup.

## What to build

- `web/`: Next.js (App Router, `output: 'standalone'`), React,
  TypeScript `strict: true` (plus `noUncheckedIndexedAccess`), Tailwind
  with the kit's theme, `@rootxkit/uspace-ui` pinned (git tag until a
  registry exists, Q14), `npm` with a committed lockfile and `npm ci`.
- Layout: `app/[locale]/(public)/` (WP-10 fills it) and
  `app/[locale]/(console)/` (WP-11), `app/_bff/` routes, `src/api/`
  (generated `types.ts` from `../api/openapi.yaml` by
  `openapi-typescript`, plus a thin typed `fetch` wrapper that reads
  `NEXT_PUBLIC_API_BASE_URL` on the client and `CISP_API_INTERNAL_URL`
  on the server), `src/i18n/` (`ka.json`, `en.json`, the kit's provider;
  a test that both catalogues have the same keys), `src/branding.ts`
  (reads `CISP_BRANDING_FILE` at build or start: name, logo, contact;
  defaults are code names, never a real organisation's), `middleware.ts`
  (locale routing `/ka`, `/en`, default from `Accept-Language`, `ka`
  first).
- The BFF (`app/_bff/login/route.ts`, `logout`, `proxy/[...path]`): the
  kit's helpers; login posts credentials to `/v1/console/session`
  server-side and sets the `HttpOnly; Secure; SameSite=Strict` cookie
  with the token; the proxy forwards `/_bff/proxy/*` to `/v1/console/*`
  with the cookie as the bearer and a double-submit CSRF token on
  mutating methods; nothing else runs server-side. `web` holds no
  signing key, no database URL, no NATS URL (a test greps the built
  server bundle's env usage for `CISP_DATABASE_URL`, `CISP_NATS_URL`,
  `CISP_SIGNING` and fails if present).
- Lint: the kit's ESLint config plus two project rules in
  `web/eslint-rules/`: `no-geometry-import` (forbids `@turf/*`, `geojson`,
  `proj4`, `h3-js`, `@mapbox/*` except what the kit re-exports,
  `geolib`, `cheap-ruler`, any package with `geodesy` in its name) and
  `no-server-business-logic` (files under `app/_bff/` may import only
  the kit's BFF helpers, `next/server` and `src/api/types`; no other
  `app/**/route.ts` may exist). Both rules have a failing fixture in
  the test.
- Fonts: the kit's Noto Sans Georgian through `next/font` (self-hosted
  in the image, no runtime fetch); a Playwright smoke test renders a
  Georgian string and asserts the computed font family.
- `deploy/Dockerfile.web`: `node:22-alpine` builder (`npm ci`,
  `npm run build`), runner with the standalone output, non-root, port
  3000; health at `/healthz` (a static route). The `web` compose
  service with `NEXT_PUBLIC_API_BASE_URL` and `CISP_API_INTERNAL_URL`.
- CI job `web` (path-filtered to `web/**`, `api/openapi.yaml`): `npm
  ci`, `npm run generate` then `git diff --exit-code web/src/api`,
  `npm run lint`, `npm run typecheck`, `npm test` (vitest), `npm run
  build`, Playwright smoke against `next start` with `/public/v1/*`
  mocked by a small fixture server (`web/test/mock-api.mjs`) — browsers
  cached by `actions/cache` keyed on the Playwright version. The image
  job of WP-0 gains the `web` image step.

## Tests

- i18n: catalogue keys equal; no hardcoded display string in `app/`
  (an ESLint rule from the kit if it has one, else a grep test for
  JSX text nodes outside `t()` in this repo's pages).
- Lint fixtures: a file importing `@turf/boolean-point-in-polygon` fails
  `no-geometry-import`; a `route.ts` outside `_bff` fails
  `no-server-business-logic`; the BFF files pass.
- BFF: login sets the cookie flags (unit test on the route handler with
  a mocked `fetch`), the proxy forwards the bearer and refuses a
  mutating request without the CSRF token, `logout` clears the cookie
  and calls `DELETE /v1/console/session`.
- Bundle check: the built server bundle contains none of the forbidden
  env names.
- Playwright: `/ka` and `/en` load, the Georgian glyphs render with the
  kit's font, the locale switch works.

## Done when

- [ ] The `web` CI job green with every step listed above (paste the
  summary); the `web` image pushed on `main`.
- [ ] `docker compose --profile web up` serves the shell at `/ka` with
  the kit's theme (screenshot in the PR).
- [ ] The two lint rules fail their fixtures and pass the tree.
- [ ] CHANGELOG line; outputs pasted (E-04).

## Safety notes

The only safety rule for `web` is that it cannot become a second place
where airspace is judged or where a credential lives. The two lint
rules and the bundle check are that rule in executable form; they are
not optional and they fail CI, not warn.

## Commits

`feat(web): Next.js scaffold on uspace-ui with ka/en and generated API types [WP-9 C-M1]`,
`feat(web): the BFF login, proxy and logout routes with the session cookie [WP-9 C-M1]`,
`ci(web): lint, typecheck, generate check, build, smoke test and the web image [WP-9 C-M1]`,
`build(deploy): the web image and compose service [WP-9 C-M1]`.
