// The three BFF routes (/_bff/login, /_bff/logout, /_bff/api/*) on the
// kit's helpers (docs/PLAN.md §6.6; spec 06 §3). Nothing else runs on
// the server: no database, no bus, no key, no judgement. The BFF never
// verifies a token; the API decides every request.
//
// - login: the kit's `login`, posting {username, password} to
//   POST /v1/console/session and setting `uspace_session` (HttpOnly,
//   Secure, SameSite=Strict) and the `uspace_csrf` double-submit cookie.
// - proxy: the kit's `proxy`, forwarding /_bff/api/v1/console/* with the
//   session cookie as the bearer; unsafe methods need X-CSRF-Token equal
//   to the CSRF cookie.
// - logout: the kit's CSRF check and cookie clearing around the API's
//   DELETE /v1/console/session, sent through the kit's `forward` (the
//   kit's own logout POSTs, and the CISP revokes with DELETE).
//
// The WebSocket is not proxied: the browser upgrades WS /v1/stream
// same-origin and the cookie rides the upgrade (M22). No ticket route.
//
// This file may import only the kit's BFF helpers and next/server
// (eslint-rules/no-server-business-logic.mjs).
import {
  bffHandlers,
  checkCsrf,
  clearSession,
  forward,
  readSessionToken,
  type BffHandlers,
  type SessionCookieOptions,
} from "@rootxkit/uspace-ui/auth/server";
import { NextRequest, NextResponse } from "next/server";

/** The console API's session resource: login (POST) and logout (DELETE). */
export const CONSOLE_SESSION_PATH = "/v1/console/session";

/** What the proxy may reach: the console API and nothing else. */
export const PROXY_ALLOW_PATHS: RegExp[] = [/^\/v1\/console\/[^/]/];

export interface BffConfig {
  /** The API as the web container reaches it (CISP_API_INTERNAL_URL). */
  apiBase: string;
  /** The cookie's Max-Age ceiling, seconds (CISP_WEB_SESSION_MAX_AGE_S). */
  sessionMaxAgeS: number;
  /** The upstream timeout of every call, ms (CISP_WEB_UPSTREAM_TIMEOUT_MS). */
  timeoutMs: number;
  /** Reverse proxies in front of Next.js (CISP_WEB_TRUSTED_PROXY_HOPS). */
  trustedProxyHops?: number;
  fetch?: typeof fetch;
}

export type Handler = (req: NextRequest) => Promise<Response>;

export interface Bff {
  login: Handler;
  logout: Handler;
  proxy: Handler;
}

function problem(status: number, slug: string, title: string, detail: string): NextResponse {
  return NextResponse.json(
    { type: `https://schemas.uspace.ge/problems/${slug}`, title, status, detail },
    {
      status,
      headers: { "Content-Type": "application/problem+json", "Cache-Control": "no-store" },
    },
  );
}

/** The three handlers for one configuration. */
export function createBff(cfg: BffConfig): Bff {
  const session: SessionCookieOptions = { secure: true, maxAgeS: cfg.sessionMaxAgeS };
  const common = {
    timeoutMs: cfg.timeoutMs,
    ...(cfg.trustedProxyHops === undefined ? {} : { trustedProxyHops: cfg.trustedProxyHops }),
    ...(cfg.fetch === undefined ? {} : { fetch: cfg.fetch }),
  };
  const kit: BffHandlers = bffHandlers({
    apiBase: cfg.apiBase,
    apiLoginPath: CONSOLE_SESSION_PATH,
    session,
    allowPaths: PROXY_ALLOW_PATHS,
    ...common,
  });
  const base = new URL(cfg.apiBase);
  const sessionUrl = new URL(base.pathname.replace(/\/$/, "") + CONSOLE_SESSION_PATH, base);

  const logout: Handler = async (req) => {
    if (!checkCsrf(req)) {
      return problem(403, "csrf_refused", "CSRF check failed", "send the uspace_csrf cookie's value as X-CSRF-Token");
    }
    if (readSessionToken(req) !== null) {
      // The cookies are cleared whatever the API answers: signing out
      // in the browser does not wait for the API.
      const revoke = new NextRequest(sessionUrl, { method: "DELETE", headers: req.headers });
      const answer = await forward(revoke, sessionUrl, {
        session,
        allowPaths: [/^\/v1\/console\/session$/],
        ...common,
      });
      await answer.body?.cancel();
    }
    const res = new NextResponse(null, { status: 204, headers: { "Cache-Control": "no-store" } });
    clearSession(res, session);
    return res;
  };

  return { login: kit.login, logout, proxy: kit.proxy };
}

function positiveInt(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 1) throw new Error(`${name}: want a whole number of at least 1, got ${JSON.stringify(raw)}`);
  return n;
}

/** The configuration from the environment, read at the first request. */
export function configFromEnv(): BffConfig | null {
  const apiBase = process.env["CISP_API_INTERNAL_URL"];
  if (apiBase === undefined || apiBase === "") return null;
  const hops = process.env["CISP_WEB_TRUSTED_PROXY_HOPS"];
  return {
    apiBase,
    // Display-side ceiling only: the API's session lifetime (<= 12 h)
    // shortens it through expires_at.
    sessionMaxAgeS: positiveInt("CISP_WEB_SESSION_MAX_AGE_S", 12 * 3600),
    timeoutMs: positiveInt("CISP_WEB_UPSTREAM_TIMEOUT_MS", 10_000),
    ...(hops === undefined || hops === "" ? {} : { trustedProxyHops: positiveInt("CISP_WEB_TRUSTED_PROXY_HOPS", 1) }),
  };
}

let cached: Bff | null = null;

function unconfigured(): Promise<Response> {
  return Promise.resolve(
    problem(503, "bff_unavailable", "Console unavailable", "CISP_API_INTERNAL_URL is not set"),
  );
}

/** The handlers for this process, built lazily (the build has no environment). */
export function bff(): Bff {
  if (cached !== null) return cached;
  const cfg = configFromEnv();
  if (cfg === null) return { login: unconfigured, logout: unconfigured, proxy: unconfigured };
  cached = createBff(cfg);
  return cached;
}
