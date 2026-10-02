// Next.js request proxy (the middleware): locale routing and the CSP.
//
// - A path without /ka or /en is redirected to the language the request
//   prefers: the uspace_lang cookie, then Accept-Language, then ka.
// - Every page gets a fresh CSP nonce. It is set, never read, on a copy of
//   the request headers (a client-sent x-nonce is overwritten), passed to
//   the layout in CSP_NONCE_HEADER, and put in the request's CSP header so
//   Next.js stamps its own scripts with it.
import { CSP_NONCE_HEADER, issueCspNonce } from "@rootxkit/uspace-ui/auth/server";
import { LANG_COOKIE, negotiateLang } from "@rootxkit/uspace-ui/i18n";
import { NextResponse, type NextRequest } from "next/server";
import { contentSecurityPolicy } from "./src/csp";

const LOCALE_PREFIX = /^\/(ka|en)(\/|$)/;

export function proxy(req: NextRequest): NextResponse {
  const { pathname } = req.nextUrl;
  if (!LOCALE_PREFIX.test(pathname)) {
    const lang = negotiateLang(req.headers.get("accept-language"), req.cookies.get(LANG_COOKIE)?.value ?? null);
    const url = req.nextUrl.clone();
    url.pathname = `/${lang}${pathname === "/" ? "" : pathname}`;
    return NextResponse.redirect(url);
  }
  const nonce = issueCspNonce();
  const csp = contentSecurityPolicy(nonce, process.env.NODE_ENV === "development");
  const headers = new Headers(req.headers);
  headers.set(CSP_NONCE_HEADER, nonce);
  headers.set("Content-Security-Policy", csp);
  const res = NextResponse.next({ request: { headers } });
  res.headers.set("Content-Security-Policy", csp);
  return res;
}

export const config = {
  // Pages only: not Next's assets, the BFF, the API paths Caddy routes to
  // api, the basemap, or the static health file.
  matcher: ["/((?!_next/|_bff/|v1/|public/|basemap/|\\.well-known/|healthz|favicon\\.ico).*)"],
};
