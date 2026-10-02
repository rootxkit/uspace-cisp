// The BFF's three routes against a mocked API (fetch). Each refusal has
// its acceptance twin that differs in one thing (E-01).
import { readdirSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { NextRequest } from "next/server";
import { describe, expect, it, vi } from "vitest";
import { createBff, type BffConfig } from "./handlers";

const ORIGIN = "https://cisp.test";
const API = "http://api.internal:8080";

interface Call {
  url: string;
  method: string;
  headers: Headers;
  body: string | null;
}

function mockApi(answer: (c: Call) => Response) {
  const calls: Call[] = [];
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const req = new Request(input, init);
    const call: Call = {
      url: req.url,
      method: req.method,
      headers: req.headers,
      body: req.body === null ? null : await req.text(),
    };
    calls.push(call);
    return answer(call);
  });
  return { calls, fetch: fetchMock as unknown as typeof fetch };
}

function bffWith(f: typeof fetch) {
  const cfg: BffConfig = { apiBase: API, sessionMaxAgeS: 43200, timeoutMs: 2000, fetch: f };
  return createBff(cfg);
}

function req(pathname: string, init: { method: string; headers?: Record<string, string>; body?: string }) {
  return new NextRequest(`${ORIGIN}${pathname}`, {
    method: init.method,
    headers: { host: "cisp.test", ...init.headers },
    ...(init.body === undefined ? {} : { body: init.body }),
  });
}

/** The Set-Cookie lines of a response, by cookie name. */
function setCookies(res: Response): Map<string, string> {
  const out = new Map<string, string>();
  for (const line of res.headers.getSetCookie()) {
    const name = line.slice(0, line.indexOf("="));
    out.set(name, line);
  }
  return out;
}

const SESSION = {
  token: "header.payload.signature",
  expires_at: new Date(Date.now() + 3600_000).toISOString(),
  account: { id: "a1", username: "viewer1", role: "viewer" },
};

describe("login", () => {
  const login = (headers: Record<string, string> = {}) =>
    req("/_bff/login", {
      method: "POST",
      headers: { origin: ORIGIN, "content-type": "application/json", ...headers },
      body: JSON.stringify({ username: "viewer1", password: "pw" }),
    });

  it("posts the credentials to POST /v1/console/session and sets both cookies with their flags", async () => {
    const api = mockApi(() => Response.json(SESSION, { status: 201 }));
    const res = await bffWith(api.fetch).login(login());
    expect(res.status).toBe(200);
    expect(api.calls).toHaveLength(1);
    expect(api.calls[0]?.method).toBe("POST");
    expect(api.calls[0]?.url).toBe(`${API}/v1/console/session`);
    expect(JSON.parse(api.calls[0]?.body ?? "{}")).toEqual({ username: "viewer1", password: "pw" });

    const cookies = setCookies(res);
    const session = cookies.get("uspace_session") ?? "";
    expect(session).toContain(`uspace_session=${SESSION.token}`);
    expect(session).toMatch(/HttpOnly/i);
    expect(session).toMatch(/Secure/i);
    expect(session).toMatch(/SameSite=Strict/i);
    const csrf = cookies.get("uspace_csrf") ?? "";
    expect(csrf).toMatch(/^uspace_csrf=[A-Za-z0-9_-]{20,};/);
    expect(csrf).not.toMatch(/HttpOnly/i);
    expect(csrf).toMatch(/SameSite=Strict/i);
    // The token never reaches page script.
    expect(await res.text()).not.toContain(SESSION.token);
  });

  it("passes the API's refusal through and sets no cookie", async () => {
    const api = mockApi(() =>
      Response.json(
        { type: "https://schemas.uspace.ge/problems/invalid_credentials", title: "Invalid credentials", status: 401 },
        { status: 401, headers: { "content-type": "application/problem+json" } },
      ),
    );
    const res = await bffWith(api.fetch).login(login());
    expect(res.status).toBe(401);
    expect(setCookies(res).size).toBe(0);
  });

  it("refuses a cross-origin sign-in before calling the API", async () => {
    const api = mockApi(() => Response.json(SESSION, { status: 201 }));
    const res = await bffWith(api.fetch).login(login({ origin: "https://evil.test" }));
    expect(res.status).toBe(403);
    expect(api.calls).toHaveLength(0);
  });
});

describe("proxy", () => {
  const cookie = "uspace_session=tok123; uspace_csrf=csrf456";

  it("forwards /_bff/api/v1/console/* with the session cookie as the bearer", async () => {
    const api = mockApi(() => Response.json({ ok: true }));
    const res = await bffWith(api.fetch).proxy(req("/_bff/api/v1/console/me", { method: "GET", headers: { cookie } }));
    expect(res.status).toBe(200);
    expect(api.calls[0]?.url).toBe(`${API}/v1/console/me`);
    expect(api.calls[0]?.headers.get("authorization")).toBe("Bearer tok123");
    expect(api.calls[0]?.headers.get("cookie")).toBeNull();
  });

  it("refuses a mutating request without X-CSRF-Token", async () => {
    const api = mockApi(() => Response.json({ ok: true }));
    const res = await bffWith(api.fetch).proxy(
      req("/_bff/api/v1/console/subscriptions/s1/suspend", { method: "POST", headers: { cookie }, body: "{}" }),
    );
    expect(res.status).toBe(403);
    expect(api.calls).toHaveLength(0);
  });

  it("refuses a mutating request whose X-CSRF-Token differs from the cookie", async () => {
    const api = mockApi(() => Response.json({ ok: true }));
    const res = await bffWith(api.fetch).proxy(
      req("/_bff/api/v1/console/subscriptions/s1/suspend", {
        method: "POST",
        headers: { cookie, "x-csrf-token": "other" },
        body: "{}",
      }),
    );
    expect(res.status).toBe(403);
    expect(api.calls).toHaveLength(0);
  });

  it("forwards a mutating request whose X-CSRF-Token matches the cookie", async () => {
    const api = mockApi(() => Response.json({ ok: true }));
    const res = await bffWith(api.fetch).proxy(
      req("/_bff/api/v1/console/subscriptions/s1/suspend", {
        method: "POST",
        headers: { cookie, "x-csrf-token": "csrf456", "content-type": "application/json" },
        body: JSON.stringify({ reason: "test" }),
      }),
    );
    expect(res.status).toBe(200);
    expect(api.calls[0]?.method).toBe("POST");
    expect(api.calls[0]?.url).toBe(`${API}/v1/console/subscriptions/s1/suspend`);
    expect(api.calls[0]?.headers.get("authorization")).toBe("Bearer tok123");
  });

  it("refuses a path outside /v1/console", async () => {
    const api = mockApi(() => Response.json({ ok: true }));
    const res = await bffWith(api.fetch).proxy(req("/_bff/api/v1/publications/zones", { method: "GET", headers: { cookie } }));
    expect(res.status).toBe(404);
    expect(api.calls).toHaveLength(0);
  });
});

describe("logout", () => {
  const cookie = "uspace_session=tok123; uspace_csrf=csrf456";

  it("calls DELETE /v1/console/session with the bearer and clears both cookies", async () => {
    const api = mockApi(() => new Response(null, { status: 204 }));
    const res = await bffWith(api.fetch).logout(
      req("/_bff/logout", { method: "POST", headers: { cookie, "x-csrf-token": "csrf456" } }),
    );
    expect(res.status).toBe(204);
    expect(api.calls).toHaveLength(1);
    expect(api.calls[0]?.method).toBe("DELETE");
    expect(api.calls[0]?.url).toBe(`${API}/v1/console/session`);
    expect(api.calls[0]?.headers.get("authorization")).toBe("Bearer tok123");
    const cookies = setCookies(res);
    expect(cookies.get("uspace_session")).toMatch(/Max-Age=0|Expires=Thu, 01 Jan 1970/i);
    expect(cookies.get("uspace_csrf")).toMatch(/Max-Age=0|Expires=Thu, 01 Jan 1970/i);
  });

  it("clears the cookies even when the API is down", async () => {
    const f = vi.fn(() => Promise.reject(new TypeError("connect ECONNREFUSED"))) as unknown as typeof fetch;
    const res = await bffWith(f).logout(req("/_bff/logout", { method: "POST", headers: { cookie, "x-csrf-token": "csrf456" } }));
    expect(res.status).toBe(204);
    expect(setCookies(res).has("uspace_session")).toBe(true);
  });

  it("refuses a logout without X-CSRF-Token and leaves the cookies", async () => {
    const api = mockApi(() => new Response(null, { status: 204 }));
    const res = await bffWith(api.fetch).logout(req("/_bff/logout", { method: "POST", headers: { cookie } }));
    expect(res.status).toBe(403);
    expect(api.calls).toHaveLength(0);
    expect(setCookies(res).size).toBe(0);
  });
});

describe("routes", () => {
  const appDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../app");

  function routeFiles(dir: string): string[] {
    return readdirSync(dir).flatMap((name) => {
      const p = path.join(dir, name);
      if (statSync(p).isDirectory()) return routeFiles(p);
      return /^route\.[cm]?[jt]sx?$/.test(name) ? [path.relative(appDir, p).replaceAll("\\", "/")] : [];
    });
  }

  it("the app has exactly the three BFF routes and no ws-ticket", () => {
    expect(routeFiles(appDir).sort()).toEqual([
      "%5Fbff/api/[...path]/route.ts",
      "%5Fbff/login/route.ts",
      "%5Fbff/logout/route.ts",
    ]);
  });
});
