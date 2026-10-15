// The BFF's three routes against a mocked API (fetch). Each refusal has
// its acceptance twin that differs in one thing (E-01).
import { readdirSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { NextRequest } from "next/server";
import { describe, expect, it, vi } from "vitest";
import { configFromEnv, configProblem, createBff, exactRoutesOf, type BffConfig } from "./handlers";

const ORIGIN = "https://cisp.test";
const API = "http://api.internal:8080";
// A test value built at run time, not a secret.
const MFA_SECRET = "t".repeat(32);

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

function bffWith(f: typeof fetch, trustedProxyHops = 1) {
  const cfg: BffConfig = { apiBase: API, sessionMaxAgeS: 43200, timeoutMs: 2000, mfaChallengeSecret: MFA_SECRET, trustedProxyHops, fetch: f };
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

describe("two-step sign-in (MFA)", () => {
  const CHALLENGE = { mfa_token: "challenge-token-abc", expires_at: new Date(Date.now() + 300_000).toISOString() };
  const step = (body: Record<string, string>, cookie?: string) =>
    req("/_bff/login", {
      method: "POST",
      headers: { origin: ORIGIN, "content-type": "application/json", ...(cookie === undefined ? {} : { cookie }) },
      body: JSON.stringify(body),
    });
  /** The `name=value` of a Set-Cookie line, for the next request. */
  const pair = (line: string | undefined) => (line ?? "").split(";")[0] ?? "";

  it("seals the API's challenge into uspace_mfa and exchanges it with the code at POST /v1/console/session/mfa", async () => {
    const api = mockApi((c) =>
      c.url.endsWith("/v1/console/session/mfa") ? Response.json(SESSION, { status: 201 }) : Response.json(CHALLENGE, { status: 200 }),
    );
    const bff = bffWith(api.fetch);
    const first = await bff.login(step({ username: "admin1", password: "pw" }));
    expect(first.status).toBe(200);
    expect(await first.json()).toEqual({ status: "mfa_required" });
    const mfa = setCookies(first).get("uspace_mfa") ?? "";
    expect(mfa).toMatch(/HttpOnly/i);
    expect(mfa).toMatch(/Path=\/_bff/i);
    expect(mfa).toMatch(/SameSite=Strict/i);
    // Sealed: the challenge itself is not in the cookie, nor a session.
    expect(mfa).not.toContain(CHALLENGE.mfa_token);
    expect(setCookies(first).has("uspace_session")).toBe(false);
    expect(api.calls[0]?.url).toBe(`${API}/v1/console/session`);

    const second = await bff.login(step({ username: "admin1", otp: "123456" }, pair(mfa)));
    expect(second.status).toBe(200);
    expect(api.calls).toHaveLength(2);
    expect(api.calls[1]?.method).toBe("POST");
    expect(api.calls[1]?.url).toBe(`${API}/v1/console/session/mfa`);
    expect(JSON.parse(api.calls[1]?.body ?? "{}")).toEqual({ mfa_token: CHALLENGE.mfa_token, code: "123456" });
    const cookies = setCookies(second);
    expect(cookies.get("uspace_session") ?? "").toContain(`uspace_session=${SESSION.token}`);
    expect(cookies.get("uspace_mfa") ?? "").toMatch(/Max-Age=0/i);
  });

  it("passes a wrong code's 401 through and keeps the challenge cookie", async () => {
    const api = mockApi((c) =>
      c.url.endsWith("/v1/console/session/mfa")
        ? Response.json(
            { type: "https://schemas.uspace.ge/problems/invalid_totp", title: "Unauthorized", status: 401 },
            { status: 401, headers: { "content-type": "application/problem+json" } },
          )
        : Response.json(CHALLENGE, { status: 200 }),
    );
    const bff = bffWith(api.fetch);
    const first = await bff.login(step({ username: "admin1", password: "pw" }));
    const res = await bff.login(step({ username: "admin1", otp: "000000" }, pair(setCookies(first).get("uspace_mfa"))));
    expect(res.status).toBe(401);
    expect(setCookies(res).size).toBe(0);
  });

  it("refuses the code step without the password step's cookie, before calling the API", async () => {
    const api = mockApi(() => Response.json(SESSION, { status: 201 }));
    const res = await bffWith(api.fetch).login(step({ username: "admin1", otp: "123456" }));
    expect(res.status).toBe(401);
    expect(api.calls).toHaveLength(0);
  });
});

describe("configuration", () => {
  const keys = ["CISP_API_INTERNAL_URL", "CISP_WEB_MFA_CHALLENGE_SECRET", "CISP_WEB_TRUSTED_PROXY_HOPS"] as const;
  function withEnv(env: Partial<Record<(typeof keys)[number], string>>, run: () => void) {
    try {
      for (const k of keys) vi.stubEnv(k, env[k]);
      run();
    } finally {
      vi.unstubAllEnvs();
    }
  }

  it("names a missing or short MFA challenge secret, and accepts one of 32 bytes", () => {
    withEnv({ CISP_API_INTERNAL_URL: API }, () => {
      expect(configProblem()).toMatch(/CISP_WEB_MFA_CHALLENGE_SECRET/);
      expect(configFromEnv()).toBeNull();
    });
    withEnv({ CISP_API_INTERNAL_URL: API, CISP_WEB_MFA_CHALLENGE_SECRET: "t".repeat(31) }, () => {
      expect(configProblem()).toMatch(/CISP_WEB_MFA_CHALLENGE_SECRET/);
    });
    withEnv({ CISP_API_INTERNAL_URL: API, CISP_WEB_MFA_CHALLENGE_SECRET: MFA_SECRET, CISP_WEB_TRUSTED_PROXY_HOPS: "1" }, () => {
      expect(configProblem()).toBeNull();
      expect(configFromEnv()?.mfaChallengeSecret).toBe(MFA_SECRET);
    });
    withEnv({ CISP_WEB_MFA_CHALLENGE_SECRET: MFA_SECRET }, () => {
      expect(configProblem()).toMatch(/CISP_API_INTERNAL_URL/);
    });
  });
});

describe("trusted proxy hops", () => {
  const complete = { CISP_API_INTERNAL_URL: API, CISP_WEB_MFA_CHALLENGE_SECRET: MFA_SECRET };
  function withEnv(hops: string | undefined, run: () => void) {
    try {
      vi.stubEnv("CISP_API_INTERNAL_URL", complete.CISP_API_INTERNAL_URL);
      vi.stubEnv("CISP_WEB_MFA_CHALLENGE_SECRET", complete.CISP_WEB_MFA_CHALLENGE_SECRET);
      vi.stubEnv("CISP_WEB_TRUSTED_PROXY_HOPS", hops);
      run();
    } finally {
      vi.unstubAllEnvs();
    }
  }

  it("is required: unset, empty or malformed, the BFF is not configured and names it", () => {
    for (const hops of [undefined, "", "-1", "1.5", "one", "9", "100"]) {
      withEnv(hops, () => {
        expect(configProblem(), String(hops)).toMatch(/CISP_WEB_TRUSTED_PROXY_HOPS/);
        expect(configFromEnv(), String(hops)).toBeNull();
      });
    }
  });

  it("takes 0 to 8, 1 behind Caddy", () => {
    for (const [raw, n] of [["0", 0], ["1", 1], ["8", 8]] as const) {
      withEnv(raw, () => {
        expect(configProblem()).toBeNull();
        expect(configFromEnv()?.trustedProxyHops).toBe(n);
      });
    }
  });

  const login = (xff: string) =>
    req("/_bff/login", {
      method: "POST",
      headers: { origin: ORIGIN, "content-type": "application/json", "x-forwarded-for": xff, "x-forwarded-proto": "https", "x-forwarded-host": "cisp.test" },
      body: JSON.stringify({ username: "admin1", password: "pw" }),
    });

  it("with one hop the API gets the address Caddy appended, never the client's own", async () => {
    const api = mockApi(() => Response.json({ access_token: "t", expires_at: new Date(Date.now() + 3_600_000).toISOString() }, { status: 201 }));
    await bffWith(api.fetch, 1).login(login("6.6.6.6, 203.0.113.7"));
    expect(api.calls).toHaveLength(1);
    expect(api.calls[0]?.headers.get("x-forwarded-for")).toBe("203.0.113.7");
  });

  it("with 0 the API gets no client address at all", async () => {
    const api = mockApi(() => Response.json({ access_token: "t", expires_at: new Date(Date.now() + 3_600_000).toISOString() }, { status: 201 }));
    await bffWith(api.fetch, 0).login(req("/_bff/login", {
      method: "POST",
      headers: { origin: ORIGIN, host: "cisp.test", "content-type": "application/json", "x-forwarded-for": "6.6.6.6" },
      body: JSON.stringify({ username: "admin1", password: "pw" }),
    }));
    expect(api.calls).toHaveLength(1);
    expect(api.calls[0]?.headers.get("x-forwarded-for")).toBeNull();
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

  it("forwards GET /v1/console/summary, its exact entry, to the API", async () => {
    const api = mockApi(() => Response.json({ ok: true }));
    const res = await bffWith(api.fetch).proxy(req("/_bff/api/v1/console/summary", { method: "GET", headers: { cookie } }));
    expect(res.status).toBe(200);
    expect(api.calls).toHaveLength(1);
    expect(api.calls[0]?.method).toBe("GET");
    expect(api.calls[0]?.url).toBe(`${API}/v1/console/summary`);
    expect(api.calls[0]?.headers.get("authorization")).toBe("Bearer tok123");
  });

  it("refuses any other method on the summary before the API, CSRF pair or not, encoded or not", async () => {
    const api = mockApi(() => Response.json({ ok: true }));
    const bff = bffWith(api.fetch);
    for (const method of ["POST", "PUT", "PATCH", "DELETE", "HEAD"]) {
      for (const path of ["/_bff/api/v1/console/summary", "/_bff/api/v1/console/%73ummary"]) {
        const res = await bff.proxy(
          req(path, {
            method,
            headers: { cookie, "x-csrf-token": "csrf456", "content-type": "application/json" },
            ...(method === "HEAD" ? {} : { body: "{}" }),
          }),
        );
        expect(res.status, `${method} ${path}`).toBe(405);
        expect(res.headers.get("allow")).toBe("GET");
      }
    }
    expect(api.calls).toHaveLength(0);
  });

  it("names the exact entry of a summary path only", () => {
    expect(exactRoutesOf("/_bff/api/v1/console/summary")).toEqual([{ method: "GET", path: "/v1/console/summary" }]);
    expect(exactRoutesOf("/_bff/api/v1/console/%73ummary")).toHaveLength(1);
    for (const p of ["/_bff/api/v1/console/summary/", "/_bff/api/v1/console/summaryx", "/_bff/api/v1/console/status", "/v1/console/summary", "/_bff/api/v1/console/%E0%A4%A"]) {
      expect(exactRoutesOf(p), p).toEqual([]);
    }
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
