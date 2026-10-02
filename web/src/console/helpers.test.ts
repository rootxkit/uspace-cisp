// The console's pure helpers: the login's wording of the API's refusals
// (the lockout with its time left), the status strip's ages and
// warnings, the audit filter, the retry offer and the box ring.
import { describe, expect, it } from "vitest";
import type { Translate } from "@rootxkit/uspace-ui/i18n";
import { auditQuery } from "./AuditPage";
import { bboxRing, fmtBBox } from "./BBoxPreview";
import { localisingFetch, minutesLeft } from "./LoginPage";
import { ageOnApiClockS, timesShown, warningsOf } from "./StatusStrip";
import { retryable } from "./SubscriptionsPage";

const t: Translate = (key, vars) => (vars === undefined ? key : `${key} ${JSON.stringify(vars)}`);

function problemResponse(status: number, slug: string, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify({ type: `https://schemas.uspace.ge/problems/${slug}`, title: "T", status, detail: "API text" }), {
    status,
    headers: { "Content-Type": "application/problem+json", ...headers },
  });
}

async function detailOf(res: Response): Promise<unknown> {
  return ((await res.json()) as { detail?: unknown }).detail;
}

describe("the login's wording", () => {
  it("a lockout says the minutes left from Retry-After", async () => {
    const f = localisingFetch(t, () => Promise.resolve(problemResponse(423, "locked", { "Retry-After": "840" })));
    const res = await f("/_bff/login");
    expect(res.status).toBe(423);
    expect(res.headers.get("Retry-After")).toBe("840");
    expect(await detailOf(res)).toBe('cisp.console.login.locked_for {"minutes":14}');
  });

  it("a lockout without Retry-After still says it is locked", async () => {
    const f = localisingFetch(t, () => Promise.resolve(problemResponse(423, "locked")));
    expect(await detailOf(await f("/_bff/login"))).toBe("cisp.console.login.locked");
  });

  it("a known refusal is worded by its slug; an unknown one passes as the API sent it", async () => {
    const known = localisingFetch(t, () => Promise.resolve(problemResponse(401, "invalid_totp")));
    expect(await detailOf(await known("/_bff/login"))).toBe("cisp.console.login.problem.invalid_totp");
    const unknown = localisingFetch(t, () => Promise.resolve(problemResponse(400, "bad_request")));
    expect(await detailOf(await unknown("/_bff/login"))).toBe("API text");
  });

  it("a success passes untouched", async () => {
    const ok = new Response(JSON.stringify({ status: "signed_in" }), { status: 200 });
    const f = localisingFetch(t, () => Promise.resolve(ok));
    expect(await f("/_bff/login")).toBe(ok);
  });

  it("minutes left round up and are at least one", () => {
    expect(minutesLeft(1)).toBe(1);
    expect(minutesLeft(60)).toBe(1);
    expect(minutesLeft(61)).toBe(2);
    expect(minutesLeft(900)).toBe(15);
  });
});

const healthy = {
  now: "2026-10-02T12:00:30Z",
  datasets: [{ dataset: "zones", current_version: 3 }],
  publishers: [{ client_id: "authority-01", stale: false, last_heartbeat_at: "2026-10-02T12:00:20Z" }],
  degraded: [],
  mtls_mode: "required" as const,
  restrictions: { active: 1, expiry: { stale: false, stale_after_s: 30, last_run_at: "2026-10-02T12:00:25Z" } },
};

describe("the status strip", () => {
  it("ages are measured on the API's clock", () => {
    expect(ageOnApiClockS("2026-10-02T12:00:30Z", "2026-10-02T12:00:20Z")).toBe(10);
    expect(ageOnApiClockS("2026-10-02T12:00:30Z", undefined)).toBeNull();
    expect(ageOnApiClockS("2026-10-02T12:00:30Z", "not a time")).toBeNull();
  });

  it("a healthy status raises no warning", () => {
    expect(warningsOf(healthy)).toEqual([]);
  });

  it("each degraded state raises its warning", () => {
    const keys = warningsOf({
      ...healthy,
      degraded: [{ component: "nats", since: "2026-10-02T11:00:00Z" }],
      publishers: [
        { client_id: "ansp-01", stale: true, last_heartbeat_at: "2026-10-02T11:58:00Z", stale_since: "2026-10-02T11:59:00Z" },
        { client_id: "authority-01", stale: true },
      ],
      mtls_mode: "off",
      restrictions: { active: 0, expiry: { stale: true, stale_after_s: 30, last_run_at: "2026-10-02T11:00:00Z" } },
    }).map((w) => w.key);
    expect(keys).toEqual([
      "cisp.console.status.degraded",
      "cisp.console.status.publisher_stale",
      "cisp.console.status.publisher_never",
      "cisp.console.status.mtls_off",
      "cisp.console.status.expiry_stale",
    ]);
  });

  it("the times of a warning are shown in the viewer's reading", () => {
    expect(timesShown({ since: "2026-10-02T11:00:00Z", component: "nats" }, () => "LOCAL")).toEqual({ since: "LOCAL", component: "nats" });
    expect(timesShown({ last: "" }, () => "LOCAL")).toEqual({ last: "—" });
  });
});

describe("the audit filter", () => {
  const toUtc = (s: string) => (s === "2026-10-01T00:00" ? "2026-10-01T00:00:00Z" : null);

  it("leaves empty members out", () => {
    expect(auditQuery({ since: "", actor: " ", type: "" }, toUtc)).toEqual({});
  });

  it("sends since as UTC, the actor and the type trimmed", () => {
    expect(auditQuery({ since: "2026-10-01T00:00", actor: " admin1 ", type: "console_republish" }, toUtc)).toEqual({
      since: "2026-10-01T00:00:00Z",
      actor: "admin1",
      type: "console_republish",
    });
  });

  it("an unreadable since is refused before the API", () => {
    expect(auditQuery({ since: "yesterday", actor: "", type: "" }, toUtc)).toBeNull();
  });
});

describe("subscriptions", () => {
  it("a retry is offered for a failed, expired or queued delivery, not one in flight or delivered", () => {
    expect(["failed", "expired", "queued"].map(retryable)).toEqual([true, true, true]);
    expect(["delivering", "delivered"].map(retryable)).toEqual([false, false]);
  });

  it("the box is drawn from its four numbers as sent", () => {
    expect(bboxRing([44.7, 41.6, 44.9, 41.8])).toEqual([
      [44.7, 41.6],
      [44.9, 41.6],
      [44.9, 41.8],
      [44.7, 41.8],
      [44.7, 41.6],
    ]);
    expect(fmtBBox([44.7, 41.6, 44.9, 41.8])).toBe("[44.7000, 41.6000, 44.9000, 41.8000]");
  });

  it("anything but four finite numbers draws no box", () => {
    expect(bboxRing(undefined)).toBeNull();
    expect(bboxRing([1, 2, 3])).toBeNull();
    expect(bboxRing([1, 2, 3, Number.NaN])).toBeNull();
    expect(fmtBBox([])).toBeNull();
  });
});

describe("times", () => {
  it("a time is rendered in the viewer's zone with the zone named, in both languages", async () => {
    const { localTime } = await import("./ui");
    for (const lang of ["en", "ka"] as const) {
      const s = localTime("2026-10-02T12:00:30Z", lang);
      expect(s, lang).not.toBeNull();
      expect(s, lang).toMatch(/2026/);
    }
  });

  it("an unreadable time renders nothing", async () => {
    const { localTime } = await import("./ui");
    expect(localTime("not a time", "en")).toBeNull();
  });
});
