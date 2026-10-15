import { describe, expect, it } from "vitest";
import { failedView, latencyView, usspsView, type Summary } from "./summary";

const base: Summary = {
  now: "2026-10-15T12:00:00Z",
  subscriptions: { pending_verification: 1, active: 4, suspended: 0, deleted: 2 },
  failed_deliveries: { window_s: 86400, failed: 0, expired: 0 },
  ussps: { version: 3, count: 5 },
  delivery_latency: { window_s: 3600, max_attempts: 10000, log: "complete", attempts: 12, sampled: false, p50_ms: 40, p95_ms: 310 },
};

describe("summary tiles", () => {
  it("no failure is ok; one due again is a warning; one given up is critical", () => {
    expect(failedView(base)).toMatchObject({ total: 0, tone: "ok" });
    expect(failedView({ ...base, failed_deliveries: { window_s: 86400, failed: 2, expired: 0 } })).toMatchObject({ total: 2, tone: "warning" });
    expect(failedView({ ...base, failed_deliveries: { window_s: 86400, failed: 2, expired: 1 } })).toMatchObject({ total: 3, tone: "critical" });
  });

  it("the USSP count is shown from the first version, never before", () => {
    expect(usspsView(base)).toEqual({ published: true, version: 3, count: 5 });
    expect(usspsView({ ...base, ussps: { version: 0, count: 0 } }).published).toBe(false);
  });

  it("the latency has figures only from a log that was read and held an attempt", () => {
    expect(latencyView(base)).toEqual({ kind: "figures", p50Ms: 40, p95Ms: 310, attempts: 12, sampled: false });
    const rest = { window_s: 3600, max_attempts: 10000, log: "complete" as const, attempts: 0, sampled: false };
    expect(latencyView({ ...base, delivery_latency: { ...rest, attempts: 0 } })).toEqual({ kind: "none" });
    expect(latencyView({ ...base, delivery_latency: { ...rest, log: "unavailable", attempts: 0 } })).toEqual({ kind: "unavailable" });
    expect(latencyView({ ...base, delivery_latency: { ...rest, log: "not_configured", attempts: 0 } })).toEqual({ kind: "not_configured" });
  });
});
