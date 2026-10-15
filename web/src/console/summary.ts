// What the overview's summary tiles show of GET /v1/console/summary
// (docs/PLAN.md §15 Q52): the API's counts as they are, the tone each
// earns, and the latency only when the delivery log was read and held
// an attempt. Nothing is counted here.
import type { components } from "../api/generated/openapi";

export type Summary = components["schemas"]["ConsoleSummary"];

export function subscriptionsView(s: Summary) {
  const x = s.subscriptions;
  return { active: x.active, pending: x.pending_verification, suspended: x.suspended, deleted: x.deleted };
}

/** The failed deliveries: critical when one was given up, a warning while they are due again. */
export function failedView(s: Summary) {
  const { failed, expired } = s.failed_deliveries;
  const tone: "ok" | "warning" | "critical" = expired > 0 ? "critical" : failed > 0 ? "warning" : "ok";
  return { failed, expired, total: failed + expired, tone };
}

/** The USSP list: no count before the first version (a dash, not a zero). */
export function usspsView(s: Summary) {
  return { published: s.ussps.version > 0, version: s.ussps.version, count: s.ussps.count };
}

export type LatencyView =
  | { kind: "figures"; p50Ms: number; p95Ms: number; attempts: number; sampled: boolean }
  | { kind: "none" }
  | { kind: "unavailable" }
  | { kind: "not_configured" };

/** The latency: figures only from a log that was read and held an attempt. */
export function latencyView(s: Summary): LatencyView {
  const l = s.delivery_latency;
  if (l.log === "unavailable") return { kind: "unavailable" };
  if (l.log === "not_configured") return { kind: "not_configured" };
  if (l.attempts === 0 || l.p50_ms === undefined || l.p95_ms === undefined) return { kind: "none" };
  return { kind: "figures", p50Ms: l.p50_ms, p95Ms: l.p95_ms, attempts: l.attempts, sampled: l.sampled };
}
