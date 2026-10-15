"use client";

// The overview's second row of key figures, from GET /v1/console/summary
// (docs/PLAN.md §15 Q52): the subscriptions by state, the deliveries
// that failed in the last 24 h, the USSPs of the current list and the
// delivery latency over the last hour. The API counts; the page shows
// its numbers and its windows, and an unknown figure is a dash, never a
// zero.
import { useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { KpiRow, StatTile, type StatTileStatus } from "@rootxkit/uspace-ui/ui";
import { AccountsIcon, HealthIcon, SourceIcon, SubscriptionsIcon } from "../components/icons";
import { useLoad } from "./context";
import { failedView, latencyView, subscriptionsView, usspsView, type Summary } from "./summary";
import { ProblemNotice } from "./ui";

export function SummaryTiles() {
  const t = useT();
  const { lang } = useLang();
  const sum = useLoad<Summary | null>(async (c) => (await c.GET("/v1/console/summary")).data ?? null, "overview-summary");
  const s = sum.data;
  if (s === null) return sum.failure === null ? null : <ProblemNotice failure={sum.failure} />;

  const n = (v: number) => v.toLocaleString(lang);
  const hours = (windowS: number) => n(Math.round(windowS / 3600));
  const subs = subscriptionsView(s);
  const failed = failedView(s);
  const ussps = usspsView(s);
  const lat = latencyView(s);

  const failedStatus: StatTileStatus =
    failed.tone === "ok"
      ? { tone: "ok", label: t("cisp.console.kpi.failed_ok") }
      : failed.tone === "critical"
        ? { tone: "critical", label: t("cisp.console.kpi.failed_expired", { count: n(failed.expired) }) }
        : { tone: "warning", label: t("cisp.console.kpi.failed_retrying", { count: n(failed.failed) }) };

  let latency: { value: string | null; unit?: string; hint?: string; status?: StatTileStatus };
  switch (lat.kind) {
    case "figures":
      latency = {
        value: `${n(lat.p50Ms)} / ${n(lat.p95Ms)}`,
        unit: t("cisp.console.kpi.latency_unit"),
        hint: t(lat.sampled ? "cisp.console.kpi.latency_sampled" : "cisp.console.kpi.latency_hint", { count: n(lat.attempts) }),
      };
      break;
    case "none":
      latency = { value: null, hint: t("cisp.console.kpi.latency_none") };
      break;
    case "unavailable":
      latency = { value: null, status: { tone: "critical", label: t("cisp.console.kpi.latency_unavailable") } };
      break;
    case "not_configured":
      latency = { value: null, status: { tone: "warning", label: t("cisp.console.kpi.latency_not_configured") } };
      break;
  }

  return (
    <div data-testid="overview-summary" className="grid min-w-0 gap-3">
      {sum.failure !== null && <ProblemNotice failure={sum.failure} />}
      <KpiRow label={t("cisp.console.overview.kpis_delivery")}>
        <StatTile
          icon={<SubscriptionsIcon />}
          label={t("cisp.console.kpi.subscriptions")}
          value={n(subs.active)}
          hint={t("cisp.console.kpi.subscriptions_hint", {
            pending: n(subs.pending),
            suspended: n(subs.suspended),
            deleted: n(subs.deleted),
          })}
          status={
            subs.suspended === 0
              ? { tone: "ok", label: t("cisp.console.kpi.subscriptions_ok") }
              : { tone: "warning", label: t("cisp.console.kpi.subscriptions_suspended", { count: n(subs.suspended) }) }
          }
        />
        <StatTile
          icon={<HealthIcon />}
          label={t("cisp.console.kpi.failed", { hours: hours(s.failed_deliveries.window_s) })}
          value={n(failed.total)}
          hint={t("cisp.console.kpi.failed_hint", { failed: n(failed.failed), expired: n(failed.expired) })}
          status={failedStatus}
        />
        <StatTile
          icon={<AccountsIcon />}
          label={t("cisp.console.kpi.ussps")}
          value={ussps.published ? n(ussps.count) : null}
          {...(ussps.published
            ? { hint: t("cisp.console.kpi.ussps_version", { version: n(ussps.version) }) }
            : { status: { tone: "warning", label: t("cisp.console.kpi.ussps_none") } })}
        />
        <StatTile
          icon={<SourceIcon />}
          label={t("cisp.console.kpi.latency", { hours: hours(s.delivery_latency.window_s) })}
          value={latency.value}
          {...(latency.unit === undefined ? {} : { unit: latency.unit })}
          {...(latency.hint === undefined ? {} : { hint: latency.hint })}
          {...(latency.status === undefined ? {} : { status: latency.status })}
        />
      </KpiRow>
    </div>
  );
}
