"use client";

// The console's first page, the operations dashboard, from the status
// document (GET /v1/console/status), the summary (GET
// /v1/console/summary) and the public read of the current versions for
// the map: two rows of the service's key figures as the API counts them
// (the second, subscribers and deliveries, loads on its own and fails on
// its own), the map of what is published now, what needs attention,
// every dataset's current version, every publisher's heartbeat, the
// health of the API's components and safeguards, and this API instance's
// counters since it started (collapsed: they are technical, worded where
// the console knows them). The page shows what the API says and decides
// nothing: stale is the API's verdict, ages are on its clock, and every
// time is in UTC.
import Link from "next/link";
import { useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { EmptyState, KpiRow, Panel, StatTile, StatusBadge } from "@rootxkit/uspace-ui/ui";
import { CheckIcon, HealthIcon, LockIcon, PublicationsIcon, RestrictionsIcon, SourceIcon } from "../components/icons";
import { useLoad } from "./context";
import { ConsoleHeader } from "./header";
import { componentLabel, countersShown } from "./labels";
import { OverviewMap } from "./OverviewMap";
import { ageOnApiClockS, componentShown, timesShown, warningsOf } from "./StatusStrip";
import { SummaryTiles } from "./SummaryTiles";
import { Loading, ProblemNotice, Time, useUtcTime } from "./ui";

/** This API instance's counters, behind a disclosure: grouped by component, each by its label where known, its code in the tooltip. */
function TechnicalCounters({ counters }: { counters: Record<string, number> }) {
  const t = useT();
  const { lang } = useLang();
  const groups = countersShown(t, counters);
  const total = groups.reduce((n, g) => n + g.counters.length, 0);
  return (
    <details className="group rounded-md border border-border" data-testid="technical-counters">
      <summary className="cursor-pointer px-3 py-2 text-xs font-semibold text-muted-foreground hover:text-foreground">
        {t("cisp.console.overview.counters_technical", { count: total })}
      </summary>
      <div className="grid gap-2 border-t border-border px-3 py-2">
        <p className="m-0 text-xs text-muted-foreground">{t("cisp.console.overview.counters")}</p>
        {total === 0 ? (
          <p className="m-0 text-xs">{t("cisp.console.overview.no_counters")}</p>
        ) : (
          groups.map((g) => (
            <div key={g.component} data-component={g.component}>
              <h3 className="m-0 mb-0.5 text-xs font-semibold" title={g.component}>
                {g.label}
              </h3>
              <ul className="m-0 grid list-none gap-0.5 p-0 text-xs">
                {g.counters.map((c) => (
                  <li key={c.key} className="flex justify-between gap-2" title={c.key} data-counter={c.key}>
                    <span className={c.label === null ? "min-w-0 truncate font-mono" : "min-w-0"}>{c.label ?? c.key}</span>
                    <span className="tabular-nums">{c.value.toLocaleString(lang)}</span>
                  </li>
                ))}
              </ul>
            </div>
          ))
        )}
      </div>
    </details>
  );
}

export function OverviewPage() {
  const t = useT();
  const { lang } = useLang();
  const st = useLoad(async (c) => (await c.GET("/v1/console/status")).data ?? null, "overview");
  const s = st.data?.status ?? null;
  const shown = useUtcTime();
  const stale = s?.publishers.filter((p) => p.stale).length ?? 0;
  const published = s?.datasets.filter((d) => d.current_version > 0).length ?? 0;
  const warnings = s === null ? [] : warningsOf(s);

  return (
    <>
      <ConsoleHeader
        title={t("cisp.console.nav.overview")}
        description={t("cisp.console.page.overview")}
        {...(s === null
          ? {}
          : {
              meta: <span className="text-xs text-muted-foreground">{t("cisp.console.overview.as_of", { time: shown(s.now) })}</span>,
            })}
      />
      {st.failure !== null && <ProblemNotice failure={st.failure} />}
      {st.loading && st.data === null && <Loading />}
      {s !== null && (
        <>
          <KpiRow label={t("cisp.console.overview.kpis")}>
            <StatTile
              icon={<RestrictionsIcon />}
              label={t("cisp.console.kpi.restrictions")}
              value={s.restrictions === undefined ? null : s.restrictions.active.toLocaleString(lang)}
              hint={t("cisp.console.kpi.restrictions_hint")}
            />
            <StatTile
              icon={<SourceIcon />}
              label={t("cisp.console.kpi.publishers")}
              value={s.publishers.length.toLocaleString(lang)}
              status={
                stale === 0
                  ? { tone: "ok", label: t("cisp.console.kpi.publishers_ok") }
                  : { tone: "warning", label: t("cisp.console.kpi.publishers_stale", { count: stale }) }
              }
            />
            <StatTile
              icon={<PublicationsIcon />}
              label={t("cisp.console.kpi.datasets")}
              value={published.toLocaleString(lang)}
              unit={t("cisp.console.kpi.datasets_unit", { total: s.datasets.length })}
              status={
                published === s.datasets.length
                  ? { tone: "ok", label: t("cisp.console.kpi.datasets_ok") }
                  : { tone: "warning", label: t("cisp.console.kpi.datasets_missing", { count: s.datasets.length - published }) }
              }
            />
            <StatTile
              icon={<HealthIcon />}
              label={t("cisp.console.kpi.degraded")}
              value={s.degraded.length.toLocaleString(lang)}
              status={
                s.degraded.length === 0
                  ? { tone: "ok", label: t("cisp.console.kpi.degraded_ok") }
                  : { tone: "critical", label: t("cisp.console.kpi.degraded_bad") }
              }
            />
          </KpiRow>
          <SummaryTiles />

          <div className="grid min-w-0 gap-5 xl:grid-cols-[minmax(0,1fr)_26rem]">
            <OverviewMap />
            <Panel
              title={t("cisp.console.overview.attention_title")}
              description={t("cisp.console.overview.attention_description")}
              actions={
                warnings.length === 0 ? (
                  <StatusBadge tone="ok">{t("cisp.console.kpi.degraded_ok")}</StatusBadge>
                ) : (
                  <StatusBadge tone="critical">{t("cisp.console.overview.attention_count", { count: warnings.length })}</StatusBadge>
                )
              }
            >
              {warnings.length === 0 ? (
                <EmptyState
                  icon={<CheckIcon />}
                  title={t("cisp.console.overview.attention_none")}
                  description={t("cisp.console.overview.attention_none_detail")}
                />
              ) : (
                <ul className="m-0 grid list-none gap-2 p-0" data-testid="overview-attention">
                  {warnings.map((w) => (
                    <li
                      key={`${w.key}-${JSON.stringify(w.vars)}`}
                      className="rounded-md border border-[var(--us-danger)] px-3 py-2 text-sm font-semibold text-[var(--us-danger)]"
                    >
                      {t(w.key, componentShown(t, timesShown(w.vars, shown)))}
                    </li>
                  ))}
                </ul>
              )}
            </Panel>
          </div>

          <div className="grid min-w-0 items-start gap-5 lg:grid-cols-2 xl:grid-cols-3">
            <Panel title={t("cisp.console.status.datasets")} description={t("cisp.console.overview.datasets_description")}>
              <ul className="m-0 grid list-none gap-0 p-0">
                {s.datasets.map((d) => (
                  <li
                    key={d.dataset}
                    className="grid gap-1 border-b border-border py-2 text-sm last:border-b-0"
                  >
                    <span className="flex w-full flex-wrap items-center justify-between gap-2">
                      <Link
                        href={`/${lang}/console/publications?dataset=${encodeURIComponent(d.dataset)}`}
                        aria-label={t("cisp.console.overview.open_dataset", { dataset: t(`cisp.console.dataset.${d.dataset}`) })}
                        className="font-semibold underline underline-offset-4"
                      >
                        {t(`cisp.console.dataset.${d.dataset}`)}
                      </Link>
                      <StatusBadge tone={d.current_version > 0 ? "info" : "warning"} variant="outline">
                        {t("cisp.console.status.version", { version: d.current_version })}
                      </StatusBadge>
                    </span>
                    <span className="text-xs text-muted-foreground">
                      {t("cisp.console.overview.updated")}: <Time iso={d.updated_at} />
                    </span>
                  </li>
                ))}
              </ul>
            </Panel>

            <Panel title={t("cisp.console.status.publishers")} description={t("cisp.console.overview.publishers_description")}>
              <ul className="m-0 grid list-none gap-0 p-0">
                {s.publishers.map((p) => {
                  const age = ageOnApiClockS(s.now, p.last_heartbeat_at);
                  return (
                    <li key={p.client_id} className="grid gap-1 border-b border-border py-2 text-sm last:border-b-0">
                      <span className="flex flex-wrap items-center justify-between gap-2">
                        <span className="font-mono font-semibold">{p.client_id}</span>
                        <StatusBadge tone={p.stale ? "critical" : "ok"}>
                          {p.stale ? t("cisp.console.status.stale") : t("cisp.console.overview.publisher_ok")}
                        </StatusBadge>
                      </span>
                      <span className="flex flex-wrap gap-x-3 text-xs text-muted-foreground">
                        <span>
                          {age === null
                            ? t("cisp.console.status.heartbeat_never")
                            : t("cisp.console.status.heartbeat_age", { age: age.toLocaleString(lang) })}
                        </span>
                        <span>
                          {t("cisp.console.overview.last_publication")}: <Time iso={p.last_publication_at} />
                        </span>
                      </span>
                    </li>
                  );
                })}
              </ul>
            </Panel>

            <Panel title={t("cisp.console.overview.health_title")} description={t("cisp.console.overview.health_description")}>
              <div className="grid gap-3 text-sm">
                {s.degraded.length === 0 ? (
                  <p className="m-0 flex flex-wrap items-center justify-between gap-2">
                    <span>{t("cisp.console.overview.none_degraded")}</span>
                    <StatusBadge tone="ok">{t("cisp.console.overview.component_ok")}</StatusBadge>
                  </p>
                ) : (
                  <ul className="m-0 grid list-none gap-1 p-0">
                    {s.degraded.map((d) => (
                      <li key={d.component} className="font-semibold text-[var(--us-danger)]" data-component={d.component}>
                        <span title={d.component}>{componentLabel(t, d.component)}</span> <Time iso={d.since} /> {d.reason ?? ""}
                      </li>
                    ))}
                  </ul>
                )}
                {s.mtls_mode !== undefined && (
                  <p className="m-0 flex flex-wrap items-center justify-between gap-2" data-testid="overview-mtls">
                    <span className="flex items-center gap-2">
                      <LockIcon />
                      <span>
                        {t("cisp.console.kpi.mtls")}:{" "}
                        <span className="font-semibold">
                          {t(s.mtls_mode === "off" ? "cisp.console.kpi.mtls_off" : "cisp.console.kpi.mtls_required")}
                        </span>
                      </span>
                    </span>
                    <StatusBadge tone={s.mtls_mode === "off" ? "critical" : "ok"}>
                      {t(s.mtls_mode === "off" ? "cisp.console.kpi.mtls_bad" : "cisp.console.kpi.mtls_ok")}
                    </StatusBadge>
                  </p>
                )}
                <TechnicalCounters counters={st.data?.counters ?? {}} />
              </div>
            </Panel>
          </div>
        </>
      )}
    </>
  );
}
