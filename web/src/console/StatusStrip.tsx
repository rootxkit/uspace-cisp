"use client";

// The status strip, where the operator looks first (WP-11 safety notes;
// hard rule 4): the datasets and their versions, the publishers with
// their heartbeat age and the API's stale flag, every degraded component,
// a disabled mTLS check, a dead expiry job, and the stream. The status is
// GET /v1/console/status, read again every STATUS_POLL_MS; the stream is
// WS /v1/stream (same origin, the session cookie rides the upgrade).
// Ages are measured on the API's clock (the document's `now` against its
// own times), never on the browser's; stale is the API's verdict.
import { useEffect } from "react";
import { fmtTimeUTC, useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { useFeed, useNowMs } from "@rootxkit/uspace-ui/live";
import { FeedStatusBar } from "@rootxkit/uspace-ui/status";
import type { components } from "../api/types";
import { useRuntimeConfig } from "../components/Providers";
import { useConsole, useLoad } from "./context";
import { localTime, ProblemNotice, Time, useInBrowser } from "./ui";

export type ConsoleStatus = components["schemas"]["ConsoleStatus"];
type Status = components["schemas"]["Status"];

/** How often the strip reads the status again. Display-only. */
export const STATUS_POLL_MS = 10_000;
/** How often ages on the strip are redrawn. Display-only. */
const TICK_MS = 1000;

/** Seconds from `from` to `at`, both RFC 3339 on the API's clock; null when either is absent. */
export function ageOnApiClockS(at: string, from: string | undefined): number | null {
  if (from === undefined) return null;
  const a = Date.parse(at);
  const b = Date.parse(from);
  if (!Number.isFinite(a) || !Number.isFinite(b)) return null;
  return Math.max(0, Math.round((a - b) / 1000));
}

/** Every line of the status that says something is wrong, as catalogue keys and values. */
export function warningsOf(s: Status): { key: string; vars: Record<string, string | number> }[] {
  const out: { key: string; vars: Record<string, string | number> }[] = [];
  for (const d of s.degraded) {
    out.push({ key: "cisp.console.status.degraded", vars: { component: d.component, since: d.since, reason: d.reason ?? "" } });
  }
  for (const p of s.publishers) {
    if (!p.stale) continue;
    out.push(
      p.last_heartbeat_at === undefined
        ? { key: "cisp.console.status.publisher_never", vars: { publisher: p.client_id } }
        : { key: "cisp.console.status.publisher_stale", vars: { publisher: p.client_id, since: p.stale_since ?? p.last_heartbeat_at } },
    );
  }
  if (s.mtls_mode === "off") out.push({ key: "cisp.console.status.mtls_off", vars: {} });
  if (s.restrictions?.expiry.stale === true) {
    out.push({
      key: "cisp.console.status.expiry_stale",
      vars: { last: s.restrictions.expiry.last_run_at ?? "", bound: s.restrictions.expiry.stale_after_s },
    });
  }
  return out;
}

/** The vars with their times (`since`, `last`) as the viewer reads them. */
export function timesShown(
  vars: Record<string, string | number>,
  show: (iso: string) => string,
): Record<string, string | number> {
  const out = { ...vars };
  for (const k of ["since", "last"]) {
    const v = out[k];
    if (typeof v === "string") out[k] = v === "" ? "—" : show(v);
  }
  return out;
}

export function StatusStrip() {
  const t = useT();
  const { lang } = useLang();
  const cfg = useRuntimeConfig();
  const { me } = useConsole();
  const status = useLoad(async (c) => (await c.GET("/v1/console/status")).data ?? null, "status");
  const { reload } = status;
  useEffect(() => {
    const id = setInterval(reload, STATUS_POLL_MS);
    return () => clearInterval(id);
  }, [reload]);
  const nowMs = useNowMs(TICK_MS);
  const browser = useInBrowser();
  const feed = useFeed({ url: `${cfg.apiBaseUrl}/v1/stream`, onFrame: () => undefined });
  const s = status.data?.status ?? null;

  return (
    <section
      aria-label={t("cisp.console.status.label")}
      data-testid="status-strip"
      className="flex flex-col gap-1 border-b border-[var(--us-border)] bg-[var(--us-surface-sunken)] px-4 py-2 text-xs"
    >
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
        {me !== null && <FeedStatusBar status={feed} nowMs={nowMs} />}
        {s !== null && (
          <>
            <span className="text-[var(--us-text-muted)]">
              {t("cisp.console.status.as_of")} <Time iso={s.now} />
            </span>
            <ul aria-label={t("cisp.console.status.datasets")} className="m-0 flex flex-wrap gap-3 p-0">
              {s.datasets.map((d) => (
                <li key={d.dataset} className="list-none" data-dataset={d.dataset}>
                  <span className="font-semibold">{t(`cisp.console.dataset.${d.dataset}`)}</span>{" "}
                  {t("cisp.console.status.version", { version: d.current_version })}
                </li>
              ))}
            </ul>
            <ul aria-label={t("cisp.console.status.publishers")} className="m-0 flex flex-wrap gap-3 p-0">
              {s.publishers.map((p) => {
                const age = ageOnApiClockS(s.now, p.last_heartbeat_at);
                return (
                  <li key={p.client_id} className="list-none" data-publisher={p.client_id} data-stale={p.stale}>
                    <span className="font-semibold">{p.client_id}</span>{" "}
                    {age === null
                      ? t("cisp.console.status.heartbeat_never")
                      : t("cisp.console.status.heartbeat_age", { age: age.toLocaleString(lang) })}
                    {p.stale && <span className="ms-1 font-semibold text-[var(--us-danger)]">{t("cisp.console.status.stale")}</span>}
                  </li>
                );
              })}
            </ul>
          </>
        )}
      </div>
      {s !== null &&
        warningsOf(s).map((w) => (
          <p key={`${w.key}-${JSON.stringify(w.vars)}`} role="alert" className="m-0 font-semibold text-[var(--us-danger)]">
            {t(w.key, timesShown(w.vars, (iso) => (browser ? localTime(iso, lang) : null) ?? fmtTimeUTC(iso, lang)))}
          </p>
        ))}
      {status.failure !== null && status.failure.status !== 401 && (
        <div>
          <p className="m-0 font-semibold text-[var(--us-danger)]">{t("cisp.console.status.unavailable")}</p>
          <ProblemNotice failure={status.failure} />
        </div>
      )}
    </section>
  );
}
