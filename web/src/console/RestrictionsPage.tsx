"use client";

// Restrictions: the lifecycle heads with state, window, U-space airspace,
// the ANSP's version and the events timeline (GET
// /v1/console/restrictions), a map preview of the current ones, and, at
// the top, the ANSP's staleness and the expiry job's last run (GET
// /v1/console/status). Read only: the ANSP is the master of every state
// (docs/PLAN.md D5). An API without the restrictions endpoints (404)
// shows "not available", never an empty list.
import { useState } from "react";
import { useT } from "@rootxkit/uspace-ui/i18n";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@rootxkit/uspace-ui/ui";
import type { components } from "../api/types";
import { RESTRICTION_STATES, restrictionBadge } from "./badges";
import { useLoad } from "./context";
import { FeaturePreview } from "./FeaturePreview";
import { ageOnApiClockS } from "./StatusStrip";
import { Loading, ProblemNotice, Section, StateBadge, Time } from "./ui";

type Head = components["schemas"]["RestrictionHead"];
type RestrictionState = Head["state"];

function Events({ head }: { head: Head }) {
  const t = useT();
  if (head.events.length === 0) return <span>—</span>;
  return (
    <ol className="m-0 ps-5 text-xs" data-testid="restriction-events">
      {head.events.map((e, i) => (
        <li key={`${e.at}-${i}`}>
          <Time iso={e.at} /> {t(`cisp.console.restriction.op.${e.op}`)}{" "}
          {t("cisp.console.restrictions.event_detail", { version: e.ansp_version, actor: e.actor })}
        </li>
      ))}
    </ol>
  );
}

export function RestrictionsPage() {
  const t = useT();
  const [state, setState] = useState<RestrictionState | "">("");
  const heads = useLoad(
    async (c) => (await c.GET("/v1/console/restrictions", { params: { query: state === "" ? {} : { state } } })).data ?? null,
    state,
  );
  const status = useLoad(async (c) => (await c.GET("/v1/console/status")).data?.status ?? null, "status");
  const rs = status.data?.restrictions;
  const notAvailable = heads.failure?.status === 404;
  const anspStale = heads.data !== null && Object.hasOwn(heads.data, "cis_publisher_stale_since");
  const anspStaleSince = heads.data?.cis_publisher_stale_since ?? null;
  const current = (heads.data?.restrictions ?? []).filter((h) => h.state === "planned" || h.state === "active").map((h) => h.feature_id);
  const expiryAge = rs?.expiry.last_run_at === undefined || status.data === null ? null : ageOnApiClockS(status.data.now, rs.expiry.last_run_at);

  return (
    <div className="flex flex-col gap-3">
      <h2 className="m-0 text-lg font-bold">{t("cisp.console.nav.restrictions")}</h2>
      <p className="m-0 text-xs text-[var(--us-text-muted)]">{t("cisp.console.restrictions.read_only")}</p>
      {notAvailable ? (
        <p role="alert" data-testid="restrictions-not-available" className="m-0 rounded border border-[var(--us-danger)] p-3 text-sm font-semibold">
          {t("cisp.console.restrictions.not_available")}
        </p>
      ) : (
        <>
          <div className="flex flex-col gap-1 text-sm" data-testid="restrictions-health">
            {anspStale && (
              <p role="alert" className="m-0 font-semibold text-[var(--us-danger)]" data-testid="ansp-stale">
                {anspStaleSince === null ? (
                  t("cisp.console.restrictions.ansp_never")
                ) : (
                  <>
                    {t("cisp.console.restrictions.ansp_stale")} <Time iso={anspStaleSince} />
                  </>
                )}
              </p>
            )}
            {heads.data !== null && !anspStale && <p className="m-0">{t("cisp.console.restrictions.ansp_fresh")}</p>}
            {rs !== undefined && (
              <p
                className={rs.expiry.stale ? "m-0 font-semibold text-[var(--us-danger)]" : "m-0"}
                role={rs.expiry.stale ? "alert" : undefined}
                data-testid="expiry-job"
              >
                {rs.expiry.last_run_at === undefined
                  ? t("cisp.console.restrictions.expiry_never")
                  : t(rs.expiry.stale ? "cisp.console.restrictions.expiry_stale" : "cisp.console.restrictions.expiry_age", {
                      age: expiryAge ?? "—",
                      bound: rs.expiry.stale_after_s,
                    })}
              </p>
            )}
            {status.failure !== null && <ProblemNotice failure={status.failure} />}
            {rs !== undefined && (rs.heartbeat_ref_unknown?.length ?? 0) + (rs.heartbeat_ref_missing?.length ?? 0) > 0 && (
              <p className="m-0 font-semibold">
                {t("cisp.console.restrictions.refs_differ", {
                  unknown: (rs.heartbeat_ref_unknown ?? []).join(", ") || "—",
                  missing: (rs.heartbeat_ref_missing ?? []).join(", ") || "—",
                })}
              </p>
            )}
          </div>
          <label className="flex items-center gap-2 text-sm">
            {t("cisp.console.restrictions.filter")}
            <select
              className="rounded border border-[var(--us-border)] bg-[var(--us-surface)] px-2 py-1"
              value={state}
              onChange={(e) => setState(e.target.value as RestrictionState | "")}
            >
              <option value="">{t("cisp.console.filter.all")}</option>
              {RESTRICTION_STATES.map((s) => (
                <option key={s} value={s}>
                  {t(`cisp.console.restriction.state.${s}`)}
                </option>
              ))}
            </select>
          </label>
          {heads.failure !== null && <ProblemNotice failure={heads.failure} />}
          {heads.loading && heads.data === null && <Loading />}
          {heads.data !== null &&
            (heads.data.restrictions.length === 0 ? (
              <p className="m-0 text-sm">{t("cisp.console.restrictions.none")}</p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t("cisp.console.restrictions.feature")}</TableHead>
                    <TableHead>{t("cisp.console.restrictions.state")}</TableHead>
                    <TableHead>{t("cisp.console.restrictions.window")}</TableHead>
                    <TableHead>{t("cisp.console.restrictions.airspace")}</TableHead>
                    <TableHead>{t("cisp.console.restrictions.ansp")}</TableHead>
                    <TableHead>{t("cisp.console.restrictions.events")}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {heads.data.restrictions.map((h) => (
                    <TableRow key={h.id} data-restriction={h.feature_id}>
                      <TableCell className="font-mono">{h.feature_id}</TableCell>
                      <TableCell>
                        <StateBadge spec={restrictionBadge(h.state)} value={h.state} />
                        {h.ended_by !== undefined && (
                          <span className="ms-1 text-xs">{t(`cisp.console.restriction.ended_by.${h.ended_by}`)}</span>
                        )}
                      </TableCell>
                      <TableCell>
                        <Time iso={h.starts_at} /> – <Time iso={h.ends_at} />
                      </TableCell>
                      <TableCell className="font-mono">{h.uspace_airspace_id}</TableCell>
                      <TableCell>
                        {t("cisp.console.restrictions.ansp_value", { ref: h.ansp_ref, version: h.ansp_version })}
                      </TableCell>
                      <TableCell className="min-w-[18rem] whitespace-normal">
                        <Events head={h} />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ))}
          {current.length > 0 && (
            <Section titleKey="cisp.console.preview.title">
              <FeaturePreview dataset="restrictions" ids={current} />
            </Section>
          )}
        </>
      )}
    </div>
  );
}
