"use client";

import { useEffect, useMemo, useState } from "react";
import { fmtTimeUTC, useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { browserClient } from "../api/client";
import type { components } from "../api/types";
import { PageHeader } from "@rootxkit/uspace-ui/ui";
import { useRuntimeConfig } from "../components/Providers";

type PublicUsspList = components["schemas"]["PublicUsspList"];

type Load =
  | { kind: "loading" }
  | { kind: "served"; list: PublicUsspList; stale: boolean }
  | { kind: "unavailable"; since: string };

/** The national USSP list as the CISP serves it publicly (/public/v1/ussp_list). */
export function UsspList() {
  const t = useT();
  const { lang } = useLang();
  const cfg = useRuntimeConfig();
  const client = useMemo(() => browserClient(cfg.apiBaseUrl, () => lang), [cfg.apiBaseUrl, lang]);
  const [load, setLoad] = useState<Load>({ kind: "loading" });
  useEffect(() => {
    let cancelled = false;
    client
      .GET("/public/v1/{dataset}", { params: { path: { dataset: "ussp_list" } }, cache: "no-cache" })
      .then(({ data, response }) => {
        if (cancelled) return;
        const list = data as PublicUsspList | undefined;
        if (list === undefined || !Array.isArray(list.ussps)) throw new Error("not a USSP list");
        setLoad({ kind: "served", list, stale: response.headers.get("X-CIS-Stale") === "true" });
      })
      .catch(() => {
        if (!cancelled) setLoad({ kind: "unavailable", since: new Date().toISOString() });
      });
    return () => {
      cancelled = true;
    };
  }, [client]);

  return (
    <div className="mx-auto flex w-full max-w-[96rem] flex-col gap-4 p-4 sm:p-5">
      <PageHeader title={t("cisp.ussps.title")} />
      {load.kind === "loading" && (
        <p role="status" className="m-0 text-sm text-muted-foreground">
          {t("cisp.ussps.loading")}
        </p>
      )}
      {load.kind === "unavailable" && (
        <p role="alert" className="m-0 font-bold text-[var(--us-danger)]">
          {t("cisp.banner.unavailable_since", { since: fmtTimeUTC(load.since, lang, { seconds: true }) })}
        </p>
      )}
      {load.kind === "served" && (
        <>
          <p className="m-0 text-sm text-muted-foreground" data-dataset="ussp_list">
            {t("cisp.banner.as_of", { version: String(load.list.cis_version), updated: fmtTimeUTC(load.list.cis_updated_at, lang) })}
            {load.stale && <span className="ms-2 text-[var(--us-danger)]">{t("cisp.banner.stale_snapshot")}</span>}
          </p>
          {load.list.ussps.length === 0 && <p className="m-0">{t("cisp.ussps.none")}</p>}
          <ul className="m-0 grid list-none gap-4 p-0 xl:grid-cols-2">
            {load.list.ussps.map((u) => (
              <li key={u.ussp_id} data-ussp={u.ussp_id} className="rounded-panel border border-border bg-card p-4 text-card-foreground shadow-panel">
                <h2 className="m-0 mb-3 flex flex-wrap items-baseline gap-x-2 text-base font-bold">
                  {u.name} <span className="font-mono text-sm font-normal text-muted-foreground">{u.ussp_id}</span>
                </h2>
                <dl className="m-0 grid grid-cols-1 gap-x-3 gap-y-1 text-sm sm:grid-cols-[10rem_1fr] [&_dd]:m-0 [&_dt]:text-muted-foreground">
                  <dt>{t("cisp.ussps.status")}</dt>
                  <dd>{t(`cisp.ussps.status.${u.status}`)}</dd>
                  <dt>{t("cisp.ussps.services")}</dt>
                  <dd>{u.services.map((s) => t(`cisp.ussps.service.${s}`)).join(", ")}</dd>
                  <dt>{t("cisp.ussps.validity")}</dt>
                  <dd>
                    {t("cisp.panel.window_value", { from: fmtTimeUTC(u.valid_from, lang), to: fmtTimeUTC(u.valid_until, lang) })}
                  </dd>
                  <dt>{t("cisp.ussps.limitations")}</dt>
                  <dd>
                    {u.certification_limitations.length === 0 ? (
                      t("cisp.ussps.no_limitations")
                    ) : (
                      <ul>
                        {u.certification_limitations.map((l, i) => (
                          <li key={i}>{l}</li>
                        ))}
                      </ul>
                    )}
                  </dd>
                  {(u.contact.email !== undefined || u.contact.phone !== undefined || u.contact.url !== undefined) && (
                    <>
                      <dt>{t("cisp.ussps.contact")}</dt>
                      <dd>{[u.contact.email, u.contact.phone, u.contact.url].filter((x) => x !== undefined).join(" · ")}</dd>
                    </>
                  )}
                  <dt>{t("cisp.ussps.terms")}</dt>
                  <dd>
                    <a href={u.terms_url} rel="noopener noreferrer" className="underline">
                      {t("cisp.ussps.terms_link")}
                    </a>
                  </dd>
                </dl>
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}
