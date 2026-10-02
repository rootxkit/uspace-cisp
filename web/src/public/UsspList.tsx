"use client";

import { useEffect, useMemo, useState } from "react";
import { fmtTimeUTC, useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { browserClient } from "../api/client";
import type { components } from "../api/types";
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
    <div className="flex flex-col gap-4 p-4">
      <h2 className="text-lg font-bold">{t("cisp.ussps.title")}</h2>
      {load.kind === "loading" && <p role="status">{t("cisp.ussps.loading")}</p>}
      {load.kind === "unavailable" && (
        <p role="alert" className="font-bold text-[var(--us-danger)]">
          {t("cisp.banner.unavailable_since", { since: fmtTimeUTC(load.since, lang, { seconds: true }) })}
        </p>
      )}
      {load.kind === "served" && (
        <>
          <p className="text-sm text-[var(--us-text-muted)]" data-dataset="ussp_list">
            {t("cisp.banner.as_of", { version: String(load.list.cis_version), updated: fmtTimeUTC(load.list.cis_updated_at, lang) })}
            {load.stale && <span className="ms-2 text-[var(--us-danger)]">{t("cisp.banner.stale_snapshot")}</span>}
          </p>
          {load.list.ussps.length === 0 && <p>{t("cisp.ussps.none")}</p>}
          <ul className="flex flex-col gap-3">
            {load.list.ussps.map((u) => (
              <li key={u.ussp_id} data-ussp={u.ussp_id} className="rounded border border-[var(--us-border)] p-3">
                <h3 className="font-bold">
                  {u.name} <span className="font-mono text-sm">{u.ussp_id}</span>
                </h3>
                <dl className="grid grid-cols-[10rem_1fr] gap-x-2 gap-y-1 text-sm">
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
