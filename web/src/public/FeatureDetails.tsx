"use client";

import type { ReactNode } from "react";
import { fmtTimeUTC, useLang, useT } from "@rootxkit/uspace-ui/i18n";
import type { MapFeature } from "../map/adapt";
import {
  applicabilityOf,
  authorityRows,
  circleOf,
  fmtApplicability,
  fmtApplicabilityVerdict,
  fmtLayer,
  fmtNumber,
  layersOf,
  localText,
  obj,
} from "./format";

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[7.5rem_minmax(0,1fr)] gap-2 py-1">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="m-0 min-w-0 break-words">{children}</dd>
    </div>
  );
}

/**
 * The ED-318 properties of one feature as published: its identifier and
 * type, limits in their own reference and unit, the applicability
 * schedule as written, the zone authorities, the restriction's window and
 * state, and the CISP's verdict at the chosen instant (with why an
 * unknown one is drawn). Shown inside the feature's row of the list when
 * the row is expanded.
 */
export function FeatureDetails({ feature, id }: { feature: MapFeature; id: string }) {
  const t = useT();
  const { lang } = useLang();
  const p = obj(feature.raw["properties"]) ?? {};
  const restriction = obj(obj(p["extendedProperties"])?.["cis_restriction"]);
  const verdict = applicabilityOf(p);
  const circle = circleOf(feature.raw["geometry"]);
  const layers = layersOf(feature.raw["geometry"]);
  const reasons = Array.isArray(p["reason"]) ? p["reason"].filter((r): r is string => typeof r === "string") : [];
  const authorities: unknown[] = Array.isArray(p["zoneAuthority"]) ? p["zoneAuthority"] : [];
  const otherReason = localText(p["otherReasonInfo"], lang);
  const conditions = typeof p["restrictionConditions"] === "string" ? p["restrictionConditions"] : null;
  return (
    <div id={id} data-panel={feature.id} className="mx-2 mb-2 rounded-md border border-border bg-surface-sunken px-3 py-2 text-xs">
      <dl className="m-0">
        <Row label={t("cisp.panel.identifier")}>
          <span className="font-mono">{feature.id}</span>
        </Row>
        <Row label={t("cisp.panel.type")}>{t(`zone.type.${feature.view.type}`)}</Row>
        {reasons.length > 0 && <Row label={t("cisp.panel.reason")}>{reasons.join(", ")}</Row>}
        {otherReason !== null && <Row label={t("cisp.panel.other_reason")}>{otherReason}</Row>}
        {feature.view.message !== null && <Row label={t("cisp.panel.message")}>{feature.view.message}</Row>}
        {conditions !== null && <Row label={t("cisp.panel.conditions")}>{conditions}</Row>}
        <Row label={t("cisp.panel.limits")}>
          <ul data-limits className="m-0 list-none p-0">
            {layers.map((l, i) => (
              <li key={i}>{fmtLayer(l, lang, t)}</li>
            ))}
          </ul>
        </Row>
        {circle !== null && (
          <Row label={t("cisp.panel.shape")}>
            {t(feature.drawnFromOutline ? "cisp.panel.circle_drawn" : "cisp.panel.circle", {
              radius: fmtNumber(circle.radiusM, lang),
            })}
          </Row>
        )}
        <Row label={t("cisp.panel.applicability")}>
          <ul data-schedule className="m-0 list-none p-0">
            {fmtApplicability(p["limitedApplicability"], t).map((line, i) => (
              <li key={i}>{line}</li>
            ))}
          </ul>
        </Row>
        <Row label={t("cisp.panel.verdict")}>
          <span data-verdict={verdict ?? "unstated"}>{fmtApplicabilityVerdict(verdict, t)}</span>
        </Row>
        {restriction !== null && (
          <>
            <Row label={t("cisp.panel.restriction_state")}>
              {feature.view.restrictionState === null
                ? t("restriction.state.unstated")
                : t(`restriction.state.${feature.view.restrictionState}`)}
            </Row>
            <Row label={t("cisp.panel.window")}>
              {t("cisp.panel.window_value", {
                from: fmtTimeUTC(feature.view.startsAt ?? null, lang),
                to: fmtTimeUTC(feature.view.endsAt ?? null, lang),
              })}
            </Row>
          </>
        )}
        {authorities.map((a, i) => (
          <Row key={i} label={t("cisp.panel.authority")}>
            <dl className="m-0">
              {authorityRows(a, lang, t).map((r) => (
                <div key={r.label} className="flex flex-wrap gap-x-2">
                  <dt className="text-muted-foreground">{r.label}</dt>
                  <dd className="m-0">{r.value}</dd>
                </div>
              ))}
            </dl>
          </Row>
        ))}
        <Row label={t("cisp.panel.version")}>
          {t("cisp.panel.version_value", {
            version: feature.view.version ?? "—",
            updated: fmtTimeUTC(feature.view.updatedAt, lang),
          })}
        </Row>
      </dl>
    </div>
  );
}
