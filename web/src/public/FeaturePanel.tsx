"use client";

import { useEffect, useRef, type ReactNode } from "react";
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
    <div className="grid grid-cols-[9rem_1fr] gap-2 py-1">
      <dt className="text-[var(--us-text-muted)]">{label}</dt>
      <dd>{children}</dd>
    </div>
  );
}

/**
 * The ED-318 properties of one feature as published: limits in their
 * own reference and unit, the applicability schedule as written, the
 * zone authorities, the restriction's window and state, and the CISP's
 * verdict at the chosen instant (with why an unknown one is drawn).
 */
export function FeaturePanel({ feature, onClose }: { feature: MapFeature; onClose(): void }) {
  const t = useT();
  const { lang } = useLang();
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    heading.current?.focus();
  }, [feature.id]);
  // Escape closes the panel wherever the focus is.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);
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
    <section
      aria-labelledby={`panel-${feature.id}`}
      data-panel={feature.id}
      className="rounded border border-[var(--us-border)] bg-[var(--us-surface-raised)] p-3 text-sm"
    >
      <div className="flex items-start justify-between gap-2">
        <h2 id={`panel-${feature.id}`} ref={heading} tabIndex={-1} className="text-base font-bold">
          <span className="font-mono">{feature.id}</span> {feature.view.name ?? ""}
        </h2>
        <button type="button" onClick={onClose} aria-label={t("cisp.panel.close")} className="rounded px-2">
          <span aria-hidden="true">{"×"}</span>
        </button>
      </div>
      <dl>
        <Row label={t("cisp.panel.type")}>{t(`zone.type.${feature.view.type}`)}</Row>
        {reasons.length > 0 && <Row label={t("cisp.panel.reason")}>{reasons.join(", ")}</Row>}
        {otherReason !== null && <Row label={t("cisp.panel.other_reason")}>{otherReason}</Row>}
        {feature.view.message !== null && <Row label={t("cisp.panel.message")}>{feature.view.message}</Row>}
        {conditions !== null && <Row label={t("cisp.panel.conditions")}>{conditions}</Row>}
        <Row label={t("cisp.panel.limits")}>
          <ul data-limits>
            {layers.map((l, i) => (
              <li key={i}>{fmtLayer(l, lang, t)}</li>
            ))}
          </ul>
        </Row>
        {circle !== null && (
          <Row label={t("cisp.panel.shape")}>{t("cisp.panel.circle", { radius: fmtNumber(circle.radiusM, lang) })}</Row>
        )}
        <Row label={t("cisp.panel.applicability")}>
          <ul data-schedule>
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
            <dl>
              {authorityRows(a, lang, t).map((r) => (
                <div key={r.label} className="flex gap-2">
                  <dt className="text-[var(--us-text-muted)]">{r.label}</dt>
                  <dd>{r.value}</dd>
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
    </section>
  );
}
