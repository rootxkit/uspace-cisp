"use client";

import { useEffect, useId, useState } from "react";
import { useT } from "@rootxkit/uspace-ui/i18n";
import type { MapFeature } from "../map/adapt";
import { MAP_DATASETS, type MapDataset } from "./banner";
import { FeatureDetails } from "./FeatureDetails";
import { applicabilityOf, circleOf } from "./format";

/**
 * Every feature the map was given, as an accordion: one section per
 * layer (zones, U-space airspace, dynamic restrictions) that expands and
 * collapses and shows its count, and in it one row per feature that
 * expands to the feature's details. The keyboard's way to every zone, and
 * the list that says a zone is there when the map cannot draw it (a
 * circle the API sent as a point, a browser without WebGL).
 *
 * The expanded row is the selected feature: expanding a row selects it
 * (the map highlights it), a click on the map expands its row, and
 * collapsing it, or Escape, clears the selection. Each control is a
 * button with aria-expanded and aria-controls (WAI-ARIA APG disclosure).
 */
export function FeatureList(props: {
  features: Record<MapDataset, MapFeature[]>;
  undrawable: Record<MapDataset, number>;
  visible: Record<MapDataset, boolean>;
  /** The datasets the API answered 404 no_version for: nothing published yet. */
  empty: Record<MapDataset, boolean>;
  selectedId: string | null;
  onSelect(id: string | null): void;
}) {
  const t = useT();
  const base = useId();
  const { features, selectedId, onSelect } = props;
  const [open, setOpen] = useState<Record<MapDataset, boolean>>({
    zones: true,
    uspace_airspace: true,
    restrictions: true,
  });

  // The section of the selected feature is open whatever its toggle says
  // (a click on the map opens it); collapsing it clears the selection.
  const selectedIn = selectedId === null ? undefined : MAP_DATASETS.find((x) => features[x].some((f) => f.id === selectedId));

  // A feature selected on the map comes into view in the list.
  useEffect(() => {
    if (selectedId === null) return;
    document.querySelector(`[data-feature="${CSS.escape(selectedId)}"]`)?.scrollIntoView({ block: "nearest" });
  }, [selectedId]);

  // Escape collapses the expanded row wherever the focus is.
  useEffect(() => {
    if (selectedId === null) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onSelect(null);
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [selectedId, onSelect]);

  return (
    <div className="flex flex-col divide-y divide-border">
      {MAP_DATASETS.filter((d) => props.visible[d]).map((d) => {
        const sectionId = `${base}-${d}`;
        const isOpen = open[d] || selectedIn === d;
        const count = features[d].length;
        return (
          <section
            key={d}
            aria-labelledby={`${sectionId}-h`}
            data-layer={d}
            data-open={isOpen ? "true" : "false"}
            className="py-1.5 first:pt-0 last:pb-0"
          >
            <h3 id={`${sectionId}-h`} className="m-0 text-sm font-semibold">
              <button
                type="button"
                aria-expanded={isOpen}
                aria-controls={`${sectionId}-body`}
                data-section-toggle={d}
                className="flex w-full items-center gap-2 rounded-md px-1 py-1.5 text-start transition-colors hover:bg-hover focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
                onClick={() => {
                  setOpen((prev) => ({ ...prev, [d]: !isOpen }));
                  if (isOpen && selectedIn === d) onSelect(null);
                }}
              >
                <Chevron open={isOpen} />
                <span className="min-w-0 flex-1">{t(`cisp.dataset.${d}`)}</span>
                <span data-count className="rounded-full bg-surface-sunken px-2 text-xs tabular-nums">
                  {count}
                </span>
              </button>
            </h3>
            <div id={`${sectionId}-body`} hidden={!isOpen} className="pt-1">
              {count === 0 && (
                <p
                  className="m-0 px-1 text-xs text-[var(--us-text-muted)]"
                  data-empty-note={props.empty[d] ? "none-yet" : "none-in-view"}
                >
                  {props.empty[d] ? t(`cisp.list.none_yet.${d}`) : t("cisp.list.none_in_view")}
                </p>
              )}
              {props.undrawable[d] > 0 && (
                <p className="m-0 px-1 text-xs text-[var(--us-danger)]">
                  {t("cisp.list.undrawable", { count: props.undrawable[d] })}
                </p>
              )}
              <ul className="m-0 flex list-none flex-col gap-0.5 p-0">
                {features[d].map((f) => {
                  const verdict = applicabilityOf(f.raw["properties"]);
                  const circle = circleOf(f.raw["geometry"]);
                  const expanded = selectedId === f.id;
                  const detailsId = `${sectionId}-f-${f.id}`;
                  return (
                    <li key={`${d}:${f.id}`}>
                      <button
                        type="button"
                        data-feature={f.id}
                        data-applicability={verdict ?? "unstated"}
                        data-drawn={circle === null ? "as-published" : f.drawnFromOutline ? "outline" : "not-drawn"}
                        aria-expanded={expanded}
                        // The details exist only while expanded.
                        aria-controls={expanded ? detailsId : undefined}
                        className={[
                          "flex w-full items-start gap-2 rounded-md px-1 py-1.5 text-start text-sm transition-colors hover:bg-hover focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none",
                          verdict === "not_applicable" ? "opacity-60" : "",
                          expanded ? "bg-accent-soft text-accent-text" : "",
                        ].join(" ")}
                        onClick={() => onSelect(expanded ? null : f.id)}
                      >
                        <Chevron open={expanded} />
                        <span className="min-w-0 flex-1">
                          <span className="font-mono">{f.id}</span> {f.view.name ?? ""}
                          <span className={["block text-xs", expanded ? "" : "text-[var(--us-text-muted)]"].join(" ")}>
                            {t(`zone.type.${f.view.type}`)}
                            {f.view.restrictionState !== null && ` · ${t(`restriction.state.${f.view.restrictionState}`)}`}
                            {verdict !== null && verdict !== "applies" && ` · ${t(`cisp.applicability.short.${verdict}`)}`}
                            {circle !== null && ` · ${t(f.drawnFromOutline ? "cisp.list.circle_drawn" : "cisp.list.circle")}`}
                          </span>
                        </span>
                      </button>
                      {expanded && <FeatureDetails feature={f} id={detailsId} />}
                    </li>
                  );
                })}
              </ul>
            </div>
          </section>
        );
      })}
    </div>
  );
}

/** The disclosure's state for the eye; aria-expanded carries it for assistive technology. */
function Chevron({ open }: { open: boolean }) {
  return (
    <svg
      aria-hidden="true"
      viewBox="0 0 16 16"
      className={["mt-0.5 size-4 shrink-0 transition-transform", open ? "rotate-90" : ""].join(" ")}
      fill="none"
      stroke="currentColor"
      strokeWidth="1.75"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M6 4l4 4-4 4" />
    </svg>
  );
}

/** The feature with this identifier across the three layers. */
export function findFeature(features: Record<MapDataset, MapFeature[]>, id: string | null): MapFeature | null {
  if (id === null) return null;
  for (const d of MAP_DATASETS) {
    const f = features[d].find((x) => x.id === id);
    if (f !== undefined) return f;
  }
  return null;
}
