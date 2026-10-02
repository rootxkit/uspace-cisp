"use client";

import { useT } from "@rootxkit/uspace-ui/i18n";
import type { MapFeature } from "../map/adapt";
import { MAP_DATASETS, type MapDataset } from "./banner";
import { applicabilityOf, circleOf } from "./format";

/**
 * Every feature the map was given, by layer, each a button that opens
 * the panel: the keyboard's way to every zone, and the list that says a
 * zone is there when the map cannot draw it (a circle the API sent as a
 * point, a browser without WebGL).
 */
export function FeatureList(props: {
  features: Record<MapDataset, MapFeature[]>;
  undrawable: Record<MapDataset, number>;
  visible: Record<MapDataset, boolean>;
  selectedId: string | null;
  onSelect(id: string): void;
}) {
  const t = useT();
  return (
    <div className="flex flex-col gap-3">
      {MAP_DATASETS.filter((d) => props.visible[d]).map((d) => (
        <section key={d} aria-label={t(`cisp.dataset.${d}`)} data-layer={d}>
          <h3 className="text-sm font-bold">
            {t(`cisp.dataset.${d}`)} <span data-count>{props.features[d].length}</span>
          </h3>
          {props.features[d].length === 0 && (
            <p className="text-xs text-[var(--us-text-muted)]">{t("cisp.list.none_in_view")}</p>
          )}
          {props.undrawable[d] > 0 && (
            <p className="text-xs text-[var(--us-danger)]">{t("cisp.list.undrawable", { count: props.undrawable[d] })}</p>
          )}
          <ul className="flex flex-col gap-1">
            {props.features[d].map((f) => {
              const verdict = applicabilityOf(f.raw["properties"]);
              const circle = circleOf(f.raw["geometry"]);
              const selected = props.selectedId === f.id;
              return (
                <li key={`${d}:${f.id}`}>
                  <button
                    type="button"
                    data-feature={f.id}
                    data-applicability={verdict ?? "unstated"}
                    aria-pressed={selected}
                    className={[
                      "w-full rounded px-2 py-1 text-start text-sm hover:bg-[var(--us-hover)]",
                      verdict === "not_applicable" ? "opacity-60" : "",
                      selected ? "outline outline-2 outline-[var(--us-focus)]" : "",
                    ].join(" ")}
                    onClick={() => props.onSelect(f.id)}
                  >
                    <span className="font-mono">{f.id}</span> {f.view.name ?? ""}
                    <span className="block text-xs text-[var(--us-text-muted)]">
                      {t(`zone.type.${f.view.type}`)}
                      {f.view.restrictionState !== null && ` · ${t(`restriction.state.${f.view.restrictionState}`)}`}
                      {verdict !== null && verdict !== "applies" && ` · ${t(`cisp.applicability.short.${verdict}`)}`}
                      {circle !== null && ` · ${t("cisp.list.circle")}`}
                    </span>
                  </button>
                </li>
              );
            })}
          </ul>
        </section>
      ))}
    </div>
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
