"use client";

// A map preview of some features of a dataset's current version: the
// public read (GET /public/v1/{dataset}, with applies_at so circles carry
// the CISP's outline, Q43), the named features kept, drawn with the kit's
// layers. The console API's diff and restriction heads carry identifiers
// only, and the public read serves the current version only, so the page
// says which of the named features are drawn and why the others are not
// (docs/PLAN.md §15 Q44). Nothing is computed from a geometry here.
import { useEffect, useMemo, useState, useSyncExternalStore } from "react";
import { useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { RestrictionLayer, ZoneLayer } from "@rootxkit/uspace-ui/layers";
import { MapView } from "@rootxkit/uspace-ui/map";
import { useTheme } from "@rootxkit/uspace-ui/theme";
import { useRuntimeConfig } from "../components/Providers";
import { toView, type MapFeature } from "../map/adapt";
import { obj } from "../public/format";
import { previewClient } from "./client";

export type MapDatasetName = MapFeature["dataset"];

export function isMapDataset(d: string): d is MapDatasetName {
  return d === "zones" || d === "uspace_airspace" || d === "restrictions";
}

function noSubscribe(): () => void {
  return () => undefined;
}

/** The features of `served` named in `ids`, and the ids not served. */
export function pick(served: readonly MapFeature[], ids: readonly string[]): { drawn: MapFeature[]; missing: string[] } {
  const want = new Set(ids);
  const drawn = served.filter((f) => want.has(f.id));
  const have = new Set(drawn.map((f) => f.id));
  return { drawn, missing: ids.filter((id) => !have.has(id)) };
}

export function FeaturePreview({ dataset, ids }: { dataset: MapDatasetName; ids: readonly string[] }) {
  const t = useT();
  const { lang } = useLang();
  const { resolved } = useTheme();
  const cfg = useRuntimeConfig();
  const client = useMemo(() => previewClient(cfg.apiBaseUrl, () => lang), [cfg.apiBaseUrl, lang]);
  const [read, setRead] = useState<{ key: string; served: MapFeature[] | null; failed: boolean }>({
    key: "",
    served: null,
    failed: false,
  });
  const readKey = `${dataset}:${lang}`;
  const origin = useSyncExternalStore(
    noSubscribe,
    () => window.location.origin,
    () => null,
  );

  useEffect(() => {
    let live = true;
    client
      .GET("/public/v1/{dataset}", {
        params: { path: { dataset }, query: { applies_at: new Date().toISOString().replace(/\.\d{3}Z$/, "Z") } },
      })
      .then(({ data }) => {
        if (!live) return;
        const body = obj(data);
        const list = Array.isArray(body?.["features"]) ? body["features"] : [];
        const version = typeof body?.["cis_version"] === "number" ? String(body["cis_version"]) : null;
        const updatedAt = typeof body?.["cis_updated_at"] === "string" ? body["cis_updated_at"] : null;
        setRead({
          key: `${dataset}:${lang}`,
          served: list.map((f) => toView(f, dataset, { version, updatedAt }, lang)).filter((v): v is MapFeature => v !== null),
          failed: false,
        });
      })
      .catch(() => {
        if (live) setRead({ key: `${dataset}:${lang}`, served: null, failed: true });
      });
    return () => {
      live = false;
    };
  }, [client, dataset, lang]);
  const served = read.key === readKey ? read.served : null;
  const failed = read.key === readKey && read.failed;

  const { drawn, missing } = useMemo(() => pick(served ?? [], ids), [served, ids]);
  const views = useMemo(() => drawn.map((f) => f.view), [drawn]);

  return (
    <div className="flex flex-col gap-2" data-testid="feature-preview">
      <p className="m-0 text-xs text-[var(--us-text-muted)]">{t("cisp.console.preview.note")}</p>
      {failed && (
        <p role="alert" className="m-0 text-sm text-[var(--us-danger)]">
          {t("cisp.console.preview.unavailable")}
        </p>
      )}
      {served !== null && (
        <p className="m-0 text-sm" data-testid="preview-drawn">
          {drawn.length === 0
            ? t("cisp.console.preview.none_drawn")
            : t("cisp.console.preview.drawn", { ids: drawn.map((f) => f.id).join(", ") })}
        </p>
      )}
      {served !== null && missing.length > 0 && (
        <p className="m-0 text-sm" data-testid="preview-missing">
          {t("cisp.console.preview.missing", { ids: missing.join(", ") })}
        </p>
      )}
      {cfg.mapView === null ? (
        <p role="alert" className="m-0 text-sm text-[var(--us-danger)]">
          {t("cisp.map.not_configured", { problem: cfg.mapViewProblem ?? "" })}
        </p>
      ) : (
        origin !== null && (
          <div className="relative h-72 w-full overflow-hidden rounded border border-[var(--us-border)]">
            <MapView
              className="absolute inset-0"
              basemap={{ baseUrl: origin }}
              initial={{ center: cfg.mapView.center, zoom: cfg.mapView.zoom, bearing: 0, pitch: 0 }}
              lang={lang}
              scheme={resolved}
            >
              {dataset === "restrictions" ? (
                <RestrictionLayer id="console-preview-restrictions" restrictions={views} />
              ) : (
                <ZoneLayer id="console-preview-zones" zones={views} />
              )}
            </MapView>
          </div>
        )
      )}
    </div>
  );
}
