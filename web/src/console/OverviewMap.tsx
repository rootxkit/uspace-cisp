"use client";

// The overview's map: the current version of the three drawable datasets
// through the public read the previews already make (GET
// /public/v1/{dataset}, with applies_at so circles carry the CISP's
// outline, Q43), drawn with the kit's layers in a MapPanel with the zone
// legend laid over it. Read once on opening the page; nothing is computed
// from a geometry here.
import { useEffect, useMemo, useState, useSyncExternalStore } from "react";
import Link from "next/link";
import { useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { ZoneLegend } from "@rootxkit/uspace-ui/legend";
import { MapView } from "@rootxkit/uspace-ui/map";
import type { ZoneType } from "@rootxkit/uspace-ui/model";
import { useTheme } from "@rootxkit/uspace-ui/theme";
import { Button, MapPanel } from "@rootxkit/uspace-ui/ui";
import { useRuntimeConfig } from "../components/Providers";
import { toView, type MapFeature } from "../map/adapt";
import { MapLayers } from "../map/MapLayers";
import { MAP_DATASETS, type MapDataset } from "../public/banner";
import { obj } from "../public/format";
import { previewClient } from "./client";

type Served = Record<MapDataset, MapFeature[]>;

const NONE: Served = { zones: [], uspace_airspace: [], restrictions: [] };

function noSubscribe(): () => void {
  return () => undefined;
}

export function OverviewMap() {
  const t = useT();
  const { lang } = useLang();
  const { resolved } = useTheme();
  const cfg = useRuntimeConfig();
  const client = useMemo(() => previewClient(cfg.apiBaseUrl, () => lang), [cfg.apiBaseUrl, lang]);
  const [served, setServed] = useState<{ lang: string; features: Served; failed: MapDataset[] } | null>(null);
  const [visible, setVisible] = useState<Record<MapDataset, boolean>>({ zones: true, uspace_airspace: true, restrictions: true });
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const origin = useSyncExternalStore(
    noSubscribe,
    () => window.location.origin,
    () => null,
  );

  useEffect(() => {
    let live = true;
    const at = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
    void Promise.all(
      MAP_DATASETS.map(async (dataset) => {
        try {
          const { data } = await client.GET("/public/v1/{dataset}", { params: { path: { dataset }, query: { applies_at: at } } });
          const body = obj(data);
          const list = Array.isArray(body?.["features"]) ? body["features"] : [];
          const version = typeof body?.["cis_version"] === "number" ? String(body["cis_version"]) : null;
          const updatedAt = typeof body?.["cis_updated_at"] === "string" ? body["cis_updated_at"] : null;
          return {
            dataset,
            features: list.map((f) => toView(f, dataset, { version, updatedAt }, lang)).filter((v): v is MapFeature => v !== null),
            failed: false,
          };
        } catch {
          return { dataset, features: [] as MapFeature[], failed: true };
        }
      }),
    ).then((reads) => {
      if (!live) return;
      const features: Served = { ...NONE };
      for (const r of reads) features[r.dataset] = r.features;
      setServed({ lang, features, failed: reads.filter((r) => r.failed).map((r) => r.dataset) });
    });
    return () => {
      live = false;
    };
  }, [client, lang]);

  const features = served?.lang === lang ? served.features : NONE;
  const counts = useMemo(() => {
    const c: Partial<Record<ZoneType, number>> = {};
    for (const d of MAP_DATASETS) {
      if (!visible[d]) continue;
      for (const f of features[d]) c[f.view.type] = (c[f.view.type] ?? 0) + 1;
    }
    return c;
  }, [features, visible]);

  return (
    <MapPanel
      title={t("cisp.console.overview.map_title")}
      description={t("cisp.console.overview.map_description")}
      actions={
        <Button asChild variant="outline" size="sm">
          <Link href={`/${lang}`}>{t("cisp.console.overview.open_map")}</Link>
        </Button>
      }
      legend={<ZoneLegend counts={counts} className="border-0 bg-transparent p-0 shadow-none" />}
      defaultLegendOpen={false}
      mapClassName="h-[26rem]"
      {...(served !== null && served.failed.length > 0
        ? {
            footer: (
              <span role="alert" className="font-semibold text-[var(--us-danger)]">
                {t("cisp.console.preview.unavailable")}
              </span>
            ),
          }
        : {})}
    >
      {cfg.mapView === null ? (
        <p role="alert" className="m-0 p-4 text-sm text-[var(--us-danger)]">
          {t("cisp.map.not_configured", { problem: cfg.mapViewProblem ?? "" })}
        </p>
      ) : (
        origin !== null && (
          <MapView
            className="absolute inset-0"
            basemap={{ baseUrl: origin }}
            initial={{ center: cfg.mapView.center, zoom: cfg.mapView.zoom, bearing: 0, pitch: 0 }}
            lang={lang}
            scheme={resolved}
          >
            <MapLayers
              features={features}
              visible={visible}
              onVisible={(d, v) => setVisible((prev) => ({ ...prev, [d]: v }))}
              selectedId={selectedId}
              onSelect={setSelectedId}
            />
          </MapView>
        )
      )}
    </MapPanel>
  );
}
