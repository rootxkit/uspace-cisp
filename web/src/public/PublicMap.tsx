"use client";

import { useCallback, useEffect, useMemo, useState, useSyncExternalStore } from "react";
import { ZoneLegend } from "@rootxkit/uspace-ui/legend";
import { fmtTimeUTC, useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { MapView, type BBox } from "@rootxkit/uspace-ui/map";
import type { ZoneType } from "@rootxkit/uspace-ui/model";
import { useTheme } from "@rootxkit/uspace-ui/theme";
import { useRuntimeConfig } from "../components/Providers";
import { BBoxWatcher, MapLayers } from "../map/MapLayers";
import { AsOfBanner } from "./AsOfBanner";
import { MAP_DATASETS, type MapDataset } from "./banner";
import { FeatureList, findFeature } from "./FeatureList";
import { FeaturePanel } from "./FeaturePanel";
import { instantOf, TimeControl, type TimeChoice } from "./TimeControl";
import { useMapData } from "./useMapData";

/** "Now" is asked to the minute, so the browser cache can answer within it. Display-only. */
const NOW_QUANTUM_MS = 60_000;

function nowQuantised(): string {
  return new Date(Math.floor(Date.now() / NOW_QUANTUM_MS) * NOW_QUANTUM_MS).toISOString().replace(/\.\d{3}Z$/, "Z");
}

function noSubscribe(): () => void {
  return () => undefined;
}

/** "Now" to the minute, moving on by itself. */
function useNowInstant(): string {
  const [now, setNow] = useState(nowQuantised);
  useEffect(() => {
    const id = setInterval(() => setNow(nowQuantised()), NOW_QUANTUM_MS / 4);
    return () => clearInterval(id);
  }, []);
  return now;
}

/** The public zone map: banner, map, time control, legend, list and panel. */
export function PublicMap() {
  const t = useT();
  const { lang } = useLang();
  const { resolved } = useTheme();
  const cfg = useRuntimeConfig();
  const [bbox, setBBox] = useState<BBox | null>(null);
  const [time, setTime] = useState<TimeChoice>({ kind: "now" });
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [visible, setVisible] = useState<Record<MapDataset, boolean>>({
    zones: true,
    uspace_airspace: true,
    restrictions: true,
  });
  const now = useNowInstant();
  const appliesAt = time.kind === "instant" ? (instantOf(time.local) ?? now) : now;
  const data = useMapData({
    apiBaseUrl: cfg.apiBaseUrl,
    lang,
    bbox,
    ready: bbox !== null || cfg.mapView === null,
    appliesAt,
    pollIntervalS: cfg.pollIntervalS,
  });
  const selected = findFeature(data.features, selectedId);
  const counts = useMemo(() => {
    const c: Partial<Record<ZoneType, number>> = {};
    for (const d of MAP_DATASETS) {
      if (!visible[d]) continue;
      for (const f of data.features[d]) c[f.view.type] = (c[f.view.type] ?? 0) + 1;
    }
    return c;
  }, [data.features, visible]);
  const onVisible = useCallback((d: MapDataset, v: boolean) => setVisible((prev) => ({ ...prev, [d]: v })), []);
  // The basemap is read from this origin's /basemap/; null while rendering on the server.
  const origin = useSyncExternalStore(
    noSubscribe,
    () => window.location.origin,
    () => null,
  );

  return (
    <div className="flex flex-col">
      <AsOfBanner state={data.banner} />
      {/* A fixed height: the list growing beside the map must not resize it (a resize is a new bbox). */}
      <div className="flex flex-col lg:h-[75vh] lg:flex-row">
        <div className="relative h-[50vh] lg:h-auto lg:flex-1">
          {cfg.mapView === null ? (
            <p role="alert" className="p-4 text-[var(--us-danger)]">
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
                <BBoxWatcher onChange={setBBox} />
                <MapLayers
                  features={data.features}
                  visible={visible}
                  onVisible={onVisible}
                  selectedId={selectedId}
                  onSelect={setSelectedId}
                />
              </MapView>
            )
          )}
        </div>
        <aside
          aria-label={t("cisp.map.side")}
          className="flex w-full flex-col gap-4 border-[var(--us-border)] p-3 lg:w-[26rem] lg:overflow-y-auto lg:border-s"
        >
          <TimeControl value={time} onChange={setTime} instantShown={fmtTimeUTC(appliesAt, lang)} />
          {selected !== null && <FeaturePanel feature={selected} onClose={() => setSelectedId(null)} />}
          <ZoneLegend counts={counts} defaultCollapsed />
          <FeatureList
            features={data.features}
            undrawable={data.undrawable}
            visible={visible}
            selectedId={selectedId}
            onSelect={setSelectedId}
          />
        </aside>
      </div>
    </div>
  );
}
