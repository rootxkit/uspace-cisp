"use client";

// A subscription's box on the map: the four numbers the API sent
// ([min lng, min lat, max lng, max lat], GeoJSON order) drawn as the
// rectangle they name, and the map moved to it. Nothing is computed:
// the corners are the numbers as sent.
import { useCallback, useSyncExternalStore } from "react";
import type { Map as MapLibreMap } from "maplibre-gl";
import { useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { MapView, useStyleLoad } from "@rootxkit/uspace-ui/map";
import { useTheme } from "@rootxkit/uspace-ui/theme";
import { useRuntimeConfig } from "../components/Providers";

const SOURCE_ID = "console-bbox";

/** "[44.7000, 41.6000, 44.9000, 41.8000]" (GeoJSON order, as sent). */
export function fmtBBox(b: readonly number[] | undefined): string | null {
  if (b === undefined || b.length !== 4 || b.some((v) => !Number.isFinite(v))) return null;
  return `[${b.map((v) => v.toFixed(4)).join(", ")}]`;
}

/** The closed ring of the box's corners, as sent; null for anything but four finite numbers. */
export function bboxRing(b: readonly number[] | undefined): [number, number][] | null {
  if (b === undefined || b.length !== 4 || b.some((v) => !Number.isFinite(v))) return null;
  const [w, s, e, n] = b as [number, number, number, number];
  return [
    [w, s],
    [e, s],
    [e, n],
    [w, n],
    [w, s],
  ];
}

function BoxLayer({ bbox }: { bbox: readonly number[] }) {
  const add = useCallback(
    (map: MapLibreMap) => {
      const ring = bboxRing(bbox);
      if (ring === null || map.getSource(SOURCE_ID) !== undefined) return;
      map.addSource(SOURCE_ID, {
        type: "geojson",
        data: { type: "Feature", properties: {}, geometry: { type: "Polygon", coordinates: [ring] } },
      });
      map.addLayer({ id: `${SOURCE_ID}-line`, type: "line", source: SOURCE_ID, paint: { "line-width": 2 } });
      const [w, s, e, n] = bbox as [number, number, number, number];
      map.fitBounds(
        [
          [w, s],
          [e, n],
        ],
        { padding: 24, animate: false },
      );
    },
    [bbox],
  );
  useStyleLoad(add);
  return null;
}

function noSubscribe(): () => void {
  return () => undefined;
}

export function BBoxPreview({ bbox }: { bbox: readonly number[] | undefined }) {
  const t = useT();
  const { lang } = useLang();
  const { resolved } = useTheme();
  const cfg = useRuntimeConfig();
  const origin = useSyncExternalStore(
    noSubscribe,
    () => window.location.origin,
    () => null,
  );
  const text = fmtBBox(bbox);
  if (bbox === undefined || text === null) return <p className="m-0 text-sm">{t("cisp.console.subscriptions.bbox_none")}</p>;
  return (
    <div className="flex flex-col gap-1" data-testid="bbox-preview">
      <p className="m-0 font-mono text-xs">{text}</p>
      {cfg.mapView === null ? (
        <p role="alert" className="m-0 text-sm text-[var(--us-danger)]">
          {t("cisp.map.not_configured", { problem: cfg.mapViewProblem ?? "" })}
        </p>
      ) : (
        origin !== null && (
          <div className="relative h-56 w-full max-w-xl overflow-hidden rounded border border-[var(--us-border)]">
            <MapView
              className="absolute inset-0"
              basemap={{ baseUrl: origin }}
              initial={{ center: cfg.mapView.center, zoom: cfg.mapView.zoom, bearing: 0, pitch: 0 }}
              lang={lang}
              scheme={resolved}
            >
              <BoxLayer bbox={bbox} />
            </MapView>
          </div>
        )
      )}
    </div>
  );
}
