"use client";

// The public map's data: the three ED-318 datasets read by the visible
// bbox from /public/v1/* with applies_at (one fetch each, nothing
// filtered out), kept current by the stream (WS /v1/stream: a status
// whose datasets{} version moved, a resync_since, or a cis/change/v1
// frame refetches) or, while the stream is not live, by a HEAD on each
// dataset every poll period (a changed ETag refetches). A dataset the
// API cannot serve keeps what was last shown and is marked "unavailable
// since" on the banner: an outage is never drawn as an empty sky.
import { useCallback, useEffect, useMemo, useReducer, useRef, useState } from "react";
import type { Lang } from "@rootxkit/uspace-ui/i18n";
import { useFeed, useNowMs } from "@rootxkit/uspace-ui/live";
import type { BBox } from "@rootxkit/uspace-ui/map";
import { browserClient } from "../api/client";
import { toView, type MapFeature } from "../map/adapt";
import { MAP_DATASETS, initialBanner, reduceBanner, type MapDataset } from "./banner";
import { obj } from "./format";

/** How often the banner re-reads the clock. Display-only. */
const TICK_MS = 1000;

export interface MapData {
  banner: ReturnType<typeof initialBanner>;
  features: Record<MapDataset, MapFeature[]>;
  /** Features served but not drawable by the kit (no identifier, unknown type), per dataset. */
  undrawable: Record<MapDataset, number>;
}

export function bboxParam(b: BBox | null): string | undefined {
  return b === null ? undefined : [b.minLng, b.minLat, b.maxLng, b.maxLat].map((v) => v.toFixed(4)).join(",");
}

function nowIso(): string {
  return new Date().toISOString();
}

export function useMapData(opts: {
  apiBaseUrl: string;
  lang: Lang;
  bbox: BBox | null;
  /** False until the map has a view (its first bbox); without a map, true at once. */
  ready: boolean;
  appliesAt: string;
  pollIntervalS: number;
}): MapData {
  const { apiBaseUrl, lang, bbox, ready, appliesAt, pollIntervalS } = opts;
  const [banner, dispatch] = useReducer(reduceBanner, undefined, initialBanner);
  const [features, setFeatures] = useState<Record<MapDataset, MapFeature[]>>({
    zones: [],
    uspace_airspace: [],
    restrictions: [],
  });
  const [undrawable, setUndrawable] = useState<Record<MapDataset, number>>({ zones: 0, uspace_airspace: 0, restrictions: 0 });
  const langRef = useRef(lang);
  langRef.current = lang;
  const client = useMemo(() => browserClient(apiBaseUrl, () => langRef.current), [apiBaseUrl]);
  const seq = useRef<Record<MapDataset, number>>({ zones: 0, uspace_airspace: 0, restrictions: 0 });
  const bannerRef = useRef(banner);
  bannerRef.current = banner;
  const query = useRef({ bbox, appliesAt });
  query.current = { bbox, appliesAt };

  const fetchDataset = useCallback(
    async (dataset: MapDataset) => {
      const mine = ++seq.current[dataset];
      const { bbox: b, appliesAt: at } = query.current;
      const bboxQ = bboxParam(b);
      try {
        const { data, response } = await client.GET("/public/v1/{dataset}", {
          params: { path: { dataset }, query: { ...(bboxQ === undefined ? {} : { bbox: bboxQ }), applies_at: at } },
          // Revalidate with the browser cache's If-None-Match.
          cache: "no-cache",
        });
        if (mine !== seq.current[dataset]) return;
        const body = obj(data);
        const list = Array.isArray(body?.["features"]) ? body["features"] : null;
        if (body === null || list === null) throw new Error("not a feature collection");
        const version = typeof body["cis_version"] === "number" ? String(body["cis_version"]) : null;
        const updatedAt = typeof body["cis_updated_at"] === "string" ? body["cis_updated_at"] : null;
        const views = list.map((f) => toView(f, dataset, { version, updatedAt }, langRef.current));
        setFeatures((prev) => ({ ...prev, [dataset]: views.filter((v): v is MapFeature => v !== null) }));
        setUndrawable((prev) => ({ ...prev, [dataset]: views.filter((v) => v === null).length }));
        const pss = body["cis_publisher_stale_since"];
        dispatch({
          kind: "served",
          dataset,
          version,
          updatedAt,
          etag: response.headers.get("ETag"),
          stale: response.headers.get("X-CIS-Stale") === "true",
          publisherStaleSince: Object.hasOwn(body, "cis_publisher_stale_since")
            ? typeof pss === "string"
              ? pss
              : null
            : undefined,
        });
      } catch {
        if (mine !== seq.current[dataset]) return;
        dispatch({ kind: "unavailable", dataset, at: nowIso() });
      }
    },
    [client],
  );

  const fetchAll = useCallback(() => {
    for (const d of MAP_DATASETS) void fetchDataset(d);
  }, [fetchDataset]);

  // The view or the instant changed: read all three again.
  const bboxKey = bboxParam(bbox) ?? "";
  useEffect(() => {
    if (ready) fetchAll();
  }, [ready, fetchAll, bboxKey, appliesAt, lang]);

  // The stream: status frames say what is current; change frames name a dataset.
  const feed = useFeed({
    url: `${apiBaseUrl}/v1/stream?datasets=${MAP_DATASETS.join(",")}`,
    onFrame(frame) {
      if (frame.schema !== "cis/change/v1") return;
      const ds = obj(frame.body)?.["dataset"];
      if (typeof ds === "string" && (MAP_DATASETS as readonly string[]).includes(ds)) void fetchDataset(ds as MapDataset);
    },
  });
  const requested = useRef<Record<MapDataset, string | null>>({ zones: null, uspace_airspace: null, restrictions: null });
  const lastResync = useRef<string | null>(null);
  useEffect(() => {
    if (feed.connection !== "live" || feed.lastStatusAtMs === null || feed.liveMaxAgeS === null) {
      dispatch({ kind: "stream_down", atMs: Date.now() });
      return;
    }
    dispatch({ kind: "stream_status", atMs: feed.lastStatusAtMs, liveMaxAgeS: feed.liveMaxAgeS });
    const announced = feed.extras.datasets;
    for (const d of MAP_DATASETS) {
      const v = announced?.[d]?.version;
      if (v === undefined) continue;
      const shown = bannerRef.current.datasets[d].version;
      if (shown !== null && v !== shown && requested.current[d] !== v) {
        requested.current[d] = v;
        void fetchDataset(d);
      }
    }
    const resync = feed.extras.resyncSince;
    if (resync !== null && resync !== lastResync.current) {
      lastResync.current = resync;
      fetchAll();
    }
  }, [feed.connection, feed.lastStatusAtMs, feed.liveMaxAgeS, feed.extras, fetchDataset, fetchAll]);

  // The clock: a stream silent past its live_max_age_s is no longer live.
  const nowMs = useNowMs(TICK_MS);
  useEffect(() => {
    dispatch({ kind: "tick", atMs: nowMs });
  }, [nowMs]);

  // Polling while the stream is not live: HEAD each dataset, refetch on a
  // new ETag. At once when the stream is down; while it is still
  // connecting, from one period on.
  const live = banner.mode === "live";
  const streamDown = feed.connection === "down";
  useEffect(() => {
    if (live || !ready) return;
    let cancelled = false;
    const round = async () => {
      let reached = true;
      await Promise.all(
        MAP_DATASETS.map(async (d) => {
          try {
            const { response } = await client.HEAD("/public/v1/{dataset}", { params: { path: { dataset: d } }, cache: "no-store" });
            const etag = response.headers.get("ETag");
            const st = bannerRef.current.datasets[d];
            // A dataset never served has its first read in flight, or is unavailable.
            if (etag !== null && ((st.etag !== null && etag !== st.etag) || st.unavailableSince !== null)) {
              void fetchDataset(d);
            }
          } catch (err) {
            const status = obj(err)?.["status"];
            if (typeof status === "number") {
              // The API answered: reachable, but not serving this dataset.
              dispatch({ kind: "unavailable", dataset: d, at: nowIso() });
            } else {
              reached = false;
            }
          }
        }),
      );
      if (!cancelled) dispatch({ kind: "poll", ok: reached, atMs: Date.now() });
    };
    if (streamDown) void round();
    const id = setInterval(() => void round(), pollIntervalS * 1000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [live, streamDown, ready, client, fetchDataset, pollIntervalS]);

  return { banner, features, undrawable };
}
