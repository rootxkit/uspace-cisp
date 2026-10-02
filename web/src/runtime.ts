// Values the server reads at request time and hands to the page. They
// are read with bracket access so `next build` does not inline them: the
// image is built once in CI and configured at start.
export interface MapViewConfig {
  /** [lng, lat], WGS84 degrees (NEXT_PUBLIC_MAP_CENTER "lng,lat"). */
  center: [number, number];
  /** NEXT_PUBLIC_MAP_ZOOM. */
  zoom: number;
}

export interface RuntimeConfig {
  /** Where the browser reaches the API; "" is same-origin (NEXT_PUBLIC_API_BASE_URL). */
  apiBaseUrl: string;
  /**
   * The public map's first view; null when it is not configured or not
   * valid (the page says so, and names the variable, rather than invent
   * a place: INV-03).
   */
  mapView: MapViewConfig | null;
  /** Why mapView is null, naming the variable; null when it is set. */
  mapViewProblem: string | null;
  /** The HEAD poll period while the stream is not live, seconds (CISP_WEB_POLL_INTERVAL_S). */
  pollIntervalS: number;
}

/** The map's first view from its two variables, or the problem with them. */
export function parseMapView(
  center: string | undefined,
  zoom: string | undefined,
): { view: MapViewConfig } | { problem: string } {
  if (center === undefined || center.trim() === "") return { problem: "NEXT_PUBLIC_MAP_CENTER is not set" };
  if (zoom === undefined || zoom.trim() === "") return { problem: "NEXT_PUBLIC_MAP_ZOOM is not set" };
  const parts = center.split(",").map((p) => p.trim());
  const lng = Number(parts[0]);
  const lat = Number(parts[1]);
  if (parts.length !== 2 || parts.some((p) => p === "") || !Number.isFinite(lng) || !Number.isFinite(lat)) {
    return { problem: `NEXT_PUBLIC_MAP_CENTER: want "lng,lat", got ${JSON.stringify(center)}` };
  }
  if (lng < -180 || lng > 180 || lat < -90 || lat > 90) {
    return { problem: `NEXT_PUBLIC_MAP_CENTER: ${center} is outside WGS84 longitude -180..180, latitude -90..90` };
  }
  const z = Number(zoom);
  if (!Number.isFinite(z) || z < 0 || z > 22) return { problem: `NEXT_PUBLIC_MAP_ZOOM: want 0..22, got ${JSON.stringify(zoom)}` };
  return { view: { center: [lng, lat], zoom: z } };
}

function pollIntervalS(raw: string | undefined): number {
  const n = Number(raw);
  return raw !== undefined && raw !== "" && Number.isInteger(n) && n >= 1 ? n : 60;
}

export function runtimeConfig(): RuntimeConfig {
  const env = process.env;
  const map = parseMapView(env["NEXT_PUBLIC_MAP_CENTER"], env["NEXT_PUBLIC_MAP_ZOOM"]);
  return {
    apiBaseUrl: env["NEXT_PUBLIC_API_BASE_URL"] ?? "",
    mapView: "view" in map ? map.view : null,
    mapViewProblem: "problem" in map ? map.problem : null,
    pollIntervalS: pollIntervalS(env["CISP_WEB_POLL_INTERVAL_S"]),
  };
}
