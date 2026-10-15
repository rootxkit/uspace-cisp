// The "as of" banner's state (spec 02 F3, Art. 9(2); the failure rule of
// spec 02 §1): per dataset its version and update time, the ANSP's
// staleness, "unavailable since" when the API cannot serve it, and
// "nothing published yet" when it answers 404 no_version; and
// for the page whether changes reach it live (the stream), by polling
// (HEAD on the ETag), or not at all. Pure: events in, state out; the
// clock is the caller's.
export const MAP_DATASETS = ["zones", "uspace_airspace", "restrictions"] as const;
export type MapDataset = (typeof MAP_DATASETS)[number];

export type FeedMode = "connecting" | "live" | "polling" | "disconnected";

export interface DatasetState {
  /** The version the page shows (cis_version), null before the first answer. */
  version: string | null;
  /** cis_updated_at as the API sent it. */
  updatedAt: string | null;
  /** The ETag of the last answer: what a HEAD is compared against. */
  etag: string | null;
  /** The API answered from its held snapshot (X-CIS-Stale: true). */
  stale: boolean;
  /** cis_publisher_stale_since: undefined when absent, null when "never heard from". */
  publisherStaleSince: string | null | undefined;
  /** When the API first failed to serve the dataset; null while it serves it. */
  unavailableSince: string | null;
  /**
   * The API answered 404 no_version: nothing has been published in this
   * dataset yet. An empty dataset, not an outage.
   */
  empty: boolean;
}

export interface BannerState {
  mode: FeedMode;
  /** The stream's last status (ms since the epoch, the page's clock). */
  streamStatusAtMs: number | null;
  /** live_max_age_s from the stream's own status frame. */
  liveMaxAgeS: number | null;
  streamUp: boolean;
  /** The last HEAD round: true all answered, false one failed, null none yet. */
  pollOk: boolean | null;
  datasets: Record<MapDataset, DatasetState>;
}

export type BannerEvent =
  | { kind: "stream_status"; atMs: number; liveMaxAgeS: number }
  | { kind: "stream_down"; atMs: number }
  | { kind: "tick"; atMs: number }
  | { kind: "poll"; ok: boolean; atMs: number }
  | {
      kind: "served";
      dataset: MapDataset;
      version: string | null;
      updatedAt: string | null;
      etag: string | null;
      stale: boolean;
      publisherStaleSince: string | null | undefined;
    }
  | { kind: "unavailable"; dataset: MapDataset; at: string }
  | { kind: "no_version"; dataset: MapDataset };

/** What a failed read of a dataset means for the page. */
export type ReadFailure = "no_version" | "unavailable";

/**
 * A 404 whose problem type is no_version is a dataset nothing has been
 * published in yet (api/openapi.yaml, GET /public/v1/{dataset}): shown
 * as empty. Every other failure (a 5xx, another 404, no answer at all)
 * is an outage, shown as unavailable.
 */
export function readFailure(err: unknown): ReadFailure {
  if (typeof err !== "object" || err === null) return "unavailable";
  const e = err as { status?: unknown; slug?: unknown };
  return e.status === 404 && e.slug === "no_version" ? "no_version" : "unavailable";
}

const EMPTY: DatasetState = {
  version: null,
  updatedAt: null,
  etag: null,
  stale: false,
  publisherStaleSince: undefined,
  unavailableSince: null,
  empty: false,
};

export function initialBanner(): BannerState {
  return {
    mode: "connecting",
    streamStatusAtMs: null,
    liveMaxAgeS: null,
    streamUp: false,
    pollOk: null,
    datasets: { zones: { ...EMPTY }, uspace_airspace: { ...EMPTY }, restrictions: { ...EMPTY } },
  };
}

/**
 * Live while the stream's last status is younger than the live_max_age_s
 * it announced; else polling while the last HEAD round answered; else
 * disconnected (connecting before anything was heard).
 */
function modeOf(s: BannerState, nowMs: number): FeedMode {
  const fresh =
    s.streamUp &&
    s.streamStatusAtMs !== null &&
    s.liveMaxAgeS !== null &&
    nowMs - s.streamStatusAtMs <= s.liveMaxAgeS * 1000;
  if (fresh) return "live";
  if (s.pollOk === true) return "polling";
  if (s.pollOk === false) return "disconnected";
  return s.streamStatusAtMs === null ? "connecting" : "disconnected";
}

export function reduceBanner(s: BannerState, e: BannerEvent): BannerState {
  switch (e.kind) {
    case "stream_status": {
      const n = { ...s, streamUp: true, streamStatusAtMs: e.atMs, liveMaxAgeS: e.liveMaxAgeS };
      return { ...n, mode: modeOf(n, e.atMs) };
    }
    case "stream_down": {
      const n = { ...s, streamUp: false };
      return { ...n, mode: modeOf(n, e.atMs) };
    }
    case "tick":
      return { ...s, mode: modeOf(s, e.atMs) };
    case "poll": {
      const n = { ...s, pollOk: e.ok };
      return { ...n, mode: modeOf(n, e.atMs) };
    }
    case "served":
      return {
        ...s,
        datasets: {
          ...s.datasets,
          [e.dataset]: {
            version: e.version,
            updatedAt: e.updatedAt,
            etag: e.etag,
            stale: e.stale,
            publisherStaleSince: e.publisherStaleSince,
            unavailableSince: null,
            empty: false,
          },
        },
      };
    case "no_version":
      return {
        ...s,
        datasets: {
          ...s.datasets,
          // The answer carries no version, update time or ANSP staleness.
          [e.dataset]: { ...EMPTY, empty: true },
        },
      };
    case "unavailable": {
      const d = s.datasets[e.dataset];
      return {
        ...s,
        datasets: { ...s.datasets, [e.dataset]: { ...d, unavailableSince: d.unavailableSince ?? e.at } },
      };
    }
  }
}
