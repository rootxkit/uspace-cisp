import { describe, expect, it } from "vitest";
import { initialBanner, readFailure, reduceBanner, type BannerEvent, type BannerState } from "./banner";

function run(events: BannerEvent[], from: BannerState = initialBanner()): BannerState {
  return events.reduce(reduceBanner, from);
}

const served = (version: string): BannerEvent => ({
  kind: "served",
  dataset: "zones",
  version,
  updatedAt: "2026-10-01T08:00:00Z",
  etag: `"zones:${version}"`,
  stale: false,
  publisherStaleSince: undefined,
});

describe("the banner", () => {
  it("starts connecting", () => {
    expect(initialBanner().mode).toBe("connecting");
  });

  it("goes live → polling → disconnected → unavailable", () => {
    const live = run([{ kind: "stream_status", atMs: 1_000, liveMaxAgeS: 6 }]);
    expect(live.mode).toBe("live");

    const polling = run([{ kind: "stream_down", atMs: 2_000 }, { kind: "poll", ok: true, atMs: 2_000 }], live);
    expect(polling.mode).toBe("polling");

    const disconnected = run([{ kind: "poll", ok: false, atMs: 62_000 }], polling);
    expect(disconnected.mode).toBe("disconnected");

    const unavailable = run([{ kind: "unavailable", dataset: "zones", at: "2026-10-02T10:00:00Z" }], disconnected);
    expect(unavailable.datasets.zones.unavailableSince).toBe("2026-10-02T10:00:00Z");
    expect(unavailable.datasets.restrictions.unavailableSince).toBeNull();
  });

  it("stops being live when the stream's status is older than its live_max_age_s", () => {
    const live = run([{ kind: "stream_status", atMs: 10_000, liveMaxAgeS: 6 }]);
    expect(run([{ kind: "tick", atMs: 16_000 }], live).mode).toBe("live");
    expect(run([{ kind: "tick", atMs: 16_001 }], live).mode).toBe("disconnected");
    expect(run([{ kind: "poll", ok: true, atMs: 16_500 }, { kind: "tick", atMs: 17_000 }], live).mode).toBe("polling");
  });

  it("keeps the first failure time while the dataset stays unavailable, and clears it when served", () => {
    const first = run([served("3"), { kind: "unavailable", dataset: "zones", at: "2026-10-02T10:00:00Z" }]);
    const again = run([{ kind: "unavailable", dataset: "zones", at: "2026-10-02T10:01:00Z" }], first);
    expect(again.datasets.zones.unavailableSince).toBe("2026-10-02T10:00:00Z");
    // What was shown stays shown: an outage is not an empty sky.
    expect(again.datasets.zones.version).toBe("3");
    expect(run([served("4")], again).datasets.zones).toMatchObject({ version: "4", unavailableSince: null });
  });

  it("records the publisher's staleness and the held snapshot", () => {
    const s = run([
      {
        kind: "served",
        dataset: "restrictions",
        version: "7",
        updatedAt: "2026-10-01T08:00:00Z",
        etag: '"restrictions:7"',
        stale: true,
        publisherStaleSince: "2026-10-02T09:59:00Z",
      },
    ]);
    expect(s.datasets.restrictions).toMatchObject({ stale: true, publisherStaleSince: "2026-10-02T09:59:00Z" });
    expect(run([served("1")]).datasets.zones.publisherStaleSince).toBeUndefined();
  });
});

describe("a dataset nothing has been published in (404 no_version)", () => {
  const noVersion: BannerEvent = { kind: "no_version", dataset: "restrictions" };

  it("is empty, not unavailable", () => {
    const s = run([noVersion]);
    expect(s.datasets.restrictions.empty).toBe(true);
    expect(s.datasets.restrictions.unavailableSince).toBeNull();
    expect(s.datasets.restrictions.version).toBeNull();
    expect(s.datasets.zones.empty).toBe(false);
  });

  it("clears an earlier unavailable, and a first version clears empty (the twin)", () => {
    const down = run([{ kind: "unavailable", dataset: "restrictions", at: "2026-10-02T10:00:00Z" }]);
    expect(down.datasets.restrictions.unavailableSince).not.toBeNull();
    const empty = run([noVersion], down);
    expect(empty.datasets.restrictions.unavailableSince).toBeNull();
    expect(empty.datasets.restrictions.empty).toBe(true);
    const published = run(
      [
        {
          kind: "served",
          dataset: "restrictions",
          version: "1",
          updatedAt: "2026-10-01T08:00:00Z",
          etag: '"restrictions:1"',
          stale: false,
          publisherStaleSince: undefined,
        },
      ],
      empty,
    );
    expect(published.datasets.restrictions.empty).toBe(false);
    expect(published.datasets.restrictions.version).toBe("1");
  });

  it("an outage after it is still shown as unavailable", () => {
    const s = run([noVersion, { kind: "unavailable", dataset: "restrictions", at: "2026-10-02T10:00:00Z" }]);
    expect(s.datasets.restrictions.unavailableSince).toBe("2026-10-02T10:00:00Z");
  });
});

describe("readFailure", () => {
  it("reads a 404 no_version as an empty dataset", () => {
    expect(readFailure({ status: 404, slug: "no_version" })).toBe("no_version");
  });

  it("reads every other failure as unavailable", () => {
    expect(readFailure({ status: 503, slug: "cis_stale" })).toBe("unavailable");
    expect(readFailure({ status: 500, slug: null })).toBe("unavailable");
    // Another 404, or a 404 without a problem body (a HEAD), is not no_version.
    expect(readFailure({ status: 404, slug: "not_found" })).toBe("unavailable");
    expect(readFailure({ status: 404, slug: null })).toBe("unavailable");
    // No answer at all: the network failed.
    expect(readFailure(new TypeError("Failed to fetch"))).toBe("unavailable");
    expect(readFailure(new Error("not a feature collection"))).toBe("unavailable");
    expect(readFailure(undefined)).toBe("unavailable");
  });
});
