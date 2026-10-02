import { describe, expect, it } from "vitest";
import { parseMapView } from "./runtime";

describe("the map's first view", () => {
  it("reads lng,lat and zoom", () => {
    expect(parseMapView("44.8, 41.7", "9")).toEqual({ view: { center: [44.8, 41.7], zoom: 9 } });
  });

  it("names the missing variable instead of choosing a place", () => {
    expect(parseMapView(undefined, "9")).toEqual({ problem: "NEXT_PUBLIC_MAP_CENTER is not set" });
    expect(parseMapView("44.8,41.7", "")).toEqual({ problem: "NEXT_PUBLIC_MAP_ZOOM is not set" });
  });

  it("refuses a centre that is not lng,lat in range, and a zoom out of range", () => {
    expect(parseMapView("41.7", "9")).toHaveProperty("problem");
    expect(parseMapView("44.8,91", "9")).toHaveProperty("problem");
    expect(parseMapView("x,41.7", "9")).toHaveProperty("problem");
    expect(parseMapView("44.8,41.7", "23")).toHaveProperty("problem");
  });
});
