import { describe, expect, it } from "vitest";
import base from "../../test/fixtures/ed318_roundtrip.base.json";
import { toView } from "./adapt";

const OUTLINE = {
  type: "Polygon",
  coordinates: [
    [
      [44.9, 41.7523],
      [44.897, 41.75],
      [44.9, 41.7477],
      [44.903, 41.75],
      [44.9, 41.7523],
    ],
  ],
};

function feature(id: string, extra: Record<string, unknown> = {}): unknown {
  const f = base.features.find((x) => x.properties.identifier === id);
  if (f === undefined) throw new Error(id);
  return { ...f, properties: { ...f.properties, extendedProperties: { ...extra } } };
}

const meta = { version: "1", updatedAt: "2026-10-01T08:00:00Z" };

describe("the view of a served feature", () => {
  it("draws a circle from the CIS's cis_display_geometry", () => {
    const v = toView(feature("TSN001", { cis_display_geometry: OUTLINE }), "zones", meta, "en");
    expect(v?.drawnFromOutline).toBe(true);
    expect(v?.view.geometry).toEqual(OUTLINE);
  });

  it("passes a circle without an outline as published, marked not drawn from one", () => {
    const v = toView(feature("TSN001"), "zones", meta, "en");
    expect(v?.drawnFromOutline).toBe(false);
    expect(v?.view.geometry).toMatchObject({ type: "Point", coordinates: [44.9, 41.75] });
  });

  it("ignores a display member that is not a polygon geometry", () => {
    const v = toView(feature("TSN001", { cis_display_geometry: { type: "Point" } }), "zones", meta, "en");
    expect(v?.drawnFromOutline).toBe(false);
  });

  it("maps the applicability and the restriction state as the CIS sent them", () => {
    const v = toView(feature("TSR001", { cis_applicability: "not_applicable" }), "zones", meta, "en");
    expect(v?.view.applies).toBe(false);
    expect(v?.view.lowerLimitM).toBe(0);
    const ft = toView(feature("TSD001", { cis_restriction: { state: "planned" } }), "restrictions", meta, "en");
    // A limit in feet is never converted into the kit's metres.
    expect(ft?.view.lowerLimitM).toBeNull();
    expect(ft?.view.restrictionState).toBe("planned");
  });
});
