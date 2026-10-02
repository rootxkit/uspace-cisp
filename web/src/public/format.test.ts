import { describe, expect, it } from "vitest";
import { createTranslator } from "@rootxkit/uspace-ui/i18n";
import { catalogues } from "../i18n/catalogues";
import base from "../../test/fixtures/ed318_roundtrip.base.json";
import vectors from "../../test/fixtures/zones_applicability.json";
import {
  applicabilityOf,
  circleOf,
  fmtApplicability,
  fmtApplicabilityVerdict,
  fmtLayer,
  layersOf,
  localText,
  obj,
} from "./format";

const en = createTranslator("en", catalogues);
const ka = createTranslator("ka", catalogues);

function feature(id: string): Record<string, unknown> {
  const f = base.features.find((x) => x.properties.identifier === id);
  if (f === undefined) throw new Error(`no ${id} in the fixture`);
  return f as unknown as Record<string, unknown>;
}

const DAY_EN: Record<string, string> = {
  MON: "Monday",
  TUE: "Tuesday",
  WED: "Wednesday",
  THU: "Thursday",
  FRI: "Friday",
  SAT: "Saturday",
  SUN: "Sunday",
  ANY: "Any day",
};

describe("vertical limits", () => {
  it("are shown in their own reference: metres AGL to metres AGL", () => {
    expect(fmtLayer({ lower: 0, lowerReference: "AGL", upper: 120, upperReference: "AGL", uom: "m" }, "en", en)).toBe(
      "0 m AGL – 120 m AGL",
    );
  });

  it("are never converted between references", () => {
    expect(fmtLayer({ lower: 600, lowerReference: "AMSL", upper: 800, upperReference: "AMSL", uom: "m" }, "en", en)).toBe(
      "600 m AMSL – 800 m AMSL",
    );
  });

  it("stay in feet when published in feet", () => {
    const [layer] = layersOf(feature("TSD001")["geometry"]);
    expect(fmtLayer(layer, "en", en)).toBe("0 ft AGL – 2,500 ft AMSL");
    expect(fmtLayer(layer, "ka", ka)).toContain("ფტ");
  });

  it("default to metres when the unit is not published (ED-318)", () => {
    expect(fmtLayer({ lower: 0, lowerReference: "AGL", upper: 50, upperReference: "AGL" }, "en", en)).toBe("0 m AGL – 50 m AGL");
  });

  it("show a missing limit as unbounded, never as zero", () => {
    const [layer] = layersOf(feature("TSN001")["geometry"]);
    expect(fmtLayer(layer, "en", en)).toBe("unbounded – unbounded");
  });

  it("list every layer of a geometry collection", () => {
    const layers = layersOf(feature("TSC001")["geometry"]).map((l) => fmtLayer(l, "en", en));
    expect(layers).toEqual(["0 m AGL – 50 m AGL", "50 m AGL – 150 m AGL"]);
  });

  it("keep a reference the panel does not know as published", () => {
    expect(fmtLayer({ lower: 0, lowerReference: "SFC", upper: 10, upperReference: "AGL", uom: "m" }, "en", en)).toBe(
      "0 m SFC – 10 m AGL",
    );
  });
});

describe("the schedule as published", () => {
  it.each(vectors.cases.map((c) => [c.name, c.input.applicability] as const))("%s", (_name, periods) => {
    const text = fmtApplicability(periods, en).join("\n");
    for (const raw of periods) {
      const p = obj(raw) ?? {};
      if (p["permanent"] === "YES") expect(text).toContain("Permanent");
      for (const k of ["startDateTime", "endDateTime"]) {
        const v = p[k];
        if (typeof v === "string") expect(text).toContain(v.replace("T", " "));
      }
      for (const s of Array.isArray(p["schedule"]) ? p["schedule"] : []) {
        const sched = obj(s) ?? {};
        for (const k of ["startTime", "endTime"]) {
          const v = sched[k];
          if (typeof v === "string") expect(text).toContain(v);
        }
        for (const d of Array.isArray(sched["day"]) ? sched["day"] : []) expect(text).toContain(DAY_EN[String(d)]);
      }
    }
  });

  it("names daylight events and keeps the times with their offsets", () => {
    const tsd = fmtApplicability(obj(feature("TSD001")["properties"])?.["limitedApplicability"], en);
    expect(tsd).toEqual([
      "From 2026-10-01 00:00:00Z to 2026-10-08 00:00:00Z",
      "Any day: morning civil twilight (BMCT) to evening civil twilight (EECT)",
    ]);
    const tsr = fmtApplicability(obj(feature("TSR001")["properties"])?.["limitedApplicability"], en);
    expect(tsr).toEqual([
      "From 2026-10-01 00:00:00+04:00 to 2027-01-01 00:00:00+04:00",
      "Monday, Tuesday, Wednesday, Thursday, Friday: 08:00:00+04:00 to 18:00:00+04:00",
    ]);
  });

  it("calls a feature without limited applicability permanent", () => {
    expect(fmtApplicability(undefined, en)).toEqual(["Permanent (no limited applicability published)"]);
  });
});

describe("the CISP's verdict", () => {
  it("reads cis_applicability and nothing else", () => {
    expect(applicabilityOf({ extendedProperties: { cis_applicability: "not_applicable" } })).toBe("not_applicable");
    expect(applicabilityOf({ extendedProperties: { cis_applicability: "maybe" } })).toBeNull();
    expect(applicabilityOf({})).toBeNull();
  });

  it("says why an unknown one is drawn", () => {
    expect(fmtApplicabilityVerdict("unknown", en)).toMatch(/could not evaluate/);
    expect(fmtApplicabilityVerdict("unknown", en)).toMatch(/drawn in full/);
    expect(fmtApplicabilityVerdict("applies", en)).not.toMatch(/could not evaluate/);
  });
});

describe("text and shape", () => {
  it("picks the name in the page's language, else the first published", () => {
    const name = obj(feature("TSU001")["properties"])?.["name"];
    expect(localText(name, "ka")).toBe("თბილისის U-space საჰაერო სივრცე (ტესტი)");
    expect(localText(name, "en")).toBe("Tbilisi U-space airspace (test)");
    expect(localText(obj(feature("TSR001")["properties"])?.["name"], "ka")).toBe("Test authorisation zone");
  });

  it("reads a circle's radius as published and nothing from a polygon", () => {
    expect(circleOf(feature("TSN001")["geometry"])).toEqual({ radiusM: 250.5 });
    expect(circleOf(feature("TSR001")["geometry"])).toBeNull();
  });
});
