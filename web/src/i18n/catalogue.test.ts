import { describe, expect, it } from "vitest";
import en from "./en.json";
import ka from "./ka.json";

const GEORGIAN = /[Ⴀ-ჿᲐ-Ჿⴀ-⴯]/u;

describe("catalogues", () => {
  it("ka and en hold the same keys", () => {
    expect(Object.keys(ka).sort()).toEqual(Object.keys(en).sort());
  });

  it("a key missing from one catalogue is found", () => {
    const short: Record<string, string> = { ...ka };
    delete short["cisp.app.title"];
    expect(Object.keys(short).sort()).not.toEqual(Object.keys(en).sort());
  });

  it("no value is empty", () => {
    for (const [k, v] of [...Object.entries(ka), ...Object.entries(en)]) {
      expect(v.trim(), k).not.toBe("");
    }
  });

  it("the Georgian catalogue is Georgian", () => {
    expect(ka["cisp.app.title"]).toMatch(GEORGIAN);
    expect(en["cisp.app.title"]).not.toMatch(GEORGIAN);
  });
});
