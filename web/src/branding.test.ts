import { describe, expect, it } from "vitest";
import { DEFAULT_BRAND, parseBranding } from "./branding";

describe("branding", () => {
  it("defaults are code names", () => {
    expect(DEFAULT_BRAND.name).toBe("U-space CIS");
    expect(DEFAULT_BRAND.contact).toBeNull();
  });

  it("a file sets name, logo, contact and accent", () => {
    const b = parseBranding(
      JSON.stringify({ name: "Demo CIS", logo_url: "/brand/logo.svg", contact: "ops@example.test", accent: "#112233" }),
      "brand.json",
    );
    expect(b).toEqual({
      name: "Demo CIS",
      shortName: "Demo CIS",
      logoUrl: "/brand/logo.svg",
      contact: "ops@example.test",
      accent: "#112233",
    });
  });

  it("refuses an unknown member, naming it", () => {
    expect(() => parseBranding(JSON.stringify({ colour: "red" }), "brand.json")).toThrow(/unknown member colour/);
  });

  it("refuses an accent that is not a colour", () => {
    expect(() => parseBranding(JSON.stringify({ accent: "blue" }), "brand.json")).toThrow(/accent/);
  });

  it("refuses a document that is not an object", () => {
    expect(() => parseBranding("[]", "brand.json")).toThrow(/object/);
    expect(() => parseBranding("{", "brand.json")).toThrow(/not JSON/);
  });
});
