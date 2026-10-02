// Branding is configuration (spec 08 Q15; docs/PLAN.md §11): the name,
// logo and contact come from the JSON file CISP_BRANDING_FILE names, read
// once at start. The defaults are code names, never a real organisation's.
//
//   {"name": "...", "short_name": "...", "logo_url": "/brand/logo.svg",
//    "contact": "...", "accent": "#1f5fc4"}
//
// A file that cannot be read or holds an unknown member or a wrong type
// is a start-up error naming the member: a deployment that looks branded
// but is not is worse than one that fails.
import { readFileSync } from "node:fs";
import type { Brand } from "@rootxkit/uspace-ui/theme";

export const DEFAULT_BRAND: Brand = {
  name: "U-space CIS",
  shortName: "CIS",
  logoUrl: null,
  contact: null,
  accent: null,
};

const MEMBERS = {
  name: "name",
  short_name: "shortName",
  logo_url: "logoUrl",
  contact: "contact",
  accent: "accent",
} as const;

type Member = keyof typeof MEMBERS;

function isMember(k: string): k is Member {
  return Object.hasOwn(MEMBERS, k);
}

/** The brand a branding document describes, over the defaults. */
export function parseBranding(text: string, source: string): Brand {
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch (err) {
    throw new Error(`${source}: not JSON: ${err instanceof Error ? err.message : String(err)}`);
  }
  if (typeof doc !== "object" || doc === null || Array.isArray(doc)) {
    throw new Error(`${source}: want a JSON object`);
  }
  const brand: Brand = { ...DEFAULT_BRAND };
  for (const [k, v] of Object.entries(doc)) {
    if (!isMember(k)) throw new Error(`${source}: unknown member ${k}`);
    if (v === null && k !== "name" && k !== "short_name") continue;
    if (typeof v !== "string" || v.trim() === "") throw new Error(`${source}: ${k} must be a non-empty string`);
    if (k === "accent" && !/^#[0-9a-fA-F]{6}$/.test(v)) throw new Error(`${source}: accent must be #rrggbb`);
    brand[MEMBERS[k]] = v;
  }
  if (!Object.hasOwn(doc, "short_name")) brand.shortName = brand.name;
  return brand;
}

let cached: Brand | null = null;

/** The deployment's brand: CISP_BRANDING_FILE, else the defaults. */
export function branding(): Brand {
  if (cached !== null) return cached;
  const file = process.env["CISP_BRANDING_FILE"];
  cached = file === undefined || file === "" ? DEFAULT_BRAND : parseBranding(readFileSync(file, "utf8"), file);
  return cached;
}
