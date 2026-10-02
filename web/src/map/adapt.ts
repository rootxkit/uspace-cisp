// The one hand-written mapping from the API's features to the kit's view
// models (uspace-ui PLAN §3.14). It copies what the API said and decides
// nothing: the geometry is passed as published, or, for a circle, as the
// outline the CISP drew (extendedProperties.cis_display_geometry, Q43);
// the limits are passed
// only when published in metres (the kit's view model holds metres, and
// a limit in feet is never converted: the panel shows it as published),
// and `applies` is the CISP's own cis_applicability.
import { isRestrictionState, isVerticalRef, isZoneType, type ZoneView } from "@rootxkit/uspace-ui/model";
import type { RestrictionView } from "@rootxkit/uspace-ui/layers";
import type { Lang } from "@rootxkit/uspace-ui/i18n";
import { applicabilityOf, limitsOf, localText, obj } from "../public/format";

/** One served feature, kept whole for the panel beside its view model. */
export interface MapFeature {
  id: string;
  dataset: "zones" | "uspace_airspace" | "restrictions";
  view: RestrictionView;
  /** The feature as the API sent it. */
  raw: Record<string, unknown>;
  /** The map draws the CISP's outline of a circle (cis_display_geometry). */
  drawnFromOutline: boolean;
}

/** The CISP's drawable outline of a feature with a circle, or null. */
export function displayGeometryOf(properties: unknown): Record<string, unknown> | null {
  const g = obj(obj(obj(properties)?.["extendedProperties"])?.["cis_display_geometry"]);
  return g !== null && (g["type"] === "Polygon" || g["type"] === "GeometryCollection") ? g : null;
}

function metres(layer: unknown) {
  const lim = limitsOf(layer);
  if (lim === null || lim.lower.uom !== "m") return { lowerLimitM: null, upperLimitM: null };
  return { lowerLimitM: lim.lower.value, upperLimitM: lim.upper.value };
}

function refOf(v: unknown) {
  return isVerticalRef(v) ? v : null;
}

/**
 * The view of one feature, or null when it has no identifier or a zone
 * type the kit cannot draw (counted by the caller and listed, never
 * dropped silently).
 */
export function toView(
  raw: unknown,
  dataset: MapFeature["dataset"],
  meta: { version: string | null; updatedAt: string | null },
  lang: Lang,
): MapFeature | null {
  const f = obj(raw);
  const p = obj(f?.["properties"]);
  if (f === null || p === null) return null;
  const id = typeof p["identifier"] === "string" ? p["identifier"] : null;
  const type = p["type"];
  if (id === null || !isZoneType(type)) return null;
  const geometry = obj(f["geometry"]);
  const outline = displayGeometryOf(p);
  const layer = geometry?.["type"] === "GeometryCollection" ? null : geometry?.["layer"];
  const lim = obj(layer);
  const verdict = applicabilityOf(p);
  const restriction = obj(obj(p["extendedProperties"])?.["cis_restriction"]);
  const state = restriction?.["state"];
  const view: RestrictionView = {
    identifier: id,
    name: localText(p["name"], lang),
    type,
    variant: typeof p["variant"] === "string" ? p["variant"] : null,
    reason: Array.isArray(p["reason"]) ? p["reason"].filter((r): r is string => typeof r === "string") : [],
    message: localText(p["message"], lang),
    ...metres(layer),
    lowerRef: refOf(lim?.["lowerReference"]),
    upperRef: refOf(lim?.["upperReference"]),
    geometry: (outline ?? geometry ?? { type: "GeometryCollection", geometries: [] }) as unknown as ZoneView["geometry"],
    applies: verdict === "applies" ? true : verdict === "not_applicable" ? false : null,
    restrictionState: isRestrictionState(state) ? state : null,
    version: meta.version,
    updatedAt: meta.updatedAt,
    startsAt: typeof restriction?.["starts_at"] === "string" ? restriction["starts_at"] : null,
    endsAt: typeof restriction?.["ends_at"] === "string" ? restriction["ends_at"] : null,
  };
  return { id, dataset, view, raw: f, drawnFromOutline: outline !== null };
}
