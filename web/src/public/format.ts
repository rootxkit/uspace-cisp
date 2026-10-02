// What the feature panel says about an ED-318 feature, as text, from the
// properties exactly as published. Nothing here converts a unit or a
// datum, places a time in another zone, or evaluates a schedule: a limit
// is shown in its own reference and unit ("0 m AGL", "1,000 ft AMSL"),
// a time as published with its offset, a daylight event by name. The
// CISP's own verdict (cis_applicability) is shown, never recomputed.
import { LOCALES, type Lang, type Translate } from "@rootxkit/uspace-ui/i18n";

/** A JSON object, or null. Every reader below takes the API's JSON as unknown. */
export function obj(v: unknown): Record<string, unknown> | null {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

function str(v: unknown): string | null {
  return typeof v === "string" && v !== "" ? v : null;
}

function strs(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string" && x !== "") : [];
}

const LANG_TAG: Readonly<Record<Lang, string>> = { ka: "ka", en: "en" };

/**
 * The text of an ED-318 TextShortType list ([{lang, text}]) in `lang`
 * (ka-GE for ka, en-GB for en), else the first one published; null when
 * there is none.
 */
export function localText(v: unknown, lang: Lang): string | null {
  if (typeof v === "string") return v === "" ? null : v;
  if (!Array.isArray(v)) return null;
  const items = v.map(obj).filter((x): x is Record<string, unknown> => x !== null);
  const mine = items.find((i) => str(i["lang"])?.toLowerCase().split("-")[0] === LANG_TAG[lang]);
  return str((mine ?? items[0])?.["text"]);
}

/** A number in the language's grouping and decimal mark, as published (up to 3 decimals). */
export function fmtNumber(v: number, lang: Lang): string {
  return new Intl.NumberFormat(LOCALES[lang], { maximumFractionDigits: 3 }).format(v);
}

/** One vertical limit: value, unit and reference as published. */
export interface Limit {
  value: number | null;
  /** "m" or "ft"; ED-318's default is metres. */
  uom: string;
  /** "AGL", "AMSL", "WGS84", or whatever was published. */
  reference: string | null;
}

const KNOWN_REFS = ["AGL", "AMSL", "WGS84"] as const;
const KNOWN_PURPOSES = ["AUTHORIZATION", "NOTIFICATION", "INFORMATION"] as const;

/** "0 m AGL", "1,000 ft AMSL", "unbounded" for a missing value; never converted. */
export function fmtLimit(l: Limit, lang: Lang, t: Translate): string {
  if (l.value === null) return t("cisp.limit.unbounded");
  const unit = l.uom === "ft" ? t("cisp.unit.ft") : l.uom === "m" ? t("cisp.unit.m") : l.uom;
  const ref =
    l.reference === null
      ? t("cisp.limit.no_reference")
      : (KNOWN_REFS as readonly string[]).includes(l.reference)
        ? t(`cisp.ref.${l.reference}`)
        : l.reference;
  return `${fmtNumber(l.value, lang)} ${unit} ${ref}`;
}

/** The lower and upper limits of one ED-318 `layer` object. */
export function limitsOf(layer: unknown): { lower: Limit; upper: Limit } | null {
  const l = obj(layer);
  if (l === null) return null;
  const uom = str(l["uom"]) ?? "m";
  const num = (v: unknown) => (typeof v === "number" && Number.isFinite(v) ? v : null);
  return {
    lower: { value: num(l["lower"]), uom, reference: str(l["lowerReference"]) },
    upper: { value: num(l["upper"]), uom, reference: str(l["upperReference"]) },
  };
}

/** "0 m AGL – 120 m AGL" for one layer. */
export function fmtLayer(layer: unknown, lang: Lang, t: Translate): string {
  const lim = limitsOf(layer);
  if (lim === null) return t("cisp.limit.not_published");
  return `${fmtLimit(lim.lower, lang, t)} – ${fmtLimit(lim.upper, lang, t)}`;
}

/** Every layer of a geometry: one for a simple geometry, one per member of a collection. */
export function layersOf(geometry: unknown): unknown[] {
  const g = obj(geometry);
  if (g === null) return [];
  if (g["type"] === "GeometryCollection" && Array.isArray(g["geometries"])) {
    return g["geometries"].map((m) => obj(m)?.["layer"]);
  }
  return [g["layer"]];
}

/** The circle of a Point with an ED-318 `extent`, as published; null otherwise. */
export function circleOf(geometry: unknown): { radiusM: number } | null {
  const g = obj(geometry);
  const e = obj(g?.["extent"]);
  if (g?.["type"] !== "Point" || e === null) return null;
  const r = e["radius"];
  return typeof r === "number" && Number.isFinite(r) ? { radiusM: r } : null;
}

/** A published date-time with its own offset, the "T" made a space: never moved to another zone. */
export function fmtPublishedTime(v: unknown): string | null {
  const s = str(v);
  return s === null ? null : s.replace("T", " ");
}

const DAY_CODES = ["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN", "ANY"] as const;
const EVENT_CODES = ["BMCT", "SR", "SS", "EECT"] as const;

function dayName(code: string, t: Translate): string {
  return (DAY_CODES as readonly string[]).includes(code) ? t(`cisp.day.${code}`) : code;
}

function endText(time: unknown, event: unknown, t: Translate): string {
  const ev = str(event);
  if (ev !== null) {
    return (EVENT_CODES as readonly string[]).includes(ev) ? `${t(`cisp.event.${ev}`)} (${ev})` : ev;
  }
  return str(time) ?? "—";
}

/**
 * The applicability periods as published, one line per period and one
 * per weekly schedule: "From 2026-10-01 00:00:00+04:00 to 2027-01-01
 * 00:00:00+04:00", "Monday, Tuesday: 08:00:00+04:00 to 18:00:00+04:00",
 * "Any day: morning civil twilight (BMCT) to evening civil twilight
 * (EECT)". An empty list is "permanent".
 */
export function fmtApplicability(periods: unknown, t: Translate): string[] {
  if (!Array.isArray(periods) || periods.length === 0) return [t("cisp.schedule.permanent")];
  const lines: string[] = [];
  for (const raw of periods) {
    const p = obj(raw);
    if (p === null) continue;
    if (p["permanent"] === "YES") {
      lines.push(t("cisp.schedule.permanent"));
      continue;
    }
    const from = fmtPublishedTime(p["startDateTime"]);
    const to = fmtPublishedTime(p["endDateTime"]);
    if (from !== null || to !== null) {
      lines.push(
        from !== null && to !== null
          ? t("cisp.schedule.between", { from, to })
          : from !== null
            ? t("cisp.schedule.from", { from })
            : t("cisp.schedule.until", { to: to ?? "" }),
      );
    }
    const schedule = Array.isArray(p["schedule"]) ? p["schedule"] : [];
    for (const rawS of schedule) {
      const s = obj(rawS);
      if (s === null) continue;
      const days = strs(s["day"]).map((d) => dayName(d, t));
      lines.push(
        t("cisp.schedule.weekly", {
          days: days.length > 0 ? days.join(", ") : "—",
          start: endText(s["startTime"], s["startEvent"], t),
          end: endText(s["endTime"], s["endEvent"], t),
        }),
      );
    }
    if (from === null && to === null && schedule.length === 0) lines.push(t("cisp.schedule.permanent"));
  }
  return lines.length > 0 ? lines : [t("cisp.schedule.permanent")];
}

export type Applicability = "applies" | "not_applicable" | "unknown";

/** The CISP's verdict on the feature at the chosen instant, or null when it gave none. */
export function applicabilityOf(properties: unknown): Applicability | null {
  const v = obj(obj(properties)?.["extendedProperties"])?.["cis_applicability"];
  return v === "applies" || v === "not_applicable" || v === "unknown" ? v : null;
}

/** The sentence the panel shows for a verdict; `unknown` says why it is drawn anyway. */
export function fmtApplicabilityVerdict(a: Applicability | null, t: Translate): string {
  return t(`cisp.applicability.${a ?? "unstated"}`);
}

/** One zone authority, its published members as label/value rows. */
export function authorityRows(raw: unknown, lang: Lang, t: Translate): { label: string; value: string }[] {
  const a = obj(raw);
  if (a === null) return [];
  const rows: { label: string; value: string }[] = [];
  const add = (key: string, value: string | null) => {
    if (value !== null) rows.push({ label: t(`cisp.authority.${key}`), value });
  };
  add("name", localText(a["name"], lang));
  const purpose = str(a["purpose"]);
  add(
    "purpose",
    purpose === null ? null : (KNOWN_PURPOSES as readonly string[]).includes(purpose) ? t(`cisp.purpose.${purpose}`) : purpose,
  );
  add("service", localText(a["service"], lang));
  add("contact_name", localText(a["contactName"], lang));
  add("email", str(a["email"]));
  add("phone", str(a["phone"]));
  add("site", str(a["siteURL"]));
  add("interval_before", str(a["intervalBefore"]));
  return rows;
}
