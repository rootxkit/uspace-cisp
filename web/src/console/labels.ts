// The words for names the API sends as codes: an audit event type, a
// status component and an instance counter ("<component>.<counter>",
// GET /v1/console/status). A name the catalogue words is shown by its
// label with the code in the tooltip; a name it does not know (the API
// may add one) is shown as sent, never dropped and never guessed at.
import type { Translate } from "@rootxkit/uspace-ui/i18n";
import en from "../i18n/en.json";

const KNOWN: ReadonlySet<string> = new Set(Object.keys(en));

function known(key: string): boolean {
  return KNOWN.has(key);
}

/** The label of an audit event type, or null when the console does not word it. */
export function eventLabel(t: Translate, type: string): string | null {
  const key = `cisp.console.audit.event.${type}`;
  return known(key) ? t(key) : null;
}

/** The label of a status component, or the component as sent. */
export function componentLabel(t: Translate, component: string): string {
  const key = `cisp.console.component.${component}`;
  return known(key) ? t(key) : component;
}

export interface CounterShown {
  /** The counter as the API names it. */
  key: string;
  component: string;
  /** The counter's label, or null when the console does not word it. */
  label: string | null;
  value: number;
}

/** A counter's component and name split at the first dot ("console_auth.session_accepted"). */
export function splitCounter(key: string): { component: string; name: string } {
  const dot = key.indexOf(".");
  return dot < 0 ? { component: "", name: key } : { component: key.slice(0, dot), name: key.slice(dot + 1) };
}

/** The counters grouped by component, both in the API's order of names. */
export function countersShown(t: Translate, counters: Record<string, number>): { component: string; label: string; counters: CounterShown[] }[] {
  const groups = new Map<string, CounterShown[]>();
  for (const [key, value] of Object.entries(counters).sort(([a], [b]) => a.localeCompare(b))) {
    const { component, name } = splitCounter(key);
    const labelKey = `cisp.console.counter.${name}`;
    const row: CounterShown = { key, component, label: known(labelKey) ? t(labelKey) : null, value };
    groups.set(component, [...(groups.get(component) ?? []), row]);
  }
  return [...groups].map(([component, rows]) => ({ component, label: component === "" ? "—" : componentLabel(t, component), counters: rows }));
}

/** The label of an audit payload member, or null when the console does not word it. */
export function payloadKeyLabel(t: Translate, member: string): string | null {
  const key = `cisp.console.audit.member.${member}`;
  return known(key) ? t(key) : null;
}
