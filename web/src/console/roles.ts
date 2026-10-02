// The console roles and what each one is shown (docs/PLAN.md §8.2,
// spec 01 §2). A courtesy to the layout, never a control: an item or a
// button hidden here is still refused by the API, and a page reached by
// typing its address shows the API's 403 (src/console/ProblemNotice).
import type { components } from "../api/types";

export type ConsoleRole = components["schemas"]["ConsoleRole"];

/** Lowest first; a role may do what every role below it may. */
export const ROLES: readonly ConsoleRole[] = ["viewer", "publisher_admin", "admin"];

export function isRole(v: unknown): v is ConsoleRole {
  return typeof v === "string" && (ROLES as readonly string[]).includes(v);
}

/** True when `role` is `min` or above; false for no role. */
export function atLeast(role: ConsoleRole | null, min: ConsoleRole): boolean {
  if (role === null) return false;
  return ROLES.indexOf(role) >= ROLES.indexOf(min);
}

export interface NavItem {
  /** The path under /<locale>/console. */
  path: string;
  /** The catalogue key of its label. */
  labelKey: string;
  /** The lowest role the API serves it to (the operation's x-role). */
  minRole: ConsoleRole;
}

/** Every console page, in navigation order, with its operation's x-role. */
export const NAV_ITEMS: readonly NavItem[] = [
  { path: "", labelKey: "cisp.console.nav.overview", minRole: "viewer" },
  { path: "/publications", labelKey: "cisp.console.nav.publications", minRole: "viewer" },
  { path: "/restrictions", labelKey: "cisp.console.nav.restrictions", minRole: "viewer" },
  { path: "/subscriptions", labelKey: "cisp.console.nav.subscriptions", minRole: "viewer" },
  { path: "/accounts", labelKey: "cisp.console.nav.accounts", minRole: "admin" },
  { path: "/audit", labelKey: "cisp.console.nav.audit", minRole: "admin" },
];

/** The items `role` is shown; none without a role. */
export function navFor(role: ConsoleRole | null): NavItem[] {
  return NAV_ITEMS.filter((i) => atLeast(role, i.minRole));
}

/**
 * The console actions and the role each needs (the operations' x-role).
 * Every one is about re-notification, subscriptions, deliveries or
 * accounts; none writes content (hard rule 2).
 */
export const ACTION_ROLES = {
  republish: "publisher_admin",
  suspend: "publisher_admin",
  resume: "publisher_admin",
  retry: "publisher_admin",
  accounts: "admin",
} as const satisfies Record<string, ConsoleRole>;

export type ConsoleAction = keyof typeof ACTION_ROLES;

/** True when `role` is shown the action's button. */
export function mayAct(role: ConsoleRole | null, action: ConsoleAction): boolean {
  return atLeast(role, ACTION_ROLES[action]);
}
