import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { ACTION_ROLES, atLeast, mayAct, NAV_ITEMS, navFor, ROLES } from "./roles";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");

describe("navigation by role", () => {
  it("each role sees exactly its items", () => {
    const paths = (r: Parameters<typeof navFor>[0]) => navFor(r).map((i) => i.path);
    expect(paths("viewer")).toEqual(["", "/publications", "/restrictions", "/subscriptions"]);
    expect(paths("publisher_admin")).toEqual(["", "/publications", "/restrictions", "/subscriptions"]);
    expect(paths("admin")).toEqual(["", "/publications", "/restrictions", "/subscriptions", "/accounts", "/audit"]);
  });

  it("no role sees nothing (the pair: a role sees something)", () => {
    expect(navFor(null)).toEqual([]);
    expect(navFor("viewer").length).toBeGreaterThan(0);
  });

  it("the order of roles is viewer < publisher_admin < admin", () => {
    expect(ROLES).toEqual(["viewer", "publisher_admin", "admin"]);
    expect(atLeast("admin", "publisher_admin")).toBe(true);
    expect(atLeast("publisher_admin", "admin")).toBe(false);
    expect(atLeast("viewer", "viewer")).toBe(true);
  });

  it("a viewer is shown no action; a publisher_admin the re-notification and delivery ones; an admin all", () => {
    for (const a of Object.keys(ACTION_ROLES) as (keyof typeof ACTION_ROLES)[]) {
      expect(mayAct("viewer", a), a).toBe(false);
      expect(mayAct("admin", a), a).toBe(true);
      expect(mayAct(null, a), a).toBe(false);
    }
    expect(mayAct("publisher_admin", "republish")).toBe(true);
    expect(mayAct("publisher_admin", "retry")).toBe(true);
    expect(mayAct("publisher_admin", "accounts")).toBe(false);
  });

  it("each item's and action's role is its operation's x-role in api/openapi.yaml", () => {
    const spec = readFileSync(path.join(repo, "api/openapi.yaml"), "utf8");
    const roleOf = (p: string, method: string): string | null => {
      const at = spec.indexOf(`\n  ${p}:\n`);
      if (at < 0) return null;
      const block = spec.slice(at, spec.indexOf("\n  /", at + 3));
      const m = new RegExp(`\\n    ${method}:[\\s\\S]*?x-role: (\\w+)`).exec(block);
      return m?.[1] ?? null;
    };
    const page: Record<string, [string, string]> = {
      "": ["/v1/console/status", "get"],
      "/publications": ["/v1/console/publications", "get"],
      "/restrictions": ["/v1/console/restrictions", "get"],
      "/subscriptions": ["/v1/console/subscriptions", "get"],
      "/accounts": ["/v1/console/accounts", "get"],
      "/audit": ["/v1/console/audit", "get"],
    };
    for (const i of NAV_ITEMS) {
      const [p, m] = page[i.path] ?? ["", ""];
      expect(roleOf(p, m), i.path).toBe(i.minRole);
    }
    expect(roleOf("/v1/console/publications/{id}/republish", "post")).toBe(ACTION_ROLES.republish);
    expect(roleOf("/v1/console/subscriptions/{id}/suspend", "post")).toBe(ACTION_ROLES.suspend);
    expect(roleOf("/v1/console/subscriptions/{id}/resume", "post")).toBe(ACTION_ROLES.resume);
    expect(roleOf("/v1/console/subscriptions/{id}/deliveries/{delivery_id}/retry", "post")).toBe(ACTION_ROLES.retry);
    expect(roleOf("/v1/console/accounts/{id}", "patch")).toBe(ACTION_ROLES.accounts);
  });
});
