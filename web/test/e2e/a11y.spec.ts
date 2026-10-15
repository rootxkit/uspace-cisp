// WCAG 2.2 AA with axe on every page of the redesigned frame: the public
// map and the USSP list, the sign-in, and each signed-in console page, in
// English and Georgian, light and dark. axe-core is the one the kit's
// `test` entry point runs (its peer, pinned by pnpm-lock.yaml), read from
// beside the kit so web/ adds no dependency, and evaluated in the page
// through the debugging protocol (the page's CSP governs page scripts,
// not this).
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { expect, test, type Page } from "@playwright/test";

const kit = createRequire(import.meta.url).resolve("@rootxkit/uspace-ui/test");
const AXE_SOURCE = readFileSync(createRequire(kit).resolve("axe-core/axe.min.js"), "utf8");
// The success criteria of levels A and AA up to 2.2 (the kit's WCAG_22_AA_TAGS).
const WCAG_22_AA = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"];

// The mock's test accounts and code (test/mock-console.mjs), not credentials.
const ADMIN = { username: "admin1", password: "admin1-test-password" };
const CODE = "246810";

/** One line per violation and node: rule, target, what axe measured. */
async function violations(page: Page): Promise<string[]> {
  await page.evaluate(AXE_SOURCE);
  return page.evaluate(async (tags) => {
    const axe = (globalThis as unknown as { axe: { run(ctx: Document, o: object): Promise<{ violations: { id: string; nodes: { target: string[]; failureSummary?: string }[] }[] }> } }).axe;
    const r = await axe.run(document, { runOnly: { type: "tag", values: tags }, resultTypes: ["violations"] });
    return r.violations.flatMap((v) => v.nodes.map((n) => `${v.id} ${n.target.join(" ")}: ${(n.failureSummary ?? "").replace(/\s+/g, " ")}`));
  }, WCAG_22_AA);
}

async function signInAdmin(page: Page, lang: string): Promise<void> {
  await page.goto(`/${lang}/console/login`);
  for (const body of [ADMIN, { username: ADMIN.username, otp: CODE }]) {
    const status = await page.evaluate(async (b) => {
      const res = await fetch("/_bff/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(b) });
      return res.status;
    }, body);
    expect(status).toBe(200);
  }
}

/** Waits for what each page shows once its reads are in. */
const PUBLIC: [string, string][] = [
  ["", '[data-dataset="zones"]'],
  ["/ussps", "[data-ussp]"],
  ["/console/login", "form"],
];
const CONSOLE: [string, string][] = [
  // The overview's second row of tiles loads on its own (the summary).
  ["/console", '[data-testid="overview-summary"] [data-slot="stat-tile"]'],
  ["/console/publications?dataset=zones", "tr[data-version]"],
  ["/console/publications/pub-zones-2", '[data-testid="diff"]'],
  ["/console/restrictions", "tr[data-restriction]"],
  ["/console/subscriptions", "tr[data-subscription]"],
  ["/console/subscriptions/sub-02", "tr[data-delivery]"],
  ["/console/accounts", "tr[data-account]"],
  ["/console/audit", "form"],
];

test.beforeEach(async ({ request }) => {
  expect((await request.post("/__mock/reset")).ok()).toBe(true);
});

for (const lang of ["en", "ka"] as const) {
  for (const colorScheme of ["light", "dark"] as const) {
    test.describe(`${lang}, ${colorScheme}`, () => {
      test.use({ colorScheme });

      test("the public pages and the sign-in pass axe at WCAG 2.2 AA", async ({ page }) => {
        for (const [path, ready] of PUBLIC) {
          await page.goto(`/${lang}${path}`);
          await expect(page.locator(ready).first()).toBeVisible();
          expect(await violations(page), `/${lang}${path}`).toEqual([]);
        }
      });

      test("the map's accordion passes axe with a row expanded, a section collapsed and a dataset empty", async ({ page, request }) => {
        expect((await request.post("/__mock/state", { data: { unpublished: ["uspace_airspace"] } })).ok()).toBe(true);
        await page.goto(`/${lang}`);
        await expect(page.locator('[data-dataset="uspace_airspace"]')).toHaveAttribute("data-empty", "true");
        await page.locator('[data-feature="DAR00A1"]').click();
        await expect(page.locator('[data-panel="DAR00A1"]')).toBeVisible();
        await page.locator('[data-section-toggle="zones"]').click();
        await expect(page.locator('[data-section-toggle="zones"]')).toHaveAttribute("aria-expanded", "false");
        expect(await violations(page), `/${lang}`).toEqual([]);
      });

      test("every signed-in console page passes axe at WCAG 2.2 AA", async ({ page }) => {
        await signInAdmin(page, lang);
        for (const [path, ready] of CONSOLE) {
          await page.goto(`/${lang}${path}`);
          await expect(page.locator(ready).first()).toBeVisible();
          expect(await violations(page), `/${lang}${path}`).toEqual([]);
        }
      });
    });
  }
}

// The pair (E-01): the same check fails on a page that has a violation.
test("the check reports a violation when there is one", async ({ page }) => {
  await page.goto("/en/console/login");
  await expect(page.locator("form")).toBeVisible();
  await page.evaluate(() => {
    const img = document.createElement("img");
    img.src = "data:image/gif;base64,R0lGODlhAQABAAAAACw=";
    document.querySelector("main")?.append(img);
  });
  expect((await violations(page)).some((v) => v.startsWith("image-alt "))).toBe(true);
});

// WCAG 1.4.10 Reflow: at 320 CSS px no page scrolls sideways (a wide
// table scrolls inside its own region, which is allowed).
test.describe("at 320 CSS px", () => {
  test.use({ viewport: { width: 320, height: 640 } });

  test("no page scrolls sideways", async ({ page }) => {
    const overflowPx = async (path: string, ready: string) => {
      await page.goto(path);
      await expect(page.locator(ready).first()).toBeAttached();
      return page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    };
    for (const [path, ready] of PUBLIC) {
      expect(await overflowPx(`/ka${path}`, ready), `/ka${path}`).toBeLessThanOrEqual(0);
    }
    await signInAdmin(page, "ka");
    for (const [path, ready] of CONSOLE) {
      expect(await overflowPx(`/ka${path}`, ready), `/ka${path}`).toBeLessThanOrEqual(0);
    }
  });
});
