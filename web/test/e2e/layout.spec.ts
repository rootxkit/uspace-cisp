// The console's tables at the widths it is used at (1024 and 1440 px,
// the sidebar open), in English light and Georgian dark: no page and no
// table wider than its card; ids, times and numbers on one line; no raw
// counter name or event code outside the expanders that hold them; and
// every time in UTC, laid out for the page's language. With UI_SHOTS_DIR
// set, each page is saved there at 1024 px.
import path from "node:path";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { expect, test, type Locator, type Page } from "@playwright/test";

const kit = createRequire(import.meta.url).resolve("@rootxkit/uspace-ui/test");
const AXE_SOURCE = readFileSync(createRequire(kit).resolve("axe-core/axe.min.js"), "utf8");
const WCAG_22_AA = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"];
const SHOTS = process.env["UI_SHOTS_DIR"];

// The mock's test account and code (test/mock-console.mjs), not credentials.
const ADMIN = { username: "admin1", password: "admin1-test-password" };
const CODE = "246810";

/** The counter names test/mock-console.mjs serves, and the audit's event codes: never shown outside an expander. */
const RAW_COUNTERS = /\b(auth\.accepted|console_auth\.\w+|console\.console_logins|nats\.nats_slow_consumer|stream\.frames_coalesced)\b/;
const RAW_EVENTS = /\b(publication_accepted|session_issued|login_challenge_issued|console_republish|login_failed)\b/;
/** A time as the console shows it: in UTC, the month in the page's language. */
const UTC_TIME = {
  en: /^\d{1,2} (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4}, \d{2}:\d{2}:\d{2} UTC$/,
  ka: /^\d{1,2} (იან|თებ|მარ|აპრ|მაი|ივნ|ივლ|აგვ|სექ|ოქტ|ნოე|დეკ)\. \d{4}, \d{2}:\d{2}:\d{2} UTC$/u,
};
/** The viewer's zone, which the console never shows. */
const LOCAL_ZONE = /GMT[+-]\d|\bGMT\b/;

test.beforeEach(async ({ request }) => {
  expect((await request.post("/__mock/reset")).ok()).toBe(true);
});

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

async function expectAccessible(page: Page, where: string): Promise<void> {
  await page.evaluate(AXE_SOURCE);
  const found = await page.evaluate(async (tags) => {
    const axe = (globalThis as unknown as { axe: { run(ctx: Document, o: object): Promise<{ violations: { id: string; nodes: { target: string[] }[] }[] }> } }).axe;
    const r = await axe.run(document, { runOnly: { type: "tag", values: tags }, resultTypes: ["violations"] });
    return r.violations.flatMap((v) => v.nodes.map((n) => `${v.id} ${n.target.join(" ")}`));
  }, WCAG_22_AA);
  expect(found, where).toEqual([]);
}

/** No horizontal scroll: neither the page nor a table wider than the card it sits in. */
async function expectNoOverflow(page: Page, where: string): Promise<void> {
  const o = await page.evaluate(() => ({
    page: document.documentElement.scrollWidth - document.documentElement.clientWidth,
    tables: [...document.querySelectorAll("main table")].map((t) => {
      const box = t.closest('[role="region"]') ?? t.parentElement;
      return { over: t.scrollWidth - (box?.clientWidth ?? t.scrollWidth), id: t.getAttribute("data-testid") ?? "" };
    }),
  }));
  expect(o.page, `${where}: the page scrolls sideways`).toBeLessThanOrEqual(0);
  for (const t of o.tables) expect(t.over, `${where}: the table ${t.id} is wider than its card`).toBeLessThanOrEqual(1);
}

/** The element's content is on one line (the box of its text is not taller than one line of it). */
async function expectOneLine(l: Locator, what: string): Promise<void> {
  const r = await l.evaluate((e) => {
    const s = getComputedStyle(e);
    const line = parseFloat(s.lineHeight) || parseFloat(s.fontSize) * 1.5;
    const range = document.createRange();
    range.selectNodeContents(e);
    return { h: range.getBoundingClientRect().height, line };
  });
  expect(r.h, `${what} wraps`).toBeLessThan(r.line * 1.6);
}

/** Every time on the page is in UTC in the page's language; none is in the viewer's zone. */
async function expectUtcTimes(page: Page, lang: "en" | "ka", where: string): Promise<void> {
  const times = page.getByTestId("utc-time");
  expect(await times.count(), `${where}: times`).toBeGreaterThan(0);
  for (const t of await times.all()) {
    if (!(await t.isVisible())) continue;
    await expect(t, where).toHaveText(UTC_TIME[lang]);
    await expectOneLine(t, `${where}: a time`);
  }
  expect(await page.locator("body").innerText(), `${where}: a time in the viewer's zone`).not.toMatch(LOCAL_ZONE);
}

/** No raw counter name or event code in what the page shows (innerText leaves closed expanders out). */
async function expectNoRawCodes(page: Page, where: string): Promise<void> {
  const text = await page.locator("body").innerText();
  expect(text, `${where}: a raw counter name`).not.toMatch(RAW_COUNTERS);
  expect(text, `${where}: a raw event code`).not.toMatch(RAW_EVENTS);
}

async function shot(page: Page, name: string, width: number): Promise<void> {
  if (SHOTS !== undefined && width === 1024) await page.screenshot({ path: path.join(SHOTS, `${name}.png`), fullPage: true });
}

for (const width of [1024, 1440]) {
  for (const { lang, colorScheme } of [
    { lang: "en" as const, colorScheme: "light" as const },
    { lang: "ka" as const, colorScheme: "dark" as const },
  ]) {
    test.describe(`${width} px, ${lang} ${colorScheme}`, () => {
      test.use({ viewport: { width, height: 900 }, colorScheme, timezoneId: "Asia/Tbilisi" });

      test("the overview: times in UTC, the counters collapsed and worded", async ({ page }) => {
        await signInAdmin(page, lang);
        await page.goto(`/${lang}/console`);
        await expect(page.locator('[data-testid="overview-summary"] [data-slot="stat-tile"]').first()).toBeVisible();
        await expect(page.getByTestId("status-strip").getByTestId("utc-time")).toHaveText(UTC_TIME[lang]);
        await expectUtcTimes(page, lang, "/console");
        await expectNoOverflow(page, "/console");
        const counters = page.getByTestId("technical-counters");
        // Collapsed: no counter is shown until it is opened.
        await expect(counters).not.toHaveAttribute("open", "");
        await expect(counters.locator("[data-counter]").first()).toBeHidden();
        await expectNoRawCodes(page, "/console");
        await expectAccessible(page, "/console");
        await shot(page, `overview-${lang}-${colorScheme}`, width);
        // Opened: a known counter by its label with the name in the tooltip;
        // the one the console does not word, by its name (the pair).
        await counters.locator("summary").click();
        const known = counters.locator('[data-counter="console_auth.rejected_no_token"]');
        await expect(known).toBeVisible();
        await expect(known).toHaveAttribute("title", "console_auth.rejected_no_token");
        await expect(known).toContainText(lang === "en" ? "Refused: no token" : "უარყოფილია: ტოკენი არ არის");
        await expect(known).not.toContainText("rejected_no_token");
        await expect(counters.locator('[data-component="console_auth"] h3')).toHaveText(lang === "en" ? "Console sessions" : "კონსოლის სესიები");
        await expect(counters.locator('[data-counter="stream.frames_coalesced"]')).toContainText("stream.frames_coalesced");
        await expectAccessible(page, "/console, counters open");
      });

      test("publications fit, the secondary columns behind the expander", async ({ page }) => {
        await signInAdmin(page, lang);
        await page.goto(`/${lang}/console/publications?dataset=zones`);
        const row = page.locator('tr[data-version="2"]');
        await expect(row).toBeVisible();
        await expectNoOverflow(page, "/console/publications");
        await expectUtcTimes(page, lang, "/console/publications");
        await expectOneLine(row.getByTestId("version-counts"), "the feature counts");
        await expectAccessible(page, "/console/publications");
        await shot(page, `publications-${lang}-${colorScheme}`, width);
        // The expander opens the details: the publisher and the version's id with a copy button.
        await row.getByTestId("row-expander").click();
        await expect(row.getByTestId("row-expander")).toHaveAttribute("aria-expanded", "true");
        const details = page.locator(`[id="${await row.getByTestId("row-expander").getAttribute("aria-controls")}"]`);
        await expect(details).toBeVisible();
        await expect(details).toContainText("authority-01");
        await expect(details.getByTestId("copy-id")).toHaveCount(1);
        await expectNoOverflow(page, "/console/publications, a row open");
        await expectAccessible(page, "/console/publications, a row open");
      });

      test("subscriptions fit: a short id with a copy button, the datasets as a count", async ({ page }) => {
        await signInAdmin(page, lang);
        await page.goto(`/${lang}/console/subscriptions`);
        const ulid = "01JXR5Q2ZK8M3T7V9W4Y6B1C0D";
        const row = page.locator(`tr[data-subscription="${ulid}"]`);
        await expect(row).toBeVisible();
        await expectNoOverflow(page, "/console/subscriptions");
        await expectUtcTimes(page, lang, "/console/subscriptions");
        // The ULID: shown short, whole in the tooltip and to a screen reader, copied whole.
        const id = row.locator(`[data-id="${ulid}"]`).first();
        await expect(id).toHaveAttribute("title", ulid);
        await expect(id.locator('[aria-hidden="true"]')).toHaveText("01JX…6B1C0D");
        await expect(row.getByTestId("copy-id")).toHaveAttribute("aria-label", new RegExp(ulid));
        // The pair: a short id is shown whole, without a tooltip.
        await expect(page.locator('tr[data-subscription="sub-02"] [data-id="sub-02"]')).toHaveText("sub-02");
        // All four datasets, as one count on one line, the names in the tooltip.
        const datasets = row.getByTestId("subscription-datasets");
        await expect(datasets).toHaveText(lang === "en" ? /4 of 4/ : /4 \/ 4/);
        await expect(datasets).toHaveAttribute("title", lang === "en" ? /Geographical zones/ : /გეოგრაფიული ზონები/);
        await expectOneLine(datasets, "the datasets");
        // Rows are one or two lines, never word by word.
        for (const r of await page.locator("tr[data-subscription]").all()) expect((await r.boundingBox())?.height ?? 999).toBeLessThan(80);
        await expectAccessible(page, "/console/subscriptions");
        await shot(page, `subscriptions-${lang}-${colorScheme}`, width);
        await row.getByTestId("row-expander").click();
        const details = page.locator(`[id="${await row.getByTestId("row-expander").getAttribute("aria-controls")}"]`);
        await expect(details).toContainText("https://test.example.invalid/v1/cis/notifications");
        await expect(details).toContainText(lang === "en" ? "U-space airspace" : "U-space საჰაერო სივრცე");
        await expectNoOverflow(page, "/console/subscriptions, a row open");
        await expectAccessible(page, "/console/subscriptions, a row open");
      });

      test("the audit fits: labels for the codes, usernames, UTC times, the payload behind the expander", async ({ page }) => {
        await signInAdmin(page, lang);
        await page.goto(`/${lang}/console/audit`);
        const table = page.getByTestId("audit-table");
        await expect(table.locator("tr[data-event]").first()).toBeVisible();
        await expectNoOverflow(page, "/console/audit");
        await expectUtcTimes(page, lang, "/console/audit");
        await expectNoRawCodes(page, "/console/audit");
        // An event type by its label, the code in its tooltip.
        const published = table.locator('tr[data-event="publication_accepted"]');
        await expect(published.getByTestId("audit-event-type")).toHaveText(lang === "en" ? "Publication accepted" : "პუბლიკაცია მიღებულია");
        await expect(published.getByTestId("audit-event-type")).toHaveAttribute("title", "publication_accepted");
        // An account by its username, the id in the tooltip; a client by its id (the pair).
        const session = table.locator('tr[data-event="session_issued"]').first();
        await expect(session.getByTestId("audit-actor").locator("[data-username]")).toHaveText("admin1");
        await expect(session.getByTestId("audit-actor").locator("[data-username]")).toHaveAttribute("title", "acc-admin1");
        await expect(published.getByTestId("audit-actor").locator('[data-id="authority-01"]')).toHaveText("authority-01");
        for (const r of await table.locator("tr[data-event]").all()) {
          await expectOneLine(r.locator("td").nth(1), "the event number");
          expect((await r.boundingBox())?.height ?? 999, "an audit row taller than two lines").toBeLessThan(80);
        }
        await expectAccessible(page, "/console/audit");
        await shot(page, `audit-${lang}-${colorScheme}`, width);
        // The payload: terms and values, and the JSON behind its own disclosure.
        await published.getByTestId("row-expander").click();
        const details = page.locator(`[id="${await published.getByTestId("row-expander").getAttribute("aria-controls")}"]`);
        const payload = details.getByTestId("audit-payload");
        await expect(payload.locator('[data-member="version"]')).toHaveText("2");
        await expect(payload.locator('[data-member="dataset"]')).toHaveText(lang === "en" ? "Geographical zones" : "გეოგრაფიული ზონები");
        await expect(payload.getByTestId("audit-json")).toBeHidden();
        await payload.locator("summary").click();
        await expect(payload.getByTestId("audit-json")).toContainText('"dataset": "zones"');
        await expect(details).toContainText("publication_accepted");
        await expect(details.getByTestId("audit-entity").locator('[data-id="pub-zones-2"]')).toBeVisible();
        await expectNoOverflow(page, "/console/audit, a row open");
        await expectAccessible(page, "/console/audit, a row open");
      });
    });
  }
}
