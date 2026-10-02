// The WP-9 smoke run: both locales load, Georgian renders in the kit's
// Noto Sans Georgian (self-hosted), the locale switch works, and no
// request leaves the origin.
import { expect, test, type Page } from "@playwright/test";

const GEORGIAN = /[Ⴀ-ჿᲐ-Ჿⴀ-⴯]/u;

/** Every request URL the page makes from here on. */
function recordRequests(page: Page): string[] {
  const urls: string[] = [];
  page.on("request", (r) => urls.push(r.url()));
  return urls;
}

function offOrigin(urls: string[], origin: string): string[] {
  return urls.filter((u) => !u.startsWith("data:") && !u.startsWith("blob:") && new URL(u).origin !== origin);
}

test("/ka renders Georgian in the kit's Georgian face and stays on the origin", async ({ page, baseURL }) => {
  const urls = recordRequests(page);
  const errors: string[] = [];
  page.on("console", (m) => {
    if (m.type() === "error" && /Content Security Policy/i.test(m.text())) errors.push(m.text());
  });
  await page.goto("/ka");
  await expect(page.locator("html")).toHaveAttribute("lang", "ka");
  const title = page.getByRole("heading", { level: 1 });
  await expect(title).toHaveText(GEORGIAN);

  const family = await title.evaluate((el) => getComputedStyle(el).fontFamily);
  expect(family).toMatch(/notoSansGeorgian/i);
  // The Georgian face was fetched and is in use: its unicode-range makes
  // the browser load it only for Georgian text.
  const loaded = await page.evaluate(async () => {
    await document.fonts.ready;
    return [...document.fonts].filter((f) => f.status === "loaded").map((f) => f.family);
  });
  expect(loaded.some((f) => /notoSansGeorgian/i.test(f))).toBe(true);
  expect(urls.some((u) => /\/_next\/static\/media\/.+\.woff2$/.test(u))).toBe(true);

  // The map page keeps its stream open, so the network never idles: give
  // the page a moment to make every request it makes on load.
  await page.waitForTimeout(1500);
  expect(offOrigin(urls, new URL(baseURL ?? "").origin)).toEqual([]);
  // A CSP violation is a console error; the page must load without one.
  expect(errors).toEqual([]);
});

test("/en renders English with the same shell", async ({ page }) => {
  await page.goto("/en");
  await expect(page.locator("html")).toHaveAttribute("lang", "en");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Common Information Service");
});

test("the locale switch moves between ka and en", async ({ page }) => {
  await page.goto("/ka");
  await page.getByRole("link", { name: "English" }).click();
  await expect(page).toHaveURL(/\/en$/);
  await expect(page.locator("html")).toHaveAttribute("lang", "en");
  await page.getByRole("link", { name: "ქართული" }).click();
  await expect(page).toHaveURL(/\/ka$/);
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(GEORGIAN);
});

test.describe("the root redirects by language", () => {
  test.use({ locale: "en-GB" });
  test("an English browser lands on /en", async ({ page }) => {
    await page.goto("/");
    await expect(page).toHaveURL(/\/en$/);
  });
});

test.describe("the root defaults to Georgian", () => {
  test.use({ locale: "ka-GE" });
  test("a Georgian browser lands on /ka", async ({ page }) => {
    await page.goto("/");
    await expect(page).toHaveURL(/\/ka$/);
  });
});

test("pages carry the CSP with a nonce and no third-party source", async ({ request }) => {
  const res = await request.get("/ka");
  const csp = res.headers()["content-security-policy"] ?? "";
  expect(csp).toContain("connect-src 'self'");
  expect(csp).toContain("font-src 'self'");
  expect(csp).toContain("worker-src blob:");
  expect(csp).toMatch(/script-src 'self' 'nonce-[A-Za-z0-9+/=]+'/);
  expect(csp).not.toMatch(/https?:/);
});

test("/healthz answers", async ({ request }) => {
  const res = await request.get("/healthz");
  expect(res.status()).toBe(200);
});
