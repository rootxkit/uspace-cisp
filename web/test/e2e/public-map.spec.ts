// The public map against test/mock-api.mjs: the ED-318 base collection of
// uspace-core's ed318_roundtrip.json split into the three datasets, plus
// one polygon restriction. Each scenario resets the mock first.
import { expect, test, type APIRequestContext, type Page } from "@playwright/test";

interface Recorded {
  method: string;
  path: string;
  query: Record<string, string>;
  ifNoneMatch: string | null;
  atMs: number;
}

async function requests(request: APIRequestContext): Promise<Recorded[]> {
  return (await (await request.get("/__mock/requests")).json()) as Recorded[];
}

async function mock(request: APIRequestContext, path: string, data: unknown = {}) {
  const res = await request.post(`/__mock/${path}`, { data });
  expect(res.ok()).toBe(true);
}

/** Waits until the page has read nothing for a second: the view has settled. */
async function settled(request: APIRequestContext) {
  await expect
    .poll(async () => {
      const last = (await requests(request)).filter((r) => r.method === "GET").at(-1);
      return last === undefined ? 0 : Date.now() - last.atMs;
    }, { timeout: 15_000 })
    .toBeGreaterThan(1000);
}

function item(page: Page, id: string) {
  return page.locator(`[data-feature="${id}"]`);
}

test.beforeEach(async ({ request }) => {
  await mock(request, "reset");
});

test("the three layers render from /public/v1/* with the banner live", async ({ page, request }) => {
  await page.goto("/en");
  await expect(page.locator('[data-layer="zones"] [data-feature]')).toHaveCount(3);
  await expect(page.locator('[data-layer="uspace_airspace"] [data-feature]')).toHaveCount(1);
  await expect(page.locator('[data-layer="restrictions"] [data-feature]')).toHaveCount(2);
  await expect(page.getByTestId("feed-mode")).toHaveText("Live");
  for (const d of ["zones", "uspace_airspace", "restrictions"]) {
    await expect(page.locator(`[data-dataset="${d}"]`)).toContainText("version 1, updated 2026-10-01 08:00 UTC");
  }
  // One read per dataset by the view's bbox, annotated at an instant; never the filtering at=.
  const reads = (await requests(request)).filter((r) => r.method === "GET");
  for (const d of ["zones", "uspace_airspace", "restrictions"]) {
    const mine = reads.filter((r) => r.path === `/public/v1/${d}`);
    expect(mine.length).toBeGreaterThan(0);
    for (const r of mine) {
      expect(r.query["bbox"]).toMatch(/^-?\d+\.\d{4}(,-?\d+\.\d{4}){3}$/);
      expect(r.query["applies_at"]).toMatch(/^\d{4}-\d\d-\d\dT\d\d:\d\d:00Z$/);
      expect(r.query["at"]).toBeUndefined();
    }
  }
  // The map drew the two zone layers and the restriction layer.
  await expect(page.locator(".us-map canvas")).toHaveCount(1);
});

test("clicking a zone expands its row with its identifier and limits as published", async ({ page }) => {
  await page.goto("/en");
  await expect(item(page, "TSR001")).toHaveAttribute("aria-expanded", "false");
  await item(page, "TSR001").click();
  await expect(item(page, "TSR001")).toHaveAttribute("aria-expanded", "true");
  await expect(item(page, "TSR001")).toContainText("TSR001 Test authorisation zone");
  const panel = page.locator('[data-panel="TSR001"]');
  await expect(item(page, "TSR001")).toHaveAttribute("aria-controls", (await panel.getAttribute("id")) ?? "");
  await expect(panel).toContainText("IdentifierTSR001");
  await expect(panel.locator("[data-limits]")).toHaveText("0 m AGL – 600 m above the WGS 84 ellipsoid");
  await expect(panel.locator("[data-schedule]")).toContainText("08:00:00+04:00 to 18:00:00+04:00");

  // Feet stay feet; a circle is drawn from the CIS's outline.
  await item(page, "TSD001").click();
  const tsd = page.locator('[data-panel="TSD001"]');
  await expect(tsd.locator("[data-limits]")).toHaveText("0 ft AGL – 2,500 ft AMSL");
  await expect(tsd).toContainText("Circle of radius 1,500 m");
  await expect(tsd).toContainText("draws the outline the CIS computed");
  await expect(tsd).toContainText("morning civil twilight (BMCT) to evening civil twilight (EECT)");
  await expect(tsd).toContainText("Planned");

  // One row is expanded at a time: the first collapsed when the second opened.
  await expect(panel).toHaveCount(0);
  await expect(item(page, "TSR001")).toHaveAttribute("aria-expanded", "false");
  // The row collapses with Escape and the list keeps every zone reachable by keyboard.
  await page.keyboard.press("Escape");
  await expect(tsd).toHaveCount(0);
  await expect(item(page, "TSD001")).toHaveAttribute("aria-expanded", "false");
  await item(page, "TSC001").focus();
  await page.keyboard.press("Enter");
  await expect(page.locator('[data-panel="TSC001"] [data-limits] li')).toHaveText([
    "0 m AGL – 50 m AGL",
    "50 m AGL – 150 m AGL",
  ]);
});

test("the time control dims a zone outside its window and keeps the unknown one", async ({ page, request }) => {
  await page.goto("/en");
  await expect(item(page, "TSD001")).toHaveAttribute("data-applicability", "unknown");
  // Saturday 2026-10-10 12:00 UTC: TSR001 is weekdays only.
  await page.getByLabel("Chosen instant (your local time)").fill("2026-10-10T12:00");
  await expect(item(page, "TSR001")).toHaveAttribute("data-applicability", "not_applicable");
  await expect(item(page, "TSR001")).toContainText("not applicable then");
  // Not hidden: still listed, and still on the map's source.
  await expect(page.locator('[data-layer="zones"] [data-feature]')).toHaveCount(3);
  await expect(item(page, "TSD001")).toHaveAttribute("data-applicability", "unknown");
  await expect(item(page, "TSD001")).toContainText("could not be evaluated");
  await item(page, "TSD001").click();
  await expect(page.locator('[data-panel="TSD001"] [data-verdict="unknown"]')).toContainText("could not evaluate");
  const asked = (await requests(request)).filter((r) => r.query["applies_at"] === "2026-10-10T12:00:00Z");
  expect(asked.map((r) => r.path).sort()).toEqual(
    expect.arrayContaining(["/public/v1/restrictions", "/public/v1/uspace_airspace", "/public/v1/zones"]),
  );

  // Back to a weekday morning: it applies again.
  await page.getByLabel("Chosen instant (your local time)").fill("2026-10-12T06:00");
  await expect(item(page, "TSR001")).toHaveAttribute("data-applicability", "applies");
});

test("a 503 turns the banner to unavailable since, and the zones stay drawn", async ({ page, request }) => {
  await page.goto("/en");
  await expect(page.locator('[data-layer="zones"] [data-feature]')).toHaveCount(3);
  await expect(page.locator('[data-dataset="zones"]')).toHaveAttribute("data-unavailable", "false");
  await mock(request, "state", { unavailable: ["zones"] });
  // A new instant reads every dataset again.
  await page.getByLabel("Chosen instant (your local time)").fill("2026-10-12T06:00");
  await expect(page.locator('[data-dataset="zones"]')).toHaveAttribute("data-unavailable", "true");
  await expect(page.locator('[data-dataset="zones"]')).toContainText(/unavailable since \d{4}-\d\d-\d\d \d\d:\d\d:\d\d UTC/);
  await expect(page.locator('[data-dataset="restrictions"]')).toHaveAttribute("data-unavailable", "false");
  // Never an empty sky: what was shown stays.
  await expect(page.locator('[data-layer="zones"] [data-feature]')).toHaveCount(3);

  // And it recovers when the API serves again.
  await mock(request, "state", { unavailable: [] });
  await page.getByLabel("Chosen instant (your local time)").fill("2026-10-12T07:00");
  await expect(page.locator('[data-dataset="zones"]')).toHaveAttribute("data-unavailable", "false");
});

test("without the stream it polls HEAD, and a changed ETag refetches", async ({ page, request }) => {
  await mock(request, "state", { stream: false });
  await page.goto("/en");
  await expect(page.getByTestId("feed-mode")).toHaveText("Polling (no live stream)");
  await expect(page.locator('[data-dataset="zones"]')).toContainText("version 1");
  const heads = (await requests(request)).filter((r) => r.method === "HEAD" && r.path === "/public/v1/zones");
  expect(heads.length).toBeGreaterThan(0);
  await settled(request);

  const bumpedAt = Date.now();
  await mock(request, "bump", { dataset: "zones" });
  await expect(page.locator('[data-dataset="zones"]')).toContainText("version 2", { timeout: 10_000 });
  const after = (await requests(request)).filter((r) => r.atMs >= bumpedAt && r.path === "/public/v1/zones");
  const head = after.find((r) => r.method === "HEAD");
  const get = after.find((r) => r.method === "GET");
  expect(head).toBeDefined();
  expect(get).toBeDefined();
  expect(get?.atMs ?? 0).toBeGreaterThanOrEqual(head?.atMs ?? Infinity);
  // Nothing else moved: the other datasets were not read again.
  expect(after.filter((r) => r.method === "GET" && r.path !== "/public/v1/zones")).toEqual([]);
});

test("with the stream live, a new dataset version in the status frame refetches without polling", async ({ page, request }) => {
  await page.goto("/en");
  await expect(page.getByTestId("feed-mode")).toHaveText("Live");
  await settled(request);
  const bumpedAt = Date.now();
  await mock(request, "bump", { dataset: "restrictions" });
  await expect(page.locator('[data-dataset="restrictions"]')).toContainText("version 2", { timeout: 10_000 });
  const after = (await requests(request)).filter((r) => r.atMs >= bumpedAt);
  expect(after.some((r) => r.method === "GET" && r.path === "/public/v1/restrictions")).toBe(true);
  expect(after.filter((r) => r.method === "HEAD")).toEqual([]);
});

test("the stream going away moves the banner from live to polling", async ({ page, request }) => {
  await page.goto("/en");
  await expect(page.getByTestId("feed-mode")).toHaveText("Live");
  await mock(request, "state", { stream: false });
  await expect(page.getByTestId("feed-mode")).toHaveText("Polling (no live stream)", { timeout: 15_000 });
});

test("the ANSP's staleness is on the banner", async ({ page, request }) => {
  await mock(request, "state", { publisherStaleSince: "2026-10-02T09:59:00Z" });
  await page.goto("/en");
  await expect(page.locator('[data-dataset="restrictions"]')).toContainText("publisher silent since 2026-10-02 09:59 UTC");
});

test("the map in Georgian: names, banner and panel", async ({ page }) => {
  await page.goto("/ka");
  await expect(item(page, "TSU001")).toContainText("თბილისის U-space საჰაერო სივრცე (ტესტი)");
  await expect(page.locator('[data-dataset="zones"]')).toContainText("ვერსია 1");
  await item(page, "TSD001").click();
  await expect(page.locator('[data-panel="TSD001"] [data-limits]')).toHaveText(/^0 ფტ AGL – 2\D?500 ფტ AMSL$/);
});

test("the USSP list page in both languages", async ({ page }) => {
  await page.goto("/en/ussps");
  const ussp = page.locator('[data-ussp="USSPDEV"]');
  await expect(ussp).toContainText("Test USSP");
  await expect(ussp).toContainText("Network identification, Geo-awareness, Flight authorisation, Traffic information");
  await expect(ussp).toContainText("Daytime operations only");
  await expect(ussp.getByRole("link")).toHaveAttribute("href", "https://example.invalid/terms");
  await page.goto("/ka/ussps");
  await expect(page.locator('[data-ussp="USSPDEV"]')).toContainText("ქსელური იდენტიფიკაცია");
});

test("the map makes no request off the origin and loads under the CSP", async ({ page, baseURL }) => {
  const off: string[] = [];
  const failed: string[] = [];
  page.on("request", (r) => {
    const u = r.url();
    if (!u.startsWith("data:") && !u.startsWith("blob:") && new URL(u).origin !== new URL(baseURL ?? "").origin) off.push(u);
  });
  page.on("response", (r) => {
    // The fixture server holds no basemap: the kit's "no base map" notice is the expected answer.
    if (r.status() >= 400 && !new URL(r.url()).pathname.startsWith("/basemap/")) failed.push(`${r.status()} ${r.url()}`);
  });
  const violations: string[] = [];
  page.on("console", (m) => {
    if (m.type() === "error" && /Content Security Policy/i.test(m.text())) violations.push(m.text());
  });
  await page.goto("/en");
  await expect(page.locator('[data-layer="zones"] [data-feature]')).toHaveCount(3);
  await page.waitForTimeout(1500);
  expect(off).toEqual([]);
  expect(failed).toEqual([]);
  expect(violations).toEqual([]);
});

test("circle zones are drawn from the CIS's outline, and say so when it is missing", async ({ page, request }) => {
  await page.goto("/en");
  for (const id of ["TSN001", "TSD001"]) {
    await expect(item(page, id)).toHaveAttribute("data-drawn", "outline");
    await expect(item(page, id)).toContainText("circle, outline drawn by the CIS");
  }
  await expect(item(page, "TSR001")).toHaveAttribute("data-drawn", "as-published");
  // An API without the outline: the circle is still listed, and says it is not drawn.
  await mock(request, "state", { outlines: false });
  await page.getByLabel("Chosen instant (your local time)").fill("2026-10-12T06:00");
  await expect(item(page, "TSN001")).toHaveAttribute("data-drawn", "not-drawn");
  await expect(item(page, "TSN001")).toContainText("circle, not drawn on the map");
});

test("the object list is an accordion: sections with counts collapse and expand by keyboard", async ({ page }) => {
  await page.goto("/en");
  const toggle = (d: string) => page.locator(`[data-section-toggle="${d}"]`);
  await expect(toggle("zones")).toHaveAttribute("aria-expanded", "true");
  await expect(toggle("zones").locator("[data-count]")).toHaveText("3");
  await expect(toggle("uspace_airspace").locator("[data-count]")).toHaveText("1");
  await expect(toggle("restrictions").locator("[data-count]")).toHaveText("2");
  // Collapsed: the rows are gone from view and from the tab order; the count stays.
  await toggle("zones").focus();
  await page.keyboard.press("Enter");
  await expect(toggle("zones")).toHaveAttribute("aria-expanded", "false");
  await expect(item(page, "TSR001")).toBeHidden();
  await expect(toggle("zones").locator("[data-count]")).toHaveText("3");
  await expect(item(page, "TSU001")).toBeVisible();
  // And open again with Space.
  await page.keyboard.press(" ");
  await expect(toggle("zones")).toHaveAttribute("aria-expanded", "true");
  await expect(item(page, "TSR001")).toBeVisible();

  // A restriction's row shows its type, reason, limits, window and state.
  await item(page, "DAR00A1").focus();
  await page.keyboard.press("Enter");
  const details = page.locator('[data-panel="DAR00A1"]');
  await expect(details).toContainText("IdentifierDAR00A1");
  await expect(details).toContainText("DAR");
  await expect(details.locator("[data-limits]")).toHaveText("0 m AGL – 120 m AGL");
  await expect(details).toContainText("2026-10-01 00:00 UTC to 2027-01-01 00:00 UTC");
  await expect(details).toContainText("Active");
  // Collapsing the section of the expanded row clears it.
  await toggle("restrictions").click();
  await expect(details).toHaveCount(0);
  await toggle("restrictions").click();
  await expect(item(page, "DAR00A1")).toHaveAttribute("aria-expanded", "false");
});

test("the page has no visible header, and the time panel says what it shows", async ({ page }) => {
  await page.goto("/en");
  await expect(page.locator('[data-dataset="zones"]')).toContainText("version 1");
  // The name is the page's h1 for assistive technology only.
  const h1 = page.getByRole("heading", { level: 1 });
  await expect(h1).toHaveText("Common Information Service");
  await expect(h1).toHaveClass(/sr-only/);
  await expect(page.getByText("as published by the authority and the air navigation service provider")).toHaveCount(0);
  await expect(page.getByTestId("time-hint")).toHaveText("The map shows what is in force now, or at the moment you choose.");
  await page.goto("/ka");
  await expect(page.getByTestId("time-hint")).toHaveText("რუკა აჩვენებს, რა მოქმედებს ახლა ან თქვენ მიერ არჩეულ მომენტში.");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("საერთო საინფორმაციო მომსახურება");
  await expect(page.getByRole("heading", { level: 1 })).toHaveClass(/sr-only/);
});

test("a dataset nothing has been published in is empty, not unavailable", async ({ page, request }) => {
  await mock(request, "state", { unpublished: ["restrictions"] });
  await page.goto("/en");
  const banner = page.locator('[data-dataset="restrictions"]');
  await expect(banner).toHaveAttribute("data-empty", "true");
  await expect(banner).toContainText("no restrictions yet");
  await expect(banner).toHaveAttribute("data-unavailable", "false");
  await expect(banner).not.toContainText("unavailable");
  await expect(banner.getByRole("alert")).toHaveCount(0);
  await expect(page.locator('[data-layer="restrictions"] [data-empty-note="none-yet"]')).toHaveText("No restrictions yet.");
  await expect(page.locator('[data-section-toggle="restrictions"] [data-count]')).toHaveText("0");
  // The other datasets are served as usual.
  await expect(page.locator('[data-dataset="zones"]')).toContainText("version 1");
  // It was asked with GET and answered 404 no_version.
  expect((await requests(request)).some((r) => r.method === "GET" && r.path === "/public/v1/restrictions")).toBe(true);

  // Georgian, in the same neutral words.
  await page.goto("/ka");
  await expect(page.locator('[data-dataset="restrictions"]')).toContainText("შეზღუდვები ჯერ არ არის");
  await expect(page.locator('[data-dataset="restrictions"]')).not.toContainText("მიუწვდომელია");
  await expect(page.locator('[data-layer="restrictions"] [data-empty-note="none-yet"]')).toHaveText("შეზღუდვები ჯერ არ არის.");

  // The first publication arrives (the status frame announces version 1): it is shown.
  await mock(request, "state", { unpublished: [] });
  await expect(page.locator('[data-dataset="restrictions"]')).toHaveAttribute("data-empty", "false", { timeout: 10_000 });
  await expect(page.locator('[data-dataset="restrictions"]')).toContainText("ვერსია 1");
  await expect(page.locator('[data-layer="restrictions"] [data-feature]')).toHaveCount(2);
});

test("without the stream, an empty dataset's HEAD 404 keeps it empty, and its first version is read", async ({ page, request }) => {
  await mock(request, "state", { stream: false, unpublished: ["restrictions"] });
  await page.goto("/en");
  await expect(page.getByTestId("feed-mode")).toHaveText("Polling (no live stream)");
  const banner = page.locator('[data-dataset="restrictions"]');
  await expect(banner).toHaveAttribute("data-empty", "true");
  await expect
    .poll(async () => (await requests(request)).filter((r) => r.method === "HEAD" && r.path === "/public/v1/restrictions").length, {
      timeout: 10_000,
    })
    .toBeGreaterThan(1);
  await expect(banner).toHaveAttribute("data-unavailable", "false");
  await expect(banner).toHaveAttribute("data-empty", "true");
  await mock(request, "state", { unpublished: [] });
  await expect(banner).toContainText("version 1", { timeout: 10_000 });
  await expect(banner).toHaveAttribute("data-empty", "false");
});

test("a real failure is still unavailable: a 503 and a network error on restrictions", async ({ page, request }) => {
  await mock(request, "state", { unavailable: ["restrictions"] });
  await page.goto("/en");
  const banner = page.locator('[data-dataset="restrictions"]');
  await expect(banner).toHaveAttribute("data-unavailable", "true");
  await expect(banner).toContainText(/unavailable since \d{4}-\d\d-\d\d \d\d:\d\d:\d\d UTC/);
  await expect(banner).toHaveAttribute("data-empty", "false");
  await expect(banner).not.toContainText("no restrictions yet");

  // No answer at all: the request never reaches the API.
  await mock(request, "state", { unavailable: [] });
  await page.route("**/public/v1/restrictions**", (route) => route.abort("connectionfailed"));
  await page.goto("/ka");
  const ka = page.locator('[data-dataset="restrictions"]');
  await expect(ka).toHaveAttribute("data-unavailable", "true");
  await expect(ka).toContainText("მიუწვდომელია");
  await expect(ka).not.toContainText("შეზღუდვები ჯერ არ არის");
});
