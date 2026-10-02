// The console (WP-11) in the browser: `next start` behind
// test/mock-api.mjs, whose /v1/console/* (test/mock-console.mjs) answers
// in the shapes of api/openapi.yaml with the operations' roles. Every
// page talks to /_bff/* (and the public read for map previews); the BFF
// is the real one.
import { expect, test, type APIRequestContext, type Page } from "@playwright/test";

// The mock's test accounts and code (test/mock-console.mjs), not credentials.
const ADMIN = { username: "admin1", password: "admin1-test-password" };
const PUBLISHER = { username: "pub1", password: "pub1-test-password" };
const VIEWER = { username: "viewer1", password: "viewer1-test-password" };
const LOCKABLE = { username: "lock1", password: "lock1-test-password" };
const CODE = "246810";
const GEORGIAN = /[Ⴀ-ჿᲐ-Ჿⴀ-⴯]/u;

async function bffLogin(page: Page, body: Record<string, string>): Promise<number> {
  return page.evaluate(async (b) => {
    const res = await fetch("/_bff/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(b) });
    return res.status;
  }, body);
}

/** Signs in through the BFF (two steps for an MFA account) without the form. */
async function signIn(page: Page, who: { username: string; password: string }, lang = "en"): Promise<void> {
  await page.goto(`/${lang}/console/login`);
  expect(await bffLogin(page, who)).toBe(200);
  if (who.username === ADMIN.username) expect(await bffLogin(page, { username: who.username, otp: CODE })).toBe(200);
}

async function consoleCalls(request: APIRequestContext): Promise<{ method: string; path: string }[]> {
  return (await (await request.get("/__mock/console")).json()) as { method: string; path: string }[];
}

async function confirmWithReason(page: Page, reason: string): Promise<void> {
  const dialog = page.getByRole("alertdialog");
  await expect(dialog).toBeVisible();
  await dialog.getByLabel("Reason").fill(reason);
  await dialog.getByRole("button", { name: "Confirm" }).click();
}

test.beforeEach(async ({ request }) => {
  expect((await request.post("/__mock/reset")).ok()).toBe(true);
});

test.describe("sign-in", () => {
  test("an account without MFA signs in with the form in one step", async ({ page }) => {
    await page.goto("/en/console/login");
    await page.getByLabel("Username").fill(VIEWER.username);
    await page.getByLabel("Password").fill(VIEWER.password);
    await page.getByRole("button", { name: "Sign in" }).click();
    await expect(page).toHaveURL(/\/en\/console$/);
    await expect(page.getByTestId("account-menu")).toHaveText(VIEWER.username);
    // No code was asked for.
    await expect(page.getByLabel("One-time code")).toHaveCount(0);
  });

  test("an admin is asked for the code after the password, and signs in with it", async ({ page, request }) => {
    await page.goto("/en/console/login");
    await expect(page.getByLabel("One-time code")).toHaveCount(0);
    await page.getByLabel("Username").fill(ADMIN.username);
    await page.getByLabel("Password").fill(ADMIN.password);
    await page.getByRole("button", { name: "Sign in" }).click();
    const code = page.getByLabel("One-time code");
    await expect(code).toBeVisible();
    // A wrong code is said in the console's words, and the form stays on the code.
    await code.fill("135790");
    await page.getByRole("button", { name: "Sign in" }).click();
    await expect(page.locator("form").getByRole("alert")).toContainText("The code is wrong.");
    await code.fill(CODE);
    await page.getByRole("button", { name: "Sign in" }).click();
    await expect(page).toHaveURL(/\/en\/console$/);
    await expect(page.getByTestId("account-menu")).toHaveText(ADMIN.username);
    const posts = (await consoleCalls(request)).filter((c) => c.method === "POST").map((c) => c.path);
    expect(posts).toEqual(["/v1/console/session", "/v1/console/session/mfa", "/v1/console/session/mfa"]);
  });

  test("five wrong passwords lock the account, and the form says for how long", async ({ page }) => {
    await page.goto("/en/console/login");
    for (let i = 0; i < 5; i++) {
      await page.getByLabel("Username").fill(LOCKABLE.username);
      await page.getByLabel("Password").fill("wrong-password");
      await page.getByRole("button", { name: "Sign in" }).click();
      await expect(page.locator("form").getByRole("alert")).toContainText("The username or the password is wrong.");
    }
    // Locked now: even the right password is refused, with the time left.
    await page.getByLabel("Username").fill(LOCKABLE.username);
    await page.getByLabel("Password").fill(LOCKABLE.password);
    await page.getByRole("button", { name: "Sign in" }).click();
    await expect(page.locator("form").getByRole("alert")).toContainText("This account is locked after repeated failures. Try again in 15 min.");
    await expect(page.getByTestId("retry-countdown")).toBeVisible();
    await expect(page.getByRole("button", { name: "Sign in" })).toBeDisabled();
    await expect(page).toHaveURL(/\/console\/login$/);
  });

  test("a console page without a session goes to the sign-in", async ({ page }) => {
    await page.goto("/en/console/publications");
    await expect(page).toHaveURL(/\/en\/console\/login$/);
  });

  test("sign-out ends the session", async ({ page }) => {
    await signIn(page, VIEWER);
    await page.goto("/en/console");
    await page.getByTestId("account-menu").click();
    await page.getByRole("menuitem", { name: "Sign out" }).click();
    await expect(page).toHaveURL(/\/en\/console\/login$/);
    await page.goto("/en/console");
    await expect(page).toHaveURL(/\/en\/console\/login$/);
  });
});

test.describe("roles", () => {
  test("a viewer sees no action and no admin page; a forced request shows the API's 403", async ({ page, request }) => {
    await signIn(page, VIEWER);
    await page.goto("/en/console/publications?dataset=zones");
    await expect(page.locator('tr[data-version="2"]')).toBeVisible();
    await expect(page.getByRole("button", { name: "Republish current version" })).toHaveCount(0);
    const nav = page.getByRole("navigation", { name: "Console navigation" });
    await expect(nav.getByRole("link")).toHaveText(["Overview", "Publications", "Restrictions", "Subscriptions"]);

    await page.goto("/en/console/subscriptions/sub-02");
    await expect(page.locator('tr[data-delivery="del-0201"]')).toBeVisible();
    await expect(page.getByRole("button", { name: "Retry now" })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Suspend" })).toHaveCount(0);

    // Typed by address: the page asks, the API refuses, the page says so.
    await page.goto("/en/console/accounts");
    await expect(page.getByRole("alert").filter({ hasText: "Refused (403): your role does not allow this." })).toBeVisible();
    await expect(page.getByRole("button", { name: "Create" })).toHaveCount(0);
    // A forced action from the page (its own session, the CSRF pair) is the API's 403 too.
    const forced = await page.evaluate(async () => {
      const csrf = /(?:^|; )uspace_csrf=([^;]*)/.exec(document.cookie)?.[1] ?? "";
      const res = await fetch("/_bff/api/v1/console/publications/pub-zones-2/republish", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": decodeURIComponent(csrf) },
        body: JSON.stringify({ reason: "forced" }),
      });
      return res.status;
    });
    expect(forced).toBe(403);
    expect((await consoleCalls(request)).some((c) => c.path.endsWith("/republish"))).toBe(true);
  });

  test("an admin sees every item (the pair)", async ({ page }) => {
    await signIn(page, ADMIN);
    await page.goto("/en/console");
    const nav = page.getByRole("navigation", { name: "Console navigation" });
    await expect(nav.getByRole("link")).toHaveText(["Overview", "Publications", "Restrictions", "Subscriptions", "Accounts", "Audit"]);
  });
});

test("a publisher_admin republishes with a reason and the admin's audit shows it", async ({ page, context }) => {
  await signIn(page, PUBLISHER);
  await page.goto("/en/console/publications?dataset=zones");
  // Only the current version offers it.
  await expect(page.getByRole("button", { name: "Republish current version" })).toHaveCount(1);
  await page.getByRole("button", { name: "Republish current version" }).click();
  await expect(page.getByRole("alertdialog")).toContainText("receive a new change notification for version 2");
  await expect(page.getByRole("alertdialog")).toContainText("No content changes");
  // A reason is required: confirming without one asks for it.
  await page.getByRole("alertdialog").getByRole("button", { name: "Confirm" }).click();
  await expect(page.getByRole("alertdialog")).toBeVisible();
  await confirmWithReason(page, "subscriber lost the notification");
  await expect(page.getByRole("status").filter({ hasText: "Version 2 announced again." })).toBeVisible();

  await context.clearCookies();
  await signIn(page, ADMIN);
  await page.goto("/en/console/audit");
  const row = page.locator('tr[data-event="console_republish"]');
  await expect(row).toHaveCount(1);
  // The actor is the account's id, as the CISP records it.
  await expect(row).toContainText("acc-pub1");
  await expect(row.getByTestId("audit-payload")).toContainText("subscriber lost the notification");
  // The filter by type keeps it and drops the rest.
  await page.getByLabel("Event type").fill("console_republish");
  await page.getByRole("button", { name: "Apply" }).click();
  await expect(page.locator("tr[data-event]")).toHaveCount(1);
});

test("a subscription's failed delivery is retried with a reason", async ({ page }) => {
  await signIn(page, PUBLISHER);
  await page.goto("/en/console/subscriptions");
  const row = page.locator('tr[data-subscription="sub-02"]');
  await expect(row).toContainText("lab-01");
  await row.getByRole("link", { name: "sub-02" }).click();
  await expect(page).toHaveURL(/\/en\/console\/subscriptions\/sub-02$/);
  const delivery = page.locator('tr[data-delivery="del-0201"]');
  await expect(delivery.getByTestId("delivery-state")).toHaveText("Failed");
  await expect(delivery.getByTestId("attempt-log").locator("li")).toHaveCount(3);
  // A delivered one offers no retry (the pair).
  await expect(page.locator('tr[data-delivery="del-0202"]').getByRole("button", { name: "Retry now" })).toHaveCount(0);
  await delivery.getByRole("button", { name: "Retry now" }).click();
  await expect(page.getByRole("alertdialog")).toContainText("lab-01 will be sent this change notification again");
  await confirmWithReason(page, "subscriber back online");
  await expect(delivery.getByTestId("delivery-state")).toHaveText("Queued");
});

test("a subscription is suspended and resumed, each with its consequence", async ({ page }) => {
  await signIn(page, PUBLISHER);
  await page.goto("/en/console/subscriptions/sub-01");
  await expect(page.getByTestId("subscription-status")).toContainText("Active");
  await expect(page.getByTestId("bbox-preview")).toContainText("[44.7000, 41.6500, 44.9000, 41.8000]");
  await page.getByRole("button", { name: "Suspend" }).click();
  await expect(page.getByRole("alertdialog")).toContainText("will receive no change notification");
  await confirmWithReason(page, "callback under maintenance");
  await expect(page.getByTestId("subscription-status")).toContainText("Suspended");
  await page.getByRole("button", { name: "Resume" }).click();
  await confirmWithReason(page, "maintenance over");
  await expect(page.getByTestId("subscription-status")).toContainText("Pending verification");
});

test.describe("publications", () => {
  test("a version page shows the diff with a bounded path list and the map preview", async ({ page }) => {
    await signIn(page, VIEWER);
    await page.goto("/en/console/publications?dataset=zones");
    await page.getByRole("link", { name: "Version 2" }).click();
    await expect(page).toHaveURL(/\/publications\/pub-zones-2$/);
    await expect(page.getByTestId("diff")).toContainText("Against version 1.");
    await expect(page.locator('[data-feature="TSN001"][data-op="added"]')).toBeVisible();
    await expect(page.locator('[data-feature="OLD0001"][data-op="removed"]')).toBeVisible();
    const changed = page.locator('[data-feature="TSR001"][data-op="changed"]');
    await expect(changed.getByTestId("diff-paths").locator("li")).toHaveCount(20);
    await expect(changed.getByTestId("paths-hidden")).toHaveText("Paths not shown here: 5.");
    await page.getByRole("button", { name: "Show every path" }).click();
    await expect(changed.getByTestId("diff-paths").locator("li")).toHaveCount(25);
    await expect(page.getByTestId("version-current")).toHaveText("current");
    await expect(page.getByTestId("preview-drawn")).toHaveText("Drawn: TSR001, TSN001");
  });

  test("a superseded version draws no preview and offers no republish", async ({ page }) => {
    await signIn(page, PUBLISHER);
    await page.goto("/en/console/publications/pub-zones-1");
    await expect(page.getByTestId("diff")).toContainText("The first version of the dataset");
    await expect(page.getByTestId("version-current")).toHaveText("superseded (current is 2)");
    await expect(page.getByTestId("feature-preview")).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Republish current version" })).toHaveCount(0);
  });
});

test.describe("restrictions", () => {
  test("the heads are listed with their events, the ANSP's staleness is called out", async ({ page, request }) => {
    await request.post("/__mock/console-state", { data: { anspStale: true } });
    await signIn(page, VIEWER);
    await page.goto("/en/console/restrictions");
    await expect(page.locator('tr[data-restriction="DAR00A1"]')).toContainText("Active");
    await expect(page.locator('tr[data-restriction="DAR00A1"]').getByTestId("restriction-events").locator("li")).toHaveCount(2);
    await expect(page.getByTestId("ansp-stale")).toContainText("The ANSP is stale");
    await expect(page.getByTestId("expiry-job")).toContainText("The expiry job last ran");
    // The status strip says it too, where the operator looks first.
    await expect(page.getByTestId("status-strip")).toContainText("Publisher ansp-01 silent since");
  });

  test("a fresh ANSP is not called stale (the pair)", async ({ page }) => {
    await signIn(page, VIEWER);
    await page.goto("/en/console/restrictions");
    await expect(page.locator('tr[data-restriction="DAR00A1"]')).toBeVisible();
    await expect(page.getByTestId("ansp-stale")).toHaveCount(0);
    await expect(page.getByTestId("status-strip")).not.toContainText("silent since");
  });

  test("the page says not available when the restriction endpoints answer 404", async ({ page, request }) => {
    await request.post("/__mock/console-state", { data: { restrictions404: true } });
    await signIn(page, VIEWER);
    await page.goto("/en/console/restrictions");
    await expect(page.getByTestId("restrictions-not-available")).toBeVisible();
    await expect(page.locator("tr[data-restriction]")).toHaveCount(0);
  });
});

test("an admin creates an account and sees its one-time password once", async ({ page }) => {
  await signIn(page, ADMIN);
  await page.goto("/en/console/accounts");
  await page.getByLabel("Username").fill("ops2");
  await page.getByLabel("Role").selectOption("publisher_admin");
  await page.getByRole("button", { name: "Create" }).click();
  const once = page.getByTestId("once-secrets");
  await expect(once).toContainText("Shown once.");
  await expect(once.getByTestId("initial-password")).toHaveText(/^init-[0-9a-f]{16}$/);
  await expect(once.getByTestId("totp-uri")).toHaveCount(0);
  await expect(page.locator('tr[data-account="ops2"]')).toContainText("Publisher administrator");
  await page.getByRole("button", { name: "I have copied it" }).click();
  await expect(page.getByTestId("once-secrets")).toHaveCount(0);
});

test.describe("locales", () => {
  test("the sign-in and the console render in Georgian", async ({ page }) => {
    await page.goto("/ka/console/login");
    await expect(page.locator("html")).toHaveAttribute("lang", "ka");
    await expect(page.getByRole("heading", { level: 2 })).toHaveText(GEORGIAN);
    await signIn(page, VIEWER, "ka");
    await page.goto("/ka/console/publications");
    await expect(page.getByRole("navigation", { name: "კონსოლის ნავიგაცია" }).getByRole("link").first()).toHaveText("მიმოხილვა");
    await expect(page.getByRole("heading", { name: "პუბლიკაციები" })).toBeVisible();
  });

  test("the same page renders in English", async ({ page }) => {
    await signIn(page, VIEWER);
    await page.goto("/en/console/publications");
    await expect(page.getByRole("heading", { name: "Publications" })).toBeVisible();
  });
});
