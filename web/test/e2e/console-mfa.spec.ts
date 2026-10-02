// The two-step console sign-in through the real BFF (`next start`) in the
// browser, against test/mock-api.mjs answering the CISP's
// POST /v1/console/session, POST /v1/console/session/mfa and
// GET /v1/console/me (docs/PLAN.md §15 Q41 (3)). The page script talks
// to /_bff/* only, as the console will: the password once, then the
// code; the challenge waits in the sealed HttpOnly `uspace_mfa` cookie
// and the session in `uspace_session`, neither readable by the page.
import { expect, test, type APIRequestContext, type Page } from "@playwright/test";

// The mock's test accounts and code (test/mock-api.mjs), not credentials.
const ADMIN = { username: "admin1", password: "admin1-test-password" };
const VIEWER = { username: "viewer1", password: "viewer1-test-password" };
const CODE = "246810";

interface Answer {
  status: number;
  body: Record<string, unknown>;
}

/** A POST to the BFF's sign-in from the page: same origin, the browser's cookies. */
async function signIn(page: Page, body: Record<string, string>): Promise<Answer> {
  return page.evaluate(async (b) => {
    const res = await fetch("/_bff/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(b),
    });
    const text = await res.text();
    return { status: res.status, body: text === "" ? {} : (JSON.parse(text) as Record<string, unknown>) };
  }, body);
}

async function me(page: Page): Promise<Answer> {
  return page.evaluate(async () => {
    const res = await fetch("/_bff/api/v1/console/me");
    return { status: res.status, body: (await res.json()) as Record<string, unknown> };
  });
}

interface ConsoleCall {
  method: string;
  path: string;
  keys: string[];
}

async function consoleCalls(request: APIRequestContext): Promise<ConsoleCall[]> {
  return (await (await request.get("/__mock/console")).json()) as ConsoleCall[];
}

test.beforeEach(async ({ request }) => {
  expect((await request.post("/__mock/reset")).ok()).toBe(true);
});

test("an MFA account signs in in two steps through the BFF", async ({ page, context, request }) => {
  await page.goto("/en");
  expect(await me(page)).toMatchObject({ status: 401 });

  const first = await signIn(page, ADMIN);
  expect(first).toEqual({ status: 200, body: { status: "mfa_required" } });
  let cookies = await context.cookies();
  const challenge = cookies.find((c) => c.name === "uspace_mfa");
  expect(challenge?.httpOnly).toBe(true);
  expect(challenge?.path).toBe("/_bff");
  expect(cookies.some((c) => c.name === "uspace_session")).toBe(false);
  // The page cannot read the challenge.
  expect(await page.evaluate(() => document.cookie)).not.toContain("uspace_mfa");

  // A wrong code is the API's 401, and the challenge stays for another try.
  const wrong = await signIn(page, { username: ADMIN.username, otp: "135790" });
  expect(wrong.status).toBe(401);
  expect(wrong.body["type"]).toBe("https://schemas.uspace.ge/problems/invalid_totp");

  const second = await signIn(page, { username: ADMIN.username, otp: CODE });
  expect(second).toEqual({ status: 200, body: { status: "signed_in" } });
  cookies = await context.cookies();
  expect(cookies.find((c) => c.name === "uspace_session")?.httpOnly).toBe(true);
  expect(cookies.some((c) => c.name === "uspace_mfa")).toBe(false);

  const who = await me(page);
  expect(who.status).toBe(200);
  expect(who.body["account"]).toMatchObject({ username: ADMIN.username, role: "admin" });

  // What reached the API: the password once, then the challenge and the
  // code, never the password again.
  const calls = (await consoleCalls(request)).filter((c) => c.method === "POST");
  expect(calls).toEqual([
    { method: "POST", path: "/v1/console/session", keys: ["password", "username"] },
    { method: "POST", path: "/v1/console/session/mfa", keys: ["code", "mfa_token"] },
    { method: "POST", path: "/v1/console/session/mfa", keys: ["code", "mfa_token"] },
  ]);

  // The challenge is spent: the code again has no challenge left.
  const again = await signIn(page, { username: ADMIN.username, otp: CODE });
  expect(again.status).toBe(401);
  expect(again.body["type"]).toBe("https://schemas.uspace.ge/problems/mfa_challenge_missing");
});

test("the code step without the password step is refused before the API", async ({ page, request }) => {
  await page.goto("/en");
  const res = await signIn(page, { username: ADMIN.username, otp: CODE });
  expect(res.status).toBe(401);
  expect(res.body["type"]).toBe("https://schemas.uspace.ge/problems/mfa_challenge_missing");
  expect(await consoleCalls(request)).toEqual([]);
});

test("an account without MFA signs in in one step (the pair)", async ({ page, context }) => {
  await page.goto("/en");
  expect(await signIn(page, VIEWER)).toEqual({ status: 200, body: { status: "signed_in" } });
  const cookies = await context.cookies();
  expect(cookies.some((c) => c.name === "uspace_session")).toBe(true);
  expect(cookies.some((c) => c.name === "uspace_mfa")).toBe(false);
  expect((await me(page)).body["account"]).toMatchObject({ username: VIEWER.username, role: "viewer" });
});
