// The Playwright smoke run: `next start` behind test/mock-api.mjs, which
// stands in for Caddy (one origin; /public/v1/* answered from fixtures).
// Run `pnpm build` first.
import { defineConfig, devices } from "@playwright/test";

const CI = process.env["CI"] !== undefined;
const WEB_PORT = "3100";
const ORIGIN_PORT = "3000";

export default defineConfig({
  testDir: "test/e2e",
  workers: 1,
  retries: 0,
  forbidOnly: CI,
  reporter: CI ? [["list"], ["github"]] : "list",
  use: {
    baseURL: `http://127.0.0.1:${ORIGIN_PORT}`,
    trace: "retain-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: [
    {
      command: `pnpm exec next start --port ${WEB_PORT} --hostname 127.0.0.1`,
      url: `http://127.0.0.1:${WEB_PORT}/healthz`,
      reuseExistingServer: !CI,
      env: { NEXT_TELEMETRY_DISABLED: "1", CISP_API_INTERNAL_URL: `http://127.0.0.1:${ORIGIN_PORT}` },
    },
    {
      command: "node test/mock-api.mjs",
      url: `http://127.0.0.1:${ORIGIN_PORT}/__mock/health`,
      reuseExistingServer: !CI,
      env: { MOCK_PORT: ORIGIN_PORT, MOCK_UPSTREAM: `http://127.0.0.1:${WEB_PORT}` },
    },
  ],
});
