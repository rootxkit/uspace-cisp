import path from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const root = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  resolve: {
    alias: [
      { find: /^@\//, replacement: `${root}/` },
      // The kit's auth/server marks itself server-only; a test is a server.
      { find: /^server-only$/, replacement: `${root}/test/server-only.ts` },
    ],
  },
  test: {
    environment: "node",
    include: ["**/*.test.ts"],
    exclude: ["node_modules/**", ".next/**", "test/e2e/**"],
    server: { deps: { inline: ["@rootxkit/uspace-ui"] } },
  },
});
