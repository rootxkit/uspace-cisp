import path from "node:path";
import { fileURLToPath } from "node:url";
import { PHASE_DEVELOPMENT_SERVER } from "next/constants";
import type { NextConfig } from "next";

const root = path.dirname(fileURLToPath(import.meta.url));

export default function config(phase: string): NextConfig {
  // `pnpm dev` only: CISP_DEV_API_URL sends the API paths Caddy routes in
  // a deployment (/public/*, /v1/*, /.well-known/*) to a local api. A
  // build never has rewrites; the image is configured at start.
  const devApi = phase === PHASE_DEVELOPMENT_SERVER ? process.env["CISP_DEV_API_URL"] : undefined;
  return {
    output: "standalone",
    outputFileTracingRoot: root,
    turbopack: { root },
    poweredByHeader: false,
    reactStrictMode: true,
    // The CSP is set per request with its nonce in proxy.ts (src/csp.ts);
    // these hold for every response, assets included.
    async headers() {
      return [
        {
          source: "/:path*",
          headers: [
            { key: "X-Content-Type-Options", value: "nosniff" },
            { key: "Referrer-Policy", value: "no-referrer" },
            { key: "X-Frame-Options", value: "DENY" },
            { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
          ],
        },
      ];
    },
    async rewrites() {
      if (devApi === undefined || devApi === "") return [];
      return ["/public/:path*", "/v1/:path*", "/.well-known/:path*"].map((source) => ({
        source,
        destination: `${devApi.replace(/\/$/, "")}${source}`,
      }));
    },
  };
}
