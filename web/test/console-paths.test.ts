// No console page can reach a content write (WP-11 done-when; docs/PLAN.md
// §1.2, hard rule 2). The console's source (src/console/ and the pages
// under app/[locale]/(console)/) may name only these API paths:
//
// - /v1/console/*, through the BFF's proxy (which itself reaches nothing
//   else, src/bff/handlers.ts PROXY_ALLOW_PATHS);
// - /v1/stream, the status stream (read only, no frame is ever sent);
// - /public/v1/{dataset}, the public read the map previews make, through
//   a client that exposes GET only.
//
// The content routes (/v1/publications, /v1/restrictions) are named
// nowhere. Each rule is paired with a test that makes it fire.
import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { previewClient } from "../src/console/client";

const web = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const ROOTS = [path.join(web, "src", "console"), path.join(web, "app", "[locale]", "(console)")];

const CONTENT_ROUTES = /(?<![\w/])\/v1\/(publications|restrictions)\b/;
const API_PATH = /(?:\/public)?\/v1\/[A-Za-z0-9_{}\-./]*/g;
const ALLOWED = [/^\/v1\/console\//, /^\/v1\/stream$/, /^\/public\/v1\/\{dataset\}$/];
const METHOD_CALL = /\.(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\(\s*["'`]([^"'`]+)["'`]/g;

/** "file: problem" for every API path the console must not name. */
export function scan(file: string, source: string): string[] {
  const out: string[] = [];
  if (CONTENT_ROUTES.test(source)) out.push(`${file}: names a content route (${CONTENT_ROUTES.exec(source)?.[0] ?? ""})`);
  for (const m of source.matchAll(API_PATH)) {
    const p = m[0].replace(/[.]+$/, "");
    if (!ALLOWED.some((re) => re.test(p))) out.push(`${file}: ${p}`);
  }
  for (const m of source.matchAll(METHOD_CALL)) {
    const [, method, p] = m;
    if (p === undefined) continue;
    if (p.startsWith("/public/") && method !== "GET") out.push(`${file}: ${method ?? ""} ${p}`);
    if (method === "PUT" || method === "DELETE") out.push(`${file}: ${method} ${p}`);
  }
  return out;
}

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const p = path.join(dir, name);
    if (statSync(p).isDirectory()) return files(p);
    return /\.tsx?$/.test(name) && !/\.test\.tsx?$/.test(name) ? [p] : [];
  });
}

describe("the console's API paths", () => {
  it("the scan finds a content route, an unlisted path and a public write", () => {
    expect(scan("x.ts", `client.PUT("/v1/publications/{dataset}", {})`)).toEqual(
      expect.arrayContaining([expect.stringContaining("content route"), expect.stringContaining("PUT")]),
    );
    expect(scan("x.ts", "fetch(`${base}/v1/restrictions`)")).not.toEqual([]);
    expect(scan("x.ts", `c.GET("/v1/zones")`)).toEqual(["x.ts: /v1/zones"]);
    expect(scan("x.ts", `c.POST("/public/v1/{dataset}")`)).toEqual(["x.ts: POST /public/v1/{dataset}"]);
  });

  it("the scan passes the console's own paths", () => {
    expect(scan("x.ts", `c.GET("/v1/console/publications"); c.POST("/v1/console/publications/{id}/republish")`)).toEqual([]);
    expect(scan("x.ts", "useFeed({ url: `${base}/v1/stream` }); c.GET(\"/public/v1/{dataset}\")")).toEqual([]);
    // The console's own path is not a content route.
    expect(scan("x.ts", `c.GET("/v1/console/restrictions")`)).toEqual([]);
  });

  it("the console's source names no other path", () => {
    const all = ROOTS.flatMap(files);
    expect(all.length).toBeGreaterThan(10);
    const found = all.flatMap((f) => scan(path.relative(web, f), readFileSync(f, "utf8")));
    expect(found).toEqual([]);
    // And it does name the console API (the scan reads real files).
    expect(all.some((f) => readFileSync(f, "utf8").includes('"/v1/console/publications/{id}/republish"'))).toBe(true);
  });

  it("the preview client exposes GET only", () => {
    expect(Object.keys(previewClient("", () => "en"))).toEqual(["GET"]);
  });
});
