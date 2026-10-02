#!/usr/bin/env node
// The web holds no signing key, no database URL and no NATS URL (WP-9
// safety note; spec 06 §3): after `next build`, no server bundle file may
// name the environment variables that carry them. A run that scanned no
// file proves nothing and fails (E-02).
//
//   node scripts/check-bundle-env.mjs [.next]
import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const FORBIDDEN_ENV = [
  "CISP_DATABASE_URL",
  "CISP_TIMESERIES_URL",
  "CISP_NATS_URL",
  "CISP_SIGNING",
  "CISP_SESSION_KEY",
  "CISP_SECRETS_KEY",
];

const SCANNED = /\.(?:[cm]?js|json)$/;

function* files(dir) {
  for (const name of readdirSync(dir)) {
    const p = path.join(dir, name);
    if (statSync(p).isDirectory()) yield* files(p);
    else if (SCANNED.test(name)) yield p;
  }
}

/**
 * Every forbidden name in the server bundle under `nextDir` (its `server`
 * and, when present, `standalone` directories), with the files naming it.
 */
export function scanBundle(nextDir) {
  const roots = ["server", "standalone"].map((d) => path.join(nextDir, d)).filter((d) => {
    try {
      return statSync(d).isDirectory();
    } catch {
      return false;
    }
  });
  let scanned = 0;
  const found = [];
  for (const root of roots) {
    for (const file of files(root)) {
      scanned++;
      const text = readFileSync(file, "utf8");
      for (const name of FORBIDDEN_ENV) {
        if (text.includes(name)) found.push({ name, file: path.relative(nextDir, file) });
      }
    }
  }
  return { scanned, found };
}

function main(argv) {
  const nextDir = argv[0] ?? ".next";
  const { scanned, found } = scanBundle(nextDir);
  if (scanned === 0) {
    console.error(`check-bundle-env: no server bundle file under ${nextDir}; run pnpm build first`);
    return 1;
  }
  if (found.length > 0) {
    for (const f of found) console.error(`check-bundle-env: ${f.name} in ${f.file}`);
    return 1;
  }
  console.log(`check-bundle-env: ${scanned} server bundle files, none names ${FORBIDDEN_ENV.join(", ")}`);
  return 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = main(process.argv.slice(2));
}
