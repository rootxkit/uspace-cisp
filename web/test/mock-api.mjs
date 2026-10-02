#!/usr/bin/env node
// The Playwright fixture server: a stand-in for the deployment's Caddy in
// front of `next start`. It answers the CISP's public read surface
// (/public/v1/*) from fixtures and passes everything else to Next.js, so
// the browser sees one origin, as in a deployment.
//
//   MOCK_PORT=3000 MOCK_UPSTREAM=http://127.0.0.1:3100 node test/mock-api.mjs
//
// GET /__mock/requests lists the API requests it answered (method, path,
// If-None-Match) so a test can assert a fetch happened.
import http from "node:http";

const PORT = Number(process.env.MOCK_PORT ?? "3000");
const UPSTREAM = new URL(process.env.MOCK_UPSTREAM ?? "http://127.0.0.1:3100");
const UPDATED_AT = "2026-10-01T08:00:00Z";

const DATASETS = ["zones", "uspace_airspace", "restrictions", "ussp_list"];

/** The body of one dataset: an empty ED-318 collection, or the empty USSP list. */
function datasetBody(dataset) {
  const cis = { cis_dataset: dataset, cis_version: 1, cis_updated_at: UPDATED_AT };
  if (dataset === "ussp_list") return { ...cis, ussps: [] };
  return { type: "FeatureCollection", metadata: { issued: UPDATED_AT, provider: "fixture" }, ...cis, features: [] };
}

const requests = [];

function json(res, status, body, headers = {}) {
  const text = JSON.stringify(body);
  res.writeHead(status, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(text), ...headers });
  res.end(text);
}

function publicRead(req, res, dataset) {
  const etag = `"${dataset}:1"`;
  const headers = { ETag: etag, "Cache-Control": "no-cache", "X-CIS-Version": "1" };
  if (req.headers["if-none-match"] === etag) {
    res.writeHead(304, headers);
    res.end();
    return;
  }
  if (req.method === "HEAD") {
    res.writeHead(200, { ...headers, "Content-Type": "application/geo+json" });
    res.end();
    return;
  }
  json(res, 200, datasetBody(dataset), { ...headers, "Content-Type": "application/geo+json" });
}

function passToNext(req, res) {
  const upstream = http.request(
    {
      host: UPSTREAM.hostname,
      port: UPSTREAM.port,
      method: req.method,
      path: req.url,
      headers: { ...req.headers, "x-forwarded-for": req.socket.remoteAddress ?? "127.0.0.1" },
    },
    (up) => {
      res.writeHead(up.statusCode ?? 502, up.headers);
      up.pipe(res);
    },
  );
  upstream.on("error", (err) => {
    if (!res.headersSent) json(res, 502, { title: "upstream unreachable", detail: err.message });
    else res.destroy(err);
  });
  req.pipe(upstream);
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url ?? "/", "http://mock");
  if (url.pathname === "/__mock/health") return json(res, 200, { ok: true });
  if (url.pathname === "/__mock/requests") return json(res, 200, requests);
  const m = /^\/public\/v1\/([a-z_]+)$/.exec(url.pathname);
  if (m) {
    requests.push({ method: req.method, path: url.pathname + url.search, ifNoneMatch: req.headers["if-none-match"] ?? null });
    const dataset = m[1];
    if (!DATASETS.includes(dataset) || (req.method !== "GET" && req.method !== "HEAD")) {
      return json(res, 404, { type: "https://schemas.uspace.ge/problems/not_found", title: "Not found", status: 404 });
    }
    return publicRead(req, res, dataset);
  }
  return passToNext(req, res);
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(`mock-api: 127.0.0.1:${PORT}, pages from ${UPSTREAM.origin}`);
});
