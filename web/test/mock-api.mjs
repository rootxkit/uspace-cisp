#!/usr/bin/env node
// The Playwright fixture server: a stand-in for the deployment's Caddy in
// front of `next start`. It answers the CISP's public surface from
// fixtures (GET and HEAD /public/v1/*, WS /v1/stream) and passes every
// other request to Next.js, so the browser sees one origin, as in a
// deployment.
//
//   MOCK_PORT=3000 MOCK_UPSTREAM=http://127.0.0.1:3100 node test/mock-api.mjs
//
// The datasets are the ED-318 base collection of uspace-core's
// ed318_roundtrip.json (test/fixtures), split as the CISP splits it
// (USPACE in uspace_airspace, DAR in restrictions), plus one polygon
// restriction. The applicability annotations (applies_at) are fixture
// values chosen per feature, not an evaluation: the web never judges, and
// neither does its test server.
//
// Control (tests only):
//   GET  /__mock/requests                 the API requests answered
//   POST /__mock/reset                    stream on, every dataset served at version 1
//   POST /__mock/state {stream?, unavailable?: [dataset], publisherStaleSince?}
//   POST /__mock/bump {dataset}           a new version of one dataset
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import http from "node:http";

const PORT = Number(process.env.MOCK_PORT ?? "3000");
const UPSTREAM = new URL(process.env.MOCK_UPSTREAM ?? "http://127.0.0.1:3100");
const STATUS_PERIOD_MS = 1000;
const UPDATED_AT = "2026-10-01T08:00:00Z";

const base = JSON.parse(readFileSync(new URL("./fixtures/ed318_roundtrip.base.json", import.meta.url), "utf8"));
const byId = Object.fromEntries(base.features.map((f) => [f.properties.identifier, f]));

function withExtended(feature, extra) {
  const props = feature.properties;
  return { ...feature, properties: { ...props, extendedProperties: { ...(props.extendedProperties ?? {}), ...extra } } };
}

const RESTRICTION_POLYGON = {
  type: "Feature",
  geometry: {
    type: "Polygon",
    coordinates: [
      [
        [44.74, 41.68],
        [44.76, 41.68],
        [44.76, 41.7],
        [44.74, 41.7],
        [44.74, 41.68],
      ],
    ],
    layer: { lower: 0, lowerReference: "AGL", upper: 120, upperReference: "AGL", uom: "m" },
  },
  properties: {
    identifier: "DAR00A1",
    country: "GEO",
    name: [
      { lang: "en-GB", text: "Test dynamic restriction" },
      { lang: "ka-GE", text: "სატესტო დინამიკური შეზღუდვა" },
    ],
    type: "PROHIBITED",
    variant: "COMMON",
    reason: ["DAR"],
    limitedApplicability: [{ startDateTime: "2026-10-01T00:00:00Z", endDateTime: "2027-01-01T00:00:00Z" }],
    zoneAuthority: [{ name: [{ lang: "en-GB", text: "Test ANSP" }], purpose: "NOTIFICATION" }],
  },
};

const RESTRICTION_STATE = {
  TSD001: { state: "planned", starts_at: "2026-10-01T00:00:00Z", ends_at: "2026-10-08T00:00:00Z" },
  DAR00A1: { state: "active", starts_at: "2026-10-01T00:00:00Z", ends_at: "2027-01-01T00:00:00Z" },
};

function restriction(feature) {
  const id = feature.properties.identifier;
  return withExtended(feature, {
    cis_restriction: {
      id: `01J${id}`,
      ansp_ref: `ref-${id}`,
      ansp_version: 1,
      ...RESTRICTION_STATE[id],
      ended_by: null,
      uspace_airspace_id: "TSU001",
    },
  });
}

const FEATURES = {
  zones: [byId.TSR001, byId.TSC001, byId.TSN001],
  uspace_airspace: [byId.TSU001],
  restrictions: [restriction(byId.TSD001), restriction(RESTRICTION_POLYGON)],
};

const USSP_LIST = {
  schema: "cis/ussp_list/v1",
  issued: UPDATED_AT,
  ussps: [
    {
      ussp_id: "USSPDEV",
      name: "Test USSP",
      contact: { email: "ops@example.invalid" },
      services: ["network_identification", "geo_awareness", "flight_authorisation", "traffic_information"],
      certification_limitations: ["Daytime operations only"],
      valid_from: "2026-01-01T00:00:00Z",
      valid_until: "2027-01-01T00:00:00Z",
      terms_url: "https://example.invalid/terms",
      status: "operating",
    },
  ],
};

/**
 * Fixture verdicts at `at`: TSR001 (weekdays 08:00-18:00 +04:00) applies
 * on a weekday in that window, else not; TSD001 (daylight events) is
 * unknown; the rest apply.
 */
function verdict(id, at) {
  if (id === "TSD001") return "unknown";
  if (id === "TSR001") {
    const local = new Date(at.getTime() + 4 * 3600_000);
    const day = local.getUTCDay();
    const h = local.getUTCHours();
    return day >= 1 && day <= 5 && h >= 8 && h < 18 ? "applies" : "not_applicable";
  }
  return "applies";
}

let state;
function reset() {
  state = {
    stream: true,
    unavailable: new Set(),
    publisherStaleSince: undefined,
    versions: { zones: 1, uspace_airspace: 1, restrictions: 1, ussp_list: 1 },
  };
}
reset();
const requests = [];
const clients = new Set();

function body(dataset, appliesAt) {
  const cis = { cis_dataset: dataset, cis_version: state.versions[dataset], cis_updated_at: UPDATED_AT };
  if (dataset === "ussp_list") return { ...USSP_LIST, ...cis };
  const at = appliesAt === null ? null : new Date(appliesAt);
  const features = FEATURES[dataset].map((f) =>
    at === null || Number.isNaN(at.getTime()) ? f : withExtended(f, { cis_applicability: verdict(f.properties.identifier, at) }),
  );
  const extra =
    dataset === "restrictions" && state.publisherStaleSince !== undefined
      ? { cis_publisher_stale_since: state.publisherStaleSince }
      : {};
  return { type: "FeatureCollection", metadata: { issued: UPDATED_AT, provider: "fixture" }, ...cis, ...extra, features };
}

function json(res, status, payload, headers = {}) {
  const text = JSON.stringify(payload);
  res.writeHead(status, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(text), ...headers });
  res.end(text);
}

function problem(res, status, slug, title, headers = {}) {
  json(
    res,
    status,
    { type: `https://schemas.uspace.ge/problems/${slug}`, title, status },
    { "Content-Type": "application/problem+json", ...headers },
  );
}

function publicRead(req, res, url, dataset) {
  if (state.unavailable.has(dataset)) {
    if (req.method === "HEAD") {
      res.writeHead(503, { "Retry-After": "5" });
      res.end();
      return;
    }
    problem(res, 503, "cis_stale", "The CIS cannot serve this dataset now", { "Retry-After": "5" });
    return;
  }
  const etag = `"${dataset}:${state.versions[dataset]}"`;
  const headers = { ETag: etag, "Cache-Control": "no-cache", "X-CIS-Version": String(state.versions[dataset]) };
  if (req.headers["if-none-match"] === etag) {
    res.writeHead(304, headers);
    res.end();
    return;
  }
  const type = dataset === "ussp_list" ? "application/json" : "application/geo+json";
  if (req.method === "HEAD") {
    res.writeHead(200, { ...headers, "Content-Type": type });
    res.end();
    return;
  }
  json(res, 200, body(dataset, url.searchParams.get("applies_at")), { ...headers, "Content-Type": type });
}

function readJson(req) {
  return new Promise((resolve) => {
    let text = "";
    req.on("data", (c) => (text += c));
    req.on("end", () => {
      try {
        resolve(text === "" ? {} : JSON.parse(text));
      } catch {
        resolve({});
      }
    });
  });
}

async function control(req, res, path) {
  if (path === "/__mock/health") return json(res, 200, { ok: true });
  if (path === "/__mock/requests") return json(res, 200, requests);
  const input = await readJson(req);
  if (path === "/__mock/reset") {
    reset();
    requests.length = 0;
    for (const c of clients) c.destroy();
  } else if (path === "/__mock/state") {
    if (typeof input.stream === "boolean") {
      state.stream = input.stream;
      if (!state.stream) for (const c of clients) c.destroy();
    }
    if (Array.isArray(input.unavailable)) state.unavailable = new Set(input.unavailable);
    if ("publisherStaleSince" in input) state.publisherStaleSince = input.publisherStaleSince;
  } else if (path === "/__mock/bump") {
    if (typeof input.dataset === "string" && input.dataset in state.versions) state.versions[input.dataset] += 1;
  } else {
    return json(res, 404, { error: "unknown control" });
  }
  return json(res, 200, { versions: state.versions, stream: state.stream, unavailable: [...state.unavailable] });
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

// WS /v1/stream: server-to-client text frames only (RFC 6455 section
// 5.2), the common envelope around console/status/v1 on connect and
// every period.
function wsText(text) {
  const payload = Buffer.from(text);
  let head;
  if (payload.length < 126) {
    head = Buffer.from([0x81, payload.length]);
  } else if (payload.length < 65536) {
    head = Buffer.alloc(4);
    head[0] = 0x81;
    head[1] = 126;
    head.writeUInt16BE(payload.length, 2);
  } else {
    head = Buffer.alloc(10);
    head[0] = 0x81;
    head[1] = 127;
    head.writeBigUInt64BE(BigInt(payload.length), 2);
  }
  return Buffer.concat([head, payload]);
}

let msg = 0;
function statusFrame() {
  const now = new Date().toISOString();
  const datasets = Object.fromEntries(
    ["zones", "uspace_airspace", "restrictions"].map((d) => [d, { version: String(state.versions[d]), age_s: 1 }]),
  );
  return JSON.stringify({
    schema: "console/status/v1",
    msg_id: `mock-${++msg}`,
    producer: "cisp/api",
    ts: now,
    rx_ts: now,
    captured_at: now,
    time_source: "system",
    backlog: false,
    body: {
      connection_id: "mock-connection",
      server_ts: now,
      policy_version: "cfg-000000000000",
      stale_after_s: 60,
      live_max_age_s: 3,
      dropped_frames: 0,
      degraded: [],
      sources: [],
      datasets,
      nats: "connected",
    },
  });
}

function upgrade(req, socket) {
  const url = new URL(req.url ?? "/", "http://mock");
  const key = req.headers["sec-websocket-key"];
  if (url.pathname !== "/v1/stream" || !state.stream || typeof key !== "string") {
    socket.end("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    return;
  }
  const accept = createHash("sha1").update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).digest("base64");
  socket.write(
    `HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`,
  );
  clients.add(socket);
  const send = () => {
    if (!socket.destroyed) socket.write(wsText(statusFrame()));
  };
  send();
  const timer = setInterval(send, STATUS_PERIOD_MS);
  const end = () => {
    clearInterval(timer);
    clients.delete(socket);
  };
  socket.on("data", () => undefined);
  socket.on("close", end);
  socket.on("error", end);
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url ?? "/", "http://mock");
  if (url.pathname.startsWith("/__mock/")) {
    void control(req, res, url.pathname);
    return;
  }
  const m = /^\/public\/v1\/([a-z_]+)$/.exec(url.pathname);
  if (m) {
    requests.push({
      method: req.method,
      path: url.pathname,
      query: Object.fromEntries(url.searchParams),
      ifNoneMatch: req.headers["if-none-match"] ?? null,
      atMs: Date.now(),
    });
    const dataset = m[1];
    if (!(dataset in state.versions) || (req.method !== "GET" && req.method !== "HEAD")) {
      problem(res, 404, "not_found", "Not found");
      return;
    }
    publicRead(req, res, url, dataset);
    return;
  }
  passToNext(req, res);
});
server.on("upgrade", upgrade);

server.listen(PORT, "127.0.0.1", () => {
  console.log(`mock-api: 127.0.0.1:${PORT}, pages from ${UPSTREAM.origin}`);
});
