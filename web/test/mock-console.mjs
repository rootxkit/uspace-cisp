// The console API of test/mock-api.mjs: /v1/console/* in the shapes of
// api/openapi.yaml (the `console` tag), for the Playwright scenarios of
// the console (WP-11). Fixture data, not an implementation: the roles are
// the operations' x-role, the lockout is five failures for 15 minutes as
// the CISP's (docs/PLAN.md §6.6), and every action writes an audit row
// as the CISP does, so the audit page shows it. Nothing here edits
// content: republish writes a change record, never a version.
//
// Accounts (test data, not credentials of anything): admin1 (admin, MFA
// with the fixed code MOCK_TOTP_CODE), pub1 (publisher_admin), viewer1
// and lock1 (viewer; lock1 is the lockout scenario's).
//
// Control (through test/mock-api.mjs):
//   POST /__mock/console-state {restrictions404?, anspStale?}
import { randomBytes } from "node:crypto";

export const MOCK_TOTP_CODE = "246810";
const CHALLENGE_TTL_MS = 300_000;
const MAX_FAILED_LOGINS = 5;
const LOCKOUT_MS = 15 * 60_000;
const SESSION_TTL_MS = 3_600_000;
const T0 = "2026-10-01T08:00:00Z";

const ROLE_RANK = { viewer: 0, publisher_admin: 1, admin: 2 };

/** The x-role of each console operation (api/openapi.yaml), by method and path pattern. */
const ROUTES = [
  ["DELETE", /^\/v1\/console\/session$/, "viewer"],
  ["GET", /^\/v1\/console\/me$/, "viewer"],
  ["GET", /^\/v1\/console\/accounts$/, "admin"],
  ["POST", /^\/v1\/console\/accounts$/, "admin"],
  ["PATCH", /^\/v1\/console\/accounts\/([^/]+)$/, "admin"],
  ["GET", /^\/v1\/console\/publications$/, "viewer"],
  ["GET", /^\/v1\/console\/publications\/([^/]+)\/diff$/, "viewer"],
  ["POST", /^\/v1\/console\/publications\/([^/]+)\/republish$/, "publisher_admin"],
  ["GET", /^\/v1\/console\/restrictions$/, "viewer"],
  ["GET", /^\/v1\/console\/subscriptions$/, "viewer"],
  ["GET", /^\/v1\/console\/subscriptions\/([^/]+)\/deliveries$/, "viewer"],
  ["POST", /^\/v1\/console\/subscriptions\/([^/]+)\/suspend$/, "publisher_admin"],
  ["POST", /^\/v1\/console\/subscriptions\/([^/]+)\/resume$/, "publisher_admin"],
  ["POST", /^\/v1\/console\/subscriptions\/([^/]+)\/deliveries\/([^/]+)\/retry$/, "publisher_admin"],
  ["GET", /^\/v1\/console\/audit$/, "admin"],
  ["GET", /^\/v1\/console\/status$/, "viewer"],
];

function iso(ms) {
  return new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");
}

function hex(n) {
  return randomBytes(n).toString("hex");
}

function account(username, password, role, mfa) {
  return {
    id: `acc-${username}`,
    username,
    password,
    role,
    status: "active",
    mfa_required: mfa,
    mfa_enrolled: mfa,
    created_at: T0,
    failed_logins: 0,
    locked_until: null,
    last_login_at: null,
  };
}

function publicView(a) {
  const out = {
    id: a.id,
    username: a.username,
    role: a.role,
    status: a.status,
    mfa_required: a.mfa_required,
    mfa_enrolled: a.mfa_enrolled,
    created_at: a.created_at,
    failed_logins: a.failed_logins,
  };
  if (a.last_login_at !== null) out.last_login_at = a.last_login_at;
  if (a.locked_until !== null && a.locked_until > Date.now()) out.locked_until = iso(a.locked_until);
  return out;
}

function version(dataset, n, reason, counts, receivedAt) {
  return {
    id: `pub-${dataset}-${n}`,
    dataset,
    version: n,
    publisher: dataset === "restrictions" ? "ansp-01" : "authority-01",
    received_at: receivedAt,
    feature_count: counts[0],
    added: counts[1],
    changed: counts[2],
    removed: counts[3],
    reason,
    ...(n > 1 ? { supersedes_version: n - 1 } : {}),
  };
}

/** TSR001's changed paths: more than the page shows at once (its bound is 20). */
const TSR001_PATHS = [
  { path: "/properties/name/0/text", op: "changed" },
  { path: "/properties/limitedApplicability/0/schedule/0/endTime", op: "changed" },
  ...Array.from({ length: 23 }, (_, i) => ({ path: `/properties/zoneAuthority/0/name/${i}`, op: "added" })),
];

function seedPublications() {
  return {
    zones: [
      version("zones", 2, "publication", [3, 1, 1, 1], "2026-10-01T09:00:00Z"),
      version("zones", 1, "publication", [3, 3, 0, 0], T0),
    ],
    uspace_airspace: [version("uspace_airspace", 1, "publication", [1, 1, 0, 0], T0)],
    restrictions: [
      version("restrictions", 2, "restriction_activated", [2, 0, 1, 0], "2026-10-01T10:00:00Z"),
      version("restrictions", 1, "restriction_created", [2, 2, 0, 0], T0),
    ],
    ussp_list: [version("ussp_list", 1, "publication", [0, 0, 0, 0], T0)],
  };
}

const DIFFS = {
  "pub-zones-2": {
    previous_version: 1,
    features: [
      { feature_id: "TSN001", op: "added" },
      { feature_id: "TSR001", op: "changed", paths: TSR001_PATHS },
      { feature_id: "OLD0001", op: "removed" },
    ],
  },
  "pub-zones-1": {
    features: [
      { feature_id: "TSR001", op: "added" },
      { feature_id: "TSC001", op: "added" },
      { feature_id: "OLD0001", op: "added" },
    ],
  },
  "pub-uspace_airspace-1": { features: [{ feature_id: "TSU001", op: "added" }] },
  "pub-restrictions-2": {
    previous_version: 1,
    features: [{ feature_id: "DAR00A1", op: "changed", paths: [{ path: "/properties/extendedProperties/cis_restriction/state", op: "changed" }] }],
  },
  "pub-restrictions-1": {
    features: [
      { feature_id: "TSD001", op: "added" },
      { feature_id: "DAR00A1", op: "added" },
    ],
  },
  "pub-ussp_list-1": { features: [], body_paths: [{ path: "/ussps/0", op: "added" }] },
};

function heads() {
  return [
    {
      id: "01JDAR00A1",
      ansp_ref: "ref-DAR00A1",
      ansp_version: 2,
      uspace_airspace_id: "TSU001",
      feature_id: "DAR00A1",
      state: "active",
      starts_at: "2026-10-01T00:00:00Z",
      ends_at: "2027-01-01T00:00:00Z",
      created_at: T0,
      updated_at: "2026-10-01T10:00:00Z",
      last_publisher: "ansp-01",
      events: [
        { at: T0, op: "create", ansp_version: 1, publication_id: "pub-restrictions-1", actor: "ansp-01" },
        { at: "2026-10-01T10:00:00Z", op: "activate", ansp_version: 2, publication_id: "pub-restrictions-2", actor: "ansp-01" },
      ],
    },
    {
      id: "01JTSD001",
      ansp_ref: "ref-TSD001",
      ansp_version: 1,
      uspace_airspace_id: "TSU001",
      feature_id: "TSD001",
      state: "planned",
      starts_at: "2026-10-01T00:00:00Z",
      ends_at: "2026-10-08T00:00:00Z",
      created_at: T0,
      updated_at: T0,
      last_publisher: "ansp-01",
      events: [{ at: T0, op: "create", ansp_version: 1, publication_id: "pub-restrictions-1", actor: "ansp-01" }],
    },
  ];
}

function seedSubscriptions(now) {
  return [
    {
      sub: {
        id: "sub-01",
        client_id: "ussp-dev-01",
        callback_url: "https://ussp.example.invalid/v1/cis/notifications",
        datasets: ["zones", "restrictions"],
        bbox: [44.7, 41.65, 44.9, 41.8],
        status: "active",
        created_at: T0,
        verified_at: T0,
        consecutive_failures: 0,
        last_success_at: iso(now - 60_000),
      },
      deliveries: [
        {
          id: "del-0101",
          subscription_id: "sub-01",
          change_id: 7,
          reason: "publication",
          state: "delivered",
          attempts: 1,
          created_at: iso(now - 61_000),
          first_attempt_at: iso(now - 61_000),
          last_attempt_at: iso(now - 60_000),
          delivered_at: iso(now - 60_000),
          last_status_code: 204,
          log: [{ at: iso(now - 60_000), attempt: 1, status_code: 204, latency_ms: 41, payload_bytes: 812, deliver_instance: "deliver-1" }],
        },
      ],
    },
    {
      sub: {
        id: "sub-02",
        client_id: "lab-01",
        callback_url: "https://lab.example.invalid/v1/cis/notifications",
        datasets: ["zones"],
        status: "active",
        created_at: T0,
        verified_at: T0,
        consecutive_failures: 3,
        failing_since: iso(now - 600_000),
        last_success_at: iso(now - 3_600_000),
      },
      deliveries: [
        {
          id: "del-0201",
          subscription_id: "sub-02",
          change_id: 8,
          reason: "publication",
          state: "failed",
          attempts: 3,
          created_at: iso(now - 600_000),
          first_attempt_at: iso(now - 600_000),
          last_attempt_at: iso(now - 300_000),
          last_status_code: 503,
          last_error: "callback answered 503",
          log: [1, 2, 3].map((n) => ({
            at: iso(now - 600_000 + (n - 1) * 150_000),
            attempt: n,
            status_code: 503,
            error: "callback answered 503",
            latency_ms: 120 + n,
            payload_bytes: 812,
            deliver_instance: "deliver-1",
          })),
        },
        {
          id: "del-0202",
          subscription_id: "sub-02",
          change_id: 6,
          reason: "publication",
          state: "delivered",
          attempts: 1,
          created_at: iso(now - 3_600_000),
          last_attempt_at: iso(now - 3_600_000),
          delivered_at: iso(now - 3_600_000),
          last_status_code: 204,
          log: [{ at: iso(now - 3_600_000), attempt: 1, status_code: 204, latency_ms: 38, payload_bytes: 790, deliver_instance: "deliver-1" }],
        },
      ],
    },
    {
      sub: {
        id: "sub-03",
        client_id: "ussp-test-01",
        callback_url: "https://test.example.invalid/v1/cis/notifications",
        datasets: ["ussp_list"],
        status: "suspended",
        created_at: T0,
        suspended_reason: `suspended by admin1 at ${T0}: callback retired`,
        consecutive_failures: 0,
      },
      deliveries: [],
    },
  ];
}

function counts(deliveries) {
  const c = { queued: 0, delivering: 0, delivered: 0, failed: 0, expired: 0 };
  for (const d of deliveries) c[d.state] += 1;
  return c;
}

export function createConsole({ json, problem, readJson }) {
  let s;
  const requests = [];

  function audit(actorType, actorId, eventType, entityType, entityId, payload) {
    const prev = s.events[0]?.hash;
    s.events.unshift({
      id: ++s.eventId,
      ts: iso(Date.now()),
      actor_type: actorType,
      actor_id: actorId,
      event_type: eventType,
      entity_type: entityType,
      entity_id: entityId,
      payload,
      ...(prev === undefined ? {} : { prev_hash: prev }),
      hash: hex(32),
    });
  }

  function reset() {
    const now = Date.now();
    s = {
      accounts: new Map(
        [
          account("admin1", "admin1-test-password", "admin", true),
          account("pub1", "pub1-test-password", "publisher_admin", false),
          account("viewer1", "viewer1-test-password", "viewer", false),
          account("lock1", "lock1-test-password", "viewer", false),
        ].map((a) => [a.username, a]),
      ),
      challenges: new Map(),
      sessions: new Map(),
      next: 0,
      publications: seedPublications(),
      subscriptions: seedSubscriptions(now),
      events: [],
      eventId: 0,
      changeCursor: 41,
      restrictions404: false,
      anspStale: false,
    };
    audit("system", "system", "dataset_published", "publication", "pub-zones-2", { dataset: "zones", version: 2 });
    requests.length = 0;
  }
  reset();

  function issueSession(res, a) {
    const token = `mock-session-${++s.next}`;
    a.failed_logins = 0;
    a.last_login_at = iso(Date.now());
    s.sessions.set(token, a.username);
    audit("account", a.id, "session_issued", "session", token, {});
    json(res, 201, { token, expires_at: iso(Date.now() + SESSION_TTL_MS), account: publicView(a) });
  }

  function locked(res, a) {
    const left = Math.max(1, Math.ceil((a.locked_until - Date.now()) / 1000));
    return problem(res, 423, "locked", "Locked", { "Retry-After": String(left) }, "the account is locked after repeated failures; try again later");
  }

  function failLogin(res, a, slug) {
    audit("account", a.id, "login_failed", "account", a.id, { reason: slug });
    a.failed_logins += 1;
    if (a.failed_logins >= MAX_FAILED_LOGINS) {
      a.failed_logins = 0;
      a.locked_until = Date.now() + LOCKOUT_MS;
      audit("system", "system", "account_locked", "account", a.id, {});
    }
    return problem(res, 401, slug, "Unauthorized");
  }

  function caller(req) {
    const token = /^Bearer (.+)$/.exec(req.headers.authorization ?? "")?.[1];
    const username = token === undefined ? undefined : s.sessions.get(token);
    const a = username === undefined ? undefined : s.accounts.get(username);
    return a === undefined || a.status !== "active" ? null : { token, account: a };
  }

  function login(res, body) {
    const a = s.accounts.get(body.username);
    if (a === undefined || a.status !== "active") return problem(res, 401, "invalid_credentials", "Unauthorized");
    if (a.locked_until !== null && a.locked_until > Date.now()) return locked(res, a);
    if (a.password !== body.password) return failLogin(res, a, "invalid_credentials");
    if (!a.mfa_required) return issueSession(res, a);
    const token = `mock-challenge-${++s.next}`;
    const expiresAt = new Date(Date.now() + CHALLENGE_TTL_MS);
    s.challenges.set(token, { username: a.username, expiresAt, used: false });
    return json(res, 200, { mfa_token: token, expires_at: expiresAt.toISOString() });
  }

  function mfa(res, body) {
    const ch = s.challenges.get(body.mfa_token);
    if (ch === undefined || ch.used || ch.expiresAt.getTime() <= Date.now()) return problem(res, 401, "challenge_invalid", "Unauthorized");
    const a = s.accounts.get(ch.username);
    if (a.locked_until !== null && a.locked_until > Date.now()) return locked(res, a);
    if (body.code !== MOCK_TOTP_CODE) return failLogin(res, a, "invalid_totp");
    ch.used = true;
    return issueSession(res, a);
  }

  function reasonOf(res, body) {
    const r = typeof body.reason === "string" ? body.reason : "";
    if (r.length < 1 || r.length > 500) {
      problem(res, 400, "bad_request", "Bad request", {}, "reason: 1 to 500 characters", [{ field: "reason", reason: "1 to 500 characters" }]);
      return null;
    }
    return r;
  }

  function findSub(id) {
    return s.subscriptions.find((x) => x.sub.id === id);
  }

  function status() {
    const now = Date.now();
    const datasets = Object.entries(s.publications).map(([dataset, vs]) => ({
      dataset,
      current_version: vs[0]?.version ?? 0,
      updated_at: vs[0]?.received_at,
      etag: `"${dataset}:${vs[0]?.version ?? 0}"`,
    }));
    const ansp = s.anspStale
      ? { client_id: "ansp-01", kind: "ansp", stale: true, stale_after_s: 60, last_heartbeat_at: iso(now - 120_000), stale_since: iso(now - 60_000) }
      : { client_id: "ansp-01", kind: "ansp", stale: false, stale_after_s: 60, last_heartbeat_at: iso(now - 4_000) };
    return {
      status: {
        now: iso(now),
        datasets,
        publishers: [
          { client_id: "authority-01", kind: "authority", stale: false, stale_after_s: 60, last_heartbeat_at: iso(now - 7_000), last_publication_at: "2026-10-01T09:00:00Z" },
          ansp,
        ],
        degraded: [],
        mtls_mode: "required",
        restrictions: {
          active: 1,
          expiry: { last_run_at: iso(now - 3_000), last_instance: "api-1", last_count: 0, stale: false, stale_after_s: 30 },
          ansp_stale_since: s.anspStale ? iso(now - 60_000) : undefined,
        },
      },
      counters: { "console.sessions_issued": s.next, "deliver.attempts": 5 },
    };
  }

  async function handle(req, res, path, url) {
    const body = req.method === "POST" || req.method === "PATCH" ? await readJson(req) : {};
    requests.push({ method: req.method, path, keys: Object.keys(body).sort() });
    if (req.method === "POST" && path === "/v1/console/session") return login(res, body);
    if (req.method === "POST" && path === "/v1/console/session/mfa") return mfa(res, body);

    const route = ROUTES.find(([m, re]) => m === req.method && re.test(path));
    if (route === undefined) return problem(res, 404, "not_found", "Not found");
    const who = caller(req);
    if (who === null) return problem(res, 401, "unauthenticated", "Unauthorized");
    if (ROLE_RANK[who.account.role] < ROLE_RANK[route[2]]) {
      return problem(res, 403, "forbidden", "Forbidden", {}, `this operation needs the role ${route[2]}`);
    }
    const m = route[1].exec(path) ?? [];
    // The audit names the actor by account id, as the CISP does.
    const actor = who.account.id;

    if (req.method === "DELETE") {
      s.sessions.delete(who.token);
      res.writeHead(204);
      return res.end();
    }
    if (path === "/v1/console/me") {
      const now = new Date().toISOString();
      return json(res, 200, { account: publicView(who.account), session: { jti: who.token, issued_at: now, expires_at: iso(Date.now() + SESSION_TTL_MS) } });
    }
    if (path === "/v1/console/status") return json(res, 200, status());

    if (path === "/v1/console/publications") {
      const ds = url.searchParams.get("dataset");
      if (!(ds in s.publications)) return problem(res, 400, "bad_request", "Bad request", {}, "dataset", [{ field: "dataset", reason: "not a dataset" }]);
      const limit = Number(url.searchParams.get("limit") ?? "100");
      const before = Number(url.searchParams.get("before") ?? "0");
      const all = s.publications[ds].filter((v) => before === 0 || v.version < before);
      const page = all.slice(0, limit);
      return json(res, 200, { dataset: ds, versions: page, ...(all.length > limit ? { next_before: page.at(-1).version } : {}) });
    }
    if (route[1].source.includes("diff")) {
      const pub = Object.values(s.publications).flat().find((v) => v.id === m[1]);
      const d = DIFFS[m[1]];
      if (pub === undefined || d === undefined) return problem(res, 404, "not_found", "Not found");
      return json(res, 200, { publication: pub, truncated: false, ...d });
    }
    if (route[1].source.includes("republish")) {
      const reason = reasonOf(res, body);
      if (reason === null) return;
      const pub = Object.values(s.publications).flat().find((v) => v.id === m[1]);
      if (pub === undefined) return problem(res, 404, "not_found", "Not found");
      if (s.publications[pub.dataset][0].id !== pub.id) return problem(res, 409, "not_current", "Not the current version");
      const change = {
        schema: "cis/change/v1",
        msg_id: String(++s.changeCursor),
        producer: "uspace-cisp",
        dataset: pub.dataset,
        version: pub.version,
        etag: `"${pub.dataset}:${pub.version}"`,
        feature_ids: [],
        removed_ids: [],
        reason: "republished",
        at: iso(Date.now()),
        pull_url: `https://cisp.example.invalid/v1/${pub.dataset}?since_version=${pub.version - 1}`,
      };
      audit("account", actor, "console_republish", "publication", pub.id, { reason, dataset: pub.dataset, version: pub.version, change_id: Number(change.msg_id) });
      return json(res, 202, change);
    }

    if (path === "/v1/console/restrictions") {
      if (s.restrictions404) return problem(res, 404, "not_found", "Not found");
      const st = url.searchParams.get("state");
      const list = heads().filter((h) => st === null || h.state === st);
      return json(res, 200, { restrictions: list, ...(s.anspStale ? { cis_publisher_stale_since: iso(Date.now() - 60_000) } : {}) });
    }

    if (path === "/v1/console/subscriptions") {
      const st = url.searchParams.get("status");
      const list = s.subscriptions.filter((x) => st === null || x.sub.status === st);
      return json(res, 200, { subscriptions: list.map((x) => ({ subscription: x.sub, deliveries: counts(x.deliveries) })) });
    }
    if (m[1] !== undefined && path.startsWith("/v1/console/subscriptions/")) {
      const x = findSub(m[1]);
      if (x === undefined) return problem(res, 404, "not_found", "Not found");
      if (path.endsWith("/deliveries")) return json(res, 200, { deliveries: x.deliveries, log: "complete" });
      const reason = reasonOf(res, body);
      if (reason === null) return;
      if (path.endsWith("/suspend")) {
        if (x.sub.status !== "active" && x.sub.status !== "pending_verification") return problem(res, 409, "subscription_state", "Conflict");
        audit("account", actor, "console_subscription_suspended", "subscription", x.sub.id, { reason });
        x.sub.status = "suspended";
        x.sub.suspended_reason = `suspended by ${who.account.username} at ${iso(Date.now())}: ${reason}`;
        return json(res, 200, x.sub);
      }
      if (path.endsWith("/resume")) {
        if (x.sub.status !== "suspended") return problem(res, 409, "subscription_state", "Conflict");
        audit("account", actor, "console_subscription_resumed", "subscription", x.sub.id, { reason });
        x.sub.status = "pending_verification";
        delete x.sub.suspended_reason;
        return json(res, 200, x.sub);
      }
      const d = x.deliveries.find((y) => y.id === m[2]);
      if (d === undefined) return problem(res, 404, "not_found", "Not found");
      if (d.state === "delivering") return problem(res, 409, "delivering", "Conflict");
      audit("account", actor, "console_delivery_retried", "delivery", d.id, { reason, subscription_id: x.sub.id });
      d.state = "queued";
      d.next_retry_at = iso(Date.now());
      return json(res, 202, d);
    }

    if (path === "/v1/console/accounts" && req.method === "GET") {
      return json(res, 200, { accounts: [...s.accounts.values()].map(publicView) });
    }
    if (path === "/v1/console/accounts") {
      if (typeof body.username !== "string" || !/^[a-z0-9][a-z0-9._-]{2,63}$/.test(body.username)) {
        return problem(res, 400, "bad_request", "Bad request", {}, "username", [{ field: "username", reason: "lower case, 3-64 of a-z 0-9 . _ -" }]);
      }
      if (!(body.role in ROLE_RANK)) return problem(res, 400, "bad_request", "Bad request", {}, "role", [{ field: "role", reason: "not a role" }]);
      if (s.accounts.has(body.username)) return problem(res, 409, "username_taken", "Conflict");
      const mfaRequired = body.role === "admin" || body.mfa_required === true;
      const password = `init-${hex(8)}`;
      const a = account(body.username, password, body.role, mfaRequired);
      s.accounts.set(a.username, a);
      audit("account", actor, "account_created", "account", a.id, { username: a.username, role: a.role });
      return json(res, 201, {
        account: publicView(a),
        initial_password: password,
        ...(mfaRequired ? { totp_uri: `otpauth://totp/uspace-cisp:${a.username}?secret=${hex(10).toUpperCase()}&issuer=uspace-cisp` } : {}),
      });
    }
    if (path.startsWith("/v1/console/accounts/")) {
      const a = [...s.accounts.values()].find((x) => x.id === m[1]);
      if (a === undefined) return problem(res, 404, "not_found", "Not found");
      const activeAdmins = [...s.accounts.values()].filter((x) => x.role === "admin" && x.status === "active");
      const lastAdmin = a.role === "admin" && a.status === "active" && activeAdmins.length === 1;
      if (lastAdmin && ((body.role !== undefined && body.role !== "admin") || body.status === "disabled")) {
        return problem(res, 409, "last_admin", "Conflict", {}, "the last active admin can be neither demoted nor disabled");
      }
      let revoked = 0;
      const change = {};
      if (body.role !== undefined && body.role !== a.role) {
        a.role = body.role;
        change.role = body.role;
      }
      if (body.status !== undefined && body.status !== a.status) {
        a.status = body.status;
        change.status = body.status;
      }
      if (change.role !== undefined || change.status !== undefined) {
        for (const [tok, u] of s.sessions) {
          if (u === a.username) {
            s.sessions.delete(tok);
            revoked += 1;
          }
        }
      }
      let totpUri;
      if (body.reset_mfa === true) {
        a.mfa_enrolled = true;
        totpUri = `otpauth://totp/uspace-cisp:${a.username}?secret=${hex(10).toUpperCase()}&issuer=uspace-cisp`;
        change.reset_mfa = true;
      }
      audit("account", actor, "account_changed", "account", a.id, change);
      return json(res, 200, { account: publicView(a), sessions_revoked: revoked, ...(totpUri === undefined ? {} : { totp_uri: totpUri }) });
    }

    if (path === "/v1/console/audit") {
      const actorQ = url.searchParams.get("actor");
      const typeQ = url.searchParams.get("type");
      const sinceQ = url.searchParams.get("since");
      const beforeId = Number(url.searchParams.get("before_id") ?? "0");
      const limit = Number(url.searchParams.get("limit") ?? "100");
      const sinceMs = sinceQ === null ? 0 : Date.parse(sinceQ);
      if (Number.isNaN(sinceMs)) return problem(res, 400, "bad_request", "Bad request", {}, "since", [{ field: "since", reason: "not an RFC 3339 time" }]);
      const all = s.events.filter(
        (e) =>
          (actorQ === null || e.actor_id === actorQ) &&
          (typeQ === null || e.event_type === typeQ) &&
          Date.parse(e.ts) >= sinceMs &&
          (beforeId === 0 || e.id < beforeId),
      );
      const page = all.slice(0, limit);
      return json(res, 200, { events: page, ...(all.length > limit ? { next_before_id: page.at(-1).id } : {}) });
    }
    return problem(res, 404, "not_found", "Not found");
  }

  function control(input) {
    if (typeof input.restrictions404 === "boolean") s.restrictions404 = input.restrictions404;
    if (typeof input.anspStale === "boolean") s.anspStale = input.anspStale;
    return { restrictions404: s.restrictions404, anspStale: s.anspStale };
  }

  return { handle, reset, control, requests };
}
