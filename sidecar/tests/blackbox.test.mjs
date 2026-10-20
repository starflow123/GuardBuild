import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { runBlackbox, openapiRoutes, extractItems, extractEntityById, extractOwner } from "../lib/blackbox.mjs";

function jsonPath(obj, path) {
  return String(path)
    .split(".")
    .reduce((o, k) => (o && typeof o === "object" ? o[k] : undefined), obj);
}

function targetServer({ fixed = false } = {}) {
  const tokens = new Map();
  const orders = {
    1: [{ id: 101, userId: 1, item: "alice-order" }],
    2: [{ id: 102, userId: 2, item: "bob-secret" }],
  };
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, "http://127.0.0.1");
    const send = (status, body) => {
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(JSON.stringify(body));
    };
    const authHeader = req.headers.authorization ?? "";
    const token = authHeader.replace(/^Bearer\s+/, "");
    const user = tokens.get(token) ?? null;

    if (req.method === "POST" && url.pathname === "/api/login") {
      const chunks = [];
      for await (const c of req) chunks.push(c);
      const body = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
      const users = {
        "alice@test.com": { id: 1, email: "alice@test.com", password: "alice123" },
        "bob@test.com": { id: 2, email: "bob@test.com", password: "bob123" },
      };
      const u = users[body.email];
      if (!u || u.password !== body.password) return send(401, { error: "bad credentials" });
      const t = `tok-${u.id}`;
      tokens.set(t, u);
      return send(200, { authentication: { token: t, user: { id: u.id, role: "user", email: u.email } } });
    }

    if (req.method === "GET" && url.pathname === "/api/me") {
      if (!user) return send(401, { error: "unauthorized" });
      return send(200, { user: { id: user.id, email: user.email } });
    }

    if (req.method === "GET" && url.pathname === "/api/orders") {
      if (!user) return send(401, { error: "unauthorized" });
      const items = orders[user.id] ?? [];
      return send(200, { code: 0, data: { items, total: items.length } });
    }

    const detail = url.pathname.match(/^\/api\/orders\/(\d+)$/);
    if (detail) {
      if (!user) return send(401, { error: "unauthorized" });
      const id = Number(detail[1]);
      const ownerId = id === 101 ? 1 : id === 102 ? 2 : null;
      const item = orders[ownerId]?.find((o) => o.id === id);
      if (!item) return send(404, { error: "not found" });
      if (fixed && user.id !== ownerId) return send(403, { error: "forbidden" });
      if (req.method === "GET") return send(200, { code: 0, data: { ...item } });
      if (req.method === "PUT") {
        const chunks = [];
        for await (const c of req) chunks.push(c);
        const body = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
        if (typeof body.item === "string") item.item = body.item;
        return send(200, { code: 0, data: { ...item } });
      }
    }

    return send(404, { error: "not found" });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      resolve({
        url: `http://127.0.0.1:${server.address().port}`,
        close: () => new Promise((r) => server.close(r)),
        orders,
      });
    });
  });
}

function makeCtx(vault) {
  const events = [];
  const evidence = [];
  const ctx = {
    sessionId: "s_blackbox_test",
    tokens: { http: "session-token" },
    identities: [
      { name: "alice", email: "alice@test.com", password: "alice123", role: "user" },
      { name: "bob", email: "bob@test.com", password: "bob123", role: "user" },
    ],
    loginConfig: {
      path: "/api/login",
      bodyTemplate: { email: "{email}", password: "{password}" },
      credentialPath: "authentication.token",
      credentialPrefix: "Bearer ",
      credentialHeader: "Authorization",
      extraHeaders: {},
    },
    events,
    evidence,
    emit(ev) {
      events.push(ev);
    },
    db: {
      insertEvidence(rec) {
        evidence.push(rec);
      },
    },
    rpc: {
      async request(method, params) {
        assert.equal(method, "http.request");
        const headers = { ...(params.headers ?? {}) };
        if (params.identityRef) {
          const cred = vault.get(params.identityRef);
          assert.ok(cred, `vault missing credential for ${params.identityRef}`);
          headers[cred.header] = cred.value;
        }
        const res = await fetch(params.url, { method: params.method, headers, body: params.body });
        const body = await res.text();
        let storedIdentity;
        if (params.storeCredentialAs) {
          let parsed = null;
          try {
            parsed = JSON.parse(body);
          } catch {
            /* ignore */
          }
          const value = parsed ? jsonPath(parsed, params.credentialPath) : undefined;
          if (value != null) {
            vault.set(params.storeCredentialAs, {
              header: params.credentialHeader ?? "Authorization",
              value: `${params.credentialPrefix ?? ""}${value}`,
            });
            storedIdentity = params.storeCredentialAs;
          }
        }
        return {
          status: res.status,
          statusText: res.statusText,
          body,
          headers: {},
          redacted: false,
          durationMs: 1,
          storedIdentity,
        };
      },
    },
  };
  return ctx;
}

test("extractItems/extractEntityById/extractOwner: 兼容嵌套 data.items 形状", () => {
  const json = { code: 0, data: { items: [{ id: 7, ownerId: 3, name: "x" }] } };
  const items = extractItems(json);
  assert.equal(items.length, 1);
  assert.equal(extractOwner(items[0]).field, "ownerId");
  assert.equal(extractEntityById({ data: { order: { id: 7 } } }, 7).id, 7);
  assert.equal(extractEntityById({ data: { order: { id: 8 } } }, 7), null);
});

test("runBlackbox: 经 Host 登录 + 跨用户读取复现（cross-proven）", async () => {
  const target = await targetServer();
  const vault = new Map();
  const ctx = makeCtx(vault);
  try {
    const result = await runBlackbox(ctx, target.url, {
      config: { login: ctx.loginConfig, identities: ctx.identities, blackbox: null },
      allowMutation: false,
    });
    assert.equal(result.reachable, true);
    assert.equal(result.login.ok, true);
    assert.ok(result.routes.some((r) => r.path === "/api/orders"));
    assert.equal(result.findings.length, 1, JSON.stringify(result.findings));
    assert.match(result.findings[0].type, /IDOR/);
    assert.match(result.findings[0].path, /\/api\/orders\/102$/);

    const idor = result.evidence.find((e) => e.caseId.startsWith("blackbox-idor-"));
    assert.ok(idor);
    assert.equal(idor.verdict, "vulnerable");
    assert.equal(idor.evidenceGrade, "cross-proven");
    assert.equal(idor.identity, "alice");
    assert.ok(!JSON.stringify(idor).includes("tok-"), "证据不得包含令牌明文");
    assert.ok(ctx.events.some((e) => e.kind === "identity" && e.message.includes("alice")));
    assert.ok(!result.evidence.some((e) => e.method === "PUT"), "默认不执行写操作探测");
  } finally {
    await target.close();
  }
});

test("runBlackbox: 有归属校验时标记 blocked，且无漏洞结论", async () => {
  const target = await targetServer({ fixed: true });
  const vault = new Map();
  const ctx = makeCtx(vault);
  try {
    const result = await runBlackbox(ctx, target.url, {
      config: { login: ctx.loginConfig, identities: ctx.identities, blackbox: null },
      allowMutation: false,
    });
    assert.equal(result.findings.length, 0);
    const idor = result.evidence.find((e) => e.caseId.startsWith("blackbox-idor-"));
    assert.ok(idor);
    assert.equal(idor.verdict, "blocked");
    assert.equal(result.summary.attackBlocked, 1);
  } finally {
    await target.close();
  }
});

function openapiServer(count) {
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, "http://127.0.0.1");
    if (url.pathname === "/openapi.json") {
      const paths = {};
      for (let i = 0; i < count; i++) {
        paths[`/api/items${i}`] = { get: { responses: { 200: { description: "ok" } } } };
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ openapi: "3.0.0", paths }));
      return;
    }
    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "not found" }));
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      resolve({
        url: `http://127.0.0.1:${server.address().port}`,
        close: () => new Promise((r) => server.close(r)),
      });
    });
  });
}

test("openapiRoutes: limit 截断路由数量", () => {
  const paths = {};
  for (let i = 0; i < 25; i++) paths[`/api/r${i}`] = { get: {} };
  const found = { doc: { openapi: "3.0.0", paths } };
  assert.equal(openapiRoutes(found, 10).length, 10);
  assert.equal(openapiRoutes(found, 200).length, 25);
  assert.equal(openapiRoutes(found).length, 25);
});

test("runBlackbox: blackbox.maxRoutes 控制发现与探测上限", async () => {
  const target = await openapiServer(30);
  const ctx = makeCtx(new Map());
  try {
    const capped = await runBlackbox(ctx, target.url, {
      config: { login: ctx.loginConfig, identities: ctx.identities, blackbox: { maxRoutes: 10 } },
      allowMutation: false,
    });
    assert.equal(capped.maxRoutes, 10);
    assert.equal(capped.routes.length, 10);
    assert.ok(capped.routes.every((r) => r.path.startsWith("/api/items")));
    const start = ctx.events.find((e) => e.kind === "phase" && e.message.startsWith("开始黑盒"));
    assert.equal(start.data.routeCap, 10);
    assert.equal(start.data.probeCap, 10);

    const dflt = await runBlackbox(ctx, target.url, {
      config: { login: ctx.loginConfig, identities: ctx.identities, blackbox: null },
      allowMutation: false,
    });
    assert.equal(dflt.maxRoutes, 60);
    assert.equal(dflt.openapiRouteCount, 30);
    assert.equal(dflt.routes.length, 53, "30 条 OpenAPI + 23 条目录探测（404 亦视为路由存在）");
  } finally {
    await target.close();
  }
});

test("runBlackbox: 目标不可达时 reachable=false（供调用方判失败）", async () => {
  const ctx = makeCtx(new Map());
  ctx.rpc.request = async () => {
    throw new Error("connection refused");
  };
  const result = await runBlackbox(ctx, "http://127.0.0.1:1", {
    config: { login: ctx.loginConfig, identities: ctx.identities, blackbox: null },
    allowMutation: false,
  });
  assert.equal(result.reachable, false);
  assert.equal(result.findings.length, 0);
});
