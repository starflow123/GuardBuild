import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { runBlackbox, openapiRoutes, extractItems, extractEntityById, extractOwner, extractRoutesFromText } from "../lib/blackbox.mjs";

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
        if (params.storeCookieAs) {
          const cookies = (res.headers.getSetCookie?.() ?? []).map((c) => c.split(";")[0]);
          if (cookies.length) {
            vault.set(params.storeCookieAs, { header: "Cookie", value: cookies.join("; ") });
            storedIdentity = params.storeCookieAs;
          }
        }
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
          headers: Object.fromEntries([...res.headers.entries()].filter(([k]) => k.toLowerCase() !== "set-cookie")),
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
    assert.equal(dflt.routes.length, 60, "OpenAPI 30 条优先占位，剩余名额由目录探测补满");
    assert.ok(dflt.routes.filter((r) => r.source === "openapi").length === 30);
    assert.ok(dflt.routes.length <= dflt.maxRoutes);
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

/** 注入缺口靶子：搜索参数名是 query（不是写死的 q），值被直接拼进 LIKE；
 *  spec=true 时通过 OpenAPI 声明参数名，false 时只能靠常见参数名回退。
 *  复刻 DVWA-modern /api/products/search 的形态。 */
function sqliTargetServer({ spec = true } = {}) {
  const tokens = new Map([["tok-1", { id: 1 }]]);
  const products = Array.from({ length: 20 }, (_, i) => ({ id: i + 1, name: `prod-${i + 1}`, price: i }));
  const rows = (raw) => {
    if (raw == null) return [];
    if (/OR\s+1\s*=\s*1/.test(raw)) return products;
    if (/OR\s+1\s*=\s*2/.test(raw)) return [];
    return products.filter((p) => p.name.includes(raw));
  };
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, "http://127.0.0.1");
    const send = (status, body) => {
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(JSON.stringify(body));
    };
    if (req.method === "POST" && url.pathname === "/api/login") {
      return send(200, { authentication: { token: "tok-1", user: { id: 1, role: "user" } } });
    }
    if (url.pathname === "/openapi.json" && spec) {
      return send(200, {
        openapi: "3.0.0",
        paths: {
          "/api/products": { get: { parameters: [{ name: "query", in: "query" }] } },
          "/api/report": { get: { parameters: [{ name: "file", in: "query" }] } },
          "/api/bank_codes": { get: { parameters: [{ name: "code", in: "query" }] } },
        },
      });
    }
    const authed = tokens.get((req.headers.authorization ?? "").replace(/^Bearer\s+/, ""));
    if (url.pathname === "/api/products") {
      if (!authed) return send(401, { error: "unauthorized" });
      // 只认 query；未知参数（q=）被忽略，等价于做了参数白名单的框架
      return send(200, { items: rows(url.searchParams.get("query")), total: rows(url.searchParams.get("query")).length });
    }
    if (url.pathname === "/api/report") {
      if (!authed) return send(401, { error: "unauthorized" });
      const f = url.searchParams.get("file") ?? "";
      return send(200, {
        content: f.includes("..") ? "root:x:0:0:root:/root:/bin/sh" : "quarterly report",
      });
    }
    if (url.pathname === "/api/bank_codes") {
      if (!authed) return send(401, { error: "unauthorized" });
      const code = url.searchParams.get("code") ?? "";
      // 复刻 fetchone 型端点：正常值查不到 404，注入放开 WHERE 后返回单对象
      if (/OR\s+1\s*=\s*1/.test(code)) return send(200, { bank: "ADDIKO BANK", code: "115", swift: "HAAB HR 22" });
      return send(404, { detail: "Item not found" });
    }
    return send(404, { error: "not found" });
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

test("openapiRoutes: 携带操作声明的查询参数名（注入用例的参数来源）", () => {
  const found = {
    doc: {
      openapi: "3.0.0",
      paths: {
        "/api/products": { get: { parameters: [{ name: "query", in: "query" }, { name: "page", in: "query" }] } },
        "/api/items/{id}": { get: { parameters: [{ name: "id", in: "path" }] } },
      },
    },
  };
  const routes = openapiRoutes(found);
  assert.deepEqual(routes.find((r) => r.path === "/api/products").queryParams, ["query", "page"]);
  assert.deepEqual(routes.find((r) => r.path === "/api/items/{id}").queryParams, [], "path 参数不是注入点");
});

test("runBlackbox: 注入打在 OpenAPI 声明的参数上（写死 q 会漏报）", async () => {
  const target = await sqliTargetServer({ spec: true });
  const ctx = makeCtx(new Map());
  try {
    const result = await runBlackbox(ctx, target.url, {
      config: { login: ctx.loginConfig, identities: ctx.identities, blackbox: null },
      allowMutation: false,
    });
    const sqli = result.evidence.find((e) => e.caseId.startsWith("blackbox-sqli-"));
    assert.ok(sqli, JSON.stringify(result.findings.map((f) => f.type)));
    assert.equal(sqli.verdict, "vulnerable");
    assert.match(sqli.caseId, /^blackbox-sqli-(or|error|blind)-api-products-query$/);
    assert.match(sqli.endpoint, /\/api\/products\?query=.*OR%201%3D1/);
    assert.ok(result.findings.some((f) => /SQL 注入/.test(f.type)), "SQLi 要进入结论清单");
  } finally {
    await target.close();
  }
});

test("runBlackbox: 单对象端点（基线 404、注入后返回对象）判为注入", async () => {
  const target = await sqliTargetServer({ spec: true });
  const ctx = makeCtx(new Map());
  try {
    const result = await runBlackbox(ctx, target.url, {
      config: { login: ctx.loginConfig, identities: ctx.identities, blackbox: null },
      allowMutation: false,
    });
    const sqli = result.evidence.find((e) => e.caseId.startsWith("blackbox-sqli-") && e.endpoint.includes("/api/bank_codes"));
    assert.ok(sqli, JSON.stringify(result.evidence.map((e) => e.caseId)));
    assert.equal(sqli.verdict, "vulnerable");
    assert.match(sqli.caseId, /^blackbox-sqli-single-api-bank-codes-code$/);
    assert.match(sqli.actual, /基线 HTTP 404/);
    assert.ok(result.findings.some((f) => /SQL 注入/.test(f.type)), "SQLi 要进入结论清单");
  } finally {
    await target.close();
  }
});

test("runBlackbox: 无 OpenAPI 规格时用常见参数名仍能复现注入", async () => {
  const target = await sqliTargetServer({ spec: false });
  const ctx = makeCtx(new Map());
  try {
    const result = await runBlackbox(ctx, target.url, {
      config: { login: ctx.loginConfig, identities: ctx.identities, blackbox: null },
      allowMutation: false,
    });
    const sqli = result.evidence.find((e) => e.caseId.startsWith("blackbox-sqli-"));
    assert.ok(sqli, "常见参数名回退应命中 query");
    assert.equal(sqli.verdict, "vulnerable");
    assert.match(sqli.endpoint, /query=/);
  } finally {
    await target.close();
  }
});

test("runBlackbox: 穿越 payload 注入声明的文件读取参数", async () => {
  const target = await sqliTargetServer({ spec: true });
  const ctx = makeCtx(new Map());
  try {
    const result = await runBlackbox(ctx, target.url, {
      config: { login: ctx.loginConfig, identities: ctx.identities, blackbox: null },
      allowMutation: false,
    });
    const trav = result.evidence.find((e) => e.caseId.startsWith("blackbox-traversal-") && e.endpoint.includes("file="));
    assert.ok(trav, JSON.stringify(result.evidence.map((e) => e.caseId)));
    assert.equal(trav.verdict, "vulnerable");
    assert.match(trav.actual, /root:x:/);
  } finally {
    await target.close();
  }
});

test("extractRoutesFromText: 只取字面量 API 路径，跳过动态片段与静态资源", () => {
  const routes = extractRoutesFromText(
    [
      `fetch('/api/x?y=1');`,
      `const a = "/api/users/1";`,
      `const b = "/api/users/\${id}";`,
      `const c = '/assets/logo.png';`,
      `const d = '/rest/products/search';`,
      `const e = '/v1/orders';`,
    ].join("\n")
  );
  assert.deepEqual(routes.sort(), ["/api/users/1", "/api/x", "/rest/products/search", "/v1/orders"].sort());
});

function frontendServer() {
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, "http://127.0.0.1");
    const send = (status, body, type = "application/json") => {
      res.writeHead(status, { "Content-Type": type });
      res.end(typeof body === "string" ? body : JSON.stringify(body));
    };
    if (url.pathname === "/") {
      return send(
        200,
        `<!doctype html><html><head><script type="module" src="/assets/app.js"></script></head>
         <body><script>fetch('/api/from-inline')</script></body></html>`,
        "text/html"
      );
    }
    if (url.pathname === "/assets/app.js") {
      return send(
        200,
        `fetch('/api/accounts/summary?full=1');
         const logo = '/assets/logo.png';
         const tpl = '/api/users/\${id}';`,
        "application/javascript"
      );
    }
    // 只在 JS 里出现、目录词表与 OpenAPI 都没有的端点：匿名返回敏感字段
    if (url.pathname === "/api/accounts/summary") {
      return send(200, { email: "admin@example.com", balance: 42 });
    }
    return send(404, { error: "not found" });
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

test("runBlackbox: 从首页脚本提取路由并发现词表外的未认证读取", async () => {
  const target = await frontendServer();
  const ctx = makeCtx(new Map());
  try {
    const result = await runBlackbox(ctx, target.url, {
      config: { login: ctx.loginConfig, identities: ctx.identities, blackbox: null },
      allowMutation: false,
    });
    const discovered = result.routes.find((r) => r.path === "/api/accounts/summary");
    assert.ok(discovered, JSON.stringify(result.routes.map((r) => `${r.source}:${r.path}`)));
    assert.equal(discovered.source, "frontend");
    assert.equal(result.frontendScripts, 1);
    assert.ok(result.frontendRouteCount >= 1);
    assert.ok(!result.routes.some((r) => /\.(?:png|js)$/.test(r.path)), "静态资源不应进入路由表");
    assert.ok(!result.routes.some((r) => r.path.includes("${")), "动态模板路径不应进入路由表");
    const finding = result.findings.find((f) => f.path === "/api/accounts/summary");
    assert.ok(finding, JSON.stringify(result.findings.map((f) => f.path)));
    assert.match(finding.type, /未认证读取/);
  } finally {
    await target.close();
  }
});

/**
 * 攻击面补强靶场：一个目标同时埋 5 类旧版打不到的洞——
 * 管理端点缺角色校验（垂直越权）、只解码一次的读文件参数（编码绕过穿越）、
 * 数字条件拼接（数字语境注入）、跨用户 PATCH/DELETE（写越权）、匿名 POST（未认证写入）。
 * hardened=true 时同一批端点全部做对，用来证明新版判据不会把「防住了」报成漏洞。
 */
function wideServer({ hardened = false } = {}) {
  const accounts = {
    "alice@test.com": { id: 1, email: "alice@test.com", password: "alice123", role: "user" },
    "bob@test.com": { id: 2, email: "bob@test.com", password: "bob123", role: "user" },
    "carol@test.com": { id: 3, email: "carol@test.com", password: "carol123", role: "admin" },
  };
  const tokens = new Map();
  const sessions = new Map();
  const orders = [
    { id: 101, userId: 1, note: "alice-note" },
    { id: 102, userId: 2, note: "bob-note" },
  ];
  const messages = [{ id: 900, userId: 1, body: "seed-message" }];
  let nextMessageId = 901;
  const invoices = [
    { id: 1, year: 2024, total: 100 },
    { id: 2, year: 2024, total: 220 },
    { id: 3, year: 2025, total: 340 },
  ];
  let serverOrigin = "";

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, "http://127.0.0.1");
    const cors =
      hardened || !req.headers.origin
        ? hardened
          ? { "Access-Control-Allow-Origin": "https://app.wide.shop", "Access-Control-Allow-Credentials": "true" }
          : {}
        : { "Access-Control-Allow-Origin": req.headers.origin, "Access-Control-Allow-Credentials": "true" };
    const send = (status, body, extra = {}) => {
      res.writeHead(status, { "Content-Type": "application/json", ...cors, ...extra });
      res.end(JSON.stringify(body));
    };
    const sendHtml = (status, html) => {
      res.writeHead(status, { "Content-Type": "text/html; charset=utf-8", ...cors });
      res.end(html);
    };
    const cookie = String(req.headers.cookie ?? "");
    const sid = cookie.match(/(?:^|;\s*)sid=([^;]+)/)?.[1];
    const user =
      tokens.get((req.headers.authorization ?? "").replace(/^Bearer\s+/, "")) ?? (sid ? sessions.get(sid) : null) ?? null;
    const readBody = async () => {
      const chunks = [];
      for await (const c of req) chunks.push(c);
      const raw = Buffer.concat(chunks).toString("utf8") || "";
      if ((req.headers["content-type"] ?? "").includes("application/x-www-form-urlencoded")) {
        return Object.fromEntries(new URLSearchParams(raw));
      }
      try {
        return JSON.parse(raw || "{}");
      } catch {
        return {};
      }
    };
    const escapeHtml = (v) =>
      String(v).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

    if (hardened && req.method !== "GET" && req.headers.origin && req.headers.origin !== serverOrigin) {
      return send(403, { error: "cross-site request blocked" });
    }

    if (req.method === "POST" && url.pathname === "/api/login") {
      const body = await readBody();
      const u = accounts[body.email];
      if (!u || u.password !== body.password) return send(401, { error: "bad credentials" });
      const t = `tok-${u.id}`;
      tokens.set(t, u);
      return send(200, { authentication: { token: t, user: { id: u.id, role: u.role, email: u.email } } });
    }

    if (req.method === "POST" && url.pathname === "/session/login") {
      const body = await readBody();
      const u = accounts[body.email];
      if (!u || u.password !== body.password) return send(401, { error: "bad credentials" });
      const sessionId = `sess-${u.id}`;
      sessions.set(sessionId, u);
      return send(200, { user: { id: u.id, role: u.role, email: u.email } }, { "Set-Cookie": `sid=${sessionId}; Path=/; HttpOnly` });
    }

    if (req.method === "GET" && url.pathname === "/openapi.json") {
      return send(200, {
        openapi: "3.0.0",
        paths: {
          "/api/invoices": { get: { parameters: [{ name: "year", in: "query" }] } },
          "/api/documents": { get: { parameters: [{ name: "name", in: "query" }] } },
          "/api/search": { get: { parameters: [{ name: "q", in: "query" }] } },
        },
      });
    }

    if (req.method === "GET" && url.pathname === "/") return send(200, { service: "wide-shop" });

    if (req.method === "GET" && url.pathname === "/api/search") {
      const q = url.searchParams.get("q") ?? "";
      const shown = hardened ? escapeHtml(q) : q;
      return sendHtml(200, `<!doctype html><html><body><p>${shown}</p></body></html>`);
    }

    // 管理端点：非 hardened 只校验「登录了」，角色形同虚设
    if (req.method === "GET" && url.pathname === "/api/admin/users") {
      if (!user) return send(401, { error: "unauthorized" });
      if (hardened && user.role !== "admin") return send(403, { error: "forbidden" });
      return send(200, { items: Object.values(accounts).map(({ id, email }) => ({ id, email })) });
    }

    if (req.method === "GET" && url.pathname === "/api/orders") {
      if (!user) return send(401, { error: "unauthorized" });
      return send(200, { items: orders.filter((o) => o.userId === user.id) });
    }
    const orderDetail = url.pathname.match(/^\/api\/orders\/(\d+)$/);
    if (orderDetail) {
      if (!user) return send(401, { error: "unauthorized" });
      const o = orders.find((x) => x.id === Number(orderDetail[1]));
      if (!o) return send(404, { error: "not found" });
      if (hardened && o.userId !== user.id) return send(403, { error: "forbidden" });
      if (req.method === "GET") return send(200, { ...o });
      if (req.method === "PATCH" || req.method === "PUT") {
        const body = await readBody();
        if (typeof body.note === "string") o.note = body.note;
        return send(200, { ...o });
      }
      if (req.method === "DELETE") {
        orders.splice(orders.indexOf(o), 1);
        return send(200, { deleted: true });
      }
      return send(405, { error: "method not allowed" });
    }

    // 留言板：读要登录（用来复核 canary 真的落库），写与删在漏洞版里完全不校验身份
    if (url.pathname === "/api/messages") {
      if (req.method === "GET") {
        if (!user) return send(401, { error: "unauthorized" });
        return send(200, { items: messages });
      }
      if (req.method === "POST") {
        if (hardened) return send(401, { error: "unauthorized" });
        const body = await readBody();
        if (typeof body.body !== "string") return send(400, { error: "bad body" });
        const m = { id: nextMessageId++, userId: null, body: body.body };
        messages.push(m);
        return send(201, { ...m });
      }
    }
    const msgDetail = url.pathname.match(/^\/api\/messages\/(\d+)$/);
    if (msgDetail && req.method === "DELETE") {
      const idx = messages.findIndex((m) => m.id === Number(msgDetail[1]));
      if (idx < 0) return send(404, { error: "not found" });
      if (hardened) return send(401, { error: "unauthorized" });
      messages.splice(idx, 1);
      return send(200, { deleted: true });
    }

    // 数字上下文：WHERE year = <原样拼接>。非法值 400，所以带引号的字符串 payload 一律打不进去
    if (req.method === "GET" && url.pathname === "/api/invoices") {
      const raw = url.searchParams.get("year");
      if (raw == null) return send(200, { items: invoices });
      const m = raw.match(/^(\d+)(?:\s+or\s+(\d+)\s*=\s*(\d+))?$/i);
      if (!m || (hardened && m[2] !== undefined)) return send(400, { error: "year must be numeric" });
      const items = m[2] !== undefined && Number(m[2]) === Number(m[3]) ? invoices : invoices.filter((i) => i.year === Number(m[1]));
      return send(200, { items });
    }

    // 读文件参数：过滤器只看一次解码后的串，于是二次编码的 ../ 漏过去后被应用自己解出来
    if (req.method === "GET" && url.pathname === "/api/documents") {
      const v = url.searchParams.get("name") ?? "";
      if (v.includes("../") || v.includes("..\\")) return send(400, { error: "bad path" });
      let real = v;
      if (!hardened) {
        try {
          real = decodeURIComponent(v);
        } catch {
          /* 保留原串 */
        }
      }
      if (real.includes("../") || real.includes("..\\")) {
        return send(200, { content: "root:x:0:0:root:/root:/bin/bash" });
      }
      return send(200, { content: "quarterly report" });
    }

    return send(404, { error: "not found" });
  });

  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      serverOrigin = `http://127.0.0.1:${server.address().port}`;
      resolve({
        url: `http://127.0.0.1:${server.address().port}`,
        close: () => new Promise((r) => server.close(r)),
        orders,
        messages,
      });
    });
  });
}

function makeWideCtx(vault) {
  const ctx = makeCtx(vault);
  ctx.identities = [
    { name: "alice", email: "alice@test.com", password: "alice123", role: "user" },
    { name: "bob", email: "bob@test.com", password: "bob123", role: "user" },
    { name: "carol", email: "carol@test.com", password: "carol123", role: "admin" },
  ];
  return ctx;
}

const byCase = (result, prefix) => result.evidence.filter((e) => e.caseId?.startsWith(prefix));

test("runBlackbox: 垂直越权——普通登录身份拿到管理端点数据（管理身份交叉证明）", async () => {
  const target = await wideServer();
  const ctx = makeWideCtx(new Map());
  try {
    const result = await runBlackbox(ctx, target.url, {
      config: { login: ctx.loginConfig, identities: ctx.identities, blackbox: null },
      allowMutation: false,
    });
    const rec = byCase(result, "blackbox-vertical-").find((e) => e.caseId.includes("api-admin-users"));
    assert.ok(rec, JSON.stringify(byCase(result, "blackbox-vertical-").map((e) => e.caseId)));
    assert.equal(rec.verdict, "vulnerable");
    assert.equal(rec.evidenceGrade, "cross-proven");
    assert.match(rec.actual, /carol/);
    assert.ok(result.findings.some((f) => /垂直越权/.test(f.type)), "垂直越权要进结论清单");
    assert.ok(result.coverage.includes("垂直越权（管理端点）"));
  } finally {
    await target.close();
  }
});

test("runBlackbox: 数字语境注入——字符串 payload 打不进去的整数参数仍被差分判出", async () => {
  const target = await wideServer();
  const ctx = makeWideCtx(new Map());
  try {
    const result = await runBlackbox(ctx, target.url, {
      config: { login: ctx.loginConfig, identities: ctx.identities, blackbox: null },
      allowMutation: false,
    });
    const rec = byCase(result, "blackbox-sqli-numeric-").find((e) => e.caseId.includes("api-invoices-year"));
    assert.ok(rec, JSON.stringify(byCase(result, "blackbox-sqli-").map((e) => e.caseId)));
    assert.equal(rec.verdict, "vulnerable");
    assert.match(rec.actual, /1 OR 1=1 得 3 条/);
    assert.match(rec.actual, /1 OR 1=2 得 0 条/);
    // 字符串语境不能在这类参数上瞎报
    assert.ok(
      !byCase(result, "blackbox-sqli-").some((e) => e.caseId.includes("api-invoices-year") && !e.caseId.includes("numeric")),
      "数字端点不应同时产出字符串语境注入结论"
    );
  } finally {
    await target.close();
  }
});

test("runBlackbox: 编码绕过穿越——明文 ../ 被过滤器吃掉，二次编码变体仍能读出文件", async () => {
  const target = await wideServer();
  const ctx = makeWideCtx(new Map());
  try {
    const result = await runBlackbox(ctx, target.url, {
      config: { login: ctx.loginConfig, identities: ctx.identities, blackbox: null },
      allowMutation: false,
    });
    const rec = byCase(result, "blackbox-traversal-").find((e) => e.endpoint.includes("name="));
    assert.ok(rec, JSON.stringify(byCase(result, "blackbox-traversal-").map((e) => e.endpoint)));
    assert.equal(rec.verdict, "vulnerable");
    assert.match(rec.actual, /root:x:/);
    assert.ok(
      decodeURIComponent(rec.endpoint).includes("%2f") || rec.endpoint.includes("%252f"),
      `命中的必须是编码变体而非明文：${rec.endpoint}`
    );
  } finally {
    await target.close();
  }
});

test("runBlackbox: 写越权默认关闭，开 allowMutation 后 PUT/PATCH 复现并恢复原值，DELETE 仍需单独开关", async () => {
  const off = await wideServer();
  const ctxOff = makeWideCtx(new Map());
  try {
    const result = await runBlackbox(ctxOff, off.url, {
      config: { login: ctxOff.loginConfig, identities: ctxOff.identities, blackbox: null },
      allowMutation: false,
    });
    assert.equal(byCase(result, "blackbox-idor-patch-").length, 0);
    assert.equal(byCase(result, "blackbox-anon-write-").length, 0);
    assert.ok(
      ctxOff.events.some((e) => /写操作类越权探测/.test(e.message ?? "")),
      "默认关闭要在事件里写明开关"
    );
  } finally {
    await off.close();
  }

  const mut = await wideServer();
  const ctxMut = makeWideCtx(new Map());
  try {
    const result = await runBlackbox(ctxMut, mut.url, {
      config: { login: ctxMut.loginConfig, identities: ctxMut.identities, blackbox: null },
      allowMutation: true,
    });
    const patch = byCase(result, "blackbox-idor-patch-").find((e) => e.caseId.includes("api-orders-102"));
    assert.ok(patch, JSON.stringify(byCase(result, "blackbox-idor-").map((e) => e.caseId)));
    assert.equal(patch.verdict, "vulnerable");
    assert.equal(patch.evidenceGrade, "cross-proven");
    assert.match(patch.actual, /恢复未确认|生效/);
    assert.ok(result.findings.some((f) => /IDOR-PATCH/.test(f.type)));
    // 未开 destructive：DELETE 一条都不发
    assert.equal(byCase(result, "blackbox-idor-delete-").length, 0);
    assert.ok(result.coverage.includes("跨用户修改（PUT/PATCH）"));
    assert.ok(!result.coverage.includes("跨用户删除（DELETE）"));
    // 原值已被尽力还原
    const stillThere = mut.orders.find((o) => o.id === 102);
    assert.ok(stillThere, "PUT/PATCH 阶段不得销毁对象");
  } finally {
    await mut.close();
  }

  const dest = await wideServer();
  const ctxDest = makeWideCtx(new Map());
  try {
    const result = await runBlackbox(ctxDest, dest.url, {
      config: { login: ctxDest.loginConfig, identities: ctxDest.identities, blackbox: null },
      allowMutation: true,
      allowDestructive: true,
    });
    const del = byCase(result, "blackbox-idor-delete-").find((e) => e.caseId.includes("api-orders-102"));
    assert.ok(del, JSON.stringify(byCase(result, "blackbox-idor-").map((e) => e.caseId)));
    assert.equal(del.verdict, "vulnerable");
    assert.equal(del.evidenceGrade, "cross-proven");
    assert.ok(!dest.orders.some((o) => o.id === 102), "靶场里 102 应真的被删掉（判据来自归属人复读）");
    assert.ok(result.coverage.includes("跨用户删除（DELETE）"));
  } finally {
    await dest.close();
  }
});

test("runBlackbox: 未认证写入以「归属人复读见 canary」为准，而不是 2xx 就算", async () => {
  const target = await wideServer();
  const ctx = makeWideCtx(new Map());
  try {
    const result = await runBlackbox(ctx, target.url, {
      config: { login: ctx.loginConfig, identities: ctx.identities, blackbox: null },
      allowMutation: true,
    });
    const rec = byCase(result, "blackbox-anon-write-").find((e) => e.caseId.includes("api-messages"));
    assert.ok(rec, JSON.stringify(byCase(result, "blackbox-anon-write-").map((e) => e.caseId)));
    assert.equal(rec.verdict, "vulnerable");
    assert.equal(rec.evidenceGrade, "cross-proven");
    assert.match(rec.actual, /复读列表可见 canary/);
    // 自清理要真的清掉：靶场里不应留下 canary
    assert.ok(!target.messages.some((m) => String(m.body).startsWith("gb-anon-write-")), JSON.stringify(target.messages));
  } finally {
    await target.close();
  }
});

test("runBlackbox: 伪造 Origin 被回显且允许凭证 → CORS 漏洞；加固版按白名单拒绝", async () => {
  const vuln = await wideServer();
  const ctx = makeWideCtx(new Map());
  try {
    const result = await runBlackbox(ctx, vuln.url, {
      config: { login: ctx.loginConfig, identities: ctx.identities, blackbox: null },
      allowMutation: false,
    });
    const cors = byCase(result, "blackbox-cors-");
    assert.ok(cors.length, JSON.stringify(result.evidence.map((e) => e.caseId)));
    assert.equal(cors[0].verdict, "vulnerable");
    assert.match(cors[0].actual, /回显攻击者 Origin/);
    assert.equal(cors[0].request.headers.Origin, "https://gb-cors-canary.invalid");
    assert.ok(result.coverage.includes("CORS 配置（跨源读取）"));
    assert.ok(result.findings.some((f) => /CORS/.test(f.type)));
  } finally {
    await vuln.close();
  }

  const hard = await wideServer({ hardened: true });
  const ctxHard = makeWideCtx(new Map());
  try {
    const result = await runBlackbox(ctxHard, hard.url, {
      config: { login: ctxHard.loginConfig, identities: ctxHard.identities, blackbox: null },
      allowMutation: true,
    });
    const cors = byCase(result, "blackbox-cors-");
    assert.equal(cors.length, 1);
    assert.equal(cors[0].verdict, "blocked");
    assert.match(cors[0].actual, /白名单/);
  } finally {
    await hard.close();
  }
});

test("runBlackbox: HTML 原样反射无害 canary → XSS 漏洞；加固版编码反射 → blocked", async () => {
  const vuln = await wideServer();
  const ctx = makeWideCtx(new Map());
  try {
    const result = await runBlackbox(ctx, vuln.url, {
      config: { login: ctx.loginConfig, identities: ctx.identities, blackbox: null },
      allowMutation: false,
    });
    const xss = byCase(result, "blackbox-xss-").find((e) => e.caseId.includes("api-search"));
    assert.ok(xss, JSON.stringify(result.evidence.map((e) => e.caseId)));
    assert.equal(xss.verdict, "vulnerable");
    assert.match(xss.endpoint, /q=/);
    assert.match(xss.actual, /未转义载荷/);
    assert.ok(result.coverage.includes("反射型 XSS（HTML 上下文）"));
    assert.ok(result.findings.some((f) => /XSS/.test(f.type)));
  } finally {
    await vuln.close();
  }

  const hard = await wideServer({ hardened: true });
  const ctxHard = makeWideCtx(new Map());
  try {
    const result = await runBlackbox(ctxHard, hard.url, {
      config: { login: ctxHard.loginConfig, identities: ctxHard.identities, blackbox: null },
      allowMutation: false,
    });
    const xss = byCase(result, "blackbox-xss-").find((e) => e.caseId.includes("api-search"));
    assert.ok(xss);
    assert.equal(xss.verdict, "blocked");
    assert.match(xss.actual, /编码/);
    assert.equal(result.findings.length, 0);
  } finally {
    await hard.close();
  }
});

function makeCookieCtx(vault) {
  const ctx = makeWideCtx(vault);
  ctx.loginConfig = {
    path: "/session/login",
    bodyTemplate: { email: "{email}", password: "{password}" },
    cookieAuth: true,
    encoding: "form",
    extraHeaders: {},
  };
  return ctx;
}

test("runBlackbox: CSRF 只在 Cookie 会话 + allowMutation 下探测，改写有复读证明并恢复", async () => {
  const off = await wideServer();
  const ctxOff = makeCookieCtx(new Map());
  try {
    const result = await runBlackbox(ctxOff, off.url, {
      config: { login: ctxOff.loginConfig, identities: ctxOff.identities, blackbox: null },
      allowMutation: false,
    });
    assert.equal(byCase(result, "blackbox-csrf-").length, 0);
    assert.ok(!result.coverage.includes("CSRF（Cookie 会话）"));
  } finally {
    await off.close();
  }

  const vuln = await wideServer();
  const ctx = makeCookieCtx(new Map());
  try {
    const result = await runBlackbox(ctx, vuln.url, {
      config: { login: ctx.loginConfig, identities: ctx.identities, blackbox: null },
      allowMutation: true,
    });
    assert.equal(result.login.ok, true);
    const csrf = byCase(result, "blackbox-csrf-").find((e) => e.caseId.includes("api-orders-102"));
    assert.ok(csrf, JSON.stringify(result.evidence.map((e) => e.caseId)));
    assert.equal(csrf.verdict, "vulnerable");
    assert.equal(csrf.evidenceGrade, "cross-proven");
    assert.equal(csrf.request.headers.Origin, "https://gb-csrf-canary.invalid");
    assert.match(csrf.request.headers["Content-Type"], /x-www-form-urlencoded/);
    assert.ok(result.coverage.includes("CSRF（Cookie 会话）"));
    assert.ok(result.findings.some((f) => /CSRF/.test(f.type)));
    assert.equal(vuln.orders.find((o) => o.id === 102).note, "bob-note", "canary 必须被恢复");
  } finally {
    await vuln.close();
  }

  const hard = await wideServer({ hardened: true });
  const ctxHard = makeCookieCtx(new Map());
  try {
    const result = await runBlackbox(ctxHard, hard.url, {
      config: { login: ctxHard.loginConfig, identities: ctxHard.identities, blackbox: null },
      allowMutation: true,
    });
    const csrf = byCase(result, "blackbox-csrf-");
    assert.ok(csrf.length, "加固版应记录 blocked 而非静默");
    assert.ok(csrf.every((e) => e.verdict === "blocked"));
    assert.equal(result.findings.length, 0);
  } finally {
    await hard.close();
  }
});

test("runBlackbox: hardened 靶场（角色校验 + 参数校验 + 归属校验 + 单一解码）零漏洞结论，且拒绝有据可查", async () => {
  const target = await wideServer({ hardened: true });
  const ctx = makeWideCtx(new Map());
  try {
    const result = await runBlackbox(ctx, target.url, {
      config: { login: ctx.loginConfig, identities: ctx.identities, blackbox: null },
      allowMutation: true,
      allowDestructive: true,
    });
    assert.deepEqual(
      result.findings.map((f) => `${f.type} ${f.path}`),
      [],
      JSON.stringify(result.findings, null, 2)
    );
    const blocked = result.evidence.filter((e) => e.verdict === "blocked").map((e) => e.caseId);
    assert.ok(blocked.some((c) => c.startsWith("blackbox-vertical-")), "管理端点拒绝普通身份要记 blocked");
    assert.ok(blocked.some((c) => c.startsWith("blackbox-idor-patch-")), "跨用户修改被拒要记 blocked");
    assert.ok(blocked.some((c) => c.startsWith("blackbox-idor-delete-")), "跨用户删除被拒要记 blocked");
    assert.ok(blocked.some((c) => c.startsWith("blackbox-anon-write-")), "匿名写入被拒要记 blocked");
    const vertical = result.evidence.find((e) => e.caseId.startsWith("blackbox-vertical-") && e.caseId.includes("api-admin-users"));
    assert.equal(vertical.evidenceGrade, "cross-proven", "管理身份有数据 + 普通身份被拒 = 交叉证明拒绝成立");
  } finally {
    await target.close();
  }
});
