import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import crypto from "node:crypto";
import {
  runBlackbox,
  openapiRoutes,
  extractItems,
  extractEntityById,
  extractOwner,
  extractRoutesFromText,
  extractModuleRefs,
  extractManifestScripts,
  extractSourceMapUrl,
  extractRoutesFromSourceMap,
  discoverOpenapi,
  discoverFrontendRoutes,
  discoverSeoRoutes,
  extractRobotsDirectives,
  extractSitemapRefs,
  extractSitemapLocs,
  extractNextBuildId,
  extractNextManifestScripts,
  extractOpenapiRefsFromHtml,
} from "../lib/blackbox.mjs";

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
    const blocked = result.evidence.filter((e) => e.verdict === "blocked");
    assert.equal(result.summary.attackBlocked, blocked.length, "blocked 计数要与证据条数一致");
    assert.ok(
      blocked.some((e) => e.caseId === "blackbox-jwt-api-me"),
      `该目标会验签，伪造令牌要记 blocked 而不是静默：${blocked.map((e) => e.caseId).join("、")}`
    );
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

test("extractRoutesFromText: 额外接受同源绝对 URL 与无前缀业务资源路径", () => {
  const base = "http://127.0.0.1:3210";
  const routes = extractRoutesFromText(
    [
      `fetch("http://127.0.0.1:3210/api/absolute?x=1");`,
      `fetch("https://cdn.example.com/api/remote");`,
      `fetch("/orders");`,
      `fetch("/assets/logo.png");`,
      `fetch("/static/chunk.js");`,
      `fetch("/users/\${id}");`,
    ].join("\n"),
    base
  );
  assert.ok(routes.includes("/api/absolute"));
  assert.ok(routes.includes("/orders"));
  assert.ok(!routes.includes("/api/remote"), "跨源 URL 不应进入路由表");
  assert.ok(!routes.some((p) => /\.(?:png|js)$/.test(p)));
  assert.ok(!routes.some((p) => p.includes("${")));
});

test("extractModuleRefs: 静态/动态 import 与相对路径，跨源与非 JS 忽略", () => {
  const text = [
    `import { a } from "./dep.js";`,
    `export * from "/static/js/shared.mjs";`,
    `const lazy = () => import("./chunk-orders.js");`,
    `import "https://cdn.example.com/remote.js";`,
    `const css = "/assets/app.css";`,
  ].join("\n");
  const refs = extractModuleRefs(text, "http://127.0.0.1:8080", "/static/js/main.js");
  assert.deepEqual(refs.sort(), ["/static/js/chunk-orders.js", "/static/js/dep.js", "/static/js/shared.mjs"].sort());
});

test("extractManifestScripts: 兼容 CRA asset-manifest 与 Vite manifest", () => {
  const cra = { files: { "main.js": "/static/js/main.abc123.js", "main.css": "/static/css/main.css" } };
  assert.deepEqual(extractManifestScripts(cra, "http://127.0.0.1:8080", "/asset-manifest.json"), [
    "/static/js/main.abc123.js",
  ]);
  const vite = {
    "src/main.jsx": { file: "assets/index-xyz.js", src: "src/main.jsx" },
    "src/lazy.js": { file: "assets/lazy-abc.js", isDynamicEntry: true },
  };
  assert.deepEqual(
    extractManifestScripts(vite, "http://127.0.0.1:8080", "/.vite/manifest.json").sort(),
    ["/assets/index-xyz.js", "/assets/lazy-abc.js"].sort()
  );
  assert.deepEqual(extractManifestScripts({ x: "https://cdn.example.com/x.js" }, "http://127.0.0.1:8080"), []);
});

test("source map: 识别 sourceMappingURL 并从 sourcesContent 提取路由", () => {
  assert.equal(
    extractSourceMapUrl(`console.log(1);\n//# sourceMappingURL=main.js.map`),
    "main.js.map"
  );
  assert.equal(extractSourceMapUrl(`/*# sourceMappingURL=main.js.map */`), "main.js.map");
  const routes = extractRoutesFromSourceMap({
    sourcesContent: [`fetch("/api/from-source");`, null, `const x = "/orders/1";`],
  });
  assert.deepEqual(routes.sort(), ["/api/from-source", "/orders/1"].sort());
});

function discoveryServer() {
  const originRef = { value: "" };
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, "http://127.0.0.1");
    const send = (status, body, type = "application/json") => {
      res.writeHead(status, { "Content-Type": type });
      res.end(typeof body === "string" ? body : JSON.stringify(body));
    };
    if (url.pathname === "/") {
      return send(
        200,
        `<!doctype html><html><head><script type="module" src="/static/js/main.js"></script></head></html>`,
        "text/html"
      );
    }
    if (url.pathname === "/static/js/main.js") {
      return send(
        200,
        `const load = () => import("./chunk-a.js");\n//# sourceMappingURL=main.js.map`,
        "application/javascript"
      );
    }
    if (url.pathname === "/static/js/main.js.map") {
      return send(200, { version: 3, sourcesContent: [`fetch("/api/map-only");`] });
    }
    if (url.pathname === "/asset-manifest.json") {
      return send(200, { files: { "main.js": "/static/js/main.js", "chunk-b.js": "/static/js/chunk-b.js" } });
    }
    if (url.pathname === "/static/js/chunk-a.js") {
      return send(200, `export const x = "/api/chunk-only";`, "application/javascript");
    }
    if (url.pathname === "/static/js/chunk-b.js") {
      return send(
        200,
        `fetch("${originRef.value}/api/absolute?x=1");\nfetch("https://cdn.example.com/api/remote");\nfetch("/orders");`,
        "application/javascript"
      );
    }
    if (url.pathname === "/v3/api-docs/swagger-config") {
      return send(200, { urls: [{ url: "/v3/api-docs/default" }] });
    }
    if (url.pathname === "/v3/api-docs/default") {
      return send(200, { openapi: "3.0.0", paths: { "/api/widgets": { get: {} } } });
    }
    return send(404, { error: "not found" });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      originRef.value = `http://127.0.0.1:${server.address().port}`;
      resolve({
        url: originRef.value,
        close: () => new Promise((r) => server.close(r)),
      });
    });
  });
}

test("discoverFrontendRoutes: 动态 import 二级 chunk + source map + 构建清单一起发现", async () => {
  const target = await discoveryServer();
  const ctx = makeCtx(new Map());
  try {
    const result = await discoverFrontendRoutes(ctx, target.url, {});
    const paths = result.routes.map((r) => r.path);
    assert.ok(paths.includes("/api/chunk-only"), JSON.stringify(paths));
    assert.ok(paths.includes("/api/map-only"), JSON.stringify(paths));
    assert.ok(paths.includes("/api/absolute"), JSON.stringify(paths));
    assert.ok(paths.includes("/orders"), JSON.stringify(paths));
    assert.ok(!paths.some((p) => p.includes("/api/remote")), "跨源路由不应进入结果");
    assert.equal(result.sourceMaps, 1);
    assert.equal(result.manifests, 1);
    assert.ok(result.fetched >= 3);
  } finally {
    await target.close();
  }
});

test("discoverOpenapi: 跟随 swagger-config 声明的间接文档地址", async () => {
  const target = await discoveryServer();
  const ctx = makeCtx(new Map());
  try {
    const found = await discoverOpenapi(ctx, target.url);
    assert.ok(found, "应通过 swagger-config 找到文档");
    assert.equal(found.path, "/v3/api-docs/default");
    assert.deepEqual(openapiRoutes(found).map((r) => r.path), ["/api/widgets"]);
  } finally {
    await target.close();
  }
});

/**
 * 动态取证四族靶场：一个服务同时埋 SSRF（按参数回连）、JWT 只解码不验签、
 * 上传后按声明类型同源回读、状态跳步 + 并发退款双花。
 * hardened=true 时同一批端点全部做对（主机白名单 / HMAC 验签 / 类型白名单 / 前置状态校验 / 幂等锁），
 * 用来证明「拿不到外部证据就不下结论」的判据不会把防住了的报成漏洞。
 */
function familyTargetServer({ hardened = false } = {}) {
  const secret = "gb-family-test-secret";
  const accounts = {
    "alice@test.com": { id: 1, username: "alice", role: "user" },
    "bob@test.com": { id: 2, username: "bob", role: "user" },
  };
  const orders = [
    { id: 101, ownerId: 1, status: "pending" },
    { id: 102, ownerId: 1, status: "paid" },
    { id: 201, ownerId: 2, status: "pending" },
  ];
  const uploads = new Map();
  const ledger = [];
  const delay = (ms) => new Promise((r) => setTimeout(r, ms));
  const b64urlDecode = (s) => Buffer.from(s, "base64url").toString("utf8");
  const sign = (claims) => {
    const h = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
    const p = Buffer.from(JSON.stringify(claims)).toString("base64url");
    return `${h}.${p}.${crypto.createHmac("sha256", secret).update(`${h}.${p}`).digest("base64url")}`;
  };
  const decode = (raw) => {
    const parts = String(raw).split(".");
    if (parts.length !== 3) return null;
    try {
      return {
        header: JSON.parse(b64urlDecode(parts[0])),
        claims: JSON.parse(b64urlDecode(parts[1])),
        signed: `${parts[0]}.${parts[1]}`,
        sig: parts[2],
      };
    } catch {
      return null;
    }
  };
  // 唯一的鉴权差异：hardened 校验算法与 HMAC 签名，漏洞版拿到能解码的令牌就认（jwt-shop 的写法错误）
  const authUser = (req) => {
    const parsed = decode(String(req.headers.authorization ?? "").replace(/^Bearer\s+/, ""));
    if (!parsed) return null;
    if (hardened) {
      if (parsed.header.alg !== "HS256") return null;
      if (parsed.sig !== crypto.createHmac("sha256", secret).update(parsed.signed).digest("base64url")) return null;
    }
    return { id: Number(parsed.claims.sub ?? 0), username: String(parsed.claims.username ?? parsed.claims.name ?? "") };
  };

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, "http://127.0.0.1");
    const send = (status, body, extra = {}) => {
      res.writeHead(status, { "Content-Type": "application/json", ...extra });
      res.end(JSON.stringify(body));
    };
    let raw = "";
    if (req.method !== "GET" && req.method !== "HEAD") {
      const chunks = [];
      for await (const c of req) chunks.push(c);
      raw = Buffer.concat(chunks).toString("latin1");
    }
    const user = authUser(req);

    if (req.method === "POST" && url.pathname === "/api/login") {
      let body = {};
      try {
        body = JSON.parse(raw || "{}");
      } catch {
        /* 非法登录体按未登录处理 */
      }
      const acc = accounts[body.email];
      if (!acc || body.password !== `${acc.username}123`) return send(401, { error: "bad credentials" });
      const exp = Math.floor(Date.now() / 1000) + 3600;
      return send(200, {
        authentication: {
          token: sign({ sub: acc.id, username: acc.username, name: acc.username, email: body.email, role: acc.role, exp }),
          user: { id: acc.id, role: acc.role, email: body.email },
        },
      });
    }

    // SSRF：漏洞版按参数地址发起服务端请求；hardened 只放行固定外部主机
    if (req.method === "GET" && url.pathname === "/api/preview") {
      const target = url.searchParams.get("url") ?? "";
      if (!target) return send(400, { error: "url is required" });
      let host = "";
      try {
        host = new URL(target).hostname;
      } catch {
        return send(400, { error: "malformed url" });
      }
      if (hardened && host !== "example.com") return send(403, { error: "host is not allowlisted" });
      try {
        const upstream = await fetch(target);
        return send(200, { fetched: upstream.status, bytes: (await upstream.text()).length });
      } catch {
        return send(502, { error: "upstream fetch failed" });
      }
    }

    if (req.method === "GET" && url.pathname === "/api/me") {
      if (!user) return send(401, { error: "unauthorized" });
      return send(200, { user: { id: user.id, username: user.username } });
    }

    if (req.method === "GET" && url.pathname === "/api/orders") {
      if (!user) return send(401, { error: "unauthorized" });
      return send(200, { items: orders.filter((o) => o.ownerId === user.id).map(({ id, status }) => ({ id, status })) });
    }

    // 上传：漏洞版原样保存并按声明类型同源回读；hardened 只收图片
    if (req.method === "POST" && url.pathname === "/api/avatar") {
      if (!user) return send(401, { error: "unauthorized" });
      if (hardened) return send(415, { error: "only image/png and image/jpeg are accepted" });
      const name = raw.match(/filename="([^"]+)"/)?.[1] ?? "";
      const declared = raw.match(/\r\nContent-Type:\s*([^\r\n]+)/i)?.[1]?.trim() ?? "application/octet-stream";
      const start = raw.indexOf("\r\n\r\n");
      const end = raw.lastIndexOf("\r\n--");
      if (!name || start < 0 || end <= start) return send(400, { error: "malformed multipart body" });
      uploads.set(name, { body: raw.slice(start + 4, end), contentType: declared });
      return send(201, { url: `/uploads/${name}` });
    }
    if (req.method === "GET" && url.pathname.startsWith("/uploads/")) {
      const file = uploads.get(decodeURIComponent(url.pathname.slice("/uploads/".length)));
      if (!file) return send(404, { error: "not found" });
      res.writeHead(200, { "Content-Type": file.contentType });
      res.end(file.body);
      return;
    }

    // 业务逻辑：ship 不看前置状态；refund 在「查状态」与「落账」之间有 await，于是并发全部通过
    const action = url.pathname.match(/^\/api\/orders\/(\d+)\/([a-z-]+)$/i);
    if (action && req.method === "POST") {
      if (!user) return send(401, { error: "unauthorized" });
      const order = orders.find((o) => String(o.id) === action[1]);
      if (!order) return send(404, { error: "not found" });
      const verb = action[2].toLowerCase();
      if (verb === "ship") {
        if (hardened) return send(409, { error: "order is not paid yet" });
        await delay(20);
        order.status = "shipped";
        return send(200, { id: order.id, status: order.status });
      }
      if (verb === "refund") {
        if (hardened) {
          if (order.refundId != null) return send(409, { error: "already refunded" });
          order.refundId = 9001; // 同步占位，并发只有一个请求能进入
          await delay(80);
          ledger.push(order.refundId);
          return send(200, { id: order.id, refund_id: order.refundId });
        }
        await delay(80);
        ledger.push(1000 + ledger.length);
        return send(200, { id: order.id, refund_id: ledger[ledger.length - 1] });
      }
      return send(404, { error: "unknown action" });
    }

    return send(404, { error: "not found" });
  });

  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      resolve({
        url: `http://127.0.0.1:${server.address().port}`,
        close: () => new Promise((r) => server.close(r)),
        orders,
        refunds: () => ledger.length,
      });
    });
  });
}

const runFamilies = (ctx, url, options = {}) =>
  runBlackbox(ctx, url, {
    config: { login: ctx.loginConfig, identities: ctx.identities, blackbox: null },
    ...options,
  });

test("runBlackbox: SSRF 以本机 canary 回连定性、JWT 以伪造身份回显定性，两者默认执行", async () => {
  const target = await familyTargetServer();
  const ctx = makeCtx(new Map());
  try {
    const result = await runFamilies(ctx, target.url, { allowMutation: false });
    assert.equal(result.login.ok, true, "登录失败说明 JWT 契约没对上");

    const ssrf = byCase(result, "blackbox-ssrf-").find((e) => e.verdict === "vulnerable");
    assert.ok(ssrf, JSON.stringify(byCase(result, "blackbox-ssrf-").map((e) => [e.caseId, e.verdict])));
    assert.equal(ssrf.caseId, "blackbox-ssrf-api-preview");
    assert.equal(ssrf.evidenceGrade, "strong", "判据是独立监听器收到的回连，不靠响应猜测");
    assert.match(ssrf.actual, /回连本机 canary/);
    assert.match(ssrf.endpoint, /url=http%3A%2F%2F127\.0\.0\.1/);

    const jwt = byCase(result, "blackbox-jwt-").find((e) => e.caseId === "blackbox-jwt-api-me");
    assert.ok(jwt, JSON.stringify(byCase(result, "blackbox-jwt-").map((e) => [e.caseId, e.verdict])));
    assert.equal(jwt.verdict, "vulnerable");
    assert.equal(jwt.evidenceGrade, "strong");
    assert.match(jwt.actual, /alg=none 伪造令牌通过认证/);
    assert.match(jwt.actual, /响应回显伪造身份/);
    assert.equal(jwt.request.headers.Authorization, "Bearer <forged-jwt>", "证据只留占位符");
    assert.ok(!/Bearer\s+(?!\*\*\*|<)[A-Za-z0-9._-]{16,}/.test(JSON.stringify(result.evidence)), "任何证据都不得含令牌明文");

    assert.ok(result.coverage.includes("SSRF（本机回连 canary）"));
    assert.ok(result.coverage.includes("JWT 伪造令牌"));
    assert.ok(result.findings.some((f) => /SSRF/.test(f.type)));
    assert.ok(result.findings.some((f) => /JWT 伪造令牌/.test(f.type)));
    assert.equal(byCase(result, "blackbox-upload-").length, 0, "未开 allowMutation 不得上传文件");
    assert.equal(byCase(result, "blackbox-biz-").length, 0, "未开 allowMutation 不得推进业务状态");
    assert.ok(!result.coverage.includes("文件上传（主动内容）"));
  } finally {
    await target.close();
  }
});

test("runBlackbox: 上传以同源回读到令牌、状态跳步以回读状态变化定性；并发双花另需 allowDestructive", async () => {
  const mut = await familyTargetServer();
  const ctxMut = makeCtx(new Map());
  try {
    const result = await runFamilies(ctxMut, mut.url, { allowMutation: true });

    const upload = byCase(result, "blackbox-upload-").find((e) => e.caseId === "blackbox-upload-api-avatar");
    assert.ok(upload, JSON.stringify(byCase(result, "blackbox-upload-").map((e) => [e.caseId, e.verdict, e.actual])));
    assert.equal(upload.verdict, "vulnerable");
    assert.equal(upload.evidenceGrade, "cross-proven", "判据是上传响应与回读内容同时命中随机令牌");
    assert.match(upload.actual, /text\/html/);
    assert.match(upload.endpoint, /^\/api\/avatar$/);
    assert.match(String(upload.request.body), /multipart\/form-data · 字段 file · 文件 gb-/);

    const state = byCase(result, "blackbox-biz-state-").find((e) => e.caseId === "blackbox-biz-state-api-orders-101-ship");
    assert.ok(state, JSON.stringify(byCase(result, "blackbox-biz-state-").map((e) => [e.caseId, e.verdict])));
    assert.equal(state.verdict, "vulnerable");
    assert.equal(state.evidenceGrade, "cross-proven");
    assert.match(state.actual, /原状态 pending，调用 ship 后回读为 shipped/);
    assert.equal(mut.orders.find((o) => o.id === 101).status, "shipped");

    assert.equal(byCase(result, "blackbox-biz-race-").length, 0, "未开 allowDestructive 不得发退款这类资金动作");
    assert.equal(mut.refunds(), 0);
    assert.ok(result.coverage.includes("文件上传（主动内容）"));
    assert.ok(result.coverage.includes("业务逻辑跳步/并发双花"));
    assert.ok(!result.coverage.includes("CSRF（Cookie 会话）"), "Bearer 会话不做 CSRF");
  } finally {
    await mut.close();
  }

  const dest = await familyTargetServer();
  const ctxDest = makeCtx(new Map());
  try {
    const result = await runFamilies(ctxDest, dest.url, { allowMutation: true, allowDestructive: true });
    const race = byCase(result, "blackbox-biz-race-").find((e) => e.caseId === "blackbox-biz-race-api-orders-102-refund");
    assert.ok(race, JSON.stringify(byCase(result, "blackbox-biz-race-").map((e) => [e.caseId, e.verdict])));
    assert.equal(race.verdict, "vulnerable");
    assert.equal(race.evidenceGrade, "cross-proven");
    assert.match(race.actual, /并发 5 次 refund，5 次成功且产生 5 个不同副作用标识/);
    assert.equal(dest.refunds(), 5, "同一笔退款被重复落账 5 次");
  } finally {
    await dest.close();
  }
});

test("runBlackbox: 主机白名单 + HMAC 验签 + 类型白名单 + 前置状态校验 + 幂等锁 → 四族全部 blocked 且零漏洞", async () => {
  const target = await familyTargetServer({ hardened: true });
  const ctx = makeCtx(new Map());
  try {
    const result = await runFamilies(ctx, target.url, { allowMutation: true, allowDestructive: true });
    assert.deepEqual(
      result.findings.map((f) => `${f.type} ${f.path}`),
      [],
      JSON.stringify(result.findings, null, 2)
    );

    const ssrf = byCase(result, "blackbox-ssrf-").find((e) => e.caseId === "blackbox-ssrf-api-preview");
    assert.ok(ssrf, JSON.stringify(byCase(result, "blackbox-ssrf-").map((e) => e.caseId)));
    assert.equal(ssrf.verdict, "blocked");
    assert.match(ssrf.actual, /携带 canary URL 的请求被拒绝/);

    const jwt = byCase(result, "blackbox-jwt-").find((e) => e.caseId === "blackbox-jwt-api-me");
    assert.ok(jwt);
    assert.equal(jwt.verdict, "blocked");
    assert.match(jwt.actual, /alg=none:401/);
    assert.match(jwt.actual, /HS256\(签名无效\):401/);

    const upload = byCase(result, "blackbox-upload-").find((e) => e.caseId === "blackbox-upload-api-avatar");
    assert.ok(upload, JSON.stringify(byCase(result, "blackbox-upload-").map((e) => [e.caseId, e.verdict])));
    assert.equal(upload.verdict, "blocked");
    assert.match(upload.actual, /HTTP 415/);

    const state = byCase(result, "blackbox-biz-state-").find((e) => e.caseId === "blackbox-biz-state-api-orders-101-ship");
    assert.ok(state, JSON.stringify(byCase(result, "blackbox-biz-state-").map((e) => [e.caseId, e.verdict])));
    assert.equal(state.verdict, "blocked");
    assert.match(state.actual, /处于 pending，流转被拒绝/);

    const race = byCase(result, "blackbox-biz-race-").find((e) => e.caseId === "blackbox-biz-race-api-orders-102-refund");
    assert.ok(race, JSON.stringify(byCase(result, "blackbox-biz-race-").map((e) => [e.caseId, e.verdict])));
    assert.equal(race.verdict, "blocked");
    assert.match(race.actual, /仅 1 次成功/);
    assert.equal(target.refunds(), 1, "加固版只落账一次");
  } finally {
    await target.close();
  }
});


// ---------- 补充3：路由发现（robots/sitemap 声明、Next.js buildManifest、Swagger UI 内嵌地址）----------

test("extractRobotsDirectives: 取 Disallow/Allow 的字面量路径，跳过根路径与通配尾部", () => {
  const found = extractRobotsDirectives(
    [
      "User-agent: *",
      "Disallow: /api/accounts/export",
      "Disallow: /private/tools?*",
      "Allow: /admin/panel$",
      "Disallow: /",
      "Sitemap: http://127.0.0.1:1/sitemap.xml",
      "Crawl-delay: 5",
    ].join("\n")
  );
  assert.deepEqual(found, ["/api/accounts/export", "/private/tools", "/admin/panel"]);
});

test("extractSitemapRefs / extractSitemapLocs: 解析声明地址与 <loc>（含 CDATA）", () => {
  assert.deepEqual(extractSitemapRefs("Sitemap: http://a/sitemap.xml\nsitemap: http://a/s2.xml\n"), [
    "http://a/sitemap.xml",
    "http://a/s2.xml",
  ]);
  assert.deepEqual(
    extractSitemapLocs('<urlset><url><loc>http://a/</loc><loc><![CDATA[http://a/api/x?y=1]]></loc></url></urlset>'),
    ["http://a/", "http://a/api/x?y=1"]
  );
});

test("extractNextBuildId / extractNextManifestScripts: 首页反推构建号，清单列出二级 chunk", () => {
  assert.equal(extractNextBuildId('<script src="/_next/static/NhB7xk2pQ/chunks/main-1.js"></script>'), "NhB7xk2pQ");
  assert.equal(extractNextBuildId('<script src="/assets/app.js"></script>'), null);
  assert.equal(extractNextBuildId('<link href="/_next/static/media/logo.svg" />'), null);
  assert.deepEqual(
    extractNextManifestScripts(
      'self.__BUILD_MANIFEST={"/":["static/chunks/pages/a.js"],"/b":["/_next/static/chunks/pages/b.js","static/chunks/fallback.js"]};'
    ),
    ["/_next/static/chunks/pages/a.js", "/_next/static/chunks/pages/b.js", "/_next/static/chunks/fallback.js"]
  );
});

test("extractOpenapiRefsFromHtml: 取页面内嵌的文档地址，丢掉静态资源与锚点", () => {
  const refs = extractOpenapiRefsFromHtml(
    [
      '<script src="/swagger-ui/swagger-ui-bundle.js"></script>',
      'SwaggerUIBundle({ url: "/internal/spec.json", dom_id: "#swagger-ui" });',
      '<script id="cfg">{"specUrl": "/cfg-spec.json"}</script>',
      '<redoc spec-url="/redoc-spec.json"></redoc>',
      'var anchor = "#/section";',
    ].join("\n")
  );
  assert.ok(refs.includes("/internal/spec.json"), JSON.stringify(refs));
  assert.ok(refs.includes("/cfg-spec.json"), JSON.stringify(refs));
  assert.ok(refs.includes("/redoc-spec.json"), JSON.stringify(refs));
  assert.ok(!refs.some((r) => /\.(?:js|css)$/i.test(r)), "静态资源不该被当文档地址");
});

function seoTargetServer({ harden = false } = {}) {
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, "http://127.0.0.1");
    const host = req.headers.host ?? "127.0.0.1";
    const send = (status, body, type = "application/json") => {
      res.writeHead(status, { "Content-Type": type });
      res.end(typeof body === "string" ? body : JSON.stringify(body));
    };
    if (url.pathname === "/robots.txt") {
      return send(
        200,
        `User-agent: *\nDisallow: /api/accounts/export\nDisallow: /private/tools\nSitemap: http://${host}/sitemap.xml\n`,
        "text/plain"
      );
    }
    if (url.pathname === "/sitemap.xml") {
      return send(
        200,
        `<urlset><url><loc>http://${host}/pricing</loc></url><url><loc>http://${host}/blog/release</loc></url><url><loc>http://${host}/api/invoices/archive</loc></url></urlset>`,
        "application/xml"
      );
    }
    if (url.pathname === "/api/accounts/export") {
      return harden ? send(401, { error: "unauthorized" }) : send(200, { items: [{ id: 1, email: "a@x.io", balance: 10 }] });
    }
    if (url.pathname === "/api/invoices/archive") {
      return harden ? send(401, { error: "unauthorized" }) : send(200, { items: [{ id: 7, ownerId: 2, iban: "DE0000" }] });
    }
    return send(404, { error: "not found" });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      resolve({ url: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((r) => server.close(r)) });
    });
  });
}

test("discoverSeoRoutes: robots 声明的路径全收，sitemap 只收接口形状", async () => {
  const target = await seoTargetServer();
  const ctx = makeCtx(new Map());
  try {
    const found = await discoverSeoRoutes(ctx, target.url);
    assert.deepEqual(
      found.routes.map((r) => `${r.source}:${r.path}`).sort(),
      ["robots:/api/accounts/export", "robots:/private/tools", "sitemap:/api/invoices/archive"].sort()
    );
    assert.equal(found.sitemaps, 1, "robots 声明的 sitemap 与内建候选去重后只抓一次");
  } finally {
    await target.close();
  }
});

test("runBlackbox: 仅靠 robots/sitemap 声明的端点能判出未认证读取", async () => {
  const target = await seoTargetServer();
  const ctx = makeCtx(new Map());
  try {
    const result = await runBlackbox(ctx, target.url, {
      config: { login: ctx.loginConfig, identities: ctx.identities, blackbox: null },
      allowMutation: false,
    });
    const byPath = new Map(result.routes.map((r) => [r.path, r.source]));
    assert.equal(byPath.get("/api/accounts/export"), "robots", JSON.stringify([...byPath]));
    assert.equal(byPath.get("/api/invoices/archive"), "sitemap", JSON.stringify([...byPath]));
    assert.ok(!byPath.has("/pricing") && !byPath.has("/blog/release"), "公开营销页不该进路由表");
    assert.ok(result.seoRouteCount >= 3);
    for (const p of ["/api/accounts/export", "/api/invoices/archive"]) {
      const finding = result.findings.find((f) => f.path === p);
      assert.ok(finding, `缺少 ${p} 的未认证读取结论：${JSON.stringify(result.findings.map((f) => f.path))}`);
      assert.match(finding.type, /未认证读取/);
    }
  } finally {
    await target.close();
  }
});

test("runBlackbox: 声明出来的端点要求登录时不判漏洞（sitemap 不是免死金牌）", async () => {
  const target = await seoTargetServer({ harden: true });
  const ctx = makeCtx(new Map());
  try {
    const result = await runBlackbox(ctx, target.url, {
      config: { login: ctx.loginConfig, identities: ctx.identities, blackbox: null },
      allowMutation: false,
    });
    assert.equal(result.findings.length, 0, JSON.stringify(result.findings.map((f) => [f.path, f.type])));
    const unauth = result.evidence.filter((e) => e.caseId.startsWith("blackbox-unauth-"));
    assert.deepEqual(unauth.map((e) => e.caseId), [], "401 端点不该产生未认证读取证据");
  } finally {
    await target.close();
  }
});

function nextTargetServer() {
  const chunks = {
    "/_next/static/chunks/main-1.js": "self.__WEBPACK_RUNTIME__=1;\n",
    "/_next/static/chunks/pages/index-2.js": 'export const BANNER = "welcome";\n',
    "/_next/static/chunks/pages/accounts-3.js":
      'export const LEDGER = "/api/accounts/ledger";\nexport const load = () => fetch(LEDGER + "?full=1");\n',
  };
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, "http://127.0.0.1");
    const send = (status, body, type = "application/json") => {
      res.writeHead(status, { "Content-Type": type });
      res.end(typeof body === "string" ? body : JSON.stringify(body));
    };
    if (url.pathname === "/") {
      return send(
        200,
        '<!doctype html><html><head><script src="/_next/static/chunks/main-1.js" async></script></head>' +
          '<body><div id="__next"></div><script>self.__NEXT_DATA__={"buildId":"NhB7xk2pQ","page":"/","props":{}}</script></body></html>',
        "text/html"
      );
    }
    if (url.pathname === "/_next/static/NhB7xk2pQ/_buildManifest.js") {
      return send(
        200,
        'self.__BUILD_MANIFEST={"/":["static/chunks/pages/index-2.js"],"/accounts":["static/chunks/pages/accounts-3.js"]};\n',
        "application/javascript"
      );
    }
    if (chunks[url.pathname]) return send(200, chunks[url.pathname], "application/javascript");
    if (url.pathname === "/api/accounts/ledger") return send(200, { items: [{ id: 1, email: "a@x.io", balance: 42 }] });
    return send(404, { error: "404 not found" });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      resolve({ url: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((r) => server.close(r)) });
    });
  });
}

test("discoverFrontendRoutes: 顺 _buildManifest.js 爬到二级 chunk 里的接口字面量", async () => {
  const target = await nextTargetServer();
  const ctx = makeCtx(new Map());
  try {
    const found = await discoverFrontendRoutes(ctx, target.url);
    assert.equal(found.nextManifests, 1);
    assert.ok(found.routes.some((r) => r.path === "/api/accounts/ledger"), JSON.stringify(found.routes.map((r) => r.path)));
    assert.ok(found.fetched >= 3, `入口 chunk 里没有接口字面量，必须按清单继续爬：fetched=${found.fetched}`);
  } finally {
    await target.close();
  }
});

function swaggerUiTargetServer() {
  const spec = {
    openapi: "3.0.0",
    paths: {
      "/api/invoices": { get: { parameters: [{ name: "year", in: "query" }] } },
      "/api/invoices/{id}": { get: { parameters: [{ name: "id", in: "path" }] } },
    },
  };
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, "http://127.0.0.1");
    const send = (status, body, type = "application/json") => {
      res.writeHead(status, { "Content-Type": type });
      res.end(typeof body === "string" ? body : JSON.stringify(body));
    };
    if (url.pathname === "/swagger-ui.html") {
      return send(
        200,
        [
          '<!doctype html><html><head><link rel="stylesheet" href="/swagger-ui/swagger-ui.css"></head><body>',
          '<script src="/swagger-ui/swagger-ui-bundle.js"></script>',
          "<script>window.ui = SwaggerUIBundle({ url: \"/internal/openapi-spec.json\", dom_id: \"#swagger-ui\" });</script>",
          "</body></html>",
        ].join("\n"),
        "text/html"
      );
    }
    if (url.pathname === "/internal/openapi-spec.json") return send(200, spec);
    return send(404, { error: "not found" });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      resolve({ url: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((r) => server.close(r)) });
    });
  });
}

test("discoverOpenapi: 规格只写在 /swagger-ui.html 页面里也能找到（含声明的查询参数）", async () => {
  const target = await swaggerUiTargetServer();
  const ctx = makeCtx(new Map());
  try {
    const found = await discoverOpenapi(ctx, target.url);
    assert.ok(found, "应顺着页面内嵌地址取到规格");
    assert.equal(found.path, "/internal/openapi-spec.json");
    const routes = openapiRoutes(found);
    assert.deepEqual(routes.find((r) => r.path === "/api/invoices").queryParams, ["year"]);
    assert.ok(ctx.events.some((e) => e.kind === "discovery" && /发现 OpenAPI 文档/.test(e.message)));
  } finally {
    await target.close();
  }
});

/**
 * 第三方靶场上实测到的误报形状：商品目录这类共享/全局集合，两个身份的同一个列表接口
 * 返回同一批 id，早先会被判成「bob 读到了 alice 的对象」。orders 才是真按身份切分的集合，
 * 用来证明加固后真阳性不丢。writeAttempts 记录服务端真的收到过哪些写请求。
 */
function sharedCatalogServer() {
  const tokens = new Map();
  const writeAttempts = [];
  const catalog = [
    { id: 1, name: "widget", price: 9 },
    { id: 2, name: "gadget", price: 19 },
  ];
  const orders = [
    { id: 101, userId: 1, note: "alice-note" },
    { id: 102, userId: 2, note: "bob-note" },
  ];
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, "http://127.0.0.1");
    const send = (status, body) => {
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(JSON.stringify(body));
    };
    const user = tokens.get((req.headers.authorization ?? "").replace(/^Bearer\s+/, "")) ?? null;
    const readBody = async () => {
      const chunks = [];
      for await (const c of req) chunks.push(c);
      try {
        return JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
      } catch {
        return {};
      }
    };

    if (req.method === "POST" && url.pathname === "/api/login") {
      const body = await readBody();
      const users = {
        "alice@test.com": { id: 1, email: "alice@test.com", password: "alice123", role: "user" },
        "bob@test.com": { id: 2, email: "bob@test.com", password: "bob123", role: "user" },
      };
      const u = users[body.email];
      if (!u || u.password !== body.password) return send(401, { error: "bad credentials" });
      const t = `tok-${u.id}`;
      tokens.set(t, u);
      return send(200, { authentication: { token: t } });
    }

    if (req.method === "GET" && url.pathname === "/openapi.json") {
      return send(200, { openapi: "3.0.0", paths: { "/api/catalog": { get: {} }, "/api/orders": { get: {} } } });
    }

    if (req.method === "GET" && url.pathname === "/api/catalog") return send(200, { items: catalog });

    const catalogDetail = url.pathname.match(/^\/api\/catalog\/(\d+)$/);
    if (catalogDetail) {
      const item = catalog.find((x) => String(x.id) === catalogDetail[1]);
      if (!item) return send(404, { error: "not found" });
      if (req.method === "GET") return send(200, { ...item });
      writeAttempts.push(`${req.method} ${url.pathname}`);
      return send(405, { error: "catalog is read-only" });
    }

    if (req.method === "GET" && url.pathname === "/api/orders") {
      if (!user) return send(401, { error: "unauthorized" });
      return send(200, { items: orders.filter((o) => o.userId === user.id) });
    }

    const orderDetail = url.pathname.match(/^\/api\/orders\/(\d+)$/);
    if (orderDetail) {
      const o = orders.find((x) => String(x.id) === orderDetail[1]);
      if (!o) return send(404, { error: "not found" });
      if (req.method === "GET") return send(200, { ...o });
      writeAttempts.push(`${req.method} ${url.pathname}`);
      const body = await readBody();
      if (typeof body.note === "string") o.note = body.note;
      return send(200, { ...o });
    }

    return send(404, { error: "not found" });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      resolve({
        url: `http://127.0.0.1:${server.address().port}`,
        writeAttempts,
        close: () => new Promise((r) => server.close(r)),
      });
    });
  });
}

test("runBlackbox: 共享/全局目录不被当成他人对象（IDOR 误报回退为 inconclusive）", async () => {
  const target = await sharedCatalogServer();
  const ctx = makeCtx(new Map());
  try {
    const result = await runBlackbox(ctx, target.url, {
      config: { login: ctx.loginConfig, identities: ctx.identities, blackbox: null },
      allowMutation: false,
    });
    const shared = byCase(result, "blackbox-idor-").find((e) => e.caseId.includes("api-catalog-1"));
    assert.ok(shared, JSON.stringify(byCase(result, "blackbox-idor-").map((e) => e.caseId)));
    assert.equal(shared.verdict, "inconclusive");
    assert.match(shared.actual, /共享\/全局集合/);
    assert.ok(
      !result.findings.some((f) => /catalog/i.test(f.path ?? "")),
      `共享目录不该进结论清单：${JSON.stringify(result.findings.map((f) => f.path))}`
    );

    // 真按身份切分的集合不能因为这次加固而漏报
    const real = byCase(result, "blackbox-idor-").find((e) => e.caseId.includes("api-orders-"));
    assert.ok(real, JSON.stringify(byCase(result, "blackbox-idor-").map((e) => e.caseId)));
    assert.equal(real.verdict, "vulnerable");
    assert.equal(real.evidenceGrade, "cross-proven");
  } finally {
    await target.close();
  }
});

test("runBlackbox: 写越权探测不对共享/全局集合下手（真实请求根本没发出去）", async () => {
  const target = await sharedCatalogServer();
  const ctx = makeCtx(new Map());
  try {
    const result = await runBlackbox(ctx, target.url, {
      config: { login: ctx.loginConfig, identities: ctx.identities, blackbox: null },
      allowMutation: true,
    });
    const rec = byCase(result, "blackbox-idor-write-").find((e) => e.caseId.includes("api-catalog-1"));
    assert.ok(rec, JSON.stringify(byCase(result, "blackbox-idor-write-").map((e) => e.caseId)));
    assert.equal(rec.verdict, "inconclusive");
    assert.match(rec.actual, /写\/删探测跳过/);
    assert.ok(
      !target.writeAttempts.some((a) => /catalog/.test(a)),
      `不该对共享目录发起写请求：${JSON.stringify(target.writeAttempts)}`
    );
    assert.ok(
      target.writeAttempts.some((a) => /orders\/10/.test(a)),
      `按身份切分的集合仍要照常探写越权：${JSON.stringify(target.writeAttempts)}`
    );
  } finally {
    await target.close();
  }
});
