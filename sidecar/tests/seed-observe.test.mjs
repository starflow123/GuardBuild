import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { RPC_TO_HOST } from "../../shared/protocol.mjs";
import { observeSeedWrites } from "../lib/probe.mjs";
import {
  attributeCanary,
  canaryBody,
  extractBodyFields,
  projectRelPath,
  readHandlerSource,
  seedWriteCandidates,
  showsCanary,
} from "../lib/seedobserve.mjs";

// #183：契约没写 register.seed 时，引擎要能自己找到「会把对象落在该身份名下」的写接口。
// 这一层的立场是：观测不等于断言——采纳只凭复读归因（写入方看得见、别人看不见），
// 归因不成立就把这条写入丢掉，绝不造出「对象有归属」这个假前提。

function safeJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function listen(app) {
  return new Promise((resolve) => {
    const server = createServer(app);
    server.listen(0, "127.0.0.1", () => resolve({ server, url: `http://127.0.0.1:${server.address().port}` }));
  });
}

/**
 * 观测靶场：注册/登录/按归属列表 + 三个写接口。
 *  - /api/orders   与列表同集合，字段 title 来自处理函数源码
 *  - /api/notes    另一集合，字段 text
 *  - /api/feedback 处理函数根本不读请求体（写进去也不会成为名下对象）
 * ownerFilter=false 模拟「列表不按归属过滤」——此时 canary 人人可见，归因无从谈起。
 */
function rangeApp({ ownerFilter = true, deny = null, silentOrders = false } = {}) {
  const users = new Map();
  const tokens = new Map();
  const items = [];
  let seq = 0;
  return async (req, res) => {
    const path = new URL(req.url, "http://x").pathname;
    const method = req.method;
    let raw = "";
    for await (const c of req) raw += c;
    const body = safeJson(raw) ?? {};
    const send = (status, obj) => {
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(JSON.stringify(obj));
    };
    const me = tokens.get((req.headers.authorization ?? "").replace(/^Bearer\s+/, ""));
    if (method === "POST" && path === "/api/register") {
      if (typeof body.email !== "string" || typeof body.password !== "string") return send(422, { error: "email+password required" });
      if (users.has(body.email)) return send(409, { error: "exists" });
      users.set(body.email, ++seq);
      return send(201, { id: seq });
    }
    if (method === "POST" && path === "/api/login") {
      const id = users.get(body.email);
      if (id == null || body.password !== `pw-${id}`) return send(401, { error: "invalid" });
      const token = `tok-${id}`;
      tokens.set(token, id);
      return send(200, { token });
    }
    if (method === "GET" && path === "/api/orders") {
      if (me == null) return send(401, { error: "no session" });
      return send(200, items.filter((o) => !ownerFilter || o.owner === me).map((o) => ({ id: o.id, title: o.title, owner: o.owner })));
    }
    if (method === "POST" && path === "/api/orders") {
      if (me == null) return send(401, { error: "no session" });
      if (deny === "orders") return send(403, { error: "forbidden" });
      if (typeof body.title !== "string" || !body.title) return send(422, { error: "title required" });
      // silentOrders：接口回 201 但对象没落进调用方自己的列表（入库被中间件按租户/角色丢掉）
      if (silentOrders) return send(201, { ok: true });
      const it = { id: ++seq, title: body.title, owner: me };
      items.push(it);
      return send(201, it);
    }
    if (method === "POST" && path === "/api/notes") {
      if (me == null) return send(401, { error: "no session" });
      if (typeof body.text !== "string" || !body.text) return send(422, { error: "text required" });
      const it = { id: ++seq, title: body.text, owner: me };
      items.push(it);
      return send(201, it);
    }
    if (method === "POST" && path === "/api/feedback") {
      if (me == null) return send(401, { error: "no session" });
      return send(201, { ok: true }); // 收下请求，但什么都没落到该身份名下
    }
    return send(404, { error: "not found" });
  };
}

const HANDLER_SOURCE = {
  "routes/orders.js": "const r = require('express').Router();\nr.use(auth);\nr.post('/', (req, res) => {\n  const t = req.body.title;\n  res.json(store.add(t, req.user.id));\n});\n",
  "routes/notes.js": "const r = require('express').Router();\nr.use(auth);\nr.post('/', (req, res) => {\n  const { text } = req.body;\n  res.json(store.addNote(text, req.user.id));\n});\n",
  "routes/feedback.js": "const r = require('express').Router();\nr.use(auth);\nr.post('/', (req, res) => {\n  res.json({ ok: true });\n});\n",
};

const PROJECT_ROOT = "D:/targets/obs-shop";

// 分析器交出来的 file 是绝对路径（Windows 上还带反斜杠），单测必须用同一形态：
// 早前这里写相对路径，#183 的「字段名取自处理函数源码」在真实项目里静默读不到、测试却全绿。
const asFile = (rel) => `${PROJECT_ROOT}/${rel}`.replace(/\//g, "\\");

const EP = (path, file, { method = "POST", hasAuth = true, graphql = false } = {}) => ({
  method,
  path,
  fullPath: path,
  file: /^[A-Za-z]:/.test(file) ? file : asFile(file),
  startLine: 3,
  hasAuth,
  graphql,
});

const ANALYSIS = {
  endpoints: [
    EP("/api/register", "routes/auth.js"),
    EP("/api/login", "routes/auth.js"),
    EP("/api/password/reset", "routes/auth.js"),
    EP("/api/orders/:id/cancel", "routes/orders.js"),
    EP("/api/orders", "routes/orders.js", { method: "GET" }),
    EP("/api/orders", "routes/orders.js"),
    EP("/api/notes", "routes/notes.js"),
    EP("/api/feedback", "routes/feedback.js"),
    EP("/api/public/query", "routes/gql.js", { hasAuth: true, graphql: true }),
  ],
};

/** 仿 Host：FS_READ 只按项目令牌回源码片段，HTTP_REQUEST 走真实靶场 */
function makeCtx({ blackbox = false, projectRoot = PROJECT_ROOT } = {}) {
  const vault = new Map();
  const requests = [];
  const fsReads = [];
  const events = [];
  const ctx = {
    tokens: { net: "net-token", project: "proj-token" },
    projectRoot,
    loginConfig: { credentialPath: "token", extraHeaders: {} },
    registerConfig: null,
    analysis: ANALYSIS,
    plan: { listEndpoint: { method: "GET", path: "/api/orders" } },
    blackboxUrl: blackbox ? "https://target.example" : null,
    targetConfig: null,
    _probePhase: "pre",
    events,
    emit: (ev) => events.push(ev),
    requests,
    fsReads,
    vault,
    rpc: {
      request: async (method, params) => {
        if (method === RPC_TO_HOST.FS_READ) {
          assert.equal(params.token, "proj-token", "读源码必须带 project.read 令牌");
          fsReads.push(params.path);
          const rel = String(params.path).replace(`${projectRoot}/`, "");
          return { content: HANDLER_SOURCE[rel] ?? "" };
        }
        assert.equal(method, RPC_TO_HOST.HTTP_REQUEST);
        const headers = { ...(params.headers ?? {}) };
        if (params.identityRef) {
          const cred = vault.get(params.identityRef);
          assert.ok(cred, `vault 应有身份 ${params.identityRef} 的凭据`);
          headers[cred.header] = cred.value;
        }
        requests.push({ method: params.method, path: new URL(params.url).pathname, body: params.body });
        const res = await fetch(params.url, { method: params.method, headers, body: params.body ?? undefined });
        const body = await res.text();
        return { status: res.status, statusText: res.statusText, body, headers: {}, redacted: false, durationMs: 1 };
      },
    },
  };
  ctx._identityBootstrap = {
    byPhase: {
      pre: {
        phase: "pre",
        endpoint: "/api/register",
        endpointSource: "contract",
        accounts: [
          { name: "alice", verdict: "created", generated: true },
          { name: "bob", verdict: "created", generated: true },
        ],
        seeds: [],
      },
    },
  };
  return ctx;
}

/** 两个身份各自在本靶场里注册并登录，凭据放进仿 Host 保险库 */
async function seedVault(ctx, url) {
  const loggedIn = [];
  for (const [i, name] of ["alice", "bob"].entries()) {
    const email = `${name}@guardbuild.test`;
    const password = `pw-${i + 1}`;
    await fetch(`${url}/api/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    const r = await fetch(`${url}/api/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    const { token } = await r.json();
    ctx.vault.set(name, { header: "Authorization", value: `Bearer ${token}` });
    loggedIn.push({ name, role: "user" });
  }
  return loggedIn;
}

/* ------------------------------ 纯规则层 ------------------------------ */

test("seedWriteCandidates：只收「要求会话的集合形态 POST」，注册/登录/改口令与带路径参数的一律排除", () => {
  const cands = seedWriteCandidates(ANALYSIS, { listPath: "/api/orders", registerPath: "/api/register" });
  assert.deepEqual(cands.map((c) => c.path), ["/api/orders", "/api/feedback", "/api/notes"]);
  assert.equal(cands[0].sameCollection, true, "与列表同集合的写接口排最前");
  assert.equal(cands[2].sameCollection, false);
  assert.deepEqual(cands.map((c) => c.file), [asFile("routes/orders.js"), asFile("routes/feedback.js"), asFile("routes/notes.js")]);
  assert.deepEqual(
    cands.map((c) => projectRelPath(PROJECT_ROOT, c.file)),
    ["routes/orders.js", "routes/feedback.js", "routes/notes.js"],
    "绝对路径要能折回项目内相对路径，否则读处理函数源码会静默失败"
  );
  const paths = cands.map((c) => c.path);
  assert.ok(!paths.includes("/api/register"), "注册端点不是「往名下写对象」的接口");
  assert.ok(!paths.includes("/api/login"), "登录端点绝不能收到建号/写入体");
  assert.ok(!paths.includes("/api/password/reset"), "找回密码端点是策略线排除项");
  assert.ok(!paths.some((p) => p.includes(":")), "带路径参数的写接口本轮没有 id 可填");
  assert.ok(!paths.includes("/api/public/query"), "GraphQL 端点不走 REST 形状");
});

test("seedWriteCandidates：不要求会话的写接口被排除（无会话就无法把对象归属到该身份）", () => {
  const a = { endpoints: [EP("/api/orders", "routes/orders.js"), { ...EP("/api/notes", "routes/notes.js"), hasAuth: false }] };
  assert.deepEqual(seedWriteCandidates(a, { listPath: "/api/orders" }).map((c) => c.path), ["/api/orders"]);
});

test("seedWriteCandidates：候选数量有上限，超出截断", () => {
  const a = { endpoints: ["/api/aaa", "/api/bbb", "/api/ccc", "/api/ddd", "/api/eee"].map((p) => EP(p, "routes/x.js")) };
  const cands = seedWriteCandidates(a, { listPath: "/api/orders", max: 3 });
  assert.equal(cands.length, 3);
});

test("extractBodyFields：从处理函数源码取字段名，忽略鉴权/框架字段并按上限截断", () => {
  assert.deepEqual(extractBodyFields(HANDLER_SOURCE["routes/orders.js"]), ["title"]);
  assert.deepEqual(extractBodyFields(HANDLER_SOURCE["routes/notes.js"]), ["text"]);
  assert.deepEqual(extractBodyFields(HANDLER_SOURCE["routes/feedback.js"]), [], "不读请求体的处理函数没有可用字段");
  assert.deepEqual(extractBodyFields('h(req){ const {name, comment, user, body} = req.body; return db.insert(req.body["note"], data["ref"], form.get("x")); }'), [
    "note",
    "name",
    "comment",
    "ref",
  ], "user/body 这类鉴权与框架字段不算业务字段");
  assert.deepEqual(extractBodyFields(""), []);
});

test("canaryBody：观测到的字段一律填同一条无害标记，判定权在复读不在字段猜得准", () => {
  assert.deepEqual(canaryBody(["title", "note"], "gbseed-abc"), { title: "gbseed-abc", note: "gbseed-abc" });
  assert.equal(canaryBody([], "gbseed-abc"), null);
  assert.equal(Object.keys(canaryBody(["a", "b", "c", "d", "e"], "x")).length, 4);
});

test("attributeCanary：写入方看得见且别人看不见才叫 attributed；人人可见判 unattributed；看不见判 absent", () => {
  const item = { id: 1, title: "gbseed-abc" };
  assert.deepEqual(
    attributeCanary({ ownerItems: [item], otherItemsByOwner: { bob: [{ id: 2, title: "other" }] }, canary: "gbseed-abc" }),
    { verdict: "attributed", ownerSeen: true, othersSeen: [] }
  );
  assert.deepEqual(
    attributeCanary({ ownerItems: [item], otherItemsByOwner: { bob: [item] }, canary: "gbseed-abc" }).verdict,
    "unattributed",
    "列表没按归属过滤时不能把它当「名下对象」用"
  );
  assert.deepEqual(
    attributeCanary({ ownerItems: [], otherItemsByOwner: { bob: [] }, canary: "gbseed-abc" }),
    { verdict: "absent", ownerSeen: false, othersSeen: [] }
  );
  assert.equal(showsCanary([{ title: "x" }], "gbseed-abc"), false);
});

test("readHandlerSource：按 startLine 取片段；越界路径/缺令牌/读失败都回空串而不是猜", async () => {
  const ctx = makeCtx();
  const src = await readHandlerSource(ctx, { file: asFile("routes/orders.js"), startLine: 3 });
  assert.match(src, /req\.body\.title/, "分析器给的绝对路径（Windows 反斜杠）要能折回项目内相对路径再读");
  assert.deepEqual(ctx.fsReads, [`${PROJECT_ROOT}/routes/orders.js`], "发给 Host 的路径是规范化的项目内路径");
  assert.equal(await readHandlerSource(ctx, { file: "routes/orders.js", startLine: 3 }), src, "相对形态同样能读");
  assert.equal(await readHandlerSource(ctx, { file: `${PROJECT_ROOT}\\routes\\nope.js`, startLine: 3 }), "");
  assert.equal(await readHandlerSource({ ...ctx, projectRoot: "" }, { file: asFile("routes/orders.js"), startLine: 3 }), "");
  assert.equal(await readHandlerSource(ctx, { file: "../../etc/passwd", startLine: 3 }), "", "拒绝越出项目根的路径");
  assert.equal(
    await readHandlerSource(ctx, { file: "D:\\other\\repo\\routes\\orders.js", startLine: 3 }),
    "",
    "仓库外的绝对路径一律不读"
  );
  assert.equal(ctx.fsReads.some((p) => p.includes("..")), false, "越界路径不得发给 Host");
  assert.equal(ctx.fsReads.some((p) => p.toLowerCase().includes("d:\\other")), false, "仓库外路径不得发给 Host");
});

/* ------------------------------ 编排层（真靶场） ------------------------------ */

test("observeSeedWrites：契约没写 seed 时观测选定写接口，本人回读到标记才算造出对象", async () => {
  const app = rangeApp();
  const { server, url } = await listen(app);
  try {
    const ctx = makeCtx();
    const loggedIn = await seedVault(ctx, url);
    const byUser = { alice: [], bob: [] };
    const out = await observeSeedWrites(ctx, { baseUrl: url, byUser, loggedIn });
    assert.equal(out.attributed, 2, "两个新建账号各造出名下对象");
    assert.equal(byUser.alice.length, 1);
    assert.equal(byUser.bob.length, 1);
    assert.equal(byUser.alice[0].owner, 1);
    assert.equal(byUser.bob[0].owner, 2);
    const boot = ctx._identityBootstrap.byPhase.pre;
    assert.deepEqual(
      boot.seeds.map((s) => [s.identity, s.path, s.verdict, s.source]),
      [
        ["alice", "/api/orders", "written", "observed"],
        ["bob", "/api/orders", "written", "observed"],
      ]
    );
    assert.deepEqual(boot.seeds[0].fields, ["title"], "字段名来自该端点自己的处理函数源码");
    assert.equal(boot.seeds[0].ownerSeen, true);
    assert.deepEqual(boot.seeds[0].othersSeen, []);
    assert.equal(boot.seedObservation.attempted, true);
    assert.deepEqual(boot.seedObservation.candidates, ["/api/orders", "/api/feedback", "/api/notes"]);
    const info = ctx.events.filter((e) => /写入种子数据/.test(e.message));
    assert.equal(info.length, 2);
    assert.match(info[0].message, /本人经 \/api\/orders 回读到标记 gbseed-/);
    assert.match(info[0].message, /端点由本轮实跑选定/);
    // 处理函数不读请求体的端点根本不发出写入请求
    assert.equal(ctx.requests.filter((r) => r.path === "/api/feedback").length, 0);
  } finally {
    server.close();
  }
});

test("observeSeedWrites：列表不按归属过滤时判 unattributed，绝不把这条写入当成名下对象", async () => {
  const app = rangeApp({ ownerFilter: false });
  const { server, url } = await listen(app);
  try {
    const ctx = makeCtx();
    // 只留一个有字段的候选 + 一个无字段的候选，让归因失败后没有别的出路
    ctx.analysis = { endpoints: [EP("/api/orders", "routes/orders.js", { method: "GET" }), EP("/api/orders", "routes/orders.js"), EP("/api/feedback", "routes/feedback.js")] };
    ctx.plan = { listEndpoint: { method: "GET", path: "/api/orders" } };
    const loggedIn = await seedVault(ctx, url);
    const byUser = { alice: [], bob: [] };
    const out = await observeSeedWrites(ctx, { baseUrl: url, byUser, loggedIn });
    assert.equal(out.attributed, 0);
    assert.deepEqual(byUser, { alice: [], bob: [] }, "归因不成立就不改归属表：宁可有缺口也不造假前提");
    assert.deepEqual(
      ctx._identityBootstrap.byPhase.pre.seeds.map((s) => [s.identity, s.path, s.verdict]),
      [
        ["alice", "/api/orders", "unattributed"],
        ["alice", "/api/feedback", "no_body_fields"],
        ["bob", "/api/orders", "unattributed"],
        ["bob", "/api/feedback", "no_body_fields"],
      ]
    );
    const warn = ctx.events.find((e) => /无法归属/.test(e.message));
    assert.ok(warn, "报告口径要说清「写进去了但归不了属」");
    assert.match(warn.message, /列表未按归属过滤/);
  } finally {
    server.close();
  }
});

test("observeSeedWrites：写入返回 201 但本人列表看不到标记 → 该端点不算数，继续试下一个候选", async () => {
  const app = rangeApp({ silentOrders: true });
  const { server, url } = await listen(app);
  try {
    const ctx = makeCtx();
    // /api/orders 的处理函数有字段，但把它的源码换成「不入库」的形态：写入成功、列表看不到
    ctx.analysis = {
      endpoints: [
        EP("/api/orders", "routes/orders.js", { method: "GET" }),
        { ...EP("/api/orders", "routes/empty.js"), startLine: 1 },
        { ...EP("/api/notes", "routes/notes.js") },
      ],
    };
    HANDLER_SOURCE["routes/empty.js"] = "r.post('/', (req, res) => { log(req.body.title); res.json({ ok: true }); });\n";
    const loggedIn = await seedVault(ctx, url);
    const byUser = { alice: [], bob: [] };
    const out = await observeSeedWrites(ctx, { baseUrl: url, byUser, loggedIn });
    assert.equal(out.attributed, 2, "orders 不入库时 notes 仍能把对象落到本人名下");
    const first = ctx._identityBootstrap.byPhase.pre.seeds.find((s) => s.path === "/api/orders");
    assert.equal(first.verdict, "absent", "写入成功但回读不到标记＝该接口没把对象落在该身份名下");
    assert.equal(first.ownerSeen, false);
    assert.match(byUser.alice[0].title, /^gbseed-/, "最终采纳的是 notes：对象确实落在本人列表里");
    assert.match(ctx.events.find((e) => /回读不到标记/.test(e.message)).message, /没有把对象落在该身份名下/);
  } finally {
    server.close();
  }
});

test("observeSeedWrites：写入被 403 拒掉时记 denied 并继续试，不抛错也不谎报", async () => {
  const app = rangeApp({ deny: "orders" });
  const { server, url } = await listen(app);
  try {
    const ctx = makeCtx();
    ctx.analysis = {
      endpoints: [
        EP("/api/orders", "routes/orders.js", { method: "GET" }),
        { ...EP("/api/orders", "routes/orders.js") },
        { ...EP("/api/notes", "routes/notes.js") },
      ],
    };
    const loggedIn = await seedVault(ctx, url);
    const out = await observeSeedWrites(ctx, { baseUrl: url, byUser: { alice: [], bob: [] }, loggedIn });
    const seeds = ctx._identityBootstrap.byPhase.pre.seeds;
    assert.deepEqual(seeds.filter((s) => s.path === "/api/orders").map((s) => [s.verdict, s.status]), Array(2).fill(["denied", 403]));
    assert.equal(out.attributed, 2, "被拒的端点不影响后续候选");
  } finally {
    server.close();
  }
});

test("observeSeedWrites：纯黑盒目标一律不参与（不对他人系统发写请求）", async () => {
  const app = rangeApp();
  const { server, url } = await listen(app);
  try {
    const ctx = makeCtx({ blackbox: true });
    ctx.tokens = { http: "egress-token", project: null };
    const loggedIn = await seedVault(ctx, url);
    const out = await observeSeedWrites(ctx, { baseUrl: url, byUser: { alice: [], bob: [] }, loggedIn });
    assert.equal(out.attributed, 0);
    assert.equal(ctx.requests.length, 0, "黑盒模式下这一层一个请求都不发");
    assert.equal(ctx._identityBootstrap.byPhase.pre.seedObservation, undefined);
  } finally {
    server.close();
  }
});

test("observeSeedWrites：只有一个普通身份时不参与——「别人看不见」这条判据无从验证", async () => {
  const app = rangeApp();
  const { server, url } = await listen(app);
  try {
    const ctx = makeCtx();
    ctx._identityBootstrap.byPhase.pre.accounts = [{ name: "alice", verdict: "created", generated: true }];
    const loggedIn = (await seedVault(ctx, url)).filter((i) => i.name === "alice");
    const out = await observeSeedWrites(ctx, { baseUrl: url, byUser: { alice: [] }, loggedIn });
    assert.equal(out.blocked, "single_identity");
    assert.equal(ctx.requests.length, 0);
    assert.equal(ctx._identityBootstrap.byPhase.pre.seedObservation.blocked, "single_identity");
  } finally {
    server.close();
  }
});

test("observeSeedWrites：列表端点还没被定下来时，用静态集合端点当候选通道，选定权在 canary 复读", async () => {
  const app = rangeApp();
  const { server, url } = await listen(app);
  try {
    const ctx = makeCtx();
    ctx.plan = { listEndpoint: null };
    const loggedIn = await seedVault(ctx, url);
    const out = await observeSeedWrites(ctx, { baseUrl: url, byUser: { alice: [], bob: [] }, loggedIn });
    assert.equal(out.attributed, 2, "本人读到 canary、别人读不到＝这条通道经实测选定，两个身份各造一条");
    const obs = ctx._identityBootstrap.byPhase.pre.seedObservation;
    assert.deepEqual(obs.channels, ["/api/orders"], "候选通道来自静态集合形态 GET 枚举，不是猜的");
    assert.equal(obs.listEndpoint, "/api/orders", "复读通过后才把通道写进经过");
    assert.deepEqual(
      ctx._identityBootstrap.byPhase.pre.seeds.filter((s) => s.verdict === "written").map((s) => `${s.identity}:${s.readBackVia}`),
      ["alice:/api/orders", "bob:/api/orders"]
    );
  } finally {
    server.close();
  }
});

test("observeSeedWrites：一条读取通道都没有时诚实关闭，不发无人能对证的写请求", async () => {
  const app = rangeApp();
  const { server, url } = await listen(app);
  try {
    const ctx = makeCtx();
    ctx.plan = { listEndpoint: null };
    ctx.analysis = { endpoints: [EP("/api/orders/:id", "routes/orders.js", { method: "GET" }), EP("/api/orders", "routes/orders.js")] };
    const loggedIn = await seedVault(ctx, url);
    const out = await observeSeedWrites(ctx, { baseUrl: url, byUser: { alice: [], bob: [] }, loggedIn });
    assert.equal(out.blocked, "no_list_endpoint");
    assert.equal(ctx.requests.length, 0);
    assert.match(ctx.events.find((e) => /观测兜底未参与/.test(e.message)).message, /register\.seed/);
  } finally {
    server.close();
  }
});

test("observeSeedWrites：本轮没找到可试的写接口时记 no_write_candidates，并把修法写进提示", async () => {
  const app = rangeApp();
  const { server, url } = await listen(app);
  try {
    const ctx = makeCtx();
    ctx.analysis = { endpoints: [EP("/api/orders", "routes/orders.js", { method: "GET" }), EP("/api/login", "routes/auth.js")] };
    const loggedIn = await seedVault(ctx, url);
    const out = await observeSeedWrites(ctx, { baseUrl: url, byUser: { alice: [], bob: [] }, loggedIn });
    assert.equal(out.blocked, "no_write_candidates");
    assert.equal(ctx.requests.length, 0);
    assert.match(ctx.events.find((e) => /观测兜底未参与/.test(e.message)).message, /register\.seed/);
  } finally {
    server.close();
  }
});

test("observeSeedWrites：只对「本轮引擎注册且名下没有对象」的账号发写入，声明账号与已有对象不参与", async () => {
  const app = rangeApp();
  const { server, url } = await listen(app);
  try {
    const ctx = makeCtx();
    ctx._identityBootstrap.byPhase.pre.accounts = [
      { name: "alice", verdict: "created", generated: true },
      { name: "bob", verdict: "exists", generated: false },
    ];
    const loggedIn = await seedVault(ctx, url);
    const out = await observeSeedWrites(ctx, { baseUrl: url, byUser: { alice: [], bob: [{ id: 9, title: "已有对象" }] }, loggedIn });
    assert.equal(out.attributed, 1);
    assert.deepEqual(ctx._identityBootstrap.byPhase.pre.seeds.map((s) => s.identity), ["alice"]);
  } finally {
    server.close();
  }
});

test("observeSeedWrites：契约 register.seed 已经写过数据的身份不再重复造", async () => {
  const app = rangeApp();
  const { server, url } = await listen(app);
  try {
    const ctx = makeCtx();
    ctx._identityBootstrap.byPhase.pre.seeds = [
      { identity: "alice", path: "/api/orders", status: 201, verdict: "written" },
      { identity: "bob", path: "/api/orders", status: 201, verdict: "written" },
    ];
    const loggedIn = await seedVault(ctx, url);
    const before = ctx._identityBootstrap.byPhase.pre.seeds.length;
    const out = await observeSeedWrites(ctx, { baseUrl: url, byUser: { alice: [], bob: [] }, loggedIn });
    assert.equal(out.attributed, 0);
    assert.equal(out.blocked, null, "没有需要兜底的身份时静默返回，不算被挡住");
    assert.equal(ctx._identityBootstrap.byPhase.pre.seeds.length, before);
    assert.equal(ctx.requests.length, 0);
  } finally {
    server.close();
  }
});
