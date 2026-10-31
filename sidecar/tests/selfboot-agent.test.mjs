import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RPC_TO_HOST } from "../../shared/protocol.mjs";
import { loginAll } from "../lib/probe.mjs";
import {
  SELFBOOT_AGENT_VERSION,
  askRegisterAgent,
  buildRegisterMenu,
  cacheKeyFor,
  patchAgentCache,
  readAgentCache,
  sanitizeRegisterChoice,
  selfBootAgentEnabled,
  selfBootBudget,
  selfBootModelCallable,
  writeAgentCache,
} from "../lib/selfbootagent.mjs";

// #182：注册端点与请求体字段名的 agent 兜底。
// 断言重点不是「模型答得对」，而是「模型答错也造不出假绿灯」：
// 采纳必须由引擎实跑（注册被接受 **且** 能建立会话）决定，模型给的任何请求内容一律丢弃，
// gate 不得调模型，口令一律不进模型/事件/报告。

function listen(app) {
  return new Promise((resolve) => {
    const server = createServer(app);
    server.listen(0, "127.0.0.1", () => resolve({ server, url: `http://127.0.0.1:${server.address().port}` }));
  });
}

function safeJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

const PROJECT_SOURCE = `// 目标里的注册处理函数（异形命名，静态词表打不中）
app.post('/api/huiyuan/add', async (req, res) => {
  const mail = String(req.body.mail ?? '');
  const pwd = String(req.body.pwd ?? '');
  if (!mail || !pwd) return res.status(422).json({ error: 'mail/pwd required' });
  const u = await db.huiyuan.create({ mail, pwd });
  res.status(201).json({ id: u.id });
});
`;

/** 仿 Host：保险库不外泄凭据，FS_READ 只回项目源码片段，HTTP 出站一律记账 */
function makeCtx({ projectSource = PROJECT_SOURCE } = {}) {
  const vault = new Map();
  const protectedSecrets = [];
  const requests = [];
  const fsReads = [];
  const events = [];
  const ctx = {
    tokens: { net: "net-token", http: "net-token", project: "project-token" },
    projectRoot: "D:/targets/huiyuan-shop",
    loginConfig: null,
    registerConfig: null,
    identities: [],
    plan: { loginCandidates: ["/api/login"], loginPath: "/api/login" },
    analysis: null,
    events,
    emit: (ev) => events.push(ev),
    _probePhase: "pre",
    protectedSecrets,
    requests,
    fsReads,
    vault,
    llm: { getToken: async () => "egress-token" },
    llmConfig: { enabled: true, model: "test-model" },
    rpc: {
      request: async (method, params) => {
        if (method === RPC_TO_HOST.CREDENTIAL_PROTECT) {
          protectedSecrets.push({ label: params.label, value: params.value });
          return { ok: true };
        }
        if (method === RPC_TO_HOST.FS_READ) {
          assert.equal(params.token, "project-token", "读项目源码必须带 project 作用域令牌");
          fsReads.push({ path: params.path, redact: params.redact });
          if (!params.path.endsWith("routes/huiyuan.js")) return { content: "" };
          return { content: projectSource };
        }
        assert.equal(method, RPC_TO_HOST.HTTP_REQUEST);
        const headers = { ...(params.headers ?? {}) };
        if (params.identityRef) {
          const cred = vault.get(params.identityRef);
          assert.ok(cred, `vault 应有身份 ${params.identityRef} 的凭据`);
          headers[cred.header] = cred.value;
        }
        requests.push({ method: params.method, path: new URL(params.url).pathname, headers, body: params.body });
        const res = await fetch(params.url, { method: params.method, headers, body: params.body ?? undefined });
        const body = await res.text();
        let storedIdentity;
        if (params.storeCredentialAs && params.credentialPath) {
          const node = String(params.credentialPath)
            .split(".")
            .reduce((acc, k) => (acc == null ? undefined : acc[k]), safeJson(body));
          if (node != null) {
            vault.set(params.storeCredentialAs, { header: params.credentialHeader ?? "Authorization", value: `${params.credentialPrefix ?? ""}${node}` });
            storedIdentity = params.storeCredentialAs;
          }
        }
        return {
          status: res.status,
          statusText: res.statusText,
          body,
          headers: Object.fromEntries(res.headers.entries()),
          redacted: false,
          durationMs: 1,
          storedIdentity,
        };
      },
    },
  };
  return ctx;
}

/**
 * 异形命名靶场：公开建号接口是 POST /api/huiyuan/add，字段名 mail/pwd。
 * /api/feedback 是「201 但不建号」的诱饵——它专门用来验证「注册被接受 ≠ 采纳」。
 */
function huiyuanApp() {
  const users = new Map(); // mail -> { id, password }
  const tokens = new Map();
  let seq = 0;
  const readBody = async (req) => {
    let raw = "";
    for await (const c of req) raw += c;
    return safeJson(raw) ?? {};
  };
  return async (req, res) => {
    const path = new URL(req.url, "http://x").pathname;
    if (req.method === "POST" && path === "/api/huiyuan/add") {
      const b = await readBody(req);
      if (typeof b.mail !== "string" || !b.mail || typeof b.pwd !== "string" || !b.pwd) {
        res.writeHead(422, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ error: "mail/pwd required" }));
      }
      if (users.has(b.mail)) {
        res.writeHead(409, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ error: "already exists" }));
      }
      users.set(b.mail, { id: ++seq, password: b.pwd });
      res.writeHead(201, { "Content-Type": "application/json" });
      return res.end(JSON.stringify({ id: seq }));
    }
    if (req.method === "POST" && path === "/api/login") {
      const b = await readBody(req);
      const u = users.get(b.email);
      if (!u || u.password !== b.password) {
        res.writeHead(401, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ error: "invalid credentials" }));
      }
      tokens.set(`tok-${u.id}`, b.email);
      res.writeHead(200, { "Content-Type": "application/json" });
      return res.end(JSON.stringify({ token: `tok-${u.id}` }));
    }
    if (req.method === "GET" && path === "/api/profile") {
      const who = tokens.get((req.headers.authorization ?? "").replace(/^Bearer\s+/, ""));
      if (!who) {
        res.writeHead(401, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ error: "unauthorized" }));
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      return res.end(JSON.stringify({ id: users.get(who).id, email: who }));
    }
    if (req.method === "POST" && path === "/api/feedback") {
      await readBody(req);
      res.writeHead(201, { "Content-Type": "application/json" });
      return res.end(JSON.stringify({ ok: true })); // 收下任何内容，但根本不建号
    }
    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "not found" }));
  };
}

/** 仿 DeepSeek chat completions：把引擎给的观测交给测试里的「模型」，只回文本 */
async function listenLlm(modelFn, seen) {
  const app = async (req, res) => {
    let raw = "";
    for await (const c of req) raw += c;
    const payload = safeJson(raw) ?? {};
    const obs = safeJson(payload?.messages?.[1]?.content ?? "") ?? {};
    seen.push({ obs, raw, auth: req.headers.authorization ?? "" });
    const content = typeof modelFn === "function" ? modelFn(obs, seen.length) : modelFn;
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ choices: [{ message: { role: "assistant", content } }], usage: { total_tokens: 42 } }));
  };
  return listen(app);
}

// 分析器交出来的 file 是绝对路径（Windows 上还带反斜杠），单测必须用同一形态：
// 早前这里写相对路径，#182 的「字段名取自处理函数源码」在真实项目里静默读不到、测试却全绿。
const HUIYUAN_ANALYSIS = {
  endpoints: [
    { method: "POST", fullPath: "/api/huiyuan/add", file: "D:\\targets\\huiyuan-shop\\routes\\huiyuan.js", startLine: 2, hasAuth: false },
    { method: "POST", fullPath: "/api/feedback", file: "D:\\targets\\huiyuan-shop\\routes\\feedback.js", startLine: 3, hasAuth: false },
    { method: "POST", fullPath: "/api/orders", file: "D:\\targets\\huiyuan-shop\\routes\\orders.js", startLine: 4, hasAuth: true },
    { method: "POST", fullPath: "/api/login", file: "D:\\targets\\huiyuan-shop\\routes\\login.js", startLine: 5, hasAuth: false },
    { method: "POST", fullPath: "/api/password/reset", file: "D:\\targets\\huiyuan-shop\\routes\\pw.js", startLine: 6, hasAuth: false },
    { method: "GET", fullPath: "/api/profile", file: "D:\\targets\\huiyuan-shop\\routes\\profile.js", startLine: 7, hasAuth: true },
  ],
};

const LOGIN_CONTRACT = { path: "/api/login", bodyTemplate: { email: "{email}", password: "{password}" }, credentialPath: "token" };

function useLlmEnv(llmUrl) {
  const prev = { base: process.env.DEEPSEEK_BASE_URL, key: process.env.DEEPSEEK_API_KEY, selfboot: process.env.GUARDBUILD_LLM_SELFBOOT };
  process.env.DEEPSEEK_BASE_URL = `${llmUrl}/v1`;
  process.env.DEEPSEEK_API_KEY = "sk-test-key";
  return () => {
    const restore = (k, v) => (v === undefined ? delete process.env[k] : (process.env[k] = v));
    restore("DEEPSEEK_BASE_URL", prev.base);
    restore("DEEPSEEK_API_KEY", prev.key);
    restore("GUARDBUILD_LLM_SELFBOOT", prev.selfboot);
  };
}

function useTempDataDir() {
  const dir = mkdtempSync(join(tmpdir(), "gb-selfboot-"));
  const prev = process.env.GUARDBUILD_DATA_DIR;
  process.env.GUARDBUILD_DATA_DIR = dir;
  return {
    dir,
    restore: () => {
      if (prev === undefined) delete process.env.GUARDBUILD_DATA_DIR;
      else process.env.GUARDBUILD_DATA_DIR = prev;
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

const pick = (path) => (obs) => {
  const item = (obs.candidates ?? []).find((c) => c.path === path);
  return { picks: item ? [item.id] : [], templates: item ? { [item.id]: { mail: "{email}", pwd: "{password}" } } : undefined, note: "测试替身" };
};

// ---------- 纯函数：菜单 ----------

test("buildRegisterMenu: 只收 POST、策略禁止的写接口根本不进菜单、静态命中排前面", () => {
  const menu = buildRegisterMenu(HUIYUAN_ANALYSIS, { staticHits: ["/api/huiyuan/add"] });
  assert.deepEqual(
    menu.items.map((i) => i.path),
    ["/api/huiyuan/add", "/api/feedback", "/api/orders"],
    "/api/login 与 /api/password/reset 必须在引擎侧被排除：猜错就是往别人的写接口发建号请求"
  );
  assert.deepEqual(menu.items.map((i) => i.id), [1, 2, 3]);
  assert.equal(menu.items[0].staticSignupShape, true);
  assert.equal(menu.items[1].staticSignupShape, false);
  assert.equal(menu.items[2].hasAuth, true, "是否要求登录要作为线索交给模型");
  assert.equal(menu.byId.get(1).path, "/api/huiyuan/add");
  assert.equal(menu.byPath.get("/api/feedback").id, 2);
});

test("buildRegisterMenu: 超出预算的候选截掉并如实计数", () => {
  const eps = Array.from({ length: 30 }, (_, i) => ({ method: "POST", fullPath: `/api/x${i}/new` }));
  const menu = buildRegisterMenu({ endpoints: eps }, { maxMenu: 6 });
  assert.equal(menu.items.length, 6);
  assert.equal(menu.excludedCount, 24);
});

test("selfBootAgentEnabled / callable：黑盒不参与，gate 不得调模型", () => {
  assert.equal(selfBootAgentEnabled({ registerConfig: { agent: true } }), true);
  assert.equal(selfBootAgentEnabled({ registerConfig: { agent: false } }), false);
  assert.equal(selfBootAgentEnabled({ registerConfig: { agent: { enabled: false } }, llmConfig: { enabled: true } }), false, "契约否定优先于全局 llm");
  assert.equal(selfBootAgentEnabled({ llmConfig: { enabled: true } }), true);
  assert.equal(selfBootAgentEnabled({ blackboxUrl: "https://third-party.test", registerConfig: { agent: true } }), false, "纯黑盒不给目标建号");
  const gate = { registerConfig: { agent: true }, blackboxUrl: null };
  assert.equal(selfBootModelCallable(gate), true);
  assert.equal(selfBootModelCallable({ ...gate, gate: true }), false, "gate 只允许复用已实测验证的缓存提案");
  assert.deepEqual(selfBootBudget({ registerConfig: { agent: { maxPicks: 99, maxMenu: 1, rounds: 9 } } }), { maxPicks: 8, maxMenu: 5, rounds: 2 });
});

// ---------- 纯函数：提案校验（走私字段一律丢弃） ----------

test("sanitizeRegisterChoice: 只认编号与「字段名→占位符」，越界键名留痕不留值", () => {
  const menu = buildRegisterMenu(HUIYUAN_ANALYSIS, {});
  const res = sanitizeRegisterChoice(
    {
      picks: [1, 1, 99, "2", 3],
      templates: {
        1: { mail: "{email}", pwd: "{password}", x: "constant-value" },
        2: { name: "{name}" }, // 没有 {password}：整条模板不可用
        9: { a: "{email}", b: "{password}" }, // 编号不在菜单
        "3": { "bad field": "{email}", c: "{password}" },
      },
      note: "模型原文",
      severity: "critical",
      body: { admin: true },
      url: "http://attacker.test",
      headers: { Cookie: "session=abc" },
    },
    menu,
    { maxPicks: 3 }
  );
  assert.equal(res.ok, true);
  assert.deepEqual(res.candidates.map((c) => c.path), ["/api/feedback", "/api/huiyuan/add", "/api/orders"], "重复编号与未知编号被去掉");
  assert.deepEqual(res.candidates[0].bodyTemplate, { mail: "{email}", pwd: "{password}" }, "常量值不入模板");
  assert.equal(res.candidates[1].bodyTemplate, null, "缺 {password} 映射时不猜字段名，交由引擎默认注册体");
  assert.deepEqual(res.candidates[2].bodyTemplate, { c: "{password}" }, "非法字段名丢弃、合法映射保留");
  for (const k of ["severity", "body", "url", "headers"]) assert.ok(res.ignored.includes(k), `越界键名要留痕：${k}`);
  assert.ok(!res.ignored.includes("note") && !res.ignored.includes("templates") && !res.ignored.includes("picks"));
  assert.ok(!JSON.stringify(res.candidates).includes("constant-value"), "模型给的常量值绝不带进请求");
  assert.deepEqual(sanitizeRegisterChoice({ picks: [1, 2, 3] }, menu, { maxPicks: 2 }).ignored, ["picks>2"], "超出预算的编号同样丢弃");
  assert.deepEqual(res.invalid, ["99"], "非法编号只留字符串，不回显模型内容");
  assert.ok(res.droppedFields.some((d) => d.includes("1.x")), "常量字段映射要记进审计");
  assert.ok(res.droppedFields.some((d) => d.startsWith("2(")), "缺口令映射的模板记为不可用");
  assert.ok(res.droppedFields.includes("9"), "不在菜单的编号模板直接丢弃");
  assert.ok(res.droppedFields.some((d) => d.includes("bad field")), "非法字段名丢弃");
});

test("sanitizeRegisterChoice: 非对象提案 / picks 非数组一律拒绝", () => {
  const menu = buildRegisterMenu(HUIYUAN_ANALYSIS, {});
  assert.equal(sanitizeRegisterChoice("just a string", menu).ok, false);
  assert.equal(sanitizeRegisterChoice({ picks: 3 }, menu).ok, false);
  assert.equal(sanitizeRegisterChoice({ picks: [] }, menu).empty, true);
});

// ---------- 纯函数：磁盘缓存 ----------

test("缓存：写读往返、路由一变即整条作废、gate 只认已实测验证的提案", () => {
  const tmp = useTempDataDir();
  try {
    const ctx = makeCtx();
    const menu = buildRegisterMenu(HUIYUAN_ANALYSIS, {});
    const key = cacheKeyFor("test-model", menu);
    const candidates = [{ path: "/api/huiyuan/add", bodyTemplate: { mail: "{email}", pwd: "{password}" } }];

    const saved = writeAgentCache(ctx, key, candidates, { model: "test-model", verified: { endpoint: false, session: false } });
    assert.ok(saved?.file && existsSync(saved.file), "提案要落盘到 GUARDBUILD_DATA_DIR 下");

    const unverified = readAgentCache(ctx, key, menu);
    assert.equal(unverified.candidates[0].path, "/api/huiyuan/add");
    assert.equal(unverified.candidates[0].id, menu.byPath.get("/api/huiyuan/add").id, "缓存只记路径，编号按当前菜单重新解析");
    assert.equal(readAgentCache(ctx, key, menu, { requireVerified: true }), null, "未实测验证的提案不能给 gate 复用");

    assert.equal(patchAgentCache(saved.file, { endpoint: true, session: true }), true);
    const verified = readAgentCache(ctx, key, menu, { requireVerified: true });
    assert.equal(verified.candidates[0].bodyTemplate.mail, "{email}");
    assert.equal(verified.verified.endpoint, true);

    // 路由形状变了：菜单里已没有这个路径（或被策略排除），整条作废并删文件
    const changed = buildRegisterMenu({ endpoints: [{ method: "POST", fullPath: "/api/other/new" }] }, {});
    assert.equal(readAgentCache(ctx, key, changed, { requireVerified: true }), null);
    assert.equal(existsSync(saved.file), false, "过期缓存要删掉，不能留在盘上等下次撞键");

    // 版本不符 → 作废
    const staleFile = writeAgentCache(ctx, key, candidates, {});
    writeFileSync(staleFile.file, JSON.stringify({ version: `${SELFBOOT_AGENT_VERSION}-old`, candidates, verified: { endpoint: true } }), "utf8");
    assert.equal(readAgentCache(ctx, key, menu), null);

    // 缓存里的越界值同样重校验：常量值/缺口令的模板回落为 null，不直接照发
    writeAgentCache(
      ctx,
      key,
      [{ path: "/api/huiyuan/add", bodyTemplate: { mail: "who@mail.test", pwd: "hunter0" } }],
      { verified: { endpoint: true, session: true } }
    );
    const reused = readAgentCache(ctx, key, menu, { requireVerified: true });
    assert.equal(reused.candidates[0].bodyTemplate, null, "缓存里对不上占位符白名单的值一律不用");
  } finally {
    tmp.restore();
  }
});

test("cacheKeyFor：路由形状变或换模型就换键，源码改行不换键", () => {
  const a = buildRegisterMenu(HUIYUAN_ANALYSIS, { staticHits: ["/api/huiyuan/add"] });
  const b = buildRegisterMenu(HUIYUAN_ANALYSIS, { staticHits: ["/api/huiyuan/add"] });
  assert.equal(cacheKeyFor("m1", a), cacheKeyFor("m1", b));
  assert.notEqual(cacheKeyFor("m1", a), cacheKeyFor("m2", a), "换模型要重问");
  const c = buildRegisterMenu({ endpoints: [...HUIYUAN_ANALYSIS.endpoints, { method: "POST", fullPath: "/api/x/new" }] }, {});
  assert.notEqual(cacheKeyFor("m1", a), cacheKeyFor("m1", c), "候选菜单变了不能照旧提案发请求");
});

// ---------- askRegisterAgent：观测内容与失败回落 ----------

test("askRegisterAgent: 菜单源码进观测，坏 JSON / 拒答 / 空 picks 都回空候选并给原因", async () => {
  const ctx = makeCtx();
  const menu = buildRegisterMenu(HUIYUAN_ANALYSIS, {});
  const impl = (content) => async () => ({ content, model: "test-model", usage: { total_tokens: 1 } });

  const good = await askRegisterAgent(ctx, {
    menu,
    getToken: ctx.llm.getToken,
    chatImpl: async () => ({ content: JSON.stringify(pick("/api/huiyuan/add")({ candidates: menu.items })), model: "test-model", usage: { total_tokens: 1 } }),
  });
  assert.equal(good.candidates.length, 1);
  assert.equal(good.candidates[0].path, "/api/huiyuan/add");
  assert.equal(good.meta.source, "model");
  assert.equal(good.meta.fallback, null);

  const bad = await askRegisterAgent(ctx, { menu, getToken: ctx.llm.getToken, chatImpl: impl("这不是 JSON") });
  assert.equal(bad.candidates.length, 0);
  assert.equal(bad.meta.fallback, "bad_json");

  const declined = await askRegisterAgent(ctx, { menu, getToken: ctx.llm.getToken, chatImpl: impl(JSON.stringify({ picks: [], note: "菜单里没有公开建号接口" })) });
  assert.equal(declined.meta.fallback, "model_declined");

  const boom = await askRegisterAgent(ctx, {
    menu,
    getToken: ctx.llm.getToken,
    chatImpl: async () => {
      throw new Error("上游 5xx");
    },
  });
  assert.equal(boom.candidates.length, 0);
  assert.equal(boom.meta.fallback, "agent_error");

  const emptyMenu = buildRegisterMenu({ endpoints: [{ method: "GET", fullPath: "/api/a" }] }, {});
  assert.equal(emptyMenu.items.length, 0);
  const noMenu = await askRegisterAgent(ctx, { menu: emptyMenu, chatImpl: async () => ({ content: "{}" }) });
  assert.equal(noMenu.meta.fallback, "no_menu_candidates");
});

// ---------- 真实链路：引擎实跑裁决 ----------

test("loginAll + 兜底代理：异形命名的注册端点由模型指出、由引擎实跑采纳，口令不进模型", async () => {
  const target = await listen(huiyuanApp());
  const seen = [];
  const llm = await listenLlm((obs) => JSON.stringify(pick("/api/huiyuan/add")(obs)), seen);
  const restoreEnv = useLlmEnv(llm.url);
  const tmp = useTempDataDir();
  try {
    const ctx = makeCtx();
    ctx.loginConfig = LOGIN_CONTRACT;
    // 契约没写 register.path，静态词表也打不中 /api/huiyuan/add —— 全靠这一层
    ctx.registerConfig = { agent: true, seed: [], headers: {} };
    ctx.analysis = HUIYUAN_ANALYSIS;
    ctx.identities = [
      { name: "alice", username: "alice", password: null },
      { name: "bob", username: "bob", password: null },
    ];

    const loggedIn = await loginAll(ctx, target.url);
    assert.deepEqual(loggedIn.map((i) => i.name), ["alice", "bob"]);

    assert.equal(seen.length, 1, "第二轮身份复用同一份采纳端点，不重复问模型");
    const obs = seen[0].obs;
    assert.deepEqual(
      obs.candidates.map((c) => c.path),
      ["/api/feedback", "/api/huiyuan/add", "/api/orders"],
      "找回密码/登录不能出现在菜单里：猜错就是往改口令的接口发建号请求"
    );
    const huiyuan = obs.candidates.find((c) => c.path === "/api/huiyuan/add");
    assert.match(huiyuan.handler_source, /req\.body\.mail/, "字段名的唯一可靠来源是处理函数源码片段");
    assert.equal(huiyuan.static_signup_shape, false, "静态词表确实打不中——这一层的必要性就在这");
    assert.deepEqual(obs.available_placeholders, ["{name}", "{username}", "{email}", "{password}"]);
    assert.ok(ctx.fsReads.every((r) => r.redact === true && r.path.startsWith("D:/targets/huiyuan-shop/")), "读源码走 project 作用域且脱敏");

    const regs = ctx.requests.filter((r) => r.path === "/api/huiyuan/add");
    assert.equal(regs.length, 2);
    assert.equal(JSON.parse(regs[0].body).mail, "alice@guardbuild.test", "字段名取自模型、值由引擎生成");
    const genPwd = JSON.parse(regs[0].body).pwd;
    assert.match(genPwd, /^Gb.{14}\d\d$/, "口令仍是引擎随机生成的那一份");
    assert.ok(!seen[0].raw.includes(genPwd), "引擎口令绝不进模型请求");

    const boot = ctx._identityBootstrap.byPhase.pre;
    assert.equal(boot.endpoint, "/api/huiyuan/add");
    assert.equal(boot.endpointSource, "agent");
    assert.equal(boot.unavailableReason, null);
    assert.deepEqual(boot.accounts.map((a) => [a.name, a.verdict, a.endpointSource]), [
      ["alice", "created", "agent"],
      ["bob", "created", "agent"],
    ]);
    assert.equal(boot.agent.asked, true);
    assert.equal(boot.agent.source, "model");
    assert.equal(boot.agent.adoptedEndpoint, "/api/huiyuan/add");
    assert.equal(boot.agent.menuSize, 3);

    const rep = JSON.stringify(ctx._identityReport);
    assert.ok(!rep.includes(genPwd), "口令不进报告");
    assert.ok(!rep.includes("测试替身"), "模型原文（note）不进报告");
    assert.ok(!ctx.events.some((e) => JSON.stringify(e).includes(genPwd)), "口令不进事件流");
    assert.ok(ctx.events.some((e) => e.kind === "selfboot"), "代理提议要作为一类事件留痕");
    assert.ok(!ctx.events.some((e) => e.kind === "selfboot" && JSON.stringify(e).includes("测试替身")));

    // 报告的「身份基础」一节由 ctx._identityReport 走 getter 取用：中途失败也要留痕，
    // 明细（注册端点/代理经过）在 ctx._identityBootstrap 里，由报告层按白名单展开。
    assert.deepEqual(ctx._identityReport.configured, ["alice", "bob"]);
    assert.deepEqual(ctx._identityReport.loggedIn.map((i) => [i.name, i.endpoint, i.credentialKind]), [
      ["alice", "/api/login", "token"],
      ["bob", "/api/login", "token"],
    ]);
    assert.equal(ctx._identityReport.bootstrap, undefined, "身份基础一节不自己复制明细，避免两处口径不一致");
    assert.equal(boot.agent.adoptedEndpoint, "/api/huiyuan/add");
  } finally {
    restoreEnv();
    tmp.restore();
    target.server.close();
    llm.server.close();
  }
});

test("loginAll + 兜底代理：纠偏轮带着上一轮的实跑结果，且看不到口令", async () => {
  const target = await listen(huiyuanApp());
  const seen = [];
  const llm = await listenLlm((obs, round) => JSON.stringify(pick(round === 1 ? "/api/feedback" : "/api/huiyuan/add")(obs)), seen);
  const restoreEnv = useLlmEnv(llm.url);
  const tmp = useTempDataDir();
  try {
    const ctx = makeCtx();
    ctx.loginConfig = LOGIN_CONTRACT;
    ctx.registerConfig = { agent: true };
    ctx.analysis = HUIYUAN_ANALYSIS;
    ctx.identities = [{ name: "alice", username: "alice", password: null }];

    const loggedIn = await loginAll(ctx, target.url);
    assert.equal(loggedIn.length, 1);
    assert.equal(seen.length, 2, "第一轮的端点没换来会话，必须把实跑结果交给第二轮");
    assert.equal(seen[1].obs.prior_attempts[0].endpoint, "/api/feedback");
    assert.equal(seen[1].obs.prior_attempts[0].verdict, "login_rejected", "判定说「换不来会话」，而不是粉饰成注册成功");
    assert.match(seen[1].obs.prior_attempts[0].error_excerpt, /注册返回 HTTP 201[\s\S]*HTTP 401/, "纠偏轮要同时看见两步的真实状态码");
    const pwd = ctx.protectedSecrets[0].value;
    assert.ok(pwd && !seen[1].raw.includes(pwd), "纠偏轮的观测里没有口令");

    const boot = ctx._identityBootstrap.byPhase.pre;
    assert.equal(boot.agent.rounds, 2);
    assert.deepEqual(boot.agent.tried.map((t) => t.endpoint), ["/api/feedback", "/api/huiyuan/add"]);
    assert.equal(boot.endpoint, "/api/huiyuan/add");
  } finally {
    restoreEnv();
    tmp.restore();
    target.server.close();
    llm.server.close();
  }
});

test("loginAll + 兜底代理：201 但不建号的端点绝不采纳，两轮用尽仍回「测不了」", async () => {
  const target = await listen(huiyuanApp());
  const seen = [];
  const llm = await listenLlm((obs) => JSON.stringify(pick("/api/feedback")(obs)), seen);
  const restoreEnv = useLlmEnv(llm.url);
  const tmp = useTempDataDir();
  try {
    const ctx = makeCtx();
    ctx.loginConfig = LOGIN_CONTRACT;
    ctx.registerConfig = { agent: true };
    ctx.analysis = HUIYUAN_ANALYSIS;
    ctx.identities = [{ name: "alice", username: "alice", password: null }];

    await assert.rejects(() => loginAll(ctx, target.url), (e) => {
      assert.equal(e.code, "identity_bootstrap_failed", "找到了端点、目标也收下了，但换不来会话＝登录层不成立");
      assert.match(e.message, /无法在任何候选登录端点上建立会话/);
      assert.match(e.hint, /实跑过 \/api\/feedback→login_rejected/, "提示要说清代理实跑过什么、结果如何");
      return true;
    });
    assert.equal(seen.length, 2, "预算内做一轮纠偏，之后停下");
    // 关键：没有退回匿名探测，也没有把「全线被拒」写成通过
    assert.equal(ctx.requests.filter((r) => r.path === "/api/profile").length, 0);
    assert.equal(ctx._identityBootstrap.byPhase.pre.agent.adoptedEndpoint, null);
    assert.deepEqual(
      ctx._identityBootstrap.byPhase.pre.accounts.map((a) => a.verdict),
      ["created"],
      "注册被接受这件事要如实留痕，但它不等于身份成立"
    );
  } finally {
    restoreEnv();
    tmp.restore();
    target.server.close();
    llm.server.close();
  }
});

test("loginAll：gate 绝不出站问模型，只能复用交互轮已验证的提案", async () => {
  // 沙箱每次从空库重启，所以两轮各起一个目标实例（同一个库跑两轮会因 409/口令不符而失真）
  const target = await listen(huiyuanApp());
  const seen = [];
  const llm = await listenLlm((obs) => JSON.stringify(pick("/api/huiyuan/add")(obs)), seen);
  const restoreEnv = useLlmEnv(llm.url);
  const tmp = useTempDataDir();
  let target2 = null;
  try {
    const mk = (gate) => {
      const ctx = makeCtx();
      ctx.loginConfig = LOGIN_CONTRACT;
      ctx.registerConfig = { agent: true };
      ctx.analysis = HUIYUAN_ANALYSIS;
      ctx.identities = [{ name: "alice", username: "alice", password: null }];
      ctx.gate = gate;
      return ctx;
    };

    // 交互轮：问模型并落盘已验证提案
    const interactive = mk(false);
    await loginAll(interactive, target.url);
    assert.equal(seen.length, 1);
    assert.equal(interactive._identityBootstrap.byPhase.pre.agent.cacheVerified, true);

    // gate 轮：同一项目、同一菜单 → 命中缓存且一次都不调模型
    target2 = await listen(huiyuanApp());
    const before = seen.length;
    const gated = mk(true);
    const loggedIn = await loginAll(gated, target2.url);
    assert.equal(loggedIn.length, 1, "gate 靠已验证的提案照样能测");
    assert.equal(seen.length, before, "gate 结构性禁止调用模型");
    assert.equal(gated.requests.some((r) => r.path === "/v1/chat/completions"), false, "gate 一轮里连出站请求都不该有");
    const agentMeta = gated._identityBootstrap.byPhase.pre.agent;
    assert.deepEqual([agentMeta.source, agentMeta.cacheHit, agentMeta.cacheVerified], ["cache", true, true]);
  } finally {
    restoreEnv();
    tmp.restore();
    target.server.close();
    target2?.server.close();
    llm.server.close();
  }
});

test("loginAll：gate 冷跑（无缓存）时不调模型，仍回 identity_bootstrap_unavailable", async () => {
  const target = await listen(huiyuanApp());
  const seen = [];
  const llm = await listenLlm(() => JSON.stringify({ picks: [1] }), seen);
  const restoreEnv = useLlmEnv(llm.url);
  const tmp = useTempDataDir();
  try {
    const ctx = makeCtx();
    ctx.loginConfig = LOGIN_CONTRACT;
    ctx.registerConfig = { agent: true };
    ctx.analysis = HUIYUAN_ANALYSIS;
    ctx.identities = [{ name: "alice", username: "alice", password: null }];
    ctx.gate = true;
    await assert.rejects(() => loginAll(ctx, target.url), (e) => {
      assert.equal(e.code, "identity_bootstrap_unavailable");
      assert.match(e.hint, /gate_forbids_model_call|注册兜底代理/, "提示要说明这一层为什么没参与");
      return true;
    });
    assert.equal(seen.length, 0);
  } finally {
    restoreEnv();
    tmp.restore();
    target.server.close();
    llm.server.close();
  }
});

test("loginAll：契约端点已经换来会话时不去问模型（兜底层只在前面落空后才登场）", async () => {
  const target = await listen(huiyuanApp());
  const seen = [];
  const llm = await listenLlm(() => JSON.stringify({ picks: [1] }), seen);
  const restoreEnv = useLlmEnv(llm.url);
  const tmp = useTempDataDir();
  try {
    const ctx = makeCtx();
    ctx.loginConfig = LOGIN_CONTRACT;
    ctx.registerConfig = { path: "/api/huiyuan/add", bodyTemplate: { mail: "{email}", pwd: "{password}" }, agent: true };
    ctx.analysis = HUIYUAN_ANALYSIS;
    ctx.identities = [{ name: "alice", username: "alice", password: null }];
    const loggedIn = await loginAll(ctx, target.url);
    assert.equal(loggedIn.length, 1);
    assert.equal(seen.length, 0, "确定性来源已经成功，不该再花一次模型调用");
    assert.equal(ctx._identityBootstrap.byPhase.pre.endpointSource, "contract");
    assert.equal(ctx._identityBootstrap.byPhase.pre.agent.asked, false);
  } finally {
    restoreEnv();
    tmp.restore();
    target.server.close();
    llm.server.close();
  }
});

test("loginAll：代理没开启时保持改动前的行为（显式 inconclusive，绝不匿名兜底）", async () => {
  const target = await listen(huiyuanApp());
  const tmp = useTempDataDir();
  try {
    const ctx = makeCtx();
    ctx.loginConfig = LOGIN_CONTRACT;
    ctx.registerConfig = { agent: false };
    ctx.llmConfig = null;
    delete ctx.llm;
    ctx.analysis = HUIYUAN_ANALYSIS;
    ctx.identities = [{ name: "alice", username: "alice", password: null }];
    await assert.rejects(() => loginAll(ctx, target.url), (e) => {
      assert.equal(e.code, "identity_bootstrap_unavailable");
      assert.match(e.hint, /register\.agent:true/, "要把「开这一层」写成可执行的下一步");
      return true;
    });
    assert.equal(ctx.requests.filter((r) => r.path === "/api/huiyuan/add").length, 0);
    assert.equal(ctx._identityBootstrap.byPhase.pre.agent.enabled, false);
  } finally {
    tmp.restore();
    target.server.close();
  }
});
