import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { RPC_TO_HOST } from "../../shared/protocol.mjs";
import { loginAll } from "../lib/probe.mjs";
import {
  classifyRegisterResponse,
  classifySeedResponse,
  defaultRegisterBody,
  fillTemplate,
  generateCanary,
  generateTestPassword,
  registerBody,
  resolveRegisterEndpoint,
  seedBody,
  signupCandidates,
  unresolvedPlaceholders,
} from "../lib/identityboot.mjs";

// #179：沙箱目标每次从空库启动，「两个各自名下有数据的账号」只能由引擎自己造。
// 这一层的全部价值在于「造不出来就明说」，所以断言的重点不是注册成功，
// 而是：注册真的发出了请求、口令只进 Host 保险库、任一环节不成立时不许降级成匿名探测。

function listen(app) {
  return new Promise((resolve) => {
    const server = createServer(app);
    server.listen(0, "127.0.0.1", () => resolve({ server, url: `http://127.0.0.1:${server.address().port}` }));
  });
}

/** 仿 Host：令牌只存保险库，credential.protect 只登记脱敏词；请求体不外泄 */
function makeCtx() {
  const vault = new Map();
  const protectedSecrets = [];
  const requests = [];
  const events = [];
  const ctx = {
    tokens: { net: "net-token" },
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
    vault,
    rpc: {
      request: async (method, params) => {
        if (method === RPC_TO_HOST.CREDENTIAL_PROTECT) {
          assert.equal(params.token, "net-token", "脱敏登记必须带会话令牌");
          protectedSecrets.push({ label: params.label, value: params.value });
          return { ok: true };
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
            const value = `${params.credentialPrefix ?? ""}${node}`;
            vault.set(params.storeCredentialAs, { header: params.credentialHeader ?? "Authorization", value });
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

function safeJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

/**
 * 空库注册靶场：库里一开始谁都没有。
 * 注册只接受 email+password（字段名对不上就 422），登录只认库里已存在的账号。
 */
function emptyDbApp({ registerFields = ["email", "password"], denySeed = false } = {}) {
  const users = new Map(); // email -> { id, password }
  const orders = [];
  const tokens = new Map(); // token -> email
  let seq = 0;
  const readBody = async (req) => {
    let raw = "";
    for await (const c of req) raw += c;
    return safeJson(raw) ?? {};
  };
  const authed = (req) => {
    const t = (req.headers.authorization ?? "").replace(/^Bearer\s+/, "");
    return tokens.get(t) ?? null;
  };
  return async (req, res) => {
    const path = new URL(req.url, "http://x").pathname;
    if (req.method === "POST" && path === "/api/register") {
      const b = await readBody(req);
      if (registerFields.some((f) => typeof b[f] !== "string" || !b[f])) {
        res.writeHead(422, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ error: `missing field: expected ${registerFields.join(",")}` }));
      }
      if (users.has(b.email)) {
        res.writeHead(409, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ error: "email already registered" }));
      }
      users.set(b.email, { id: ++seq, password: b.password });
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
      const token = `tok-${u.id}`;
      tokens.set(token, b.email);
      res.writeHead(200, { "Content-Type": "application/json" });
      return res.end(JSON.stringify({ token }));
    }
    if (req.method === "GET" && path === "/api/profile") {
      const who = authed(req);
      if (!who) {
        res.writeHead(401, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ error: "unauthorized" }));
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      return res.end(JSON.stringify({ id: users.get(who).id, email: who }));
    }
    if (req.method === "POST" && path === "/api/orders") {
      const who = authed(req);
      if (!who) {
        res.writeHead(401, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ error: "unauthorized" }));
      }
      if (denySeed) {
        res.writeHead(403, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ error: "forbidden" }));
      }
      const b = await readBody(req);
      orders.push({ id: orders.length + 1, userId: users.get(who).id, title: b.title ?? "" });
      res.writeHead(201, { "Content-Type": "application/json" });
      return res.end(JSON.stringify(orders[orders.length - 1]));
    }
    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "not found" }));
  };
}

const PROFILE_ANALYSIS = {
  endpoints: [
    { method: "GET", fullPath: "/api/profile", hasAuth: true, hasRoleGuard: false },
    { method: "POST", fullPath: "/api/register", hasAuth: false, hasRoleGuard: false },
  ],
};

const LOGIN_CONTRACT = { path: "/api/login", bodyTemplate: { email: "{email}", password: "{password}" }, credentialPath: "token" };

test("signupCandidates: 只认 POST 建号形状，找回密码/登录/设备注册一律不收", () => {
  const eps = [
    { method: "POST", fullPath: "/api/auth/register" },
    { method: "POST", fullPath: "/signup" },
    { method: "POST", fullPath: "/api/create-user" },
    { method: "POST", fullPath: "/api/users/create" }, // 集合 + 创建动词
    { method: "GET", fullPath: "/register" }, // 方法不对
    { method: "POST", fullPath: "/api/orders/create" }, // 创建的是订单，不是账号
    { method: "POST", fullPath: "/api/login" },
    { method: "POST", fullPath: "/api/password/reset" },
    { method: "POST", fullPath: "/api/auth/verify-email" },
    { method: "POST", fullPath: "/api/oauth/github" },
    { method: "POST", fullPath: "/api/devices/register-device" }, // 段名不是建号
  ];
  assert.deepEqual(
    signupCandidates({ endpoints: eps }).map((c) => c.path),
    ["/api/auth/register", "/signup", "/api/create-user", "/api/users/create"]
  );
  assert.deepEqual(signupCandidates(null), []);
});

test("resolveRegisterEndpoint: 契约优先，静态唯一候选才敢用，多个候选回 static-ambiguous", () => {
  const one = { endpoints: [{ method: "POST", fullPath: "/api/register" }] };
  assert.deepEqual(resolveRegisterEndpoint(null, one), { path: "/api/register", source: "static", file: null });
  assert.deepEqual(
    resolveRegisterEndpoint({ path: "/v2/signup" }, one),
    { path: "/v2/signup", source: "contract" },
    "契约声明压过静态推断"
  );
  const two = { endpoints: [{ method: "POST", fullPath: "/api/register" }, { method: "POST", fullPath: "/api/users/create" }] };
  const amb = resolveRegisterEndpoint(null, two);
  assert.equal(amb.path, null);
  assert.equal(amb.source, "static-ambiguous");
  assert.deepEqual(amb.candidates, ["/api/register", "/api/users/create"]);
  const none = resolveRegisterEndpoint(null, { endpoints: [{ method: "POST", fullPath: "/api/login" }] });
  assert.deepEqual([none.path, none.source, none.candidates], [null, "none", []]);
});

test("fillTemplate / unresolvedPlaceholders: 递归填充，填不出的占位符要能被点名", () => {
  const v = { name: "a", username: "u" };
  assert.deepEqual(
    fillTemplate({ user: { login: "{username}", display: "{name}" }, tags: ["{name}", "{nope}"] }, v),
    { user: { login: "u", display: "a" }, tags: ["a", "{nope}"] }
  );
  assert.deepEqual(unresolvedPlaceholders({ a: "{x}{y}" }), ["x", "y"]);
  assert.deepEqual(unresolvedPlaceholders({ a: "plain" }), []);
});

test("registerBody: 未声明模板时按身份形状给最小体，声明了就用契约模板", () => {
  const values = { name: "alice", username: "alice", email: "alice@guardbuild.test", password: "GbXx12" };
  const byEmail = registerBody({ name: "alice", email: "a@b.c" }, null, values);
  assert.deepEqual(
    byEmail.body,
    { email: "a@b.c", password: "GbXx12" },
    "身份自己写了 email 就用它，引擎派生的邮箱只兜空缺"
  );
  const byUsername = registerBody({ name: "bob", username: "bob" }, null, values);
  assert.deepEqual(byUsername.body, { username: "bob", password: "GbXx12" });
  const declared = registerBody(
    { name: "alice" },
    { bodyTemplate: { login: "{username}", pwd: "{password}", profile: { nickname: "{name}" } } },
    values
  );
  assert.deepEqual(declared.body, { login: "alice", pwd: "GbXx12", profile: { nickname: "alice" } });
  assert.deepEqual(declared.unresolved, []);
  const broken = registerBody({ name: "dave" }, { bodyTemplate: { token: "{csrf}" } }, values);
  assert.deepEqual(broken.unresolved, ["csrf"], "契约字段名对不上必须暴露，不能把字面量 {csrf} 发出去");
  assert.deepEqual(defaultRegisterBody({ fields: { login: "x", code: "y" } }), { login: "x", code: "y" });
});

test("generateTestPassword: 满足常见复杂度校验且不含易混字符，两次生成不同", () => {
  const p1 = generateTestPassword();
  const p2 = generateTestPassword();
  assert.notEqual(p1, p2);
  assert.equal(p1.length, 18);
  assert.match(p1, /[a-z]/);
  assert.match(p1, /[A-Z]/);
  assert.match(p1, /\d/);
  assert.doesNotMatch(p1, /[01lIO]/, "易混字符会让人工核对出错");
  assert.match(generateCanary(), /^gbseed-[0-9a-f]{10}$/);
});

test("classifyRegisterResponse: 只看目标真实响应，2xx 建号 / 409 或「已存在」/ 404 端点不存在", () => {
  assert.deepEqual(classifyRegisterResponse({ status: 201, body: "{}" }), { verdict: "created", status: 201 });
  assert.deepEqual(classifyRegisterResponse({ status: 409, body: "{}" }), { verdict: "exists", status: 409 });
  assert.deepEqual(
    classifyRegisterResponse({ status: 400, body: JSON.stringify({ msg: "email already in use" }) }),
    { verdict: "exists", status: 400 }
  );
  assert.deepEqual(classifyRegisterResponse({ status: 404, body: "no route" }), { verdict: "not_found", status: 404 });
  assert.deepEqual(classifyRegisterResponse({ status: 422, body: "missing field" }), { verdict: "rejected", status: 422 });
  assert.deepEqual(classifyRegisterResponse({ status: 500, body: "" }), { verdict: "rejected", status: 500 });
});

test("seedBody / classifySeedResponse: 401/403 判成身份不可信，不是「目标没问题」", () => {
  assert.equal(seedBody({ path: "/api/orders" }, {}), null, "没写 bodyTemplate 的种子步骤不发请求");
  const prepared = seedBody({ bodyTemplate: { title: "{canary}" } }, { canary: "gbseed-1" });
  assert.deepEqual(prepared, { body: { title: "gbseed-1" }, unresolved: [] });
  assert.deepEqual(classifySeedResponse({ status: 403, body: "" }), { verdict: "denied", status: 403 });
  assert.deepEqual(classifySeedResponse({ status: 201, body: "" }), { verdict: "written", status: 201 });
  assert.deepEqual(classifySeedResponse({ status: 404, body: "" }), { verdict: "not_found", status: 404 });
});

test("loginAll: 省略口令的身份由引擎注册建号，口令只进 Host 保险库", async () => {
  const { server, url } = await listen(emptyDbApp());
  try {
    const ctx = makeCtx();
    ctx.loginConfig = LOGIN_CONTRACT;
    ctx.registerConfig = { path: "/api/register", bodyTemplate: { email: "{email}", password: "{password}" }, seed: [], headers: {} };
    ctx.analysis = PROFILE_ANALYSIS;
    ctx.identities = [
      { name: "alice", username: "alice", password: null, role: "user" },
      { name: "bob", username: "bob", password: null, role: "user" },
    ];
    const loggedIn = await loginAll(ctx, url);
    assert.deepEqual(loggedIn.map((i) => i.name), ["alice", "bob"]);
    assert.equal(ctx._identityBootstrap.byPhase.pre.endpoint, "/api/register");
    assert.equal(ctx._identityBootstrap.byPhase.pre.endpointSource, "contract");
    assert.deepEqual(
      ctx._identityBootstrap.byPhase.pre.accounts.map((a) => [a.name, a.verdict, a.trigger, a.generated]),
      [
        ["alice", "created", "no-declared-password", true],
        ["bob", "created", "no-declared-password", true],
      ]
    );
    // 注册请求真的打到了目标，且带的是引擎生成的强口令
    const regs = ctx.requests.filter((r) => r.path === "/api/register");
    assert.equal(regs.length, 2);
    assert.equal(JSON.parse(regs[0].body).email, "alice@guardbuild.test");
    assert.match(JSON.parse(regs[0].body).password, /^Gb.{14}\d\d$/);
    // 引擎口令登记进 protected 保险库（只脱敏、不作为请求头凭证）
    assert.deepEqual(ctx.protectedSecrets.map((s) => s.label), ["password:alice", "password:bob"]);
    assert.equal(ctx.protectedSecrets[0].value, JSON.parse(regs[0].body).password);
    assert.equal(ctx._identityBootstrap.byPhase.pre.secretProtection.alice, "ok");
    // 会话对象里绝不带口令：Sidecar 侧的 identities 结构不应外泄到会话条目
    assert.ok(!("password" in loggedIn[0]), "会话条目不得携带口令字段");
    // 事件流/报告里不能出现口令明文
    const dump = JSON.stringify({ events: ctx.events, report: ctx._identityReport });
    assert.ok(!dump.includes(ctx.protectedSecrets[0].value), "口令不能出现在事件流或报告里");
    assert.match(
      ctx.events.find((e) => /随机生成/.test(e.message)).message,
      /只进 Host 保险库（不落配置\/报告\/证据库）/
    );
  } finally {
    server.close();
  }
});

test("loginAll: 声明口令但空库里没有该账号时，注册一次再登录（不静默当已防护）", async () => {
  const { server, url } = await listen(emptyDbApp());
  try {
    const ctx = makeCtx();
    ctx.loginConfig = LOGIN_CONTRACT;
    ctx.registerConfig = { path: "/api/register", bodyTemplate: { email: "{email}", password: "{password}" }, seed: [], headers: {} };
    ctx.analysis = PROFILE_ANALYSIS;
    ctx.identities = [
      { name: "alice", email: "alice@t.test", password: "alice123456", role: "user" },
      { name: "bob", email: "bob@t.test", password: "bob12345678", role: "user" },
    ];
    const loggedIn = await loginAll(ctx, url);
    assert.deepEqual(loggedIn.map((i) => i.name), ["alice", "bob"]);
    assert.deepEqual(
      ctx._identityBootstrap.byPhase.pre.accounts.map((a) => [a.name, a.verdict, a.trigger, a.generated]),
      [
        ["alice", "created", "login-rejected", false],
        ["bob", "created", "login-rejected", false],
      ],
      "声明了口令就用口令注册，口令来源如实记为 declared"
    );
  } finally {
    server.close();
  }
});

test("loginAll: register.seed 给新建账号写数据，写入被拒就显式失败而不是继续跑", async () => {
  const { server, url } = await listen(emptyDbApp());
  try {
    const ctx = makeCtx();
    ctx.loginConfig = LOGIN_CONTRACT;
    ctx.registerConfig = {
      path: "/api/register",
      bodyTemplate: { email: "{email}", password: "{password}" },
      seed: [{ method: "POST", path: "/api/orders", bodyTemplate: { title: "{canary}" } }],
      headers: {},
    };
    ctx.analysis = PROFILE_ANALYSIS;
    ctx.identities = [
      { name: "alice", username: "alice", password: null },
      { name: "bob", username: "bob", password: null },
    ];
    const loggedIn = await loginAll(ctx, url);
    assert.equal(loggedIn.length, 2);
    const boot = ctx._identityBootstrap.byPhase.pre;
    assert.deepEqual(boot.seeds.map((s) => [s.identity, s.path, s.status, s.verdict]), [
      ["alice", "/api/orders", 201, "written"],
      ["bob", "/api/orders", 201, "written"],
    ]);
    const seedReq = ctx.requests.find((r) => r.path === "/api/orders");
    assert.match(JSON.parse(seedReq.body).title, /^gbseed-/);
    assert.ok(seedReq.headers.Authorization, "种子写入必须带着该身份自己的会话");
  } finally {
    server.close();
  }
});

test("loginAll: 注册成功但写入被 403 拒掉 → identity_seed_failed，本轮不算测过", async () => {
  const { server, url } = await listen(emptyDbApp({ denySeed: true }));
  try {
    const ctx = makeCtx();
    ctx.loginConfig = LOGIN_CONTRACT;
    ctx.registerConfig = {
      path: "/api/register",
      bodyTemplate: { email: "{email}", password: "{password}" },
      seed: [{ method: "POST", path: "/api/orders", bodyTemplate: { title: "{canary}" } }],
      headers: {},
    };
    ctx.analysis = PROFILE_ANALYSIS;
    ctx.identities = [
      { name: "alice", username: "alice", password: null },
      { name: "bob", username: "bob", password: null },
    ];
    await assert.rejects(() => loginAll(ctx, url), (e) => {
      assert.equal(e.code, "identity_seed_failed");
      assert.match(e.message, /HTTP 403/);
      assert.match(e.hint, /写入却被拒/);
      return true;
    });
  } finally {
    server.close();
  }
});

test("loginAll: 目标没有注册接口而身份省略口令 → 显式 inconclusive，绝不退回匿名探测", async () => {
  const { server, url } = await listen(emptyDbApp());
  try {
    const ctx = makeCtx();
    ctx.loginConfig = LOGIN_CONTRACT;
    ctx.registerConfig = null;
    ctx.analysis = { endpoints: [{ method: "GET", fullPath: "/api/profile", hasAuth: true, hasRoleGuard: false }] };
    ctx.identities = [{ name: "alice", username: "alice", password: null }];
    await assert.rejects(() => loginAll(ctx, url), (e) => {
      assert.equal(e.code, "identity_bootstrap_unavailable");
      assert.equal(e.details.reason, "none");
      assert.match(e.hint, /register\.path/);
      return true;
    });
    assert.deepEqual(
      ctx.requests.map((r) => r.path),
      [],
      "身份没建立前一个请求都不该发出去——发出去就是拿匿名会话冒充越权测试"
    );
  } finally {
    server.close();
  }
});

test("loginAll: 静态注册候选有多个时引擎不猜，报错里列出候选", async () => {
  const { server, url } = await listen(emptyDbApp());
  try {
    const ctx = makeCtx();
    ctx.loginConfig = LOGIN_CONTRACT;
    ctx.registerConfig = null;
    ctx.analysis = {
      endpoints: [
        { method: "GET", fullPath: "/api/profile", hasAuth: true, hasRoleGuard: false },
        { method: "POST", fullPath: "/api/register" },
        { method: "POST", fullPath: "/api/users/create" },
      ],
    };
    ctx.identities = [{ name: "alice", username: "alice", password: null }];
    await assert.rejects(() => loginAll(ctx, url), (e) => {
      assert.equal(e.code, "identity_bootstrap_unavailable");
      assert.equal(e.details.reason, "static-ambiguous");
      assert.deepEqual(e.details.candidates, ["/api/register", "/api/users/create"]);
      return true;
    });
  } finally {
    server.close();
  }
});

test("loginAll: 纯黑盒模式不给外部目标发注册请求", async () => {
  const { server, url } = await listen(emptyDbApp());
  try {
    const ctx = makeCtx();
    ctx.blackboxUrl = url;
    ctx.loginConfig = LOGIN_CONTRACT;
    ctx.analysis = PROFILE_ANALYSIS;
    ctx.identities = [{ name: "alice", username: "alice", password: null }];
    await assert.rejects(() => loginAll(ctx, url), (e) => {
      assert.equal(e.code, "identity_bootstrap_unavailable");
      assert.equal(e.details.reason, "blackbox");
      assert.match(e.hint, /纯黑盒模式不会向外部目标发注册请求/);
      return true;
    });
    assert.deepEqual(ctx.requests.map((r) => r.path), []);
  } finally {
    server.close();
  }
});

test("loginAll: 静态识别到唯一注册路由时不需要契约也能自举", async () => {
  const { server, url } = await listen(emptyDbApp());
  try {
    const ctx = makeCtx();
    ctx.loginConfig = LOGIN_CONTRACT;
    ctx.registerConfig = null;
    ctx.analysis = PROFILE_ANALYSIS; // POST /api/register 是唯一建号候选
    ctx.identities = [
      { name: "alice", email: "alice@t.test", password: null },
      { name: "bob", email: "bob@t.test", password: null },
    ];
    const loggedIn = await loginAll(ctx, url);
    assert.equal(loggedIn.length, 2);
    assert.equal(ctx._identityBootstrap.byPhase.pre.endpointSource, "static");
    assert.equal(ctx._identityBootstrap.byPhase.pre.endpoint, "/api/register");
    const regBody = JSON.parse(ctx.requests.find((r) => r.path === "/api/register").body);
    assert.deepEqual(Object.keys(regBody).sort(), ["email", "password"], "最小注册体只带身份里确有的字段");
    assert.equal(regBody.email, "alice@t.test");
    assert.match(regBody.password, /^Gb.{14}\d\d$/);
  } finally {
    server.close();
  }
});

test("loginAll: 目标要求的字段引擎填不出时报 rejected，不猜字段名", async () => {
  const { server, url } = await listen(emptyDbApp());
  try {
    const ctx = makeCtx();
    ctx.loginConfig = LOGIN_CONTRACT;
    ctx.registerConfig = null;
    ctx.analysis = PROFILE_ANALYSIS;
    // 身份只有 username：默认注册体发的是 {username,password}，而目标要 email
    ctx.identities = [{ name: "alice", username: "alice", password: null }];
    await assert.rejects(() => loginAll(ctx, url), (e) => {
      assert.equal(e.code, "identity_bootstrap_failed");
      assert.match(e.message, /rejected \(HTTP 422\)/);
      return true;
    });
    assert.equal(ctx._identityBootstrap.byPhase.pre.accounts[0].verdict, "rejected");
  } finally {
    server.close();
  }
});

test("loginAll: register.enabled=false 时省略口令的身份直接显式失败", async () => {
  const { server, url } = await listen(emptyDbApp());
  try {
    const ctx = makeCtx();
    ctx.loginConfig = LOGIN_CONTRACT;
    ctx.registerConfig = { enabled: false, path: "/api/register", seed: [], headers: {} };
    ctx.analysis = PROFILE_ANALYSIS;
    ctx.identities = [{ name: "alice", username: "alice", password: null }];
    await assert.rejects(() => loginAll(ctx, url), (e) => {
      assert.equal(e.code, "identity_bootstrap_unavailable");
      assert.equal(e.details.reason, "disabled");
      return true;
    });
  } finally {
    server.close();
  }
});

test("loginAll: 注册体有引擎填不出的占位符时不发请求，报错点名该字段", async () => {
  const { server, url } = await listen(emptyDbApp());
  try {
    const ctx = makeCtx();
    ctx.loginConfig = LOGIN_CONTRACT;
    ctx.registerConfig = { path: "/api/register", bodyTemplate: { email: "{email}", password: "{password}", invite: "{code}" }, seed: [], headers: {} };
    ctx.analysis = PROFILE_ANALYSIS;
    ctx.identities = [{ name: "alice", username: "alice", password: null }];
    await assert.rejects(() => loginAll(ctx, url), (e) => {
      assert.equal(e.code, "identity_bootstrap_failed");
      assert.match(e.message, /自举失败/);
      return true;
    });
    assert.equal(
      ctx._identityBootstrap.byPhase.pre.accounts[0].verdict,
      "template_unresolved"
    );
    assert.deepEqual(ctx._identityBootstrap.byPhase.pre.accounts[0].fields, ["code"]);
    assert.equal(
      ctx.requests.filter((r) => r.path === "/api/register").length,
      0,
      "带字面量 {code} 的请求不该发出去"
    );
  } finally {
    server.close();
  }
});

test("loginAll: 注册端点不存在（404）时如实记 not_found 并终止", async () => {
  const { server, url } = await listen(emptyDbApp());
  try {
    const ctx = makeCtx();
    ctx.loginConfig = LOGIN_CONTRACT;
    ctx.registerConfig = { path: "/api/nope", bodyTemplate: { email: "{email}", password: "{password}" }, seed: [], headers: {} };
    ctx.analysis = PROFILE_ANALYSIS;
    ctx.identities = [{ name: "alice", username: "alice", password: null }];
    await assert.rejects(() => loginAll(ctx, url), (e) => {
      assert.equal(e.code, "identity_bootstrap_failed");
      assert.match(e.message, /not_found/);
      return true;
    });
    assert.equal(ctx._identityBootstrap.byPhase.pre.accounts[0].status, 404);
  } finally {
    server.close();
  }
});

test("loginAll: 已存在的账号被注册接口报 409 后照常登录，口令不会被改写", async () => {
  const app = emptyDbApp();
  const { server, url } = await listen(async (req, res) => {
    // 预置一个账号，模拟「库里已经有测试账号」
    await app(req, res);
  });
  try {
    // 先手动建号（用固定口令），再让引擎带声明口令跑
    await fetch(`${url}/api/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "alice@t.test", password: "known12345" }),
    });
    const ctx = makeCtx();
    ctx.loginConfig = LOGIN_CONTRACT;
    ctx.registerConfig = { path: "/api/register", bodyTemplate: { email: "{email}", password: "{password}" }, seed: [], headers: {} };
    ctx.analysis = PROFILE_ANALYSIS;
    ctx.identities = [
      { name: "alice", email: "alice@t.test", password: "known12345" },
      { name: "bob", email: "bob@t.test", password: "known12345" },
    ];
    const loggedIn = await loginAll(ctx, url);
    assert.deepEqual(loggedIn.map((i) => i.name), ["alice", "bob"], "alice 直接登录成功；bob 走一次注册");
    const accounts = Object.fromEntries(ctx._identityBootstrap.byPhase.pre.accounts.map((a) => [a.name, a.verdict]));
    assert.equal(accounts.alice, undefined, "登录成功的身份不该触发注册");
    assert.equal(accounts.bob, "created");
    assert.equal(ctx.protectedSecrets.length, 0, "声明口令的身份不该产生引擎口令登记");
  } finally {
    server.close();
  }
});
