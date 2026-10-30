import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { RPC_TO_HOST } from "../../shared/protocol.mjs";
import { loginAll, pickSessionProbePath, rendersLoginForm } from "../lib/probe.mjs";

// 真实项目形态（event-manager 实测，2026-10-30 12:56，端口 4177）：
// 密码错误 → HTTP 200 + 重新渲染的登录表单 + 照样下发 Set-Cookie；
// 密码正确 → HTTP 302 + 会话；匿名与「假会话」打受保护页得到完全同形的登录页。
// 只按状态码判定的旧逻辑会把前者记成登录成功，随后所有越权用例拿匿名会话打，全线被拒 → 误报「未复现」。

function listen(app) {
  return new Promise((resolve) => {
    const server = createServer(app);
    server.listen(0, "127.0.0.1", () => resolve({ server, url: `http://127.0.0.1:${server.address().port}` }));
  });
}

/** 仿 Host 保险库：Set-Cookie 即存即用，identityRef 才附带；3xx 不自动跟随（交给 followRedirects） */
function makeCtx(vault) {
  const events = [];
  return {
    tokens: { net: "net-token" },
    loginConfig: null,
    identities: [],
    plan: { loginCandidates: ["/auth/login"], loginPath: "/auth/login" },
    analysis: null,
    events,
    emit: (ev) => events.push(ev),
    rpc: {
      request: async (method, params) => {
        assert.equal(method, RPC_TO_HOST.HTTP_REQUEST);
        const headers = { ...(params.headers ?? {}) };
        if (params.identityRef) {
          const cred = vault.get(params.identityRef);
          assert.ok(cred, `vault 应有身份 ${params.identityRef} 的凭据`);
          headers[cred.header] = cred.value;
        }
        const res = await fetch(params.url, {
          method: params.method,
          headers,
          body: params.body,
          redirect: "manual",
        });
        const body = await res.text();
        let storedIdentity;
        if (params.storeCookieAs) {
          const cookies = (res.headers.getSetCookie?.() ?? []).map((c) => c.split(";")[0]);
          if (cookies.length) {
            vault.set(params.storeCookieAs, { header: "Cookie", value: cookies.join("; ") });
            storedIdentity = params.storeCookieAs;
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
}

const LOGIN_FORM = '<!doctype html><html><body><form method="post"><input name="email"><input type="password" name="password"></form></body></html>';

function formApp({ failWithForm }) {
  const sessions = new Map(); // sid -> user
  let seq = 0;
  return async (req, res) => {
    const url = new URL(req.url, "http://x");
    const sid = (req.headers.cookie ?? "").match(/sid=([^;]+)/)?.[1] ?? null;
    const user = sid ? sessions.get(sid) : null;
    if (req.method === "POST" && url.pathname === "/auth/login") {
      const raw = await new Promise((r) => {
        let b = "";
        req.on("data", (c) => (b += c));
        req.on("end", () => r(b));
      });
      const form = new URLSearchParams(raw);
      const email = form.get("email");
      const ok = email === "u1@test.com" && form.get("password") === "right123";
      if (ok) {
        const id = `s${++seq}`;
        sessions.set(id, email);
        res.writeHead(302, { Location: "/dashboard", "Set-Cookie": `sid=${id}; Path=/` });
        return res.end("Found. Redirecting to /dashboard");
      }
      if (failWithForm) {
        res.writeHead(200, { "Content-Type": "text/html", "Set-Cookie": `sid=anon${++seq}; Path=/` });
        return res.end(LOGIN_FORM);
      }
      // 无表单形态：只回 JSON「成功」并照样下发会话——状态码判定看不出来，只能靠鉴权回读
      res.writeHead(200, { "Content-Type": "application/json", "Set-Cookie": `sid=anon${++seq}; Path=/` });
      return res.end(JSON.stringify({ ok: true }));
    }
    if (req.method === "GET" && url.pathname === "/auth/login") {
      res.writeHead(200, { "Content-Type": "text/html" });
      return res.end(LOGIN_FORM);
    }
    if (req.method === "GET" && url.pathname === "/dashboard") {
      if (user) {
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ user, orders: [1, 2] }));
      }
      res.writeHead(302, { Location: "/auth/login" });
      return res.end("redirect");
    }
    res.writeHead(404, { "Content-Type": "text/plain" });
    res.end("not found");
  };
}

function jsonDenyApp() {
  const sessions = new Map();
  let seq = 0;
  return async (req, res) => {
    const url = new URL(req.url, "http://x");
    const sid = (req.headers.cookie ?? "").match(/sid=([^;]+)/)?.[1] ?? null;
    if (req.method === "POST" && url.pathname === "/auth/login") {
      const raw = await new Promise((r) => {
        let b = "";
        req.on("data", (c) => (b += c));
        req.on("end", () => r(b));
      });
      const form = new URLSearchParams(raw);
      if (form.get("email") === "u1@test.com" && form.get("password") === "right123") {
        const id = `s${++seq}`;
        sessions.set(id, form.get("email"));
        res.writeHead(200, { "Content-Type": "application/json", "Set-Cookie": `sid=${id}; Path=/` });
        return res.end(JSON.stringify({ user: { id: 1 } }));
      }
      res.writeHead(200, { "Content-Type": "application/json", "Set-Cookie": `sid=anon${++seq}; Path=/` });
      return res.end(JSON.stringify({ ok: true }));
    }
    if (req.method === "GET" && url.pathname === "/api/profile") {
      if (!sessions.has(sid)) {
        res.writeHead(401, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ error: "unauthorized" }));
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      return res.end(JSON.stringify({ id: 1 }));
    }
    res.writeHead(404);
    res.end("nope");
  };
}

const CONTRACT = {
  path: "/auth/login",
  encoding: "form",
  cookieAuth: true,
  bodyTemplate: { email: "{email}", password: "{password}" },
};

function withIdentities(ctx) {
  ctx.loginConfig = CONTRACT;
  ctx.identities = [
    { name: "u1", email: "u1@test.com", password: "right123" },
    { name: "u2", email: "u2@test.com", password: "right123" }, // 目标库里不存在该账号
  ];
  return ctx;
}

const PROBE_ANALYSIS = { endpoints: [{ method: "GET", fullPath: "/dashboard", hasAuth: true, hasRoleGuard: false }] };

test("rendersLoginForm: 只认带密码输入框的 HTML 形态", () => {
  assert.equal(rendersLoginForm({ body: LOGIN_FORM }), true);
  assert.equal(rendersLoginForm({ body: JSON.stringify({ token: "a.b.c" }) }), false);
  assert.equal(rendersLoginForm({ body: "<html><body>仪表板</body></html>" }), false);
  assert.equal(rendersLoginForm({ body: "" }), false);
});

test("pickSessionProbePath: 只取无参数、只读、非角色门禁、非登录类路径", () => {
  const eps = [
    { method: "GET", fullPath: "/api/admin/users", hasAuth: true, hasRoleGuard: true },
    { method: "GET", fullPath: "/api/orders/:id", hasAuth: true, hasRoleGuard: false },
    { method: "POST", fullPath: "/api/profile", hasAuth: true, hasRoleGuard: false },
    { method: "GET", fullPath: "/auth/login", hasAuth: true, hasRoleGuard: false },
    { method: "GET", fullPath: "/health", hasAuth: false, hasRoleGuard: false },
    { method: "GET", fullPath: "/api/profile", hasAuth: true, hasRoleGuard: false },
  ];
  assert.equal(pickSessionProbePath({ endpoints: eps }, "/auth/login"), "/api/profile");
  assert.equal(pickSessionProbePath({ endpoints: [] }, "/auth/login"), null);
  assert.equal(pickSessionProbePath(null, "/auth/login"), null);
});

test("loginAll: 密码错误时目标回 200 登录表单，不得记成登录成功", async () => {
  const vault = new Map();
  const { server, url } = await listen(formApp({ failWithForm: true }));
  try {
    const ctx = withIdentities(makeCtx(vault));
    ctx.analysis = PROBE_ANALYSIS;
    await assert.rejects(() => loginAll(ctx, url), (e) => {
      assert.equal(e.code, "login_form_rerendered", "应归因成「响应仍是登录表单」");
      assert.match(e.hint, /密码输入框/);
      return true;
    });
  } finally {
    server.close();
  }
});

test("loginAll: 全部身份密码正确时登录成立，并回读会话真实性", async () => {
  const vault = new Map();
  const { server, url } = await listen(formApp({ failWithForm: true }));
  try {
    const ctx = makeCtx(vault);
    ctx.loginConfig = CONTRACT;
    ctx.identities = [{ name: "u1", email: "u1@test.com", password: "right123" }];
    ctx.analysis = PROBE_ANALYSIS;
    const loggedIn = await loginAll(ctx, url);
    assert.deepEqual(loggedIn.map((i) => i.name), ["u1"]);
    assert.equal(ctx._loginVerified, true);
    assert.ok(
      ctx.events.some((e) => e.kind === "identity" && /会话真实性已回读验证/.test(e.message)),
      "验证通过要留下可见证据，不能静默"
    );
  } finally {
    server.close();
  }
});

test("loginAll: 200+JSON 的假成功要靠鉴权回读识破（响应体里没有表单）", async () => {
  const vault = new Map();
  const { server, url } = await listen(jsonDenyApp());
  try {
    const ctx = withIdentities(makeCtx(vault));
    ctx.analysis = { endpoints: [{ method: "GET", fullPath: "/api/profile", hasAuth: true, hasRoleGuard: false }] };
    await assert.rejects(() => loginAll(ctx, url), (e) => {
      assert.equal(e.code, "login_session_unverified");
      assert.match(e.message, /与匿名请求同形/);
      assert.equal(e.details.probePath, "/api/profile");
      assert.equal(e.details.identity, "u2", "首个身份的会话是真的，第二个才是假成功");
      return true;
    });
  } finally {
    server.close();
  }
});

test("loginAll: 识破假成功后，真实会话仍应通过回读（非对称判据不误伤）", async () => {
  const vault = new Map();
  const { server, url } = await listen(jsonDenyApp());
  try {
    const ctx = makeCtx(vault);
    ctx.loginConfig = CONTRACT;
    ctx.identities = [{ name: "u1", email: "u1@test.com", password: "right123" }];
    ctx.analysis = { endpoints: [{ method: "GET", fullPath: "/api/profile", hasAuth: true, hasRoleGuard: false }] };
    const loggedIn = await loginAll(ctx, url);
    assert.equal(loggedIn.length, 1, "真实会话读得通受保护接口，不应被回读判据否掉");
  } finally {
    server.close();
  }
});

test("loginAll: 多角色应用按 identities[].loginPath 各自登录（不再拿参与者端点登组织者）", async () => {
  const vault = new Map();
  const { server, url } = await listen(roleScopedApp());
  try {
    const ctx = makeCtx(vault);
    ctx.loginConfig = CONTRACT;
    ctx.identities = [
      { name: "att1", email: "att@test.com", password: "pw123456", loginPath: "/auth/attendee/login" },
      { name: "org1", email: "org@test.com", password: "pw123456", loginPath: "/auth/organiser/login" },
    ];
    ctx.analysis = { endpoints: [{ method: "GET", fullPath: "/dashboard", hasAuth: true, hasRoleGuard: false }] };
    const loggedIn = await loginAll(ctx, url);
    assert.deepEqual(loggedIn.map((i) => i.name), ["att1", "org1"]);
    assert.deepEqual(
      ctx._loginEndpoints,
      { att1: "/auth/attendee/login", org1: "/auth/organiser/login" },
      "每个身份记回它实际登录成功的端点"
    );
  } finally {
    server.close();
  }
});

test("loginAll: 没有 loginPath 时组织者被参与者端点拒绝，如实报错而不是记成成功", async () => {
  const vault = new Map();
  const { server, url } = await listen(roleScopedApp());
  try {
    const ctx = makeCtx(vault);
    ctx.loginConfig = CONTRACT;
    ctx.plan.loginCandidates = ["/auth/attendee/login"];
    ctx.identities = [
      { name: "att1", email: "att@test.com", password: "pw123456" },
      { name: "org1", email: "org@test.com", password: "pw123456" },
    ];
    ctx.analysis = { endpoints: [{ method: "GET", fullPath: "/dashboard", hasAuth: true, hasRoleGuard: false }] };
    await assert.rejects(() => loginAll(ctx, url), (e) => {
      assert.equal(e.code, "login_form_rerendered");
      assert.match(e.message, /org1/);
      assert.match(e.hint, /loginPath/);
      return true;
    });
  } finally {
    server.close();
  }
});

test("loginAll: 没有可用于回读的受保护只读接口时如实标注跳过，不声称已验证", async () => {
  const vault = new Map();
  const { server, url } = await listen(jsonDenyApp());
  try {
    const ctx = withIdentities(makeCtx(vault));
    ctx.analysis = { endpoints: [{ method: "GET", fullPath: "/api/profile/:id", hasAuth: true, hasRoleGuard: false }] };
    const loggedIn = await loginAll(ctx, url);
    assert.equal(loggedIn.length, 2, "无探针时不做回读判定（也不误杀）");
    assert.ok(
      ctx.events.some((e) => /会话真实性回读未执行/.test(e.message)),
      "跳过必须写明，否则等于谎称身份可信"
    );
  } finally {
    server.close();
  }
});

function roleScopedApp() {
  const sessions = new Map();
  const users = { "/auth/attendee/login": "att@test.com", "/auth/organiser/login": "org@test.com" };
  let seq = 0;
  return async (req, res) => {
    const url = new URL(req.url, "http://x");
    const sid = (req.headers.cookie ?? "").match(/sid=([^;]+)/)?.[1] ?? null;
    if (req.method === "POST" && users[url.pathname]) {
      const raw = await new Promise((r) => {
        let b = "";
        req.on("data", (c) => (b += c));
        req.on("end", () => r(b));
      });
      const form = new URLSearchParams(raw);
      const ok = form.get("email") === users[url.pathname] && form.get("password") === "pw123456";
      if (ok) {
        const id = `s${++seq}`;
        sessions.set(id, form.get("email"));
        res.writeHead(302, { Location: "/dashboard", "Set-Cookie": `sid=${id}; Path=/` });
        return res.end("Found");
      }
      res.writeHead(200, { "Content-Type": "text/html", "Set-Cookie": `sid=anon${++seq}; Path=/` });
      return res.end(LOGIN_FORM);
    }
    if (req.method === "GET" && url.pathname === "/dashboard") {
      if (sessions.has(sid)) {
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ ok: true }));
      }
      res.writeHead(200, { "Content-Type": "text/html" });
      return res.end(LOGIN_FORM);
    }
    res.writeHead(404);
    res.end("not found");
  };
}
