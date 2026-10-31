/**
 * SSR / HTML 应用的资源发现与页面越权取证（#178 补齐 c 项）。
 *
 * 这一族的传统形态是：没有 JSON 列表接口，列表和详情都是服务端渲染的页面。
 * 老逻辑在发现阶段就拿不到对象 ID（no_list_endpoint），越权类整族跑不起来；
 * 即便拿到路径，页面响应也没有 userId 字段可比对。
 * 本文件用真实 HTTP 服务（表单 + Cookie 会话）实测两条链路：
 *  ① 从登录后的页面链接里发现各自名下对象，并回读本人页面正文作归属基线；
 *  ② 越权取证按「只在受害人本人页面出现的正文片段」判定，正向断言按同一份正文契约判定。
 * 运行：npm run test:sidecar
 */
import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { RPC_TO_HOST } from "../../shared/protocol.mjs";
import { buildCases, discoverViaHtmlPages, htmlEntryPages, loginAll } from "../lib/probe.mjs";

const NAV = `<nav><a href="/">首页</a><a href="/my">我的笔记</a><a href="/login">登录</a></nav>`;

const USERS = [
  { id: 1, email: "alice@t.com", password: "pw123456", name: "周慕云" },
  { id: 2, email: "bob@t.com", password: "pw123456", name: "韩雪" },
];

const NOTES = [
  { id: 101, userId: 1, code: "A-1013", title: "机械键盘团购", courier: "SF1029384756", note: "周五前发货" },
  { id: 102, userId: 1, code: "A-1024", title: "显示器比价", courier: "SF1029388811", note: "等促销再买" },
  { id: 201, userId: 2, code: "B-2087", title: "耳机退货", courier: "YT8837462211", note: "走顺丰到付" },
];

function page(title, body) {
  return `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title></head><body>${NAV}<main>${body}</main></body></html>`;
}

function notePage(n) {
  const owner = USERS.find((u) => u.id === n.userId);
  return page(
    `${n.title} - 我的笔记`,
    `<h1>${n.title}</h1><p>单号 ${n.code}</p><p>收件人 ${owner.name}</p><p>快递单号 ${n.courier}</p><p>备注 ${n.note}</p>`
  );
}

function listPage(user) {
  const mine = NOTES.filter((n) => n.userId === user.id);
  const items = mine.map((n) => `<li><a href="/notes/${n.id}">${n.title}</a></li>`).join("");
  return page("我的笔记", `<ul>${items}</ul>`);
}

const LOGIN_FORM = `<form method="post" action="/login"><input name="email"><input type="password" name="password"></form>`;

/** 仿传统 SSR 应用：全站只有页面，没有任何 JSON 接口。GB_SSR_HARDENED=1 时详情页校验归属 */
function ssrApp({ hardened }) {
  const sessions = new Map();
  let seq = 0;
  return async (req, res) => {
    const url = new URL(req.url, "http://x");
    const p = url.pathname;
    const sid = (req.headers.cookie ?? "").match(/sid=([^;]+)/)?.[1] ?? null;
    const user = sid ? sessions.get(sid) : null;
    const send = (status, html, headers = {}) => {
      res.writeHead(status, { "Content-Type": "text/html; charset=utf-8", ...headers });
      res.end(html);
    };

    if (req.method === "POST" && p === "/login") {
      const raw = await new Promise((r) => {
        let b = "";
        req.on("data", (c) => (b += c));
        req.on("end", () => r(b));
      });
      const form = new URLSearchParams(raw);
      const found = USERS.find((u) => u.email === form.get("email") && u.password === form.get("password"));
      if (found) {
        const id = `s${++seq}`;
        sessions.set(id, found);
        res.writeHead(302, { Location: "/my", "Set-Cookie": `sid=${id}; Path=/` });
        return res.end("redirecting");
      }
      return send(200, page("登录", LOGIN_FORM), { "Set-Cookie": `sid=anon${++seq}; Path=/` });
    }

    if (req.method === "GET" && p === "/login") return send(200, page("登录", LOGIN_FORM));

    if (req.method === "GET" && p === "/") {
      return send(200, page("首页", `<p>欢迎使用笔记本，请登录后查看。</p>${LOGIN_FORM}`));
    }

    if (req.method === "GET" && p === "/my") {
      if (!user) {
        res.writeHead(302, { Location: "/login" });
        return res.end("redirect");
      }
      return send(200, listPage(user));
    }

    const detail = /^\/notes\/(\d+)$/.exec(p);
    if (req.method === "GET" && detail) {
      if (!user) {
        res.writeHead(302, { Location: "/login" });
        return res.end("redirect");
      }
      const n = NOTES.find((x) => x.id === Number(detail[1]));
      if (!n) return send(404, page("未找到", "<p>该笔记不存在</p>"));
      if (hardened && n.userId !== user.id) return send(403, page("禁止访问", "<p>无权查看该笔记</p>"));
      return send(200, notePage(n)); // 漏洞版：只验登录，不验归属
    }

    return send(404, page("未找到", "<p>该页面不存在</p>"));
  };
}

function listen(app) {
  return new Promise((resolve) => {
    const server = createServer(app);
    server.listen(0, "127.0.0.1", () => resolve({ server, url: `http://127.0.0.1:${server.address().port}` }));
  });
}

/** 仿 Host 保险库：Cookie 登录后存、按 identityRef 附带；Sidecar 永不见会话值 */
function makeCtx() {
  const vault = new Map();
  const events = [];
  const ctx = {
    tokens: { net: "net-token" },
    loginConfig: {
      path: "/login",
      encoding: "form",
      cookieAuth: true,
      bodyTemplate: { email: "{email}", password: "{password}" },
    },
    identities: [
      { name: "alice", email: "alice@t.com", password: "pw123456", role: "user" },
      { name: "bob", email: "bob@t.com", password: "pw123456", role: "user" },
    ],
    plan: {
      resource: "note",
      loginPath: "/login",
      loginCandidates: ["/login"],
      readCandidates: [{ kind: "idor-suspect", method: "GET", path: "/notes/:id", fullPath: "/notes/:id", resource: "note", routeKeys: ["notes.detail"] }],
      readCandidate: null,
      candidates: [],
    },
    analysis: {
      endpoints: [
        { method: "GET", path: "/my", fullPath: "/my", hasAuth: true, hasRoleGuard: false },
        { method: "GET", path: "/notes/:id", fullPath: "/notes/:id", hasAuth: true, hasRoleGuard: false },
      ],
      candidates: [],
    },
    targetConfig: null,
    events,
    emit: (ev) => events.push(ev),
    rpc: {
      request: async (method, params) => {
        assert.equal(method, RPC_TO_HOST.HTTP_REQUEST);
        const headers = { ...(params.headers ?? {}) };
        if (params.identityRef) {
          const cred = vault.get(params.identityRef);
          assert.ok(cred, `vault 应有身份 ${params.identityRef} 的会话`);
          headers.Cookie = cred;
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
            vault.set(params.storeCookieAs, cookies.join("; "));
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
  return ctx;
}

/** 直接按身份发一次请求，形状与 httpJson 的返回一致（json 解析失败即 null，页面形态由此判定） */
async function getAs(ctx, baseUrl, identity, path) {
  const r = await ctx.rpc.request(
    RPC_TO_HOST.HTTP_REQUEST,
    { token: ctx.tokens.net, method: "GET", url: `${baseUrl}${path}`, headers: {}, identityRef: identity, redact: true },
    {}
  );
  let json = null;
  try {
    json = JSON.parse(r.body);
  } catch {
    /* 页面响应 */
  }
  return { ...r, json };
}

/** 发现结果 → 用例所需的对象槽位（与 pickTargets 同构，单参数路由不需要多段绑定） */
function targetsFrom(disc, loggedIn) {
  const attacker = loggedIn[0];
  const victim = loggedIn[1];
  const attackerItems = disc.byUser[attacker.name] ?? [];
  const victimItems = disc.byUser[victim.name] ?? [];
  return {
    attacker,
    victim,
    admin: null,
    attackerItems,
    victimItems,
    attackerOwnIds: new Set(attackerItems.map((o) => String(o.id))),
    readTarget: victimItems[0] ?? null,
    victimOwnTarget: victimItems[0] ?? null,
    ownReadTarget: attackerItems[0] ?? null,
    attackCancelTarget: null,
    adminCancelTarget: null,
    ownCancelTarget: null,
    ownNotCancellable: null,
    anonTargets: [],
  };
}

test("htmlEntryPages: 首页 + 模板父路径 + 无参数 GET 路由，去重且不超预算", () => {
  const ctx = {
    analysis: {
      endpoints: [
        { method: "GET", fullPath: "/my" },
        { method: "GET", fullPath: "/notes/:id" },
        { method: "GET", fullPath: "/archive" },
        { method: "GET", fullPath: "/settings" },
        { method: "GET", fullPath: "/extra" },
      ],
    },
  };
  assert.deepEqual(htmlEntryPages(ctx, ["/notes/:id"]), ["/", "/notes", "/my", "/archive"]);
  assert.deepEqual(htmlEntryPages(ctx, []), ["/", "/my", "/archive", "/settings"]);
  // 多段模板只取第一个参数之前的父路径
  assert.deepEqual(htmlEntryPages({ analysis: { endpoints: [] } }, ["/orgs/:orgId/members/:id"]).slice(0, 2), ["/", "/orgs"]);
});

test("discoverViaHtmlPages: 从页面链接发现各自名下对象，并回读本人页面正文作归属基线", async () => {
  const { server, url } = await listen(ssrApp({ hardened: false }));
  try {
    const ctx = makeCtx();
    const loggedIn = await loginAll(ctx, url);
    assert.equal(loggedIn.length, 2);
    const disc = await discoverViaHtmlPages(ctx, url, loggedIn);
    assert.ok(disc, "页面链接里有对象，发现应成功");
    assert.deepEqual(
      (disc.byUser.alice ?? []).map((o) => String(o.id)),
      ["101", "102"]
    );
    assert.deepEqual(
      (disc.byUser.bob ?? []).map((o) => String(o.id)),
      ["201"]
    );
    const base = ctx._htmlPages.baseline;
    assert.deepEqual([...base.keys()].map(Number).sort((a, b) => a - b), [101, 102, 201]);
    assert.equal(base.get("201").owner, "bob", "201 的正文基线必须来自 bob 自己的会话");
    assert.equal(base.get("201").link, "/notes/201");
    assert.match(base.get("201").text, /B-2087/);
    assert.match(base.get("201").text, /韩雪/, "中文正文同样进基线（汉字二元组切片）");
    const modes = ctx.events.filter((e) => e.data?.mode === "html-pages");
    assert.equal(modes.length, 1);
    assert.ok(modes[0].message.includes("归属基线"), modes[0].message);
  } finally {
    server.close();
  }
});

test("attack-read-foreign: 页面越权按「本人页面独有片段」取证，漏洞版复现、加固版阻断", async () => {
  const { server, url } = await listen(ssrApp({ hardened: false }));
  const { server: fixed, url: fixedUrl } = await listen(ssrApp({ hardened: true }));
  try {
    const ctx = makeCtx();
    const loggedIn = await loginAll(ctx, url);
    const disc = await discoverViaHtmlPages(ctx, url, loggedIn);
    const targets = targetsFrom(disc, loggedIn);
    const cases = buildCases(ctx, targets);
    const attack = cases.find((c) => c.id === "attack-read-foreign");
    assert.ok(attack, "越权读用例应被构建");
    assert.equal(attack.path, "/notes/201");

    const leak = await getAs(ctx, url, "alice", attack.path);
    const v = attack.verify(leak, "pre");
    assert.equal(v.verdict, "vulnerable", v.actual);
    assert.match(v.actual, /独有|片段/);
    assert.match(v.actual, /B-2087|韩雪|耳机/);
    const cross = attack.crossProof(leak);
    assert.ok(cross?.note.includes("交叉证明") || cross?.note.includes("独有"), cross?.note);
    assert.match(attack.impact(leak), /页面正文/);

    // 加固版：403 页面 → 已有访问控制（静态误报形态），不得算作「复现」
    // 会话按实例隔离，加固实例要用自己的保险库重新登录
    const ctxFixed = makeCtx();
    await loginAll(ctxFixed, fixedUrl);
    const denied = await getAs(ctxFixed, fixedUrl, "alice", "/notes/201");
    assert.equal(denied.status, 403);
    assert.equal(attack.verify(denied, "pre").verdict, "blocked");
    // 修复后阶段：被拒即回归通过
    assert.equal(attack.verify(denied, "post").verdict, "blocked");
  } finally {
    server.close();
    fixed.close();
  }
});

test("页面 200 但正文没有受害人内容（重定向到登录页形态）：判 inconclusive，不给假复现", async () => {
  const { server, url } = await listen(ssrApp({ hardened: false }));
  try {
    const ctx = makeCtx();
    const loggedIn = await loginAll(ctx, url);
    const disc = await discoverViaHtmlPages(ctx, url, loggedIn);
    const attack = buildCases(ctx, targetsFrom(disc, loggedIn)).find((c) => c.id === "attack-read-foreign");
    const anonymousView = await getAs(ctx, url, "alice", "/notes/999"); // 不存在的对象：404 页面
    assert.equal(attack.verify(anonymousView, "pre").verdict, "blocked");
    const fakeOk = { status: 200, statusText: "OK", headers: { "content-type": "text/html" }, body: page("登录", LOGIN_FORM), json: null };
    assert.equal(attack.verify(fakeOk, "pre").verdict, "inconclusive", attack.verify(fakeOk, "pre").actual);
  } finally {
    server.close();
  }
});

test("正向断言：本人页面用正文契约，删减正文即判回归", async () => {
  const { server, url } = await listen(ssrApp({ hardened: false }));
  try {
    const ctx = makeCtx();
    const loggedIn = await loginAll(ctx, url);
    const disc = await discoverViaHtmlPages(ctx, url, loggedIn);
    const cases = buildCases(ctx, targetsFrom(disc, loggedIn));
    const own = cases.find((c) => c.id === "business-read-own");
    assert.ok(own, "本人读自己的页面应构成正向断言用例");

    const before = await getAs(ctx, url, "alice", own.path);
    const contract = own.contract(before);
    assert.ok(contract.length >= 3, `应记到至少 3 个本人页面片段，实得 ${contract.length}`);
    ctx._ownerContract = new Map([[own.id, contract]]);
    assert.equal(own.verify(before).verdict, "passed");

    // 「补丁」把正文里的收件人与快递信息删掉来让越权响应看起来空 —— 本人可见内容一并消失
    const gutted = {
      ...before,
      body: page("机械键盘团购", `<h1>机械键盘团购</h1><p>单号 ${contract[0]}</p>`),
    };
    const after = own.verify(gutted);
    assert.equal(after.verdict, "regressed", after.actual);
    assert.match(after.actual, /内容契约缺失/);
  } finally {
    server.close();
  }
});

test("没有对照页面时不给越权结论：单身份场景判 inconclusive 而不是「已泄露」", async () => {
  const { server, url } = await listen(ssrApp({ hardened: false }));
  try {
    const ctx = makeCtx();
    const loggedIn = await loginAll(ctx, url);
    const disc = await discoverViaHtmlPages(ctx, url, loggedIn);
    // 只保留 bob 名下页面：alice 没有可比对的本人页面 → 归属证据没有对照组
    ctx._htmlPages.byIdentity = new Map([["bob", ctx._htmlPages.byIdentity.get("bob")]]);
    const targets = targetsFrom(disc, loggedIn);
    const attack = buildCases(ctx, targets).find((c) => c.id === "attack-read-foreign");
    const leak = await getAs(ctx, url, "alice", attack.path);
    const v = attack.verify(leak, "pre");
    assert.equal(v.verdict, "inconclusive", v.actual);
  } finally {
    server.close();
  }
});

test("修复前阶段的正向断言不等「已记录契约」：本人页面按自身正文取证即应 passed", async () => {
  const { server, url } = await listen(ssrApp({ hardened: false }));
  try {
    const ctx = makeCtx();
    const loggedIn = await loginAll(ctx, url);
    const disc = await discoverViaHtmlPages(ctx, url, loggedIn);
    const own = buildCases(ctx, targetsFrom(disc, loggedIn)).find((c) => c.id === "business-read-own");
    // pre 阶段：probe 尚未把 contract 写进 ctx._ownerContract（verify 在前、记录在后）
    const before = await getAs(ctx, url, "alice", own.path);
    const v = own.verify(before, "pre");
    assert.equal(v.verdict, "passed", v.actual);
    assert.match(v.actual, /内容契约 \d+ 项全部保留/, v.actual);
    // 记录下来的契约必须是同一批片段，post 阶段才比得准
    assert.deepEqual(own.contract(before).length > 0, true);
  } finally {
    server.close();
  }
});

test("匿名请求跳回登录页＝拒绝（不是假回归）；匿名直接拿到正文才判回归", async () => {
  const { server, url } = await listen(ssrApp({ hardened: false }));
  try {
    const ctx = makeCtx();
    const loggedIn = await loginAll(ctx, url);
    const disc = await discoverViaHtmlPages(ctx, url, loggedIn);
    const anonCase = buildCases(ctx, targetsFrom(disc, loggedIn)).find((c) => c.id === "business-unauth-401");
    assert.ok(anonCase, "无参数详情路由应构成「未登录被拒」基线用例");

    // SSR 应用形态：302 → /login，跟随跳转后是 200 的登录表单
    const loginPage = {
      status: 200,
      statusText: "OK",
      headers: { "content-type": "text/html; charset=utf-8" },
      body: page("登录", LOGIN_FORM),
      json: null,
      redirects: ["302 /login"],
    };
    const v = anonCase.verify(loginPage, "pre");
    assert.equal(v.verdict, "passed", v.actual);
    assert.match(v.actual, /登录页|认证拦截生效/, v.actual);

    // 同样的 200，但正文里就是本人的独有内容 → 认证确实被绕过，必须报回归
    const leakedOwn = await getAs(ctx, url, "alice", "/notes/101");
    const bare = { ...leakedOwn, redirects: undefined };
    const bad = anonCase.verify(bare, "pre");
    assert.equal(bad.verdict, "regressed", bad.actual);
  } finally {
    server.close();
  }
});
