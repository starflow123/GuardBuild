/**
 * Sidecar 决策层单元测试：覆盖路径正则翻译、补丁锚点定位与操作生成。
 * 运行：npm run test:sidecar
 */
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import {
  translatePathRegex,
  scoreFile,
  selectSourceFiles,
  filterSourceFiles,
  collectFileAuthGuards,
  analyzeProject,
} from "../lib/analyzer.mjs";
import { parsePortFromLine, stripAnsi } from "../lib/readyline.mjs";
import { methodStyleOps, expressStyleOps, findRecordDecisionBlock, buildProbePlan } from "../lib/planner.mjs";
import { buildLoginBody, classifyLoginFailure, extractListItems, extractEntity, buildCases } from "../lib/probe.mjs";
import { loadTargetConfig, startUsesPortSlot, renderStart, PORT_SLOT } from "../lib/targetconfig.mjs";
import { createPatch } from "../lib/patcher.mjs";

const fixturePath = fileURLToPath(new URL("../../fixtures/vibeshop/src/app.js", import.meta.url));
const fixture = readFileSync(fixturePath, "utf8");

/** 模拟 Host 的定向替换（find/replace/count） */
function applyOps(content, ops) {
  let out = content;
  for (const op of ops) {
    const idx = out.indexOf(op.find);
    assert.notEqual(idx, -1, `锚点未匹配: ${JSON.stringify(op.find.slice(0, 60))}…`);
    out = out.slice(0, idx) + op.replace + out.slice(idx + op.find.length);
  }
  return out;
}

test("translatePathRegex: 捕获组数字段翻译为 :id", () => {
  assert.equal(translatePathRegex("^\\/api\\/orders\\/(\\d+)$"), "/api/orders/:id");
  assert.equal(translatePathRegex("^\\/api\\/orders\\/(\\d+)\\/cancel$"), "/api/orders/:id/cancel");
  assert.equal(translatePathRegex("^\\/api\\/admin\\/orders\\/(\\d+)\\/cancel$"), "/api/admin/orders/:id/cancel");
});

test("translatePathRegex: 其他占位写法（转义括号 / 字符类 / 非捕获组）", () => {
  assert.equal(translatePathRegex("^\\/users\\/\\(\\d+\\)$"), "/users/:id");
  assert.equal(translatePathRegex("^\\/items\\/([0-9]+)$"), "/items/:id");
  assert.equal(translatePathRegex("^\\/files\\/([^\\/]+)$"), "/files/:id");
  assert.equal(translatePathRegex("^\\/logs\\/(?:[0-9]+)$"), "/logs/:id");
});

test("scoreFile: Windows 反斜杠路径同样享受 /src/ 加分与深度惩罚", () => {
  assert.equal(
    scoreFile("D:\\work\\proj\\src\\orders.js"),
    scoreFile("D:/work/proj/src/orders.js"),
    "两种分隔符评分应一致"
  );
  const winSrc = scoreFile("D:\\work\\proj\\src\\orders.js");
  const winPlain = scoreFile("D:\\work\\proj\\misc\\orders.js");
  assert.ok(winSrc > winPlain, `同一深度下 /src/ 加分应生效（src=${winSrc}, plain=${winPlain}）`);
});

test("scoreFile: 编译产物目录（build/dist/out）与源码同分场景下调权", () => {
  const artifact = scoreFile("D:/p/build/routes/route-01.js");
  const source = scoreFile("D:/p/routes/route-01.js");
  assert.ok(source > artifact, `源码 ${source} 应高于产物 ${artifact}`);
});

test("selectSourceFiles: 产物诱饵不挤占源码分析槽位（Windows 路径）", () => {
  const listing = [];
  for (let i = 1; i <= 30; i++) {
    listing.push({ kind: "file", path: `D:\\p\\build\\routes\\route-${String(i).padStart(2, "0")}.js`, size: 100 });
  }
  listing.push({ kind: "file", path: "D:\\p\\src\\app.js", size: 100 });
  const picked = selectSourceFiles(listing, { maxFiles: 5 });
  assert.equal(picked[0].path, "D:\\p\\src\\app.js", "源码应排第一");
  assert.ok(picked.every((f) => f.score !== undefined), "应附带评分");
});

test("parsePortFromLine: ANSI 色码人类可读就绪行（真实项目形状）", () => {
  const juiceShopLine = "info: \u001b[36mServer listening on port \u001b[1m3000\u001b[22m\u001b[39m";
  assert.equal(parsePortFromLine(juiceShopLine), 3000);
  assert.equal(parsePortFromLine("App started, listening on port 8080"), 8080);
  assert.equal(parsePortFromLine("listening on port: 4123"), 4123);
});

test("parsePortFromLine: JSON 与 host:port 形状保持兼容", () => {
  assert.equal(parsePortFromLine('GB_LISTEN {"port":4000}'), 4000);
  assert.equal(parsePortFromLine('VibeShop 已启动: http://127.0.0.1:51234'), 51234);
  assert.equal(parsePortFromLine("ready at localhost:3001"), 3001);
});

test("parsePortFromLine: 无法解析时返回 null（好过错误端口）", () => {
  assert.equal(parsePortFromLine("no numbers here"), null);
  assert.equal(parsePortFromLine(""), null);
  assert.equal(parsePortFromLine(undefined), null);
  assert.equal(parsePortFromLine("report 2026-10-14"), null);
});

test("stripAnsi: 移除色码保留文本", () => {
  assert.equal(stripAnsi("\u001b[36mhello\u001b[0m"), "hello");
});

test("findRecordDecisionBlock: 定位决策为 no-check 的调用块（而非 401 拒绝块）", () => {
  const found = findRecordDecisionBlock(fixture, "orders.get");
  assert.ok(found, "应找到 orders.get 的 recordDecision 块");
  assert.ok(found.block.includes('decision: "no-check"'), "应为 no-check 决策块");
  assert.ok(found.block.includes("查询订单后直接返回"), "应为资源获取后的那次调用");
  assert.ok(!found.block.includes("未登录，拒绝访问订单详情"), "不应误命中 401 拒绝块");
});

test("methodStyleOps: 生成归属校验补丁且不影响拒绝分支", () => {
  const candGet = {
    matchVars: ["orderDetailMatch"],
    resource: "order",
    path: "/api/orders/:id",
    routeKeys: ["orders.get"],
    file: "fixtures/vibeshop/src/app.js",
  };
  const candCancel = {
    matchVars: ["orderCancelMatch"],
    resource: "order",
    path: "/api/orders/:id/cancel",
    routeKeys: ["orders.cancel"],
    file: "fixtures/vibeshop/src/app.js",
  };

  const patched = applyOps(fixture, [...methodStyleOps(fixture, candGet), ...methodStyleOps(fixture, candCancel)]);

  assert.ok(!patched.includes('decision: "no-check"'), "补丁后不应残留 no-check 决策");
  assert.equal((patched.match(/order\.userId !== auth\.user\.id/g) ?? []).length, 2, "两个端点各注入一处归属守卫");
  assert.equal((patched.match(/"order-owner"/g) ?? []).length, 4, "拒绝与放行两条决策路径各记录一次归属检查");
  assert.ok(patched.includes('note: "未登录，拒绝访问订单详情"'), "401 拒绝块注释保持原样");
  assert.ok(patched.includes('note: "未登录，拒绝取消订单"'), "401 拒绝块注释保持原样");
  assert.ok(patched.includes("order.userId !== auth.user.id"), "注入的守卫基于对象归属比较");
});

test("methodStyleOps: 锚点缺失时诚实抛错", () => {
  assert.throws(
    () => methodStyleOps("const x = 1;\n", { matchVars: ["nopeMatch"], resource: "order", path: "/x", file: "x.js" }),
    /锚点未匹配/
  );
  assert.throws(
    () => methodStyleOps(fixture, { matchVars: [], resource: "order", path: "/x", file: "x.js" }),
    /未找到 Match 变量/
  );
});

test("methodStyleOps: CRLF 内容（Windows 检出/目标项目）同样可生成补丁并保留行尾", () => {
  const crlf = fixture.replace(/\r?\n/g, "\r\n");
  const candGet = {
    matchVars: ["orderDetailMatch"],
    resource: "order",
    path: "/api/orders/:id",
    routeKeys: ["orders.get"],
    file: "fixtures/vibeshop/src/app.js",
  };
  const candCancel = {
    matchVars: ["orderCancelMatch"],
    resource: "order",
    path: "/api/orders/:id/cancel",
    routeKeys: ["orders.cancel"],
    file: "fixtures/vibeshop/src/app.js",
  };
  const patched = applyOps(crlf, [...methodStyleOps(crlf, candGet), ...methodStyleOps(crlf, candCancel)]);
  assert.ok(!patched.includes('decision: "no-check"'), "补丁后不应残留 no-check 决策");
  assert.equal((patched.match(/order\.userId !== auth\.user\.id/g) ?? []).length, 2, "两个端点各注入一处归属守卫");
  assert.ok(!/(?<!\r)\n/.test(patched), "不应混入 LF 行尾");
});

test("expressStyleOps: CRLF 内容可生成补丁并保留行尾", () => {
  const src = [
    'app.get("/orders/:id", async (req, res) => {',
    "  const order = await Order.findById(req.params.id);",
    "  res.json(order);",
    "});",
    "",
  ].join("\r\n");
  const patched = applyOps(src, expressStyleOps(src, { resource: "order", path: "/orders/:id", file: "x.js" }));
  assert.ok(patched.includes("req.user.id"), "应注入 Express 归属校验");
  assert.ok(!/(?<!\r)\n/.test(patched), "不应混入 LF 行尾");
});

// —— Batch 2/3：身份契约 / 登录选路 / prepare ——

const fakeCtx = (content, capture = {}) => ({
  projectRoot: "D:/p",
  tokens: { project: "tok" },
  rpc: {
    request: async (method, params) => {
      capture.method = method;
      capture.params = params;
      return { content };
    },
  },
});

test("loadTargetConfig: 契约按原文读取（redact:false），密码不得被脱敏掩码", async () => {
  const capture = {};
  const raw = {
    identities: [
      { name: "a", email: "a@x.io", password: "secret1", role: "user" },
      { name: "b", email: "b@x.io", password: "secret2", role: "user" },
    ],
  };
  const res = await loadTargetConfig(fakeCtx(JSON.stringify(raw), capture));
  assert.equal(capture.params.redact, false, "契约读取必须关闭脱敏（否则 password 被掩码导致登录 401）");
  assert.equal(res.identities[0].password, "secret1");
});

test("loadTargetConfig: email 身份 + login 契约归一化（前导斜杠自动补齐、默认值）", async () => {
  const raw = {
    start: { cmd: "node", args: ["x.js"] },
    login: {
      path: "api/login",
      bodyTemplate: { email: "{email}", password: "{password}" },
      credentialPath: "authentication.token",
    },
    identities: [
      { name: "jim", email: "jim@juice.sh", password: "p1", role: "user" },
      { name: "bender", email: "bender@juice.sh", password: "p2", role: "user" },
    ],
  };
  const res = await loadTargetConfig(fakeCtx(JSON.stringify(raw)));
  assert.equal(res.source, "guardbuild.json");
  assert.equal(res.login.path, "/api/login", "应自动补前导斜杠");
  assert.equal(res.login.credentialPath, "authentication.token");
  assert.equal(res.login.credentialHeader, "Authorization");
  assert.equal(res.login.credentialPrefix, "Bearer ");
  assert.equal(res.identities[0].email, "jim@juice.sh");
  assert.equal(res.identities[0].username, null);
  assert.equal(res.prepare, null, "无 prepare 时应为 null");
});

test("loadTargetConfig: fields 自定义身份 + prepare 归一化（cwd/timeoutMs 默认值）", async () => {
  const raw = {
    prepare: [{ cmd: "npm", args: ["run", "prepare"] }, { args: ["x"] }],
    identities: [
      { fields: { login: "{username}", secret: "{password}" }, username: "a", password: "p1" },
      { fields: { login: "{username}", secret: "{password}" }, username: "b", password: "p2" },
    ],
  };
  const res = await loadTargetConfig(fakeCtx(JSON.stringify(raw)));
  assert.equal(res.identities[0].fields.login, "{username}");
  assert.equal(res.prepare.length, 1, "缺少 cmd 的步骤应被剔除");
  assert.equal(res.prepare[0].cmd, "npm");
  assert.equal(res.prepare[0].cwd, ".");
  assert.equal(res.prepare[0].timeoutMs, 120_000);
});

test("loadTargetConfig: username 形状保持向后兼容；缺失文件回落到 default", async () => {
  const raw = {
    identities: [
      { name: "alice", username: "alice", password: "a", role: "user" },
      { username: "bob", password: "b", role: "user" },
    ],
  };
  const res = await loadTargetConfig(fakeCtx(JSON.stringify(raw)));
  assert.equal(res.identities[0].username, "alice");
  assert.equal(res.identities[1].name, "bob", "缺失 name 时回落到 username");

  const missing = await loadTargetConfig({
    projectRoot: "D:/p",
    tokens: { project: "tok" },
    rpc: {
      request: async () => {
        throw new Error("404");
      },
    },
  });
  assert.equal(missing.source, "default");
  assert.equal(missing.login, null);
  assert.equal(missing.prepare, null);
});

test("buildProbePlan: 登录候选顺序 = 契约 > 分析 > /api/login；override 优先", () => {
  const analysis = {
    endpoints: [
      { method: "POST", path: "/rest/user/login" },
      { method: "GET", path: "/api/orders", hasOwnerFilter: true },
    ],
    candidates: [
      { method: "GET", path: "/api/orders/:id", resource: "order", routeKeys: ["orders.get"] },
      { method: "POST", path: "/api/orders/:id/cancel", resource: "order", routeKeys: ["orders.cancel"] },
    ],
  };
  const p1 = buildProbePlan(analysis);
  assert.equal(p1.loginPath, "/rest/user/login");
  assert.deepEqual(p1.loginCandidates, ["/rest/user/login", "/api/login"]);

  const p2 = buildProbePlan(analysis, { loginPathOverride: "/api/login" });
  assert.equal(p2.loginPath, "/api/login");
  assert.deepEqual(p2.loginCandidates, ["/api/login", "/rest/user/login"], "override 优先且去重");

  const p3 = buildProbePlan({ endpoints: [], candidates: [] });
  assert.deepEqual(p3.loginCandidates, ["/api/login"], "无分析线索时回落缺省");
});

test("buildProbePlan: 任意 :param 单体接口识别 + fullPath 优先 + 旧字段回退", () => {
  const mk = (over = {}) => ({
    method: "GET",
    path: null,
    fullPath: null,
    routeKeys: [],
    hasOwnerFilter: false,
    hasRoleGuard: false,
    ...over,
  });
  const plan = buildProbePlan({
    endpoints: [
      mk({ path: "/", fullPath: "/api/users", hasOwnerFilter: true, routeKeys: ["users.list"] }),
      mk({ method: "POST", path: "/login", fullPath: "/api/login" }),
    ],
    candidates: [mk({ path: "/:userId", fullPath: "/api/users/:userId", resource: "user", kind: "idor-suspect" })],
  });
  assert.ok(plan.readCandidate, "GET 带单个 :param（非 :id 命名）应识别为读取候选");
  assert.equal(plan.readCandidate.fullPath, "/api/users/:userId");
  assert.equal(plan.listEndpoint.path, "/api/users", "列表端点使用完整挂载路径");
  assert.equal(plan.loginPath, "/api/login");

  const legacy = buildProbePlan({
    endpoints: [mk({ path: "/api/orders", hasOwnerFilter: true })],
    candidates: [mk({ path: "/api/orders/:id" })],
  });
  assert.equal(legacy.readCandidate.path, "/api/orders/:id", "无 fullPath 时应回退声明路径");
});

test("buildCases: 条件化构建（无 cancel/admin 端点不虚构用例）+ 任意 :param 填充 + 顺序保持", () => {
  const mkCtx = (plan) => ({ plan, targetConfig: null });
  const targets = {
    attacker: { name: "alice", user: { id: 1 } },
    victim: { name: "bob", user: { id: 2 } },
    readTarget: { id: 11 },
    attackCancelTarget: { id: 12 },
    adminCancelTarget: { id: 13 },
    ownReadTarget: { id: 14 },
    ownCancelTarget: null,
    ownNotCancellable: null,
  };
  const partial = buildCases(
    mkCtx({
      readCandidate: { fullPath: "/api/users/:userId", routeKeys: ["users.get"] },
      listEndpoint: { path: "/api/users", routeKey: "users.list" },
    }),
    targets
  );
  assert.deepEqual(
    partial.map((c) => c.id),
    ["attack-read-foreign", "business-read-own", "business-list-own", "business-unauth-401"],
    "缺少 cancel/admin 端点时不应生成对应用例"
  );
  assert.equal(partial[0].path, "/api/users/11", "任意 :param 应被替换为对象 ID");

  const full = buildCases(
    mkCtx({
      readCandidate: { path: "/api/orders/:id", fullPath: "/api/orders/:id", routeKeys: ["orders.get"] },
      cancelCandidate: {
        path: "/api/orders/:id/cancel",
        fullPath: "/api/orders/:id/cancel",
        routeKeys: ["orders.cancel"],
      },
      listEndpoint: { path: "/api/orders", routeKey: "orders.list" },
      adminListEndpoint: { path: "/api/admin/orders", routeKey: "admin.orders.list" },
      adminCancelEndpoint: { path: "/api/admin/orders/:id/cancel", routeKey: "admin.orders.cancel" },
    }),
    { ...targets, ownCancelTarget: { id: 15 }, ownNotCancellable: { id: 16 } }
  );
  assert.deepEqual(
    full.map((c) => c.id),
    [
      "attack-read-foreign",
      "attack-cancel-foreign",
      "business-read-own",
      "business-list-own",
      "business-cancel-own",
      "business-shipped-guard",
      "business-admin-list",
      "business-admin-cancel",
      "business-nonadmin-denied",
      "business-unauth-401",
    ],
    "端点齐全时用例顺序与既有 e2e 基线一致"
  );
});

test("buildCases: 归属字段兼容 snake_case（user_id）与 data 包裹响应", () => {
  const ctx = {
    plan: {
      readCandidate: { fullPath: "/api/users/:userId", routeKeys: ["users.get"] },
      listEndpoint: { path: "/api/users", routeKey: "users.list" },
      resource: "user",
    },
    targetConfig: null,
  };
  const targets = {
    attacker: { name: "alice", user: { id: 7 } },
    victim: { name: "bob", user: { id: 8 } },
    readTarget: { id: 11 },
    attackCancelTarget: { id: 12 },
    adminCancelTarget: { id: 13 },
    ownReadTarget: { id: 14 },
    ownCancelTarget: null,
    ownNotCancellable: null,
  };
  const cases = buildCases(ctx, targets);
  const listCase = cases.find((c) => c.id === "business-list-own");
  assert.equal(listCase.verify({ status: 200, json: { data: [{ id: 1, user_id: 7 }] } }).verdict, "passed");
  assert.equal(
    listCase.verify({ status: 200, json: { data: [{ id: 1, user_id: 7 }, { id: 2, user_id: 8 }] } }).verdict,
    "regressed",
    "列表泄露他人资源应判定回归失败"
  );
  const ownCase = cases.find((c) => c.id === "business-read-own");
  assert.equal(ownCase.verify({ status: 200, json: { data: { id: 14, user_id: 7 } } }).verdict, "passed");
});

test("buildLoginBody: 默认 username 形状 / email 形状 / bodyTemplate / fields 优先级", () => {
  const alice = { name: "alice", username: "alice", password: "p1" };
  assert.deepEqual(buildLoginBody(alice, null), { username: "alice", password: "p1" });

  const jim = { name: "jim", email: "jim@juice.sh", password: "p2" };
  assert.deepEqual(buildLoginBody(jim, null), { email: "jim@juice.sh", password: "p2" });

  const cfg = { bodyTemplate: { email: "{email}", password: "{password}", grant_type: "password" } };
  assert.deepEqual(buildLoginBody(jim, cfg), {
    email: "jim@juice.sh",
    password: "p2",
    grant_type: "password",
  });

  const withFields = { ...jim, fields: { login: "{email}", secret: "{password}" } };
  assert.deepEqual(buildLoginBody(withFields, cfg), { login: "jim@juice.sh", secret: "p2" }, "fields 优先于 bodyTemplate");
});

test("classifyLoginFailure: 401/403 凭据问题、404/405 端点缺失、5xx 服务器错误", () => {
  const auth = classifyLoginFailure([{ path: "/api/login", status: 401 }]);
  assert.equal(auth.code, "login_rejected");
  assert.ok(auth.hint.includes("凭据") || auth.hint.includes("bodyTemplate"), "hint 指向凭据/字段形状");

  const missing = classifyLoginFailure([
    { path: "/rest/user/login", status: 404 },
    { path: "/api/login", status: 405 },
  ]);
  assert.equal(missing.code, "login_endpoint_missing");
  assert.ok(missing.hint.includes("login.path"), "hint 指向契约 login.path");

  const server = classifyLoginFailure([{ path: "/api/login", status: 500 }]);
  assert.equal(server.code, "login_server_error");
});

test("filterSourceFiles: 诊断计数包含产物目录文件（供 no_candidates hint 使用）", () => {
  const listing = [
    { kind: "file", path: "D:\\p\\build\\routes\\a.js", size: 100 },
    { kind: "file", path: "D:\\p\\src\\app.js", size: 100 },
    { kind: "file", path: "D:\\p\\README.md", size: 100 },
    { kind: "dir", path: "D:\\p\\src", size: 0 },
  ];
  assert.equal(filterSourceFiles(listing).length, 2, "仅源码扩展名文件计入候选");
});

// —— 1a：响应形状自适应（列表/单体在响应中的位置） ——

test("extractListItems: 顶层数组 / 唯一对象数组键自适应", () => {
  const items = [{ id: 1 }, { id: 2 }];
  assert.equal(extractListItems(items), items, "顶层数组直接返回");
  assert.equal(extractListItems({ orders: items }), items, "orders 键（VibeShop/旧契约形状）");
  assert.equal(extractListItems({ entries: items }), items, "entries 键（真实项目常见形状）");
  assert.equal(extractListItems({ rows: items, total: 2 }), items, "唯一对象数组键 + 标量兄弟字段");
});

test("extractListItems: 契约点路径优先且命中嵌套", () => {
  const items = [{ id: 1 }];
  assert.deepEqual(extractListItems({ data: { items }, orders: [{ id: 99 }] }, "data.items"), items,
    "契约路径命中嵌套时应优先于自适应（a 形状非唯一）");
  assert.equal(extractListItems({ data: { foo: 1 } }, "data.items"), null,
    "契约路径未命中应返回 null（暴露配置错误，而非静默回退）");
});

test("extractListItems: 多数组消歧与无列表场景", () => {
  const tagged = [{ id: 9 }];
  assert.equal(extractListItems({ meta: [1, 2, 3], rows: tagged }), tagged, "优先含 id 字段的对象数组");
  assert.deepEqual(extractListItems({ meta: [1, 2] }), [1, 2], "全为标量数组时回落首个数组");
  assert.equal(extractListItems({}), null, "无任何数组");
  assert.equal(extractListItems(null), null);
  assert.equal(extractListItems(undefined), null);
  assert.equal(extractListItems("text"), null);
});

test("extractEntity: 契约点路径 / 首个对象值字段 / 响应自身", () => {
  const order = { id: 1, userId: "u1" };
  assert.equal(extractEntity({ order }), order, "唯一对象值字段（order 键）");
  assert.equal(extractEntity({ data: { order } }, "data.order"), order, "契约点路径命中嵌套");
  assert.equal(extractEntity(order), order, "响应自身即实体时直接返回");
  assert.deepEqual(extractEntity({ status: "ok" }), { status: "ok" }, "无可提取对象时回落响应自身");
  assert.equal(extractEntity([1, 2]), null, "数组响应不成实体");
  assert.equal(extractEntity(null), null);
});

test("loadTargetConfig: responses 契约归一化（点路径 trim），缺失为 null", async () => {
  const raw = {
    responses: { list: "data.items", entity: " data.order " },
    identities: [
      { username: "a", password: "p1" },
      { username: "b", password: "p2" },
    ],
  };
  const res = await loadTargetConfig(fakeCtx(JSON.stringify(raw)));
  assert.equal(res.responses.list, "data.items");
  assert.equal(res.responses.entity, "data.order", "应 trim 两端空白");

  const none = await loadTargetConfig(fakeCtx("{}"));
  assert.equal(none.responses, null, "未声明响应形状时回落自适应");
  const bad = await loadTargetConfig(fakeCtx(JSON.stringify({ responses: { list: 42 } })));
  assert.equal(bad.responses, null, "非字符串字段应忽略（整体无效时为 null）");
});

// —— 本轮修复：中文就绪行 / ${GB_PORT} 槽位 / 挂载级鉴权 / 非 git 预检 ——

test("parsePortFromLine: 中文就绪行（运行在端口 NNNN）", () => {
  assert.equal(parsePortFromLine("服务器运行在端口 51234"), 51234);
  assert.equal(parsePortFromLine("监听端口：8080"), 8080);
  assert.equal(parsePortFromLine("端口号为 4123"), 4123);
  assert.equal(parsePortFromLine("监听端口 3000 成功"), 3000);
});

test("renderStart: ${GB_PORT} 槽位替换（args/env），未分配时保持占位符", () => {
  const start = {
    cmd: "node",
    args: ["server.js", PORT_SLOT],
    env: { PORT: PORT_SLOT, NODE_ENV: "production" },
  };
  assert.equal(startUsesPortSlot(start), true);
  const rendered = renderStart(start, 41234);
  assert.deepEqual(rendered.args, ["server.js", "41234"]);
  assert.equal(rendered.env.PORT, "41234");
  assert.equal(rendered.env.NODE_ENV, "production", "无关 env 保持不变");
  assert.equal(renderStart(start, null).env.PORT, PORT_SLOT, "未分配时保持占位符（供诊断）");

  const plain = { cmd: "node", args: ["server.js"], env: { PORT: "0" } };
  assert.equal(startUsesPortSlot(plain), false, "无槽位时不应申请端口分配");
});

test("collectFileAuthGuards: 挂载级鉴权经 require 解析到路由文件", () => {
  const files = [
    {
      path: "D:/p/app.js",
      content: [
        'const express = require("express");',
        'const geoProjectRoutes = require("./routes/geoProjects");',
        'const userRoutes = require("./routes/user");',
        'app.use("/api/geo-projects", authRequired, geoProjectRoutes);',
        'app.use("/api/users", userRoutes);',
      ].join("\n"),
    },
    { path: "D:/p/routes/geoProjects.js", content: 'router.get("/:id", h);' },
    { path: "D:/p/routes/user.js", content: 'router.get("/profile/:userId", h);' },
  ];
  const g = collectFileAuthGuards(files);
  assert.ok(g.mountGuarded.has("D:/p/routes/geoProjects.js"), "带认证中间件的挂载应标记对应路由文件");
  assert.ok(!g.mountGuarded.has("D:/p/routes/user.js"), "无鉴权中间件的挂载不应标记");
});

test("collectFileAuthGuards: router.use(authenticate) 文件级守卫 + 同文件 router 回退", () => {
  const files = [
    { path: "D:/p/routes/a.js", content: 'router.use(authenticate);\nrouter.get("/x/:id", h);' },
    {
      path: "D:/p/app2.js",
      content: 'const router = express.Router();\napp.use("/api/b", requireAuth, router);',
    },
    { path: "D:/p/misc.js", content: 'app.use("/api/pub", cors(), pubRoutes);' },
  ];
  const g = collectFileAuthGuards(files);
  assert.ok(g.selfGuarded.has("D:/p/routes/a.js"), "无路径 router.use(authenticate) 视为文件级守卫");
  assert.ok(g.selfGuarded.has("D:/p/app2.js"), "同文件定义的 router 保守视为受保护");
  assert.ok(!g.selfGuarded.has("D:/p/misc.js"), "非认证中间件（cors）不应触发");
});

test("collectFileAuthGuards: \\\\?\\ 扩展前缀路径（真实 Host 形态）下挂载解析与前缀还原", () => {
  const R = "\\\\?\\D:\\proj";
  const files = [
    {
      path: `${R}\\backend\\app.js`,
      content: [
        'const geoProjectRoutes = require("./routes/geoProjects");',
        'const captchaRoutes = require("./routes/captcha");',
        'app.use("/api/geo-projects", authRequired, geoProjectRoutes);',
        'app.use("/api/captcha", captchaRoutes);',
      ].join("\n"),
    },
    { path: `${R}\\backend\\routes\\geoProjects.js`, content: 'router.get("/:id", h);' },
    { path: `${R}\\backend\\routes\\captcha.js`, content: 'router.get("/", h);' },
  ];
  const g = collectFileAuthGuards(files);
  const geo = "//?/D:/proj/backend/routes/geoProjects.js";
  const cap = "//?/D:/proj/backend/routes/captcha.js";
  assert.ok(g.mountGuarded.has(geo), "扩展前缀路径同样应解析出挂载级鉴权");
  assert.equal(g.mountPrefixes.get(geo), "/api/geo-projects");
  assert.ok(!g.mountGuarded.has(cap), "无鉴权中间件的挂载不应标记为受保护");
  assert.equal(g.mountPrefixes.get(cap), "/api/captcha", "无鉴权挂载也应记录前缀（用于还原完整路径）");
});

test("analyzeProject: 挂载前缀还原完整请求路径（fullPath）", async () => {
  const R = "\\\\?\\D:\\proj";
  const listing = {
    entries: [
      { path: `${R}\\backend\\app.js`, kind: "file", size: 300 },
      { path: `${R}\\backend\\routes\\geoProjects.js`, kind: "file", size: 300 },
    ],
  };
  const contents = new Map([
    [
      `${R}\\backend\\app.js`,
      'const geoProjectRoutes = require("./routes/geoProjects");\napp.use("/api/geo-projects", authRequired, geoProjectRoutes);',
    ],
    [
      `${R}\\backend\\routes\\geoProjects.js`,
      [
        'router.get("/", listAll);',
        'router.get("/:id", async (req, res) => {',
        "  const item = await Project.findById(req.params.id);",
        "  res.json(item);",
        "});",
      ].join("\n"),
    ],
  ]);
  const ctx = {
    projectRoot: R,
    tokens: { project: "tok" },
    rpc: {
      request: async (method, params) => {
        if (method === "fs.list") return listing;
        if (method === "fs.read") {
          return { content: contents.get(params.path), size: 300, redacted: false, redactions: [] };
        }
        throw new Error(`不应调用 ${method}`);
      },
    },
  };
  const a = await analyzeProject(ctx);
  const detail = a.endpoints.find((e) => e.path === "/:id");
  assert.ok(detail, "应解析出 /:id 路由");
  assert.equal(detail.authSource, "mount", "挂载级鉴权应在扩展前缀路径下生效");
  assert.equal(detail.fullPath, "/api/geo-projects/:id");
  const listEp = a.endpoints.find((e) => e.path === "/");
  assert.equal(listEp.fullPath, "/api/geo-projects", "挂载根路径应折叠为无尾斜杠形态");
  assert.ok(
    a.candidates.some((c) => c.fullPath === "/api/geo-projects/:id"),
    "候选端点应携带 fullPath"
  );
});

test("analyzeProject: 列表端点归属过滤识别（camelCase filter / snake_case where）", async () => {
  const R = "\\\\?\\D:\\p";
  const content = [
    'if (method === "GET" && pathname === "/api/orders") {',
    "  const mine = store.orders.filter((o) => o.userId === auth.user.id);",
    "  return json(res, 200, { orders: mine });",
    "}",
    'if (method === "GET" && pathname === "/api/tasks") {',
    "  const list = await Task.findAll({ where: { user_id }, order: [['id', 'DESC']] });",
    "  return json(res, 200, { data: list });",
    "}",
  ].join("\n");
  const a = await analyzeProject({
    projectRoot: R,
    tokens: { project: "tok" },
    rpc: {
      request: async (method) => {
        if (method === "fs.list") return { entries: [{ path: `${R}\\src\\app.js`, kind: "file", size: 400 }] };
        if (method === "fs.read") return { content, size: 400, redacted: false, redactions: [] };
        throw new Error(`不应调用 ${method}`);
      },
    },
  });
  assert.equal(a.endpoints.find((e) => e.path === "/api/orders")?.hasOwnerFilter, true, "filter+userId 形态应识别");
  assert.equal(a.endpoints.find((e) => e.path === "/api/tasks")?.hasOwnerFilter, true, "where+user_id 形态应识别");
});

test("analyzeProject: adminRequired 命名识别为角色校验（抑制候选）", async () => {
  const R = "\\\\?\\D:\\p";
  const content = [
    'const router = express.Router();',
    "router.use(authenticate);",
    'router.put("/plans/:level", adminRequired, async (req, res) => {',
    "  const plan = await MembershipPlan.findOne({ where: { level: req.params.level } });",
    "  res.json(plan);",
    "});",
  ].join("\n");
  const a = await analyzeProject({
    projectRoot: R,
    tokens: { project: "tok" },
    rpc: {
      request: async (method) => {
        if (method === "fs.list") return { entries: [{ path: `${R}\\src\\routes.js`, kind: "file", size: 400 }] };
        if (method === "fs.read") return { content, size: 400, redacted: false, redactions: [] };
        throw new Error(`不应调用 ${method}`);
      },
    },
  });
  const ep = a.endpoints.find((e) => e.path === "/plans/:level");
  assert.ok(ep, "应解析出 /plans/:level 路由");
  assert.equal(ep.hasRoleGuard, true, "adminRequired 应识别为角色校验");
  assert.equal(a.candidates.length, 0, "带角色校验的端点不应进入候选");
});

test("createPatch: 非 git 项目预检给出可操作诊断（不尝试 worktree）", async () => {
  const calls = [];
  const ctx = {
    projectRoot: "D:/p",
    sessionId: "s1",
    tokens: { worktree: "tok_wt", project: "tok_p" },
    analysis: { candidates: [{ kind: "idor-suspect", file: "D:/p/src/app.js", method: "GET", path: "/x/:id" }] },
    emit: () => {},
    db: { insertPatch: () => {} },
    rpc: {
      request: async (method) => {
        calls.push(method);
        if (method === "git.status") return { isRepo: false, entries: [] };
        throw new Error(`不应调用 ${method}`);
      },
    },
  };
  await assert.rejects(
    () => createPatch(ctx),
    (e) => e.code === "not_a_git_repo" && /git init/.test(e.hint),
    "应归类为 not_a_git_repo 并给出 git init 指引"
  );
  assert.deepEqual(calls, ["git.status"], "预检失败时不应尝试创建 worktree");
});

test("createPatch: 无提交基线的仓库归类为 no_baseline_commit", async () => {
  const ctx = {
    projectRoot: "D:/p",
    sessionId: "s1",
    tokens: { worktree: "tok_wt", project: "tok_p" },
    analysis: { candidates: [{ kind: "idor-suspect", file: "D:/p/src/app.js", method: "GET", path: "/x/:id" }] },
    emit: () => {},
    db: { insertPatch: () => {} },
    rpc: {
      request: async (method) => {
        if (method === "git.status") return { isRepo: true, entries: [] };
        if (method === "git.worktreeAdd") {
          throw new Error("Git 仓库尚无提交（HEAD 不存在）；请先提交一次基线后再运行修复");
        }
        throw new Error(`不应调用 ${method}`);
      },
    },
  };
  await assert.rejects(
    () => createPatch(ctx),
    (e) => e.code === "no_baseline_commit" && /基线提交/.test(e.hint)
  );
});
