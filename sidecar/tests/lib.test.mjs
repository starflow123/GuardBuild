/**
 * Sidecar 决策层单元测试：覆盖路径正则翻译、补丁锚点定位与操作生成。
 * 运行：npm run test:sidecar
 */
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { translatePathRegex, scoreFile, selectSourceFiles, filterSourceFiles } from "../lib/analyzer.mjs";
import { parsePortFromLine, stripAnsi } from "../lib/readyline.mjs";
import { methodStyleOps, expressStyleOps, findRecordDecisionBlock, buildProbePlan } from "../lib/planner.mjs";
import { buildLoginBody, classifyLoginFailure } from "../lib/probe.mjs";
import { loadTargetConfig } from "../lib/targetconfig.mjs";

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
