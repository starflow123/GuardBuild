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
import {
  detectStartConfig,
  diagnoseStartFailure,
  parseProcfile,
  GENERIC_READY_PATTERN,
} from "../lib/autostart.mjs";
import { RPC_TO_HOST } from "../../shared/protocol.mjs";
import { createPatch } from "../lib/patcher.mjs";
import {
  SINK,
  OWNER_FILTER,
  findQueryParamSink,
  findSqlInjectionSignal,
  findCommandInjectionSignal,
} from "../lib/signals.mjs";

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

test("filterSourceFiles/selectSourceFiles: 虚拟环境与缓存目录不参与分析（.venv 挤占槽位）", () => {
  const listing = [];
  for (let i = 1; i <= 30; i++) {
    listing.push({
      kind: "file",
      path: `D:\\p\\.venv\\Lib\\site-packages\\fastapi\\route-${String(i).padStart(2, "0")}.py`,
      size: 100,
    });
    listing.push({
      kind: "file",
      path: `D:\\p\\__pycache__\\route-${String(i).padStart(2, "0")}.py`,
      size: 100,
    });
  }
  listing.push({ kind: "file", path: "D:\\p\\app\\api\\v1\\articles.py", size: 100 });
  assert.equal(filterSourceFiles(listing).length, 1, "只应保留真实源码");
  const picked = selectSourceFiles(listing, { maxFiles: 5 });
  assert.equal(picked.length, 1);
  assert.equal(picked[0].path, "D:\\p\\app\\api\\v1\\articles.py");
  assert.ok(
    scoreFile("D:/p/.venv/Lib/site-packages/fastapi/routing.py") <
      scoreFile("D:/p/app/api/v1/articles.py"),
    "虚拟环境评分应低于真实源码"
  );
});

test("selectSourceFiles: 大项目中路由/接口目录优先于同深度模型文件", () => {
  const listing = [];
  for (let i = 1; i <= 80; i++) {
    listing.push({ kind: "file", path: `D:/p/app/models/model-${String(i).padStart(2, "0")}.py`, size: 100 });
  }
  for (let i = 1; i <= 10; i++) {
    listing.push({ kind: "file", path: `D:/p/app/api/v1/resource-${String(i).padStart(2, "0")}.py`, size: 100 });
  }
  const picked = selectSourceFiles(listing, { maxFiles: 20 });
  const apiCount = picked.filter((f) => f.path.includes("/app/api/")).length;
  assert.equal(apiCount, 10, `路由文件应全部入选（实际 ${apiCount}/10）`);
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
      (capture.calls ??= []).push({ method, params });
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
  const contractRead = capture.calls.find(
    (c) => c.method === "fs.read" && String(c.params.path).endsWith("guardbuild.json")
  );
  assert.equal(contractRead.params.redact, false, "契约读取必须关闭脱敏（否则 password 被掩码导致登录 401）");
  assert.equal(res.identities[0].password, "secret1");
});

test("loadTargetConfig: docker 契约归一化（镜像/端口/工作目录/env/命令）", async () => {
  const raw = {
    start: { cmd: "node", args: ["server.js"] },
    docker: {
      enabled: true,
      image: "node:20-alpine",
      containerPort: 8080,
      workdir: "/srv/app",
      env: { NODE_ENV: "test", BAD_KEY: "x" },
      command: ["sh", "-c", "node server.js"],
      readyTimeoutMs: 90000,
    },
  };
  const res = await loadTargetConfig(fakeCtx(JSON.stringify(raw)));
  assert.equal(res.docker.enabled, true);
  assert.equal(res.docker.image, "node:20-alpine");
  assert.equal(res.docker.containerPort, 8080);
  assert.equal(res.docker.workdir, "/srv/app");
  assert.equal(res.docker.env.NODE_ENV, "test");
  assert.equal(res.docker.env.BAD_KEY, "x");
  assert.deepEqual(res.docker.command, ["sh", "-c", "node server.js"]);
  assert.equal(res.docker.readyTimeoutMs, 90000);
  assert.equal(res.docker.invalid, null);
});

test("loadTargetConfig: docker 启用但镜像缺失 → 标记 invalid（启动时显式失败，不回退宿主机）", async () => {
  const res = await loadTargetConfig(fakeCtx(JSON.stringify({ docker: { enabled: true } })));
  assert.equal(res.docker.enabled, true);
  assert.ok(res.docker.invalid && res.docker.invalid.includes("docker.image"), res.docker.invalid);

  const badPath = await loadTargetConfig(
    fakeCtx(JSON.stringify({ docker: { enabled: true, image: "alpine", workdir: "/app/../etc" } }))
  );
  assert.ok(badPath.docker.invalid && badPath.docker.invalid.includes("docker.workdir"), badPath.docker.invalid);

  const badEnv = await loadTargetConfig(
    fakeCtx(JSON.stringify({ docker: { enabled: true, image: "alpine", env: { "bad-key": "x" } } }))
  );
  assert.ok(badEnv.docker.invalid && badEnv.docker.invalid.includes("docker.env"), badEnv.docker.invalid);
});

test("loadTargetConfig: docker 未启用时不产生副作用配置", async () => {
  const res = await loadTargetConfig(fakeCtx(JSON.stringify({ docker: { image: 42 } })));
  assert.equal(res.docker.enabled, false);
  assert.equal(res.docker.image, null);
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
    candidates: [mk({ path: "/api/orders/:id", kind: "idor-suspect" })],
  });
  assert.equal(legacy.readCandidate.path, "/api/orders/:id", "无 fullPath 时应回退声明路径");
});

test("buildProbePlan: 无鉴权候选入独立槽位，且不占用 IDOR 槽位", () => {
  const mk = (over = {}) => ({ method: "GET", path: null, fullPath: null, routeKeys: [], ...over });
  const both = buildProbePlan({
    endpoints: [],
    candidates: [
      mk({ path: "/:id", fullPath: "/api/orders/:id", resource: "order", kind: "idor-suspect" }),
      mk({ path: "/:id", fullPath: "/api/feeds/:id", resource: "feed", kind: "no-auth-suspect" }),
    ],
  });
  assert.equal(both.readCandidate.fullPath, "/api/orders/:id", "IDOR 候选进 readCandidate 槽位");
  assert.equal(both.unauthReadCandidate.fullPath, "/api/feeds/:id", "无鉴权候选进独立槽位");

  const onlyNoAuth = buildProbePlan({
    endpoints: [],
    candidates: [mk({ path: "/:id", fullPath: "/api/feeds/:id", resource: "feed", kind: "no-auth-suspect" })],
  });
  assert.equal(onlyNoAuth.readCandidate, null, "无鉴权候选不得占用 IDOR 槽位（不做自动修复）");
  assert.ok(onlyNoAuth.unauthReadCandidate, "仅无鉴权候选时仍可构建读取计划");
  assert.equal(onlyNoAuth.unauthReadCandidate.resource, "feed");
});

test("buildProbePlan: 每类候选取 top-K（去重）+ 单槽位为首元素（N-5）", () => {
  const mk = (over = {}) => ({ method: "GET", path: null, fullPath: null, routeKeys: [], ...over });
  const plan = buildProbePlan({
    endpoints: [],
    candidates: [
      mk({ fullPath: "/api/a/:id", resource: "a", kind: "no-auth-suspect" }),
      mk({ fullPath: "/api/a/:id", resource: "a", kind: "no-auth-suspect" }), // 重复 method+path 应去重
      mk({ fullPath: "/api/b/:id", resource: "b", kind: "no-auth-suspect" }),
      mk({ fullPath: "/api/c/:id", resource: "c", kind: "no-auth-suspect" }),
      mk({ fullPath: "/api/d/:id", resource: "d", kind: "no-auth-suspect" }), // 超出 top-3 应被截断
      mk({ fullPath: "/api/orders/:id", resource: "order", kind: "idor-suspect" }),
      mk({ method: "POST", fullPath: "/api/orders/:id/cancel", resource: "order", kind: "idor-suspect" }),
    ],
  });
  assert.deepEqual(
    plan.unauthReadCandidates.map((c) => c.fullPath),
    ["/api/a/:id", "/api/b/:id", "/api/c/:id"],
    "无鉴权候选应去重并截断到 top-3"
  );
  assert.equal(plan.unauthReadCandidate, plan.unauthReadCandidates[0], "单槽位应为首元素（兼容消费方）");
  assert.deepEqual(plan.readCandidates.map((c) => c.fullPath), ["/api/orders/:id"]);
  assert.deepEqual(plan.cancelCandidates.map((c) => c.fullPath), ["/api/orders/:id/cancel"]);
  assert.deepEqual(plan.readCandidates, [plan.readCandidate]);
  assert.deepEqual(plan.cancelCandidates, [plan.cancelCandidate]);
});

test("buildProbePlan: 路径穿越候选入独立槽位（去重 + 首元素 + resource 回退）", () => {
  const mk = (over = {}) => ({ method: "GET", path: null, fullPath: null, routeKeys: [], ...over });
  const plan = buildProbePlan({
    endpoints: [],
    candidates: [
      mk({ fullPath: "/v1/beer-pic/", resource: "picture", kind: "traversal-suspect" }),
      mk({ fullPath: "/v1/beer-pic/", resource: "picture", kind: "traversal-suspect" }), // 重复 method+path 应去重
      mk({ fullPath: "/v1/files/:filename", resource: "file", kind: "traversal-suspect" }),
    ],
  });
  assert.deepEqual(
    plan.traversalCandidates.map((c) => c.fullPath),
    ["/v1/beer-pic/", "/v1/files/:filename"],
    "穿越候选应去重（同 method+path 仅留一份）"
  );
  assert.equal(plan.traversalCandidate, plan.traversalCandidates[0], "单槽位应为首元素");
  assert.equal(plan.resource, "picture", "无其它候选时 resource 回退到穿越候选");
  assert.equal(plan.readCandidate, null, "穿越候选不得占用 IDOR 槽位");
});

test("buildProbePlan: 查询参数形态候选（无 :param）进 read 槽位（DVNA 修复）", () => {
  const plan = buildProbePlan({
    endpoints: [],
    candidates: [
      {
        kind: "idor-suspect",
        method: "GET",
        path: "/modifyproduct",
        fullPath: "/app/modifyproduct",
        routeKeys: ["app.modifyproduct"],
        resource: "product",
        queryParam: { param: "id", form: "direct" },
      },
    ],
  });
  assert.ok(plan.readCandidate, "无路径参数但带 queryParam 的候选应进入 read 槽位");
  assert.equal(plan.readCandidate.fullPath, "/app/modifyproduct");
  assert.equal(plan.resource, "product");
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
    { ...targets, admin: { name: "admin", role: "admin", user: { id: 3 } }, ownCancelTarget: { id: 15 }, ownNotCancellable: { id: 16 } }
  );
  assert.deepEqual(
    full.map((c) => c.id),
    [
      "attack-read-foreign",
      "attack-cancel-foreign",
      "attack-vertical-escalation",
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

test("buildCases: 身份/目标缺失时跳过对应槽位（不虚构、不崩溃）", () => {
  const ctx = {
    plan: {
      resource: "order",
      readCandidate: { path: "/api/orders/:id", fullPath: "/api/orders/:id", routeKeys: ["orders.get"] },
      cancelCandidate: {
        path: "/api/orders/:id/cancel",
        fullPath: "/api/orders/:id/cancel",
        routeKeys: ["orders.cancel"],
      },
      unauthReadCandidate: { fullPath: "/api/feeds/:id", routeKeys: ["feeds.get"] },
      listEndpoint: { path: "/api/orders", routeKey: "orders.list" },
      adminListEndpoint: { path: "/api/admin/orders", routeKey: "admin.orders.list" },
      adminCancelEndpoint: { path: "/api/admin/orders/:id/cancel", routeKey: "admin.orders.cancel" },
    },
    targetConfig: null,
  };
  // 仅一名普通用户：归属类攻击/管理员用例应跳过，本人业务用例保留
  const onlyAttacker = buildCases(ctx, {
    attacker: { name: "alice", user: { id: 1 } },
    victim: null,
    admin: null,
    readTarget: null,
    attackCancelTarget: null,
    adminCancelTarget: null,
    ownReadTarget: { id: 14 },
    ownCancelTarget: null,
    ownNotCancellable: null,
  });
  assert.deepEqual(
    onlyAttacker.map((c) => c.id),
    ["business-read-own", "business-list-own", "business-unauth-401"],
    "缺 victim/admin 时不应生成越权攻击与管理员用例"
  );
  // 匿名回退路径：readTarget 来自匿名探测（无归属），仅匿名攻击用例可构建
  const anonOnly = buildCases(ctx, {
    attacker: { name: "alice", user: { id: 1 } },
    victim: null,
    admin: null,
    readTarget: { id: 11 },
    attackCancelTarget: null,
    adminCancelTarget: null,
    ownReadTarget: null,
    ownCancelTarget: null,
    ownNotCancellable: null,
  });
  assert.deepEqual(
    anonOnly.map((c) => c.id),
    ["attack-anonymous-read", "business-list-own"],
    "匿名探测目标只服务匿名越权用例（越权读需 victim）"
  );
  assert.equal(anonOnly[0].path, "/api/feeds/11", "匿名用例 :param 应填充匿名探测到的对象 ID");
});

test("buildCases: 查询参数形态攻击用例路径为 ?param=id（无 :param 占位）", () => {
  const cand = {
    path: "/modifyproduct",
    fullPath: "/app/modifyproduct",
    routeKeys: ["app.modifyproduct"],
    queryParam: { param: "id", form: "direct" },
  };
  const ctx = { plan: { readCandidate: cand, readCandidates: [cand] }, targetConfig: null };
  const cases = buildCases(ctx, {
    attacker: { name: "alice", user: { id: 1 } },
    victim: { name: "bob", user: { id: 2 } },
    admin: null,
    readTarget: { id: 11 },
    attackCancelTarget: null,
    adminCancelTarget: null,
    ownReadTarget: { id: 14 },
    ownCancelTarget: null,
    ownNotCancellable: null,
  });
  const attack = cases.find((c) => c.id === "attack-read-foreign");
  assert.equal(attack.path, "/app/modifyproduct?id=11", "查询参数候选应构造 ?param=id 形态");
  const own = cases.find((c) => c.id === "business-read-own");
  assert.equal(own.path, "/app/modifyproduct?id=14", "本人业务用例同样使用查询参数形态");
});

test("buildCases: 多候选逐一构建攻击用例（基名 + -2 后缀，N-5）", () => {
  const ctx = {
    plan: {
      resource: "order",
      readCandidates: [
        { fullPath: "/api/orders/:id", routeKeys: ["orders.get"] },
        { fullPath: "/api/invoices/:id", routeKeys: ["invoices.get"] },
      ],
      unauthReadCandidates: [
        { fullPath: "/api/feeds/:id", routeKeys: ["feeds.get"] },
        { fullPath: "/api/loves/:id", routeKeys: ["loves.get"] },
      ],
      listEndpoint: { path: "/api/orders", routeKey: "orders.list" },
    },
    targetConfig: null,
  };
  const targets = {
    attacker: { name: "alice", user: { id: 1 } },
    victim: { name: "bob", user: { id: 2 } },
    admin: null,
    readTarget: { id: 11 },
    attackCancelTarget: null,
    adminCancelTarget: null,
    ownReadTarget: { id: 14 },
    ownCancelTarget: null,
    ownNotCancellable: null,
    anonTargets: [
      { path: "/api/feeds/:id", item: { id: 21 } },
      { path: "/api/loves/:id", item: { id: 31 } },
    ],
  };
  const cases = buildCases(ctx, targets);
  assert.deepEqual(
    cases.filter((c) => c.category === "attack").map((c) => c.id),
    ["attack-read-foreign", "attack-read-foreign-2", "attack-anonymous-read", "attack-anonymous-read-2"],
    "每类候选按序构建，首候选保持基名"
  );
  const read2 = cases.find((c) => c.id === "attack-read-foreign-2");
  assert.equal(read2.path, "/api/invoices/11", "第二读取候选应使用自身端点路径");
  const anon2 = cases.find((c) => c.id === "attack-anonymous-read-2");
  assert.equal(anon2.path, "/api/loves/31", "第二匿名候选应使用该路径匿名探测到的对象 ID");
  assert.equal(anon2.routeKey, "loves.get");
  assert.equal(
    anon2.verify({ status: 200, json: { id: 31, userId: 3 } }, "pre").verdict,
    "vulnerable",
    "多候选的判定语义与单候选一致"
  );
});

test("buildCases: 路径穿越用例构建（query/params 形态 + 泄露证据判定）", () => {
  const ctx = {
    plan: {
      resource: "resource",
      traversalCandidates: [
        { fullPath: "/v1/beer-pic/", traversal: { source: "query", param: "picture", sink: "readFile" } },
        { fullPath: "/v1/files/:filename", traversal: { source: "params", param: "filename", sink: "readFile" } },
      ],
    },
    targetConfig: null,
  };
  const targets = {
    attacker: { name: "alice", user: { id: 1 } },
    victim: { name: "bob", user: { id: 2 } },
    readTarget: null,
    attackCancelTarget: null,
    adminCancelTarget: null,
    ownReadTarget: null,
    ownCancelTarget: null,
    ownNotCancellable: null,
  };
  const cases = buildCases(ctx, targets);
  assert.deepEqual(
    cases.map((c) => c.id),
    ["attack-path-traversal", "attack-path-traversal-2"],
    "逐候选构建穿越用例（基名 + -2 后缀），且不虚构其它类别"
  );
  const q = cases[0];
  assert.equal(q.path, "/v1/beer-pic/?picture=../package.json", "query 形态应追加 payload 参数");
  assert.equal(q.identity, "bob", "穿越用例携带 victim 身份（兼容需登录端点）");
  assert.equal(typeof q.send, "function", "穿越用例自带多 payload 发送器");
  const leakedBody = '{"name":"vuln-node-js","version":"1.0.0","dependencies":{}}';
  const hitRes = {
    status: 200,
    body: leakedBody,
    _traversalProof: { localName: "vuln-node-js", matched: true, attemptPath: "/v1/beer-pic/?picture=../package.json" },
  };
  assert.equal(q.verify(hitRes, "pre").verdict, "vulnerable", "回读到 package.json 特征应判定可利用");
  assert.ok(q.crossProof(hitRes), "本机项目名一致时应给出内容交叉证明");
  const missRes = {
    status: 200,
    body: "error",
    _traversalProof: { localName: "vuln-node-js", matched: false, attemptPath: "/v1/beer-pic/?picture=../../../package.json" },
  };
  assert.equal(q.verify(missRes, "pre").verdict, "inconclusive", "2xx 但无泄露证据不得判定可利用");
  assert.equal(q.crossProof(missRes), null, "未命中时不应给出交叉证明");
  assert.equal(cases[1].path, "/v1/files/../package.json", "params 形态应以 payload 替换路径段");
});

test("buildCases: 垂直越权（victim 身份访问 admin 列表）与匿名读取用例的判定语义", () => {
  const ctx = {
    plan: {
      resource: "order",
      readCandidate: { fullPath: "/api/orders/:id", routeKeys: ["orders.get"] },
      unauthReadCandidate: { fullPath: "/api/feeds/:id", routeKeys: ["feeds.get"] },
      listEndpoint: { path: "/api/orders", routeKey: "orders.list" },
      adminListEndpoint: { path: "/api/admin/orders", routeKey: "admin.orders.list" },
    },
    targetConfig: null,
  };
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
  const cases = buildCases(ctx, targets);
  const ids = cases.map((c) => c.id);
  assert.ok(ids.includes("attack-vertical-escalation"), "应有纵向越权攻击用例");
  assert.ok(ids.includes("attack-anonymous-read"), "应有匿名读取攻击用例");

  const vert = cases.find((c) => c.id === "attack-vertical-escalation");
  assert.equal(vert.identity, "bob", "纵向越权以普通用户（victim）身份发起");
  assert.equal(vert.path, "/api/admin/orders");
  assert.equal(
    vert.verify({ status: 200, json: { orders: [{ id: 1, userId: 2 }, { id: 2, userId: 1 }] } }, "pre").verdict,
    "vulnerable",
    "普通用户拿到管理端数据应判定可利用"
  );
  assert.equal(vert.verify({ status: 403, json: {} }, "post").verdict, "blocked", "修复后 403 应判定攻击被阻断");

  const anon = cases.find((c) => c.id === "attack-anonymous-read");
  assert.equal(anon.identity, null, "匿名用例不携带任何身份");
  assert.equal(anon.path, "/api/feeds/11", ":param 应填充目标对象 ID");
  assert.equal(
    anon.verify({ status: 200, json: { id: 11, userId: 2 } }, "pre").verdict,
    "vulnerable",
    "未携带凭证拿到对象应判定可利用"
  );
  assert.equal(anon.verify({ status: 401, json: {} }, "post").verdict, "blocked", "修复后 401 应判定攻击被阻断");
  assert.ok(anon.crossProof({ status: 200, json: { id: 11, userId: 2 } }), "匿名响应归属应与请求目标一致");
});

test("N-7: 攻击用例 2xx 但无泄露证据时不得判定可利用（语义拒绝防误报）", () => {
  const ctx = {
    plan: {
      resource: "order",
      adminListEndpoint: { path: "/api/admin/orders", routeKey: "admin.orders.list" },
      unauthReadCandidate: { fullPath: "/api/feeds/:id", routeKeys: ["feeds.get"] },
    },
    targetConfig: null,
  };
  const targets = {
    attacker: { name: "alice", user: { id: 1 } },
    victim: { name: "bob", user: { id: 2 } },
    readTarget: { id: 11 },
    attackCancelTarget: null,
    adminCancelTarget: null,
    ownReadTarget: null,
    ownCancelTarget: null,
    ownNotCancellable: null,
  };
  const cases = buildCases(ctx, targets);

  const vert = cases.find((c) => c.id === "attack-vertical-escalation");
  const denied = vert.verify({ status: 200, json: { error: "Not Admin" } }, "pre");
  assert.equal(denied.verdict, "inconclusive", "200+错误体属语义拒绝，不得当作漏洞复现");
  assert.match(denied.actual, /语义拒绝/);
  assert.equal(
    vert.verify({ status: 200, json: { error: "Not Admin" } }, "post").verdict,
    "inconclusive",
    "修复后 200+错误体同样不得误判为回归失败"
  );

  const anon = cases.find((c) => c.id === "attack-anonymous-read");
  assert.equal(
    anon.verify({ status: 200, json: { error: "Not Found" } }, "pre").verdict,
    "inconclusive",
    "匿名端点 200+错误体按语义拒绝处理"
  );
  assert.equal(
    anon.verify({ status: 200, json: { id: 11, userId: 2 } }, "pre").verdict,
    "vulnerable",
    "响应含目标对象时仍判定可利用（正当路径不受影响）"
  );
});

test("N-7b: 管理端业务用例容忍语义拒绝 + user 资源列表以自身 id 为归属", () => {
  const ctx = {
    plan: {
      resource: "user",
      adminListEndpoint: { path: "/v1/admin/users", routeKey: "admin.users.list" },
    },
    targetConfig: null,
  };
  const targets = {
    attacker: { name: "alice", user: { id: 1 } },
    victim: { name: "bob", user: { id: 2 } },
    admin: { name: "amit", role: "admin", user: { id: 3 } },
    readTarget: null,
    attackCancelTarget: null,
    adminCancelTarget: null,
    ownReadTarget: null,
    ownCancelTarget: null,
    ownNotCancellable: null,
  };
  const cases = buildCases(ctx, targets);

  const denied = cases.find((c) => c.id === "business-nonadmin-denied");
  assert.equal(
    denied.verify({ status: 200, json: { error: "Not Admin, try again" } }).verdict,
    "passed",
    "200+错误体属语义拒绝，普通用户未拿到管理端数据"
  );
  assert.equal(
    denied.verify({ status: 200, json: [{ id: 1, email: "x@y.z" }] }).verdict,
    "regressed",
    "真的拿到列表仍应判业务回归"
  );
  assert.equal(denied.verify({ status: 403, json: {} }).verdict, "passed");

  const adminList = cases.find((c) => c.id === "business-admin-list");
  assert.equal(
    adminList.verify({ status: 200, json: [{ id: 1 }, { id: 2 }] }).verdict,
    "passed",
    "user 资源列表无归属字段时以自身 id 计归属，多行即多归属"
  );
  assert.equal(
    adminList.verify({ status: 200, json: [{ id: 1 }] }).verdict,
    "regressed",
    "仅一行时仍应判覆盖不足"
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

test("analyzeProject: 无鉴权端点识别为 no-auth-suspect（登录路径/无参查询被抑制）", async () => {
  const R = "\\\\?\\D:\\p";
  const content = [
    'const app = require("express")();',
    'app.get("/api/posts/:id", async (req, res) => {',
    "  const post = await Post.findById(req.params.id);",
    "  res.json(post);",
    "});",
    'app.get("/api/settings/notice", async (req, res) => {',
    "  const row = await Setting.findOne({ where: { key: 'system_notice' } });",
    "  res.json({ data: row });",
    "});",
    'app.post("/api/users/login", async (req, res) => {',
    "  const user = await User.findOne({ where: { username: req.body.username } });",
    "  res.json({ token: 'x' });",
    "});",
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
  const post = a.candidates.find((c) => c.fullPath === "/api/posts/:id");
  assert.ok(post, "无鉴权却按路径 ID 取资源的端点应入候选");
  assert.equal(post.kind, "no-auth-suspect");
  assert.equal(post.hasAuth, false);
  assert.ok(
    !a.candidates.some((c) => (c.fullPath ?? c.path ?? "").includes("login")),
    "登录路径属预期公开端点，不应成为越权候选"
  );
  assert.ok(
    !a.candidates.some((c) => (c.fullPath ?? c.path ?? "").includes("/settings/notice")),
    "无路径参数的固定键查询（公共配置读取）不应成为越权候选"
  );
});

test("analyzeProject: 路径穿越线索识别（fs 读取 + req 输入合流，固定路径不误报）", async () => {
  const R = "\\\\?\\D:\\p";
  const content = [
    'const app = require("express")();',
    'const fs = require("fs");',
    'const path = require("path");',
    'app.get("/v1/beer-pic/", (req, res) => {',
    "  var filename = req.query.picture,",
    "  filePath = `../../../uploads/${filename}`;",
    "  fs.readFile(path.join(__dirname, filePath), function (err, data) {",
    '    if (err) return res.send("error");',
    "    res.send(data);",
    "  });",
    "});",
    'app.get("/api/avatar", (req, res) => {',
    "  fs.readFile(path.join(__dirname, 'public', 'avatar.jpg'), (err, data) => res.send(data));",
    "});",
  ].join("\n");
  const a = await analyzeProject({
    projectRoot: R,
    tokens: { project: "tok" },
    rpc: {
      request: async (method) => {
        if (method === "fs.list") return { entries: [{ path: `${R}\\src\\app.js`, kind: "file", size: 800 }] };
        if (method === "fs.read") return { content, size: 800, redacted: false, redactions: [] };
        throw new Error(`不应调用 ${method}`);
      },
    },
  });
  const trav = a.candidates.find((c) => c.kind === "traversal-suspect");
  assert.ok(trav, "文件读取 sink 的相邻语句链含请求输入时应入穿越候选");
  assert.equal(trav.fullPath, "/v1/beer-pic/");
  assert.deepEqual(trav.traversal, { source: "query", param: "picture", sink: "readFile" });
  assert.ok(
    !a.candidates.some((c) => (c.fullPath ?? c.path ?? "").includes("/api/avatar")),
    "固定路径的文件读取不应误报为穿越候选"
  );
});

test("analyzeProject: 查询参数 IDOR（req.query 直引 / 变量中转两种形态）", async () => {
  const R = "\\\\?\\D:\\p";
  const content = [
    'const router = require("express").Router();',
    'router.get("/modifyproduct", authHandler.isAuthenticated, async (req, res) => {',
    "  const product = await db.Product.find({ where: { 'id': req.query.id } });",
    "  res.json(product);",
    "});",
    'router.get("/userinfo", authHandler.isAuthenticated, async (req, res) => {',
    "  const uid = req.query.userId;",
    "  const user = await User.findOne({ where: { id: uid } });",
    "  res.json(user);",
    "});",
  ].join("\n");
  const a = await analyzeProject({
    projectRoot: R,
    tokens: { project: "tok" },
    rpc: {
      request: async (method) => {
        if (method === "fs.list") return { entries: [{ path: `${R}\\src\\app.js`, kind: "file", size: 900 }] };
        if (method === "fs.read") return { content, size: 900, redacted: false, redactions: [] };
        throw new Error(`不应调用 ${method}`);
      },
    },
  });
  const c1 = a.candidates.find((c) => c.path === "/modifyproduct");
  assert.ok(c1, "查询参数取数的受保护路由应入 IDOR 候选");
  assert.equal(c1.kind, "idor-suspect");
  assert.deepEqual(c1.queryParam, { param: "id", form: "direct" });
  assert.equal(c1.resource, "product", "资源名应从 Model.find 形态推断");
  const c2 = a.candidates.find((c) => c.path === "/userinfo");
  assert.ok(c2, "变量中转的查询参数形态同样应入候选");
  assert.deepEqual(c2.queryParam, { param: "userId", form: "indirect" });
  assert.equal(c2.resource, "user", "资源名应从查询参数名推断");
});

test("signals: SINK 覆盖 Prisma/TypeORM 单查变体（findMany 列表查询不误报）", () => {
  assert.ok(SINK.test("await prisma.order.findUniqueOrThrow({ where: { id } })"), "findUniqueOrThrow");
  assert.ok(SINK.test("await db.order.findFirst({ where: { id } })"), "findFirst");
  assert.ok(SINK.test("await repo.findOneBy({ id })"), "findOneBy");
  assert.ok(SINK.test("await repo.findOneOrFail({ where: { id } })"), "findOneOrFail");
  assert.ok(SINK.test("await orderRepo.findByIdOrThrow(id)"), "findByIdOrThrow");
  assert.ok(
    !SINK.test("const list = await db.order.findMany({ where: { userId } });"),
    "findMany 为列表查询，不应识别为单查 sink"
  );
});

test("signals: findQueryParamSink 覆盖 Drizzle 链式形态（直引 / and 组合 / 变量中转）", () => {
  const direct = "const order = await db.select().from(orders).where(eq(orders.id, req.query.id));";
  assert.deepEqual(findQueryParamSink(direct), { param: "id", form: "direct" });

  const combined = [
    "const rows = await db.select().from(orders)",
    "  .where(and(eq(orders.userId, req.user.id), eq(orders.id, req.query.orderId)));",
  ].join("\n");
  assert.deepEqual(findQueryParamSink(combined), { param: "orderId", form: "direct" }, "and() 组合内任意位置的查询参数");

  const indirect = [
    "const orderId = req.query.orderId;",
    "const rows = await db.select().from(orders).where(eq(orders.id, orderId));",
  ].join("\n");
  assert.deepEqual(findQueryParamSink(indirect), { param: "orderId", form: "indirect" });
});

test("signals: OWNER_FILTER 覆盖 Drizzle/Supabase 归约形态", () => {
  assert.ok(OWNER_FILTER.test("where(and(eq(orders.userId, req.user.id), eq(orders.id, id)))"), "eq(表.userId,…)");
  assert.ok(OWNER_FILTER.test('.eq("user_id", auth.user.id)'), 'supabase .eq("user_id",…)');
  assert.ok(OWNER_FILTER.test(".eq('userId', uid)"), "supabase .eq('userId',…)");
  assert.ok(!OWNER_FILTER.test("where(eq(orders.id, orderId))"), "仅按对象 id 的查询不是归属过滤");
});

test("analyzeProject: Prisma/TypeORM 单查变体入 IDOR 候选", async () => {
  const R = "\\\\?\\D:\\p";
  const content = [
    'const express = require("express");',
    "const router = express.Router();",
    "router.use(authenticate);",
    'router.get("/api/invoices/:id", async (req, res) => {',
    "  const invoice = await prisma.invoice.findUniqueOrThrow({ where: { id: Number(req.params.id) } });",
    "  res.json({ invoice });",
    "});",
    'router.get("/api/reports/:id", async (req, res) => {',
    "  const report = await db.report.findFirst({ where: { id: Number(req.params.id) } });",
    "  res.json({ report });",
    "});",
    'router.get("/api/teams/:id", async (req, res) => {',
    "  const team = await teamRepo.findOneOrFail({ where: { id: req.params.id } });",
    "  res.json({ team });",
    "});",
  ].join("\n");
  const a = await analyzeProject({
    projectRoot: R,
    tokens: { project: "tok" },
    rpc: {
      request: async (method) => {
        if (method === "fs.list") return { entries: [{ path: `${R}\\src\\app.js`, kind: "file", size: 600 }] };
        if (method === "fs.read") return { content, size: 600, redacted: false, redactions: [] };
        throw new Error(`不应调用 ${method}`);
      },
    },
  });
  const inv = a.candidates.find((c) => c.path === "/api/invoices/:id");
  assert.ok(inv, "findUniqueOrThrow 形态应入候选");
  assert.equal(inv.kind, "idor-suspect");
  assert.equal(inv.resource, "invoice");
  assert.equal(inv.hasAuth, true, "router.use(authenticate) 应计为认证");
  const rep = a.candidates.find((c) => c.path === "/api/reports/:id");
  assert.ok(rep, "findFirst 形态应入候选");
  assert.equal(rep.resource, "report");
  const team = a.candidates.find((c) => c.path === "/api/teams/:id");
  assert.ok(team, "findOneOrFail 形态应入候选");
  assert.equal(team.resource, "team", "teamRepo 应剥去 Repo 后缀");
});

test("analyzeProject: Drizzle 链式取数（路径参数 / 查询参数 / 列表形态抑制）", async () => {
  const R = "\\\\?\\D:\\p";
  const content = [
    'const express = require("express");',
    'const { eq } = require("drizzle-orm");',
    'const { db, ordersTable } = require("./db");',
    "const router = express.Router();",
    "router.use(authenticate);",
    'router.get("/api/orders/:id", async (req, res) => {',
    "  const rows = await db.select().from(ordersTable).where(eq(ordersTable.id, Number(req.params.id)));",
    "  res.json({ order: rows[0] ?? null });",
    "});",
    'router.get("/api/order-lookup", async (req, res) => {',
    "  const rows = await db.select().from(ordersTable).where(eq(ordersTable.id, req.query.orderId));",
    "  res.json({ order: rows[0] ?? null });",
    "});",
    'router.get("/api/my-orders", async (req, res) => {',
    "  const recent = await db.select().from(ordersTable).where(eq(ordersTable.userId, req.user.id));",
    "  res.json({ orders: recent });",
    "});",
  ].join("\n");
  const a = await analyzeProject({
    projectRoot: R,
    tokens: { project: "tok" },
    rpc: {
      request: async (method) => {
        if (method === "fs.list") return { entries: [{ path: `${R}\\src\\app.js`, kind: "file", size: 800 }] };
        if (method === "fs.read") return { content, size: 800, redacted: false, redactions: [] };
        throw new Error(`不应调用 ${method}`);
      },
    },
  });
  const detail = a.candidates.find((c) => c.path === "/api/orders/:id");
  assert.ok(detail, "Drizzle 链式取数应识别为单查 sink");
  assert.equal(detail.kind, "idor-suspect");
  assert.equal(detail.resource, "order", "资源名应从 .from(ordersTable) 推断（剥 Table 后缀）");

  const lookup = a.candidates.find((c) => c.path === "/api/order-lookup");
  assert.ok(lookup, "Drizzle 查询参数形态应入 IDOR 候选");
  assert.deepEqual(lookup.queryParam, { param: "orderId", form: "direct" });

  assert.equal(
    a.endpoints.find((e) => e.path === "/api/my-orders")?.hasOwnerFilter,
    true,
    "eq(表.userId, …) 应识别为归属过滤"
  );
  assert.ok(
    !a.candidates.some((c) => c.path === "/api/my-orders"),
    "列表形态（归属过滤 + 无对象引用参数）不应成为候选"
  );

  const plan = buildProbePlan(a);
  assert.equal(plan.readCandidate?.path, "/api/orders/:id");
  assert.equal(plan.listEndpoint?.path, "/api/my-orders");
  assert.equal(plan.resource, "order");
});

test("analyzeProject: 裸 SQL helper 取数（dbGet/db.get/pool.query/prepare().get）", async () => {
  const R = "\\\\?\\D:\\p";
  const publicSrc = [
    'const express = require("express");',
    'const router = express.Router();',
    "function dbGet(sql, params) { return db.get(sql, params); }",
    'router.get("/api/user/:id", async (req, res) => {',
    "  const user = await dbGet('SELECT id, username, email FROM users WHERE id = ?', [req.params.id]);",
    "  res.json(user);",
    "});",
  ].join("\n");
  const authedSrc = [
    'const express = require("express");',
    'const router = express.Router();',
    "router.use(authenticate);",
    'router.get("/api/invoices/:id", async (req, res) => {',
    "  const [rows] = await pool.query('SELECT * FROM invoices WHERE id = ?', [req.params.id]);",
    "  res.json(rows[0] ?? null);",
    "});",
    'router.get("/api/notes/:id", async (req, res) => {',
    "  const note = db.prepare('SELECT * FROM notes WHERE id = ?').get(req.params.id);",
    "  res.json(note);",
    "});",
    'router.get("/api/products/search", async (req, res) => {',
    "  const rows = await dbAll('SELECT * FROM products WHERE name LIKE ?', [req.query.q]);",
    "  res.json(rows);",
    "});",
  ].join("\n");
  const contents = new Map([
    [`${R}\\src\\public.js`, publicSrc],
    [`${R}\\src\\app.js`, authedSrc],
  ]);
  const a = await analyzeProject({
    projectRoot: R,
    tokens: { project: "tok" },
    rpc: {
      request: async (method, params) => {
        if (method === "fs.list") {
          return {
            entries: [
              { path: `${R}\\src\\public.js`, kind: "file", size: 400 },
              { path: `${R}\\src\\app.js`, kind: "file", size: 900 },
            ],
          };
        }
        if (method === "fs.read") {
          const content = contents.get(params.path);
          return { content, size: content.length, redacted: false, redactions: [] };
        }
        throw new Error(`不应调用 ${method}`);
      },
    },
  });
  const anonymous = a.candidates.find((c) => c.path === "/api/user/:id");
  assert.ok(anonymous, "dbGet(…) 单行 helper 应入候选");
  assert.equal(anonymous.kind, "no-auth-suspect");
  assert.equal(anonymous.resource, "user");
  assert.deepEqual(anonymous.sinkCalls, ["dbGet"]);

  const poolQuery = a.candidates.find((c) => c.path === "/api/invoices/:id");
  assert.ok(poolQuery, "pool.query(…) 应入候选");
  assert.equal(poolQuery.kind, "idor-suspect");
  assert.deepEqual(poolQuery.sinkCalls, ["pool.query"]);

  const prepared = a.candidates.find((c) => c.path === "/api/notes/:id");
  assert.ok(prepared, "db.prepare(…).get(…) 应入候选");
  assert.deepEqual(prepared.sinkCalls, ["db.prepare.get"]);

  assert.ok(
    !a.candidates.some((c) => c.path === "/api/products/search"),
    "dbAll(…) 列表族不应成为单查候选"
  );
});

test("analyzeProject: 跨文件 handler 引用 + IIFE 挂载（router.get('/x', mw, appHandler.x)）", async () => {
  const R = "\\\\?\\D:\\dvna";
  const listing = {
    entries: [
      { path: `${R}\\server.js`, kind: "file", size: 500 },
      { path: `${R}\\routes\\app.js`, kind: "file", size: 500 },
      { path: `${R}\\core\\appHandler.js`, kind: "file", size: 500 },
      { path: `${R}\\core\\authHandler.js`, kind: "file", size: 500 },
    ],
  };
  const contents = new Map([
    [`${R}\\server.js`, "app.use('/app', require('./routes/app')());"],
    [
      `${R}\\routes\\app.js`,
      [
        'var router = require("express").Router()',
        'var appHandler = require("../core/appHandler")',
        'var authHandler = require("../core/authHandler")',
        "module.exports = function () {",
        "  router.get('/modifyproduct', authHandler.isAuthenticated, appHandler.modifyProduct)",
        "}",
      ].join("\n"),
    ],
    [
      `${R}\\core\\appHandler.js`,
      [
        "module.exports.modifyProduct = function (req, res) {",
        "  db.Product.find({ where: { 'id': req.query.id } }).then(product => {",
        "    res.json(product)",
        "  })",
        "}",
      ].join("\n"),
    ],
    [`${R}\\core\\authHandler.js`, "module.exports.isAuthenticated = function (req, res, next) { next() }"],
  ]);
  const a = await analyzeProject({
    projectRoot: R,
    tokens: { project: "tok" },
    rpc: {
      request: async (method, params) => {
        if (method === "fs.list") return listing;
        if (method === "fs.read") {
          return { content: contents.get(params.path), size: 500, redacted: false, redactions: [] };
        }
        throw new Error(`不应调用 ${method}`);
      },
    },
  });
  const c = a.candidates.find((x) => x.fullPath === "/app/modifyproduct");
  assert.ok(c, "跨文件 handler 应经 IIFE 挂载前缀还原为候选");
  assert.equal(c.authSource, "route", "路由中间件的认证引用（authHandler.isAuthenticated）应计为认证");
  assert.deepEqual(c.queryParam, { param: "id", form: "direct" });
  assert.equal(c.resource, "product");
  assert.ok(a.diagnostics.handlerRefsResolved >= 1, "诊断应记录已解析的 handler 引用");
  assert.equal(a.diagnostics.handlerRefsMissed, 0, "本 fixture 的 handler 引用应全部解析");
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

test("createPatch: 仅无鉴权候选（攻击已复现）归类为 no_patchable_candidates，不放行为无漏洞", async () => {
  const calls = [];
  const ctx = {
    projectRoot: "D:/p",
    sessionId: "s1",
    tokens: { worktree: "tok_wt", project: "tok_p" },
    analysis: { candidates: [{ kind: "no-auth-suspect", file: "D:/p/src/app.js", method: "GET", path: "/x/:id" }] },
    emit: () => {},
    db: { insertPatch: () => {} },
    rpc: {
      request: async (method) => {
        calls.push(method);
        throw new Error(`不应调用 ${method}`);
      },
    },
  };
  await assert.rejects(
    () => createPatch(ctx),
    (e) => e.code === "no_patchable_candidates" && /人工修复/.test(e.hint),
    "应归类为 no_patchable_candidates 并给出人工修复指引"
  );
  assert.deepEqual(calls, [], "无可修复候选时不应触碰 RPC（worktree 等）");
});

test("N-4: createPatch 链接顶层与子目录 node_modules（含 junction 形态）到 worktree", async () => {
  const calls = [];
  const events = [];
  const ctx = {
    projectRoot: "D:/p",
    sessionId: "s1",
    tokens: { worktree: "tok_wt", project: "tok_p" },
    analysis: { candidates: [{ kind: "idor-suspect", file: "D:/p/src/app.js", method: "GET", path: "/x/:id" }] },
    emit: (e) => events.push(e),
    db: { insertPatch: () => {} },
    rpc: {
      request: async (method, params) => {
        calls.push({ method, params });
        if (method === "git.status") return { isRepo: true, entries: [] };
        if (method === "git.worktreeAdd") return { path: "D:/wt/fix-1" };
        if (method === "fs.list") {
          return {
            entries: [
              { name: "src", path: "D:/p/src", kind: "dir", size: 0 },
              { name: "node_modules", path: "D:/p/node_modules", kind: "symlink", size: 0 },
              { name: "backend", path: "D:/p/backend", kind: "dir", size: 0 },
              { name: "node_modules", path: "D:/p/backend/node_modules", kind: "dir", size: 0 },
            ],
          };
        }
        if (method === "fs.linkDir") return {};
        if (method === "fs.stat") throw new Error("not found"); // 目标文件不在 worktree → 无补丁可生成
        throw new Error(`不应调用 ${method}`);
      },
    },
  };
  await assert.rejects(() => createPatch(ctx), (e) => e.code === "no_patch_applied");
  const links = calls.filter((c) => c.method === "fs.linkDir");
  assert.deepEqual(
    links.map((l) => l.params.dst),
    ["D:/wt/fix-1/node_modules", "D:/wt/fix-1/backend/node_modules"],
    "顶层与子目录 node_modules（含 junction）均应链接到 worktree 对应位置"
  );
  assert.ok(
    links.every((l) => l.params.readToken === "tok_p" && l.params.token === "tok_wt"),
    "链接以 worktree 写令牌 + project 读令牌组合授权"
  );
  const ev = events.find((e) => e.kind === "patch" && /依赖目录链接到隔离工作区/.test(e.message));
  assert.ok(ev && ev.severity === "info", "应有链接成功事件");
  assert.deepEqual(ev.data.linked, ["node_modules", "backend/node_modules"]);
});

// —— P0 接入自动化：启动方式自动探测 + 启动失败诊断 ——

/** 以 { 相对路径: 内容 } 模拟 Host 的 FS_LIST / FS_READ / FS_STAT（目录用 "dir/" 声明） */
function virtualCtx(entries, root = "D:/p") {
  const files = new Map();
  const dirs = new Set(["."]);
  for (const [raw, content] of Object.entries(entries)) {
    const rel = raw.replace(/\\/g, "/").replace(/^\.\//, "").replace(/\/$/, "");
    if (raw.endsWith("/")) {
      dirs.add(rel);
      continue;
    }
    files.set(rel, String(content));
    const parts = rel.split("/");
    for (let i = 1; i < parts.length; i++) dirs.add(parts.slice(0, i).join("/"));
  }

  const children = (dirRel) => {
    const out = [];
    for (const d of dirs) {
      if (d === ".") continue;
      const parent = d.includes("/") ? d.slice(0, d.lastIndexOf("/")) : ".";
      if (parent === dirRel) out.push({ name: d.split("/").pop(), path: `${root}/${d}`, kind: "dir", size: 0 });
    }
    for (const [rel, content] of files) {
      const parent = rel.includes("/") ? rel.slice(0, rel.lastIndexOf("/")) : ".";
      if (parent === dirRel) {
        out.push({ name: rel.split("/").pop(), path: `${root}/${rel}`, kind: "file", size: content.length });
      }
    }
    return out;
  };
  const relOf = (abs) =>
    abs === root ? "." : String(abs).startsWith(`${root}/`) ? String(abs).slice(root.length + 1) : null;
  const list = (dirRel, depth) => {
    if (depth <= 0) return [];
    const out = children(dirRel);
    if (depth > 1) {
      for (const e of [...out]) {
        if (e.kind !== "dir" || /^(node_modules|\.git|\.venv|venv)$/i.test(e.name)) continue;
        out.push(...list(relOf(e.path), depth - 1));
      }
    }
    return out;
  };

  return {
    projectRoot: root,
    tokens: { project: "tok" },
    rpc: {
      request: async (method, params) => {
        const rel = relOf(params.path);
        if (method === RPC_TO_HOST.FS_LIST) {
          if (rel == null) throw new Error("out of root");
          return { entries: list(rel, params.depth ?? 2) };
        }
        if (method === RPC_TO_HOST.FS_READ) {
          if (!files.has(rel)) throw new Error("not found");
          return { content: files.get(rel) };
        }
        if (method === RPC_TO_HOST.FS_STAT) {
          if (files.has(rel) || dirs.has(rel)) return { size: 0, kind: files.has(rel) ? "file" : "dir" };
          throw new Error("not found");
        }
        throw new Error("unexpected method");
      },
    },
  };
}

test("detectStartConfig: package.json start 脚本 → npm run start + PORT 槽位", async () => {
  const res = await detectStartConfig(
    virtualCtx({
      "package.json": JSON.stringify({ scripts: { start: "node server.js" }, dependencies: { express: "^4" } }),
      "package-lock.json": "{}",
      "server.js": "require('express')()",
      "node_modules/": "",
    })
  );
  assert.equal(res.start.cmd, "npm");
  assert.deepEqual(res.start.args, ["run", "start"]);
  assert.equal(res.start.env.PORT, PORT_SLOT);
  assert.equal(res.start.cwd, null);
  assert.match(res.origin, /scripts\.start/);
  assert.deepEqual(res.warnings, [], "npm 项目 + 已装依赖时不应有告警");
});

test("detectStartConfig: 子目录 backend/package.json → start.cwd 定位到子目录", async () => {
  const res = await detectStartConfig(
    virtualCtx({
      "README.md": "# demo",
      "backend/package.json": JSON.stringify({ scripts: { dev: "node server.js" } }),
      "backend/server.js": "",
      "backend/node_modules/": "",
      "node_modules/": "",
    })
  );
  assert.equal(res.start.cmd, "npm");
  assert.deepEqual(res.start.args, ["run", "dev"]);
  assert.equal(res.start.cwd, "backend");
  assert.match(res.origin, /scripts\.dev/);
});

test("detectStartConfig: Next.js start 缺构建产物 → 回落 dev 并告警", async () => {
  const res = await detectStartConfig(
    virtualCtx({
      "package.json": JSON.stringify({
        scripts: { start: "next start", dev: "next dev" },
        dependencies: { next: "14.0.0" },
      }),
      "node_modules/": "",
    })
  );
  assert.deepEqual(res.start.args, ["run", "dev"]);
  assert.ok(res.warnings.some((w) => /Next\.js/.test(w)), "应提示 start 需要构建");
});

test("detectStartConfig: FastAPI main.py → uvicorn 模块路径 + 槽位端口", async () => {
  const res = await detectStartConfig(
    virtualCtx({
      "main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
      "requirements.txt": "fastapi\nuvicorn\n",
    })
  );
  assert.equal(res.start.cmd, "python");
  assert.deepEqual(res.start.args, [
    "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", PORT_SLOT,
  ]);
  assert.match(res.origin, /FastAPI/);
});

test("detectStartConfig: 子目录 manage.py → Django runserver（--noreload + 槽位端口）", async () => {
  const res = await detectStartConfig(
    virtualCtx({
      "backend/manage.py": "#!/usr/bin/env python",
      "backend/settings.py": "",
    })
  );
  assert.equal(res.start.cwd, "backend");
  assert.equal(res.start.args[0], "manage.py");
  assert.equal(res.start.args[1], "runserver");
  assert.equal(res.start.args[2], `127.0.0.1:${PORT_SLOT}`);
  assert.ok(res.start.args.includes("--noreload"), "禁用 autoreload，避免子进程泄漏");
});

test("parseProcfile / detectStartConfig: web 行命令 + $PORT 槽位替换", () => {
  const parsed = parseProcfile("web: uvicorn app.main:app --host 0.0.0.0 --port $PORT\n");
  assert.equal(parsed.start.cmd, "uvicorn");
  assert.deepEqual(parsed.start.args, ["app.main:app", "--host", "0.0.0.0", "--port", PORT_SLOT]);
  assert.equal(parsed.start.env.PORT, PORT_SLOT);
  assert.equal(parseProcfile("web: bundle exec puma\n"), null, "白名单外的命令不应被探测采用");
});

test("loadTargetConfig: 缺失 start 时自动探测，login/identities 保留且部分 start 字段可覆盖", async () => {
  const identities = [
    { username: "alice", password: "a", role: "user" },
    { username: "bob", password: "b", role: "user" },
  ];
  const ctx = virtualCtx({
    "guardbuild.json": JSON.stringify({
      login: { path: "/api/login" },
      identities,
      start: { env: { JWT_SECRET: "s3cr3t" }, readyPattern: "CUSTOM_READY" },
    }),
    "package.json": JSON.stringify({ scripts: { start: "node index.js" } }),
    "index.js": "",
    "node_modules/": "",
  });
  const res = await loadTargetConfig(ctx);
  assert.equal(res.startSource, "auto");
  assert.deepEqual(res.start.args, ["run", "start"]);
  assert.equal(res.start.env.PORT, PORT_SLOT, "自动探测注入端口槽位");
  assert.equal(res.start.env.JWT_SECRET, "s3cr3t", "契约中的 env 覆盖保留");
  assert.equal(res.start.readyPattern, "CUSTOM_READY", "契约中的就绪模式覆盖保留");
  assert.equal(res.login.path, "/api/login");
  assert.equal(res.identities.length, 2);
});

test("loadTargetConfig: 显式声明 start 时不自动探测（契约优先）", async () => {
  const res = await loadTargetConfig(
    virtualCtx({
      "guardbuild.json": JSON.stringify({ start: { cmd: "node", args: ["custom.js"] } }),
      "package.json": JSON.stringify({ scripts: { start: "node server.js" } }),
      "custom.js": "",
      "server.js": "",
      "node_modules/": "",
    })
  );
  assert.equal(res.startSource, "contract");
  assert.deepEqual(res.start.args, ["custom.js"]);
});

test("diagnoseStartFailure: 常见启动错误翻译为可操作建议", () => {
  const dep = diagnoseStartFailure({ output: ["Error: Cannot find module 'express'"], exitCode: 1 });
  assert.equal(dep.code, "missing_dependency");
  assert.match(dep.hint, /npm install|prepare/);

  const pyDep = diagnoseStartFailure({ output: ["ModuleNotFoundError: No module named 'fastapi'"] });
  assert.equal(pyDep.code, "python_missing_dependency");

  const port = diagnoseStartFailure({ output: ["Error: listen EADDRINUSE: address already in use 127.0.0.1:3000"] });
  assert.equal(port.code, "port_in_use");

  const env = diagnoseStartFailure({ output: ["Error: DATABASE_URL is not set"] });
  assert.equal(env.code, "missing_env");
  assert.match(env.hint, /start\.env/);

  const exit = diagnoseStartFailure({ output: ["something"], exitCode: 7 });
  assert.equal(exit.code, "early_exit");
  assert.match(exit.hint, /退出码 7/);

  const silent = diagnoseStartFailure({ output: [] });
  assert.equal(silent.code, "no_ready_output");
});

test("GENERIC_READY_PATTERN: 匹配主流框架监听行，忽略普通启动日志", () => {
  // Host 使用 Rust regex（支持内联 (?i)）；JS RegExp 需改用 i 标志
  const re = new RegExp(GENERIC_READY_PATTERN.replace(/^\(\?i\)/, ""), "i");
  for (const line of [
    "Server running on port 3000",
    "Listening on port 8080",
    "Listening on 3000",
    "Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)",
    "Local: http://localhost:5173/",
    "Starting development server at http://127.0.0.1:8000/",
    "Nest application successfully started",
    "服务器运行在端口 51234",
  ]) {
    assert.ok(re.test(line), `应命中：${line}`);
  }
  for (const line of ["Connecting to database...", "Compiling...", "ready in 520 ms"]) {
    assert.ok(!re.test(line), `不应误命中：${line}`);
  }
  assert.equal(parsePortFromLine("Listening on 3000"), 3000, "无 port 字样的监听行也应解析端口");
});

test("findSqlInjectionSignal: 模板插值/拼接/变量传播命中，参数化与 Prisma 标签模板不误报", () => {
  const tpl = [
    "const { query } = req.query;",
    "const rows = dbAll(`SELECT * FROM products WHERE name LIKE '%${query}%'`);",
  ].join("\n");
  assert.deepEqual(findSqlInjectionSignal(tpl), {
    source: "query",
    param: "query",
    sink: "dbAll",
    form: "interpolation",
  });

  const concat = `db.query("SELECT * FROM users WHERE id = " + req.query.id);`;
  assert.deepEqual(findSqlInjectionSignal(concat), {
    source: "query",
    param: "id",
    sink: "query",
    form: "direct",
  });

  const viaVar = [
    "const uid = req.query.id;",
    'const sql = "SELECT * FROM users WHERE id = " + uid;',
    "pool.query(sql);",
  ].join("\n");
  const varHit = findSqlInjectionSignal(viaVar);
  assert.equal(varHit?.source, "query");
  assert.equal(varHit?.param, "id");
  assert.equal(varHit?.form, "variable");

  const parameterized = "dbAll('SELECT * FROM products WHERE name LIKE ?', [req.query.q]);";
  assert.equal(findSqlInjectionSignal(parameterized), null, "参数化占位符不应判定为注入");

  const prismaTagged = "prisma.$queryRaw`SELECT * FROM users WHERE id = ${req.params.id}`;";
  assert.equal(findSqlInjectionSignal(prismaTagged), null, "Prisma 标签模板自动参数化，不应误报");

  const prismaUnsafe = 'prisma.$queryRawUnsafe("SELECT * FROM users WHERE id = " + req.params.id);';
  assert.equal(findSqlInjectionSignal(prismaUnsafe)?.sink, "$queryRawUnsafe", "$queryRawUnsafe 拼接应命中");
});

test("findCommandInjectionSignal: 请求输入经变量进入 shell；正则 exec 与 execFile 数组形态不误报", () => {
  const ping = [
    "const { host } = req.body;",
    "let pingCommand = `ping -n 4 ${host}`;",
    "const out = exec(pingCommand, { timeout: 5000 });",
  ].join("\n");
  assert.deepEqual(findCommandInjectionSignal(ping), {
    source: "body",
    param: "host",
    sink: "exec",
    form: "variable",
  });

  const direct = 'execSync(`ping -c 1 ${req.query.host}`);';
  const directHit = findCommandInjectionSignal(direct);
  assert.equal(directHit?.source, "query");
  assert.equal(directHit?.param, "host");
  assert.equal(directHit?.sink, "execSync");

  assert.equal(
    findCommandInjectionSignal("const m = /(\d+)/.exec(req.query.id);"),
    null,
    "正则对象的 .exec 不是命令执行"
  );

  const arr = [
    "const host = req.body.host;",
    'execFile("ping", ["-n", "1", host]);',
  ].join("\n");
  assert.equal(findCommandInjectionSignal(arr), null, "execFile 数组参数不经 shell，不应判定");
});

test("SINK: Prisma 原始查询 / Knex 单行 / db.raw 形态可识别为取数 sink", () => {
  assert.ok(SINK.test("prisma.$queryRaw`SELECT * FROM users WHERE id = ${id}`"), "Prisma 标签模板应命中原生查询族");
  assert.ok(SINK.test('prisma.$queryRawUnsafe("SELECT * FROM users WHERE id = ?")'), "$queryRawUnsafe 应命中");
  assert.ok(SINK.test('knex("users").where({ id }).first()'), "Knex .first() 单行取数应命中");
  assert.ok(SINK.test('db.raw("SELECT * FROM users WHERE id = ?", [id])'), "db.raw 应命中");
  assert.ok(SINK.test('db.prepare("SELECT * FROM users WHERE id = ?").get(id)'), "prepare().get() 应命中");
});

test("analyzeProject: SQL/命令注入候选识别（注入形态独立于越权候选）", async () => {
  const R = "\\?\D:\p";
  const content = [
    'const express = require("express");',
    'const { execSync } = require("child_process");',
    "const app = express();",
    'app.get("/api/products/search", (req, res) => {',
    "  const { query } = req.query;",
    "  const rows = dbAll(`SELECT * FROM products WHERE name LIKE '%${query}%'`);",
    "  res.json({ products: rows });",
    "});",
    'app.get("/api/safe-search", (req, res) => {',
    "  const rows = dbAll('SELECT * FROM products WHERE name LIKE ?', [req.query.q]);",
    "  res.json({ products: rows });",
    "});",
    'app.post("/api/ping", (req, res) => {',
    "  const { host } = req.body;",
    "  const pingCommand = `ping -n 4 ${host}`;",
    "  const out = execSync(pingCommand);",
    "  res.json({ output: out.toString() });",
    "});",
  ].join("\n");
  const a = await analyzeProject({
    projectRoot: R,
    tokens: { project: "tok" },
    rpc: {
      request: async (method) => {
        if (method === "fs.list") return { entries: [{ path: `${R}\src\app.js`, kind: "file", size: 600 }] };
        if (method === "fs.read") return { content, size: 600, redacted: false, redactions: [] };
        throw new Error(`不应调用 ${method}`);
      },
    },
  });

  const sqli = a.candidates.find((c) => c.fullPath === "/api/products/search");
  assert.ok(sqli, "模板拼接进 dbAll 的端点应成为 sqli 候选");
  assert.equal(sqli.kind, "sqli-suspect");
  assert.deepEqual(sqli.sqli, { source: "query", param: "query", sink: "dbAll", form: "interpolation" });

  const cmdi = a.candidates.find((c) => c.fullPath === "/api/ping");
  assert.ok(cmdi, "请求体进入 execSync 的端点应成为 cmdi 候选");
  assert.equal(cmdi.kind, "cmdi-suspect");
  assert.equal(cmdi.cmdi?.param, "host");

  assert.ok(
    !a.candidates.some((c) => c.fullPath === "/api/safe-search"),
    "参数化查询不应产生注入候选"
  );

  const plan = buildProbePlan(a);
  assert.equal(plan.sqliCandidate?.fullPath, "/api/products/search");
  assert.equal(plan.cmdiCandidate?.fullPath, "/api/ping");
  assert.equal(plan.sqliCandidates.length, 1);
  assert.equal(plan.cmdiCandidates.length, 1);
});

test("buildCases: 注入用例（请求通道构造 + unfixable + 布尔/报错/回显判定）", () => {
  const sqliCand = {
    path: "/api/products/search",
    fullPath: "/api/products/search",
    method: "GET",
    sqli: { source: "query", param: "query", sink: "dbAll", form: "interpolation" },
  };
  const cmdiCand = {
    path: "/api/ping",
    fullPath: "/api/ping",
    method: "POST",
    cmdi: { source: "body", param: "host", sink: "execSync", form: "variable" },
  };
  const cases = buildCases(
    { plan: { sqliCandidate: sqliCand, cmdiCandidate: cmdiCand }, targetConfig: null },
    { attacker: { name: "alice", user: { id: 1 } }, victim: { name: "bob", user: { id: 2 } } }
  );
  assert.deepEqual(cases.map((c) => c.id), ["attack-sql-injection", "attack-command-injection"]);
  assert.ok(cases.every((c) => c.unfixable === true), "注入类无自动修复模板，应标记 unfixable");

  const sqliCase = cases[0];
  assert.equal(sqliCase.method, "GET");
  assert.ok(sqliCase.path.startsWith("/api/products/search?query="), "查询参数注入应追加编码后的参数");
  assert.ok(decodeURIComponent(sqliCase.path.split("?query=")[1]).includes("OR 1=1"));

  const cmdiCase = cases[1];
  assert.equal(cmdiCase.method, "POST");
  assert.equal(cmdiCase.path, "/api/ping");
  assert.match(
    JSON.parse(cmdiCase.body).host,
    /^127\.0\.0\.1\s*&&?\s*echo GB/,
    "命令注入应通过请求体字段投递 shell 载荷"
  );

  assert.equal(
    sqliCase.verify(
      { status: 200, body: "", json: null, _sqliProof: { hit: true, errorSignature: false, attackCount: 3, baseCount: 0, payload: "x" } },
      "pre"
    ).verdict,
    "vulnerable",
    "布尔绕过导致行数增加应判定可利用"
  );
  assert.equal(
    sqliCase.verify(
      { status: 500, body: 'SQLITE_ERROR: near "\'": syntax error', json: null, _sqliProof: { hit: true, errorSignature: true, payload: "x" } },
      "pre"
    ).verdict,
    "vulnerable",
    "500 + 数据库报错特征也应判定可利用"
  );
  assert.equal(
    sqliCase.verify(
      { status: 200, body: "[]", json: [], _sqliProof: { hit: false, payload: "x" } },
      "pre"
    ).verdict,
    "inconclusive"
  );

  assert.equal(
    cmdiCase.verify(
      { status: 200, body: "GBabcdef", json: {}, _cmdiProof: { hit: true, payload: "127.0.0.1; echo GBabcdef$(id -u)" } },
      "pre"
    ).verdict,
    "vulnerable",
    "响应出现 shell 展开令牌应判定可利用"
  );
  assert.equal(
    cmdiCase.verify(
      { status: 200, body: "GBabcdef$(id -u)", json: {}, _cmdiProof: { hit: false, payload: "x" } },
      "pre"
    ).verdict,
    "inconclusive",
    "未命中的反射原文不得判定为可利用"
  );
});
