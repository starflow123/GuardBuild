/**
 * tRPC 适配器单元测试：过程 URL 还原、zod 输入寻址、鉴权链判定、跨文件组装，
 * 以及动态探测层的线协议（input 编码 / 响应信封）。
 *
 * 静态侧断言直接跑在 fixtures/trpc-shop 的真实源码上（initTRPC + 分文件路由 + Next fetch handler），
 * 因此这里同时是「靶场源码可被解析」的回归防线。
 * 运行：npm run test:sidecar
 */
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { collectTrpcSections, detectTrpcPrefix, isTrpcRouterFile, pickInputField } from "../lib/trpc.mjs";
import {
  INPUT_VARIANTS,
  encodeInput,
  inputRejected,
  isTrpcCandidate,
  looksLikeTrpcProcPath,
  trpcInputValue,
  trpcRequest,
  unwrapTrpcEnvelope,
  variantAt,
} from "../lib/trpcwire.mjs";
import { analyzeProject } from "../lib/analyzer.mjs";
import { buildProbePlan } from "../lib/planner.mjs";
import { createPatch } from "../lib/patcher.mjs";

const fixtureRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../fixtures/trpc-shop");

/** 读取靶场源码（仅 .ts，跳过垫片与运行时），供静态断言使用 */
function loadFixtureFiles() {
  const out = [];
  const walk = (dir) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (e.name === "node_modules") continue;
        walk(p);
        continue;
      }
      if (!/\.(ts|tsx|mjs|js)$/.test(e.name)) continue;
      out.push({ path: p, content: readFileSync(p, "utf8") });
    }
  };
  walk(fixtureRoot);
  return out;
}

const fixtureFiles = loadFixtureFiles();

async function analyzeFixture() {
  const contents = new Map(fixtureFiles.map((f) => [f.path, f.content]));
  const listing = { entries: [...contents.keys()].map((p) => ({ path: p, kind: "file", size: 400 })) };
  return analyzeProject({
    projectRoot: fixtureRoot,
    tokens: { project: "tok" },
    rpc: {
      request: async (method, params) => {
        if (method === "fs.list") return listing;
        if (method === "fs.read") {
          return { content: contents.get(params.path) ?? "", size: 400, redacted: false, redactions: [] };
        }
        if (method === "fs.exists") return { exists: false };
        throw new Error(`不应调用 ${method}`);
      },
    },
  });
}

// —— 挂载前缀 ——

test("detectTrpcPrefix: 显式 endpoint > [trpc] 文件位置 > 缺省", () => {
  const files = [
    { path: "/p/src/server/http.ts", content: 'fetchRequestHandler({ endpoint: "/api/trpc", router })' },
    { path: "/p/pages/api/trpc/[trpc].ts", content: "createNextApiHandler({ endpoint: '/api/trpc' })" },
  ];
  assert.equal(detectTrpcPrefix(files, "/p"), "/api/trpc");

  // 无显式 endpoint：从 App Router 文件位置推断（[trpc] 之前的目录段）
  assert.equal(
    detectTrpcPrefix([{ path: "/p/app/api/v2/trpc/[trpc]/route.ts", content: "fetchRequestHandler({ req })" }], "/p"),
    "/api/v2/trpc"
  );
  // Pages Router 的 catch-all 形态
  assert.equal(
    detectTrpcPrefix([{ path: "/p/pages/api/trpc/[...trpc].ts", content: "createContext" }], "/p"),
    "/api/trpc"
  );
  // 完全没有线索：缺省 /api/trpc（vibecoding 模板的默认挂载点）
  assert.equal(detectTrpcPrefix([{ path: "/p/src/router.ts", content: "initTRPC" }], "/p"), "/api/trpc");
});

test("isTrpcRouterFile: 直接 import @trpc/server 与经由本地 trpc 模块都识别，普通文件不误判", () => {
  assert.equal(isTrpcRouterFile('import { createTRPCRouter } from "@trpc/server";'), true);
  assert.equal(isTrpcRouterFile('import { router, protectedProcedure } from "../trpc";'), true);
  assert.equal(isTrpcRouterFile('import { z } from "zod";\nexport const h = () => 1;'), false);
  assert.equal(isTrpcRouterFile("const r = express.Router();"), false);
});

// —— zod 输入寻址 ——

test("pickInputField: 对象字段优先 id/*Id，标量类型随值一起返回", () => {
  assert.deepEqual(pickInputField("z.object({ id: z.number() })"), { field: "id", scalar: false, kind: "number" });
  assert.deepEqual(pickInputField('z.object({ orderId: z.string().uuid(), note: z.string() })'), {
    field: "orderId",
    scalar: false,
    kind: "string",
  });
  assert.deepEqual(pickInputField("z.object({ id: z.coerce.number().int() })"), {
    field: "id",
    scalar: false,
    kind: "number",
  });
  // 裸标量输入
  assert.deepEqual(pickInputField("z.string()"), { field: null, scalar: true, kind: "string" });
  assert.deepEqual(pickInputField("z.number().int()"), { field: null, scalar: true, kind: "number" });
  // 复杂输入不可寻址 / 多个非 ID 字段无从判断
  assert.equal(pickInputField("z.object({ q: z.string(), page: z.number() })"), null);
  assert.equal(pickInputField("z.object({ body: z.object({ id: z.number() }) })"), null);
  // boolean 无法承载对象 ID
  assert.equal(pickInputField("z.object({ flag: z.boolean() })"), null);
  assert.equal(pickInputField("z.boolean()"), null);
});

// —— 路由树解析（靶场真实源码）——

test("collectTrpcSections: 跨文件组装出点连接的过程路径与 HTTP 方法", () => {
  const { sections, diag } = collectTrpcSections(fixtureFiles, fixtureRoot);
  const byPath = Object.fromEntries(sections.map((s) => [s.declaredPath, s]));

  assert.deepEqual(
    Object.keys(byPath).sort(),
    ["admin.listAll", "admin.stats", "auth.login", "auth.me", "orders.byId", "orders.cancel", "orders.list"]
      .map((p) => `/api/trpc/${p}`)
      .sort(),
    "七个过程应全部还原（含跨文件 router 变量组装）"
  );
  assert.equal(diag.trpcPrefix, "/api/trpc");
  assert.equal(diag.trpcRefsResolved, 3, "root.ts 的 auth/orders/admin 三个跨文件引用应解析");
  assert.equal(byPath["/api/trpc/orders.byId"].method, "GET", "query → GET");
  assert.equal(byPath["/api/trpc/orders.cancel"].method, "POST", "mutation → POST");
  assert.equal(byPath["/api/trpc/orders.byId"].style, "trpc");
  assert.equal(
    byPath["/api/trpc/orders.byId"].file.replace(/\\/g, "/").endsWith("src/server/routers/orders.ts"),
    true,
    "来源文件应是声明该过程的路由文件"
  );
});

test("collectTrpcSections: 构建器链判定鉴权与角色，input 抽取可寻址字段", () => {
  const { sections } = collectTrpcSections(fixtureFiles, fixtureRoot);
  const byPath = Object.fromEntries(sections.map((s) => [s.declaredPath, s]));

  assert.equal(byPath["/api/trpc/orders.byId"].forcedAuth, true, "protectedProcedure 即受保护");
  assert.equal(byPath["/api/trpc/auth.login"].forcedAuth, undefined, "publicProcedure 不得被判为已认证");
  assert.equal(byPath["/api/trpc/admin.listAll"].roleGuard, true, "adminProcedure 应记为角色校验");
  assert.deepEqual(byPath["/api/trpc/orders.byId"].trpc, {
    procPath: "orders.byId",
    builder: "protectedProcedure",
    kind: "query",
    inputField: "id",
    inputScalar: false,
    inputKind: "number",
    addressable: true,
  });
  assert.equal(byPath["/api/trpc/orders.cancel"].trpc.inputField, "orderId");
  assert.equal(byPath["/api/trpc/orders.list"].trpc.addressable, false, "无输入列表不可寻址");
  assert.equal(byPath["/api/trpc/auth.login"].trpc.addressable, false, "email+password 双字段不构成可寻址 ID");
});

test("collectTrpcSections: 中间件形态（t.procedure.use(isAuthed)）与嵌套 router 也识别", () => {
  const files = [
    {
      path: "/p/src/api.ts",
      content: [
        'import { initTRPC } from "@trpc/server";',
        "const t = initTRPC.create();",
        "const authed = t.middleware(({ ctx, next }) => next());",
        "const base = t.procedure;",
        "export const apiRouter = router({",
        "  posts: createTRPCRouter({",
        "    bySlug: base.input(z.string()).use(authed).query(async () => null),",
        "  }),",
        "  users: userRouter,",
        "});",
      ].join("\n"),
    },
    {
      path: "/p/src/users.ts",
      content: [
        'import { createTRPCRouter, publicProcedure } from "@trpc/server";',
        "export const userRouter = createTRPCRouter({",
        "  detail: publicProcedure.input(z.object({ userId: z.string() })).query(async () => null),",
        "});",
      ].join("\n"),
    },
  ];
  const { sections } = collectTrpcSections(files, "/p");
  const byPath = Object.fromEntries(sections.map((s) => [s.declaredPath, s]));
  assert.equal(byPath["/api/trpc/posts.bySlug"].forcedAuth, true, ".use(authed) 中间件应判为受保护");
  assert.equal(byPath["/api/trpc/posts.bySlug"].trpc.inputScalar, true, "裸标量输入可寻址");
  assert.equal(byPath["/api/trpc/users.detail"].trpc.inputField, "userId", "跨文件引用的嵌套路由应带前缀");
  assert.equal(byPath["/api/trpc/users.detail"].forcedAuth, undefined, "publicProcedure 不受其它文件的中间件影响");
});

// —— 静态分析 + 计划 ——

test("analyzeProject: tRPC 越权过程进入候选，公开/管理过程不误报", async () => {
  const a = await analyzeFixture();
  const byPath = Object.fromEntries(a.candidates.map((c) => [`${c.method} ${c.fullPath}`, c]));

  assert.ok(byPath["GET /api/trpc/orders.byId"], "byId 缺归属校验应为 IDOR 候选");
  assert.equal(byPath["GET /api/trpc/orders.byId"].kind, "idor-suspect");
  assert.equal(byPath["GET /api/trpc/orders.byId"].style, "trpc");
  assert.equal(byPath["GET /api/trpc/orders.byId"].resource, "order", "orderRepo.findById → 资源名 order");
  assert.equal(byPath["GET /api/trpc/orders.byId"].hasAuth, true);
  assert.equal(byPath["GET /api/trpc/orders.byId"].authSource, "route", "鉴权来自构建器链而非文件级中间件");
  assert.ok(byPath["POST /api/trpc/orders.cancel"], "cancel 缺归属校验应为 IDOR 候选");

  const eps = Object.fromEntries(a.endpoints.map((e) => [e.fullPath, e]));
  assert.equal(eps["/api/trpc/orders.list"]?.hasOwnerFilter, true, "列表过程应识别归属过滤（供资源发现）");
  assert.ok(!a.candidates.some((c) => c.fullPath === "/api/trpc/orders.list"), "列表过程不应成为 IDOR 候选");
  assert.ok(!a.candidates.some((c) => c.fullPath === "/api/trpc/auth.login"), "登录过程不应成为候选");
  assert.ok(!a.candidates.some((c) => c.fullPath === "/api/trpc/admin.listAll"), "管理端过程由角色校验保护");
  assert.equal(a.diagnostics.trpcProcedures, 7);
});

test("buildProbePlan: tRPC 候选填充读/取消槽位，列表过程作资源发现端点", async () => {
  const a = await analyzeFixture();
  const plan = buildProbePlan(a, { loginPathOverride: "/api/trpc/auth.login" });
  assert.equal(plan.loginCandidates[0], "/api/trpc/auth.login");
  assert.equal(plan.readCandidates[0].fullPath, "/api/trpc/orders.byId");
  assert.equal(plan.readCandidates[0].trpc.addressable, true, "tRPC 候选按输入字段可寻址");
  assert.equal(plan.cancelCandidates[0].fullPath, "/api/trpc/orders.cancel", "过程名含 cancel 的变更应进取消槽位");
  assert.equal(plan.listEndpoint.path, "/api/trpc/orders.list");
  assert.equal(plan.adminListEndpoint.path, "/api/trpc/admin.listAll");
  assert.equal(plan.resource, "order");
});

test("createPatch: 风格门控——trpc 候选不套用 Express/method 注入", async () => {
  const calls = [];
  const ctx = {
    projectRoot: "D:/p",
    sessionId: "s1",
    tokens: { worktree: "tok_wt", project: "tok_p" },
    analysis: {
      candidates: [
        {
          kind: "idor-suspect",
          file: "D:/p/src/server/routers/orders.ts",
          method: "GET",
          path: "/api/trpc/orders.byId",
          fullPath: "/api/trpc/orders.byId",
          style: "trpc",
          resource: "order",
          trpc: { procPath: "orders.byId", addressable: true, inputField: "id", inputKind: "number" },
        },
      ],
    },
    emit: () => {},
    db: { insertPatch: () => {} },
    rpc: {
      request: async (method) => {
        calls.push(method);
        if (method === "git.status") return { isRepo: true, entries: [] };
        if (method === "git.worktreeAdd") return { path: "D:/wt" };
        if (method === "fs.list") return { entries: [] };
        if (method === "fs.linkDir") return { ok: true };
        if (method === "fs.stat") return { exists: true };
        if (method === "fs.read") {
          return { content: "export const ordersRouter = router({});", size: 40, redacted: false, redactions: [] };
        }
        throw new Error(`不应调用 ${method}`);
      },
    },
  };
  await assert.rejects(
    () => createPatch(ctx),
    (e) => e.code === "no_patchable_candidates" && /人工修复/.test(e.hint),
    "tRPC 形态无自动修复模板：应归类 vulnerable_unfixed"
  );
  assert.ok(!calls.includes("fs.write"), "不得对 tRPC 源码写入 Express 风格补丁");
});

// —— 线协议 ——

test("trpcRequest: 查询走 GET ?input=，变更走 POST 请求体，ID 按声明类型投放", () => {
  const query = {
    method: "GET",
    fullPath: "/api/trpc/orders.byId",
    trpc: { procPath: "orders.byId", inputField: "id", inputScalar: false, inputKind: "number", addressable: true },
  };
  const req = trpcRequest(query, 5002, INPUT_VARIANTS[0]);
  assert.equal(req.method, "GET");
  assert.equal(req.path.startsWith("/api/trpc/orders.byId?input="), true, "查询走 GET，input 在查询串");
  assert.equal(decodeURIComponent(req.path.split("?input=")[1]), '{"json":{"id":5002}}');
  assert.equal(req.body, null);

  const mutation = {
    method: "POST",
    fullPath: "/api/trpc/orders.cancel",
    trpc: { procPath: "orders.cancel", inputField: "orderId", inputScalar: false, inputKind: "number", addressable: true },
  };
  const mreq = trpcRequest(mutation, 5002, variantAt(1));
  assert.equal(mreq.path, "/api/trpc/orders.cancel");
  assert.equal(mreq.body, '{"orderId":5002}');

  // 裸标量输入：值即 ID 本身
  const bare = {
    method: "GET",
    fullPath: "/api/trpc/posts.bySlug",
    trpc: { procPath: "posts.bySlug", inputField: null, inputScalar: true, inputKind: "string", addressable: true },
  };
  assert.equal(decodeURIComponent(trpcRequest(bare, 7, variantAt(0)).path.split("?input=")[1]), '{"json":"7"}');
  assert.equal(trpcRequest({ method: "GET", path: "/api/orders/:id" }, 1, variantAt(0)), null, "非 tRPC 候选返回 null");
});

test("trpcInputValue: 类型翻转用于纠正猜错的 ID 形态", () => {
  const cand = {
    method: "GET",
    path: "/api/trpc/orders.byId",
    trpc: { inputField: "id", inputScalar: false, inputKind: "number", addressable: true },
  };
  assert.deepEqual(trpcInputValue(cand, "5002", variantAt(0)), { id: 5002 });
  assert.deepEqual(trpcInputValue(cand, "5002", variantAt(2)), { id: "5002" });
  // 类型未知时以传入值自身的类型为基准，flip 才翻转
  const unknown = { method: "GET", path: "/x", trpc: { inputField: "id", inputKind: null, addressable: true } };
  assert.deepEqual(trpcInputValue(unknown, 5002, variantAt(0)), { id: 5002 });
  assert.deepEqual(trpcInputValue(unknown, 5002, variantAt(2)), { id: "5002" });
  // 非数值 ID 翻转后不得产出 NaN
  const cuid = { method: "GET", path: "/x", trpc: { inputField: "id", inputKind: "string", addressable: true } };
  assert.deepEqual(trpcInputValue(cuid, "c_abc", variantAt(3)), { id: "c_abc" });
});

test("encodeInput: superjson 包裹与裸值两种线形态", () => {
  assert.equal(encodeInput({ id: 1 }, true), '{"json":{"id":1}}');
  assert.equal(encodeInput({ id: 1 }, false), '{"id":1}');
});

test("unwrapTrpcEnvelope: 只解协议信封，普通 REST 响应原样返回", () => {
  assert.deepEqual(
    unwrapTrpcEnvelope({ result: { data: { json: { order: { id: 1 } }, meta: { values: {} } } } }),
    { order: { id: 1 } }
  );
  assert.deepEqual(unwrapTrpcEnvelope({ result: { data: { order: { id: 2 } } } }), { order: { id: 2 } });
  assert.deepEqual(unwrapTrpcEnvelope({ orders: [{ id: 3 }] }), { orders: [{ id: 3 }] }, "REST 列表不受影响");
  assert.deepEqual(
    unwrapTrpcEnvelope({ result: { data: { user: { id: 4 }, result: 1 } } }),
    { user: { id: 4 }, result: 1 },
    "data 内含同名键时仍按信封解开一层，但 data 自身不再被误判为信封"
  );
  assert.deepEqual(unwrapTrpcEnvelope({ result: { data: null } }), null);
  assert.equal(unwrapTrpcEnvelope(null), null);
});

test("inputRejected: 400 与 BAD_REQUEST/PARSE_ERROR 错误码都视为 input 形态不合", () => {
  assert.equal(inputRejected({ status: 400, json: {} }), true);
  assert.equal(inputRejected({ status: 400 }), true);
  assert.equal(inputRejected({ status: 422, json: { error: { data: { code: "BAD_REQUEST" } } } }), true);
  assert.equal(inputRejected({ status: 422, json: { error: { json: { data: { code: "PARSE_ERROR" } } } } }), true);
  assert.equal(inputRejected({ status: 401, json: { error: { data: { code: "UNAUTHORIZED" } } } }), false);
  assert.equal(inputRejected({ status: 404, json: { error: { data: { code: "NOT_FOUND" } } } }), false);
  assert.equal(inputRejected({ status: 200, json: { order: {} } }), false);
});

test("looksLikeTrpcProcPath: 识别点连接过程路径（登录端点编码协商的触发条件）", () => {
  assert.equal(looksLikeTrpcProcPath("/api/trpc/auth.login"), true);
  assert.equal(looksLikeTrpcProcPath("/api/trpc/admin.users.list"), true);
  assert.equal(looksLikeTrpcProcPath("/api/login"), false);
  assert.equal(looksLikeTrpcProcPath("/api/orders/1"), false);
});

test("isTrpcCandidate: 候选形态判定不抛异常", () => {
  assert.equal(isTrpcCandidate({ trpc: { addressable: true } }), true);
  assert.equal(isTrpcCandidate({}), false);
  assert.equal(isTrpcCandidate(null), false);
  assert.equal(variantAt(99), INPUT_VARIANTS[0], "越界下标回退默认形态");
});
