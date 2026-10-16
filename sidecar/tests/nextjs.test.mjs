/**
 * Next.js 适配器单元测试：路由路径还原、方法处理器抽取、候选判定与补丁风格门控。
 * 运行：npm run test:sidecar
 */
import test from "node:test";
import assert from "node:assert/strict";

import {
  nextRouteUrl,
  parseNextRoute,
  extractMethodHandlers,
  extractDefaultHandler,
  collectNextSections,
} from "../lib/nextjs.mjs";
import { analyzeProject } from "../lib/analyzer.mjs";
import { buildProbePlan } from "../lib/planner.mjs";
import { createPatch } from "../lib/patcher.mjs";
import { AUTH_GUARD, findQueryParamSink, findTraversalSignal } from "../lib/signals.mjs";

const R = "\\\\?\\D:\\proj"; // Host 返回的 Windows 扩展路径前缀形态

test("nextRouteUrl: App Router 路径还原（动态段 / 路由组 / src 目录）", () => {
  assert.equal(nextRouteUrl(`${R}\\app\\api\\orders\\route.ts`, R), "/api/orders");
  assert.equal(nextRouteUrl(`${R}\\app\\api\\orders\\[id]\\route.ts`, R), "/api/orders/:id");
  assert.equal(nextRouteUrl(`${R}\\app\\api\\orders\\[id]\\cancel\\route.ts`, R), "/api/orders/:id/cancel");
  assert.equal(nextRouteUrl(`${R}\\app\\api\\reports\\[...slug]\\route.ts`, R), "/api/reports/:slug");
  assert.equal(nextRouteUrl(`${R}\\app\\api\\docs\\[[...slug]]\\route.js`, R), "/api/docs/:slug");
  assert.equal(nextRouteUrl(`${R}\\src\\app\\(shop)\\items\\[itemId]\\route.tsx`, R), "/items/:itemId");
  assert.equal(
    nextRouteUrl(`${R}\\apps\\web\\app\\api\\v1\\ping\\route.mjs`, R),
    "/api/v1/ping",
    "monorepo 嵌套 app 目录也应识别"
  );
});

test("nextRouteUrl: 非路由文件与构建产物不误报", () => {
  assert.equal(nextRouteUrl(`${R}\\.next\\server\\app\\api\\orders\\route.js`, R), null);
  assert.equal(nextRouteUrl(`${R}\\app\\api\\orders\\helpers.ts`, R), null);
  assert.equal(nextRouteUrl(`${R}\\app\\api\\orders\\route.test.ts`, R), null);
  assert.equal(nextRouteUrl(`${R}\\app\\api\\_internal\\route.ts`, R), null);
  assert.equal(nextRouteUrl(`${R}\\server.js`, R), null);
  assert.equal(nextRouteUrl(`${R}\\src\\db.ts`, R), null);
});

test("nextRouteUrl: Pages Router（index 折叠 / 动态段 / 访问路径前缀）", () => {
  assert.equal(nextRouteUrl(`${R}\\pages\\api\\orders.ts`, R), "/api/orders");
  assert.equal(nextRouteUrl(`${R}\\pages\\api\\orders\\index.ts`, R), "/api/orders");
  assert.equal(nextRouteUrl(`${R}\\pages\\api\\orders\\[id].ts`, R), "/api/orders/:id");
  assert.equal(nextRouteUrl(`${R}\\pages\\api\\index.ts`, R), "/api");
  assert.equal(nextRouteUrl(`${R}\\src\\pages\\api\\profile.js`, R), "/api/profile");
  assert.equal(nextRouteUrl(`${R}\\pages\\api\\_middleware.ts`, R), null);
  assert.equal(nextRouteUrl(`${R}\\pages\\index.tsx`, R), null, "非 api 的 pages 文件不参与");
});

test("extractMethodHandlers: App Router 导出函数（含 TS 注解与 const 箭头形态）", () => {
  const content = [
    'import { getServerSession } from "next-auth";',
    "",
    "export async function GET(req: NextRequest, { params }: { params: { id: string } }) {",
    "  const session = await getServerSession();",
    "  const order = await db.order.findUnique({ where: { id: Number(params.id) } });",
    "  return NextResponse.json({ order });",
    "}",
    "",
    "export const POST = async (req: NextRequest) => {",
    "  const body = await req.json();",
    "  return NextResponse.json({ ok: true, body });",
    "};",
  ].join("\n");
  const handlers = extractMethodHandlers(content);
  assert.deepEqual(handlers.map((h) => h.method), ["GET", "POST"]);
  assert.equal(handlers[0].startLine, 3);
  assert.ok(handlers[0].text.includes("findUnique"));
  assert.ok(!handlers[0].text.includes("require") && handlers[1].text.includes("req.json()"));
});

test("extractDefaultHandler: Pages Router 方法分支收集（无分支按 GET）", () => {
  const withBranch = [
    "export default async function handler(req: NextApiRequest, res: NextApiResponse) {",
    '  if (req.method === "GET") {',
    "    return res.status(200).json({ items: [] });",
    "  }",
    '  if (req.method === "POST") {',
    "    return res.status(201).json({ ok: true });",
    "  }",
    "  return res.status(405).end();",
    "}",
  ].join("\n");
  const handlers = extractDefaultHandler(withBranch);
  assert.deepEqual(handlers.map((h) => h.method).sort(), ["GET", "POST"]);

  const noBranch = [
    "module.exports = async (req, res) => {",
    "  const item = await Item.findById(req.query.id);",
    "  res.json({ item });",
    "};",
  ].join("\n");
  const single = extractDefaultHandler(noBranch);
  assert.deepEqual(single.map((h) => h.method), ["GET"], "无方法分支时按 GET 处理");
  assert.ok(single[0].text.includes("findById"));
});

test("collectNextSections: 汇总区块（style=next-api + declaredPath）", () => {
  const files = [
    { path: `${R}\\app\\api\\orders\\[id]\\route.ts`, content: "export async function GET() {\n  return null;\n}\n" },
    {
      path: `${R}\\pages\\api\\orders.ts`,
      content: 'export default function handler(req, res) {\n  if (req.method === "GET") {\n    res.end("ok");\n  }\n}\n',
    },
    { path: `${R}\\src\\db.ts`, content: "export const db = {};\n" },
  ];
  const { sections, diag } = collectNextSections(files, R);
  assert.equal(diag.nextRouteFiles, 2);
  assert.equal(diag.nextAppFiles, 1);
  assert.equal(diag.nextPagesFiles, 1);
  assert.equal(sections.length, 2);
  assert.ok(sections.every((s) => s.style === "next-api"));
  assert.equal(sections[0].declaredPath, "/api/orders/:id");
  assert.equal(sections[0].method, "GET");
  assert.equal(sections[1].declaredPath, "/api/orders");
});

test("signals: AUTH_GUARD 覆盖现代框架会话 API 且不误伤普通函数", () => {
  assert.ok(AUTH_GUARD.test("const session = await getServerSession();"));
  assert.ok(AUTH_GUARD.test("const { userId } = await auth();"));
  assert.ok(AUTH_GUARD.test("const user = await currentUser();"));
  assert.ok(AUTH_GUARD.test("const token = await getToken({ req });"));
  assert.ok(AUTH_GUARD.test("export default withAuth(handler);"));
  assert.ok(!AUTH_GUARD.test("const author = findAuthor(id);"), "author 不应命中 auth()");
});

test("signals: findQueryParamSink 支持 searchParams.get 直接/间接形态", () => {
  const direct = 'const order = await db.order.findUnique({ where: { id: Number(searchParams.get("id")) } });';
  assert.deepEqual(findQueryParamSink(direct), { param: "id", form: "direct" });
  const indirect = [
    'const orderId = searchParams.get("orderId");',
    "const order = await db.order.findUnique({ where: { id: Number(orderId) } });",
  ].join("\n");
  assert.deepEqual(findQueryParamSink(indirect), { param: "orderId", form: "indirect" });
});

test("signals: findTraversalSignal 识别 searchParams 输入合流", () => {
  const text = [
    'const name = searchParams.get("file");',
    'const buf = fs.readFileSync(path.join("public", name));',
  ].join("\n");
  const sig = findTraversalSignal(text);
  assert.equal(sig?.source, "searchParams");
  assert.equal(sig?.param, "file");
  assert.equal(sig?.sink, "readFileSync");
});

test("analyzeProject: Next.js route handler 生成 IDOR 候选，列表路由仅作发现端点", async () => {
  const contents = new Map([
    [
      `${R}\\app\\api\\login\\route.ts`,
      [
        'import { NextResponse } from "next/server";',
        "export async function POST(req) {",
        "  const { email, password } = await req.json();",
        "  const result = login(email, password);",
        "  if (!result) return NextResponse.json({ error: 'bad' }, { status: 401 });",
        "  return NextResponse.json({ token: result.token, user: result.user });",
        "}",
      ].join("\n"),
    ],
    [
      `${R}\\app\\api\\orders\\route.ts`,
      [
        'import { getServerSession } from "next-auth";',
        "export async function GET() {",
        "  const session = await getServerSession();",
        "  if (!session) return NextResponse.json({ error: '401' }, { status: 401 });",
        "  const orders = await db.order.findMany({ where: { userId: session.user.id } });",
        "  return NextResponse.json({ orders });",
        "}",
      ].join("\n"),
    ],
    [
      `${R}\\app\\api\\orders\\[id]\\route.ts`,
      [
        'import { getServerSession } from "next-auth";',
        "export async function GET(req, { params }) {",
        "  const session = await getServerSession();",
        "  if (!session) return NextResponse.json({ error: '401' }, { status: 401 });",
        "  const order = await db.order.findUnique({ where: { id: Number(params.id) } });",
        "  return NextResponse.json({ order });",
        "}",
      ].join("\n"),
    ],
    [
      `${R}\\app\\api\\orders\\[id]\\cancel\\route.ts`,
      [
        'import { getServerSession } from "next-auth";',
        "export async function POST(req, { params }) {",
        "  const session = await getServerSession();",
        "  if (!session) return NextResponse.json({ error: '401' }, { status: 401 });",
        "  const order = await db.order.findUnique({ where: { id: Number(params.id) } });",
        "  order.status = 'cancelled';",
        "  return NextResponse.json({ ok: true, order });",
        "}",
      ].join("\n"),
    ],
    [
      `${R}\\pages\\api\\health.ts`,
      [
        "export default function handler(req, res) {",
        '  if (req.method === "GET") {',
        '    return res.status(200).json({ ok: true });',
        "  }",
        "  return res.status(405).end();",
        "}",
      ].join("\n"),
    ],
    [`${R}\\src\\db.ts`, "export const db = { order: { findUnique: async () => null, findMany: async () => [] } };\n"],
    [`${R}\\server.js`, 'import http from "node:http";\nhttp.createServer(() => {}).listen(0);\n'],
  ]);
  const listing = {
    entries: [...contents.keys()].map((p) => ({ path: p, kind: "file", size: 400 })),
  };
  const a = await analyzeProject({
    projectRoot: R,
    tokens: { project: "tok" },
    rpc: {
      request: async (method, params) => {
        if (method === "fs.list") return listing;
        if (method === "fs.read") {
          return { content: contents.get(params.path), size: 400, redacted: false, redactions: [] };
        }
        throw new Error(`不应调用 ${method}`);
      },
    },
  });

  const readCand = a.candidates.find((c) => c.method === "GET" && c.path === "/api/orders/:id");
  assert.ok(readCand, "应解析出详情 route handler 的 IDOR 候选");
  assert.equal(readCand.kind, "idor-suspect");
  assert.equal(readCand.style, "next-api");
  assert.equal(readCand.hasAuth, true, "getServerSession 应识别为已认证");
  assert.equal(readCand.hasOwnerGuard, false);

  const cancelCand = a.candidates.find((c) => c.method === "POST" && c.path === "/api/orders/:id/cancel");
  assert.ok(cancelCand, "应解析出取消 route handler 的 IDOR 候选");

  assert.ok(
    !a.candidates.some((c) => c.path === "/api/orders"),
    "列表路由（findMany + 归属过滤）不应成为候选"
  );
  assert.ok(
    !a.candidates.some((c) => c.path === "/api/login"),
    "登录路由不应成为候选"
  );
  assert.ok(!a.candidates.some((c) => c.path === "/api/health"), "健康检查不应成为候选");

  assert.equal(a.diagnostics.nextRouteFiles, 5);
  assert.equal(a.diagnostics.nextSections, 5, "4 个 app handler + 1 个 pages handler");
  assert.equal(a.diagnostics.nextAppFiles, 4);

  const plan = buildProbePlan(a);
  assert.equal(plan.loginPath, "/api/login");
  assert.equal(plan.readCandidate?.path, "/api/orders/:id");
  assert.equal(plan.cancelCandidate?.path, "/api/orders/:id/cancel");
  assert.equal(plan.listEndpoint?.path, "/api/orders");
  assert.equal(plan.resource, "order");
});

test("createPatch: 风格门控——next-api 候选不套用 Express/method 注入", async () => {
  const calls = [];
  const nextContent = [
    'import { getServerSession } from "next-auth";',
    "export async function GET(req, { params }) {",
    "  const session = await getServerSession();",
    "  if (!session) return NextResponse.json({ error: '401' }, { status: 401 });",
    "  const order = await db.order.findUnique({ where: { id: Number(params.id) } });",
    "  if (!order) return NextResponse.json({ error: '404' }, { status: 404 });",
    "  return NextResponse.json({ order });",
    "}",
  ].join("\n");
  const ctx = {
    projectRoot: "D:/p",
    sessionId: "s1",
    tokens: { worktree: "tok_wt", project: "tok_p" },
    analysis: {
      candidates: [
        {
          kind: "idor-suspect",
          file: "D:/p/app/api/orders/[id]/route.ts",
          method: "GET",
          path: "/api/orders/:id",
          style: "next-api",
          resource: "order",
        },
      ],
    },
    emit: () => {},
    db: { insertPatch: () => {} },
    rpc: {
      request: async (method, params) => {
        calls.push({ method, params });
        if (method === "git.status") return { isRepo: true, entries: [] };
        if (method === "git.worktreeAdd") return { path: "D:/wt/fix-1" };
        if (method === "fs.list") return { entries: [] };
        if (method === "fs.stat") return {};
        if (method === "fs.read") return { content: nextContent, size: nextContent.length, redacted: false };
        if (method === "fs.write") return { appliedOps: 1, beforeSha256: "a", sha256: "b" };
        if (method === "git.diff") return { diff: "x", files: ["f"], patchHash: "h" };
        throw new Error(`不应调用 ${method}`);
      },
    },
  };
  await assert.rejects(
    () => createPatch(ctx),
    (e) => e.code === "no_patchable_candidates",
    "next-api 形态无修复策略：应归类为 vulnerable_unfixed 而非注入错误代码"
  );
  assert.ok(
    !calls.some((c) => c.method === "fs.write"),
    "风格门控生效：不得对 Next.js 文件写入 Express 风格补丁"
  );
});

test("createPatch: express 风格候选照常走 express 策略（门控不误伤）", async () => {
  const calls = [];
  const expressContent = [
    'router.get("/orders/:id", authenticate, async (req, res) => {',
    "  const order = await Order.findByPk(req.params.id);",
    '  if (!order) return res.status(404).json({ error: "not found" });',
    "  return res.json({ order });",
    "});",
  ].join("\n");
  const ctx = {
    projectRoot: "D:/p",
    sessionId: "s1",
    tokens: { worktree: "tok_wt", project: "tok_p" },
    analysis: {
      candidates: [
        {
          kind: "idor-suspect",
          file: "D:/p/src/app.js",
          method: "GET",
          path: "/orders/:id",
          style: "express",
          resource: "order",
        },
      ],
    },
    emit: () => {},
    db: { insertPatch: () => {} },
    rpc: {
      request: async (method, params) => {
        calls.push({ method, params });
        if (method === "git.status") return { isRepo: true, entries: [] };
        if (method === "git.worktreeAdd") return { path: "D:/wt/fix-2" };
        if (method === "fs.list") return { entries: [] };
        if (method === "fs.stat") return {};
        if (method === "fs.read") return { content: expressContent, size: expressContent.length, redacted: false };
        if (method === "fs.write") return { appliedOps: 1, beforeSha256: "a", sha256: "b" };
        if (method === "git.diff") return { diff: "diff", files: ["src/app.js"], patchHash: "h2" };
        throw new Error(`不应调用 ${method}`);
      },
    },
  };
  const out = await createPatch(ctx);
  const write = calls.find((c) => c.method === "fs.write");
  assert.ok(write, "express 候选应生成写入操作");
  assert.ok(write.params.ops.some((o) => o.replace.includes("req.user.id")), "应注入归属校验");
  assert.equal(out.filePatches[0].fixes[0].strategy, "express-owner-guard");
});
