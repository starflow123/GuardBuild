/**
 * NestJS 适配器单元测试：装饰器路由解析、类级守卫上下文注入、候选判定与探测计划。
 * 运行：npm run test:sidecar
 */
import test from "node:test";
import assert from "node:assert/strict";

import { extractControllers, extractControllerMethods, collectNestSections } from "../lib/nestjs.mjs";
import { analyzeProject } from "../lib/analyzer.mjs";
import { buildProbePlan } from "../lib/planner.mjs";
import { AUTH_GUARD, ROLE_GUARD, findQueryParamSink, findTraversalSignal } from "../lib/signals.mjs";

const R = "\\\\?\\D:\\proj"; // Host 返回的 Windows 扩展路径前缀形态

test("extractControllers: 控制器前缀（字面量/对象实参）与类级装饰器块", () => {
  const content = [
    'import { Controller, UseGuards } from "@nestjs/common";',
    "",
    "@UseGuards(JwtAuthGuard)",
    "// 订单控制器",
    '@Controller("orders")',
    "export class OrdersController {",
    "}",
    "",
    '@Controller({ path: "v1/users", version: "1" })',
    "export class UsersController {}",
  ].join("\n");
  const ctrls = extractControllers(content);
  assert.equal(ctrls.length, 2);
  assert.equal(ctrls[0].prefix, "orders");
  assert.ok(ctrls[0].headerText.includes("UseGuards(JwtAuthGuard)"), "注释行上方的类级守卫应纳入装饰器块");
  assert.ok(ctrls[0].headerText.includes("@Controller"), "");
  assert.equal(ctrls[1].prefix, "v1/users", "对象实参应取 path 属性而非首个字面量");
});

test("extractControllerMethods: 方法映射 / 签名前装饰器跳过 / 多装饰器叠加", () => {
  const content = [
    '@Controller("orders")',
    "export class OrdersController {",
    "  @Get()",
    "  list() { return []; }",
    "",
    '  @Get(":id")',
    "  @UseGuards(RolesGuard)",
    '  async detail(@Param("id") id: string) {',
    "    return this.ordersService.findOne(Number(id));",
    "  }",
    "",
    '  @Get(":id")',
    '  @Post(":id")',
    "  @All()",
    "  ping() { return 'pong'; }",
    "}",
  ].join("\n");
  const [ctrl] = extractControllers(content);
  const ms = extractControllerMethods(content, ctrl);
  const pairs = ms.map((m) => `${m.method} ${m.subPath || "(root)"}`);
  assert.deepEqual(pairs, ["GET (root)", "GET :id", "GET :id", "POST :id", "GET (root)"], "@All 按 GET 参与判定");
  const detail = ms.find((m) => m.subPath === ":id" && m.text.includes("findOne"));
  assert.ok(detail.text.includes("@UseGuards(RolesGuard)"), "装饰器与签名之间的方法级守卫应包含在区块文本中");
  assert.ok(detail.text.includes("async detail"), "");
});

test("collectNestSections: 全局前缀 + 控制器前缀 + 类级守卫注入（style=nest）", () => {
  const files = [
    { path: `${R}\\src\\main.ts`, content: 'const app = await NestFactory.create(AppModule);\napp.setGlobalPrefix("api");\n' },
    {
      path: `${R}\\src\\orders\\orders.controller.ts`,
      content: [
        'import { Controller, Get, UseGuards } from "@nestjs/common";',
        "@UseGuards(JwtAuthGuard)",
        '@Controller("orders")',
        "export class OrdersController {",
        '  @Get(":id")',
        '  async detail(@Param("id") id: string) {',
        "    return this.ordersService.findOne(Number(id));",
        "  }",
        "}",
      ].join("\n"),
    },
    { path: `${R}\\src\\db.ts`, content: "export const db = {};\n" },
  ];
  const { sections, diag } = collectNestSections(files);
  assert.equal(diag.nestFiles, 1);
  assert.equal(diag.nestControllers, 1);
  assert.equal(diag.nestHandlers, 1);
  assert.equal(diag.nestGlobalPrefix, "api");
  assert.equal(sections[0].declaredPath, "/api/orders/:id");
  assert.equal(sections[0].method, "GET");
  assert.equal(sections[0].style, "nest");
  assert.ok(sections[0].text.includes("UseGuards(JwtAuthGuard)"), "类级守卫应随区块文本下发");
});

test("signals: NestJS 守卫/角色装饰器覆盖，import 语句不误判", () => {
  assert.ok(AUTH_GUARD.test("@UseGuards(JwtAuthGuard)"));
  assert.ok(AUTH_GUARD.test("@UseGuards(AuthGuard('jwt'))"));
  assert.ok(!AUTH_GUARD.test('import { UseGuards } from "@nestjs/common";'), "import 语句不应视为守卫");
  assert.ok(ROLE_GUARD.test('@Roles("admin")'));
});

test("signals: findQueryParamSink 识别 @Query 参数绑定", () => {
  const text = [
    'async detail(@Query("id") id: string) {',
    "  return this.ordersService.findOne(Number(id));",
    "}",
  ].join("\n");
  assert.deepEqual(findQueryParamSink(text), { param: "id", form: "indirect" });
});

test("signals: findTraversalSignal 识别 @Query 输入合流", () => {
  const text = [
    'exportOrders(@Query("file") file: string) {',
    '  const target = path.join(__dirname, "..", "..", "public", file);',
    '  return fs.readFileSync(target, "utf8");',
    "}",
  ].join("\n");
  const sig = findTraversalSignal(text);
  assert.equal(sig?.source, "query");
  assert.equal(sig?.param, "file");
  assert.equal(sig?.sink, "readFileSync");
});

test("analyzeProject: NestJS 装饰器路由生成候选并规划探测（守卫/列表过滤正确识别）", async () => {
  const contents = new Map([
    [
      `${R}\\src\\main.ts`,
      'import { NestFactory } from "@nestjs/core";\nconst app = await NestFactory.create(AppModule);\napp.setGlobalPrefix("api");\n',
    ],
    [
      `${R}\\src\\orders\\orders.controller.ts`,
      [
        'import { ConflictException, Controller, Get, NotFoundException, Param, Post, Query, Req, UseGuards } from "@nestjs/common";',
        'import * as fs from "node:fs";',
        'import * as path from "node:path";',
        "",
        "interface AuthedRequest { user: { id: string; role: string } }",
        "",
        "@UseGuards(JwtAuthGuard)",
        '@Controller("orders")',
        "export class OrdersController {",
        "  constructor(private readonly ordersService: OrdersService) {}",
        "",
        "  @Get()",
        "  list(@Req() req: AuthedRequest) {",
        "    return { orders: this.ordersService.findAll({ where: { userId: req.user.id } }) };",
        "  }",
        "",
        '  @Get("export")',
        '  exportOrders(@Query("file") file: string) {',
        '    const target = path.join(__dirname, "..", "..", "public", file);',
        '    return fs.readFileSync(target, "utf8");',
        "  }",
        "",
        '  @Get(":id")',
        '  async detail(@Param("id") id: string) {',
        "    const order = await this.ordersService.findOne(Number(id));",
        '    if (!order) throw new NotFoundException("订单不存在");',
        "    return { order };",
        "  }",
        "",
        '  @Post(":id/cancel")',
        '  async cancel(@Param("id") id: string) {',
        "    const order = await this.ordersService.findOne(Number(id));",
        '    if (!order) throw new NotFoundException("订单不存在");',
        '    if (order.status !== "paid") throw new ConflictException("当前订单状态不可取消");',
        "    return { ok: true, order: await this.ordersService.markCancelled(order.id) };",
        "  }",
        "}",
      ].join("\n"),
    ],
    [
      `${R}\\src\\auth\\auth.controller.ts`,
      [
        'import { Body, Controller, Post, UnauthorizedException } from "@nestjs/common";',
        "",
        '@Controller("auth")',
        "export class AuthController {",
        '  @Post("login")',
        "  login(@Body() dto: { email: string; password: string }) {",
        "    return this.authService.login(dto.email, dto.password);",
        "  }",
        "}",
      ].join("\n"),
    ],
    [`${R}\\src\\app.module.ts`, "export class AppModule {}\n"],
  ]);
  const listing = { entries: [...contents.keys()].map((p) => ({ path: p, kind: "file", size: 400 })) };
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
  assert.ok(readCand, "详情接口应解析为 IDOR 候选");
  assert.equal(readCand.kind, "idor-suspect");
  assert.equal(readCand.style, "nest");
  assert.equal(readCand.hasAuth, true, "类级 @UseGuards 应识别为已认证");
  assert.equal(readCand.hasOwnerGuard, false);
  assert.equal(readCand.resource, "order", "ordersService.findOne 应归约为资源名 order");

  const cancelCand = a.candidates.find((c) => c.method === "POST" && c.path === "/api/orders/:id/cancel");
  assert.ok(cancelCand, "取消接口应解析为 IDOR 候选");

  const travCand = a.candidates.find((c) => c.kind === "traversal-suspect");
  assert.ok(travCand, "导出接口的 @Query 文件读取应解析为穿越候选");
  assert.equal(travCand.path, "/api/orders/export");
  assert.deepEqual(travCand.traversal, { source: "query", param: "file", sink: "readFileSync" });

  assert.ok(!a.candidates.some((c) => c.path === "/api/orders"), "列表接口（归属过滤）不应成为候选");
  assert.ok(!a.candidates.some((c) => c.path === "/api/auth/login"), "登录接口不应成为候选");

  assert.equal(a.diagnostics.nestControllers, 2);
  assert.equal(a.diagnostics.nestGlobalPrefix, "api");

  const plan = buildProbePlan(a);
  assert.equal(plan.readCandidate?.path, "/api/orders/:id");
  assert.equal(plan.cancelCandidate?.path, "/api/orders/:id/cancel");
  assert.equal(plan.traversalCandidate?.path, "/api/orders/export");
  assert.equal(plan.listEndpoint?.path, "/api/orders");
  assert.equal(plan.resource, "order");
});
