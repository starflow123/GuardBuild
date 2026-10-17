/**
 * GraphQL 适配器单元测试：SDL 解析（类型/参数/枚举/选取集）、三层鉴权信号
 * （字段指令 / resolver 映射表 / shield 规则 / 装饰器）、候选判定与探测计划，
 * 以及线协议（文档构造 / 登录 mutation / introspection / 两种拒绝语义）。
 *
 * 静态侧直接跑在 fixtures/graphql-shop 的真实源码上（schema.graphql + src/resolvers.mjs），
 * 因此这里同时是「靶场源码可被解析」的回归防线。
 * 运行：npm run test:sidecar
 */
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  collectGraphqlSections,
  detectGraphqlEndpoint,
  normalizeType,
  parseSdl,
  pickAddressArg,
  selectionFor,
} from "../lib/graphql.mjs";
import {
  castArg,
  graphqlDocument,
  graphqlLoginRequest,
  graphqlPlainRequest,
  graphqlRequest,
  graphqlShapeRejected,
  isGraphqlCandidate,
  isGraphqlDenied,
  isGraphqlEnvelope,
  looksLikeGraphqlPath,
  parseIntrospection,
  unwrapGraphqlEnvelope,
} from "../lib/graphqlwire.mjs";
import { analyzeProject } from "../lib/analyzer.mjs";
import { buildProbePlan } from "../lib/planner.mjs";
import { createPatch } from "../lib/patcher.mjs";

const fixtureRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../fixtures/graphql-shop");

function loadFixtureFiles() {
  const out = [];
  const walk = (dir) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (e.name === "node_modules" || e.name === ".git") continue;
        walk(p);
        continue;
      }
      if (!/\.(graphql|gql|ts|tsx|mjs|js)$/.test(e.name)) continue;
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

// —— SDL 解析 ——

test("normalizeType: 列表/非空包装逐层剥开", () => {
  assert.deepEqual(normalizeType("[Order!]!").base, "Order");
  assert.equal(normalizeType("[Order!]!").list, true);
  assert.equal(normalizeType("[Order!]!").nonNull, true);
  assert.deepEqual(normalizeType("Int"), { base: "Int", list: false, nonNull: false, raw: "Int" });
});

test("parseSdl: 字段参数、指令、枚举类型名与 extend 合并", () => {
  const sdl = readFileSync(path.join(fixtureRoot, "schema.graphql"), "utf8");
  const { types, enums } = parseSdl(sdl);
  const query = types.get("Query");
  const order = query.fields.find((f) => f.name === "order");
  assert.deepEqual(order.args, [{ name: "id", type: normalizeType("Int!") }]);
  assert.match(order.directives, /@auth/, "字段指令应随字段定义保留");
  assert.equal(query.fields.find((f) => f.name === "adminOrders").directives.includes("@hasRole(role: \"ADMIN\")"), true);
  // 枚举收的是「类型名」：选取集据此把 status: OrderStatus! 当作标量叶子
  assert.ok(enums.has("OrderStatus"));
  assert.equal(types.get("Order").fields.find((f) => f.name === "status").type.base, "OrderStatus");

  // extend type Query 与主定义合并
  const merged = parseSdl("extend type Query { extra: Int! }");
  assert.equal(merged.types.get("Query").fields[0].name, "extra");
});

test("selectionFor: 标量/枚举行保留，对象字段展开一层，列表对象不展开", () => {
  const sdl = readFileSync(path.join(fixtureRoot, "schema.graphql"), "utf8");
  const { types, enums, scalars } = parseSdl(sdl);
  const orderSel = selectionFor(types, enums, scalars, "Order");
  assert.ok(orderSel.includes("id"));
  assert.ok(orderSel.includes("status"), "枚举字段必须在选取集里（取消类证据依赖状态字段）");
  const authSel = selectionFor(types, enums, scalars, "AuthPayload");
  assert.ok(authSel.includes("token"), "登录响应必须取回 token");
  assert.ok(authSel.includes("user { id email name role }"), "对象字段展开一层供归属比对");
});

test("pickAddressArg: 单标量 ID 参数 / Prisma 式 input 对象 / 多 ID 无法定主键", () => {
  const scalar = pickAddressArg([{ name: "id", type: normalizeType("Int!") }], new Map());
  assert.deepEqual(scalar, { form: "scalar", name: "id", typeName: "Int", nonNull: true });

  const { types } = parseSdl("input OrderWhereInput { id: Int!  note: String }");
  const input = pickAddressArg([{ name: "where", type: normalizeType("OrderWhereInput!") }], types);
  assert.deepEqual(input, {
    form: "input",
    name: "where",
    inputType: "OrderWhereInput",
    field: "id",
    typeName: "Int",
    nonNull: true,
  });

  assert.equal(
    pickAddressArg(
      [
        { name: "fromId", type: normalizeType("Int!") },
        { name: "toId", type: normalizeType("Int!") },
      ],
      new Map()
    ),
    null,
    "两个 ID 参数无法确定对象主键"
  );
  assert.equal(pickAddressArg([{ name: "limit", type: normalizeType("Int") }], new Map()), null);
});

// —— 端点发现 ——

test("detectGraphqlEndpoint: 接线显式路径 > Next.js 文件位置 > 缺省 /graphql", () => {
  assert.equal(
    detectGraphqlEndpoint([
      { path: "/p/src/server.js", content: 'server.applyMiddleware({ app, path: "/api/gql" });' },
    ]),
    "/api/gql",
    "Apollo applyMiddleware 的 path 是权威端点（可不含 graphql 字样）"
  );
  assert.equal(
    detectGraphqlEndpoint([{ path: "/p/src/server.js", content: 'app.use("/api/graphql", graphqlHTTP({ schema }))' }]),
    "/api/graphql"
  );
  assert.equal(
    detectGraphqlEndpoint(
      [{ path: "/p/app/api/graphql/route.ts", content: "export const POST = handler;" }],
      "/p"
    ),
    "/api/graphql",
    "App Router 文件位置推导须保留 graphql 段"
  );
  assert.equal(detectGraphqlEndpoint([{ path: "/p/src/resolvers.ts", content: "export const resolvers = {};" }]), "/graphql");
});

// —— 三层鉴权信号 ——

test("collectFieldImplementations: resolver 映射表 / shield 规则 / 装饰器方法体", () => {
  const resolverFile = {
    path: "/p/src/resolvers.mjs",
    content: [
      'import { ApolloServer } from "@apollo/server";',
      "const typeDefs = `type Query { order(id: Int!): Order!  report(id: Int!): Report! }",
      "type Order { id: Int! total: Int! }",
      "type Report { id: Int! name: String! }`;",
      "const resolvers = {",
      "  Query: {",
      "    order: async (_, { id }, ctx) => {",
      "      const order = await db.order.findUnique({ where: { id } });",
      "      return order;",
      "    },",
      "    report: () => reports,",
      "  },",
      "};",
      "const permissions = shield({ Query: { report: isAuthenticated } });",
    ].join("\n"),
  };
  const scan = collectGraphqlSections([resolverFile], "/p");
  const byKey = Object.fromEntries(scan.sections.map((s) => [`${s.graphql.root}.${s.graphql.field}`, s]));
  // order 的 resolver 体不含会话读取 → 无鉴权线索（映射表解析成功才会走到这里）
  assert.equal(byKey["Query.order"].forcedAuth, undefined);
  assert.match(byKey["Query.order"].text, /findUnique/);
  // shield 规则 isAuthenticated → 认证信号
  assert.equal(byKey["Query.report"].forcedAuth, true);
});

test("collectGraphqlSections: code-first 装饰器（@UseGuards + @Query）与 SDL 合并", () => {
  const file = {
    path: "/p/src/invoice.resolver.ts",
    content: [
      'import { Resolver, Query, Args } from "@nestjs/graphql";',
      "const typeDefs = `type Query { invoice(id: Int!): Invoice! }",
      "type Invoice { id: Int! total: Int! }`;",
      '@Resolver(() => Invoice)',
      "export class InvoiceResolver {",
      "  @UseGuards(JwtAuthGuard)",
      "  @Query(() => Invoice)",
      "  async invoice(@Args(\"id\") id: number) {",
      "    return this.repo.findById(id);",
      "  }",
      "}",
    ].join("\n"),
  };
  const scan = collectGraphqlSections([file], "/p");
  const invoice = scan.sections.find((s) => s.graphql?.field === "invoice");
  assert.ok(invoice, "装饰器方法应归集到 Query.invoice");
  assert.equal(invoice.forcedAuth, true, "类/方法级 @UseGuards 视为认证守卫");
  assert.equal(invoice.graphql.arg.form, "scalar");
});

test("collectGraphqlSections: input 对象参数可寻址，多 ID 参数不可寻址", () => {
  const file = {
    path: "/p/src/schema.graphql",
    content: [
      "type Query {",
      "  order(where: OrderWhereInput!): Order! @auth",
      "  transfer(fromId: Int!, toId: Int!): Transfer! @auth",
      "}",
      "input OrderWhereInput { id: Int! note: String }",
      "type Order { id: Int! total: Int! }",
      "type Transfer { id: Int! }",
    ].join("\n"),
  };
  const scan = collectGraphqlSections([file], "/p");
  const byField = Object.fromEntries(scan.sections.map((s) => [s.graphql.field, s]));
  assert.equal(byField.order.graphql.addressable, true);
  assert.equal(byField.order.graphql.arg.form, "input");
  assert.equal(byField.order.graphql.arg.field, "id");
  assert.equal(byField.transfer.graphql.addressable, false);
});

// —— 靶场整体：候选 / 计划 / 补丁门控 ——

test("collectGraphqlSections: 靶场登录字段与字段级区块（含指令鉴权）", () => {
  const { sections, endpoint, login, diag } = collectGraphqlSections(fixtureFiles, fixtureRoot);
  assert.equal(endpoint, "/graphql");
  assert.equal(login.field, "login");
  assert.deepEqual(login.args.map((a) => a.name), ["email", "password"]);
  assert.ok(login.selection.includes("token"));
  assert.equal(diag.graphqlLoginField, "login");

  const byKey = Object.fromEntries(sections.map((s) => [`${s.graphql.root}.${s.graphql.field}`, s]));
  assert.equal(Object.keys(byKey).length, 7, "SDL 根字段 4 查询 + 3 变更");
  assert.equal(byKey["Query.order"].forcedAuth, true);
  assert.equal(byKey["Query.order"].graphql.addressable, true);
  assert.equal(byKey["Query.receipt"].forcedAuth, undefined, "@skipAuth 覆盖全局/指令推断");
  assert.equal(byKey["Query.adminOrders"].roleGuard, true);
  assert.equal(byKey["Mutation.adminCancelOrder"].roleGuard, true);
  assert.equal(byKey["Query.myOrders"].graphql.list, true);
  assert.equal(byKey["Query.myOrders"].graphql.addressable, false);
});

test("analyzeProject: GraphQL 靶场恰好 3 条字段级候选，登录/列表/管理字段不误报", async () => {
  const a = await analyzeFixture();
  assert.equal(a.graphql.endpoint, "/graphql");
  assert.deepEqual(
    a.candidates.map((c) => `${c.routeKeys[0]}:${c.kind}`).sort(),
    ["Mutation.cancelOrder:idor-suspect", "Query.order:idor-suspect", "Query.receipt:no-auth-suspect"]
  );
  const order = a.candidates.find((c) => c.routeKeys[0] === "Query.order");
  assert.equal(order.method, "POST");
  assert.equal(order.fullPath, "/graphql");
  assert.equal(order.style, "graphql");
  assert.equal(order.hasAuth, true);
  assert.equal(order.resource, "order");
  assert.ok(order.startLine > 0);
  const receipt = a.candidates.find((c) => c.routeKeys[0] === "Query.receipt");
  assert.equal(receipt.hasAuth, false);
  assert.equal(receipt.resource, "receipt");
  // 单端点模型：所有候选共用 /graphql，候选全靠 routeKeys 区分
  assert.equal(a.candidates.every((c) => c.fullPath === "/graphql"), true);
});

test("buildProbePlan: 字段级槽位（读/取消/匿名读/列表/管理）与登录候选", async () => {
  const a = await analyzeFixture();
  const plan = buildProbePlan(a, { loginPathOverride: "/graphql" });
  assert.equal(plan.loginCandidates[0], "/graphql");
  assert.ok(plan.loginCandidates.includes("/api/login"), "保留 REST 兜底登录端点");
  assert.equal(plan.graphql.login.field, "login");
  assert.equal(plan.readCandidates[0].routeKeys[0], "Query.order");
  assert.equal(plan.cancelCandidates[0].routeKeys[0], "Mutation.cancelOrder");
  assert.equal(plan.unauthReadCandidates[0].routeKeys[0], "Query.receipt");
  assert.equal(plan.listEndpoint.routeKey, "Query.myOrders");
  assert.equal(plan.listEndpoint.method, "POST", "GraphQL 列表仍走 POST 文档");
  assert.equal(plan.adminListEndpoint.routeKey, "Query.adminOrders");
  assert.equal(plan.adminCancelEndpoint.routeKey, "Mutation.adminCancelOrder");
  assert.equal(plan.resource, "order");
});

test("createPatch: 风格门控——GraphQL 候选不套用 Express/method 注入 → 人工修复", async () => {
  const calls = [];
  const ctx = {
    projectRoot: "D:/p",
    sessionId: "s1",
    tokens: { worktree: "tok_wt", project: "tok_p" },
    analysis: {
      candidates: [
        {
          kind: "idor-suspect",
          file: "D:/p/src/resolvers.mjs",
          method: "POST",
          path: "/graphql",
          fullPath: "/graphql",
          style: "graphql",
          resource: "order",
          routeKeys: ["Query.order"],
          graphql: { root: "Query", op: "query", field: "order", addressable: true },
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
        if (method === "fs.read") return { content: "export const resolvers = {};", size: 40, redacted: false, redactions: [] };
        throw new Error(`不应调用 ${method}`);
      },
    },
  };
  await assert.rejects(
    () => createPatch(ctx),
    (e) => e.code === "no_patchable_candidates" && /人工修复/.test(e.hint),
    "GraphQL 鉴权分散在 middleware/shield/resolver，不应自动注入"
  );
  assert.ok(!calls.includes("fs.write"), "不得对 GraphQL 源码写入 Express 风格补丁");
});

// —— 线协议 ——

test("graphqlDocument / graphqlRequest: 标量参数按 SDL 类型投放，input 对象嵌套", () => {
  const scalar = graphqlDocument(
    { field: "order", op: "query", arg: { form: "scalar", name: "id", typeName: "Int" }, selection: ["id", "status"] },
    7001
  );
  assert.equal(scalar.query, "query GuardbuildProbe($id: Int!) { order(id: $id) { id status } }");
  assert.deepEqual(scalar.variables, { id: 7001 });
  assert.deepEqual(graphqlDocument({ field: "order", op: "query", arg: { form: "scalar", name: "id", typeName: "Int" }, selection: ["id"] }, "7001", true).variables, { id: "7001" });

  const input = graphqlDocument(
    {
      field: "order",
      op: "query",
      arg: { form: "input", name: "where", inputType: "OrderWhereInput", field: "id", typeName: "Int" },
      selection: ["id"],
    },
    7
  );
  assert.equal(input.query, "query GuardbuildProbe($where: OrderWhereInput!) { order(where: $where) { id } }");
  assert.deepEqual(input.variables, { where: { id: 7 } });

  const cand = {
    fullPath: "/graphql",
    graphql: { field: "order", op: "query", arg: { form: "scalar", name: "id", typeName: "Int" }, selection: ["id"] },
  };
  const req = graphqlRequest(cand, 3);
  assert.equal(req.method, "POST");
  assert.equal(req.path, "/graphql");
  assert.equal(req.graphql, true);
  assert.deepEqual(JSON.parse(req.body), {
    query: "query GuardbuildProbe($id: Int!) { order(id: $id) { id } }",
    variables: { id: 3 },
  });
  assert.equal(graphqlRequest({ fullPath: "/api/x" }, 1), null);
  assert.equal(castArg("9", "ID"), "9");
});

test("graphqlPlainRequest / graphqlLoginRequest: 列表文档与登录 mutation", () => {
  const list = graphqlPlainRequest({ field: "myOrders", op: "query", selection: ["id"] }, "/graphql");
  assert.equal(JSON.parse(list.body).query, "query GuardbuildList { myOrders { id } }");

  const login = {
    path: "/graphql",
    field: "login",
    args: [
      { name: "email", typeName: "String", list: false },
      { name: "password", typeName: "String", list: false },
    ],
    selection: ["token", "user { id }"],
  };
  const req = graphqlLoginRequest(login, { email: "a@b.c", password: "pw" });
  const doc = JSON.parse(req.body);
  assert.equal(
    doc.query,
    "mutation GuardbuildLogin($email: String!, $password: String!) { login(email: $email, password: $password) { token user { id } } }"
  );
  assert.deepEqual(doc.variables, { email: "a@b.c", password: "pw" });
  // 缺参数（例如 SDL 被脱敏/契约字段不全）不可构造，交由上层给可行动报错
  assert.equal(graphqlLoginRequest(login, { email: "a@b.c" }), null);
  assert.equal(graphqlLoginRequest({ ...login, selection: [] }, { email: "a@b.c", password: "pw" }).body.includes("login(email"), true);
});

test("parseIntrospection: 运行时根字段/参数类型/对象标量字段", () => {
  const nonNull = (ofType) => ({ kind: "NON_NULL", name: null, ofType });
  const json = {
    data: {
      __schema: {
        queryType: {
          name: "Query",
          fields: [
            {
              name: "order",
              type: nonNull({ kind: "OBJECT", name: "Order", ofType: null }),
              args: [{ name: "id", type: nonNull({ kind: "SCALAR", name: "Int" }) }],
            },
            {
              name: "myOrders",
              type: nonNull({ kind: "LIST", ofType: nonNull({ kind: "OBJECT", name: "Order", ofType: null }) }),
              args: [],
            },
          ],
        },
        mutationType: {
          name: "Mutation",
          fields: [
            { name: "login", type: { kind: "OBJECT", name: "AuthPayload", ofType: null }, args: [] },
          ],
        },
        types: [
          {
            kind: "OBJECT",
            name: "Order",
            fields: [
              { name: "id", type: nonNull({ kind: "SCALAR", name: "Int" }) },
              { name: "status", type: { kind: "ENUM", name: "OrderStatus" } },
              { name: "items", type: { kind: "LIST", offType: null, ofType: { kind: "OBJECT", name: "OrderItem" } } },
            ],
          },
        ],
      },
    },
  };
  const info = parseIntrospection(json);
  assert.equal(info.queryType, "Query");
  assert.equal(info.fields["Query.order"].returns, "Order");
  assert.equal(info.fields["Query.order"].list, false);
  assert.deepEqual(info.fields["Query.order"].args, [{ name: "id", typeName: "Int", list: false }]);
  assert.equal(info.fields["Query.myOrders"].list, true);
  assert.equal(info.fields["Mutation.login"].op, "mutation");
  assert.deepEqual(info.types.Order, ["id", "status"], "对象类型的列表字段不展开");
  assert.equal(parseIntrospection({ errors: [] }), null);
});

test("信封与拒绝语义: data 解开、UNAUTHENTICATED/FORBIDDEN 算拒绝、NOT_FOUND/CONFLICT 不算", () => {
  assert.equal(isGraphqlEnvelope({ data: { order: 1 } }), true);
  assert.equal(isGraphqlEnvelope({ data: null, errors: [] }), true);
  assert.equal(isGraphqlEnvelope({ result: { data: 1 } }), false);
  assert.deepEqual(unwrapGraphqlEnvelope({ data: { order: { id: 1 } } }), { order: { id: 1 } });
  assert.deepEqual(unwrapGraphqlEnvelope({ ok: true }), { ok: true });

  assert.equal(isGraphqlDenied({ errors: [{ extensions: { code: "UNAUTHENTICATED" } }] }), true);
  assert.equal(isGraphqlDenied({ errors: [{ extensions: { code: "FORBIDDEN" } }] }), true);
  assert.equal(isGraphqlDenied({ errors: [{ message: "Not authenticated" }] }), true);
  assert.equal(isGraphqlDenied({ errors: [{ extensions: { code: "NOT_FOUND" } }] }), false);
  assert.equal(isGraphqlDenied({ errors: [{ extensions: { code: "CONFLICT" } }] }), false);
  assert.equal(isGraphqlDenied({ data: { order: null } }), false);
  assert.equal(isGraphqlDenied({ errors: [] }), false);

  assert.equal(graphqlShapeRejected({ status: 400 }), true);
  assert.equal(graphqlShapeRejected({ status: 200, jsonRaw: { errors: [{ extensions: { code: "GRAPHQL_VALIDATION_FAILED" } }] } }), true);
  assert.equal(graphqlShapeRejected({ status: 403, jsonRaw: { errors: [{ extensions: { code: "FORBIDDEN" } }] } }), false);

  assert.equal(looksLikeGraphqlPath("/graphql"), true);
  assert.equal(looksLikeGraphqlPath("/api/graphql/"), true);
  assert.equal(looksLikeGraphqlPath("/api/login"), false);
  assert.equal(isGraphqlCandidate({ graphql: { field: "order" } }), true);
  assert.equal(isGraphqlCandidate({ trpc: {} }), false);
});
