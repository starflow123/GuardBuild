import http from "node:http";
import { authenticate, login } from "./src/auth.mjs";
import { findOrderById, findReceiptByOrderId, listOrdersOf, store } from "./src/store.mjs";

/*
 * 运行时垫片（shim）：以纯 Node HTTP 复刻 schema-first GraphQL 服务（express-graphql /
 * Apollo Server / graphql-yoga）的线上协议语义。
 *
 * 说明：这不是 GraphQL 运行时本体。被测的静态对象是 schema.graphql 与 src/resolvers.mjs
 * 里的真实源码（字段指令 + 解析器函数体），动态探测层只需要「单一 POST 端点 + {query,variables}
 * 请求体 + {data}/{errors} 信封」，因此这里用等价 HTTP 契约承载动态复现，CI 无需安装任何依赖。
 *
 * 与环境变量对齐的三个可观测开关（e2e 三轮分别覆盖）：
 *  1) GRAPHQL_ERROR_STATUS=mapped（默认）：拒绝语义按错误码映射 HTTP 状态
 *     （UNAUTHENTICATED 401 / FORBIDDEN 403 / NOT_FOUND 404 / CONFLICT 409），
 *     Apollo Server v2/v3 与自行 res 的写法属这一流派；
 *     GRAPHQL_ERROR_STATUS=inline：一律 HTTP 200 + errors[].extensions.code（Apollo v4 形态），
 *     此时「越权被拒绝」在 HTTP 层不可判，必须由探测层识别 errors 语义。
 *  2) GRAPHQL_INTROSPECTION=off：关闭内省（生产环境常见），探测层需完全按源码 SDL 构造文档。
 *  3) 参数类型校验：文档声明的变量类型与 schema 不符（例如把 Int! 传成字符串）一律 400 +
 *     GRAPHQL_VALIDATION_FAILED，与真实运行时一致，供 ID 投放形态协商试错。
 */

const ENDPOINT = "/graphql";
const INLINE_ERROR_STATUS = process.env.GRAPHQL_ERROR_STATUS === "inline";
const INTROSPECTION_ENABLED = process.env.GRAPHQL_INTROSPECTION !== "off";

const CODE_STATUS = {
  UNAUTHENTICATED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  BAD_REQUEST: 400,
  GRAPHQL_VALIDATION_FAILED: 400,
  CONFLICT: 409,
  INTERNAL_SERVER_ERROR: 500,
};

class GqlError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

/**
 * 字段表（键为「根类型.字段名」）：与 schema.graphql + src/resolvers.mjs 一一对应。
 * auth: "user" 需登录、"admin" 需管理员、null 为公开字段（对应 SDL 的 @skipAuth）。
 * 刻意写成扁平键，避免与本仓库静态分析器的 resolver 映射表形态（Query: {…}）混淆：
 * 运行时实现不是被测对象，静态候选必须唯一来自 schema.graphql 与 src/resolvers.mjs。
 */
const fields = {
  "Query.order": {
    auth: "user",
    args: { id: "Int" },
    resolve: ({ id }) => {
      const order = findOrderById(id);
      if (!order) throw new GqlError("NOT_FOUND", "订单不存在");
      return order; // 复刻漏洞：未校验订单归属
    },
  },
  "Query.myOrders": {
    auth: "user",
    args: {},
    resolve: (_vars, ctx) => listOrdersOf(ctx.user.id),
  },
  "Query.receipt": {
    auth: null,
    args: { id: "Int" },
    resolve: ({ id }) => {
      const receipt = findReceiptByOrderId(id);
      if (!receipt) throw new GqlError("NOT_FOUND", "小票不存在");
      return receipt; // 复刻漏洞：字段本身公开，匿名即可取回他人地址与金额
    },
  },
  "Query.adminOrders": {
    auth: "admin",
    args: {},
    resolve: (_vars, ctx) => {
      if (ctx.user.role !== "admin") throw new GqlError("FORBIDDEN", "仅管理员可访问");
      return store.orders;
    },
  },
  "Mutation.login": {
    auth: null,
    args: { email: "String", password: "String" },
    resolve: ({ email, password }) => {
      const session = login(email, password);
      if (!session) throw new GqlError("UNAUTHENTICATED", "邮箱或密码错误");
      return session;
    },
  },
  "Mutation.cancelOrder": {
    auth: "user",
    args: { id: "Int" },
    resolve: ({ id }) => {
      const order = findOrderById(id);
      if (!order) throw new GqlError("NOT_FOUND", "订单不存在");
      if (order.status !== "paid") throw new GqlError("CONFLICT", "当前订单状态不可取消");
      order.status = "cancelled"; // 复刻漏洞：未校验归属即可取消他人订单
      return order;
    },
  },
  "Mutation.adminCancelOrder": {
    auth: "admin",
    args: { id: "Int" },
    resolve: ({ id }, ctx) => {
      if (ctx.user.role !== "admin") throw new GqlError("FORBIDDEN", "仅管理员可访问");
      const order = findOrderById(id);
      if (!order) throw new GqlError("NOT_FOUND", "订单不存在");
      if (order.status !== "paid") throw new GqlError("CONFLICT", "当前订单状态不可取消");
      order.status = "cancelled";
      return order;
    },
  },
};

// —— introspection 表：与 schema.graphql 一致的运行时 schema（探测层仅用于确认端点与校正类型）——
const nonNull = (kind, name) => ({ kind: "NON_NULL", name: null, ofType: { kind, name, ofType: null } });
const list = (kind, name) => ({ kind: "LIST", name: null, ofType: nonNull(kind, name) });
const arg = (name, kind, t) => ({ name, type: nonNull(kind, t) });
const objFields = (names) =>
  names.map(([n, kind, t]) => ({ name: n, type: { kind, name: t, ofType: null } }));

const INTROSPECTION = {
  __schema: {
    queryType: {
      name: "Query",
      fields: [
        { name: "order", args: [arg("id", "SCALAR", "Int")], type: nonNull("OBJECT", "Order") },
        { name: "myOrders", args: [], type: list("OBJECT", "Order") },
        { name: "receipt", args: [arg("id", "SCALAR", "Int")], type: nonNull("OBJECT", "Receipt") },
        { name: "adminOrders", args: [], type: list("OBJECT", "Order") },
      ],
    },
    mutationType: {
      name: "Mutation",
      fields: [
        {
          name: "login",
          args: [arg("email", "SCALAR", "String"), arg("password", "SCALAR", "String")],
          type: nonNull("OBJECT", "AuthPayload"),
        },
        { name: "cancelOrder", args: [arg("id", "SCALAR", "Int")], type: nonNull("OBJECT", "Order") },
        { name: "adminCancelOrder", args: [arg("id", "SCALAR", "Int")], type: nonNull("OBJECT", "Order") },
      ],
    },
    types: [
      { kind: "OBJECT", name: "Order", fields: objFields([["id", "SCALAR", "Int"], ["userId", "SCALAR", "String"], ["title", "SCALAR", "String"], ["amount", "SCALAR", "Int"], ["status", "ENUM", "OrderStatus"], ["address", "SCALAR", "String"]]) },
      { kind: "OBJECT", name: "Receipt", fields: objFields([["id", "SCALAR", "Int"], ["userId", "SCALAR", "String"], ["title", "SCALAR", "String"], ["amount", "SCALAR", "Int"], ["status", "ENUM", "OrderStatus"], ["address", "SCALAR", "String"]]) },
      { kind: "OBJECT", name: "User", fields: objFields([["id", "SCALAR", "String"], ["email", "SCALAR", "String"], ["name", "SCALAR", "String"], ["role", "SCALAR", "String"]]) },
      { kind: "OBJECT", name: "AuthPayload", fields: objFields([["token", "SCALAR", "String"], ["user", "OBJECT", "User"]]) },
      { kind: "ENUM", name: "OrderStatus", fields: [] },
    ],
  },
};

function json(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(payload),
  });
  res.end(payload);
}

const errBody = (code, message) => ({ errors: [{ message, extensions: { code } }] });
const fail = (res, err) =>
  json(res, INLINE_ERROR_STATUS && err.code !== "GRAPHQL_VALIDATION_FAILED" ? 200 : CODE_STATUS[err.code] ?? 500, errBody(err.code, err.message));

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

/** 从查询文档取出顶层字段：`query X($v: Int!) { order(id: $v) { id } }` → {root:"Query", name:"order", args:{id:"v"}, typeName:{v:"Int"}} */
function parseDocument(query) {
  const text = String(query ?? "");
  const opM = /^\s*(query|mutation)\s*(?:[A-Za-z_]\w*)?\s*(\(([^)]*)\))?/.exec(text);
  if (!opM) throw new GqlError("GRAPHQL_PARSE_FAILED", "无法解析操作");
  const root = opM[1] === "mutation" ? "Mutation" : "Query";
  const declared = {};
  for (const d of String(opM[3] ?? "").matchAll(/\$([A-Za-z_]\w*)\s*:\s*([\w![\]]+)/g)) {
    declared[d[1]] = d[2].replace(/!$/, "").replace(/[\[!\]]/g, "");
  }
  const bodyStart = text.indexOf("{", opM.index + opM[0].length);
  if (bodyStart < 0) throw new GqlError("GRAPHQL_PARSE_FAILED", "缺少选择集");
  const rest = text.slice(bodyStart + 1);
  const fieldM = /^\s*(?:\w+\s*:\s*)?([A-Za-z_]\w*)\s*(\(([^)]*)\))?/.exec(rest);
  if (!fieldM) throw new GqlError("GRAPHQL_PARSE_FAILED", "缺少字段选择");
  const args = {};
  for (const a of String(fieldM[3] ?? "").matchAll(/([A-Za-z_]\w*)\s*:\s*\$([A-Za-z_]\w*)/g)) {
    args[a[1]] = a[2];
  }
  const inline = {};
  for (const a of String(fieldM[3] ?? "").matchAll(/([A-Za-z_]\w*)\s*:\s*(?!$)([^\s,)]+)/g)) {
    if (a[2].startsWith("$")) continue;
    inline[a[1]] = a[2].replace(/^"|"$/g, "");
  }
  return { root, name: fieldM[1], args, inline, declared };
}

/** 变量与字面量的类型校验（对齐 graphql-js 的变量强转失败 → GRAPHQL_VALIDATION_FAILED） */
function bindArgs(field, doc, variables) {
  const expected = field.args;
  const out = {};
  const wantType = (name, typeName, value) => {
    if (typeName === "Int" || typeName === "Float") {
      const n = Number(value);
      if (typeof value === "string" && !/^[-+]?\d+(\.\d+)?$/.test(value.trim())) {
        throw new GqlError("GRAPHQL_VALIDATION_FAILED", `变量 ${name} 不是合法的 ${typeName}`);
      }
      if (!Number.isFinite(n)) throw new GqlError("GRAPHQL_VALIDATION_FAILED", `变量 ${name} 不是合法的 ${typeName}`);
      return n;
    }
    return String(value ?? "");
  };
  for (const [name, typeName] of Object.entries(expected)) {
    const varName = doc.args[name];
    if (varName !== undefined) {
      if (!(varName in variables)) throw new GqlError("GRAPHQL_VALIDATION_FAILED", `缺少变量 $${varName}`);
      if (doc.declared[varName] && doc.declared[varName] !== typeName) {
        throw new GqlError("GRAPHQL_VALIDATION_FAILED", `变量 $${varName} 声明为 ${doc.declared[varName]}!，字段要求 ${typeName}!`);
      }
      out[name] = wantType(name, typeName, variables[varName]);
      continue;
    }
    if (doc.inline[name] !== undefined) {
      out[name] = wantType(name, typeName, doc.inline[name]);
      continue;
    }
    throw new GqlError("GRAPHQL_VALIDATION_FAILED", `字段缺少必需的 ${name}: ${typeName}! 参数`);
  }
  return out;
}

function applyAuth(level, ctx) {
  if (!level) return;
  if (!ctx.user) throw new GqlError("UNAUTHENTICATED", "未登录");
  if (level === "admin" && ctx.user.role !== "admin") throw new GqlError("FORBIDDEN", "仅管理员可访问");
}

async function handleGraphQL(req, res) {
  const raw = await readBody(req);
  let payload;
  try {
    payload = JSON.parse(raw || "{}");
  } catch {
    throw new GqlError("GRAPHQL_VALIDATION_FAILED", "请求体不是合法 JSON");
  }
  const query = String(payload.query ?? "");
  const variables = payload.variables && typeof payload.variables === "object" ? payload.variables : {};

  if (/\b__schema\b|\b__typename\b/.test(query)) {
    if (!INTROSPECTION_ENABLED) {
      throw new GqlError("GRAPHQL_VALIDATION_FAILED", "GraphQL introspection has been disabled for this schema");
    }
    return { data: INTROSPECTION };
  }

  const doc = parseDocument(query);
  if (doc.name === "__schema") throw new GqlError("GRAPHQL_VALIDATION_FAILED", "非法字段选择");
  const key = `${doc.root}.${doc.name}`;
  const field = fields[key];
  if (!field) throw new GqlError("GRAPHQL_VALIDATION_FAILED", `Cannot query field "${doc.name}" on type "${doc.root}".`);

  const ctx = authenticate(req) ?? { user: null };
  applyAuth(field.auth, ctx);
  const args = bindArgs(field, doc, variables);
  const value = field.resolve(args, ctx);
  return { data: { [doc.name]: value } };
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://127.0.0.1");
  if (url.pathname !== ENDPOINT || req.method !== "POST") {
    return json(res, 404, errBody("NOT_FOUND", "only POST /graphql is served"));
  }
  Promise.resolve(handleGraphQL(req, res))
    .then((body) => json(res, 200, body))
    .catch((err) => {
      if (err instanceof GqlError) return fail(res, err);
      console.error("unhandled:", err);
      fail(res, new GqlError("INTERNAL_SERVER_ERROR", err.message ?? "internal error"));
    });
});

const port = Number(process.env.PORT || 0);
server.listen(port, "127.0.0.1", () => {
  const actual = server.address().port;
  console.log(
    `GraphQLShop 已就绪（拒绝语义=${INLINE_ERROR_STATUS ? "HTTP 200+errors" : "按状态码映射"}，内省=${INTROSPECTION_ENABLED ? "on" : "off"}）: http://127.0.0.1:${actual}${ENDPOINT}`
  );
  console.log(`GB_LISTEN ${JSON.stringify({ port: actual })}`);
});
