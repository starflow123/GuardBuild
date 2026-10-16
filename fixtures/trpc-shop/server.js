import http from "node:http";
import { findOrderById, findOrdersByUser, store } from "./src/store.mjs";
import { authenticate, login } from "./src/auth.mjs";

/*
 * 运行时垫片（shim）：以纯 Node HTTP 复刻 tRPC v11 + superjson 的线上协议语义。
 *
 * 说明：这不是 tRPC 运行时本体。被测的静态对象是 src/server/**\/*.ts 里的真实路由源码
 * （initTRPC / router / protectedProcedure / z.object 输入），动态探测层只需要「过程 URL +
 * GET ?input= / POST body + 信封格式」，因此这里用等价 HTTP 契约承载动态复现，CI 无需安装
 * @trpc/server 与 zod。
 *
 * 与 tRPC 对齐的关键行为：
 *  1) 过程路径点连接（orders.byId），查询走 GET ?input=<urlencoded JSON>，变更走 POST 请求体；
 *  2) 中间件先于 input 校验：未登录恒 401，而不是 400（决定探测层的编码协商必须带身份）；
 *  3) superjson：input 必须是 {"json": 原值}，响应 data 亦为 {json, meta?}；
 *     用 TRPC_ENCODING=raw 可切换到「无 transformer」形态（探测层需自行协商出正确编码）；
 *  4) 错误按 TRPCError.code 映射 HTTP 状态（UNAUTHORIZED 401 / FORBIDDEN 403 / NOT_FOUND 404 /
 *     BAD_REQUEST 400 / CONFLICT 409），故「越权被拒绝」在 HTTP 层可判。
 */

const ENDPOINT = "/api/trpc";
const USE_SUPERJSON = process.env.TRPC_ENCODING !== "raw";

const CODE_STATUS = {
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  BAD_REQUEST: 400,
  CONFLICT: 409,
  INTERNAL_SERVER_ERROR: 500,
};

class TrpcError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

function json(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(payload),
  });
  res.end(payload);
}

const serialize = (value) => (USE_SUPERJSON ? { json: value } : value);
const ok = (res, value) => json(res, 200, { result: { data: serialize(value) } });
const fail = (res, err, path) =>
  json(res, CODE_STATUS[err.code] ?? 500, {
    error: { message: err.message, data: { code: err.code, httpStatus: CODE_STATUS[err.code] ?? 500, path } },
  });

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

/** 反序列化 input：superjson 服务端要求 {"json":…} 包裹，缺包裹即等价于 zod 校验失败 */
function deserialize(raw) {
  if (raw === null || raw === undefined) return { present: false, value: undefined };
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new TrpcError("BAD_REQUEST", "JSON 解析失败");
  }
  if (!USE_SUPERJSON) return { present: true, value: parsed };
  if (!parsed || typeof parsed !== "object" || !("json" in parsed)) {
    throw new TrpcError("BAD_REQUEST", "input 形态不合法：该服务端启用 superjson，input 须为 {json: …}");
  }
  return { present: true, value: parsed.json };
}

/** zod 形态的等价校验：声明字段与基础类型（number/string），缺失或类型不符即 BAD_REQUEST */
function validate(input, schema, procPath) {
  if (!schema) return {};
  if (input === undefined || input === null || typeof input !== "object" || Array.isArray(input)) {
    throw new TrpcError("BAD_REQUEST", `[${procPath}] No input received`);
  }
  const out = {};
  for (const [name, kind] of Object.entries(schema)) {
    const v = input[name];
    if (v === undefined || v === null) throw new TrpcError("BAD_REQUEST", `[${procPath}] expected ${name} to be ${kind}`);
    if (kind === "number" && typeof v !== "number") throw new TrpcError("BAD_REQUEST", `[${procPath}] expected ${name} to be number`);
    if (kind === "string" && typeof v !== "string") throw new TrpcError("BAD_REQUEST", `[${procPath}] expected ${name} to be string`);
    out[name] = v;
  }
  return out;
}

/** 过程表：与 src/server/routers\/*.ts 的静态形态一一对应（auth → orders → admin） */
const procedures = {
  "auth.login": {
    type: "mutation",
    guard: null,
    schema: { email: "string", password: "string" },
    run: ({ input }) => {
      const result = login(input.email, input.password);
      if (!result) throw new TrpcError("UNAUTHORIZED", "邮箱或密码错误");
      return { token: result.token, user: result.user };
    },
  },
  "auth.me": { type: "query", guard: "authed", schema: null, run: ({ ctx }) => ({ user: ctx.user }) },
  "orders.list": {
    type: "query",
    guard: "authed",
    schema: null,
    run: ({ ctx }) => ({ orders: findOrdersByUser(ctx.user.id) }),
  },
  "orders.byId": {
    type: "query",
    guard: "authed",
    schema: { id: "number" },
    run: ({ input }) => {
      const order = findOrderById(input.id);
      if (!order) throw new TrpcError("NOT_FOUND", "订单不存在");
      return { order }; // 复刻漏洞：未校验 order.userId 归属
    },
  },
  "orders.cancel": {
    type: "mutation",
    guard: "authed",
    schema: { orderId: "number" },
    run: ({ input }) => {
      const order = findOrderById(input.orderId);
      if (!order) throw new TrpcError("NOT_FOUND", "订单不存在");
      if (order.status !== "paid") throw new TrpcError("CONFLICT", "当前订单状态不可取消");
      order.status = "cancelled"; // 复刻漏洞：未校验归属即可取消他人订单
      return { ok: true, order };
    },
  },
  "admin.listAll": {
    type: "query",
    guard: "admin",
    schema: null,
    run: () => ({ orders: store.orders }),
  },
  "admin.stats": {
    type: "query",
    guard: "admin",
    schema: null,
    run: () => ({ total: store.orders.length }),
  },
};

function applyGuard(guard, ctx) {
  // 中间件先于 input 校验执行（tRPC 语义），因此 401/403 优先于 400
  if (!guard) return;
  if (!ctx.user) throw new TrpcError("UNAUTHORIZED", "未登录");
  if (guard === "admin" && ctx.user.role !== "admin") throw new TrpcError("FORBIDDEN", "仅管理员可访问");
}

async function handleTrpc(req, res, procPath, url) {
  const proc = procedures[procPath];
  if (!proc) throw new TrpcError("NOT_FOUND", `No \"query\"-procedure on path ${procPath}`);
  const isQuery = req.method === "GET";
  if (isQuery && proc.type !== "query") throw new TrpcError("NOT_FOUND", `cannot use GET on mutation ${procPath}`);
  if (!isQuery && proc.type !== "mutation") throw new TrpcError("NOT_FOUND", `cannot use POST on query ${procPath}`);

  const ctx = authenticate(req) ?? { user: null };
  applyGuard(proc.guard, ctx);

  const raw = isQuery ? url.searchParams.get("input") : await readBody(req);
  const { present, value } = deserialize(raw);
  if (!present && proc.schema) throw new TrpcError("BAD_REQUEST", `[${procPath}] No input received`);
  const input = validate(value, proc.schema, procPath);
  return proc.run({ ctx, input });
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://127.0.0.1");
  const pathname = url.pathname.replace(/\/+$/, "");
  if (!pathname.startsWith(`${ENDPOINT}/`)) {
    return json(res, 404, { error: { message: "not found", data: { code: "NOT_FOUND", httpStatus: 404 } } });
  }
  const procPath = pathname.slice(ENDPOINT.length + 1);
  Promise.resolve(handleTrpc(req, res, procPath, url))
    .then((value) => ok(res, value))
    .catch((err) => {
      if (err instanceof TrpcError) return fail(res, err, procPath);
      console.error("unhandled:", err);
      fail(res, new TrpcError("INTERNAL_SERVER_ERROR", err.message ?? "internal error"), procPath);
    });
});

const port = Number(process.env.PORT || 0);
server.listen(port, "127.0.0.1", () => {
  const actual = server.address().port;
  console.log(
    `TRPCShop 已就绪（${USE_SUPERJSON ? "superjson" : "raw"} 编码）: http://127.0.0.1:${actual}${ENDPOINT}`
  );
  console.log(`GB_LISTEN ${JSON.stringify({ port: actual })}`);
});
