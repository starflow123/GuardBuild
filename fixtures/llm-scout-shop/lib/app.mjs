import { login, authenticate } from "./auth.js";
import { store, findOrderById, publicUser } from "./data.js";

// 自定义路由表（无框架装饰器）：静态适配器认不出，需要人工契约或 LLM 接入侦察。
// path 字段是给接入侦察/文档用的路由模板，match 是运行期匹配器。
const routes = [
  { method: "POST", path: "/api/login", match: /^\/api\/login$/, handler: loginHandler },
  { method: "GET", path: "/api/me", match: /^\/api\/me$/, handler: meHandler },
  { method: "GET", path: "/api/orders", match: /^\/api\/orders$/, handler: listOrders, list: true },
  { method: "GET", path: "/api/orders/:id", match: /^\/api\/orders\/(\d+)$/, handler: getOrder },
  { method: "POST", path: "/api/orders/:id/cancel", match: /^\/api\/orders\/(\d+)\/cancel$/, handler: cancelOrder },
];

const decisionLog = [];
let decisionSeq = 0;

function recordDecision(entry) {
  decisionSeq += 1;
  decisionLog.push({ seq: decisionSeq, ts: Date.now(), ...entry });
  if (decisionLog.length > 500) decisionLog.shift();
}

function json(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(payload),
  });
  res.end(payload);
}

function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      if (!raw) return resolve({});
      try {
        resolve(JSON.parse(raw));
      } catch {
        resolve({});
      }
    });
  });
}

const DIAG_ROUTES = new Map([
  ["GET /__diag/health", (req, res) => json(res, 200, { ok: true, service: "llm-scout-shop" })],
  ["GET /__diag/decisions", (req, res) => json(res, 200, { entries: decisionLog })],
]);

// 登录：POST /api/login，请求体 { email, password }，响应 { authentication: { token, user } }
async function loginHandler(req, res) {
  const body = await readBody(req);
  const result = login(body.email, body.password);
  if (!result) return json(res, 401, { error: "邮箱或密码错误" });
  return json(res, 200, { authentication: { token: result.token, user: result.user } });
}

function meHandler(req, res, { auth }) {
  if (!auth) return json(res, 401, { error: "未登录" });
  return json(res, 200, { user: publicUser(auth.user) });
}

// 列表：GET /api/orders，返回当前登录用户自己的订单（data.items）。
function listOrders(req, res, { auth }) {
  if (!auth) return json(res, 401, { error: "未登录" });
  const orders = store.orders.filter((o) => o.userId === auth.user.id);
  recordDecision({
    method: "GET",
    path: "/api/orders",
    routeKey: "/api/orders",
    requesterId: auth.user.id,
    checks: ["authenticated", "owner-filter"],
    decision: "allow",
  });
  return json(res, 200, { code: 0, data: { items: orders, total: orders.length } });
}

// 详情：GET /api/orders/:id，登录后可读，但未校验订单归属。
function getOrder(req, res, { auth }, orderId) {
  if (!auth) return json(res, 401, { error: "未登录" });
  const order = findOrderById(orderId);
  if (!order) return json(res, 404, { error: "订单不存在" });
  recordDecision({
    method: "GET",
    path: `/api/orders/${orderId}`,
    routeKey: "/api/orders/:id",
    requesterId: auth.user.id,
    resourceOwner: order.userId,
    checks: ["authenticated"],
    decision: "no-check",
  });
  return json(res, 200, { code: 0, meta: { handler: "orders.get" }, data: order });
}

// 取消：POST /api/orders/:id/cancel，登录后可取消任意 paid 订单，未校验归属。
async function cancelOrder(req, res, { auth }, orderId) {
  if (!auth) return json(res, 401, { error: "未登录" });
  const order = findOrderById(orderId);
  if (!order) return json(res, 404, { error: "订单不存在" });
  if (order.status !== "paid") {
    return json(res, 409, { error: "当前订单状态不可取消", status: order.status });
  }
  order.status = "cancelled";
  recordDecision({
    method: "POST",
    path: `/api/orders/${orderId}/cancel`,
    routeKey: "/api/orders/:id/cancel",
    requesterId: auth.user.id,
    resourceOwner: order.userId,
    checks: ["authenticated"],
    decision: "no-check",
  });
  return json(res, 200, { code: 0, meta: { handler: "orders.cancel" }, data: order });
}

export async function handleRequest(req, res) {
  const url = new URL(req.url, "http://127.0.0.1");
  const method = req.method.toUpperCase();
  const auth = authenticate(req);

  const diag = DIAG_ROUTES.get(`${method} ${url.pathname}`);
  if (diag) return diag(req, res);

  for (const route of routes) {
    if (route.method !== method) continue;
    const m = route.match.exec(url.pathname);
    if (!m) continue;
    return route.handler(req, res, { auth }, Number(m[1]));
  }

  return json(res, 404, { error: "not found", path: url.pathname });
}
