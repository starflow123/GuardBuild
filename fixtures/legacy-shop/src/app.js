import { login, authenticate } from "./auth.js";
import { store, findOrderById, publicUser } from "./data.js";

// ---- 权限判断决策日志 ----
// 每次请求都会记录服务端实际执行了哪些授权检查、依据什么做出放行/拒绝决定。
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

function readForm(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(new URLSearchParams(Buffer.concat(chunks).toString("utf8"))));
  });
}

export async function handleRequest(req, res) {
  const url = new URL(req.url, "http://127.0.0.1");
  const pathname = url.pathname;
  const method = req.method.toUpperCase();
  const auth = authenticate(req);

  // ---- 诊断辅助（供安全测试工具读取服务端权限判断轨迹）----
  if (method === "GET" && pathname === "/__diag/health") {
    return json(res, 200, { ok: true, service: "vibeshop", uptimeSec: Math.round(process.uptime()) });
  }
  if (method === "GET" && pathname === "/__diag/decisions") {
    return json(res, 200, { entries: decisionLog });
  }

  // ---- 认证（form 登录 + 302 + Set-Cookie 会话，模拟传统 Web 形态）----
  if (method === "POST" && pathname === "/session/login") {
    const form = await readForm(req);
    const result = login(form.get("email") ?? "", form.get("password") ?? "");
    if (!result) return json(res, 401, { error: "邮箱或密码错误" });
    res.writeHead(302, {
      Location: "/api/me",
      "Set-Cookie": `sid=${result.token}; Path=/; HttpOnly; SameSite=Lax`,
      "Content-Length": "0",
    });
    return res.end();
  }

  // ---- 认证（email 登录 + 嵌套 token，模拟真实项目响应形状）----
  if (method === "POST" && pathname === "/api/login") {
    const body = await readBody(req);
    const result = login(body.email, body.password);
    if (!result) return json(res, 401, { error: "邮箱或密码错误" });
    return json(res, 200, { authentication: { token: result.token, user: result.user } });
  }

  if (method === "GET" && pathname === "/api/me") {
    if (!auth) return json(res, 401, { error: "未登录" });
    return json(res, 200, { user: publicUser(auth.user) });
  }

  // ---- 订单：列表（返回自己的订单）----
  if (method === "GET" && pathname === "/api/orders") {
    if (!auth) {
      recordDecision({
        method, path: pathname, routeKey: "orders.list",
        requesterId: null, requesterRole: null,
        checks: ["authenticated"], decision: "deny",
        note: "未登录，拒绝访问订单列表",
      });
      return json(res, 401, { error: "未登录" });
    }
    const orders = store.orders.filter((o) => o.userId === auth.user.id);
    recordDecision({
      method, path: pathname, routeKey: "orders.list",
      requesterId: auth.user.id, requesterRole: auth.user.role,
      checks: ["authenticated", "owner-filter"], decision: "allow",
      note: "按归属过滤，仅返回当前用户的订单",
    });
    return json(res, 200, { code: 0, data: { items: orders, total: orders.length } });
  }

  // ---- 订单：详情 ----
  const orderDetailMatch = pathname.match(/^\/api\/orders\/(\d+)$/);
  if (method === "GET" && orderDetailMatch) {
    if (!auth) {
      recordDecision({
        method, path: pathname, routeKey: "orders.get",
        requesterId: null, requesterRole: null,
        checks: ["authenticated"], decision: "deny",
        note: "未登录，拒绝访问订单详情",
      });
      return json(res, 401, { error: "未登录" });
    }
    const orderId = Number(orderDetailMatch[1]);
    const order = findOrderById(orderId);
    if (!order) return json(res, 404, { error: "订单不存在" });
    recordDecision({
      method, path: pathname, routeKey: "orders.get",
      requesterId: auth.user.id, requesterRole: auth.user.role,
      resourceOwner: order.userId,
      checks: ["authenticated"], decision: "no-check",
      note: "查询订单后直接返回，未校验订单归属",
    });
    return json(res, 200, { code: 0, meta: { handler: "orders.get" }, data: order });
  }

  // ---- 订单：取消 ----
  const orderCancelMatch = pathname.match(/^\/api\/orders\/(\d+)\/cancel$/);
  if (method === "POST" && orderCancelMatch) {
    if (!auth) {
      recordDecision({
        method, path: pathname, routeKey: "orders.cancel",
        requesterId: null, requesterRole: null,
        checks: ["authenticated"], decision: "deny",
        note: "未登录，拒绝取消订单",
      });
      return json(res, 401, { error: "未登录" });
    }
    const orderId = Number(orderCancelMatch[1]);
    const order = findOrderById(orderId);
    if (!order) return json(res, 404, { error: "订单不存在" });
    if (order.status !== "paid") {
      return json(res, 409, { error: "当前订单状态不可取消", status: order.status });
    }
    order.status = "cancelled";
    recordDecision({
      method, path: pathname, routeKey: "orders.cancel",
      requesterId: auth.user.id, requesterRole: auth.user.role,
      resourceOwner: order.userId,
      checks: ["authenticated"], decision: "no-check",
      note: "取消订单前未校验订单归属",
    });
    return json(res, 200, { code: 0, meta: { handler: "orders.cancel" }, data: order });
  }

  // ---- 管理端：全部订单 ----
  if (method === "GET" && pathname === "/api/admin/orders") {
    if (!auth) return json(res, 401, { error: "未登录" });
    if (auth.user.role !== "admin") {
      recordDecision({
        method, path: pathname, routeKey: "admin.orders.list",
        requesterId: auth.user.id, requesterRole: auth.user.role,
        checks: ["authenticated", "role:admin"], decision: "deny",
        note: "非管理员访问管理端",
      });
      return json(res, 403, { error: "无权访问" });
    }
    recordDecision({
      method, path: pathname, routeKey: "admin.orders.list",
      requesterId: auth.user.id, requesterRole: auth.user.role,
      checks: ["authenticated", "role:admin"], decision: "allow",
      note: "管理员可查看全部订单",
    });
    return json(res, 200, { code: 0, data: { items: store.orders, total: store.orders.length } });
  }

  // ---- 管理端：代取消订单 ----
  const adminCancelMatch = pathname.match(/^\/api\/admin\/orders\/(\d+)\/cancel$/);
  if (method === "POST" && adminCancelMatch) {
    if (!auth) return json(res, 401, { error: "未登录" });
    if (auth.user.role !== "admin") {
      recordDecision({
        method, path: pathname, routeKey: "admin.orders.cancel",
        requesterId: auth.user.id, requesterRole: auth.user.role,
        checks: ["authenticated", "role:admin"], decision: "deny",
        note: "非管理员调用管理取消接口",
      });
      return json(res, 403, { error: "无权访问" });
    }
    const orderId = Number(adminCancelMatch[1]);
    const order = findOrderById(orderId);
    if (!order) return json(res, 404, { error: "订单不存在" });
    if (order.status !== "paid") {
      return json(res, 409, { error: "当前订单状态不可取消", status: order.status });
    }
    order.status = "cancelled";
    recordDecision({
      method, path: pathname, routeKey: "admin.orders.cancel",
      requesterId: auth.user.id, requesterRole: auth.user.role,
      resourceOwner: order.userId,
      checks: ["authenticated", "role:admin"], decision: "allow",
      note: "管理员代取消订单",
    });
    return json(res, 200, { code: 0, meta: { handler: "admin.orders.cancel" }, data: order });
  }

  return json(res, 404, { error: "not found", path: pathname });
}
