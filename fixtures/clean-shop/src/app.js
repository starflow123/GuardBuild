import { login, authenticate } from "./auth.js";
import { canAccessOrder } from "./access.js";
import { store, findOrderById, publicUser } from "./data.js";

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

export async function handleRequest(req, res) {
  const url = new URL(req.url, "http://127.0.0.1");
  const pathname = url.pathname;
  const method = req.method.toUpperCase();
  const auth = authenticate(req);

  if (method === "GET" && pathname === "/__diag/health") {
    return json(res, 200, { ok: true, service: "clean-shop" });
  }

  if (method === "POST" && pathname === "/api/login") {
    const body = await readBody(req);
    const result = login(body.username, body.password);
    if (!result) return json(res, 401, { error: "用户名或密码错误" });
    return json(res, 200, { token: result.token, user: result.user });
  }

  if (method === "GET" && pathname === "/api/me") {
    if (!auth) return json(res, 401, { error: "未登录" });
    return json(res, 200, { user: publicUser(auth.user) });
  }

  if (method === "GET" && pathname === "/api/orders") {
    if (!auth) return json(res, 401, { error: "未登录" });
    const orders = store.orders.filter((o) => o.userId === auth.user.id);
    recordDecision({
      method, path: pathname, routeKey: "orders.list",
      requesterId: auth.user.id, requesterRole: auth.user.role,
      checks: ["authenticated", "owner-filter"], decision: "allow",
      note: "按归属过滤，仅返回当前用户的订单",
    });
    return json(res, 200, { orders });
  }

  const orderDetailMatch = pathname.match(/^\/api\/orders\/(\d+)$/);
  if (method === "GET" && orderDetailMatch) {
    if (!auth) return json(res, 401, { error: "未登录" });
    const orderId = Number(orderDetailMatch[1]);
    const order = findOrderById(orderId);
    if (!order) return json(res, 404, { error: "订单不存在" });
    if (!canAccessOrder(auth.user, order)) {
      recordDecision({
        method, path: pathname, routeKey: "orders.get",
        requesterId: auth.user.id, requesterRole: auth.user.role,
        resourceOwner: order.userId,
        checks: ["authenticated", "owner-check"], decision: "deny",
        note: "订单归属与当前用户不一致，拒绝访问",
      });
      return json(res, 403, { error: "无权访问该订单" });
    }
    recordDecision({
      method, path: pathname, routeKey: "orders.get",
      requesterId: auth.user.id, requesterRole: auth.user.role,
      resourceOwner: order.userId,
      checks: ["authenticated", "owner-check"], decision: "allow",
      note: "订单归属校验通过",
    });
    return json(res, 200, { order });
  }

  const orderCancelMatch = pathname.match(/^\/api\/orders\/(\d+)\/cancel$/);
  if (method === "POST" && orderCancelMatch) {
    if (!auth) return json(res, 401, { error: "未登录" });
    const orderId = Number(orderCancelMatch[1]);
    const order = findOrderById(orderId);
    if (!order) return json(res, 404, { error: "订单不存在" });
    if (!canAccessOrder(auth.user, order)) {
      recordDecision({
        method, path: pathname, routeKey: "orders.cancel",
        requesterId: auth.user.id, requesterRole: auth.user.role,
        resourceOwner: order.userId,
        checks: ["authenticated", "owner-check"], decision: "deny",
        note: "订单归属与当前用户不一致，拒绝取消",
      });
      return json(res, 403, { error: "无权访问该订单" });
    }
    if (order.status !== "paid") {
      return json(res, 409, { error: "当前订单状态不可取消", status: order.status });
    }
    order.status = "cancelled";
    recordDecision({
      method, path: pathname, routeKey: "orders.cancel",
      requesterId: auth.user.id, requesterRole: auth.user.role,
      resourceOwner: order.userId,
      checks: ["authenticated", "owner-check"], decision: "allow",
      note: "归属与状态校验通过，取消订单",
    });
    return json(res, 200, { ok: true, order });
  }

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
    return json(res, 200, { orders: store.orders });
  }

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
    return json(res, 200, { ok: true, order });
  }

  return json(res, 404, { error: "not found", path: pathname });
}
