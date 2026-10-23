import { store, findOrderById } from "../data.js";
import { json, normalizeId } from "../http.js";
import { recordDecision } from "../diag.js";

// 订单处理器：认证已在入口完成（ctx.auth），这里负责按 id 取数并返回。
// 详情与取消两个端点取到订单后直接返回/改写，没有比对订单归属 —— 越权读与越权取消都从这里发生。
export function handleOrders(req, res, ctx) {
  const { method, pathname, auth } = ctx;

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
    return json(res, 200, { orders });
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
    const orderId = normalizeId(orderDetailMatch[1]);
    const order = findOrderById(orderId);
    if (!order) return json(res, 404, { error: "订单不存在" });
    recordDecision({
      method, path: pathname, routeKey: "orders.get",
      requesterId: auth.user.id, requesterRole: auth.user.role,
      resourceOwner: order.userId,
      checks: ["authenticated"], decision: "no-check",
      note: "查询订单后直接返回，未校验订单归属",
    });
    return json(res, 200, { order });
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
    const orderId = normalizeId(orderCancelMatch[1]);
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
    return json(res, 200, { ok: true, order });
  }

  return json(res, 404, { error: "not found", path: pathname });
}
