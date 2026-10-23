import { authenticate, login } from "./auth.js";
import { publicUser, store } from "./data.js";
import { json, readBody } from "./http.js";
import { recordDecision, decisions } from "./diag.js";
import { handleOrders } from "./routes/orders.js";

// 应用入口与路由分发。订单模块的处理器在 src/routes/orders.js：
// 「谁的资源能被谁读」这件事在本文件只有一行挂载点，改动这里才会真正影响所有订单端点。
export async function handleRequest(req, res) {
  const url = new URL(req.url, "http://127.0.0.1");
  const pathname = url.pathname;
  const method = req.method.toUpperCase();
  const auth = authenticate(req);

  // ---- 诊断辅助（供安全测试工具读取服务端权限判断轨迹）----
  if (method === "GET" && pathname === "/__diag/health") {
    return json(res, 200, { ok: true, service: "crossfile-shop", uptimeSec: Math.round(process.uptime()) });
  }
  if (method === "GET" && pathname === "/__diag/decisions") {
    return json(res, 200, { entries: decisions() });
  }

  // ---- 认证 ----
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

  // ---- 管理端：全部订单（角色校验在挂载处）----
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
    return json(res, 200, { orders: store.orders });
  }

  // ---- 订单模块：列表 / 详情 / 取消 ----
  if (pathname.startsWith("/api/orders")) {
    return handleOrders(req, res, { method, pathname, auth });
  }

  return json(res, 404, { error: "not found", path: pathname });
}
