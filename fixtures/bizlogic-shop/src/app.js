/*
 * BizShop：复刻两类最常见的业务逻辑缺陷。
 *  1) 状态跳步：/api/orders/:id/ship 不校验前置状态（pending 也能直接发货）。
 *  2) 并发双花：/api/orders/:id/refund 先读状态、再异步落账，没有幂等标识或锁，
 *     并发提交同一笔退款会重复成功并各自生成退款单号。
 * GB_BIZ_HARDENED=1 时两处均加固，用于验证修复后行为（静态候选仍在）。
 */

const HARDENED = process.env.GB_BIZ_HARDENED === "1";

const USERS = [
  { id: 1, username: "alice", password: "alice123", role: "user" },
  { id: 2, username: "bob", password: "bob123", role: "user" },
];

const ORDERS = [
  { id: 101, userId: 1, item: "机械键盘", amount: 500, status: "pending" },
  { id: 102, userId: 1, item: "显示器", amount: 300, status: "paid" },
  { id: 201, userId: 2, item: "耳机", amount: 900, status: "paid" },
];

let refundSeq = 0;

function json(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(payload),
  });
  res.end(payload);
}

function readJson(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}"));
      } catch {
        resolve({});
      }
    });
  });
}

const delay = (ms) => new Promise((r) => setTimeout(r, ms));

function tokenOf(req) {
  const raw = String(req.headers.authorization ?? "");
  return raw.startsWith("Bearer ") ? raw.slice("Bearer ".length).trim() : null;
}

function authenticate(req) {
  const token = tokenOf(req);
  if (!token) return null;
  const m = /^tok-(\d+)$/.exec(token);
  if (!m) return null;
  return USERS.find((u) => u.id === Number(m[1])) ?? null;
}

export async function handleRequest(req, res) {
  const url = new URL(req.url, "http://127.0.0.1");
  const pathname = url.pathname;
  const method = req.method.toUpperCase();
  const auth = authenticate(req);

  if (method === "GET" && pathname === "/api/health") {
    return json(res, 200, { ok: true, service: "bizlogic-shop" });
  }

  if (method === "POST" && pathname === "/api/login") {
    const body = await readJson(req);
    const user = USERS.find((u) => u.username === body.username && u.password === body.password);
    if (!user) return json(res, 401, { error: "用户名或密码错误" });
    return json(res, 200, {
      token: `tok-${user.id}`,
      user: { id: user.id, username: user.username, role: user.role },
    });
  }

  if (method === "GET" && pathname === "/api/orders") {
    if (!auth) return json(res, 401, { error: "未登录" });
    const items = ORDERS.filter((o) => o.userId === auth.id);
    return json(res, 200, { items });
  }

  const detailMatch = pathname.match(/^\/api\/orders\/(\d+)$/);
  if (method === "GET" && detailMatch) {
    if (!auth) return json(res, 401, { error: "未登录" });
    const order = ORDERS.find((o) => o.id === Number(detailMatch[1]));
    if (!order) return json(res, 404, { error: "订单不存在" });
    if (order.userId !== auth.id) return json(res, 403, { error: "无权访问该订单" });
    return json(res, 200, { order });
  }

  const shipMatch = pathname.match(/^\/api\/orders\/(\d+)\/ship$/);
  if (method === "POST" && shipMatch) {
    if (!auth) return json(res, 401, { error: "未登录" });
    const order = ORDERS.find((o) => o.id === Number(shipMatch[1]));
    if (!order) return json(res, 404, { error: "订单不存在" });
    if (order.userId !== auth.id) return json(res, 403, { error: "无权操作该订单" });
    if (HARDENED && order.status !== "paid") {
      return json(res, 409, { error: `订单状态为 ${order.status}，仅已支付订单可发货` });
    }
    order.status = "shipped";
    return json(res, 200, { order });
  }

  const refundMatch = pathname.match(/^\/api\/orders\/(\d+)\/refund$/);
  if (method === "POST" && refundMatch) {
    if (!auth) return json(res, 401, { error: "未登录" });
    const order = ORDERS.find((o) => o.id === Number(refundMatch[1]));
    if (!order) return json(res, 404, { error: "订单不存在" });
    if (order.userId !== auth.id) return json(res, 403, { error: "无权操作该订单" });
    if (HARDENED) {
      // 同步置位后再异步落账：并发请求看到的是同一把“已经退过”的标记
      if (order.status === "refunded" || order.refunding) {
        return json(res, 409, { error: "该订单已退款或在退款中" });
      }
      order.refunding = true;
    } else if (order.status === "refunded") {
      return json(res, 409, { error: "该订单已退款" });
    }
    await delay(80);
    order.status = "refunded";
    order.refunding = false;
    refundSeq += 1;
    return json(res, 200, {
      ok: true,
      refund: { refund_id: `rf_${order.id}_${refundSeq}`, amount: order.amount, status: "done" },
    });
  }

  return json(res, 404, { error: "not found", path: pathname });
}
