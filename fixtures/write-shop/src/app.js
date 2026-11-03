import { authenticate, login } from "./auth.js";
import { dropOrder, findOrderById, ordersOf, publicUser, sameOwner } from "./data.js";

// 写面靶场：读取按归属过滤且单体读取也校验归属，改写（PATCH）与删除（DELETE）没有。
// GB_WRITE_HARDENED=1 时写面在运行期补上归属校验——校验藏在 helper 调用里，
// 静态层看不出来，所以「加固版」的正确结局是攻击全部 blocked（而不是静态候选消失）。
const hardened = process.env.GB_WRITE_HARDENED === "1";

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

  if (method === "GET" && pathname === "/") {
    return json(res, 200, { service: "write-shop", hardened });
  }

  if (method === "POST" && pathname === "/api/login") {
    const body = await readBody(req);
    const result = login(body.email, body.password);
    if (!result) return json(res, 401, { error: "邮箱或密码错误" });
    return json(res, 200, { token: result.token, user: publicUser(result.user) });
  }

  if (method === "GET" && pathname === "/api/orders") {
    if (!auth) return json(res, 401, { error: "unauthorized" });
    return json(res, 200, { items: ordersOf(auth.user) });
  }

  const orderGetMatch = pathname.match(/^\/api\/orders\/(\d+)$/);
  if (method === "GET" && orderGetMatch) {
    if (!auth) return json(res, 401, { error: "unauthorized" });
    const order = findOrderById(Number(orderGetMatch[1]));
    if (!order) return json(res, 404, { error: "not found" });
    if (!sameOwner(order, auth.user)) return json(res, 403, { error: "forbidden" });
    return json(res, 200, order);
  }

  const orderPatchMatch = pathname.match(/^\/api\/orders\/(\d+)$/);
  if (method === "PATCH" && orderPatchMatch) {
    if (!auth) return json(res, 401, { error: "unauthorized" });
    const order = findOrderById(Number(orderPatchMatch[1]));
    if (!order) return json(res, 404, { error: "not found" });
    if (hardened && !sameOwner(order, auth.user)) return json(res, 403, { error: "forbidden" });
    const body = await readBody(req);
    if (typeof body.note === "string") order.note = body.note;
    return json(res, 200, order);
  }

  const orderDeleteMatch = pathname.match(/^\/api\/orders\/(\d+)$/);
  if (method === "DELETE" && orderDeleteMatch) {
    if (!auth) return json(res, 401, { error: "unauthorized" });
    const order = findOrderById(Number(orderDeleteMatch[1]));
    if (!order) return json(res, 404, { error: "not found" });
    if (hardened && !sameOwner(order, auth.user)) return json(res, 403, { error: "forbidden" });
    dropOrder(order);
    return json(res, 200, { deleted: true, id: order.id });
  }

  return json(res, 404, { error: "not found" });
}
