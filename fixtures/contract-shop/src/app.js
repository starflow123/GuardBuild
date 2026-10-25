/**
 * 契约驱动靶场：分发表在运行期拼装，静态适配器识别不到 decl 形态的路由。
 * 对象端点是真实的多段路径 + 非默认字段名，专门用来验证
 * guardbuild.json 的 routes[].params / responses / listEndpoint 契约。
 */
const USERS = [
  { id: 1, username: "alice", password: "alice123", role: "user" },
  { id: 2, username: "bob", password: "bob123", role: "user" },
];

const ORDERS = [
  { order_id: 7001, org_id: 9, created_by_uid: 1, title: "alice-order", status: "paid" },
  { order_id: 7002, org_id: 9, created_by_uid: 2, title: "bob-order", status: "paid" },
  { order_id: 7003, org_id: 10, created_by_uid: 2, title: "bob-other-org", status: "paid" },
];

const HARDENED = process.env.GB_CONTRACT_HARDENED === "1";
const SESSIONS = new Map();
let seq = 0;

function send(res, status, body) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

function readBody(req) {
  return new Promise((resolve) => {
    let raw = "";
    req.on("data", (b) => {
      raw += b;
    });
    req.on("end", () => {
      try {
        resolve(raw ? JSON.parse(raw) : {});
      } catch {
        resolve({});
      }
    });
  });
}

function currentUser(req) {
  const header = req.headers.authorization ?? "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  return SESSIONS.get(token) ?? null;
}

async function login(req, res) {
  const body = await readBody(req);
  const user = USERS.find((u) => u.username === body.username && u.password === body.password);
  if (!user) return send(res, 401, { error: "invalid credentials" });
  const token = `tok-${user.username}-${++seq}`;
  SESSIONS.set(token, user);
  return send(res, 200, { token, user: { id: user.id, username: user.username, role: user.role } });
}

function listOrders(req, res, url) {
  const user = currentUser(req);
  if (!user) return send(res, 401, { error: "unauthenticated" });
  const page = Number(url.searchParams.get("page"));
  const limit = Number(url.searchParams.get("limit"));
  // 分页参数是硬要求：契约里不带 query 时资源发现会 400，以此验证 listEndpoint.query 的接线
  if (!Number.isFinite(page) || !Number.isFinite(limit)) {
    return send(res, 400, { error: "page 与 limit 为必填正整数" });
  }
  const mine = ORDERS.filter((o) => o.created_by_uid === user.id);
  const rows = mine.slice((page - 1) * limit, page * limit);
  return send(res, 200, { payload: { page, limit, total: mine.length, rows } });
}

function getOrder(req, res, url, match) {
  const user = currentUser(req);
  if (!user) return send(res, 401, { error: "unauthenticated" });
  const orgId = Number(match[1]);
  const orderId = Number(match[2]);
  const order = ORDERS.find((o) => o.order_id === orderId && o.org_id === orgId);
  if (!order) return send(res, 404, { error: "订单不存在" });
  if (HARDENED && order.created_by_uid !== user.id) return send(res, 404, { error: "订单不存在" });
  return send(res, 200, { meta: { orgId }, record: order });
}

// 路由分发表：没有 app.get/router.get 这类静态锚点
const ROUTES = [
  { method: "POST", pattern: /^\/v1\/session$/, run: login },
  { method: "GET", pattern: /^\/v2\/orders\/paged$/, run: listOrders },
  { method: "GET", pattern: /^\/v1\/orgs\/(\d+)\/orders\/(\d+)$/, run: getOrder },
  { method: "GET", pattern: /^\/v1\/health$/, run: async (req, res) => send(res, 200, { ok: true }) },
];

export async function handleRequest(req, res) {
  const url = new URL(req.url, "http://127.0.0.1");
  for (const route of ROUTES) {
    if (route.method !== req.method) continue;
    const match = route.pattern.exec(url.pathname);
    if (!match) continue;
    await route.run(req, res, url, match);
    return;
  }
  send(res, 404, { error: "not found" });
}
