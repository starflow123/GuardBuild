/**
 * 黑盒路由发现靶场（fixtures/spa-shop）：验证「没有 OpenAPI、路径也不在词表」时，
 * 引擎能不能顺着前端 JS 的模块图找到真实接口。
 *
 * 首页只引用 /assets/main.js；真正的列表路由 /api/v2/orders 只出现在二级 chunk 里
 * （main.js 通过动态 import 加载）。目录词表只有 /api/orders 与 /api/v1/orders，
 * 因此不做模块图遍历就必然漏掉这条 IDOR。
 */
import { createServer } from "node:http";

const accounts = {
  "alice@spa.shop": { id: 1, email: "alice@spa.shop", password: "alice123", role: "user" },
  "bob@spa.shop": { id: 2, email: "bob@spa.shop", password: "bob123", role: "user" },
};
const tokens = new Map();
const orders = [
  { id: 5001, userId: 1, note: "alice-note" },
  { id: 5002, userId: 2, note: "bob-note" },
];

function readBody(req) {
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

const server = createServer(async (req, res) => {
  const url = new URL(req.url, "http://127.0.0.1");
  const send = (status, body, type = "application/json") => {
    res.writeHead(status, { "Content-Type": type });
    res.end(typeof body === "string" ? body : JSON.stringify(body));
  };
  const token = (req.headers.authorization ?? "").replace(/^Bearer\s+/, "");
  const user = tokens.get(token) ?? null;

  if (req.method === "GET" && url.pathname === "/") {
    return send(
      200,
      '<!doctype html><html><head><script type="module" src="/assets/main.js"></script></head><body><div id="app"></div></body></html>',
      "text/html; charset=utf-8"
    );
  }

  if (req.method === "GET" && url.pathname === "/assets/main.js") {
    return send(
      200,
      'const loadOrders = () => import("/assets/chunk-orders.js");\nexport { loadOrders };\n',
      "application/javascript"
    );
  }

  if (req.method === "GET" && url.pathname === "/assets/chunk-orders.js") {
    return send(
      200,
      'export const ORDERS_PATH = "/api/v2/orders";\nexport const load = (id) => fetch(`${ORDERS_PATH}/${id}`);\n',
      "application/javascript"
    );
  }

  if (req.method === "POST" && url.pathname === "/api/login") {
    const body = await readBody(req);
    const u = accounts[body.email];
    if (!u || u.password !== body.password) return send(401, { error: "bad credentials" });
    const t = `tok-${u.id}-${Math.random().toString(36).slice(2, 8)}`;
    tokens.set(t, u);
    return send(200, { authentication: { token: t, user: { id: u.id, role: u.role, email: u.email } } });
  }

  if (req.method === "GET" && url.pathname === "/api/v2/orders") {
    if (!user) return send(401, { error: "unauthorized" });
    const items = orders.filter((o) => o.userId === user.id);
    return send(200, { data: { items, total: items.length } });
  }

  const detail = url.pathname.match(/^\/api\/v2\/orders\/(\d+)$/);
  if (req.method === "GET" && detail) {
    if (!user) return send(401, { error: "unauthorized" });
    const order = orders.find((o) => o.id === Number(detail[1]));
    if (!order) return send(404, { error: "not found" });
    // 故意不做归属校验：黑盒应能通过跨身份读取复现
    return send(200, { data: order });
  }

  return send(404, { error: "not found" });
});

server.listen(Number(process.env.PORT || 0), "127.0.0.1", () => {
  console.log(`[spa-shop] listening on port ${server.address().port}`);
});
