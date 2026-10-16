import http from "node:http";
import { store, findOrderById } from "./src/store.mjs";
import { login, authenticate } from "./src/auth.mjs";

/*
 * 运行时垫片（shim）：以纯 Node HTTP 复刻 app/**\/route.ts 的 API 语义。
 *
 * 说明：这不是 Next.js 运行时本体。route 文件的静态解析由 GuardBuild 直接完成
 * （对 app/**\/route.ts 源码），动态探测层只认「URL 路径 + 方法 + 身份」，
 * 因此这里用等价 HTTP 契约承载动态复现——CI 无需安装 Next.js 工具链。
 */

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

const routes = [
  {
    method: "POST",
    pattern: /^\/api\/login$/,
    async handler(req, res) {
      const body = await readBody(req);
      const result = login(body.email, body.password);
      if (!result) return json(res, 401, { error: "邮箱或密码错误" });
      return json(res, 200, { token: result.token, user: result.user });
    },
  },
  {
    method: "GET",
    pattern: /^\/api\/orders$/,
    handler(req, res, auth) {
      if (!auth) return json(res, 401, { error: "未登录" });
      const orders = store.orders.filter((o) => o.userId === auth.user.id);
      return json(res, 200, { orders });
    },
  },
  {
    method: "GET",
    pattern: /^\/api\/orders\/(\d+)$/,
    handler(req, res, auth, m) {
      if (!auth) return json(res, 401, { error: "未登录" });
      const order = findOrderById(Number(m[1]));
      if (!order) return json(res, 404, { error: "订单不存在" });
      return json(res, 200, { order }); // 复刻漏洞：未校验 order.userId 归属
    },
  },
  {
    method: "POST",
    pattern: /^\/api\/orders\/(\d+)\/cancel$/,
    handler(req, res, auth, m) {
      if (!auth) return json(res, 401, { error: "未登录" });
      const order = findOrderById(Number(m[1]));
      if (!order) return json(res, 404, { error: "订单不存在" });
      if (order.status !== "paid") return json(res, 409, { error: "当前订单状态不可取消", status: order.status });
      order.status = "cancelled"; // 复刻漏洞：未校验 order.userId 归属
      return json(res, 200, { ok: true, order });
    },
  },
];

const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://127.0.0.1");
  const auth = authenticate(req);
  const hit = routes.find((r) => r.method === req.method.toUpperCase() && r.pattern.test(url.pathname));
  if (!hit) return json(res, 404, { error: "not found", path: url.pathname });
  Promise.resolve(hit.handler(req, res, auth, hit.pattern.exec(url.pathname))).catch((err) => {
    console.error("unhandled:", err);
    json(res, 500, { error: "internal error" });
  });
});

const port = Number(process.env.PORT || 0);
server.listen(port, "127.0.0.1", () => {
  const actual = server.address().port;
  console.log(`NextShop 已就绪: http://127.0.0.1:${actual}`);
  console.log(`GB_LISTEN ${JSON.stringify({ port: actual })}`);
});
