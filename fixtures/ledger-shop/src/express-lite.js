/**
 * 微型 Express 垫片：路由源码按 Express 写法组织（router.get("/path", (req, res) => …)），
 * 但 CI 里不安装任何依赖——这里用纯 Node 复刻同一套 HTTP 契约：
 *  路由表按注册顺序匹配、req.query / req.body 已解析、res.json / res.send / res.status()。
 *
 * 为什么这样搭：静态层认 Express 风格的路由锚点，动态层只要 URL + 方法 + 身份语义等价即可，
 * 于是「框架形态」与「可运行的纯 Node 靶子」不必二选一（与 nest-shop 的垫片思路同一形状）。
 */
import http from "node:http";

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
        resolve(Object.fromEntries(new URLSearchParams(raw)));
      }
    });
  });
}

function send(res, status, payload, contentType) {
  const body = String(payload);
  res.writeHead(status, {
    "Content-Type": contentType,
    "Content-Length": Buffer.byteLength(body),
  });
  res.end(body);
}

const JSON_TYPE = "application/json; charset=utf-8";
const TEXT_TYPE = "text/plain; charset=utf-8";

export function createRouter() {
  const routes = [];
  const add = (method) => (path, handler) => {
    routes.push({ method, path, handler });
  };

  return {
    get: add("GET"),
    post: add("POST"),
    routes,
    async handle(req, res) {
      const url = new URL(req.url, "http://127.0.0.1");
      const method = req.method.toUpperCase();
      const hit = routes.find((r) => r.method === method && r.path === url.pathname);
      if (!hit) return send(res, 404, JSON.stringify({ error: "接口不存在" }), JSON_TYPE);

      req.path = url.pathname;
      req.query = Object.fromEntries(url.searchParams.entries());
      req.body = method === "GET" ? {} : await readBody(req);

      const reply = {
        json: (body) => send(res, 200, JSON.stringify(body), JSON_TYPE),
        send: (text) => send(res, 200, text, TEXT_TYPE),
        status: (code) => ({
          json: (body) => send(res, code, JSON.stringify(body), JSON_TYPE),
          send: (text) => send(res, code, text, TEXT_TYPE),
        }),
      };

      try {
        await hit.handler(req, reply);
      } catch (err) {
        send(res, 500, JSON.stringify({ error: err?.message ?? "internal error" }), JSON_TYPE);
      }
    },
  };
}

export function createServer(router) {
  return http.createServer((req, res) => {
    router.handle(req, res);
  });
}
