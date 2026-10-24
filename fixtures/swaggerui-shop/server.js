/**
 * 黑盒 Swagger UI 内嵌地址发现靶场（fixtures/swaggerui-shop）。
 *
 * 常见 JSON 文档路径全部 404，规格只挂在 HTML 页面里：
 *   /swagger-ui.html 内嵌 `url: "/internal/openapi-spec.json"`
 * 不解析页面里的文档地址就找不到 OpenAPI，也就拿不到 `/api/invoices` 声明的 year 参数——
 * 数字语境注入必须打在声明参数上，写死 `q=` 之类的猜测会直接漏报。
 *
 * GB_SWAGGER_HARDENED=1：year 严格取整后走等值查询，同一份规格不应该再判出注入。
 */
import { createServer } from "node:http";

const hardened = process.env.GB_SWAGGER_HARDENED === "1";
const accounts = {
  "alice@ui.shop": { id: 1, email: "alice@ui.shop", password: "alice123", role: "user" },
  "bob@ui.shop": { id: 2, email: "bob@ui.shop", password: "bob123", role: "user" },
};
const tokens = new Map();
const invoices = [
  { id: 1, year: 2024, total: 100 },
  { id: 2, year: 2024, total: 220 },
  { id: 3, year: 2025, total: 340 },
];

const SPEC = {
  openapi: "3.0.0",
  paths: {
    "/api/invoices": { get: { parameters: [{ name: "year", in: "query", schema: { type: "string" } }] } },
    "/api/invoices/{id}": { get: { parameters: [{ name: "id", in: "path" }] } },
  },
};

const UI_HTML = [
  '<!doctype html><html><head><link rel="stylesheet" href="/swagger-ui/swagger-ui.css"></head><body>',
  '<div id="swagger-ui"></div>',
  '<script src="/swagger-ui/swagger-ui-bundle.js"></script>',
  "<script>",
  "window.ui = SwaggerUIBundle({",
  '  url: "/internal/openapi-spec.json",',
  '  dom_id: "#swagger-ui",',
  "  deepLinking: true,",
  "});",
  "</script></body></html>",
].join("");

const server = createServer(async (req, res) => {
  const url = new URL(req.url, "http://127.0.0.1");
  const send = (status, body, type = "application/json") => {
    res.writeHead(status, { "Content-Type": type });
    res.end(typeof body === "string" ? body : JSON.stringify(body));
  };
  const token = (req.headers.authorization ?? "").replace(/^Bearer\s+/, "");
  const user = tokens.get(token) ?? null;

  if (req.method === "GET" && url.pathname === "/") return send(200, { service: "swaggerui-shop" });

  // 只有页面，没有常规 JSON 文档路径
  if (req.method === "GET" && url.pathname === "/swagger-ui.html") {
    return send(200, UI_HTML, "text/html; charset=utf-8");
  }
  if (req.method === "GET" && url.pathname === "/internal/openapi-spec.json") return send(200, SPEC);
  if (/^\/swagger-ui\/[\w.-]+\.(?:js|css)$/.test(url.pathname)) return send(200, "/* asset */", "application/javascript");

  if (req.method === "POST" && url.pathname === "/api/login") {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    let body = {};
    try {
      body = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
    } catch {
      /* 忽略非法体 */
    }
    const u = accounts[body.email];
    if (!u || u.password !== body.password) return send(401, { error: "bad credentials" });
    const t = `tok-${u.id}`;
    tokens.set(t, u);
    return send(200, { authentication: { token: t, user: { id: u.id, role: u.role, email: u.email } } });
  }

  if (url.pathname === "/api/invoices") {
    if (req.method !== "GET") return send(404, { error: "not found" });
    if (!user) return send(401, { error: "unauthorized" });
    const raw = url.searchParams.get("year");
    if (raw == null) return send(200, { items: invoices, total: invoices.length });
    // 漏洞形态等价于 `WHERE year = ${raw}` 的字符串拼接（不匹配的值查不到行，靠行数差分证明）；
    // hardened 形态先把参数取整再等值查询，布尔表达式进不去。
    let items;
    if (hardened) {
      if (!/^\d+$/.test(raw)) return send(400, { error: "year must be numeric" });
      items = invoices.filter((i) => i.year === Number(raw));
    } else {
      const m = raw.match(/^(\d+)(?:\s+or\s+(\d+)\s*=\s*(\d+))?$/i);
      if (!m) items = [];
      else items = m[2] !== undefined && Number(m[2]) === Number(m[3]) ? invoices : invoices.filter((i) => i.year === Number(m[1]));
    }
    return send(200, { items, total: items.length });
  }

  return send(404, { error: "not found" });
});

server.listen(Number(process.env.PORT || 0), "127.0.0.1", () => {
  console.log(`[swaggerui-shop] listening on port ${server.address().port}`);
});
