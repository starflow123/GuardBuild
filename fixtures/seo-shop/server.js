/**
 * 黑盒 SEO 声明发现靶场（fixtures/seo-shop）。
 *
 * 目标没有 OpenAPI，两个漏洞端点也都不在目录词表里：
 *   - /api/accounts/export   只在 robots.txt 的 Disallow 中出现
 *   - /api/invoices/archive  只在 sitemap.xml 的 <loc> 中出现
 * 不做 robots/sitemap 声明发现，这两条未认证读取必然漏报。
 * sitemap 同时列出 /pricing 与 /blog（公开营销页），用来验证「页面地址不会被当接口塞进路由表」。
 *
 * GB_SEO_HARDENED=1：两个端点都要登录，同一份声明不应该再判出漏洞。
 */
import { createServer } from "node:http";

const hardened = process.env.GB_SEO_HARDENED === "1";
const accounts = {
  "alice@seo.shop": { id: 1, email: "alice@seo.shop", password: "alice123", role: "user" },
  "bob@seo.shop": { id: 2, email: "bob@seo.shop", password: "bob123", role: "user" },
};
const tokens = new Map();
const ledger = [
  { id: 4101, ownerId: 1, email: "alice@seo.shop", balance: 1200 },
  { id: 4102, ownerId: 2, email: "bob@seo.shop", balance: 880 },
];
const invoices = [
  { id: 7001, ownerId: 1, iban: "DE000000000000000001", total: 100 },
  { id: 7002, ownerId: 2, iban: "DE000000000000000002", total: 220 },
];

const server = createServer(async (req, res) => {
  const url = new URL(req.url, "http://127.0.0.1");
  const host = req.headers.host ?? "127.0.0.1";
  const abs = (p) => `http://${host}${p}`;
  const send = (status, body, type = "application/json") => {
    res.writeHead(status, { "Content-Type": type });
    res.end(typeof body === "string" ? body : JSON.stringify(body));
  };
  const token = (req.headers.authorization ?? "").replace(/^Bearer\s+/, "");
  const user = tokens.get(token) ?? null;

  if (req.method === "GET" && url.pathname === "/robots.txt") {
    return send(
      200,
      ["User-agent: *", "Disallow: /api/accounts/export", "Disallow: /private/tools", "", `Sitemap: ${abs("/sitemap.xml")}`].join(
        "\n"
      ),
      "text/plain; charset=utf-8"
    );
  }

  if (req.method === "GET" && url.pathname === "/sitemap.xml") {
    return send(
      200,
      [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
        `  <url><loc>${abs("/")}</loc></url>`,
        `  <url><loc>${abs("/pricing")}</loc></url>`,
        `  <url><loc>${abs("/blog/release-notes")}</loc></url>`,
        `  <url><loc>${abs("/api/invoices/archive")}</loc></url>`,
        "</urlset>",
      ].join("\n"),
      "application/xml"
    );
  }

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

  if (req.method === "GET" && url.pathname === "/") return send(200, { service: "seo-shop" });

  // robots.txt 里 Disallow 的导出接口：非 hardened 时完全不校验身份
  if (url.pathname === "/api/accounts/export") {
    if (hardened && !user) return send(401, { error: "unauthorized" });
    return send(200, { items: ledger, total: ledger.length });
  }

  // sitemap.xml 里列出的归档接口：同上
  if (url.pathname === "/api/invoices/archive") {
    if (hardened && !user) return send(401, { error: "unauthorized" });
    return send(200, { items: invoices, total: invoices.length });
  }

  return send(404, { error: "not found" });
});

server.listen(Number(process.env.PORT || 0), "127.0.0.1", () => {
  console.log(`[seo-shop] listening on port ${server.address().port}`);
});
