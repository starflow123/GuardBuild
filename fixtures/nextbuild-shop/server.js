/**
 * 黑盒 Next.js 构建清单发现靶场（fixtures/nextbuild-shop）。
 *
 * 首页只挂入口 chunk，入口 chunk 里没有任何接口字面量，也不 import 业务 chunk；
 * 真正的接口 `/api/accounts/ledger` 只出现在 `_buildManifest.js` 列出的二级 chunk 里。
 * 因此只有「解析首页地址得到构建号 → 抓 _buildManifest.js → 按清单继续爬」才能发现它。
 *
 * GB_NEXT_HARDENED=1：ledger 要登录，同一份清单不应该再判出漏洞。
 */
import { createServer } from "node:http";

const hardened = process.env.GB_NEXT_HARDENED === "1";
const BUILD_ID = "NhB7xk2pQr";
const accounts = {
  "alice@next.shop": { id: 1, email: "alice@next.shop", password: "alice123", role: "user" },
  "bob@next.shop": { id: 2, email: "bob@next.shop", password: "bob123", role: "user" },
};
const tokens = new Map();
const ledger = [
  { id: 301, ownerId: 1, email: "alice@next.shop", balance: 4200 },
  { id: 302, ownerId: 2, email: "bob@next.shop", balance: 1750 },
];

const CHUNKS = {
  "/_next/static/chunks/main-HASH1.js":
    "self.__WEBPACK_RUNTIME__=(()=>1);\n",
  "/_next/static/chunks/pages/index-HASH2.js": 'export const HOME_BANNER = "welcome";\n',
  "/_next/static/chunks/pages/accounts-HASH3.js":
    'export const LEDGER_PATH = "/api/accounts/ledger";\nexport const loadLedger = () => fetch(LEDGER_PATH + "?full=1");\n',
};

const BUILD_MANIFEST = `
self.__BUILD_MANIFEST = (null !== self.__BUILD_MANIFEST ? self.__BUILD_MANIFEST : {}) ,
function() {
  self.__BUILD_MANIFEST = {
    "/": ["static/chunks/pages/index-HASH2.js"],
    "/accounts": ["static/chunks/pages/accounts-HASH3.js"],
    sortedPages: ["/", "/accounts", "/accounts/[id]"]
  };
}();
self.__BUILD_MANIFEST_ROOT_MULTI = ["static/chunks/main-HASH1.js"];
//# sourceMappingURL=_buildManifest.js.map
`;

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
      [
        "<!doctype html><html><head>",
        `<script src="/_next/static/chunks/main-HASH1.js" async></script>`,
        '<link rel="preload" href="/_next/data/' + BUILD_ID + '/index.json" as="script" />',
        "</head><body><div id=\"__next\"></div>",
        `<script>self.__NEXT_DATA__={"buildId":"${BUILD_ID}","page":"/","props":{"pageProps":{}}};</script>`,
        "</body></html>",
      ].join(""),
      "text/html; charset=utf-8"
    );
  }

  if (req.method === "GET" && url.pathname === `/_next/static/${BUILD_ID}/_buildManifest.js`) {
    return send(200, BUILD_MANIFEST, "application/javascript");
  }
  if (req.method === "GET" && CHUNKS[url.pathname]) {
    return send(200, CHUNKS[url.pathname], "application/javascript");
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

  // 只在 buildManifest 列出的二级 chunk 里出现的账务接口
  if (url.pathname === "/api/accounts/ledger") {
    if (hardened && !user) return send(401, { error: "unauthorized" });
    return send(200, { items: ledger, total: ledger.length });
  }

  return send(404, { error: "404 This page could not be found" });
});

server.listen(Number(process.env.PORT || 0), "127.0.0.1", () => {
  console.log(`[nextbuild-shop] listening on port ${server.address().port}`);
});
