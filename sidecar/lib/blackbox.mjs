/**
 * 纯黑盒扫描模块：输入目标 URL，不读源码、不启动本地服务、不生成补丁。
 *
 * 流程：
 *  1. 抓取 OpenAPI 文档
 *  2. 目录爆破常见 API 路径
 *  3. 攻击面扫描（管理后台、敏感文件）
 *  4. 限流检测
 *  5. 输出发现的路由列表
 */

async function httpGet(baseUrl, path) {
  try {
    const res = await fetch(baseUrl + path);
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch {}
    return { status: res.status, json, ok: res.status >= 200 && res.status < 300 };
  } catch (e) {
    return { status: 0, json: null, ok: false, error: e.message };
  }
}

const OPENAPI_PATHS = ["/swagger.json", "/openapi.json", "/v3/api-docs", "/api-docs", "/swagger-ui.json"];
const COMMON_API_PATHS = [
  "/api/users", "/api/user", "/api/account",
  "/api/orders", "/api/order", "/api/products", "/api/posts",
  "/api/projects", "/api/tickets", "/api/invoices",
  "/users", "/orders", "/products", "/posts",
  "/api/profile", "/api/me",
];
const ATTACK_SURFACE_PATHS = [
  "/admin", "/admin/", "/admin/login",
  "/actuator", "/actuator/health", "/actuator/env",
  "/debug/pprof", "/metrics",
  "/.env", "/.git/config", "/.git/HEAD",
  "/api/swagger", "/swagger", "/swagger-ui.html", "/v2/api-docs", "/v3/api-docs",
];

/** 抓取 OpenAPI 文档 */
export async function discoverOpenapi(ctx, baseUrl) {
  for (const p of OPENAPI_PATHS) {
    const res = await httpGet(baseUrl, p);
    if (res.ok && res.json && (res.json.paths || res.json.openapi)) {
      ctx.emit?.({
        kind: "discovery",
        severity: "info",
        message: `发现 OpenAPI 文档：${p}（${Object.keys(res.json.paths ?? {}).length} 条路径）`,
        data: { path: p },
      });
      return res.json;
    }
  }
  ctx.emit?.({ kind: "discovery", severity: "warn", message: "未发现 OpenAPI 文档，回落到目录爆破" });
  return null;
}

/** 目录爆破常见 API 路径 */
export async function bruteRoutes(ctx, baseUrl) {
  const found = [];
  for (const p of COMMON_API_PATHS) {
    const res = await httpGet(baseUrl, p);
    if (res.ok) {
      found.push({ method: "GET", path: p });
      ctx.emit?.({
        kind: "discovery",
        severity: "info",
        message: `发现路由：GET ${p}（HTTP ${res.status}）`,
      });
    }
  }
  return found;
}

/** 攻击面扫描 */
export async function scanSurface(ctx, baseUrl) {
  for (const p of ATTACK_SURFACE_PATHS) {
    const res = await httpGet(baseUrl, p);
    if (res.ok) {
      ctx.emit?.({
        kind: "evidence",
        severity: "warn",
        message: `[攻击面] ${p} 返回 HTTP ${res.status}（未授权可访问）`,
        data: { path: p, status: res.status },
      });
    }
  }
}

/** 限流检测 */
export async function checkRateLimit(ctx, baseUrl) {
  let limited = false;
  for (let i = 0; i < 10; i++) {
    const res = await httpGet(baseUrl, "/");
    if (res.status === 429) { limited = true; break; }
  }
  if (!limited) {
    ctx.emit?.({
      kind: "evidence",
      severity: "warn",
      message: "[攻击面] 连续 10 次请求无 429，可能缺少速率限制",
    });
  }
}

/** 黑盒扫描主入口 */
export async function runBlackbox(ctx, baseUrl) {
  ctx.emit?.({ kind: "phase", severity: "info", message: `开始纯黑盒扫描：${baseUrl}` });

  const openapi = await discoverOpenapi(ctx, baseUrl);
  const brute = await bruteRoutes(ctx, baseUrl);
  await scanSurface(ctx, baseUrl);
  await checkRateLimit(ctx, baseUrl);

  const routes = [];
  if (openapi?.paths) {
    for (const [path, methods] of Object.entries(openapi.paths)) {
      for (const method of Object.keys(methods)) {
        routes.push({ method: method.toUpperCase(), path });
      }
    }
  }
  routes.push(...brute);

  ctx.emit?.({
    kind: "discovery",
    severity: "info",
    message: `黑盒扫描完成：发现 ${routes.length} 条路由`,
    data: { routes, openapiFound: !!openapi },
  });

  return { routes, openapi };
}
