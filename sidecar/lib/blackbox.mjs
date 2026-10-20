/**
 * 纯黑盒外部扫描：只对已运行的目标发起 HTTP 探测，不读源码、不启动本地服务、不生成补丁。
 *
 * 所有请求经 Host 的 http.request 发出（回环 net.probe / 远程 net.egress）；
 * 登录凭证由 Host 保险库注入（identityRef），Sidecar 不见令牌明文。
 * 配置只从 guardbuild.json 读取 login / identities / blackbox 三块（不触发源码分析）。
 */
import { CASE_CATEGORY, RPC_TO_HOST, SEVERITY, VERDICT, shortId } from "../../shared/protocol.mjs";
import { loginAll } from "./probe.mjs";

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
const SENSITIVE_FILE_PATHS = new Set(["/.env", "/.git/config", "/.git/HEAD"]);
const LOGIN_PATHS_DEFAULT = ["/api/login", "/login", "/auth", "/api/auth"];
const DENIED_STATUS = new Set([401, 403, 404]);
const MAX_ROUTES = 60;
const MAX_PROBE_ROUTES = 14;

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

/** 经 Host 发起一次 HTTP 请求；identity 为保险库身份名（令牌由 Host 注入）。 */
async function httpJson(ctx, { baseUrl, method, path, identity = null, body = null, timeoutMs = 15_000 }) {
  const headers = { ...(ctx.loginConfig?.extraHeaders ?? {}) };
  if (body != null) headers["Content-Type"] = "application/json";
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
    const res = await ctx.rpc.request(RPC_TO_HOST.HTTP_REQUEST, params, { timeoutMs: timeoutMs + 5_000 });
    let json = null;
    try {
      json = JSON.parse(res.body);
    } catch {
      /* 非 JSON 响应 */
    }
    return { ...res, json, ok: isOk(res.status) };
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
  for (const p of OPENAPI_PATHS) {
    const res = await httpJson(ctx, { baseUrl, method: "GET", path: p });
    if (res.ok && res.json && (res.json.paths || res.json.openapi)) {
      ctx.emit({
        kind: "discovery",
        severity: SEVERITY.INFO,
        message: `发现 OpenAPI 文档：${p}（${Object.keys(res.json.paths ?? {}).length} 条路径）`,
        data: { path: p },
      });
      return { doc: res.json, path: p };
    }
  }
  ctx.emit({ kind: "discovery", severity: SEVERITY.WARN, message: "未发现 OpenAPI 文档，回落到目录探测" });
  return null;
}

/** OpenAPI 路径 → 路由列表；带 {param} 的模板单独标记（黑盒无法凭空构造有效 ID）。 */
export function openapiRoutes(found) {
  const doc = found?.doc ?? null;
  if (!doc?.paths) return [];
  let base = "";
  try {
    const server = Array.isArray(doc.servers) ? doc.servers[0]?.url : null;
    if (server) base = new URL(server, "http://placeholder").pathname.replace(/\/+$/, "");
  } catch {
    base = "";
  }
  const out = [];
  for (const [p, methods] of Object.entries(doc.paths)) {
    if (!methods || typeof methods !== "object") continue;
    const path = `${base}${p.startsWith("/") ? p : `/${p}`}`;
    for (const method of Object.keys(methods)) {
      if (!["get", "post", "put", "patch", "delete"].includes(method.toLowerCase())) continue;
      out.push({
        method: method.toUpperCase(),
        path,
        templated: /\{[^}]+\}|:[A-Za-z_]\w*/.test(path),
        source: "openapi",
      });
      if (out.length >= MAX_ROUTES) return out;
    }
  }
  return out;
}

/** 目录探测常见 API 路径（401/403 也算路由存在）。 */
export async function bruteRoutes(ctx, baseUrl) {
  const found = [];
  for (const p of COMMON_API_PATHS) {
    const res = await httpJson(ctx, { baseUrl, method: "GET", path: p });
    if (res.ok || isDenied(res.status)) {
      found.push({ method: "GET", path: p, templated: false, source: "brute" });
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

function mergeRoutes(...lists) {
  const seen = new Set();
  const out = [];
  for (const list of lists) {
    for (const r of list) {
      if (r.templated) continue; // 模板路径无法可靠构造，仅保留在 OpenAPI 计数里
      const key = `${r.method} ${r.path}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(r);
      if (out.length >= MAX_ROUTES) return out;
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

function makeRecord(ctx, baseUrl, { caseId, name, method, path, identity, body, res, expectation, verdict, actual, grade = "http-only", crossProof = null, impact = null }) {
  return {
    id: shortId("ev"),
    sessionId: ctx.sessionId,
    phase: "blackbox",
    identity: identity ?? "(anonymous)",
    method,
    endpoint: path,
    request: {
      url: `${baseUrl.replace(/\/+$/, "")}${path}`,
      headers: identity
        ? { Authorization: `Bearer ***vault:${identity}***`, "Content-Type": "application/json" }
        : { "Content-Type": "application/json" },
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

async function probeUnauthRead(ctx, baseUrl, routes) {
  const records = [];
  for (const route of routes.filter((r) => r.method === "GET").slice(0, MAX_PROBE_ROUTES)) {
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

async function probeIdor(ctx, baseUrl, routes, { attacker, victim }) {
  const records = [];
  const candidates = routes.filter((r) => r.method === "GET").slice(0, MAX_PROBE_ROUTES);
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

/** 写操作 IDOR 会修改目标数据：仅在 blackbox.allowMutation=true 时执行，并尽力恢复。 */
async function probePutIdor(ctx, baseUrl, routes, { attacker, victim }) {
  const records = [];
  for (const route of routes.filter((r) => r.method === "GET").slice(0, MAX_PROBE_ROUTES)) {
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
    const payload = { [field]: `${original}_gb` };
    const attack = await httpJson(ctx, { baseUrl, method: "PUT", path: detailPath, identity: attacker.name, body: payload });
    const changed = attack.ok && attack.json && JSON.stringify(attack.json).includes(`${original}_gb`);
    if (changed) {
      await httpJson(ctx, { baseUrl, method: "PUT", path: detailPath, identity: victim.name, body: { [field]: original } });
    }
    const rec = makeRecord(ctx, baseUrl, {
      caseId: `blackbox-idor-put-${detailPath.replace(/[^a-z0-9]+/gi, "-").replace(/^-|-$/g, "")}`,
      name: `黑盒·跨用户修改（IDOR-PUT）${detailPath}`,
      method: "PUT",
      path: detailPath,
      identity: attacker.name,
      body: payload,
      res: attack,
      expectation: "身份 A 不得修改身份 B 的对象",
      verdict: changed ? VERDICT.VULNERABLE : isDenied(attack.status) ? VERDICT.BLOCKED : VERDICT.INCONCLUSIVE,
      actual: changed
        ? `${attacker.name} 修改 ${victim.name} 的对象 #${victimId} 成功（字段 ${field}）`
        : `HTTP ${attack.status}，未观察到修改生效`,
      grade: changed ? "cross-proven" : "http-only",
      crossProof: changed ? `写后响应包含新值 ${field}=${original}_gb；已尝试恢复原值` : null,
      impact: changed ? "可修改他人业务对象" : null,
    });
    records.push(rec);
    emitRecord(ctx, rec);
  }
  return records;
}

const SQL_ERROR_SIGNATURES = [
  "SQL syntax", "MySQL server", "SQLite3::query", "ORA-", "PostgreSQL",
  "Microsoft SQL Server", "Unclosed quotation mark", "near \"", "syntax error",
];

async function probeSqli(ctx, baseUrl, routes, identity) {
  const records = [];
  for (const route of routes.filter((r) => r.method === "GET").slice(0, MAX_PROBE_ROUTES)) {
    const basePath = route.path;
    const sep = basePath.includes("?") ? "&" : "?";
    const baseline1 = await httpJson(ctx, { baseUrl, method: "GET", path: `${basePath}${sep}q=test`, identity });
    if (baseline1.status === 0) continue;
    const baseline2 = await httpJson(ctx, { baseUrl, method: "GET", path: `${basePath}${sep}q=test`, identity });
    const len = (r) => (r.body ?? "").length;
    const b1 = len(baseline1);
    const b2 = len(baseline2);
    const stable = b1 > 0 && Math.abs(b1 - b2) <= Math.max(1, b1 * 0.1);

    const errRes = await httpJson(ctx, {
      baseUrl,
      method: "GET",
      path: `${basePath}${sep}q=${encodeURIComponent("' OR 1=1--")}`,
      identity,
    });
    const errBody = errRes.body ?? "";
    const signature = SQL_ERROR_SIGNATURES.find((s) => errBody.includes(s));
    if (signature) {
      const rec = makeRecord(ctx, baseUrl, {
        caseId: `blackbox-sqli-error-${basePath.replace(/[^a-z0-9]+/gi, "-").replace(/^-|-$/g, "")}`,
        name: `黑盒·SQL 注入（错误回显）${basePath}`,
        method: "GET",
        path: `${basePath}${sep}q=' OR 1=1--`,
        identity,
        res: errRes,
        expectation: "输入不得进入 SQL 语句导致数据库错误回显",
        verdict: VERDICT.VULNERABLE,
        actual: `响应包含数据库错误特征：${signature}`,
        impact: "SQL 注入（错误回显）",
      });
      records.push(rec);
      emitRecord(ctx, rec);
      continue;
    }

    if (!stable) continue;
    const trueRes = await httpJson(ctx, {
      baseUrl,
      method: "GET",
      path: `${basePath}${sep}q=${encodeURIComponent("test' AND 1=1--")}`,
      identity,
    });
    const falseRes = await httpJson(ctx, {
      baseUrl,
      method: "GET",
      path: `${basePath}${sep}q=${encodeURIComponent("test' AND 1=2--")}`,
      identity,
    });
    const t = len(trueRes);
    const f = len(falseRes);
    const trueClose = Math.abs(t - b1) <= Math.max(1, b1 * 0.2);
    const falseDiff = Math.abs(f - b1) > Math.max(16, b1 * 0.3);
    if (isOk(trueRes.status) && isOk(falseRes.status) && trueClose && falseDiff) {
      const rec = makeRecord(ctx, baseUrl, {
        caseId: `blackbox-sqli-blind-${basePath.replace(/[^a-z0-9]+/gi, "-").replace(/^-|-$/g, "")}`,
        name: `黑盒·SQL 注入（布尔盲注）${basePath}`,
        method: "GET",
        path: `${basePath}${sep}q=test' AND 1=1--`,
        identity,
        res: falseRes,
        expectation: "布尔条件不应改变查询结果集",
        verdict: VERDICT.VULNERABLE,
        actual: `真条件响应 ${t}B ≈ 基线 ${b1}B，假条件 ${f}B 差异显著`,
        impact: "SQL 注入（布尔盲注）",
      });
      records.push(rec);
      emitRecord(ctx, rec);
    }
  }
  return records;
}

const TRAVERSAL_PAYLOADS = ["../../../../etc/passwd", "..%2F..%2F..%2F..%2Fetc%2Fpasswd", "..\\..\\..\\..\\windows\\win.ini"];
const TRAVERSAL_SIGNATURES = ["root:x:", "[fonts]", "[extensions]"];
const TRAVERSAL_TEMPLATES = ["/api/files/{p}", "/files/{p}", "/static/{p}", "/download/{p}", "/api/download/{p}"];

async function probeTraversal(ctx, baseUrl, identity) {
  const records = [];
  const tried = new Set();
  for (const tpl of TRAVERSAL_TEMPLATES) {
    for (const p of TRAVERSAL_PAYLOADS) {
      const path = tpl.replace("{p}", p);
      if (tried.has(path)) continue;
      tried.add(path);
      const res = await httpJson(ctx, { baseUrl, method: "GET", path, identity });
      const body = res.body ?? "";
      const signature = TRAVERSAL_SIGNATURES.find((s) => body.includes(s));
      if (!signature) continue;
      const rec = makeRecord(ctx, baseUrl, {
        caseId: `blackbox-traversal-${path.replace(/[^a-z0-9]+/gi, "-").replace(/^-|-$/g, "")}`,
        name: `黑盒·路径穿越 ${path}`,
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
      break;
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
  ctx.emit({ kind: "phase", severity: SEVERITY.INFO, message: `开始黑盒外部扫描：${baseUrl}`, phase: "blackbox" });

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
      openapiFound: false,
      openapiRouteCount: 0,
      findings: [],
      evidence: [],
      summary: summarize([], [], { attempted: false, ok: false, path: null, identities: [] }),
      rateLimited: false,
      reachable: false,
      login: null,
      configuredMutation: !!options.allowMutation,
    };
  }

  const openapiFound = await discoverOpenapi(ctx, baseUrl);
  const openapi = openapiRoutes(openapiFound);
  const brute = await bruteRoutes(ctx, baseUrl);
  const routes = mergeRoutes(openapi, brute);
  const surface = await probeAttackSurface(ctx, baseUrl);
  const rate = await checkRateLimit(ctx, baseUrl);
  const rateLimited = rate.limited;

  const login = await tryLogin(ctx, baseUrl, options.config ?? {});
  const users = login.identities.filter((i) => i.role !== "admin");
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
  const probes = [];
  probes.push(...(await probeUnauthRead(ctx, baseUrl, routes)));
  if (pair) probes.push(...(await probeIdor(ctx, baseUrl, routes, pair)));
  if (who) probes.push(...(await probeSqli(ctx, baseUrl, routes, who)));
  probes.push(...(await probeTraversal(ctx, baseUrl, who)));
  if (pair && options.allowMutation) {
    probes.push(...(await probePutIdor(ctx, baseUrl, routes, pair)));
  } else if (pair) {
    ctx.emit({
      kind: "discovery",
      severity: SEVERITY.INFO,
      message: "写操作类越权探测（PUT IDOR）默认关闭（会修改目标数据）；如需启用，在 guardbuild.json 设 blackbox.allowMutation=true 或环境变量 GUARDBUILD_BLACKBOX_MUTATE=1",
      data: { allowMutation: false },
    });
  }

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
    openapiFound: !!openapiFound,
    openapiRouteCount: openapi.length,
    findings,
    evidence: records,
    summary,
    rateLimited,
    reachable: rate.reachable,
    login: summary.login,
    configuredMutation: !!options.allowMutation,
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
