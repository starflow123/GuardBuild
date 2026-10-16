/**
 * Supabase / PostgREST 适配器。
 *
 * 静态检测：项目是否使用 Supabase（createClient / @supabase/supabase-js / .from("表")），
 * 从 .env 或代码字面量提取项目 URL 与 anon key，并识别 service_role 密钥的客户端暴露
 * （客户端前缀环境变量或硬编码 JWT 字面量）——该密钥可绕过 RLS 读写全库，属严重泄露。
 *
 * 动态探测：用 anon key 直连 `{url}/rest/v1/{表}?select=*&limit=3`（PostgREST 匿名接口），
 * 命中真实数据行即证明 RLS（行级安全）缺失——匿名可读用户数据，属可复现的数据暴露。
 *
 * 该漏洞类不在代码层修复（RLS 是数据库策略），因此流水线只取证、不生成补丁：
 * 证据成立 → vulnerable_unfixed（exit 1），报告给出 SQL 加固指引。
 *
 * 密钥处理约定：anon key / service_role 值只在 Sidecar 内存与探测请求头中使用，
 * 绝不写入事件、证据与报告（证据中的请求头为掩码形式）。
 */
import { RPC_TO_HOST, VERDICT, CASE_CATEGORY, SEVERITY, shortId } from "../../shared/protocol.mjs";

/** 参与探测的表上限与每表取样行数 */
export const MAX_TABLES = 8;
export const RLS_LIMIT = 3;

/** 环境文件读取顺序（先到先得；.local 覆盖语义按常见工具约定从高到低） */
export const ENV_FILES = [
  ".env.local",
  ".env.development.local",
  ".env.production.local",
  ".env.development",
  ".env.production",
  ".env",
];

/** 判定敏感列（命中即升级为内容级证据） */
const SENSITIVE_COL = /(email|phone|mobile|address|ssn|id_?card|passport|password|passwd|token|secret|balance|bank|birth|realname|real_?name|nickname|username)/i;

/** 客户端可读环境变量前缀（Next/Vite/CRA/Expo/Gatsby/Nuxt）——以此为前缀的密钥会进入前端产物 */
const CLIENT_ENV_PREFIX = /^(NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|PUBLIC_|GATSBY_|NUXT_PUBLIC_)/;

const JWT_LITERAL = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b/g;
const PLACEHOLDER = /^(your|xxx|example|placeholder|changeme|todo|none|null|dummy|test-)/i;

export function isLoopbackHostname(hostname) {
  return hostname === "127.0.0.1" || hostname === "localhost" || hostname === "::1" || hostname === "[::1]";
}

function lineOf(content, index) {
  let line = 1;
  for (let i = 0; i < index && i < content.length; i += 1) if (content[i] === "\n") line += 1;
  return line;
}

/** 解析 .env 文本为键值 Map（去注释/引号；忽略空值） */
export function parseEnvContent(text) {
  const out = new Map();
  for (const raw of String(text ?? "").split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const m = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line);
    if (!m) continue;
    let value = m[2].trim();
    if (value.length >= 2 && ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'")))) {
      value = value.slice(1, -1);
    }
    if (!value) continue;
    out.set(m[1], value);
  }
  return out;
}

/** 解码 JWT 载荷（base64url 中段）→ 对象；非 JWT 返回 null */
export function decodeJwtPayload(token) {
  const part = String(token ?? "").split(".")[1];
  if (!part) return null;
  try {
    const payload = JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
    return payload && typeof payload === "object" ? payload : null;
  } catch {
    return null;
  }
}

export function jwtRole(token) {
  return decodeJwtPayload(token)?.role ?? null;
}

function isPlaceholder(v) {
  return PLACEHOLDER.test(String(v).trim());
}

/** 顶层逗号切分（忽略括号/引号内的逗号） */
function splitTopLevel(s) {
  const out = [];
  let depth = 0;
  let cur = "";
  let quote = null;
  for (const ch of s) {
    if (quote) {
      cur += ch;
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") {
      quote = ch;
      cur += ch;
      continue;
    }
    if (ch === "(" || ch === "[" || ch === "{") depth += 1;
    else if (ch === ")" || ch === "]" || ch === "}") depth -= 1;
    else if (ch === "," && depth === 0) {
      out.push(cur.trim());
      cur = "";
      continue;
    }
    cur += ch;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

/** 取 openIdx 处 '(' 之后到配平 ')' 的实参文本（跳字符串引号） */
function callArgSpan(text, openIdx) {
  let depth = 0;
  let quote = null;
  for (let i = openIdx; i < text.length; i += 1) {
    const ch = text[i];
    if (quote) {
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") quote = ch;
    else if (ch === "(") depth += 1;
    else if (ch === ")") {
      depth -= 1;
      if (depth === 0) return text.slice(openIdx + 1, i);
    }
  }
  return null;
}

/**
 * 静态检测（纯函数）。files 为「疑似 Supabase 相关」源文件（可含未脱敏内容——
 * 检测需要在调用方做 I/O 与筛选；密钥值不会进入返回值之外的任何展示面）。
 * @returns {{detected:boolean, url:string|null, urlSource:string|null, anonKey:string|null,
 *   anonKeySource:string|null, keyRole:string|null, serviceRoleLeak:object|null,
 *   serviceRoleEnvs:Array, tables:Array, files:string[], probeable:boolean}}
 */
export function detectSupabaseStatic({ files = [], envVars = new Map(), envFileNames = [], overrides = {} } = {}) {
  const tables = [];
  const seenTables = new Set();
  const signalFiles = [];
  let url = typeof overrides.url === "string" && overrides.url ? overrides.url.replace(/\/+$/, "") : null;
  let urlSource = url ? "guardbuild.json" : null;
  let anonKey = typeof overrides.anonKey === "string" && overrides.anonKey ? overrides.anonKey : null;
  let anonKeySource = anonKey ? "guardbuild.json" : null;
  let literalAnonKey = null;
  let serviceRoleLeak = null;
  let envUrlRef = null;
  let envKeyRef = null;

  for (const f of files) {
    const content = String(f.content ?? "");
    const path = f.path ?? "(unknown)";
    if (!/supabase/i.test(content) && !/createClient\s*\(/.test(content)) continue;
    signalFiles.push(path);

    for (const m of content.matchAll(/\.\s*from\s*\(\s*["'`]([A-Za-z_][A-Za-z0-9_]*)["'`]\s*\)/g)) {
      if (seenTables.has(m[1])) continue;
      seenTables.add(m[1]);
      tables.push({ name: m[1], file: path, line: lineOf(content, m.index) });
    }

    for (const m of content.matchAll(new RegExp(`createClient\\s*\\(`, "g"))) {
      const argsText = callArgSpan(content, m.index + m[0].length - 1);
      if (!argsText) continue;
      const [p0 = "", p1 = ""] = splitTopLevel(argsText);
      const e0 = /(?:process\.env|import\.meta\.env)\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)/.exec(p0);
      const e1 = /(?:process\.env|import\.meta\.env)\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)/.exec(p1);
      if (e0) envUrlRef = envUrlRef ?? e0[1];
      if (e1) envKeyRef = envKeyRef ?? e1[1];
      const lit = /["'`](https?:\/\/[^"'`\s]+)["'`]/.exec(p0);
      if (lit && !url) {
        url = lit[1].replace(/\/+$/, "");
        urlSource = `${path}:${lineOf(content, m.index)}`;
      }
    }

    for (const m of content.matchAll(JWT_LITERAL)) {
      const role = jwtRole(m[0]);
      if (role === "service_role" && !serviceRoleLeak) {
        serviceRoleLeak = { source: "hardcoded-literal", file: path, line: lineOf(content, m.index) };
      } else if (role === "anon" && !literalAnonKey) {
        literalAnonKey = { value: m[0], file: path, line: lineOf(content, m.index) };
      }
    }
  }

  // 环境变量解析：显式声明(código createClient 引用) > 通用命名族
  const pickEnv = (names) => {
    for (const n of names) {
      if (!n) continue;
      const v = envVars.get(n);
      if (!v || isPlaceholder(v)) continue;
      return { name: n, value: v };
    }
    return null;
  };
  const urlEnv = pickEnv([
    envUrlRef,
    "SUPABASE_URL",
    "NEXT_PUBLIC_SUPABASE_URL",
    "VITE_SUPABASE_URL",
    "REACT_APP_SUPABASE_URL",
    "EXPO_PUBLIC_SUPABASE_URL",
    "PUBLIC_SUPABASE_URL",
    "GATSBY_SUPABASE_URL",
    "NUXT_PUBLIC_SUPABASE_URL",
  ]);
  const keyEnv = pickEnv([
    envKeyRef,
    "SUPABASE_ANON_KEY",
    "SUPABASE_KEY",
    "NEXT_PUBLIC_SUPABASE_ANON_KEY",
    "VITE_SUPABASE_ANON_KEY",
    "REACT_APP_SUPABASE_ANON_KEY",
    "EXPO_PUBLIC_SUPABASE_ANON_KEY",
    "PUBLIC_SUPABASE_ANON_KEY",
    "NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY",
    "SUPABASE_PUBLISHABLE_KEY",
  ]);

  if (!url && urlEnv) {
    url = urlEnv.value.replace(/\/+$/, "");
    urlSource = `${envFileNames[0] ?? ".env"}:${urlEnv.name}`;
  }
  if (!anonKey) {
    if (literalAnonKey) {
      anonKey = literalAnonKey.value;
      anonKeySource = `${literalAnonKey.file}:${literalAnonKey.line}`;
    } else if (keyEnv) {
      anonKey = keyEnv.value;
      anonKeySource = `${envFileNames[0] ?? ".env"}:${keyEnv.name}`;
    }
  }

  // service_role 的环境变量暴露面（客户端前缀 = 会进入前端产物，属泄露）
  const serviceRoleEnvs = [];
  for (const name of envVars.keys()) {
    if (!/SERVICE_ROLE/i.test(name)) continue;
    const clientExposed = CLIENT_ENV_PREFIX.test(name);
    serviceRoleEnvs.push({ name, clientExposed });
    if (clientExposed && !serviceRoleLeak) {
      serviceRoleLeak = { source: "env-client-prefix", name };
    }
  }

  if (Array.isArray(overrides.tables)) {
    for (const t of overrides.tables) {
      if (typeof t !== "string" || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(t) || seenTables.has(t)) continue;
      seenTables.add(t);
      tables.push({ name: t, file: "guardbuild.json", line: null });
    }
  }

  const result = {
    detected: signalFiles.length > 0 || !!(url && anonKey),
    url,
    urlSource,
    anonKey,
    anonKeySource,
    keyRole: anonKey ? jwtRole(anonKey) : null,
    serviceRoleLeak,
    serviceRoleEnvs,
    tables,
    files: signalFiles,
    envFiles: envFileNames,
  };
  result.probeable = !!result.url && !!result.anonKey && result.tables.length > 0;
  return result;
}

/**
 * 检测执行入口（I/O 层）：读环境文件 + 对 Supabase 相关源码做一次未脱敏复读
 * （JWT 会被 Host 脱敏器掩码，角色判定需要原文；仅限命中 supabase 关键词的少量文件）。
 * 任何失败都不影响主流程：返回 null 表示未检测到。
 */
export async function detectSupabase(ctx, { readContents = [] } = {}) {
  const base = String(ctx.projectRoot).replace(/[\\/]+$/, "");
  const overrides = ctx.targetConfig?.supabase ?? {};
  const envFiles = Array.isArray(overrides.envFile) ? overrides.envFile : overrides.envFile ? [overrides.envFile] : ENV_FILES;

  const envVars = new Map();
  const envFileNames = [];
  for (const name of envFiles) {
    try {
      const res = await ctx.rpc.request(
        RPC_TO_HOST.FS_READ,
        { token: ctx.tokens.project, path: `${base}/${name}`, redact: false },
        { timeoutMs: 15_000 }
      );
      envFileNames.push(name);
      for (const [k, v] of parseEnvContent(res.content)) if (!envVars.has(k)) envVars.set(k, v);
    } catch {
      /* 文件不存在或不可读：跳过 */
    }
  }

  // 疑似 Supabase 相关文件（脱敏内容即可判定相关性：import/表名/环境变量名不受脱敏影响）
  const suspects = readContents.filter(
    (f) => /supabase/i.test(f.content) || /createClient\s*\(/.test(f.content)
  );
  const files = [];
  for (const f of suspects.slice(0, 8)) {
    try {
      const res = await ctx.rpc.request(
        RPC_TO_HOST.FS_READ,
        { token: ctx.tokens.project, path: f.path, redact: false },
        { timeoutMs: 15_000 }
      );
      files.push({ path: f.path, content: res.content });
    } catch {
      files.push({ path: f.path, content: f.content });
    }
  }

  let info;
  try {
    info = detectSupabaseStatic({ files, envVars, envFileNames, overrides });
  } catch {
    return null;
  }
  if (!info.detected) return null;

  const notes = [];
  if (info.url) notes.push(`项目 URL ${info.url}（来源 ${info.urlSource}）`);
  notes.push(`表引用 ${info.tables.length} 个`);
  if (info.anonKey) notes.push(`anon key 已定位（${info.anonKeySource}${info.keyRole ? `，角色 ${info.keyRole}` : ""}）`);
  else notes.push("未定位 anon key（无法动态探测，仅静态线索）");
  ctx.emit({
    kind: "analyze",
    severity: info.serviceRoleLeak ? SEVERITY.ERROR : SEVERITY.WARN,
    message: `检测到 Supabase 使用：${notes.join("；")}`,
    phase: null,
    data: {
      url: info.url,
      tables: info.tables.map((t) => t.name),
      anonKeySource: info.anonKeySource,
      serviceRoleLeak: info.serviceRoleLeak ? { source: info.serviceRoleLeak.source, file: info.serviceRoleLeak.file ?? null, name: info.serviceRoleLeak.name ?? null } : null,
      probeable: info.probeable,
    },
  });
  return info;
}

/** 敏感列检测：命中即升级证据级别（内容级） */
function sensitiveColumns(row) {
  if (!row || typeof row !== "object") return [];
  return Object.keys(row).filter((k) => SENSITIVE_COL.test(k));
}

function supabaseCaseId(table) {
  return `attack-supabase-rls-${String(table).replace(/[^A-Za-z0-9_-]/g, "_")}`;
}

/**
 * 动态探测一个 anon key 可读的表；返回证据记录（形状与 probe.runPhase 一致）。
 * token 若为空表示无法探测（返回 null）。
 */
async function probeTable(ctx, { base, table, anonKey, token, phase }) {
  const path = `/rest/v1/${encodeURIComponent(table)}?select=*&limit=${RLS_LIMIT}`;
  let res;
  try {
    res = await ctx.rpc.request(
      RPC_TO_HOST.HTTP_REQUEST,
      {
        token,
        method: "GET",
        url: `${base}${path}`,
        headers: { apikey: anonKey, Authorization: `Bearer ${anonKey}`, Accept: "application/json" },
        redact: true,
      },
      { timeoutMs: 30_000 }
    );
  } catch (e) {
    return {
      record: {
        id: shortId("ev"),
        sessionId: ctx.sessionId,
        phase,
        identity: "(anonymous/anon-key)",
        method: "GET",
        endpoint: path,
        request: {
          url: `${base}${path}`,
          headers: { apikey: "***anon-key***", Authorization: "***anon-key***", Accept: "application/json" },
        },
        response: { status: 0, statusText: "request_failed", body: String(e.message ?? e), redacted: false, durationMs: null },
        decision: null,
        crossProof: null,
        evidenceGrade: "http-only",
        expectation: `匿名（仅携公开 anon key）读取表 ${table} 必须被 RLS 拒绝或返回空集`,
        verdict: VERDICT.INCONCLUSIVE,
        actual: `探测请求失败：${e.message ?? e}`,
        impact: null,
        caseId: supabaseCaseId(table),
        caseCategory: CASE_CATEGORY.ATTACK,
        caseName: `匿名单读 Supabase 表「${table}」`,
        createdAt: Date.now(),
      },
      error: e,
    };
  }

  let rows = null;
  try {
    const parsed = JSON.parse(res.body);
    if (Array.isArray(parsed)) rows = parsed;
  } catch {
    /* 非 JSON */
  }
  const leaked = Array.isArray(rows) && rows.length > 0;
  const cols = leaked ? Object.keys(rows[0] ?? {}) : [];
  const sens = leaked ? sensitiveColumns(rows[0]) : [];
  const sensText = sens.length ? `，含敏感列 ${sens.join("、")}` : "";

  let verdict;
  let actual;
  if (res.status >= 200 && res.status < 300 && leaked) {
    verdict = VERDICT.VULNERABLE;
    actual = `HTTP ${res.status}，匿名 anon key 读取到 ${rows.length} 行数据（列：${cols.slice(0, 8).join("、")}${cols.length > 8 ? "…" : ""}）${sensText}`;
  } else if (res.status >= 200 && res.status < 300) {
    verdict = VERDICT.INCONCLUSIVE;
    actual = `HTTP ${res.status}，匿名仅见空集（RLS 已启用、策略限制或表为空），未取得数据`;
  } else if (res.status === 401 || res.status === 403) {
    verdict = VERDICT.INCONCLUSIVE;
    actual = `HTTP ${res.status}，匿名访问被拒绝（表受保护）`;
  } else if (res.status === 404) {
    verdict = VERDICT.INCONCLUSIVE;
    actual = `HTTP 404，表不存在或未暴露（PostgREST schema）`;
  } else {
    verdict = VERDICT.INCONCLUSIVE;
    actual = `HTTP ${res.status}，探测未取得数据`;
  }

  const crossProof = leaked && sens.length ? `匿名响应包含敏感字段：${sens.join("、")}（内容级证据）` : null;
  const record = {
    id: shortId("ev"),
    sessionId: ctx.sessionId,
    phase,
    identity: "(anonymous/anon-key)",
    method: "GET",
    endpoint: path,
    request: {
      url: `${base}${path}`,
      headers: { apikey: "***anon-key***", Authorization: "***anon-key***", Accept: "application/json" },
    },
    response: {
      status: res.status,
      statusText: res.statusText,
      body: res.body ?? "",
      redacted: !!res.redacted,
      durationMs: res.durationMs ?? null,
    },
    decision: null,
    crossProof,
    evidenceGrade: leaked ? (sens.length ? "cross-proven" : "http-only") : "http-only",
    expectation: `匿名（仅携公开 anon key）读取表 ${table} 必须被 RLS 拒绝或返回空集`,
    verdict,
    actual,
    impact: leaked ? `匿名可读取表「${table}」数据（本次取样 ${rows.length} 行），可通过分页遍历全表` : null,
    caseId: supabaseCaseId(table),
    caseCategory: CASE_CATEGORY.ATTACK,
    caseName: `匿名单读 Supabase 表「${table}」`,
    createdAt: Date.now(),
  };
  return { record, rows };
}

/**
 * 执行 Supabase 探测阶段：对每个表构造攻击用例（匿名单读），返回 {evidence, summary}。
 * token 为可用网络令牌（回环用 net.probe，远程 https 用 net.egress）。
 */
export async function runSupabasePhase(ctx, { phase = "pre", token } = {}) {
  const supa = ctx.plan?.supabase;
  const empty = {
    evidence: [],
    summary: {
      phase,
      baseUrl: supa?.url ?? null,
      counts: {},
      grades: {},
      total: 0,
      attackRepro: 0,
      attackBlocked: 0,
      attackRegressed: 0,
      businessPassed: 0,
      businessRegressed: 0,
      businessTotal: 0,
      targets: {},
    },
    leaks: 0,
  };
  if (!supa?.probeable || !token) return empty;

  const base = String(supa.url).replace(/\/+$/, "");
  ctx.emit({
    kind: "phase",
    severity: SEVERITY.INFO,
    message: `开始 Supabase RLS 探测：匿名 anon key 直连 ${base}/rest/v1/（${Math.min(supa.tables.length, MAX_TABLES)} 个表）`,
    phase,
    data: { baseUrl: base, tables: supa.tables.slice(0, MAX_TABLES).map((t) => t.name) },
  });

  const evidence = [];
  let networkFailures = 0;
  for (const t of supa.tables.slice(0, MAX_TABLES)) {
    const { record, error } = await probeTable(ctx, { base, table: t.name, anonKey: supa.anonKey, token, phase });
    if (error) networkFailures += 1;
    evidence.push(record);
    ctx.db.insertEvidence(record);
    const severity =
      record.verdict === VERDICT.VULNERABLE ? SEVERITY.ERROR : SEVERITY.INFO;
    ctx.emit({
      kind: "evidence",
      severity,
      message: `[${phase === "pre" ? "修复前" : "修复后"}] ${record.caseName} → ${record.actual}${record.impact ? ` · ${record.impact}` : ""}`,
      phase,
      data: {
        evidenceId: record.id,
        caseId: record.caseId,
        category: record.caseCategory,
        verdict: record.verdict,
        status: record.response.status,
        evidenceGrade: record.evidenceGrade,
        crossProof: record.crossProof,
        decision: null,
      },
    });
  }

  if (networkFailures === evidence.length && evidence.length > 0) {
    const first = evidence[0]?.actual ?? "";
    throw Object.assign(new Error(`Supabase 探测请求全部失败（${evidence.length} 个表）`), {
      code: "supabase_probe_failed",
      hint: `请确认项目 URL 可达、anon key 有效；远程主机需 net.egress 授权（gate 模式请在 guardbuild.json 声明 net.egress:<host>）。首个失败：${first}`,
    });
  }

  const counts = { vulnerable: 0, blocked: 0, passed: 0, regressed: 0, inconclusive: 0 };
  for (const e of evidence) counts[e.verdict] = (counts[e.verdict] ?? 0) + 1;
  const grades = { strong: 0, "cross-proven": 0, "http-only": 0 };
  for (const e of evidence) grades[e.evidenceGrade] = (grades[e.evidenceGrade] ?? 0) + 1;
  const leaks = evidence.filter((e) => e.verdict === VERDICT.VULNERABLE).length;
  const summary = {
    phase,
    baseUrl: base,
    counts,
    grades,
    total: evidence.length,
    attackRepro: leaks,
    attackBlocked: 0,
    attackRegressed: 0,
    businessPassed: 0,
    businessRegressed: 0,
    businessTotal: 0,
    targets: { supabaseTables: evidence.map((e) => e.endpoint.split("/rest/v1/")[1]?.split("?")[0] ?? "") },
  };
  ctx.emit({
    kind: "phase_summary",
    severity: leaks > 0 ? SEVERITY.ERROR : SEVERITY.SUCCESS,
    message:
      leaks > 0
        ? `Supabase RLS 探测完成：${leaks}/${evidence.length} 个表匿名可读（RLS 缺失或策略过宽）`
        : `Supabase RLS 探测完成：${evidence.length} 个表均未匿名泄露数据`,
    phase,
    data: { ...summary, leaks },
  });
  return { evidence, summary, leaks };
}
