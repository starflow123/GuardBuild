/**
 * LLM 接入侦察：让 DeepSeek 只推断「怎么启动 / 怎么登录 / 有哪些路由」，
 * 不判定漏洞、不生成身份、不批准补丁、不决定扫描范围。
 *
 * 四道关（全部通过才进入主流程）：
 *  1. schema 与白名单：启动器、端口槽位、参数、登录字段、路由形态；
 *  2. 代码定位：LLM 给的路由文件必须真实存在，且文件里能找到对应路径；
 *  3. 实际启动：交给正常流程 spawn，启动失败按现有诊断处理；
 *  4. 实际登录：交给正常流程 loginAll，失败会记录 login_rejected 等诊断。
 *
 * 无 key / 超时 / 非法输出时返回 null，主流程继续走确定性逻辑。
 */
import { createHash } from "node:crypto";
import { RPC_TO_HOST } from "../../shared/protocol.mjs";
import { ALLOWED_LAUNCHERS, GENERIC_READY_PATTERN, PORT_SLOT } from "./autostart.mjs";
import { normalizeStart, normalizeLogin } from "./targetconfig.mjs";
import { isEnabled, chat, parseJson } from "./llm.mjs";

export const SCOUT_VERSION = "scout-v1";
const CACHE_TTL_MS = 30 * 60 * 1000;
const CACHE_MAX = 20;
const SCOUT_CACHE = new Map();

const MAX_TREE_ENTRIES = 300;
const MAX_FILES = 8;
const MAX_FILE_CHARS = 4000;
const MAX_TOTAL_CHARS = 24000;
const MAX_ROUTE_FILES = 20;
const MAX_ROUTE_FILE_BYTES = 128 * 1024;
const MAX_ROUTES = 30;
const READ_FILE_TIMEOUT_MS = 15_000;
const SCOUT_TIMEOUT_MS = 60_000;

const IGNORED_SEGMENTS = new Set([
  "node_modules", ".git", ".svn", "dist", "build", "out", "target", "coverage",
  ".next", ".nuxt", ".turbo", ".cache", ".venv", "venv", "__pycache__", "vendor",
  ".idea", ".vscode",
]);
const SOURCE_EXT_RE = /\.(?:js|mjs|cjs|ts|tsx|jsx|py|go|rb|php|cs|java|kt|graphql|gql)$/i;
const MANIFEST_NAMES = new Set([
  "package.json", "pyproject.toml", "requirements.txt", "pipfile", "go.mod",
  "cargo.toml", "composer.json", "gemfile", "procfile", "dockerfile",
  "docker-compose.yml", "compose.yaml",
]);
const ENTRY_RE = /(^|\/)(?:server|app|index|main|api|run|manage|wsgi|asgi|entry|bootstrap)\.(?:js|mjs|cjs|ts|py|go|rb|php|cs|java)$/i;
const ROUTE_HINT_RE = /(^|\/)(?:routes?|controllers?|handlers?|endpoints?|views?|api|resolvers?)\//i;
const SENSITIVE_FILE_RE =
  /(^|\/)(?:\.env(?:\..*)?|.*\.(?:pem|key|p12|pfx|crt)|id_rsa.*|credentials.*|secrets?\.(?:json|ya?ml|txt)|.*\.(?:sqlite|sqlite3|db)|package-lock\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lockb)$/i;

const HTTP_METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE"]);
const SHELL_META_RE = /[;&|`<>]|\$\(/;
const CREDENTIAL_HEADER_RE = /^[A-Za-z0-9-]{1,64}$/;
const JSON_PATH_RE = /^[A-Za-z0-9_.[\]-]{1,120}$/;

function normPath(p) {
  return String(p ?? "").replace(/\\/g, "/").replace(/^\/\/\?\//, "").replace(/\/+/g, "/");
}

function relOf(root, abs) {
  const r = normPath(root).replace(/\/+$/, "");
  const n = normPath(abs);
  return n.startsWith(`${r}/`) ? n.slice(r.length + 1) : null;
}

function pathAllowed(rel) {
  if (!rel) return false;
  const segs = rel.split("/");
  if (segs.some((s) => IGNORED_SEGMENTS.has(s.toLowerCase()))) return false;
  return !SENSITIVE_FILE_RE.test(rel);
}

function safeRel(v) {
  const rel = normPath(v).replace(/^\.\//, "");
  if (!rel || rel.startsWith("/") || /^[A-Za-z]:/.test(rel)) return null;
  if (rel.split("/").some((s) => s === ".." || s === "")) return null;
  return rel.length <= 200 ? rel : null;
}

function safeHttpPath(v) {
  const p = String(v ?? "").trim();
  if (!p.startsWith("/") || p.length > 200) return null;
  if (/[\s\r\n\0]/.test(p) || p.includes("://") || p.includes("..")) return null;
  return p;
}

async function readProjectText(ctx, rel) {
  const base = normPath(ctx.projectRoot).replace(/\/+$/, "");
  const res = await ctx.rpc.request(
    RPC_TO_HOST.FS_READ,
    { token: ctx.tokens.project, path: `${base}/${rel}`, redact: true },
    { timeoutMs: READ_FILE_TIMEOUT_MS }
  );
  return typeof res?.content === "string" ? res.content : "";
}

/** 列目录 + 读取有限的脱敏片段；绝不读取 .env / 密钥 / 锁文件。 */
export async function collectEvidence(ctx, { maxFiles = MAX_FILES } = {}) {
  const root = normPath(ctx.projectRoot).replace(/\/+$/, "");
  let entries = [];
  try {
    const res = await ctx.rpc.request(
      RPC_TO_HOST.FS_LIST,
      { token: ctx.tokens.project, path: root, depth: 3 },
      { timeoutMs: 30_000 }
    );
    entries = Array.isArray(res?.entries) ? res.entries : [];
  } catch (e) {
    throw new Error(`无法列举项目目录：${e.message}`);
  }

  const files = [];
  const dirs = new Set(["."]);
  const seen = new Set();
  for (const e of entries) {
    const rel = relOf(root, e.path);
    if (!rel || !pathAllowed(rel)) continue;
    if (seen.has(rel)) continue;
    seen.add(rel);
    if (e.kind === "dir") {
      dirs.add(rel);
      continue;
    }
    if (e.kind !== "file" && e.kind !== "symlink") continue;
    files.push({ rel, size: Number(e.size) || 0 });
  }

  const scored = files
    .map((f) => {
      const base = f.rel.split("/").pop().toLowerCase();
      const depth = f.rel.split("/").length - 1;
      let score = 99;
      if (MANIFEST_NAMES.has(base)) score = depth === 0 ? 0 : 1;
      else if (ENTRY_RE.test(f.rel)) score = 2;
      else if (SOURCE_EXT_RE.test(f.rel) && ROUTE_HINT_RE.test(f.rel)) score = 3;
      else if (SOURCE_EXT_RE.test(f.rel) && depth <= 2) score = 5;
      return { ...f, score, depth };
    })
    .filter((f) => f.score < 99 && f.size <= MAX_ROUTE_FILE_BYTES)
    .sort((a, b) => a.score - b.score || a.depth - b.depth || a.rel.localeCompare(b.rel));

  const picked = scored.slice(0, Math.max(1, Math.min(12, maxFiles)));
  const evidenceFiles = [];
  let totalChars = 0;
  for (const f of picked) {
    if (totalChars >= MAX_TOTAL_CHARS) break;
    let content;
    try {
      content = await readProjectText(ctx, f.rel);
    } catch {
      continue;
    }
    const budget = Math.min(MAX_FILE_CHARS, MAX_TOTAL_CHARS - totalChars);
    const truncated = content.length > budget;
    const slice = truncated ? content.slice(0, budget) : content;
    totalChars += slice.length;
    evidenceFiles.push({ rel: f.rel, content: slice, truncated, size: f.size });
  }

  const tree = [...dirs]
    .filter((d) => pathAllowed(d))
    .map((d) => (d === "." ? "." : `${d}/`))
    .concat(files.slice(0, MAX_TREE_ENTRIES).map((f) => f.rel))
    .slice(0, MAX_TREE_ENTRIES)
    .sort();

  return { root, tree, dirs, files: evidenceFiles, totalChars };
}

function buildPrompt(evidence) {
  const parts = [
    "=== 目录树（已排除 node_modules/.git/构建产物/密钥文件）===",
    evidence.tree.join("\n") || "(空)",
    "",
    "=== 关键文件片段（已脱敏，可能被截断）===",
  ];
  for (const f of evidence.files) {
    parts.push(`--- ${f.rel}${f.truncated ? "（截断）" : ""} ---`);
    parts.push(f.content);
    parts.push("");
  }
  return parts.join("\n");
}

const GB = "${GB_PORT}";
const SYSTEM_PROMPT = [
  "你是后端项目接入侦察助手。只根据用户给出的目录树和文件片段，推断如何启动服务、如何登录、有哪些按对象取数的 HTTP 路由。",
  "只返回一个 JSON 对象，不要 markdown 包裹，不要多余解释：",
  "{",
  '  "start": { "cmd": "node", "args": ["server.js"], "env": { "PORT": "' + GB + '" }, "cwd": null, "readyPattern": "listening", "readyTimeoutMs": 30000 } | null,',
  '  "login": { "path": "/api/login", "method": "POST", "bodyTemplate": { "email": "{email}", "password": "{password}" }, "credentialPath": "token", "credentialHeader": "Authorization", "credentialPrefix": "Bearer ", "userPath": null } | null,',
  '  "routes": [ { "method": "GET", "path": "/api/orders/:id", "file": "src/app.js", "line": 42, "resource": "order", "hasAuth": true },',
  '               { "method": "GET", "path": "/api/orders", "file": "src/app.js", "line": 20, "resource": "order", "hasAuth": true, "list": true, "hasOwnerFilter": true } ],',
  '  "notes": ["简短说明，最多 5 条"]',
  "}",
  "规则：",
  "- start.cmd 只能是 node / npm / npx / python / python3 / py / uvicorn / gunicorn / hypercorn / flask / fastapi / uv；",
  "- 端口必须使用 " + GB + " 占位符；不要输出固定端口；",
  "- 不要输出 identities、账号、密码、token 或任何密钥；身份由用户在 guardbuild.json 提供；",
  "- login 只描述请求形态，bodyTemplate 用 {email}/{username}/{password} 占位；",
  "- routes 只列证据中真实存在的路由；file 必须是证据里出现过的文件；line 尽量准确；",
  "- 单体路由必须带路径参数（:id / {id}）或查询参数；",
  "- 返回当前用户资源集合的列表路由（如 GET /api/orders）加 list:true；仅当代码确实按登录用户过滤时加 hasOwnerFilter:true，否则 false；",
  "- 不确定的字段用 null 或空数组，不要编造。",
].join("\n");

function sanitizeArgs(raw) {
  const list = Array.isArray(raw) ? raw.map(String) : [];
  if (list.length > 16) return null;
  const out = [];
  for (const a of list) {
    const arg = a.replace(/\$\{?PORT\}?/g, PORT_SLOT);
    if (arg.length > 200 || /[\r\n\0]/.test(arg)) return null;
    // 允许 ${GB_PORT}，其余 shell 元字符一律拒绝（Host 虽不经 shell，仍避免把危险参数传给子进程）
    if (SHELL_META_RE.test(arg.split(PORT_SLOT).join(""))) return null;
    out.push(arg);
  }
  return out;
}

/** 只允许把端口槽位注入到名称含 PORT 的环境变量，禁止 LLM 设置任意环境值。 */
function sanitizeEnv(raw) {
  const out = {};
  if (raw && typeof raw === "object" && !Array.isArray(raw)) {
    for (const [k, v] of Object.entries(raw).slice(0, 8)) {
      if (!/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(k) || !/PORT/i.test(k)) continue;
      if (typeof v !== "string") continue;
      if (v.trim().replace(/\$\{?PORT\}?/g, PORT_SLOT) === PORT_SLOT) out[k] = PORT_SLOT;
    }
  }
  if (Object.keys(out).length === 0) out.PORT = PORT_SLOT;
  return out;
}

function sanitizeReadyPattern(raw, warnings) {
  if (typeof raw !== "string" || !raw.trim()) return GENERIC_READY_PATTERN;
  const t = raw.trim();
  if (t.length > 80 || !/^[A-Za-z0-9 _.:-]+$/.test(t)) {
    warnings.push(`忽略无法安全使用的 readyPattern「${t.slice(0, 40)}」，改用通用监听日志模式`);
    return GENERIC_READY_PATTERN;
  }
  return t;
}

/** 启动契约白名单校验；不通过返回 null。 */
export function sanitizeStart(raw, { dirs = null } = {}, warnings = []) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  const cmd = typeof raw.cmd === "string" ? raw.cmd.trim() : "";
  const base = cmd.split(/[\\/]/).pop().replace(/\.(?:cmd|exe|bat)$/i, "").toLowerCase();
  if (!ALLOWED_LAUNCHERS.has(base)) {
    warnings.push(`拒绝 LLM 启动命令「${cmd || "(空)"}」：不在允许的启动器白名单内`);
    return null;
  }
  const args = sanitizeArgs(raw.args);
  if (!args) {
    warnings.push("拒绝 LLM 启动参数：含 shell 元字符或超长");
    return null;
  }
  let cwd = null;
  if (raw.cwd != null && String(raw.cwd).trim()) {
    cwd = safeRel(raw.cwd);
    if (!cwd || (dirs && !dirs.has(cwd))) {
      warnings.push(`拒绝 LLM 启动 cwd「${raw.cwd}」：不是项目内的已知目录`);
      cwd = null;
    }
  }
  let readyTimeoutMs = 30_000;
  if (Number.isFinite(raw.readyTimeoutMs)) {
    readyTimeoutMs = Math.min(120_000, Math.max(5_000, Math.floor(raw.readyTimeoutMs)));
  }
  return {
    cmd,
    args,
    env: sanitizeEnv(raw.env),
    cwd,
    readyPattern: sanitizeReadyPattern(raw.readyPattern, warnings),
    readyTimeoutMs,
  };
}

/** 登录契约白名单校验；不通过返回 null。 */
export function sanitizeLogin(raw, warnings = []) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  const path = safeHttpPath(raw.path);
  if (!path) {
    warnings.push("拒绝 LLM 登录契约：path 不是合法的站内路径");
    return null;
  }
  if (raw.method != null && String(raw.method).toUpperCase() !== "POST") {
    warnings.push(`拒绝 LLM 登录契约：method=${raw.method}（当前仅支持 POST）`);
    return null;
  }
  let bodyTemplate = null;
  if (raw.bodyTemplate && typeof raw.bodyTemplate === "object" && !Array.isArray(raw.bodyTemplate)) {
    const entries = Object.entries(raw.bodyTemplate)
      .filter(
        ([k, v]) =>
          /^[A-Za-z0-9_.-]{1,64}$/.test(k) &&
          typeof v === "string" &&
          v.length <= 200 &&
          !/[\r\n\0]/.test(v)
      )
      .slice(0, 12);
    if (entries.length) bodyTemplate = Object.fromEntries(entries);
  }
  const credentialPath =
    typeof raw.credentialPath === "string" && JSON_PATH_RE.test(raw.credentialPath)
      ? raw.credentialPath
      : "token";
  const credentialHeader =
    typeof raw.credentialHeader === "string" && CREDENTIAL_HEADER_RE.test(raw.credentialHeader)
      ? raw.credentialHeader
      : "Authorization";
  const credentialPrefix =
    typeof raw.credentialPrefix === "string" && raw.credentialPrefix.length <= 50 && !/[\r\n\0]/.test(raw.credentialPrefix)
      ? raw.credentialPrefix
      : "Bearer ";
  const userPath =
    typeof raw.userPath === "string" && JSON_PATH_RE.test(raw.userPath) ? raw.userPath : null;
  return { path, bodyTemplate, credentialPath, credentialHeader, credentialPrefix, userPath };
}

function routeFilePatterns(path) {
  const segs = path.split("/").filter(Boolean);
  const variants = [path];
  if (segs.length >= 2) variants.push(`/${segs.slice(-2).join("/")}`);
  if (segs.length >= 3) variants.unshift(`/${segs.slice(-3).join("/")}`);
  return [...new Set(variants)].map((p) => {
    const esc = p.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const withParams = esc.replace(
      /:([A-Za-z_]\w*)/g,
      "(?::[A-Za-z_]\\w*|\\{[^}]+\\}|<[^>]+>)"
    );
    return new RegExp(withParams, "i");
  });
}

function findRouteLine(content, path) {
  for (const re of routeFilePatterns(path)) {
    const m = re.exec(content);
    if (m) {
      return { line: content.slice(0, m.index).split("\n").length, matched: true };
    }
  }
  // 兜底定位只认有辨识度的静态段；"api"/"v1" 等通用前缀几乎必然出现，放行会制造假路由
  const generic = new Set(["api", "v1", "v2", "v3", "rest", "app", "www", "public"]);
  const staticSegs = path
    .split("/")
    .filter((s) => s && !s.startsWith(":") && s.length >= 3 && !generic.has(s.toLowerCase()));
  const hit = staticSegs.find((s) => content.toLowerCase().includes(s.toLowerCase()));
  return hit ? { line: null, matched: false, staticSeg: hit } : null;
}

function sanitizeRoute(raw, warnings) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  const method = String(raw.method ?? "GET").toUpperCase();
  if (!HTTP_METHODS.has(method)) {
    warnings.push(`拒绝 LLM 路由：method=${raw.method}`);
    return null;
  }
  let path = String(raw.path ?? "").trim();
  if (!path.startsWith("/")) {
    warnings.push(`拒绝 LLM 路由「${path}」：path 必须以 / 开头`);
    return null;
  }
  path = path.replace(/\{([^}]+)\}/g, ":$1").replace(/<([^>]+)>/g, ":$1");
  let query = null;
  const qi = path.indexOf("?");
  if (qi >= 0) {
    const qs = path.slice(qi + 1);
    path = path.slice(0, qi);
    const first = qs.split("&")[0]?.split("=")[0] ?? "";
    if (!/^[A-Za-z_]\w*$/.test(first)) {
      warnings.push(`拒绝 LLM 路由：查询参数非法`);
      return null;
    }
    query = first;
  }
  if (!query && typeof raw.query === "string" && /^[A-Za-z_]\w*$/.test(raw.query.trim())) {
    query = raw.query.trim();
  }
  if (!/^\/[A-Za-z0-9_./:-]*$/.test(path) || path.length > 200 || path.includes("..")) {
    warnings.push(`拒绝 LLM 路由「${path}」：路径含非法字符`);
    return null;
  }
  const hasParam = /:[A-Za-z_]\w*/.test(path);
  // 集合路由（无参数）只用于资源发现，必须由 LLM 显式标 list:true；
  // 其余不可寻址路由对动态探测无意义，直接丢弃。
  const isList = method === "GET" && !hasParam && !query && raw.list === true;
  if (!hasParam && !query && !isList) return null;

  const file = safeRel(raw.file);
  if (!file) {
    warnings.push(`拒绝 LLM 路由「${method} ${path}」：缺少可定位的文件`);
    return null;
  }
  const resource =
    typeof raw.resource === "string" && /^[A-Za-z][A-Za-z0-9_-]{0,40}$/.test(raw.resource.trim())
      ? raw.resource.trim()
      : null;
  return {
    method,
    path,
    query,
    file,
    line: Number.isFinite(raw.line) && raw.line > 0 ? Math.floor(raw.line) : null,
    resource,
    hasAuth: raw.hasAuth === false ? false : true,
    list: isList,
    // 仅集合路由的归属过滤标记参与资源发现；不据此判定漏洞
    hasOwnerFilter: isList ? raw.hasOwnerFilter === true : false,
  };
}

/**
 * 校验 LLM 返回结构。路由必须能在真实文件里定位；否则丢弃。
 * @param {object} raw LLM JSON
 * @param {object} opts { evidence, readFile }
 */
export async function validateScoutResult(raw, { evidence, readFile }, warnings = []) {
  const start = sanitizeStart(raw?.start, { dirs: evidence?.dirs ?? null }, warnings);
  const login = sanitizeLogin(raw?.login, warnings);

  if (raw?.identities) {
    warnings.push("已丢弃 LLM 返回的 identities（身份与密码必须由用户提供）");
  }

  const fileCache = new Map();
  for (const f of evidence?.files ?? []) fileCache.set(f.rel, f.content);
  const routeList = Array.isArray(raw?.routes) ? raw.routes.slice(0, MAX_ROUTES * 2) : [];
  const routes = [];
  const seen = new Set();
  let reads = 0;
  for (const item of routeList) {
    if (routes.length >= MAX_ROUTES) break;
    const r = sanitizeRoute(item, warnings);
    if (!r) continue;
    const key = `${r.method} ${r.path}`;
    if (seen.has(key)) continue;

    let content = fileCache.get(r.file);
    if (content == null) {
      if (reads >= MAX_ROUTE_FILES || typeof readFile !== "function") {
        warnings.push(`跳过 LLM 路由「${key}」：文件 ${r.file} 不在证据中，且已达读取上限`);
        continue;
      }
      reads++;
      try {
        content = await readFile(r.file);
      } catch (e) {
        warnings.push(`跳过 LLM 路由「${key}」：无法读取 ${r.file}（${e.message}）`);
        continue;
      }
      if (content.length > MAX_ROUTE_FILE_BYTES) content = content.slice(0, MAX_ROUTE_FILE_BYTES);
      fileCache.set(r.file, content);
    }

    const loc = findRouteLine(content, r.path);
    if (!loc) {
      warnings.push(`丢弃 LLM 路由「${key}」：在 ${r.file} 中找不到对应路径`);
      continue;
    }
    if (!loc.matched) {
      warnings.push(`LLM 路由「${key}」仅按静态片段「${loc.staticSeg}」定位到 ${r.file}，行号不可靠`);
    }
    r.line = loc.line ?? (r.line && r.line <= content.split("\n").length ? r.line : null);
    seen.add(key);
    routes.push(r);
  }

  const notes = Array.isArray(raw?.notes)
    ? raw.notes.filter((n) => typeof n === "string" && n.trim()).slice(0, 5).map((n) => n.slice(0, 200))
    : [];
  return { start, login, routes, notes, warnings };
}

function cacheKeyFor(model, evidence) {
  const h = createHash("sha256");
  h.update(SCOUT_VERSION);
  h.update("\0");
  h.update(model ?? "");
  h.update("\0");
  h.update(JSON.stringify(evidence.tree));
  for (const f of evidence.files) {
    h.update("\0");
    h.update(f.rel);
    h.update("\0");
    h.update(f.content);
  }
  return h.digest("hex");
}

/**
 * 运行接入侦察；失败返回 null（调用方继续确定性流程）。
 * @param {object} ctx
 * @param {object} opts { getToken, model, maxFiles, chatImpl }
 */
export async function runScout(
  ctx,
  { getToken, model = null, maxFiles = MAX_FILES, chatImpl = chat } = {}
) {
  if (!isEnabled()) return null;
  if (typeof getToken !== "function") throw new Error("缺少网络作用域令牌提供方");
  const started = Date.now();
  const evidence = await collectEvidence(ctx, { maxFiles });
  if (evidence.files.length === 0) {
    return {
      start: null,
      login: null,
      routes: [],
      notes: [],
      warnings: ["未找到可发送给 LLM 的 manifest 或源码片段"],
      _source: "llm-scout",
      _unverified: true,
      model,
      evidenceFiles: [],
      evidenceChars: 0,
      cached: false,
      durationMs: Date.now() - started,
    };
  }

  const key = cacheKeyFor(model, evidence);
  const cached = SCOUT_CACHE.get(key);
  if (cached && Date.now() - cached.at < CACHE_TTL_MS) {
    return { ...cached.result, cached: true, durationMs: Date.now() - started };
  }

  const userPrompt = buildPrompt(evidence);
  const res = await chatImpl(ctx, {
    systemPrompt: SYSTEM_PROMPT,
    userPrompt,
    getToken,
    model,
    timeoutMs: SCOUT_TIMEOUT_MS,
    maxTokens: 1600,
  });
  const raw = parseJson(res.content);
  const warnings = [];
  const validated = await validateScoutResult(
    raw,
    { evidence, readFile: (rel) => readProjectText(ctx, rel) },
    warnings
  );
  const result = {
    ...validated,
    warnings,
    _source: "llm-scout",
    _unverified: true,
    model: res.model ?? model,
    usage: res.usage ?? null,
    evidenceFiles: evidence.files.map((f) => f.rel),
    evidenceChars: evidence.totalChars,
    cached: false,
    durationMs: Date.now() - started,
  };
  SCOUT_CACHE.set(key, { at: Date.now(), result });
  while (SCOUT_CACHE.size > CACHE_MAX) {
    SCOUT_CACHE.delete(SCOUT_CACHE.keys().next().value);
  }
  return result;
}

/**
 * 只补缺：显式契约与确定性自动探测优先；LLM 只在没有可信 start 时兜底。
 * @returns {{ start: boolean, login: boolean, routes: number }}
 */
export function applyScoutResult(targetConfig, scout) {
  const applied = { start: false, login: false, routes: 0 };
  if (!targetConfig || !scout) return applied;
  if (scout.start && targetConfig.startSource !== "contract" && targetConfig.startSource !== "auto") {
    targetConfig.start = normalizeStart(scout.start);
    targetConfig.startSource = "llm-scout";
    applied.start = true;
  }
  if (scout.login && !targetConfig.login) {
    const login = normalizeLogin(scout.login);
    if (login) {
      targetConfig.login = login;
      targetConfig.loginSource = "llm-scout";
      applied.login = true;
    }
  }
  if (Array.isArray(scout.routes) && scout.routes.length) {
    targetConfig.llmRoutes = scout.routes;
    applied.routes = scout.routes.length;
  }
  return applied;
}

/** 清除侦察缓存（测试/重跑用）。 */
export function clearScoutCache() {
  SCOUT_CACHE.clear();
}
