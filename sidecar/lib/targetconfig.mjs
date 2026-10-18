/**
 * 目标项目启动契约（guardbuild.json）加载器。
 *
 * 目标仓库根可放置 guardbuild.json 声明如何启动被检服务、测试身份与预声明作用域：
 * {
 *   "start": { "cmd": "node", "args": ["server.js"], "env": { "PORT": "${GB_PORT}" },
 *              "readyPattern": "GB_LISTEN", "readyTimeoutMs": 20000 },
 *   "prepare": [{ "cmd": "npm", "args": ["run", "build"], "timeoutMs": 120000 }],
 *   "login": { "path": "/api/login", "bodyTemplate": { "email": "{email}", "password": "{password}" },
 *              "credentialHeader": "Authorization", "credentialPath": "authentication.token",
 *              "credentialPrefix": "Bearer " },
 *   "responses": { "list": "orders", "entity": "order" },
 *   "identities": [{ "name": "alice", "email": "alice@example.com", "password": "alice123", "role": "user" }],
 *   "supabase": { "envFile": ".env", "url": "https://xyz.supabase.co", "anonKey": "eyJ…", "tables": ["profiles"] },
 *   "scopes": ["project.read", "worktree.write", "proc.spawn", "net.probe"]
 * }
 *
 * 身份支持三种形状：username / email / fields（自定义字段映射），至少两项。
 * prepare 步骤在目标进程启动前按序执行（依赖安装、构建等），在 worktree 中同样复跑。
 * start 的 cmd/args/env 中可使用 `${GB_PORT}` 占位符：宿主每次 spawn 前分配一个空闲端口注入，
 *   使「原始工作区 / 隔离 worktree」多个实例可并存，也让打印字面量端口的项目无需改写。
 * responses 声明列表/单体资源在响应 JSON 中的位置（点路径，如 "data.items"）；
 * 缺省时按「顶层数组 → 首个对象数组」/「首个对象值字段」自适应。
 *
 * 文件缺失或字段不合法时回落到内建缺省（node server.js + GB_LISTEN），
 * 保持对既有目标（含内置演示项目）的向后兼容。
 *
 * scopes 供 CI gate 模式做「预声明授权」使用，由宿主侧读取生效；此处仅透传展示。
 */
import { RPC_TO_HOST } from "../../shared/protocol.mjs";
import { detectStartConfig, PORT_SLOT } from "./autostart.mjs";

export const CONFIG_FILENAME = "guardbuild.json";

export const DEFAULT_START = Object.freeze({
  cmd: "node",
  args: ["server.js"],
  env: { PORT: "0" },
  readyPattern: "GB_LISTEN",
  readyTimeoutMs: 20_000,
});

/**
 * 端口槽位占位符：start.cmd/args/env 中出现时，由宿主每次 spawn 分配空闲端口后替换。
 * 用于「双实例并存」与「应用打印字面量端口、PORT=0 无效」的目标项目。
 * 常量定义在 autostart.mjs（自动探测同样生成槽位），此处转出保持既有导入路径。
 */
export { PORT_SLOT };

export function startUsesPortSlot(start) {
  const s = start ?? DEFAULT_START;
  return [s.cmd, ...(s.args ?? []), ...Object.values(s.env ?? {})].some(
    (v) => typeof v === "string" && v.includes(PORT_SLOT)
  );
}

/** 用分配的端口渲染启动命令；port 为 null 时保持占位符原样（供测试与诊断） */
export function renderStart(start, port) {
  const s = start ?? DEFAULT_START;
  const sub = (v) => (port == null ? String(v) : String(v).split(PORT_SLOT).join(String(port)));
  return {
    cmd: sub(s.cmd),
    args: s.args.map(sub),
    env: Object.fromEntries(Object.entries(s.env).map(([k, v]) => [k, sub(v)])),
  };
}

function normalizeStart(raw) {
  const s = raw && typeof raw === "object" ? raw : {};
  const env = { ...DEFAULT_START.env };
  if (s.env && typeof s.env === "object") {
    for (const [k, v] of Object.entries(s.env)) {
      if (typeof k === "string" && (typeof v === "string" || typeof v === "number")) env[k] = String(v);
    }
  }
  return {
    cmd: typeof s.cmd === "string" && s.cmd.trim() ? s.cmd : DEFAULT_START.cmd,
    args: Array.isArray(s.args) ? s.args.map(String) : [...DEFAULT_START.args],
    env,
    readyPattern:
      typeof s.readyPattern === "string" && s.readyPattern ? s.readyPattern : DEFAULT_START.readyPattern,
    readyTimeoutMs:
      Number.isFinite(s.readyTimeoutMs) && s.readyTimeoutMs >= 1000
        ? Math.floor(s.readyTimeoutMs)
        : DEFAULT_START.readyTimeoutMs,
    cwd: typeof s.cwd === "string" && s.cwd.trim() ? s.cwd.trim() : null,
  };
}

function normalizeIdentities(raw) {
  if (!Array.isArray(raw) || raw.length < 2) return null;
  const out = [];
  for (const it of raw) {
    if (!it || typeof it !== "object") return null;
    if (typeof it.password !== "string") return null;
    const username = typeof it.username === "string" && it.username ? it.username : null;
    const email = typeof it.email === "string" && it.email ? it.email : null;
    const fields =
      it.fields && typeof it.fields === "object" && !Array.isArray(it.fields)
        ? Object.fromEntries(
            Object.entries(it.fields).filter(
              ([k, v]) => typeof k === "string" && k && typeof v === "string"
            )
          )
        : null;
    if (!username && !email && (!fields || Object.keys(fields).length < 2)) return null;
    out.push({
      name:
        typeof it.name === "string" && it.name ? it.name : username ?? email ?? `identity${out.length + 1}`,
      username,
      email,
      fields: fields && Object.keys(fields).length ? fields : null,
      password: it.password,
      role: it.role === "admin" ? "admin" : "user",
    });
  }
  return out;
}

/** 登录契约：路径 / 请求体模板 / 凭据在响应中的位置与请求头写法。 */
function normalizeLogin(raw) {
  const l = raw && typeof raw === "object" && !Array.isArray(raw) ? raw : null;
  if (!l) return null;
  if (typeof l.path !== "string" || !l.path.trim()) return null;
  const path = l.path.startsWith("/") ? l.path : `/${l.path}`;
  let bodyTemplate = null;
  if (l.bodyTemplate && typeof l.bodyTemplate === "object" && !Array.isArray(l.bodyTemplate)) {
    const entries = Object.entries(l.bodyTemplate).filter(
      ([k, v]) => typeof k === "string" && k && typeof v === "string"
    );
    if (entries.length) bodyTemplate = Object.fromEntries(entries);
  }
  return {
    path,
    bodyTemplate,
    credentialHeader:
      typeof l.credentialHeader === "string" && l.credentialHeader
        ? l.credentialHeader
        : "Authorization",
    credentialPath:
      typeof l.credentialPath === "string" && l.credentialPath ? l.credentialPath : "token",
    credentialPrefix: typeof l.credentialPrefix === "string" ? l.credentialPrefix : "Bearer ",
    userPath: typeof l.userPath === "string" && l.userPath ? l.userPath : null,
  };
}

/** prepare 步骤：spawn 目标前的顺序执行命令（安装依赖/构建等）。 */
function normalizePrepare(raw) {
  if (!Array.isArray(raw) || raw.length === 0) return null;
  const out = [];
  for (const it of raw) {
    if (!it || typeof it !== "object") continue;
    if (typeof it.cmd !== "string" || !it.cmd.trim()) continue;
    out.push({
      cmd: it.cmd.trim(),
      args: Array.isArray(it.args) ? it.args.map(String) : [],
      cwd: typeof it.cwd === "string" && it.cwd.trim() ? it.cwd : ".",
      timeoutMs:
        Number.isFinite(it.timeoutMs) && it.timeoutMs >= 1000
          ? Math.floor(it.timeoutMs)
          : 120_000,
    });
  }
  return out.length ? out : null;
}

/** 响应形状契约：列表/单体资源在 JSON 响应中的点路径（如 "data.items"），缺省为自适应探测。 */
function normalizeResponses(raw) {
  const r = raw && typeof raw === "object" && !Array.isArray(raw) ? raw : null;
  if (!r) return null;
  const list = typeof r.list === "string" && r.list.trim() ? r.list.trim() : null;
  const entity = typeof r.entity === "string" && r.entity.trim() ? r.entity.trim() : null;
  if (!list && !entity) return null;
  return { list, entity };
}

/** Supabase 覆盖项：显式指定环境文件 / 项目 URL / anon key / 表名（缺省由静态检测自动发现） */
function normalizeSupabase(raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  const out = {};
  if (typeof raw.envFile === "string" && raw.envFile.trim()) out.envFile = raw.envFile.trim();
  else if (Array.isArray(raw.envFile)) {
    const l = raw.envFile.filter((x) => typeof x === "string" && x.trim()).map((x) => x.trim());
    if (l.length) out.envFile = l;
  }
  if (typeof raw.url === "string" && raw.url.trim()) out.url = raw.url.trim();
  if (typeof raw.anonKey === "string" && raw.anonKey.trim()) out.anonKey = raw.anonKey.trim();
  if (Array.isArray(raw.tables)) {
    const t = raw.tables.filter((x) => typeof x === "string" && /^[A-Za-z_][A-Za-z0-9_]*$/.test(x));
    if (t.length) out.tables = [...new Set(t)];
  }
  return Object.keys(out).length ? out : null;
}

function emptyConfig(source, invalid = null) {
  return {
    source,
    invalid,
    identities: null,
    login: null,
    prepare: null,
    responses: null,
    supabase: null,
    scopes: null,
  };
}

function hasExplicitStart(parsed) {
  return (
    parsed?.start &&
    typeof parsed.start === "object" &&
    !Array.isArray(parsed.start) &&
    typeof parsed.start.cmd === "string" &&
    parsed.start.cmd.trim().length > 0
  );
}

/** 自动探测结果 + 契约中的部分 start 覆盖（未声明 cmd 时仍可覆盖 env/readyPattern） */
function mergeStart(detected, raw) {
  const out = {
    ...detected,
    args: [...(detected.args ?? [])],
    env: { ...(detected.env ?? {}) },
  };
  if (typeof raw.cmd === "string" && raw.cmd.trim()) out.cmd = raw.cmd.trim();
  if (Array.isArray(raw.args)) out.args = raw.args.map(String);
  if (raw.env && typeof raw.env === "object" && !Array.isArray(raw.env)) {
    for (const [k, v] of Object.entries(raw.env)) {
      if (typeof k === "string" && (typeof v === "string" || typeof v === "number")) out.env[k] = String(v);
    }
  }
  if (typeof raw.cwd === "string" && raw.cwd.trim()) out.cwd = raw.cwd.trim();
  if (typeof raw.readyPattern === "string" && raw.readyPattern) out.readyPattern = raw.readyPattern;
  if (Number.isFinite(raw.readyTimeoutMs) && raw.readyTimeoutMs >= 1000) {
    out.readyTimeoutMs = Math.floor(raw.readyTimeoutMs);
  }
  return out;
}

/** 决定最终启动契约：显式声明 > 自动探测 > 缺省（node server.js） */
async function resolveStart(ctx, parsed) {
  if (hasExplicitStart(parsed)) {
    return { start: normalizeStart(parsed.start), startSource: "contract", autostart: null };
  }
  let autostart = null;
  try {
    autostart = await detectStartConfig(ctx);
  } catch (e) {
    autostart = { start: null, warnings: [`启动方式自动探测失败：${e.message}`], alternatives: [], checked: [] };
  }
  const raw = parsed?.start && typeof parsed.start === "object" && !Array.isArray(parsed.start) ? parsed.start : null;
  const start = autostart?.start
    ? normalizeStart(raw ? mergeStart(autostart.start, raw) : autostart.start)
    : normalizeStart(raw);
  return { start, startSource: autostart?.start ? "auto" : "default", autostart };
}

/** 读取并归一化目标项目的 guardbuild.json（经 Host 读取，遵循 project.read 作用域） */
export async function loadTargetConfig(ctx) {
  const base = String(ctx.projectRoot).replace(/[\\/]+$/, "");
  const path = `${base}/${CONFIG_FILENAME}`;
  let content;
  try {
    // redact:false —— 契约含测试身份凭证（登录请求体必须用原文构造）；
    // 若走脱敏，password 会被掩码成 ***REDACTED***，登录必然 401
    const res = await ctx.rpc.request(
      RPC_TO_HOST.FS_READ,
      { token: ctx.tokens.project, path, redact: false },
      { timeoutMs: 15_000 }
    );
    content = res.content;
  } catch {
    return { ...emptyConfig("default"), ...(await resolveStart(ctx, null)) };
  }
  let parsed;
  try {
    parsed = JSON.parse(content);
  } catch (e) {
    return { ...emptyConfig("invalid", e.message), ...(await resolveStart(ctx, null)) };
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { ...emptyConfig("invalid", "顶层必须是 JSON 对象"), ...(await resolveStart(ctx, null)) };
  }
  return {
    source: CONFIG_FILENAME,
    invalid: null,
    ...(await resolveStart(ctx, parsed)),
    identities: normalizeIdentities(parsed.identities),
    login: normalizeLogin(parsed.login),
    prepare: normalizePrepare(parsed.prepare),
    responses: normalizeResponses(parsed.responses),
    supabase: normalizeSupabase(parsed.supabase),
    scopes: Array.isArray(parsed.scopes)
      ? parsed.scopes.filter((x) => typeof x === "string" && x)
      : null,
  };
}
