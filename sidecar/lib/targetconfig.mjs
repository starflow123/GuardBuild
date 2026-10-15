/**
 * 目标项目启动契约（guardbuild.json）加载器。
 *
 * 目标仓库根可放置 guardbuild.json 声明如何启动被检服务、测试身份与预声明作用域：
 * {
 *   "start": { "cmd": "node", "args": ["server.js"], "env": { "PORT": "0" },
 *              "readyPattern": "GB_LISTEN", "readyTimeoutMs": 20000 },
 *   "prepare": [{ "cmd": "npm", "args": ["run", "build"], "timeoutMs": 120000 }],
 *   "login": { "path": "/api/login", "bodyTemplate": { "email": "{email}", "password": "{password}" },
 *              "credentialHeader": "Authorization", "credentialPath": "authentication.token",
 *              "credentialPrefix": "Bearer " },
 *   "identities": [{ "name": "alice", "email": "alice@example.com", "password": "alice123", "role": "user" }],
 *   "scopes": ["project.read", "worktree.write", "proc.spawn", "net.probe"]
 * }
 *
 * 身份支持三种形状：username / email / fields（自定义字段映射），至少两项。
 * prepare 步骤在目标进程启动前按序执行（依赖安装、构建等），在 worktree 中同样复跑。
 *
 * 文件缺失或字段不合法时回落到内建缺省（node server.js + GB_LISTEN），
 * 保持对既有目标（含内置演示项目）的向后兼容。
 *
 * scopes 供 CI gate 模式做「预声明授权」使用，由宿主侧读取生效；此处仅透传展示。
 */
import { RPC_TO_HOST } from "../../shared/protocol.mjs";

export const CONFIG_FILENAME = "guardbuild.json";

export const DEFAULT_START = Object.freeze({
  cmd: "node",
  args: ["server.js"],
  env: { PORT: "0" },
  readyPattern: "GB_LISTEN",
  readyTimeoutMs: 20_000,
});

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

function fallback(source, invalid = null) {
  return {
    source,
    invalid,
    start: normalizeStart(null),
    identities: null,
    login: null,
    prepare: null,
    scopes: null,
  };
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
    return fallback("default");
  }
  let parsed;
  try {
    parsed = JSON.parse(content);
  } catch (e) {
    return fallback("invalid", e.message);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return fallback("invalid", "顶层必须是 JSON 对象");
  }
  return {
    source: CONFIG_FILENAME,
    invalid: null,
    start: normalizeStart(parsed.start),
    identities: normalizeIdentities(parsed.identities),
    login: normalizeLogin(parsed.login),
    prepare: normalizePrepare(parsed.prepare),
    scopes: Array.isArray(parsed.scopes)
      ? parsed.scopes.filter((x) => typeof x === "string" && x)
      : null,
  };
}
