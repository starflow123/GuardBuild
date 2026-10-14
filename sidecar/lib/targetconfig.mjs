/**
 * 目标项目启动契约（guardbuild.json）加载器。
 *
 * 目标仓库根可放置 guardbuild.json 声明如何启动被检服务、测试身份与预声明作用域：
 * {
 *   "start": { "cmd": "node", "args": ["server.js"], "env": { "PORT": "0" },
 *              "readyPattern": "GB_LISTEN", "readyTimeoutMs": 20000 },
 *   "identities": [{ "name": "alice", "username": "alice", "password": "alice123", "role": "user" }],
 *   "scopes": ["project.read", "worktree.write", "proc.spawn", "net.probe"]
 * }
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
    if (typeof it.username !== "string" || typeof it.password !== "string") return null;
    out.push({
      name: typeof it.name === "string" && it.name ? it.name : it.username,
      username: it.username,
      password: it.password,
      role: it.role === "admin" ? "admin" : "user",
    });
  }
  return out;
}

function fallback(source, invalid = null) {
  return { source, invalid, start: normalizeStart(null), identities: null, scopes: null };
}

/** 读取并归一化目标项目的 guardbuild.json（经 Host 读取，遵循 project.read 作用域） */
export async function loadTargetConfig(ctx) {
  const base = String(ctx.projectRoot).replace(/[\\/]+$/, "");
  const path = `${base}/${CONFIG_FILENAME}`;
  let content;
  try {
    const res = await ctx.rpc.request(
      RPC_TO_HOST.FS_READ,
      { token: ctx.tokens.project, path, redact: true },
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
    scopes: Array.isArray(parsed.scopes)
      ? parsed.scopes.filter((x) => typeof x === "string" && x)
      : null,
  };
}
