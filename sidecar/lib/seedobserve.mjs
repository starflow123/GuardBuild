/**
 * 种子数据写入端点的**观测式**发现（#183）。
 *
 * 缺口：#179 只认契约里手写的 `register.seed`。真实项目没写这份契约时，引擎注册出了账号、
 * 却给账号名下造不出对象——于是越权用例没有受害对象，整轮只能回「测不了」。
 * 「哪个写接口会把对象落在当前会话名下」是**运行期事实**，不是代码语义事实：
 * 所以这一层不叫模型猜，而是引擎自己发一次无害写入、再回读本人的列表看对象有没有落进来。
 *
 * 三条硬约束：
 *  1. 采纳只凭复读证据：写入方自己的按归属过滤列表里要能看见本次 canary，
 *     且另一身份的列表里看不见它。两边都看得见＝列表没有归属过滤，无法归属，判为不可用
 *     （宁可有缺口也不造出「有归属对象」的假前提）。
 *  2. 只对**本轮引擎自己注册的账号**、且名下确实没有对象时才发写入；纯黑盒目标一律不参与
 *     （对他人系统发写请求超出探测授权）。
 *  3. 候选由确定性规则给出（集合形态、无路径参数、要求会话、排除注册/登录/找回密码一类），
 *     字段名取自该端点自己的处理函数源码；填不进就不发这一条，不猜字段语义。
 */
import { RPC_TO_HOST } from "../../shared/protocol.mjs";
import { toRel } from "./depgraph.mjs";
import { signupPolicyExcluded } from "./identityboot.mjs";

export const MAX_SEED_CANDIDATES = 3;
export const MAX_SEED_FIELDS = 4;
export const MAX_SEED_SOURCE_CHARS = 6000;
const READ_TIMEOUT_MS = 10_000;

/** 写入请求里不该出现的端点形状：带路径参数的（/api/orders/:id/cancel）本轮根本没有 id 可填 */
function isCollectionPath(p) {
  return typeof p === "string" && p.startsWith("/") && !/:[A-Za-z_]\w*/.test(p) && !p.includes("?");
}

/**
 * 有序候选：与列表端点同集合的写接口优先（GET /api/orders ↔ POST /api/orders），
 * 其余要求会话的集合形态 POST 兜后。排除注册端点自身与登录/找回密码一类。
 * @param {object} analysis 静态分析结果
 * @param {{listPath?:string|null, registerPath?:string|null, max?:number}} opts
 */
export function seedWriteCandidates(analysis, { listPath = null, registerPath = null, max = MAX_SEED_CANDIDATES } = {}) {
  const eps = Array.isArray(analysis?.endpoints) ? analysis.endpoints : [];
  const listBase = listPath ? listPath.split("?")[0].replace(/\/+$/, "") : null;
  const out = [];
  const seen = new Set();
  for (const e of eps) {
    if (String(e.method ?? "").toUpperCase() !== "POST") continue;
    const p = e.fullPath ?? e.path ?? "";
    if (!isCollectionPath(p)) continue;
    if (p === registerPath) continue; // 注册接口不是「往名下写对象」的写接口
    if (signupPolicyExcluded(p)) continue; // 登录/oauth/改口令一类，发建号体是危险的
    if (e.hasAuth !== true) continue; // 不要求会话的写接口无法把对象归属到该身份
    if (seen.has(p)) continue;
    seen.add(p);
    const sameCollection = !!listBase && (p === listBase || p.startsWith(`${listBase}/`) || listBase.startsWith(`${p}/`));
    out.push({
      path: p,
      method: "POST",
      file: e.file ?? null,
      startLine: Number.isFinite(e.startLine) ? e.startLine : null,
      sameCollection,
      graphql: !!e.graphql,
      trpc: !!e.trpc,
    });
  }
  out.sort((a, b) => Number(b.sameCollection) - Number(a.sameCollection) || a.path.localeCompare(b.path));
  return out.slice(0, Math.max(1, max));
}

/**
 * 从处理函数源码里取请求体字段名（确定性来源，不交给模型）。
 * 覆盖 `req.body.x` / `req.body?.x` / `const {a, b} = req.body` / Python `data["a"]` 常见形态。
 */
export function extractBodyFields(source) {
  const text = String(source ?? "").slice(0, MAX_SEED_SOURCE_CHARS);
  if (!text) return [];
  const names = [];
  const push = (n) => {
    const v = String(n ?? "");
    if (!/^[A-Za-z_][A-Za-z0-9_]{0,39}$/.test(v)) return;
    if (/^(?:body|headers|query|params|cookies|files|user|users|session|token|id|length|map|filter)$/i.test(v)) return;
    if (!names.includes(v)) names.push(v);
  };
  for (const m of text.matchAll(/\breq(?:uest)?\.body\??\.([A-Za-z_][A-Za-z0-9_]*)/g)) push(m[1]);
  for (const m of text.matchAll(/\breq(?:uest)?\.body\[["']([A-Za-z_][A-Za-z0-9_]*)["']\]/g)) push(m[1]);
  for (const m of text.matchAll(/\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*req(?:uest)?\.body\b/g)) {
    for (const part of m[1].split(",")) push(part.split(":").pop()?.trim().split("=")[0]?.trim());
  }
  for (const m of text.matchAll(/\bdata\[["']([A-Za-z_][A-Za-z0-9_]*)["']\]/g)) push(m[1]);
  for (const m of text.matchAll(/\bbody\.get\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']/g)) push(m[1]);
  return names.slice(0, MAX_SEED_FIELDS);
}

/** 写入体：把观测到的字段一律填成同一条 canary——判定权在复读，不在字段猜得准不准 */
export function canaryBody(fields, canary) {
  if (!fields.length) return null;
  return Object.fromEntries(fields.slice(0, MAX_SEED_FIELDS).map((f) => [f, canary]));
}

/** 复读证据：本次 canary 是否出现在该身份看到的列表文本里 */
export function showsCanary(items, canary) {
  if (!canary) return false;
  return JSON.stringify(items ?? []).includes(String(canary));
}

/**
 * 归属判定（采纳的唯一依据）：写入方看得见、其余身份看不见。
 * @returns {{verdict:"attributed"|"unattributed"|"absent", ownerSeen:boolean, othersSeen:string[]}}
 */
export function attributeCanary({ ownerItems, otherItemsByOwner, canary }) {
  const ownerSeen = showsCanary(ownerItems, canary);
  const othersSeen = Object.entries(otherItemsByOwner ?? {})
    .filter(([, items]) => showsCanary(items, canary))
    .map(([name]) => name);
  if (!ownerSeen) return { verdict: "absent", ownerSeen: false, othersSeen };
  // 所有人都看得见＝这个列表根本没按归属过滤，「对象在谁名下」无从证明
  if (othersSeen.length) return { verdict: "unattributed", ownerSeen: true, othersSeen };
  return { verdict: "attributed", ownerSeen: true, othersSeen };
}

/**
 * 把分析器给出的 `file` 解析成仓库相对路径。
 * 真实运行里它是绝对路径（Windows 还带反斜杠），单测与磁盘缓存里存的是相对路径——
 * 只认后一种的话，#182 的「字段名取自源码」和 #183 的复读归因会在实跑里静默失效，
 * 报告照样能出，只是兜底层一条数据都没造出来。
 */
export function projectRelPath(root, file) {
  const plain = String(file ?? "").replace(/\\/g, "/").replace(/^\.?\//, "");
  if (!plain || plain.includes("..")) return null;
  const rel = toRel(root, file);
  if (rel) return rel;
  // 仓库外的绝对路径一律不读；相对形态原样返回
  return /^[A-Za-z]:\//.test(plain) || plain.startsWith("/") ? null : plain;
}

/** 同一次运行里同一个文件只读一次（菜单与观测候选常落在同一份路由文件上） */
const fileContentCache = new WeakMap();

async function readProjectFile(ctx, rel) {
  let byFile = fileContentCache.get(ctx);
  if (!byFile) {
    byFile = new Map();
    fileContentCache.set(ctx, byFile);
  }
  if (byFile.has(rel)) return byFile.get(rel);
  const base = String(ctx?.projectRoot ?? "").replace(/[\\/]+$/, "");
  let content = null;
  try {
    const res = await ctx.rpc.request(
      RPC_TO_HOST.FS_READ,
      { token: ctx.tokens.project, path: `${base}/${rel}`, redact: true },
      { timeoutMs: READ_TIMEOUT_MS }
    );
    content = typeof res?.content === "string" ? res.content : null;
  } catch {
    content = null;
  }
  byFile.set(rel, content);
  return content;
}

/** 读该端点的处理函数片段：字段名的唯一可靠来源；读不到就放弃这一条，不猜 */
export async function readHandlerSource(ctx, cand, { lines = 40 } = {}) {
  if (!ctx?.projectRoot || !cand?.file || !ctx?.rpc?.request || !ctx.tokens?.project) return "";
  const rel = projectRelPath(ctx.projectRoot, cand.file);
  if (!rel) return "";
  const content = await readProjectFile(ctx, rel);
  if (!content) return "";
  const from = Math.max(0, (Number(cand.startLine) || 1) - 1);
  return content.split(/\r?\n/).slice(from, from + lines).join("\n");
}
