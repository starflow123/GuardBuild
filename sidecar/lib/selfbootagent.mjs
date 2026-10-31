/**
 * 身份自举的 agent 兜底（#182）：静态词表挑不出注册端点、挑出多个候选、或注册体字段名
 * 对不上时，让模型在引擎给出的**编号菜单**里选出真正的建号接口，并只把「字段名 → 引擎占位符」
 * 报回来。采纳与否一律由引擎实跑裁决：注册 2xx/409 → 用该口令建立会话 → 会话真实性回读（#175）。
 *
 * 为什么必须有这一层（#179 留下的「唯一路径」缺陷）：resolveRegisterEndpoint 只有两条来源
 * ——契约 register.path 与静态建号词表。两者都打不中就直接回 unavailable，于是
 * REST 惯例命名（POST /api/users）与异形命名（POST /api/huiyuan/add）这类真实项目根本测不了。
 * 「哪个接口是建号、它收哪些字段」是代码语义事实，本该由理解来补，而不是靠无限扩词表。
 *
 * 硬边界（与 attackplan / bootstrap 同一套纪律：只放宽「选什么」，不放宽「怎么打」）：
 *  1. 只发请求、不判结论——候选必须真被目标接受并换来会话才被采用；全不中仍回
 *     identity_bootstrap_unavailable / identity_bootstrap_failed（exit 2），绝不静默退回匿名探测。
 *  2. 菜单由引擎生成（方法 / 路径 / 文件:行号 / 处理函数片段），模型只能报编号；
 *     顶层出现的其它键名（载荷、方法、URL、请求头、判定、严重度…）一律丢弃，只把键名留进审计。
 *  3. 字段模板只接受「字段名 → {name}/{username}/{email}/{password}」：模型不给任何常量值，
 *     因此不可能把请求内容变成它编的东西；缺 {password} 映射的模板视为不可用。
 *  4. 策略线在引擎侧：找回密码 / 第三方登录 / 令牌刷新 / 注销一类的写接口根本不进菜单，
 *     模型看不见就选不到——不靠提示词求它别乱发写请求。
 *  5. 纯黑盒一律不参与（对第三方站点建号超出探测授权）；gate 模式结构性禁止**调用**模型，
 *     只允许复用交互轮已实测验证过的缓存提案，复用前仍逐条实跑。
 *  6. 引擎生成的口令只进 Host protected 保险库；模型原文（note）不进事件流、审计、报告与缓存。
 */
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { signupPolicyExcluded } from "./identityboot.mjs";
import { LlmError, chat, parseJson } from "./llm.mjs";
import { projectRelPath, readHandlerSource } from "./seedobserve.mjs";

export const SELFBOOT_AGENT_VERSION = "gb-selfboot-1";
export const MAX_MENU_ITEMS = 24;
export const MAX_PICKS_DEFAULT = 3;
export const MAX_ROUNDS_DEFAULT = 2;
/** 允许的占位符：引擎 registerValues() 真实能填的键，多一个都不给 */
export const PLACEHOLDERS = Object.freeze(["name", "username", "email", "password"]);

const FIELD_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]{0,39}$/;
const MAX_SNIPPET_LINES = 16;
const MAX_SNIPPET_CHARS = 900;
const MAX_SNIPPET_FILES = 8;
const MAX_OBSERVE_CHARS = 20_000;
const MAX_EXCERPT_CHARS = 240;
const CACHE_MAX_FILES = 20;

/** 开关：register.agent 显式表态优先；否则跟随 llm.enabled 或 GUARDBUILD_LLM_SELFBOOT=1 */
export function selfBootAgentEnabled(ctx) {
  if (!ctx || ctx.blackboxUrl) return false;
  const cfg = ctx.registerConfig?.agent ?? null;
  if (cfg === false) return false;
  if (cfg === true) return true;
  if (cfg && typeof cfg === "object" && cfg.enabled !== false) return true;
  if (cfg && typeof cfg === "object" && cfg.enabled === false) return false;
  if (ctx.llmConfig?.enabled === true) return true;
  return process.env.GUARDBUILD_LLM_SELFBOOT === "1";
}

/** gate 结构性禁止调用模型：CI 不出站；缓存复用由 readAgentCache 单独放行（且必须是已验证的提案） */
export function selfBootModelCallable(ctx) {
  return selfBootAgentEnabled(ctx) && ctx?.gate !== true;
}

export function selfBootBudget(ctx) {
  const cfg = ctx?.registerConfig?.agent;
  const o = cfg && typeof cfg === "object" ? cfg : {};
  const clamp = (v, lo, hi, dft) => (Number.isFinite(v) ? Math.min(hi, Math.max(lo, Math.floor(v))) : dft);
  return {
    maxPicks: clamp(o.maxPicks, 1, 8, MAX_PICKS_DEFAULT),
    maxMenu: clamp(o.maxMenu, 5, MAX_MENU_ITEMS, MAX_MENU_ITEMS),
    rounds: clamp(o.rounds, 1, MAX_ROUNDS_DEFAULT, MAX_ROUNDS_DEFAULT),
  };
}

/**
 * 编号菜单：本轮静态识别到的**全部** POST 路由，减去引擎策略禁止写入的那批。
 * 静态建号词表命中的排在前面并带标记（模型看得见「形状已像」这个线索，但仍要自己判断语义）。
 * @returns {{items:object[], byId:Map, byPath:Map}}
 */
export function buildRegisterMenu(analysis, { maxMenu = MAX_MENU_ITEMS, staticHits = [] } = {}) {
  const eps = Array.isArray(analysis?.endpoints) ? analysis.endpoints : [];
  const hit = new Set(staticHits.map((p) => String(p)));
  const seen = new Set();
  const items = [];
  for (const e of eps) {
    if (String(e.method ?? "").toUpperCase() !== "POST") continue;
    const p = e.fullPath ?? e.path ?? "";
    if (typeof p !== "string" || !p.startsWith("/")) continue;
    // 找回密码 / oauth / token / 注销一类接口根本不给选：猜错就是往别人的写接口乱发建号请求
    if (signupPolicyExcluded(p)) continue;
    if (seen.has(p)) continue;
    seen.add(p);
    items.push({
      path: p,
      method: "POST",
      file: e.file ?? null,
      startLine: Number.isFinite(e.startLine) ? e.startLine : null,
      staticSignupShape: hit.has(p),
      hasAuth: e.hasAuth === true,
      handler: null,
      id: 0,
    });
  }
  items.sort((a, b) => Number(b.staticSignupShape) - Number(a.staticSignupShape) || a.path.localeCompare(b.path));
  const capped = items.slice(0, Math.max(1, maxMenu));
  capped.forEach((it, i) => {
    it.id = i + 1;
  });
  return {
    items: capped,
    byId: new Map(capped.map((i) => [i.id, i])),
    byPath: new Map(capped.map((i) => [i.path, i])),
    excludedCount: items.length - capped.length,
  };
}

/**
 * 给菜单补上处理函数源码片段（字段名的唯一可靠来源）。
 * 只按 project.read 作用域读、脱敏读，且最多读 MAX_SNIPPET_FILES 个文件——读不到就只给路径，
 * 模型仍可按路径语义选，只是模板大概率要纠偏轮来补。
 * 读文件走 seedobserve.readHandlerSource：分析器给的 `file` 在实跑里是绝对路径，
 * 两层（#182 字段名 / #183 复读归因）必须共用同一条解析，否则一边修好一边照样失效。
 */
export async function enrichMenuWithHandlers(ctx, menu) {
  if (!ctx?.projectRoot || !ctx?.rpc?.request || !ctx.tokens?.project) return menu;
  const filesRead = new Set();
  for (const it of menu.items) {
    if (!it.file) continue;
    const rel = projectRelPath(ctx.projectRoot, it.file);
    if (!rel) continue;
    if (!filesRead.has(rel) && filesRead.size >= MAX_SNIPPET_FILES) continue;
    filesRead.add(rel);
    const src = await readHandlerSource(ctx, { file: it.file, startLine: it.startLine ?? 1 }, { lines: MAX_SNIPPET_LINES });
    if (!src) continue;
    it.handler = src.length > MAX_SNIPPET_CHARS ? `${src.slice(0, MAX_SNIPPET_CHARS)}\n/* …截断… */` : src;
  }
  return menu;
}

function renderMenuForPrompt(menu) {
  return menu.items.map((it) => ({
    id: it.id,
    method: it.method,
    path: it.path,
    defined_in: it.file ? `${it.file}:${it.startLine ?? "?"}` : null,
    static_signup_shape: it.staticSignupShape,
    requires_auth: it.hasAuth,
    handler_source: it.handler,
  }));
}

/** 失败摘要纠偏用：只带端点、判定与状态码 + 目标自己的报错文本（口令已剔除、已截断） */
function renderPriorAttempts(priorAttempts) {
  return (priorAttempts ?? []).slice(0, 8).map((a) => ({
    endpoint: String(a.path ?? "").slice(0, 120),
    verdict: String(a.verdict ?? "").slice(0, 40),
    status: Number.isFinite(a.status) ? a.status : null,
    error_excerpt: a.excerpt ? String(a.excerpt).slice(0, MAX_EXCERPT_CHARS) : null,
  }));
}

const SYSTEM_PROMPT = `你在帮一次白盒安全扫描定位「目标项目自己的公开注册接口」，并给出它的请求体字段名。
引擎会给你一份编号菜单：本轮从源码里识别出的 POST 路由，含定义位置与处理函数片段。
硬性规则：
1. picks 只能报菜单里出现过的编号。你不能指定 URL、方法、请求头、参数值、载荷或任何请求内容——那些由引擎按固定模板生成。
2. templates 只能是「字段名 → 占位符」映射，占位符仅限 ${PLACEHOLDERS.map((p) => `{${p}}`).join(" ")}；字段名必须取自该端点源码里真实出现的请求体键名，映射表达的是「这个键装的是引擎给的那个值」。
3. 每个模板必须至少有一个字段映射到 {password}，否则该候选不可用。
4. 你不判定漏洞，也不得声称某端点「安全/有漏洞」；是否采用只由引擎实跑（注册→登录→会话回读）决定。
5. 认为菜单里没有公开建号接口，就返回空 picks——不要硬选。
只返回一个 JSON 对象：{"picks":[3],"templates":{"3":{"mail":"{email}","pwd":"{password}","nickname":"{name}"}},"note":"一句话理由"}。不要输出 JSON 以外的内容。`;

function clamp(text, n) {
  const s = String(text ?? "");
  return s.length > n ? `${s.slice(0, n)}\n/* …(超限，已截去 ${s.length - n} 字符)… */` : s;
}

/**
 * 校验模型提案：只认编号与「字段名 → 占位符」。
 * @returns {{ok:boolean, candidates:Array<{path:string, bodyTemplate:object, id:number}>, ignored:string[], invalid:array, droppedFields:string[], rejected?:string, empty?:boolean, note:string}}
 */
export function sanitizeRegisterChoice(raw, menu, { maxPicks = MAX_PICKS_DEFAULT } = {}) {
  const ignored = [];
  const droppedFields = [];
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return { ok: false, candidates: [], ignored, invalid: [], droppedFields, rejected: "提案必须是 JSON 对象" };
  }
  for (const k of Object.keys(raw)) {
    if (k !== "picks" && k !== "templates" && k !== "note") ignored.push(k);
  }
  if (raw.picks !== undefined && raw.picks !== null && !Array.isArray(raw.picks)) {
    return { ok: false, candidates: [], ignored, invalid: [], droppedFields, rejected: "picks 必须是编号数组" };
  }
  const ids = [];
  const invalid = [];
  for (const v of raw.picks ?? []) {
    const id = Number(v);
    if (!Number.isInteger(id) || !menu.byId.has(id)) {
      const shown = String(v).slice(0, 20);
      if (!invalid.includes(shown)) invalid.push(shown);
      continue;
    }
    if (ids.includes(id)) continue; // 重复编号是同一个端点，去重即可，不算越界
    if (ids.length >= maxPicks) {
      ignored.push(`picks>${maxPicks}`);
      continue;
    }
    ids.push(id);
  }
  if (!ids.length) {
    return {
      ok: true,
      candidates: [],
      ignored,
      invalid,
      droppedFields,
      empty: (raw.picks ?? []).length === 0,
      note: String(raw.note ?? "").slice(0, 300),
    };
  }

  const rawTemplates = raw.templates && typeof raw.templates === "object" && !Array.isArray(raw.templates) ? raw.templates : null;
  const templates = new Map();
  if (rawTemplates) {
    for (const [k, v] of Object.entries(rawTemplates)) {
      const id = Number(k);
      if (!Number.isInteger(id) || !menu.byId.has(id)) {
        droppedFields.push(String(k).slice(0, 20));
        continue;
      }
      if (!v || typeof v !== "object" || Array.isArray(v)) {
        droppedFields.push(`${id}`);
        continue;
      }
      const map = {};
      for (const [field, ph] of Object.entries(v)) {
        if (!FIELD_NAME_RE.test(field)) {
          droppedFields.push(`${id}.${String(field).slice(0, 40)}`);
          continue;
        }
        // 值只允许是占位符本身：常量、模板串拼接、嵌套对象一律丢弃
        const key = PLACEHOLDERS.find((p) => ph === `{${p}}`);
        if (!key) {
          droppedFields.push(`${id}.${field}`);
          continue;
        }
        if (Object.keys(map).length >= 12) {
          droppedFields.push(`${id}.${field}(超限)`);
          continue;
        }
        map[field] = `{${key}}`;
      }
      if (Object.values(map).includes("{password}")) templates.set(id, map);
      else if (Object.keys(map).length) droppedFields.push(`${id}(缺{password})`);
    }
  }

  const candidates = ids.map((id) => {
    const item = menu.byId.get(id);
    // 没有可用模板时返回 null：由调用方落到引擎的默认注册体（按身份形状），不猜字段名
    return { id, path: item.path, method: item.method, bodyTemplate: templates.get(id) ?? null };
  });
  return {
    ok: true,
    candidates,
    ignored,
    invalid,
    droppedFields,
    note: String(raw.note ?? "").slice(0, 300),
  };
}

function normPath(p) {
  return String(p ?? "").replace(/\\/g, "/").replace(/^\/\/\?\//, "").replace(/\/+/g, "/");
}

function projectCacheId(root) {
  let p = normPath(root).replace(/\/+$/, "");
  if (process.platform === "win32") p = p.toLowerCase();
  return createHash("sha256").update(p).digest("hex").slice(0, 16);
}

/** 键只取「路由形状」：方法+路径+定义位置+静态形状标记。源码换行不改键，换接口才改键 */
export function cacheKeyFor(model, menu) {
  const h = createHash("sha256");
  h.update(SELFBOOT_AGENT_VERSION);
  h.update("\0");
  h.update(model ?? "");
  for (const it of menu.items) {
    h.update("\0");
    h.update(`${it.method} ${it.path} ${it.file ?? "?"}:${it.startLine ?? "?"} ${it.staticSignupShape ? 1 : 0}`);
  }
  return h.digest("hex");
}

function cacheDataDir() {
  const dir = process.env.GUARDBUILD_DATA_DIR;
  return typeof dir === "string" && dir.trim() ? dir : null;
}

function cacheFile(ctx, key) {
  const base = cacheDataDir();
  if (!base || !key) return null;
  return join(base, "selfboot", projectCacheId(ctx.projectRoot), `${key}.json`);
}

function writeJsonAtomic(file, data) {
  const tmp = `${file}.${process.pid}.tmp`;
  try {
    writeFileSync(tmp, JSON.stringify(data), "utf8");
    renameSync(tmp, file);
  } catch (e) {
    try {
      rmSync(tmp, { force: true });
    } catch {
      /* ignore */
    }
    throw e;
  }
}

function pruneCacheDir(dir) {
  try {
    const files = readdirSync(dir)
      .filter((n) => n.endsWith(".json"))
      .map((n) => ({ name: n, mtime: statSync(join(dir, n)).mtimeMs }))
      .sort((a, b) => b.mtime - a.mtime);
    for (const f of files.slice(CACHE_MAX_FILES)) rmSync(join(dir, f.name), { force: true });
  } catch {
    /* 缓存清理失败不影响主流程 */
  }
}

/** 落盘提案（未验证时 verified.endpoint=false）；gate 只认已验证的提案 */
export function writeAgentCache(ctx, key, candidates, meta = {}) {
  const file = cacheFile(ctx, key);
  if (!file || !candidates.length) return null;
  try {
    mkdirSync(dirname(file), { recursive: true });
    writeJsonAtomic(file, {
      version: SELFBOOT_AGENT_VERSION,
      savedAt: Date.now(),
      model: meta.model ?? null,
      usage: meta.usage ?? null,
      rounds: meta.rounds ?? null,
      candidates: candidates.map((c) => ({ path: c.path, bodyTemplate: c.bodyTemplate ?? null })),
      verified: meta.verified ?? { endpoint: false, session: false },
    });
    pruneCacheDir(dirname(file));
    return { file, savedAt: Date.now() };
  } catch {
    return null;
  }
}

/** 采纳后回填实测结论：报告与 gate 复用都看这两个标志 */
export function patchAgentCache(file, patch) {
  if (!file || !existsSync(file)) return false;
  try {
    const data = JSON.parse(readFileSync(file, "utf8"));
    if (!data || data.version !== SELFBOOT_AGENT_VERSION) return false;
    data.verified = { ...(data.verified ?? {}), ...patch };
    data.verifiedAt = Date.now();
    writeJsonAtomic(file, data);
    return true;
  } catch {
    return false;
  }
}

/**
 * 读缓存提案。逐条对照**当前**菜单：路径已经不在（或被策略排除）就整条作废，
 * 绝不照旧缓存往一个已经改掉/删掉的写接口发注册请求。
 */
export function readAgentCache(ctx, key, menu, { requireVerified = false } = {}) {
  const file = cacheFile(ctx, key);
  if (!file || !existsSync(file)) return null;
  let data = null;
  try {
    data = JSON.parse(readFileSync(file, "utf8"));
  } catch {
    data = null;
  }
  const drop = (reason) => {
    if (reason === "stale") {
      try {
        rmSync(file, { force: true });
      } catch {
        /* ignore */
      }
    }
    return null;
  };
  if (!data || data.version !== SELFBOOT_AGENT_VERSION) return drop("stale");
  if (requireVerified && data?.verified?.endpoint !== true) return null;
  if (!Array.isArray(data.candidates) || !data.candidates.length) return null;
  const out = [];
  for (const c of data.candidates) {
    const path = typeof c?.path === "string" ? c.path : null;
    const item = path ? menu.byPath.get(path) : null;
    if (!item) return drop("stale"); // 有一条对不上就说明这次的路由形状已变，整体作废
    let bodyTemplate = null;
    if (c.bodyTemplate && typeof c.bodyTemplate === "object" && !Array.isArray(c.bodyTemplate)) {
      const map = {};
      for (const [field, ph] of Object.entries(c.bodyTemplate)) {
        if (!FIELD_NAME_RE.test(field)) continue;
        const key2 = PLACEHOLDERS.find((p) => ph === `{${p}}`);
        if (!key2) continue;
        map[field] = `{${key2}}`;
      }
      if (Object.values(map).includes("{password}")) bodyTemplate = map;
    }
    out.push({ id: item.id, path: item.path, method: item.method, bodyTemplate });
  }
  return out.length ? { candidates: out, file, model: data.model ?? null, verified: data.verified ?? null } : null;
}

const EMPTY_META = () => ({
  asked: false,
  rounds: 0,
  source: null,
  model: null,
  usage: null,
  durationMs: 0,
  fallback: null,
  ignored: [],
  invalid: [],
  droppedFields: [],
  menuSize: 0,
  rejected: null,
});

/**
 * 问一次模型（第 round 轮）：返回校验过的候选 + 审计元信息。
 * 出错/非法输出/空 picks 都回空候选并带 fallback 原因，调用方继续走确定性失败路径。
 * @param {object} ctx
 * @param {object} opts { menu, round, priorAttempts, identityShape, getToken, model, budget, chatImpl }
 */
export async function askRegisterAgent(
  ctx,
  { menu, round = 1, priorAttempts = [], identityShape = null, getToken, model = null, budget = null, chatImpl = chat } = {}
) {
  const b = budget ?? selfBootBudget(ctx);
  const meta = EMPTY_META();
  meta.menuSize = menu.items.length;
  if (!menu.items.length) return { candidates: [], meta: { ...meta, fallback: "no_menu_candidates" } };

  const observation = {
    goal: "在候选里选出公开建号接口，并把它的请求体字段名映射到引擎占位符；只报编号，不规定怎么发请求",
    round,
    available_placeholders: PLACEHOLDERS.map((p) => `{${p}}`),
    identity_fields: identityShape,
    picks_allowed: b.maxPicks,
    candidates: renderMenuForPrompt(menu),
  };
  if (round >= 2) {
    observation.prior_attempts = renderPriorAttempts(priorAttempts);
    observation.prior_note =
      "上面这些是引擎已经实跑过的结果（注册/登录的真实状态码与目标报错文本）。上一轮的字段名或端点没有被目标接受，请据此纠偏——换端点或换成源码里真实出现的键名。";
  }

  const t0 = Date.now();
  let res;
  try {
    res = await chatImpl(ctx, {
      systemPrompt: SYSTEM_PROMPT,
      userPrompt: clamp(JSON.stringify(observation, null, 1), MAX_OBSERVE_CHARS),
      getToken,
      model,
      maxTokens: 700,
      timeoutMs: 60_000,
      purpose: `注册端点与字段名提议（第 ${round} 轮）`,
    });
  } catch (e) {
    return {
      candidates: [],
      meta: {
        ...meta,
        asked: true,
        rounds: round,
        durationMs: Date.now() - t0,
        fallback: e instanceof LlmError ? "llm_unavailable" : "agent_error",
        rejected: String(e?.message ?? e).slice(0, 300),
      },
    };
  }
  const durationMs = Date.now() - t0;

  let raw;
  try {
    raw = parseJson(res.content);
  } catch (e) {
    return {
      candidates: [],
      meta: {
        ...meta,
        asked: true,
        rounds: round,
        durationMs,
        model: res.model ?? model,
        usage: res.usage ?? null,
        fallback: "bad_json",
        rejected: String(e?.message ?? e).slice(0, 300),
      },
    };
  }

  const checked = sanitizeRegisterChoice(raw, menu, { maxPicks: b.maxPicks });
  // 模型原文（note）不进事件流、审计、报告与缓存：留痕只记引擎侧事实与键名
  const base = {
    ...meta,
    asked: true,
    rounds: round,
    durationMs,
    model: res.model ?? model,
    usage: res.usage ?? null,
    ignored: checked.ignored,
    invalid: checked.invalid,
    droppedFields: checked.droppedFields,
    source: "model",
  };
  if (!checked.ok) {
    return { candidates: [], meta: { ...base, fallback: "choice_rejected", rejected: checked.rejected } };
  }
  if (!checked.candidates.length) {
    return { candidates: [], meta: { ...base, fallback: checked.empty ? "model_declined" : "no_valid_picks" } };
  }
  return { candidates: checked.candidates, meta: base };
}
