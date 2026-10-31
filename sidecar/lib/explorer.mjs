/**
 * 探索区（方案第 13 项）：模型在沙箱内**自主决定下一步打什么**，引擎替它发请求，
 * 跑完把真实请求序列落成一张配方草稿。
 *
 * 这一路要解决的是「模型想得出打法，但代码里还没有那一族」：草稿的来源是一次真实试打，
 * 而不是模型凭空填表——它至少证明过「这个槽位、这个身份、这么个顺序，目标真的收了请求」。
 *
 * 硬边界（与 bootstrap / attackplan / selfboot 同一套纪律，只放宽「打什么」，不放宽「怎么打」）：
 *  1. 模型只报菜单编号（动作 / 目标 / 身份 / 对象），请求构造、载荷、canary 全在 probe.mjs 的写死执行器里；
 *     菜单外的写法（自带 path/payload/body/headers/verdict…）一律丢弃，只把**字段名**留进审计。
 *  2. 探索流量**不进证据库、不参与判卷**：本通道跑在修复前取证之后，产出的 trace 与草稿都不是结论
 *     （红线 2/4）。结论字段仍只由判卷代码落笔。
 *  3. 草稿由引擎按 trace 反推成动作表词汇（槽位 + 角色 + `{plan.param}` 引用），随后立刻过
 *     `validateRecipe`：映射不到表上的那一步就当场拒收，绝不留一张「看着能执行」的假表。
 *     填表合法 ≠ 打得中——判卷器（第 6 项）之前，草稿不许注册进 `sidecar/recipes/`。
 *  4. 双闸才启用：契约 `exploration.enabled: true` **且**环境变量 `GUARDBUILD_LLM_EXPLORATION=1`。
 *     真实项目的常规扫描两个条件都不满足，因此不经过这一路；gate/CI 结构性禁用（不调用模型）。
 *  5. 超限即停：请求数 / 轮数 / 时长 / 累计输出四个预算任一用尽就停下，并在事件与报告里写明用尽了哪一个。
 *  6. 凭据值不落：trace 与草稿只记身份**名字**与脱敏后的响应摘录（红线 6）。
 */
import { createHash } from "node:crypto";
import { mkdirSync, readdirSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { SEVERITY } from "../../shared/protocol.mjs";
import { RECIPE_VERSION, VERDICT_RULES, formatRejections, validateRecipe } from "./actiontable.mjs";
import { redactSecrets } from "./failureledger.mjs";
import { LlmError, chat, parseJson } from "./llm.mjs";
import { SLOT_KIND } from "./recipes.mjs";

export const EXPLORATION_VERSION = "gb-explore-1";

export const EXPLORATION_DEFAULTS = {
  maxRequests: 12,
  maxRounds: 6,
  totalBudgetMs: 180_000,
  maxOutputChars: 40_000,
  maxTargets: 12,
  maxResources: 12,
  maxDraftSteps: 8,
};

/** 引擎侧硬上限：契约写更大也只取这些——预算属于执行器，不属于提议者 */
export const EXPLORATION_HARD_CAPS = {
  maxRequests: 30,
  maxRounds: 12,
  totalBudgetMs: 600_000,
  maxOutputChars: 200_000,
};

const MAX_TARGETS_CAP = 40;
const MAX_OBSERVE_CHARS = 20_000;
const MAX_TRACE_EXCERPT = 240;
const MAX_STEP_HISTORY = 6;
const ARTIFACT_MAX_FILES = 20;
const FAMILY_RE = /^[a-z][a-z0-9_-]{2,31}$/;

/**
 * 草稿的判据写死在这里：探索区回答的是「这一族该怎么打」，不回答「什么算打穿」。
 * 判据是冻结项（红线 1），所以菜单里没有判据编号这一项、契约里也没有对应开关，
 * 单测用 `VERDICT_RULES` 回读确认这个名字仍然存在（改名/删判据时这里必须红）。
 */
export const EXPLORATION_DRAFT_RULE = "attack-repro";

/**
 * 动作菜单：每一项都是执行器（`probe.mjs::explorationSendStep`）已经做得到的动作，
 * 并且带 anchor 指向真正执行它的那段代码——单测逐条回读，防止「菜单上写着能打、代码里已经不打」。
 * `roles: []` 表示这一动作的身份由执行器写死（匿名），模型无从选择也不许选。
 */
export const PRIMITIVES = [
  {
    id: 1,
    action: "request.anonymous",
    desc: "匿名请求一个已发现的读取端点（不带任何身份）",
    slots: ["readPath", "unauthReadPath"],
    roles: [],
    roleFixed: "anonymous",
    needsResource: "optional",
    anchor: { file: "sidecar/lib/probe.mjs", token: 'case "request.anonymous"' },
  },
  {
    id: 2,
    action: "request.as",
    desc: "以菜单里的某个身份请求一个已发现的读取端点",
    slots: ["readPath", "unauthReadPath"],
    roles: ["authed"],
    needsResource: "optional",
    anchor: { file: "sidecar/lib/probe.mjs", token: 'case "request.as"' },
  },
  {
    id: 3,
    action: "payload.inject",
    desc: "在计划已声明的 SQL 注入点上放载荷（载荷集由引擎固定，模型不给内容）",
    slots: ["sqliPath"],
    roles: ["authed"],
    needsResource: "forbidden",
    requiresPlanRef: "sqli",
    anchor: { file: "sidecar/lib/probe.mjs", token: 'case "payload.inject"' },
  },
  {
    id: 4,
    action: "fs.traverse",
    desc: "在计划已声明的穿越点上尝试回读 canary（载荷与 canary 都由引擎固定）",
    slots: ["traversalPath"],
    roles: [],
    roleFixed: "anonymous",
    needsResource: "forbidden",
    requiresPlanRef: "traversal",
    anchor: { file: "sidecar/lib/probe.mjs", token: 'case "fs.traverse"' },
  },
];

/**
 * 模型可写的键：全是编号与收手声明。
 * 判据名字不在这里——「什么算打穿」是冻结项（红线 1），草稿的判据由引擎按用过的动作映射（见 ruleForSteps）。
 */
const ALLOWED_CHOICE_KEYS = new Set(["primitive", "target", "role", "resource", "stop", "family", "action", "note"]);

/** 开关：gate 结构性禁用；外部黑盒目标不参与；契约与环境变量双闸 */
export function explorationEnabled(ctx) {
  if (ctx?.gate === true) return false;
  if (ctx?.blackboxUrl) return false;
  const cfg = ctx?.targetConfig?.exploration ?? null;
  if (cfg?.enabled !== true) return false;
  return process.env.GUARDBUILD_LLM_EXPLORATION === "1";
}

export function explorationBudget(ctx) {
  const cfg = ctx?.targetConfig?.exploration ?? {};
  const clamp = (v, lo, hi, dft) => (Number.isFinite(v) ? Math.min(hi, Math.max(lo, Math.floor(v))) : dft);
  return {
    maxRequests: clamp(cfg.maxRequests, 1, EXPLORATION_HARD_CAPS.maxRequests, EXPLORATION_DEFAULTS.maxRequests),
    maxRounds: clamp(cfg.maxRounds, 1, EXPLORATION_HARD_CAPS.maxRounds, EXPLORATION_DEFAULTS.maxRounds),
    totalBudgetMs: clamp(cfg.totalBudgetMs, 15_000, EXPLORATION_HARD_CAPS.totalBudgetMs, EXPLORATION_DEFAULTS.totalBudgetMs),
    maxOutputChars: clamp(cfg.maxOutputChars, 5_000, EXPLORATION_HARD_CAPS.maxOutputChars, EXPLORATION_DEFAULTS.maxOutputChars),
    maxTargets: clamp(cfg.maxTargets, 1, MAX_TARGETS_CAP, EXPLORATION_DEFAULTS.maxTargets),
    maxResources: clamp(cfg.maxResources, 1, MAX_TARGETS_CAP, EXPLORATION_DEFAULTS.maxResources),
    maxDraftSteps: clamp(cfg.maxDraftSteps, 1, 20, EXPLORATION_DEFAULTS.maxDraftSteps),
  };
}

/**
 * 目标菜单：只列探测计划里真实存在、且执行器会取用的槽位候选。
 * 路径、参数名都来自计划（模型看不见也改不了引擎会打到哪之外的地址）。
 */
export function buildTargetMenu(stash, { maxTargets = EXPLORATION_DEFAULTS.maxTargets } = {}) {
  const bySlot = stash?.candidates ?? {};
  const items = [];
  for (const slot of ["readPath", "unauthReadPath", "sqliPath", "traversalPath"]) {
    const kind = SLOT_KIND[slot];
    for (const cand of bySlot[slot] ?? []) {
      if (items.length >= maxTargets) break;
      const path = cand?.fullPath ?? cand?.path ?? null;
      if (typeof path !== "string" || !path.startsWith("/")) continue;
      const planRef = kind ? cand?.[kind] : null;
      const hasPathParam = /:[A-Za-z_]\w*/.test(path);
      items.push({
        id: items.length + 1,
        slot,
        kind: kind ?? null,
        path,
        method: cand.method ?? "GET",
        wire: cand.graphql ? "graphql" : cand.trpc ? "trpc" : "rest",
        // 与执行器同一个口径：这三类形态都要往请求里塞一个对象主键（见 probe.mjs::explorationNeedsResourceId）
        needsResourceId: hasPathParam || !!cand.queryParam || !!cand.graphql || !!cand.trpc,
        planRef: planRef ? { source: planRef.source ?? null, param: planRef.param ?? null } : null,
      });
    }
  }
  return { items, byId: new Map(items.map((i) => [i.id, i])) };
}

/** 身份菜单：角色名 + 本次扫描实际选中的保险库条目名；anonymous 恒为 1 号且无凭据 */
export function buildRoleMenu(stash) {
  const items = [{ id: 1, role: "anonymous", identity: null }];
  for (const key of ["attacker", "victim", "admin"]) {
    const t = stash?.targets?.[key];
    if (t?.name) items.push({ id: items.length + 1, role: key, identity: String(t.name) });
  }
  const authed = items.filter((i) => i.identity);
  return {
    items,
    byId: new Map(items.map((i) => [i.id, i])),
    anonId: 1,
    authedIds: authed.map((i) => i.id),
    defaultAuthedId: authed[0]?.id ?? null,
  };
}

/** 对象菜单：本轮已发现的资源主键（越权类试打要有具体对象可填；主键不是凭据） */
export function buildResourceMenu(stash, { maxResources = EXPLORATION_DEFAULTS.maxResources } = {}) {
  const items = (stash?.resources ?? [])
    .filter((r) => r && String(r.id ?? "") !== "")
    .slice(0, maxResources)
    .map((r, i) => ({ id: i + 1, resourceId: String(r.id), owner: r.owner ?? null }));
  return { items, byId: new Map(items.map((i) => [i.id, i])), defaultId: items[0]?.id ?? null };
}

/** 某个目标能不能承载这个动作：槽位对得上、且计划里确实声明了注入点 */
export function targetSupports(target, primitive) {
  if (!target || !primitive) return false;
  if (!primitive.slots.includes(target.slot)) return false;
  if (primitive.requiresPlanRef && !target.planRef) return false;
  return true;
}

export function buildMenu(stash, budget = explorationBudget(null)) {
  const targets = buildTargetMenu(stash, { maxTargets: budget.maxTargets });
  const roles = buildRoleMenu(stash);
  const resources = buildResourceMenu(stash, { maxResources: budget.maxResources });
  return {
    targets,
    roles,
    resources,
    primitives: PRIMITIVES.map((p) => ({
      ...p,
      allowedTargetIds: targets.items.filter((t) => targetSupports(t, p)).map((t) => t.id),
    })),
    primitiveById: new Map(PRIMITIVES.map((p) => [p.id, p])),
  };
}

function renderMenuForPrompt(menu) {
  const authedRoles = (p) =>
    menu.roles.items.filter((r) => (p.roles.length ? menu.roles.authedIds.includes(r.id) : false)).map((r) => `${r.id}:${r.role}`);
  return {
    actions: menu.primitives.map((p) => ({
      id: p.id,
      action: p.action,
      what: p.desc,
      usable_on: p.allowedTargetIds.length ? p.allowedTargetIds : null,
      roles: p.roles.length ? authedRoles(p) : ["固定匿名"],
      needs_resource: p.needsResource,
    })),
    targets: menu.targets.items.map((t) => ({
      id: t.id,
      method: t.method,
      path: t.path,
      plan_slot: t.slot,
      wire: t.wire,
      declared_param: t.planRef?.param ?? null,
      // 要填对象主键的端点：资源菜单为空时选了也打不出去（执行器不猜 id），这里如实告诉模型
      needs_resource: t.needsResourceId === true,
    })),
    roles: menu.roles.items.map((r) => ({ id: r.id, role: r.role, vault_entry: r.identity })),
    resources: menu.resources.items.map((r) => ({ id: r.id, resource_id: r.resourceId, owned_by: r.owner })),
    note: "只能报上面这些编号。载荷内容、请求头、URL 前缀、判定标准都不接受——那些由引擎按写死的执行器生成。",
  };
}

function clamp(text, n) {
  const s = String(text ?? "");
  return s.length > n ? `${s.slice(0, n)}\n/* …(超限，已截去 ${s.length - n} 字符)… */` : s;
}

/**
 * 校验一步选择：只认编号。判据不在可选项里（红线 1），草稿的判据由引擎写定。
 * @returns {{ok:boolean, ignored:string[], step?:object, stop?:boolean, family?:string, rejected?:string}}
 */
export function validateExploreChoice(raw, menu) {
  const ignored = [];
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return { ok: false, ignored, rejected: "选择必须是 JSON 对象" };
  }
  for (const k of Object.keys(raw)) if (!ALLOWED_CHOICE_KEYS.has(k)) ignored.push(k);

  let family = null;
  if (typeof raw.family === "string" && raw.family.trim()) {
    const f = raw.family.trim();
    if (!FAMILY_RE.test(f)) ignored.push("family(非法命名)");
    else family = f;
  }

  if (raw.action === "giveup" || raw.stop === true) {
    return { ok: true, stop: true, ignored, family, note: String(raw.note ?? "").slice(0, 300) };
  }

  const prim = menu.primitiveById.get(Number(raw.primitive));
  if (!prim) {
    const ids = menu.primitives.map((p) => p.id).join(", ");
    return { ok: false, ignored, family, rejected: `动作编号 ${String(raw.primitive ?? "")} 不在菜单里（可用：${ids}）` };
  }
  const target = menu.targets.byId.get(Number(raw.target));
  if (!target) {
    const ok = prim.allowedTargetIds.join(", ") || "无（本轮计划里没有这个槽位的候选）";
    return { ok: false, ignored, family, rejected: `「${prim.action}」只能用这些目标编号：${ok}` };
  }
  if (!targetSupports(target, prim)) {
    return { ok: false, ignored, family, rejected: `目标 ${target.id}（${target.slot}）不是「${prim.action}」的可用槽位，引擎不会把它打到别处` };
  }

  let role = prim.roleFixed ? (menu.roles.byId.get(menu.roles.anonId) ?? null) : null;
  if (prim.roles.length) {
    const given = Number(raw.role);
    if (Number.isInteger(given) && menu.roles.authedIds.includes(given)) {
      role = menu.roles.byId.get(given);
    } else if (Number.isInteger(given) && !menu.roles.authedIds.includes(given)) {
      return { ok: false, ignored, family, rejected: `身份编号 ${given} 不能用在这个动作上（可用：${menu.roles.authedIds.join(", ") || "无已登录身份"}）` };
    } else if (menu.roles.defaultAuthedId != null) {
      role = menu.roles.byId.get(menu.roles.defaultAuthedId);
    } else {
      return { ok: false, ignored, family, rejected: "本轮没有可用的已登录身份，这个动作无法执行" };
    }
  } else if (raw.role !== undefined && raw.role !== null) {
    ignored.push("role(该动作身份固定)");
  }

  let resource = null;
  if (prim.needsResource !== "forbidden") {
    const given = Number(raw.resource);
    if (Number.isInteger(given) && menu.resources.byId.has(given)) resource = menu.resources.byId.get(given);
    else if (Number.isInteger(given)) return { ok: false, ignored, family, rejected: `对象编号 ${given} 不在本轮发现的资源菜单里` };
    else if (target.needsResourceId) {
      // 没有可填的对象就是打不了：与其发一个凭空 id 的请求，不如当场把原因说清（执行器里还有同一道闸）
      if (menu.resources.defaultId == null) {
        return { ok: false, ignored, family, rejected: "该端点要一个对象主键，本轮发现阶段没有给出可用对象（探索区不猜 id）" };
      }
      resource = menu.resources.byId.get(menu.resources.defaultId);
    }
  } else if (raw.resource !== undefined && raw.resource !== null) {
    ignored.push("resource(该动作不填对象)");
  }

  return {
    ok: true,
    ignored,
    family,
    note: String(raw.note ?? "").slice(0, 300),
    step: { primitive: prim, action: prim.action, target, role, resource },
  };
}

/**
 * 从一步真实执行反推草稿里的那一行：只写槽位、角色名与 `{plan.*}` 引用。
 * 对象主键不进草稿——已注册配方里对象从来不由配方声明（`targets.readTarget` 那类是引擎在发现阶段选的），
 * 写了 `resource` 就是表外参数，动作表会当场拒收。实发用的是哪一个对象记在同一步的 note 里，供人核对。
 */
export function draftStepOf(entry, index) {
  const base = { id: `exp-${index + 1}`, action: entry.action };
  const path = `{slot:${entry.slot}}`;
  const obj = entry.resourceId == null ? "" : `（本轮实发对象 #${entry.resourceId}，由发现阶段选定）`;
  if (entry.action === "request.anonymous") {
    return { ...base, method: entry.method, path, note: `匿名请求该槽位候选${obj}` };
  }
  if (entry.action === "request.as") {
    return { ...base, method: entry.method, path, identity: entry.role, note: `以 ${entry.role} 身份请求该槽位候选${obj}` };
  }
  if (entry.action === "payload.inject") {
    return { ...base, path, param: "{plan.param}", payloadSet: "sqli-default", identity: entry.role, note: `在计划声明的注入参数上放载荷集 sqli-default（身份 ${entry.role}）` };
  }
  if (entry.action === "fs.traverse") {
    return { ...base, method: "GET", path, param: "{plan.param}", canary: "package.json", note: "逐级 ../ 回读 canary（method 由执行器写死为 GET）" };
  }
  return null;
}

/**
 * 把 trace 落成配方草稿：引擎按实际执行过的动作逐行映射，重复的合并成一步。
 * 随后立刻过 `validateRecipe`——映射不出表内写法就说明这一路被夸大，当场拒收并留拒收原文。
 * 判据由引擎写死（EXPLORATION_DRAFT_RULE），模型与契约都改不了：探索区只回答「怎么打」，不回答「什么算打穿」。
 */
export function buildDraft(trace, { family = null, maxSteps = EXPLORATION_DEFAULTS.maxDraftSteps } = {}) {
  const steps = [];
  const seen = new Set();
  for (const entry of trace ?? []) {
    if (entry.error) continue;
    const step = draftStepOf(entry, steps.length);
    if (!step) continue;
    const key = JSON.stringify([step.action, step.path, step.identity ?? null, step.method ?? null, step.param ?? null, step.payloadSet ?? null, step.canary ?? null]);
    if (seen.has(key)) continue;
    seen.add(key);
    if (steps.length >= maxSteps) break;
    steps.push(step);
  }
  const recipe = {
    version: RECIPE_VERSION,
    family: family ?? "explore-undecided",
    generatedBy: `${EXPLORATION_VERSION}（探索区自动草稿，非人工定稿）`,
    steps,
    verdict: { rule: EXPLORATION_DRAFT_RULE },
  };
  const validation = validateRecipe(recipe);
  return {
    recipe,
    family: recipe.family,
    familyDeclared: family != null,
    verdictRule: EXPLORATION_DRAFT_RULE,
    verdictByEngine: true,
    steps: steps.length,
    tableOk: validation.ok,
    rejections: validation.ok ? [] : validation.rejections.map((r) => ({ where: r.where, rule: r.rule, why: r.why ?? null })),
    rejectionText: formatRejections(validation),
    registered: false,
    note: "草稿未过判卷器（第 6 项）：不得进判定链，不得写入 sidecar/recipes/。过表校验只代表填表合法，不代表打得中。",
  };
}

const SYSTEM_PROMPT = `你在一个隔离沙箱里对一个本地靶场做攻击方式探索：目标是把「这一族攻击该怎么打」试出来，供引擎落成配方草稿。
硬性规则：
1. 每轮只报编号：动作（primitive）、目标端点（target）、身份（role）、对象（resource）。你不写 URL、不写载荷、不写请求头、不写参数值、不写判定标准——那些全部由引擎按写死的执行器生成。
2. 你看不到也改不了判据。不要下结论、不要说「有漏洞/安全」，你的产出只是一次次试打的选择。
3. 依据只有上一轮的真实响应（状态码、字节数、脱敏正文摘录）。据此换目标、换身份、换对象，或认为没有可试的组合就报 {"stop":true,"family":"这一族的英文名"}。
4. 预算有限（请求数、轮数、时长都写死），宁少勿多；不要重复已经同样打过的那一步。
只返回一个 JSON 对象：{"primitive":2,"target":1,"role":2,"resource":1} 或 {"stop":true,"family":"idor-read-x"}。不要输出 JSON 以外的内容。`;

function observationOf(menu, budget, state, history) {
  return {
    goal: "试出这一族攻击的打法（动作+槽位+身份+对象的组合），产出一张配方草稿；你不判定漏洞，也不构造请求内容",
    budget: {
      requests_used: state.requestsUsed,
      requests_left: Math.max(0, budget.maxRequests - state.requestsUsed),
      rounds_left: Math.max(0, budget.maxRounds - state.rounds),
      seconds_left: Math.max(0, Math.round((budget.totalBudgetMs - (Date.now() - state.startedAt)) / 1000)),
    },
    ...renderMenuForPrompt(menu),
    history,
  };
}

function artifactDir(root) {
  const base = process.env.GUARDBUILD_DATA_DIR;
  if (typeof base !== "string" || !base.trim() || !root) return null;
  let p = String(root).replace(/\\/g, "/").replace(/\/+$/, "");
  if (process.platform === "win32") p = p.toLowerCase();
  return join(base, "exploration", createHash("sha256").update(p).digest("hex").slice(0, 16));
}

/** 键只取「本轮可打组合的形状」+ 模型名：菜单变了就重探，不沿用别的目标形状的草稿 */
export function draftKeyFor(model, menu) {
  const h = createHash("sha256");
  h.update(EXPLORATION_VERSION);
  h.update("\0");
  h.update(model ?? "");
  for (const t of menu.targets.items) h.update(`\0${t.id}:${t.slot}:${t.path}:${t.planRef?.param ?? "-"}`);
  for (const r of menu.roles.items) h.update(`\0${r.id}:${r.role}:${r.identity ?? "-"}`);
  for (const r of menu.resources.items) h.update(`\0${r.id}:${r.resourceId}:${r.owner ?? "-"}`);
  return h.digest("hex").slice(0, 32);
}

function writeArtifactAtomic(file, data) {
  const tmp = `${file}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(data, null, 1), "utf8");
  renameSync(tmp, file);
}

function pruneArtifacts(dir) {
  try {
    const files = readdirSync(dir)
      .filter((n) => n.endsWith(".json"))
      .map((n) => ({ n, t: statSync(join(dir, n)).mtimeMs }))
      .sort((a, b) => b.t - a.t);
    for (const f of files.slice(ARTIFACT_MAX_FILES)) rmSync(join(dir, f.n), { force: true });
  } catch {
    /* 清理失败不影响探索结论 */
  }
}

/**
 * 探索产物落盘：`$GUARDBUILD_DATA_DIR/exploration/<项目哈希>/<键>.json`。
 * 只落数据目录，绝不落 `sidecar/recipes/`——注册是新工具经人批准后的动作（红线 1/8）。
 */
export function writeExplorationArtifact(ctx, result) {
  const dir = artifactDir(ctx?.projectRoot);
  if (!dir || !result?.draft) return null;
  const file = join(dir, `${result.draftKey}.json`);
  try {
    mkdirSync(dirname(file), { recursive: true });
    writeArtifactAtomic(file, {
      version: EXPLORATION_VERSION,
      savedAt: Date.now(),
      model: result.model ?? null,
      outcome: result.outcome,
      budget: result.budget,
      budgetStop: result.budgetStop ?? null,
      requestsUsed: result.requestsUsed,
      modelCalls: result.modelCalls,
      durationMs: result.durationMs,
      ignoredFields: result.ignoredFields,
      rejectedChoices: result.rejectedChoices,
      trace: result.trace,
      draft: result.draft,
    });
    pruneArtifacts(dir);
    return file;
  } catch {
    return null;
  }
}

/** 逐步 + 收尾事件与审计落库（与启动代理同一张 agent_actions 表） */
export function recordExploration(ctx, step) {
  try {
    ctx.db?.insertAgentAction?.({
      id: `exp_${Date.now().toString(36)}_${step.seq ?? 0}`,
      sessionId: ctx.sessionId,
      step: step.seq ?? null,
      action: "explore",
      subject: step.action ? `${step.action} ${step.slot ?? ""}`.trim() : String(step.subject ?? step.action ?? "explore"),
      ok: step.ok === true,
      exitCode: step.status ?? null,
      durationMs: step.durationMs ?? null,
      budgetRemainingMs: step.budgetRemainingMs ?? null,
      note: step.note ?? null,
      createdAt: Date.now(),
    });
  } catch {
    /* 审计失败不改变裁决：探索本来就不产结论 */
  }
}

function emitStep(ctx, data, message, severity = SEVERITY.INFO) {
  ctx.emit?.({ kind: "exploration", severity, message, phase: ctx.state ?? "pre", data });
}

/**
 * 一轮自主探索。
 * @param {object} ctx 会话上下文（emit/db/projectRoot/targetConfig）
 * @param {object} opts
 * @param {string} opts.baseUrl 目标实例地址（修复前的原始实例）
 * @param {(plan:object)=>Promise<object>} opts.sendStep 执行器（由 probe.mjs 注入：模型不给请求内容）
 * @param {object} [opts.stash] runPhase 结束后留在 ctx._exploration 上的候选/身份/资源快照
 * @param {(url:string, reason:string)=>Promise<string>} opts.getToken
 * @param {string} [opts.model]
 * @param {typeof chat} [opts.chatImpl] LLM 调用注入点（单测用）
 */
export async function runExploration(
  ctx,
  { baseUrl, sendStep, stash = null, getToken = null, model = null, chatImpl = chat, budget = null, onStep = null } = {}
) {
  const b = budget ?? explorationBudget(ctx);
  const s = stash ?? ctx?._exploration ?? null;
  const state = {
    version: EXPLORATION_VERSION,
    enabled: true,
    model: model ?? null,
    baseUrl: baseUrl ?? null,
    budget: b,
    outcome: "not_run",
    rounds: 0,
    modelCalls: 0,
    requestsUsed: 0,
    usedOutputChars: 0,
    steps: [],
    trace: [],
    ignoredFields: [],
    rejectedChoices: [],
    budgetStop: null,
    error: null,
    draft: null,
    draftKey: null,
    artifact: null,
    startedAt: Date.now(),
    durationMs: 0,
  };
  const seenIgnored = new Set();
  const noteIgnored = (names) => {
    for (const n of names ?? []) {
      if (seenIgnored.has(n)) continue;
      seenIgnored.add(n);
      state.ignoredFields.push(n);
    }
  };

  if (typeof sendStep !== "function") {
    state.outcome = "not_run";
    state.error = "no_executor";
    return state;
  }
  const menu = buildMenu(s, b);
  state.menu = {
    targets: menu.targets.items.length,
    roles: menu.roles.items.length,
    resources: menu.resources.items.length,
    actions: menu.primitives.filter((p) => p.allowedTargetIds.length).map((p) => p.action),
  };
  if (!menu.targets.items.length) {
    state.outcome = "no_targets";
    emitStep(ctx, { action: "menu", subject: "空菜单", ok: false }, "探索区未启动：本轮计划里没有可试打的端点槽位", SEVERITY.WARN);
    return finish(ctx, state, b);
  }

  let family = null;

  while (true) {
    const stop = outOfBudget(state, b);
    if (stop) {
      state.outcome = "budget_exhausted";
      state.budgetStop = stop;
      recordExploration(ctx, { seq: state.rounds, action: "budget", ok: false, note: stop });
      emitStep(ctx, { action: "budget", subject: stop, ok: false }, `探索区超限即停：${stop}`, SEVERITY.WARN);
      break;
    }
    state.rounds += 1;

    const history = state.trace.slice(-MAX_STEP_HISTORY).map((t) => ({
      seq: t.seq,
      action: t.action,
      target: t.path,
      role: t.role,
      status: t.status,
      bytes: t.bytes,
      excerpt: t.excerpt,
      error: t.error,
    }));
    let res;
    const t0 = Date.now();
    try {
      state.modelCalls += 1;
      res = await chatImpl(ctx, {
        systemPrompt: SYSTEM_PROMPT,
        userPrompt: clamp(JSON.stringify(observationOf(menu, b, state, history), null, 1), MAX_OBSERVE_CHARS),
        getToken: getToken ?? ctx?.llmGetToken,
        model,
        maxTokens: 400,
        purpose: "探索区选下一步",
      });
    } catch (e) {
      state.outcome = e instanceof LlmError ? "llm_unavailable" : "agent_error";
      state.error = redactSecrets(String(e?.message ?? e)).slice(0, 300);
      emitStep(ctx, { action: "ask", subject: state.error, ok: false, durationMs: Date.now() - t0 }, `探索区未获得可用选择：${state.error}`, SEVERITY.WARN);
      break;
    }
    state.model = res.model ?? state.model;

    let choice;
    try {
      choice = parseJson(res.content);
    } catch (e) {
      state.rejectedChoices.push({ round: state.rounds, why: String(e?.message ?? e).slice(0, 160), kind: "bad_json" });
      emitStep(ctx, { action: "rejected", subject: "非 JSON 输出", ok: false }, `探索区第 ${state.rounds} 轮输出无法解析，未发出请求`, SEVERITY.WARN);
      continue;
    }

    const checked = validateExploreChoice(choice, menu);
    noteIgnored(checked.ignored);
    if (checked.family) family = checked.family;
    if (!checked.ok) {
      state.rejectedChoices.push({ round: state.rounds, why: checked.rejected, kind: "choice_rejected" });
      emitStep(
        ctx,
        { action: "rejected", subject: `round=${state.rounds}`, ok: false, note: checked.rejected },
        `探索区第 ${state.rounds} 轮的选择被拒：${checked.rejected}`,
        SEVERITY.WARN
      );
      if (checked.ignored?.length) {
        emitStep(ctx, { action: "sanitize", subject: checked.ignored.join(","), ok: true, note: "只按菜单编号执行，模型自带字段已丢弃" }, `探索区丢弃了模型自带的表外字段：${checked.ignored.join("、")}`, SEVERITY.WARN);
      }
      continue;
    }
    if (checked.stop) {
      state.outcome = "stopped";
      recordExploration(ctx, { seq: state.rounds, action: "stop", ok: true, note: family ? `family=${family}` : "未给 family" });
      emitStep(ctx, { action: "stop", subject: family ?? "未给 family", ok: true }, `探索区自行收手：已试 ${state.requestsUsed} 次请求，草稿族名 ${family ?? "（模型未给，草稿标为待定）"}`, SEVERITY.SUCCESS);
      break;
    }
    if (checked.ignored?.length) {
      emitStep(ctx, { action: "sanitize", subject: checked.ignored.join(","), ok: true, note: "只按菜单编号执行，模型自带字段已丢弃" }, `探索区丢弃了模型自带的表外字段：${checked.ignored.join("、")}`, SEVERITY.WARN);
    }

    const plan = {
      action: checked.step.action,
      slot: checked.step.target.slot,
      cand: candOf(s, checked.step.target),
      identity: checked.step.role?.identity ?? null,
      role: checked.step.role?.role ?? "anonymous",
      resourceId: checked.step.resource?.resourceId ?? null,
      payloadIndex: state.trace.filter((t) => t.action === checked.step.action).length,
    };
    state.steps.push({ round: state.rounds, action: plan.action, slot: plan.slot, role: plan.role });

    let sent = null;
    let err = null;
    const t1 = Date.now();
    try {
      sent = await sendStep(plan);
    } catch (e) {
      err = e;
    }
    state.requestsUsed += 1;
    const entry = {
      seq: state.trace.length + 1,
      action: plan.action,
      slot: plan.slot,
      role: plan.role,
      identity: plan.identity,
      resourceId: plan.resourceId,
      method: sent?.method ?? null,
      path: sent?.path ?? null,
      status: Number.isFinite(sent?.status) ? sent.status : null,
      bytes: Number.isFinite(sent?.bytes) ? sent.bytes : 0,
      excerpt: clamp(redactSecrets(String(sent?.excerpt ?? "")), MAX_TRACE_EXCERPT) || null,
      error: err ? clamp(redactSecrets(String(err?.message ?? err)), 200) : sent?.error ? redactSecrets(String(sent.error)).slice(0, 200) : null,
      ok: !err && !!sent?.ok,
      durationMs: Date.now() - t1,
    };
    state.usedOutputChars += (entry.excerpt?.length ?? 0) + (entry.error?.length ?? 0);
    state.trace.push(entry);
    recordExploration(ctx, {
      seq: entry.seq,
      action: entry.action,
      slot: entry.slot,
      ok: entry.ok,
      status: entry.status,
      durationMs: entry.durationMs,
      budgetRemainingMs: Math.max(0, b.totalBudgetMs - (Date.now() - state.startedAt)),
      note: entry.error ?? `${entry.role}→${entry.slot}`,
    });
    emitStep(
      ctx,
      { seq: entry.seq, action: entry.action, slot: entry.slot, role: entry.role, status: entry.status, bytes: entry.bytes, ok: entry.ok },
      entry.ok
        ? `探索区第 ${entry.seq} 次实发：${entry.method ?? "?"} ${entry.path ?? "?"}（身份 ${entry.role}）→ HTTP ${entry.status}，${entry.bytes} 字节`
        : `探索区第 ${entry.seq} 次实发未成功：${entry.error ?? "无响应"}`,
      entry.ok ? SEVERITY.INFO : SEVERITY.WARN
    );
    if (typeof onStep === "function") onStep(entry);
  }

  if (state.trace.length) {
    state.draft = buildDraft(state.trace, { family, maxSteps: b.maxDraftSteps });
    state.draftKey = draftKeyFor(state.model, menu);
    state.artifact = writeExplorationArtifact(ctx, state);
    emitStep(
      ctx,
      { action: "draft", subject: state.draft.family, ok: state.draft.tableOk, draft: state.draft, artifact: state.artifact },
      state.draft.tableOk
        ? `探索区落成配方草稿：${state.draft.steps} 步（族名 ${state.draft.family}），已过动作表校验；未过判卷器，不进判定链`
        : `探索区草稿被动作表拒收：${state.draft.rejections.length} 处表外——草稿留档但不注册`,
      state.draft.tableOk ? SEVERITY.SUCCESS : SEVERITY.WARN
    );
  }
  return finish(ctx, state, b);
}

function candOf(stash, target) {
  const list = stash?.candidates?.[target.slot] ?? [];
  return list.find((c) => (c?.fullPath ?? c?.path ?? null) === target.path) ?? null;
}

function outOfBudget(state, b) {
  if (state.requestsUsed >= b.maxRequests) return `请求数上限（${b.maxRequests} 次）已用尽`;
  if (state.rounds >= b.maxRounds) return `轮数上限（${b.maxRounds} 轮）已用尽`;
  if (Date.now() - state.startedAt >= b.totalBudgetMs) return `时长预算（${Math.round(b.totalBudgetMs / 1000)}s）已用尽`;
  if (state.usedOutputChars >= b.maxOutputChars) return `累计输出预算（${b.maxOutputChars} 字符）已用尽`;
  return null;
}

function finish(ctx, state, b) {
  state.durationMs = Date.now() - state.startedAt;
  state.budgetRemainingMs = Math.max(0, b.totalBudgetMs - state.durationMs);
  state.rejected = state.rejectedChoices.length;
  if (ctx?.view) ctx.view.exploration = summarizeExploration(state);
  ctx?.pushView?.();
  return state;
}

/** 报告与视图用的压缩摘要：只带引擎侧事实，不带模型原文 */
export function summarizeExploration(state) {
  if (!state) return null;
  return {
    version: state.version ?? EXPLORATION_VERSION,
    outcome: state.outcome ?? null,
    model: state.model ?? null,
    rounds: state.rounds ?? 0,
    modelCalls: state.modelCalls ?? 0,
    requestsUsed: state.requestsUsed ?? 0,
    budget: state.budget ?? null,
    budgetStop: state.budgetStop ?? null,
    durationMs: state.durationMs ?? null,
    menu: state.menu ?? null,
    ignoredFields: state.ignoredFields ?? [],
    rejectedChoices: (state.rejectedChoices ?? []).map((r) => ({ round: r.round, kind: r.kind, why: String(r.why ?? "").slice(0, 160) })),
    error: state.error ?? null,
    trace: (state.trace ?? []).map((t) => ({
      seq: t.seq,
      action: t.action,
      slot: t.slot,
      role: t.role,
      method: t.method,
      path: t.path,
      status: t.status,
      bytes: t.bytes,
      ok: t.ok,
      error: t.error,
    })),
    draft: state.draft
      ? {
          family: state.draft.family,
          familyDeclared: state.draft.familyDeclared,
          // 判据归属是要给复核者看的事实：这一条是引擎写死的，模型自定的 verdict 早被丢弃
          verdictRule: state.draft.verdictRule,
          verdictByEngine: state.draft.verdictByEngine,
          steps: state.draft.steps,
          tableOk: state.draft.tableOk,
          rejections: state.draft.rejections,
          registered: state.draft.registered,
          note: state.draft.note,
          recipe: state.draft.recipe,
        }
      : null,
    artifact: state.artifact ?? null,
  };
}

/** 锚点自检：菜单上写的每个动作，执行器里必须真的还有那一段 */
export function checkExplorationAnchors(repoRoot, fs) {
  const unresolved = [];
  for (const p of PRIMITIVES) {
    let text = null;
    try {
      text = fs.readFileSync(join(repoRoot, p.anchor.file), "utf8");
    } catch {
      unresolved.push({ action: p.action, why: "执行器文件不存在" });
      continue;
    }
    if (!text.includes(p.anchor.token)) unresolved.push({ action: p.action, why: `记号 ${p.anchor.token} 已不在执行器里` });
  }
  return { ok: unresolved.length === 0, checked: PRIMITIVES.length, unresolved };
}
