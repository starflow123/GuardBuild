/**
 * 证据约束下的攻击规划（M2）：黑盒扫描的**路由预算**由模型分配，攻击内容仍由引擎生成。
 *
 * 要补的缺口很具体：路由发现能拿到几十条，而每类探测只打前 14 条（MAX_PROBE_ROUTES）。
 * 引擎的排序规则只有「OpenAPI 优先、404 垫底」这种形状无关的启发式，真实目标里
 * 「/api/contracts」这类高价值端点常常排在预算之外——这是漏报，不是目标安全。
 *
 * 硬边界（与 S3-full 的菜单同一套纪律，只放宽「选什么」，不放宽「怎么打」）：
 *  - 模型只能从引擎给出的**待排路由编号**里挑，挑完仍由引擎按原有探测族与判据实跑；
 *  - 载荷、方法、参数、请求内容、判定条件一概不接受：出现在选择里就丢弃并留痕；
 *  - 模型不判定漏洞、不声称「修好了」，finding 只来自实测证据；
 *  - 预算没有被挤爆时不问模型（路由数 ≤ 每类探测上限就不存在取舍，省一次外发）；
 *  - gate/CI 结构性禁用（attackPlanEnabled 里判 ctx.gate），默认关闭需显式开启。
 */
import { SEVERITY } from "../../shared/protocol.mjs";
import { LlmError, chat, parseJson } from "./llm.mjs";

export const MAX_PLAN_MENU_ROUTES = 40;
export const MAX_PICKS_DEFAULT = 8;
export const MAX_PLAN_ROUNDS = 2;
const MAX_OBSERVE_CHARS = 20_000;

/** 模型若试图自己规定「怎么打」，这些键会被丢弃并只留字段名进审计 */
const SMUGGLED_KEYS = [
  "payload", "payloads", "params", "param", "body", "headers", "method", "url", "path",
  "cmd", "command", "args", "shell", "script", "token", "identity", "verdict", "severity",
  "expectation", "exploit",
];

/** 交互模式下的攻击规划开关：gate 结构性禁用 */
export function attackPlanEnabled(ctx, options = {}) {
  if (ctx?.gate === true) return false;
  const cfg = options?.config?.blackbox?.attackPlan ?? null;
  if (cfg === true) return true;
  if (cfg === false) return false;
  if (cfg && typeof cfg === "object") {
    if (cfg.enabled === true) return true;
    if (cfg.enabled === false) return false;
  }
  return process.env.GUARDBUILD_LLM_ATTACKPLAN === "1";
}

function planBudget(options) {
  const cfg = options?.config?.blackbox?.attackPlan ?? {};
  const clamp = (v, lo, hi, dft) => (Number.isFinite(v) ? Math.min(hi, Math.max(lo, Math.floor(v))) : dft);
  return {
    maxPicks: clamp(cfg?.maxPicks, 1, 16, MAX_PICKS_DEFAULT),
    maxMenu: clamp(cfg?.maxMenu, 5, MAX_PLAN_MENU_ROUTES, MAX_PLAN_MENU_ROUTES),
    rounds: clamp(cfg?.rounds, 1, MAX_PLAN_ROUNDS, MAX_PLAN_ROUNDS),
  };
}

/**
 * 待排路由菜单：只列「按引擎原序拿不到预算」的那批，编号即选择面。
 * @param {Array<object>} routes 引擎已合并的路由（原序）
 * @param {number} probeCap 每类探测的路由预算
 */
export function buildRouteMenu(routes, probeCap, { maxMenu = MAX_PLAN_MENU_ROUTES } = {}) {
  const gets = (routes ?? []).filter((r) => r && typeof r.path === "string" && r.method === "GET");
  const covered = gets.slice(0, Math.max(1, probeCap));
  const tail = gets.slice(covered.length, covered.length + maxMenu);
  const items = tail.map((r, i) => ({
    id: i + 1,
    method: r.method,
    path: r.path,
    source: r.source ?? "unknown",
    status: Number.isFinite(r.status) ? r.status : null,
    params: (r.queryParams ?? []).filter((p) => typeof p === "string" && p).slice(0, 4),
  }));
  return {
    probeCap: Math.max(1, probeCap),
    covered: covered.map((r) => r.path),
    items,
    byId: new Map(items.map((it) => [it.id, it])),
    // 编号 → 原始路由对象（applyRouteOrder 要用它，不能让模型构造出对象）
    routesById: new Map(items.map((it, i) => [it.id, tail[i]])),
  };
}

/** 给提示词的菜单视图：只有编号与路由自身可见的线索 */
function renderMenuForPrompt(menu) {
  return {
    unprobed_routes: menu.items.map((it) => ({
      id: it.id,
      method: it.method,
      path: it.path,
      discovered_by: it.source,
      last_status: it.status,
      declared_query_params: it.params.length ? it.params : null,
    })),
    note: `只能报上面这些编号；引擎每类探测的预算是 ${menu.probeCap} 条路由。`,
  };
}

/**
 * 校验模型的选择：只认编号。
 * @returns {{ok:true, ids:number[], picked:object[], ignored:string[], note:string, invalid:number[]}|{ok:false, reason:string, ignored:string[]}}
 */
export function validatePlanChoice(raw, menu, { maxPicks = MAX_PICKS_DEFAULT } = {}) {
  const ignored = SMUGGLED_KEYS.filter((k) => raw?.[k] !== undefined);
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return { ok: false, reason: "选择必须是 JSON 对象", ignored };
  }
  if (raw.picks === undefined || raw.picks === null || raw.picks === "") {
    return { ok: true, ids: [], picked: [], ignored, note: String(raw.note ?? "").slice(0, 300), invalid: [], empty: true };
  }
  if (!Array.isArray(raw.picks)) {
    return { ok: false, reason: "picks 必须是编号数组", ignored };
  }
  if (!raw.picks.length) {
    // 「没有值得优先打的」是合法结论：不改预算，按引擎原序探测
    return { ok: true, ids: [], picked: [], ignored, note: String(raw.note ?? "").slice(0, 300), invalid: [], empty: true };
  }
  const ids = [];
  const invalid = [];
  for (const v of raw.picks) {
    const id = Number(v);
    if (!Number.isInteger(id)) {
      invalid.push(String(v).slice(0, 20));
      continue;
    }
    if (!menu.byId.has(id) || ids.includes(id)) {
      invalid.push(id);
      continue;
    }
    if (ids.length >= maxPicks) continue;
    ids.push(id);
  }
  if (!ids.length) {
    const valid = menu.items.map((i) => i.id).join(", ") || "无";
    return {
      ok: false,
      reason: `所选编号都不在待排路由菜单内（非法：${invalid.slice(0, 5).join(", ") || "无"}；可用编号：${valid}）`,
      ignored,
      invalid,
    };
  }
  return {
    ok: true,
    ids,
    picked: ids.map((id) => menu.byId.get(id)),
    ignored,
    invalid,
    note: String(raw.note ?? "").slice(0, 300),
  };
}

/** 把选中的路由提到队首（保持模型给的次序），其余按引擎原序垫后 */
export function applyRouteOrder(routes, ids, menu) {
  const chosen = ids.map((id) => menu.routesById.get(id)).filter(Boolean);
  const seen = new Set(chosen.map((r) => r));
  return [...chosen, ...(routes ?? []).filter((r) => !seen.has(r))];
}

const SYSTEM_PROMPT = `你在为一次纯黑盒 HTTP 安全扫描分配探测预算。引擎已经发现了一批路由，但请求预算只够打其中一部分，你的任务只是决定「谁优先进入预算」。
硬性规则：
1. 只能从给出的 unprobed_routes 里挑编号（picks 数组）。你不能指定 URL、方法、参数名、参数值、请求头、载荷或任何请求内容——那些由引擎按固定模板生成。
2. 你不判定漏洞，也不得声称某个端点「有漏洞/安全」。是否算漏洞只由引擎实跑后的响应证据决定。
3. 挑选只能依据路由自身可见的线索：路径语义、发现来源、探测时的状态码、声明的查询参数。
4. 预算有限，宁少勿多；认为没有值得优先打的就返回空 picks。
只返回一个 JSON 对象：{"picks":[3,11],"note":"一句话理由"}。不要输出 JSON 以外的内容。`;

function clamp(text, n) {
  const s = String(text ?? "");
  return s.length > n ? `${s.slice(0, n)}\n/* …(超限，已截去 ${s.length - n} 字符)… */` : s;
}

/** 上一轮实测结论的压缩视图（只给「哪条路由被哪族打过、结论是什么」，不给响应体） */
function priorEvidenceOf(records, limit = 24) {
  const out = [];
  for (const r of records ?? []) {
    if (!r?.caseId) continue;
    out.push({ route: String(r.endpoint ?? "").slice(0, 120), case: r.caseId, verdict: r.verdict });
    if (out.length >= limit) break;
  }
  return out;
}

/**
 * 一轮规划：问一次模型，拿到重排后的路由序。
 * @param {object} ctx 会话上下文（emit/db/state）
 * @param {object} opts
 * @param {Array<object>} opts.routes 引擎原序的路由
 * @param {number} opts.probeCap 每类探测的路由预算
 * @param {number} opts.round 第几轮（1=探测前分配预算，2=按上轮实测证据复排）
 * @param {Array<object>} [opts.records] 上一轮已落地的证据记录（round≥2 用）
 * @param {(url:string, reason:string)=>Promise<string>} opts.getToken
 * @param {string} [opts.model]
 * @param {typeof chat} [opts.chatImpl] LLM 调用注入点（单测用）
 */
export async function runAttackPlanner(
  ctx,
  { routes = [], probeCap = 14, round = 1, records = null, getToken, model = null, budget = null, chatImpl = chat } = {}
) {
  const b = budget ?? planBudget({ config: { blackbox: { attackPlan: true } } });
  const menu = buildRouteMenu(routes, probeCap, { maxMenu: b.maxMenu });
  const base = {
    round,
    probeCap: menu.probeCap,
    menuSize: menu.items.length,
    coveredCount: menu.covered.length,
    ordered: routes,
    picks: [],
    ignored: [],
    invalid: [],
    rejected: null,
    fallback: null,
    model: model ?? null,
    usage: null,
    asked: false,
    durationMs: 0,
  };
  if (!menu.items.length) {
    return { ...base, asked: false, fallback: "no_unprobed_routes" };
  }

  const observation = {
    goal: "在预算内优先攻击尚未获得探测机会的路由；只挑编号，不规定怎么打",
    round,
    budget: { route_cap_per_family: menu.probeCap, picks_allowed: b.maxPicks },
    already_covered: menu.covered.slice(0, 30),
    ...renderMenuForPrompt(menu),
  };
  if (round >= 2) {
    observation.prior_evidence = priorEvidenceOf(records);
    observation.prior_note = "上面是引擎上一轮实跑得到的证据（判定由证据给出，不是你）；请据此把还没被打过的高价值路由排进剩余预算";
  }

  const t0 = Date.now();
  let res;
  try {
    res = await chatImpl(ctx, {
      systemPrompt: SYSTEM_PROMPT,
      userPrompt: clamp(JSON.stringify(observation, null, 1), MAX_OBSERVE_CHARS),
      getToken,
      model,
      maxTokens: 500,
      purpose: `攻击规划（第 ${round} 轮）`,
    });
  } catch (e) {
    return {
      ...base,
      asked: true,
      durationMs: Date.now() - t0,
      fallback: e instanceof LlmError ? "llm_unavailable" : "planner_error",
      rejected: String(e?.message ?? e).slice(0, 300),
    };
  }
  const durationMs = Date.now() - t0;

  let choice;
  try {
    choice = parseJson(res.content);
  } catch (e) {
    return {
      ...base,
      asked: true,
      durationMs,
      model: res.model ?? model,
      usage: res.usage ?? null,
      fallback: "bad_json",
      rejected: String(e?.message ?? e).slice(0, 300),
    };
  }

  const checked = validatePlanChoice(choice, menu, { maxPicks: b.maxPicks });
  // 模型原文（note）不进事件流、审计、报告：留痕只记引擎侧事实与字段名
  const common = {
    ...base,
    asked: true,
    durationMs,
    model: res.model ?? model,
    usage: res.usage ?? null,
    ignored: checked.ignored,
    invalid: checked.invalid ?? [],
  };
  if (!checked.ok) {
    return { ...common, ordered: routes, fallback: "choice_rejected", rejected: checked.reason };
  }
  return {
    ...common,
    ordered: applyRouteOrder(routes, checked.ids, menu),
    picks: checked.picked.map((p) => ({ id: p.id, method: p.method, path: p.path })),
    applied: checked.ids.length,
    empty: checked.empty === true,
    rejected: null,
    fallback: null,
  };
}

/** 规划轮次的审计落库与事件（与启动代理同一张 agent_actions 表，便于事后回看预算是怎么分配的） */
export function recordPlan(ctx, round) {
  const subject = `${round.fallback ?? (round.empty ? "未挑选" : `picks=${round.picks.map((p) => p.path).join(",")}`)}`;
  const note = [
    round.picks.length ? `提进预算 ${round.picks.length} 条` : "未改动预算",
    round.ignored.length ? `丢弃字段：${round.ignored.join(",")}` : null,
    round.invalid.length ? `非法编号：${round.invalid.length} 个` : null,
    round.rejected ? `被拒：${String(round.rejected).slice(0, 120)}` : null,
  ]
    .filter(Boolean)
    .join("；");
  try {
    ctx.db?.insertAgentAction?.({
      id: `plan_${Date.now().toString(36)}_${round.round}`,
      sessionId: ctx.sessionId,
      step: round.round,
      action: "attack_plan",
      subject,
      ok: !round.fallback,
      exitCode: null,
      durationMs: round.durationMs,
      budgetRemainingMs: null,
      note,
      createdAt: Date.now(),
    });
  } catch {
    /* 审计失败不改变裁决 */
  }
  const severity = round.fallback ? SEVERITY.WARN : SEVERITY.INFO;
  const message = round.fallback
    ? `攻击规划第 ${round.round} 轮未采纳（${round.fallback}），按引擎原序探测`
    : `攻击规划第 ${round.round} 轮：${round.picks.length} 条预算外路由被提进探测队列（模型只选路由，判定仍由实测证据）`;
  ctx.emit?.({ kind: "attackplan", severity, message, phase: ctx.state ?? "blackbox", data: round });
  return { subject, note, message, severity };
}

export { planBudget };
