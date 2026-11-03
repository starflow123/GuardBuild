/**
 * 提议者 A/B（方案第 14 项）：同一条探索通道上跑两遍，两遍的**输入文本不同**。
 *
 * 为什么要两路：单路提议者只有一种「看问题的方式」，它写出的草稿会顺着它自己的习惯收敛。
 * 两路的差别刻意做成「依据不同」——
 *   A 通用形状：只拿菜单（动作/槽位/身份/对象编号）+ 与靶子无关的通用打法清单 + 自己那轮的状态码；
 *   B 响应形状：拿同一份菜单 + 自己那轮的真实响应摘录（状态码、字节数、脱敏正文片段）。
 * 两者**不共享中间文本**：A 的清单不会出现在 B 的提示里，B 看到的响应摘录不会出现在 A 的提示里，
 * 任何一路的历史都不会喂给另一路。这不是注释里的承诺——`checkPromptIsolation` 逐条扫出站提示词，
 * 把「只在一路出现过的文本出现在另一路」判成红线事故（见 dualpropose.mjs）。
 *
 * 两路共用的只有引擎侧事实：同一份菜单（`menuFingerprint` 比对）、同一批动作、同一份冻结判据。
 * 菜单一致而草稿不一致，差异才归因到提议者，而不是归因到「两次看到的可打面本来就不同」。
 *
 * 判据不在任何一路的可选项里（红线 1）：两路都只回答「怎么打」，「什么算打穿」由引擎写死。
 */
import { createHash } from "node:crypto";

export const PROPOSERS_VERSION = "gb-proposers-1";

/** 一路提议者的私有文本至少要这么长才算「可归因的字符串」，短词（"GET"、"200"）到处撞不算泄露 */
export const ISOLATION_MIN_TOKEN = 14;

/**
 * 与具体靶子无关的通用打法清单（A 专用）。这些句子在任何项目上都成立，
 * 所以它们出现在 B 的提示词里就意味着两路被串了。
 */
const GENERIC_SHAPES = [
  "换身份读同一类对象：先看本人能否读到，再看换成他人编号能否读到",
  "不带任何身份直接读：确认防护是缺失还是仅依赖会话",
  "在计划已声明的参数上放引擎固定载荷：观察响应是否出现数据库特征",
  "在计划已声明的文件参数上逐级回溯：观察是否回读出仓库内不该外发的文件",
];

/** B 专用：只谈「照靶子实际返回的形状换打法」，不引用任何通用清句 */
const RESPONSE_FIRST_GUIDE = [
  "上一轮返回的正文里出现了什么结构，就照那个结构换下一步：字段名、条数、错误措辞都是线索",
  "同一编号换身份后字节数变化说明归属真的参与了处理，没有变化说明这条路根本没走到归属判断",
  "正文摘录里出现数据库错误原文或文件特征字段时，优先把那一格换成同槽位的另一个候选再打一次",
];

function systemPromptFor(proposer) {
  return `${proposer.headnote}
硬性规则：
1. 每轮只报编号：动作（primitive）、目标端点（target）、身份（role）、对象（resource）。你不写 URL、不写载荷、不写请求头、不写参数值、不写判定标准——那些全部由引擎按写死的执行器生成。
2. 你看不到也改不了判据。不要下结论、不要说「有漏洞/安全」，你的产出只是一次次试打的选择。
3. 你只看得见自己这一轮的试打记录。别的提议者打过什么、看过什么，与你无关，也不在任何输入里。
4. 预算有限（请求数、轮数、时长都写死），宁少勿多；不要重复已经同样打过的那一步。
只返回一个 JSON 对象：{"primitive":2,"target":1,"role":2,"resource":1} 或 {"stop":true,"family":"这一族的英文名"}。不要输出 JSON 以外的内容。`;
}

export const PROPOSERS = [
  {
    id: "A",
    key: "shape-generic",
    label: "通用形状提议者（不看响应正文）",
    promptVersion: "gb-propose-A-1",
    seesExcerpts: false,
    headnote:
      "你在一个隔离沙箱里对一个本地靶场做攻击方式探索。你的依据只能是**通用打法形状**：靶子的具体返回内容不在你的输入里，你按下面这份与任何项目都成立的清单决定下一步试哪一格。产出供引擎落成配方草稿。",
    guide: GENERIC_SHAPES,
  },
  {
    id: "B",
    key: "target-shaped",
    label: "响应形状提议者（只看靶子真实返回）",
    promptVersion: "gb-propose-B-1",
    seesExcerpts: true,
    headnote:
      "你在一个隔离沙箱里对一个本地靶场做攻击方式探索。你的依据只能是**靶子实际返回的形状**：状态码、字节数与脱敏正文摘录都在你的输入里，你要照这些真实反应决定下一步换哪一格。你拿不到任何预先给定的通用打法清单——那一份属于另一路提议者。产出供引擎落成配方草稿。",
    guide: RESPONSE_FIRST_GUIDE,
  },
];

export function proposerById(id) {
  return PROPOSERS.find((p) => p.id === id) ?? null;
}

/** 这一路会写进提示词的全部文本：系统提示（含规则块）+ 自己的清单行 */
function textOf(proposer) {
  return [systemPromptFor(proposer), ...(proposer.guide ?? [])].join("\n");
}

/**
 * 这一路提示词文本的摘要：草稿键必须带上它——措辞改了就重新探索，
 * 旧提示词试出来的草稿不能顶着新措辞的名义复用。promptVersion 是给人看的标签，
 * 真正让缓存失效的是这份跟着文本走的摘要。
 */
export function promptDigestOf(proposer) {
  return createHash("sha256").update(textOf(proposer)).digest("hex").slice(0, 12);
}

/**
 * 这一路**独有**的文本行（隔离检查的正方）。
 * 「独有」是对照其它提议者的定义文本算出来的：共用的规则块与编号表条款本来就在两路里都出现，
 * 把它们算作私有条目会让隔离检查把正常的共享内容判成泄露——那等于每次双路都红，红线检查就成了摆设。
 */
export function privateLinesOf(proposer, all = PROPOSERS) {
  const others = all.filter((p) => p.id !== proposer.id).map((p) => textOf(p));
  const lines = textOf(proposer)
    .split("\n")
    .map((s) => s.trim())
    .filter((s) => s.length >= ISOLATION_MIN_TOKEN);
  return [...new Set(lines)].filter((l) => !others.some((o) => o.includes(l)));
}

/** 旧名保留给单测按定义回读；语义已是「整段私有条目」 */
export function privateStringsOf(proposer) {
  return privateLinesOf(proposer);
}

/**
 * 传输层错误的归类词：不看响应正文的那一路只拿到类别，拿不到原文。
 * 这不是为了省事——错误原文常带靶子返回的措辞，逐字进 A 的提示词就等于把靶子的话同时喂给两路，
 * 而两路的定义差别恰恰是「谁看得见靶子的实际反应」。状态码与字节数仍然照给。
 */
export function errorClass(err) {
  const s = String(err ?? "");
  if (!s) return null;
  if (/ECONNREFUSED|ECONNRESET|EPIPE|ENOTFOUND|EAI_AGAIN|fetch failed|socket hang/i.test(s)) return "transport_error";
  if (/timeout|ETIMEDOUT|超时/i.test(s)) return "timeout";
  if (/401|403|unauth|forbidden/i.test(s)) return "rejected";
  return "other_error";
}

/**
 * 这一路看到的观察文本。两路的差别全在这里：
 *  - A：`shapes`（自己的通用清单）+ history 只有状态码/字节数，**没有 excerpt**；
 *  - B：`observe`（照响应换打法）+ history 带 excerpt 与错误原文。
 * @param {ReturnType<typeof import("./explorer.mjs").buildMenu>} menu
 */
export function observationFor(proposer, menu, budget, state, history, renderMenu) {
  const mine = (history ?? []).map((h) => ({
    seq: h.seq,
    action: h.action,
    target: h.path,
    role: h.role,
    status: h.status,
    bytes: h.bytes,
    ...(proposer.seesExcerpts ? { excerpt: h.excerpt, error: h.error } : { error: errorClass(h.error) }),
  }));
  const base = renderMenu(menu);
  return {
    proposal: { id: proposer.id, basis: proposer.key },
    goal: "试出这一族攻击的打法（动作+槽位+身份+对象的组合），产出一张配方草稿；你不判定漏洞，也不构造请求内容",
    budget: {
      requests_used: state.requestsUsed,
      requests_left: Math.max(0, budget.maxRequests - state.requestsUsed),
      rounds_left: Math.max(0, budget.maxRounds - state.rounds),
      seconds_left: Math.max(0, Math.round((budget.totalBudgetMs - (Date.now() - state.startedAt)) / 1000)),
    },
    ...base,
    ...(proposer.seesExcerpts ? { observe: proposer.guide.map((g) => `- ${g}`) } : { shapes: proposer.guide.map((s) => `- ${s}`) }),
    history: mine,
    note: "只能报上面这些编号。载荷内容、请求头、URL 前缀、判定标准都不接受——那些由引擎按写死的执行器生成。",
  };
}

export function systemPromptOf(proposer) {
  return systemPromptFor(proposer);
}
