/**
 * 双路独立提案与对比分析（方案第 14、15 项）。
 *
 * 这一层加在探索区（第 13 项）之上，只加「看问题的方式」和「挑毛病的位置」，不加任何打法：
 * 两路用的是同一份菜单、同一批动作、同一个执行器、同一条冻结判据。
 *
 * 三条写死的边界：
 *  1. **不共享中间文本**（第 14 项）。A 一路只看菜单 + 通用形状清单 + 自己那轮的状态码与字节数
 *     （连错误原文都只给类别，见 proposers::errorClass）；B 一路只看菜单 + 自己那轮的真实响应摘录。
 *     `checkPromptIsolation` 拿每一次出站提示词逐条对账：这一路**独有的文本行**（系统提示头注、清单行）
 *     出现在另一路的提示词里 = 泄露；定义上不看正文的那一路若出现 `excerpt` 键同样算泄露。
 *     这条不是注释里的承诺，是每次都算的。
 *  2. **各自过考卷，不许共享成绩**。成绩按 `draftKey` 挂到那一路自己身上（provenance 必须逐字相等），
 *     两路任何一份没有成绩、或成绩不是自己的那次跑产的，对比结论直接落「退回」。
 *     一致性不靠自觉：判卷驱动给每次实跑打的标签里带提议者编号，标签相同就是同一份成绩，当场看得出来。
 *  3. **对比分析代理只有降级权**（红线 3）。它能说的是「这两份哪里不一致」「B 是不是 A 换皮」「建议合并」或「退回」；
 *     它写不了「通过」——`FORBIDDEN_WORDS` 里任何一个词出现在它的输出里都当表外字段丢掉，
 *     最终 `decision` 由本文件的纯函数按事实算出，模型的话只能把结论往「退回」方向压，不能往反方向推。
 *
 * 还有第 4 条容易被忽略的：草稿不同要能归因。所以 `menus_identical` 是结论的前置条件之一
 * （菜单指纹来自 explorer::menuFingerprint）——两路看到的可打面若不一样，草稿差异就是菜单差异，不是视角差异。
 */
import { SEVERITY } from "../../shared/protocol.mjs";
import { PROPOSERS, ISOLATION_MIN_TOKEN, privateLinesOf, proposerById } from "./proposers.mjs";
import { LlmError, chat, parseJson } from "./llm.mjs";
import { explorationBudget, explorationEnabled, runExploration, summarizeExploration } from "./explorer.mjs";
import { redactSecrets } from "./failureledger.mjs";

export const DUAL_VERSION = "gb-dual-1";
export const COMPARATOR_VERSION = "gb-compare-1";

/** 对比代理只能出的两个结论（红线 3：没有第三种，也没有「通过」） */
export const COMPARATOR_DECISIONS = ["merge_suggestion", "return"];
export const COMPARATOR_DECISION_LABEL = { merge_suggestion: "建议合并（仍需人工终审）", return: "退回" };

/** 这些词出现在对比代理的输出里一律按表外字段丢弃——它没有放行权 */
export const FORBIDDEN_WORDS = ["通过", "pass", "passed", "approve", "approved", "accept", "注册", "register", "放行", "批准", "conclusive"];

/** 对比代理能写的键 */
const ALLOWED_OPINION_KEYS = new Set(["divergences", "b_is_reskin", "recommendation", "why"]);

export function proposersRequested(ctx) {
  const list = ctx?.targetConfig?.exploration?.proposers ?? null;
  if (!Array.isArray(list)) return [];
  const ids = [...new Set(list.map((x) => String(x ?? "").trim().toUpperCase()).filter((x) => proposerById(x)))];
  return ids;
}

/**
 * 双路的启用条件：先过探索区那两道闸（契约 enabled **且** 环境变量，gate/纯黑盒结构性不进），
 * 再要求契约显式点名两条互不相同的提议者。默认不开——单路行为逐字保持第 13 项的样子。
 */
export function dualEnabled(ctx) {
  if (!explorationEnabled(ctx)) return false;
  return proposersRequested(ctx).length >= 2;
}

/**
 * 出站提示词账本 → 泄露清单。比对的是「这一路独有的文本行」（见 proposers::privateLinesOf）：
 *  - 一路独有的清单行/头注出现在别路的任何出站提示词里 = 串了；
 *  - 定义上「不看响应正文」的那一路，提示词里出现 `excerpt` 或 `observe` 键 = 串了（响应正文只进 B）。
 * 不做「逐行取交集」那种朴素比对：菜单、编号表、共用规则块本来就同时出现在两路里，
 * 那是引擎侧共享事实（正由 `menusIdentical` 单独钉住），把它们判成泄露会让每次双路都红。
 */
export function checkPromptIsolation(prompts, { proposers = PROPOSERS } = {}) {
  const byProposal = new Map();
  for (const p of prompts ?? []) {
    if (!byProposal.has(p.proposal)) byProposal.set(p.proposal, []);
    byProposal.get(p.proposal).push(`${p.system ?? ""}\n${p.user ?? ""}`);
  }
  const leaked = [];
  const checks = [];
  let privates = 0;
  for (const [own, blobs] of byProposal) {
    const self = proposers.find((p) => p.id === own);
    const lines = self ? privateLinesOf(self, proposers) : [];
    privates += lines.length;
    for (const [other, otherBlobs] of byProposal) {
      if (other === own) continue;
      for (const line of lines) {
        if (!otherBlobs.some((b) => b.includes(line))) continue;
        leaked.push({ from: own, to: other, kind: "private_text", token: line.slice(0, ISOLATION_MIN_TOKEN * 3) });
        if (leaked.length >= 12) return { ok: false, checked: privates, checks, leaked, truncated: true };
      }
    }
  }
  for (const [id, blobs] of byProposal) {
    const self = proposers.find((p) => p.id === id);
    if (!self || self.seesExcerpts) continue;
    const hit = blobs.some((b) => /"(excerpt|observe)"\s*:/.test(b));
    checks.push({ check: `no_response_text_in:${id}`, ok: !hit });
    if (hit) leaked.push({ from: id, to: id, kind: "response_text_present", token: "excerpt" });
  }
  return { ok: leaked.length === 0, checked: privates, checks, leaked };
}

/** 一步的「打法身份」：编号、族名、备注全不算，只有实际会发出去的形状算 */
export function stepKey(step) {
  return [
    String(step?.action ?? "-"),
    String(step?.path ?? "-"),
    String(step?.identity ?? "-"),
    String(step?.method ?? "-"),
    String(step?.param ?? "-"),
    String(step?.payloadSet ?? "-"),
    String(step?.canary ?? "-"),
  ].join("|");
}

function multiset(steps) {
  const m = new Map();
  for (const s of steps ?? []) m.set(stepKey(s), (m.get(stepKey(s)) ?? 0) + 1);
  return m;
}

/**
 * 两份草稿的结构差异（确定性代码算，不交给模型）：共用了哪些打法、各自多了哪些、B 是不是 A 换皮。
 * `reskin` = 逐步比对后打法集合完全相同，只是族名/措辞不同——那正是「两个提议者其实是同一个」的形状。
 */
export function structuralDiff(draftA, draftB) {
  const stepsA = draftA?.recipe?.steps ?? [];
  const stepsB = draftB?.recipe?.steps ?? [];
  const mA = multiset(stepsA);
  const mB = multiset(stepsB);
  const shared = [];
  const onlyA = [];
  const onlyB = [];
  for (const [k, n] of mA) {
    const inB = mB.get(k) ?? 0;
    if (inB > 0) shared.push({ shape: k, times: Math.min(n, inB) });
    if (n > inB) onlyA.push({ shape: k, times: n - inB });
  }
  for (const [k, n] of mB) if (!mA.has(k)) onlyB.push({ shape: k, times: n });
  const identical = onlyA.length === 0 && onlyB.length === 0;
  const familyA = draftA?.family ?? null;
  const familyB = draftB?.family ?? null;
  const divergences = [];
  if (identical) divergences.push({ kind: "reskin", text: "两路草稿的打法集合逐条相同，只是名字或措辞不同——B 是 A 的换皮" });
  for (const s of onlyA) divergences.push({ kind: "only_a", text: `A 独有打法：${s.shape}（${s.times} 条）` });
  for (const s of onlyB) divergences.push({ kind: "only_b", text: `B 独有打法：${s.shape}（${s.times} 条）` });
  if (familyA !== familyB) divergences.push({ kind: "family", text: `两路自报的族名不同：${familyA ?? "未给"} vs ${familyB ?? "未给"}` });
  return {
    identical,
    reskin: identical,
    shared,
    onlyA,
    onlyB,
    familyA,
    familyB,
    stepsA: stepsA.length,
    stepsB: stepsB.length,
    divergences,
  };
}

function evidenceOf(summary) {
  const trace = summary?.trace ?? [];
  return {
    draftKey: summary?.draftKey ?? null,
    requestsUsed: summary?.requestsUsed ?? 0,
    modelCalls: summary?.modelCalls ?? 0,
    outcome: summary?.outcome ?? null,
    // 证据只到「哪一步实发、拿到什么状态码与字节数」这一层：正文摘录本来也不进报告（红线 6）
    requests: trace.map((t) => ({ seq: t.seq, action: t.action, slot: t.slot, role: t.role, path: t.path, status: t.status, bytes: t.bytes, ok: t.ok })),
    okRequests: trace.filter((t) => t.ok).length,
    rejectedChoices: (summary?.rejectedChoices ?? []).length,
    ignoredFields: summary?.ignoredFields ?? [],
    artifact: summary?.artifact ?? null,
  };
}

function emit(ctx, data, message, severity = SEVERITY.INFO) {
  ctx?.emit?.({ kind: "exploration", severity, message, phase: ctx.state ?? "pre", data });
}

/**
 * 跑双路。两路各拿一份**独立预算**（同一套硬上限夹着），顺序跑：A 完成才开始 B，
 * 但两路之间不传任何文本——A 的 trace / excerpt / 草稿都不进 B 的提示词（下面用账本验证这件事）。
 * @param {object} p
 * @param {(plan:object)=>Promise<object>} p.sendStep 执行器（同第 13 项）
 * @param {typeof chat} [p.chatImpl]
 */
export async function runDualProposals(ctx, { baseUrl, sendStep, stash = null, getToken = null, model = null, chatImpl = chat, budget = null, proposers = null } = {}) {
  const ids = (proposers ?? proposersRequested(ctx)).map((id) => proposerById(id)).filter(Boolean);
  const b = budget ?? explorationBudget(ctx);
  const out = {
    version: DUAL_VERSION,
    enabled: true,
    model: model ?? null,
    outcome: "not_run",
    budget: b,
    proposals: [],
    prompts: [],
    isolation: null,
    menusIdentical: false,
    diff: null,
    evidence: null,
    startedAt: Date.now(),
    durationMs: 0,
    modelCalls: 0,
    requestsUsed: 0,
  };
  if (ids.length < 2) {
    out.outcome = "not_run";
    out.error = "需要至少两条互不相同的提议者（契约 exploration.proposers 给两个编号）";
    return out;
  }
  const sink = (rec) => out.prompts.push(rec);
  for (const proposer of ids) {
    emit(ctx, { action: "proposal", subject: `提议者 ${proposer.id}`, ok: true }, `探索区双路开始：提议者 ${proposer.id}（${proposer.label}），依据=${proposer.seesExcerpts ? "靶子真实响应形状" : "通用打法形状"}`);
    const state = await runExploration(ctx, {
      baseUrl,
      sendStep,
      stash,
      getToken,
      model,
      chatImpl,
      budget: { ...b },
      proposer,
      promptSink: sink,
    });
    const summary = summarizeExploration(state);
    summary.draftKey = state.draftKey;
    summary.menuFingerprint = state.menuFingerprint;
    out.proposals.push({ id: proposer.id, promptVersion: proposer.promptVersion, summary, evidence: evidenceOf(summary) });
    out.modelCalls += summary.modelCalls ?? 0;
    out.requestsUsed += summary.requestsUsed ?? 0;
  }
  const fingerprints = new Set(out.proposals.map((p) => p.summary.menuFingerprint));
  out.menusIdentical = fingerprints.size === 1;
  out.isolation = checkPromptIsolation(out.prompts);
  const [a, bb] = out.proposals;
  out.diff = structuralDiff(a?.summary?.draft, bb?.summary?.draft);
  out.draftsDiffer = out.diff.identical === false && (!!a?.summary?.draft || !!bb?.summary?.draft);
  out.outcome = out.proposals.every((p) => p.summary.outcome === "not_run") ? "not_run" : "ran";
  out.durationMs = Date.now() - out.startedAt;
  emit(
    ctx,
    { action: "dual", subject: `A=${a?.summary?.draft?.steps ?? 0} 步 / B=${bb?.summary?.draft?.steps ?? 0} 步`, ok: out.menusIdentical && out.isolation.ok },
    `探索区双路完成：${out.requestsUsed} 次实发 / ${out.modelCalls} 次模型调用（两路各一份预算）；菜单${out.menusIdentical ? "一致" : "不一致（差异不可归因到提议者）"}；提示词隔离${
      out.isolation.ok ? "通过" : `失败（${out.isolation.leaked.length} 处跨路文本）`
    }；草稿${out.draftsDiffer ? "确有差异" : "无差异（B 是 A 换皮）"}`,
    out.isolation.ok && out.menusIdentical ? SEVERITY.INFO : SEVERITY.WARN
  );
  return out;
}

const COMPARATOR_SYSTEM = `你是攻击配方草稿的**对比分析员**。你手上只有两份草稿（A 与 B，两名提议者各自独立试打出来的）和它们各自的引擎侧事实。
硬性规则：
1. 你**不判定漏洞**、不修改判据、不决定注册与否，也不写任何「通过/批准/放行」的意思——那些不归你。
2. 你只做三件事：指出两份草稿在哪里一致、在哪里分歧、B 是不是只是 A 换了层皮（打法集合相同、只有名字或措辞变了）。
3. 你的输出只能落进两个格子：{"recommendation":"merge"}（建议合并，仍需人工终审）或 {"recommendation":"return"}（退回）。你可以说「退回」，说「建议合并」也不等于放行。
4. 依据只有下面给你的事实与两份草稿本身。不要引用任何你没有收到的文本。
只返回一个 JSON 对象：{"divergences":["……"],"b_is_reskin":true,"recommendation":"return","why":"……"}。不要输出 JSON 以外的内容。`;

function comparatorPrompt(dual) {
  const brief = (p) => ({
    proposal: p.id,
    basis: p.summary.proposal?.basis ?? null,
    outcome: p.summary.outcome,
    requests_used: p.summary.requestsUsed,
    draft: p.summary.draft
      ? { family: p.summary.draft.family, steps: p.summary.draft.steps, table_ok: p.summary.draft.tableOk, verdict_rule: p.summary.draft.verdictRule, shapes: (p.summary.draft.recipe?.steps ?? []).map(stepKey) }
      : null,
    grades: p.grades ?? "（还没有成绩）",
  });
  return JSON.stringify(
    {
      task: "对比两份独立产出的攻击配方草稿，只出「建议合并」或「退回」",
      engine_facts: {
        menus_identical: dual.menusIdentical,
        prompt_isolation_ok: dual.isolation?.ok ?? null,
        structural_diff: { identical: dual.diff?.identical, only_a: dual.diff?.onlyA ?? [], only_b: dual.diff?.onlyB ?? [], divergences: (dual.diff?.divergences ?? []).map((d) => d.text) },
        note: "上面这些是确定性代码算出来的，你改不了；你的意见只作为分歧说明，最终结论由代码按事实落。",
      },
      proposals: [brief(dual.proposals[0]), brief(dual.proposals[1])],
    },
    null,
    1
  );
}

/** 收对比代理的输出：表外键与「通过」类措辞当场丢弃，只留下名字进审计（红线 6：原文不回显） */
export function validateComparatorOpinion(raw) {
  const ignored = [];
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return { ok: false, rejected: "对比意见必须是 JSON 对象", ignored };
  for (const k of Object.keys(raw)) if (!ALLOWED_OPINION_KEYS.has(k)) ignored.push(k);
  const rec = String(raw.recommendation ?? "").trim().toLowerCase();
  if (FORBIDDEN_WORDS.some((w) => rec.includes(w.toLowerCase()))) {
    return { ok: false, rejected: `对比代理写了它无权表达的状态：${JSON.stringify(String(raw.recommendation).slice(0, 40))}（只能出 merge 或 return）`, ignored: [...ignored, "recommendation(非法取值)"] };
  }
  let recommendation = null;
  if (rec === "merge" || rec === "merge_suggestion" || rec === "建议合并") recommendation = "merge_suggestion";
  else if (rec === "return" || rec === "退回") recommendation = "return";
  else return { ok: false, rejected: `recommendation 取值非法：${JSON.stringify(String(raw.recommendation).slice(0, 40))}（可用：merge / return）`, ignored };
  const divergences = Array.isArray(raw.divergences) ? raw.divergences.slice(0, 12).map((d) => String(d ?? "").slice(0, 240)).filter(Boolean) : [];
  return {
    ok: true,
    recommendation,
    bIsReskin: raw.b_is_reskin === true,
    why: String(raw.why ?? "").slice(0, 400),
    divergences,
    ignored,
  };
}

/**
 * 引擎侧结论（纯函数，判卷驱动和单测都调它）。模型的话**只能往「退回」压**：
 * 它说退回就一定退回；它说合并，仍要事实全部成立才落「建议合并（仍需人工终审）」。
 * 任何一条事实不成立就落「退回」，并把不成立的那条写进 reasons——这里永远没有「通过」这个出口。
 */
export function decideComparison(dual, { opinion = null, grades = null } = {}) {
  const reasons = [];
  const facts = [];
  const list = dual?.proposals ?? [];
  const [a, bb] = list;

  const push = (name, ok, whyNot) => {
    facts.push({ fact: name, ok });
    if (!ok) reasons.push(whyNot);
    return ok;
  };

  push("两路都真的跑过", list.length >= 2 && list.every((p) => p.summary?.outcome !== "not_run"), "双路没有都产出试打记录：对比没有依据");
  push("菜单一致（差异可归因到提议者）", dual?.menusIdentical === true, "两路看到的菜单指纹不同——草稿差异可能来自可打面本身，不能算作视角多样性");
  push("提示词隔离通过", dual?.isolation?.ok === true, `提示词隔离失败：${(dual?.isolation?.leaked ?? []).slice(0, 3).map((l) => `${l.from}→${l.to}`).join("、")}（两路共享了中间文本，第 14 项的前提被破坏）`);

  const draftOkA = !!a?.summary?.draft?.tableOk;
  const draftOkB = !!bb?.summary?.draft?.tableOk;
  push("A 草稿存在且过动作表", draftOkA, `A 的草稿${a?.summary?.draft ? "被动作表拒收" : "没有产出"}：草稿本身不成立，无从合并`);
  push("B 草稿存在且过动作表", draftOkB, `B 的草稿${bb?.summary?.draft ? "被动作表拒收" : "没有产出"}：草稿本身不成立，无从合并`);
  push("两份草稿确有差异", dual?.draftsDiffer === true, dual?.diff?.identical ? "两路草稿的打法集合逐条相同（B 是 A 换皮）——双路没有带来多样性" : "两路都没有可用草稿");

  // 「各自过考卷，不许共享成绩」：成绩必须存在、必须挂在这一路自己的 draftKey 上、必须显示过卷、两次跑的标签必须不同。
  // 成绩由判卷器的 `--draft` 模式落盘（红线 4：扫描这一侧只读不写），读不到就是「没有成绩」→ 退回。
  const gA = grades?.[a?.id] ?? a?.grades?.[a?.id] ?? null;
  const gB = grades?.[bb?.id] ?? bb?.grades?.[bb?.id] ?? null;
  const ownGrade = (p, g) => {
    if (!p) return [false, "这一路不存在"];
    if (!g || g.present === false) {
      return [false, `提议者 ${p.id} 没有自己的考卷成绩${g?.whyNot ? `（${String(g.whyNot).slice(0, 120)}）` : ""}：草稿未判卷（第 6 项的闸要跑过三份变体），不许借另一路的成绩`];
    }
    if (g.provenance !== p.summary?.draftKey) return [false, `提议者 ${p.id} 的成绩 provenance 与它自己的草稿键不一致——成绩不是它那次跑产的`];
    return [true, ""];
  };
  const showsPass = (p, g) => {
    if (!g || g.present === false) return [false, `提议者 ${p.id} 没有成绩，谈不上过卷`];
    if (g.pass !== true) return [false, `提议者 ${p.id} 的成绩没过卷：${String(g.whyNot ?? "四道闸未全过").slice(0, 160)}`];
    return [true, ""];
  };
  const [okA, whyA] = ownGrade(a, gA);
  const [okB, whyB] = ownGrade(bb, gB);
  push("A 有自己的成绩", okA, whyA);
  push("B 有自己的成绩", okB, whyB);
  push("A 的成绩显示过卷", okA && showsPass(a, gA)[0], showsPass(a, gA)[1]);
  push("B 的成绩显示过卷", okB && showsPass(bb, gB)[0], showsPass(bb, gB)[1]);
  if (okA && okB) push("两份成绩来自两次独立实跑", (gA.runLabel ?? null) !== (gB.runLabel ?? null) && !!gA.runLabel && !!gB.runLabel, "两份成绩的实跑标签相同或缺失：那是同一次跑的成绩被共享了");

  // 「建议合并」这个格子只能由对比代理自己填出来：它缺席或写得越界时，引擎不替它做决定。
  push("拿到合法的对比意见", opinion?.ok === true, `没有合法的对比意见（${String(opinion?.rejected ?? "未调用对比代理").slice(0, 80)}）：宁可退回，也不替没说话的一方写「建议合并」`);

  const modelReturn = opinion?.ok === true && opinion.recommendation === "return";
  const modelMerge = opinion?.ok === true && opinion.recommendation === "merge_suggestion";
  const allFactsOk = facts.every((f) => f.ok);
  const decision = modelReturn || !allFactsOk ? "return" : "merge_suggestion";
  const downgraded = modelMerge && decision === "return";

  return {
    version: COMPARATOR_VERSION,
    decidedBy: "engine",
    authority: "对比分析代理只有降级权：它能强制退回，不能给出通过",
    decision,
    decisionLabel: COMPARATOR_DECISION_LABEL[decision],
    registered: false,
    canWritePassField: false,
    reasons,
    facts,
    downgraded_model_merge: downgraded,
    model: opinion
      ? { ok: opinion.ok === true, recommendation: opinion.recommendation ?? null, rejected: opinion.rejected ?? null, ignoredFields: opinion.ignored ?? [], why: opinion.why ?? null, divergences: opinion.divergences ?? [], bIsReskin: opinion.bIsReskin ?? null }
      : { ok: false, recommendation: null, rejected: "没有拿到对比意见（模型不可用或未启用）", ignoredFields: [] },
  };
}

/**
 * 调一次对比代理，再落引擎结论。
 * 模型异常不阻断结论：事实不成立本来就是「退回」，模型缺席只是少了一份分歧说明。
 */
export async function runComparator(ctx, { dual, grades = null, chatImpl = chat, model = null, getToken = null, onOpinion = null } = {}) {
  let res;
  try {
    res = await chatImpl(ctx, {
      systemPrompt: COMPARATOR_SYSTEM,
      userPrompt: comparatorPrompt(dual),
      getToken: getToken ?? ctx?.llmGetToken,
      model,
      maxTokens: 800,
      purpose: "对比两份配方草稿",
    });
  } catch (e) {
    const why = e instanceof LlmError ? `对比代理不可用：${redactSecrets(String(e.message)).slice(0, 200)}` : `对比代理异常：${redactSecrets(String(e?.message ?? e)).slice(0, 200)}`;
    emit(ctx, { action: "compare", subject: "对比代理不可用", ok: false, note: why }, `对比分析未完成，按事实直接落结论：${why}`, SEVERITY.WARN);
    return decideComparison(dual, { opinion: { ok: false, rejected: why, ignored: [] }, grades });
  }
  let opinion;
  try {
    opinion = validateComparatorOpinion(parseJson(res.content));
  } catch (e) {
    opinion = { ok: false, rejected: redactSecrets(String(e?.message ?? e)).slice(0, 200), ignored: [] };
  }
  if (onOpinion) onOpinion(opinion);
  emit(
    ctx,
    { action: "compare", subject: opinion.ok ? `模型意见=${opinion.recommendation}` : "模型意见被拒", ok: opinion.ok === true, note: opinion.ok ? null : opinion.rejected },
    opinion.ok
      ? `对比代理意见：${opinion.recommendation === "return" ? "退回" : "建议合并"}（${(opinion.divergences ?? []).length} 条分歧说明）${opinion.ignored?.length ? `；表外字段已丢弃：${opinion.ignored.join("、")}` : ""}`
      : `对比代理的输出不被接受：${opinion.rejected}${opinion.ignored?.length ? `（表外字段：${opinion.ignored.join("、")}）` : ""}`,
    opinion.ok ? SEVERITY.INFO : SEVERITY.WARN
  );
  return decideComparison(dual, { opinion, grades });
}

/** 视图压缩摘要：不带模型原文，只带引擎侧事实（与第 13 项同一口径） */
export function summarizeDual(dual, comparison = null) {
  if (!dual) return null;
  return {
    version: dual.version ?? DUAL_VERSION,
    outcome: dual.outcome ?? null,
    model: dual.model ?? null,
    budget: dual.budget ?? null,
    menusIdentical: dual.menusIdentical ?? null,
    isolation: dual.isolation
      ? {
          ok: dual.isolation.ok,
          checked: dual.isolation.checked ?? 0,
          checks: dual.isolation.checks ?? [],
          leaked: (dual.isolation.leaked ?? []).map((l) => ({ from: l.from, to: l.to, kind: l.kind ?? "private_text", token: String(l.token ?? "").slice(0, 80) })),
          truncated: dual.isolation.truncated === true,
        }
      : null,
    draftsDiffer: dual.draftsDiffer ?? null,
    diff: dual.diff
      ? {
          identical: dual.diff.identical,
          reskin: dual.diff.reskin,
          shared: dual.diff.shared?.length ?? 0,
          onlyA: dual.diff.onlyA ?? [],
          onlyB: dual.diff.onlyB ?? [],
          familyA: dual.diff.familyA,
          familyB: dual.diff.familyB,
          divergences: (dual.diff.divergences ?? []).map((d) => d.text),
        }
      : null,
    totals: { modelCalls: dual.modelCalls ?? 0, requestsUsed: dual.requestsUsed ?? 0, durationMs: dual.durationMs ?? null },
    proposals: (dual.proposals ?? []).map((p) => ({
      id: p.id,
      promptVersion: p.promptVersion ?? null,
      basis: p.summary?.proposal?.basis ?? null,
      outcome: p.summary?.outcome ?? null,
      requestsUsed: p.summary?.requestsUsed ?? 0,
      modelCalls: p.summary?.modelCalls ?? 0,
      menuFingerprint: p.summary?.menuFingerprint ?? null,
      draftKey: p.summary?.draftKey ?? null,
      draft: p.summary?.draft
        ? { family: p.summary.draft.family, steps: p.summary.draft.steps, tableOk: p.summary.draft.tableOk, verdictRule: p.summary.draft.verdictRule, verdictByEngine: p.summary.draft.verdictByEngine, registered: p.summary.draft.registered, rejections: p.summary.draft.rejections }
        : null,
      evidence: p.evidence ?? null,
      grades: p.grades ?? null,
    })),
    comparison,
  };
}
