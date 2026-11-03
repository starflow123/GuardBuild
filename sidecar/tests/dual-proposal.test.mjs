/**
 * 双路独立提案与对比分析（方案第 14、15 项）单测。
 *
 * 这一层要守的东西只有三件，测试就按这三件写：
 *  1. 两路**不共享中间文本**：A 独有的清句不进 B 的提示词，反过来也一样，A 连响应正文的键都看不到。
 *     而且这条检查不能被「本来就共享的菜单」搞成常态红——把共享内容判成泄露等于检查作废。
 *  2. **各自过考卷，不许共享成绩**：成绩必须挂在这一路自己的草稿键上，两次实跑的标签必须不同。
 *  3. **对比代理只有降级权**（红线 3）：它说退回一定退回；它写「通过」一类措辞当场被拒；
 *     最终结论由引擎按事实算，代码里根本没有「通过」这个出口。
 */
import test from "node:test";
import assert from "node:assert/strict";
import { EXPLORATION_DEFAULTS, buildMenu, draftKeyFor, menuFingerprint, runExploration } from "../lib/explorer.mjs";
import {
  COMPARATOR_DECISIONS,
  FORBIDDEN_WORDS,
  checkPromptIsolation,
  decideComparison,
  dualEnabled,
  runComparator,
  runDualProposals,
  stepKey,
  structuralDiff,
  summarizeDual,
  validateComparatorOpinion,
} from "../lib/dualpropose.mjs";
import { PROPOSERS, errorClass, observationFor, privateLinesOf, promptDigestOf, proposerById, systemPromptOf } from "../lib/proposers.mjs";
import { createHash } from "node:crypto";
import { normalizeExploration } from "../lib/targetconfig.mjs";
import { LlmError } from "../lib/llm.mjs";
import { buildReport } from "../lib/report.mjs";

const A = proposerById("A");
const B = proposerById("B");

/** 一份「修复前取证快照」，与 explorer.test.mjs 的夹具同形状 */
function stash(over = {}) {
  return {
    baseUrl: "http://127.0.0.1:4111",
    loggedIn: true,
    targets: { attacker: { name: "gb-attacker" }, victim: { name: "gb-victim" }, admin: { name: "gb-admin" } },
    byUser: { "gb-victim": [{ id: 7 }], "gb-attacker": [{ id: 8 }] },
    candidates: {
      readPath: [
        { fullPath: "/api/orders/:id", method: "GET", read: { source: "plan" } },
        { fullPath: "/api/orders", method: "GET", read: { source: "plan" } },
      ],
      unauthReadPath: [{ fullPath: "/api/reports", method: "GET", unauthRead: { source: "plan" }, queryParam: { param: "id" } }],
      sqliPath: [{ fullPath: "/api/search", method: "GET", sqli: { param: "q", source: "plan" } }],
      traversalPath: [{ fullPath: "/api/file", method: "GET", traversal: { param: "name", source: "plan" } }],
    },
    resources: [
      { id: "7", owner: "gb-victim" },
      { id: "8", owner: "gb-attacker" },
    ],
    ...over,
  };
}

function fakeCtx(over = {}) {
  return { emit: () => {}, view: {}, projectRoot: null, state: "pre", ...over };
}

function okStep(over = {}) {
  return { ok: true, method: "GET", path: "/api/orders", status: 200, bytes: 42, excerpt: '{"items":[{"id":7,"owner":"gb-victim"}]}', error: null, ...over };
}

/** 按提议者分别脚本化的假模型：purpose 里带编号，两路的脚本互不影响 */
function perProposerChat(scripts) {
  const calls = [];
  const seen = { A: 0, B: 0, single: 0 };
  const chatImpl = async (c, req) => {
    calls.push(req);
    const m = /提议者 ([AB])/.exec(req.purpose ?? "");
    const who = m ? m[1] : "single";
    const list = scripts[who] ?? [{ stop: true }];
    const i = seen[who]++;
    const content = i < list.length ? list[i] : { stop: true };
    return { model: "fake-dual", content: typeof content === "string" ? content : JSON.stringify(content) };
  };
  return { chatImpl, calls };
}

/** 同步的双路夹具：decideComparison 是纯函数，不需要真跑就能构造 */
function dualFixture({ tableOk = true, draftsDiffer = true, menusIdentical = true, isolationOk = true } = {}) {
  const stepsA = [{ id: "exp-1", action: "request.anonymous", path: "{slot:readPath}", method: "GET" }];
  const stepsB = draftsDiffer
    ? [{ id: "exp-1", action: "payload.inject", path: "{slot:sqliPath}", param: "{plan.param}", payloadSet: "sqli-default", identity: "attacker" }]
    : stepsA;
  const mk = (id, family, steps) => ({
    id,
    promptVersion: `gb-propose-${id}-1`,
    summary: {
      outcome: "stopped",
      proposal: { id, basis: id === "A" ? "generic_shapes" : "target_response" },
      requestsUsed: 1,
      rounds: 1,
      modelCalls: 2,
      menuFingerprint: "same-menu",
      draftKey: `${id}-k1`,
      draft: { family, steps: steps.length, tableOk, recipe: { steps }, verdictRule: "attack-repro", verdictByEngine: true, registered: false },
      trace: [{ seq: 1, action: steps[0].action, slot: "readPath", role: "victim", path: "/api/x", status: 200, bytes: 4, ok: true }],
    },
    evidence: {
      draftKey: `${id}-k1`,
      requests: [{ seq: 1, action: steps[0].action, slot: "readPath", role: "victim", path: "/api/x", status: 200, bytes: 4, ok: true }],
      okRequests: 1,
      rejectedChoices: 0,
      ignoredFields: [],
      artifact: null,
    },
  });
  const proposals = [mk("A", "family-a", stepsA), mk("B", "family-b", stepsB)];
  const diff = structuralDiff(proposals[0].summary.draft, proposals[1].summary.draft);
  return {
    proposals,
    menusIdentical,
    isolation: { ok: isolationOk, checked: 6, checks: [], leaked: isolationOk ? [] : [{ from: "B", to: "A", kind: "private_text", token: "跨路的那一行" }] },
    diff,
    draftsDiffer: diff.identical === false,
    modelCalls: 4,
    requestsUsed: 2,
    budget: EXPLORATION_DEFAULTS,
    outcome: "ran",
  };
}

const ownGrades = () => ({ A: { provenance: "A-k1", runLabel: "dual--A--1" }, B: { provenance: "B-k1", runLabel: "dual--B--1" } });

// ---------- 启用条件：三闸而不是一闸 ----------

test("dualEnabled：探索区双闸之外还要契约点名两条不同提议者，gate 与纯黑盒一律不进", () => {
  const prev = process.env.GUARDBUILD_LLM_EXPLORATION;
  process.env.GUARDBUILD_LLM_EXPLORATION = "1";
  try {
    const on = { targetConfig: { exploration: { enabled: true, proposers: ["A", "B"] } } };
    assert.equal(dualEnabled(on), true, "双闸 + 点名两条 = 开");
    assert.equal(dualEnabled({ targetConfig: { exploration: { enabled: true } } }), false, "没点名就是第 13 项那条单路");
    assert.equal(dualEnabled({ targetConfig: { exploration: { enabled: true, proposers: ["A"] } } }), false, "只点一条不算双路");
    assert.equal(dualEnabled({ targetConfig: { exploration: { enabled: true, proposers: ["A", "A"] } } }), false, "重复编号去重后不足两条");
    assert.equal(dualEnabled({ targetConfig: { exploration: { enabled: true, proposers: ["A", "Z"] } } }), false, "未知编号不当第二条");
    assert.equal(dualEnabled({ ...on, gate: true }), false, "gate/CI 结构性禁用：这一路不调用模型");
    assert.equal(dualEnabled({ ...on, blackboxUrl: "https://third-party.test" }), false, "纯黑盒不经过这一路");
  } finally {
    if (prev === undefined) delete process.env.GUARDBUILD_LLM_EXPLORATION;
    else process.env.GUARDBUILD_LLM_EXPLORATION = prev;
  }
});

test("契约里的 proposers 只认 A/B，去重后不足两条就当没写（单路行为逐字不变）", () => {
  assert.deepEqual(normalizeExploration({ enabled: true, proposers: ["a", "b"] }).proposers, ["A", "B"]);
  assert.equal(normalizeExploration({ enabled: true, proposers: ["A", "C"] }).proposers, undefined);
  assert.equal(normalizeExploration({ enabled: true, proposers: ["B", "B"] }).proposers, undefined);
  assert.equal(normalizeExploration({ enabled: true }).proposers, undefined);
});

// ---------- 提议者定义：两路的依据确实不同 ----------

test("A/B 的独有文本互不相交，共用的规则块不算私有条目", () => {
  assert.equal(PROPOSERS.length, 2);
  const pa = privateLinesOf(A);
  const pb = privateLinesOf(B);
  assert.ok(pa.length >= 3 && pb.length >= 3, "每一路都要有可核对的独有文本");
  for (const l of pa) assert.ok(!pb.includes(l), `私有条目不该同时出现在两路的定义里：${l.slice(0, 30)}`);
  assert.ok(pa.some((l) => l.includes("通用打法形状")), "A 的独有文本要说清自己的依据");
  assert.ok(pb.some((l) => l.includes("靶子实际返回的形状")), "B 的独有文本要说清自己的依据");
  assert.ok(!pa.some((l) => l.includes("每轮只报编号")), "两路共用的编号条款不该被当成私有文本");
  assert.match(systemPromptOf(A), /你只看得见自己这一轮的试打记录/, "两路都被明确告知：别的路与它无关");
});

test("A 看不见响应正文：没有 excerpt 键，错误只给类别；B 看得见；菜单两份完全相同", () => {
  const menu = buildMenu(stash());
  const render = (m) => ({ targets: m.targets.items.map((t) => t.path), actions: m.primitives.map((p) => p.action), roles: m.roles.items.map((r) => r.role), resources: m.resources.items.map((r) => r.resourceId) });
  const hist = [{ seq: 1, action: "request.as", path: "/api/orders", role: "victim", status: 200, bytes: 42, excerpt: "SECRET-BODY-abcdef", error: "connect ECONNREFUSED 127.0.0.1:4111" }];
  const state = { requestsUsed: 1, rounds: 1, startedAt: Date.now() };

  const obsA = observationFor(A, menu, EXPLORATION_DEFAULTS, state, hist, render);
  const textA = JSON.stringify(obsA);
  assert.ok(!textA.includes("excerpt"), "A 的提示词里不该出现 excerpt 这个键");
  assert.ok(!textA.includes("SECRET-BODY"), "靶子正文不进 A");
  assert.ok(!textA.includes("ECONNREFUSED"), "错误原文也不进 A");
  assert.ok(textA.includes("transport_error"), "A 只拿到错误类别");
  assert.ok(Array.isArray(obsA.shapes) && obsA.shapes.length, "A 拿的是通用清单");
  assert.equal(obsA.observe, undefined, "A 拿不到那份照响应换打法的指引");

  const obsB = observationFor(B, menu, EXPLORATION_DEFAULTS, state, [{ ...hist[0], excerpt: "BODY-abcdef", error: null }], render);
  assert.ok(JSON.stringify(obsB).includes("BODY-abcdef"), "B 看得见真实响应摘录");
  assert.ok(Array.isArray(obsB.observe) && obsB.shapes === undefined, "B 拿的是响应形状指引，不是通用清单");
  assert.deepEqual(obsA.targets, obsB.targets, "菜单是两路共享的引擎事实");
  assert.notEqual(obsA.proposal.basis, obsB.proposal.basis, "两路各自的依据要写在观察里，事后能分辨");
});

test("errorClass：只给类别不给原文，且类别词短到不会触发泄露阈值", () => {
  assert.equal(errorClass("connect ECONNREFUSED 127.0.0.1:4111"), "transport_error");
  assert.equal(errorClass("request timeout after 30s"), "timeout");
  assert.equal(errorClass("403 Forbidden"), "rejected");
  assert.equal(errorClass("别的措辞"), "other_error");
  assert.equal(errorClass(null), null);
  for (const v of ["transport_error", "timeout", "rejected", "other_error"]) {
    assert.ok(!privateLinesOf(A).includes(v) && !privateLinesOf(B).includes(v), `${v} 是引擎给的类别，不是任何一路的独有文本`);
  }
});

// ---------- 隔离检查：既抓泄露，也不把共享菜单判成泄露 ----------

test("提示词隔离：共享菜单不算泄露，跨路的独有文本算泄露", () => {
  const sharedLine = '"path": "/api/orders/:id", "method": "GET", "plan_slot": "readPath", "declared_param": null';
  const clean = [
    { proposal: "A", round: 1, system: systemPromptOf(A), user: `{${sharedLine},"shapes":["- ${A.guide[0]}"]}` },
    { proposal: "B", round: 1, system: systemPromptOf(B), user: `{${sharedLine},"observe":["- ${B.guide[0]}"]}` },
  ];
  const okRes = checkPromptIsolation(clean);
  assert.equal(okRes.ok, true, `共享内容不该被判泄露：${JSON.stringify(okRes.leaked)}`);
  assert.equal(okRes.leaked.length, 0);
  assert.ok(okRes.checked >= 2, "要有实际比对条数，不能空转");

  const crossed = [
    { proposal: "A", round: 1, system: systemPromptOf(A), user: `{${sharedLine},"x":"${B.guide[1]}"}` },
    { proposal: "B", round: 1, system: systemPromptOf(B), user: `{${sharedLine}}` },
  ];
  const bad = checkPromptIsolation(crossed);
  assert.equal(bad.ok, false, "B 独有的清句出现在 A 的提示词里 = 两路被串");
  assert.equal(bad.leaked[0].from, "B");
  assert.equal(bad.leaked[0].to, "A");
  assert.equal(bad.leaked[0].kind, "private_text");

  const bodyLeak = [
    { proposal: "A", round: 1, system: "s", user: '{"history":[{"seq":1,"excerpt":"一段足够长的正文摘录内容"}]}' },
    { proposal: "B", round: 1, system: "s", user: "{}" },
  ];
  const b = checkPromptIsolation(bodyLeak);
  assert.equal(b.ok, false, "A 的定义是不看正文，出现 excerpt 键本身就是事故");
  assert.ok(b.leaked.some((l) => l.kind === "response_text_present"));
  assert.ok(b.checks.some((c) => c.check === "no_response_text_in:A" && c.ok === false), "结构性检查要留痕，不能只给一个布尔");

  const singlePath = [{ proposal: "single", round: 1, system: "旧那条单路的提示词", user: '{"history":[{"excerpt":"x"}]}' }];
  assert.equal(checkPromptIsolation(singlePath).ok, true, "单路没有别的路可比，不当泄露");
});

// ---------- 结构差异 ----------

test("stepKey 只认实际会发出去的形状：编号、族名、备注都不算", () => {
  const a = { id: "exp-1", action: "request.as", path: "{slot:readPath}", identity: "victim", method: "GET", note: "换个说法" };
  const b = { id: "exp-9", action: "request.as", path: "{slot:readPath}", identity: "victim", method: "POST", note: "另一句备注" };
  assert.equal(stepKey({ ...a, id: "exp-2", note: "再换一句" }), stepKey(a), "只改编号与措辞不该改变打法身份");
  assert.notEqual(stepKey(a), stepKey(b), "方法变了就是另一种打法");
  const d = structuralDiff({ family: "x", recipe: { steps: [a, a] } }, { family: "x", recipe: { steps: [{ ...a, identity: "admin" }, a] } });
  assert.equal(d.identical, false);
  assert.equal(d.onlyA.length, 1);
  assert.equal(d.onlyB.length, 1);
  assert.equal(d.shared.length, 1);
});

test("两份措辞不同的同打法草稿被判成换皮，并且这条分歧被写出来", () => {
  const steps = (id) => [{ id, action: "payload.inject", path: "{slot:sqliPath}", param: "{plan.param}", payloadSet: "sqli-default", identity: "attacker" }];
  const d = structuralDiff({ family: "sql-injection-v1", recipe: { steps: steps("exp-1") } }, { family: "sqli-rebased-by-response", recipe: { steps: steps("exp-7") } });
  assert.equal(d.identical, true, "打法集合逐条相同");
  assert.equal(d.reskin, true);
  assert.ok(d.divergences.some((x) => x.kind === "reskin"), "B 是 A 换皮要写成一条分歧，不能只藏在布尔里");
  assert.ok(d.divergences.some((x) => x.kind === "family"));
});

// ---------- 双路实跑（假模型 + 假执行器） ----------

test("双路各拿一份预算、互不见文本、草稿键带编号、菜单一致（第 14 项验收）", async () => {
  const s = stash();
  const { chatImpl, calls } = perProposerChat({
    A: [{ primitive: 1, target: 2 }, { stop: true, family: "generic-shape-read" }],
    B: [{ primitive: 3, target: 4, role: 2 }, { stop: true, family: "response-shape-sqli" }],
  });
  const out = await runDualProposals(fakeCtx({ targetConfig: { exploration: { enabled: true, proposers: ["A", "B"] } } }), {
    baseUrl: s.baseUrl,
    stash: s,
    model: "fake-dual",
    chatImpl,
    budget: { ...EXPLORATION_DEFAULTS, maxRequests: 3 },
    sendStep: async (plan) => okStep({ path: plan.slot === "sqliPath" ? "/api/search" : "/api/orders", excerpt: '{"owner":"gb-victim","token":"zzz-secret-value"}' }),
  });
  assert.deepEqual(out.proposals.map((p) => p.id), ["A", "B"]);
  assert.equal(out.menusIdentical, true, "两路看到的是同一份菜单，差异才归因到提议者");
  assert.equal(out.isolation.ok, true, JSON.stringify(out.isolation.leaked));
  assert.equal(out.draftsDiffer, true, "同一靶场两份草稿确有差异");
  assert.equal(out.requestsUsed, 2, "每路各发一次");
  assert.equal(out.modelCalls, 4, "每路两轮");
  assert.equal(calls.length, 4);
  const keys = out.proposals.map((p) => p.summary.draftKey);
  assert.ok(keys[0].startsWith("A-") && keys[1].startsWith("B-"), `草稿键要带提议者编号：${keys}`);
  assert.notEqual(keys[0], keys[1], "两路的草稿互不覆盖");

  const blobOf = (id) => out.prompts.filter((p) => p.proposal === id).map((p) => `${p.system}\n${p.user}`).join("\n");
  const blobA = blobOf("A");
  const blobB = blobOf("B");
  assert.ok(!blobA.includes("excerpt"), "A 一路从头到尾没收到响应正文的键");
  assert.ok(blobB.includes("excerpt"), "B 第二轮看得见自己上一轮的正文");
  assert.ok(!blobA.includes("zzz-secret-value") && !blobB.includes("zzz-secret-value"), "正文里的凭据值在进提示词前就被脱敏");
  for (const l of privateLinesOf(A)) assert.ok(!blobB.includes(l), "A 的独有文本没进 B");
  for (const l of privateLinesOf(B)) assert.ok(!blobA.includes(l), "B 的独有文本没进 A");
  assert.ok(!JSON.stringify(summarizeDual(out)).includes("zzz-secret-value"), "摘要不带正文，也就不带凭据值");
  assert.equal(out.proposals[0].summary.proposal.basis, "generic_shapes");
  assert.equal(out.proposals[1].summary.proposal.basis, "target_response");

  // 预算独立：上限压到 1，两路各自用尽自己那一份，而不是合起来用尽
  const tight = await runDualProposals(fakeCtx(), {
    baseUrl: s.baseUrl,
    stash: s,
    model: "fake-dual",
    chatImpl: perProposerChat({ A: [{ primitive: 1, target: 2 }], B: [{ primitive: 2, target: 1, role: 2 }] }).chatImpl,
    budget: { ...EXPLORATION_DEFAULTS, maxRequests: 1 },
    sendStep: async () => okStep(),
    proposers: ["A", "B"],
  });
  assert.equal(tight.requestsUsed, 2, "两路各一份预算：合计两次实发，不是第一次就耗尽");
  assert.deepEqual(tight.proposals.map((p) => p.summary.outcome), ["budget_exhausted", "budget_exhausted"]);
  assert.equal(tight.outcome, "ran");
});

test("点名不足两条就不跑；菜单指纹同一算法，换候选就变；单路键不带编号", async () => {
  const s = stash();
  const one = await runDualProposals(fakeCtx(), { baseUrl: s.baseUrl, stash: s, chatImpl: perProposerChat({}).chatImpl, proposers: ["A"] });
  assert.equal(one.outcome, "not_run");
  assert.match(one.error, /至少两条/, "缺第二路不叫双路，也不许悄悄退化成单路");
  assert.equal(one.proposals.length, 0, "没跑就没有任何一路的草稿");

  const menu = buildMenu(stash());
  assert.equal(menuFingerprint(menu), menuFingerprint(buildMenu(stash())), "同一份计划要给出同一份指纹");
  const changed = buildMenu(stash({ candidates: { ...stash().candidates, readPath: [{ fullPath: "/api/other", read: {} }] } }));
  assert.notEqual(menuFingerprint(menu), menuFingerprint(changed), "可打面变了必须反映到指纹上");
  assert.notEqual(draftKeyFor("m", menu, "A"), draftKeyFor("m", menu, "B"), "同一菜单下两路草稿键互不覆盖");
  assert.ok(!draftKeyFor("m", menu).startsWith("A-"), "单路（第 13 项）的键不带编号，行为逐字不变");
  assert.notEqual(draftKeyFor("m", menu, "A", "a".repeat(12)), draftKeyFor("m", menu, "A", "b".repeat(12)), "提示词措辞变了草稿键也要变：旧草稿不顶着新措辞的名义");
  assert.notEqual(promptDigestOf(A), promptDigestOf(B), "两路的提示词文本不同，摘要就不同");
  const expectedDigest = createHash("sha256").update([systemPromptOf(A), ...A.guide].join("\n")).digest("hex").slice(0, 12);
  assert.equal(promptDigestOf(A), expectedDigest, "摘要跟着真正写进提示词的文本算（系统提示+该路清单），不是独立维护的版本号");
});

test("单路不写 proposer 时提示词与第 13 项一致：purpose 不带编号，也没有清单段", async () => {
  const s = stash();
  const { chatImpl, calls } = perProposerChat({ single: [{ primitive: 1, target: 2 }, { stop: true, family: "single-path" }] });
  const prompts = [];
  const state = await runExploration(fakeCtx(), {
    baseUrl: s.baseUrl,
    stash: s,
    model: "fake",
    chatImpl,
    budget: EXPLORATION_DEFAULTS,
    sendStep: async () => okStep(),
    promptSink: (r) => prompts.push(r),
  });
  assert.equal(state.proposal, null, "没给提议者就没有归属信息，不许编一个");
  assert.equal(prompts.every((p) => p.proposal === "single"), true);
  assert.equal(calls[0].purpose, "探索区选下一步");
  assert.ok(!calls[0].userPrompt.includes("\"shapes\""), "单路提示词里不该混进双路的清单段");
  assert.ok(!calls[0].systemPrompt.includes("你只看得见自己这一轮"), "单路沿用第 13 项那段写死的系统提示词");
});

// ---------- 对比代理的输出：只有降级权 ----------

test("表外字段丢弃：对比代理写的 verdict/registered/pass 一个都不进结论", () => {
  const ok = validateComparatorOpinion({
    divergences: ["A 只打了匿名读，B 打了注入参数"],
    b_is_reskin: false,
    recommendation: "return",
    why: "两份打的是不同槽位",
    verdict: "vulnerable",
    registered: true,
    exitCode: 0,
  });
  assert.equal(ok.ok, true);
  assert.equal(ok.recommendation, "return");
  assert.deepEqual([...ok.ignored].sort(), ["exitCode", "registered", "verdict"], "表外键只留名字进审计，值一律不进结论");
  assert.equal(JSON.stringify(ok).includes("vulnerable"), false, "被拒的表外值不许跟着产物走");
});

test("FORBIDDEN_WORDS 逐个试：这些词是对比代理无权表达的状态，写出来就整条拒收", () => {
  for (const w of FORBIDDEN_WORDS) {
    const r = validateComparatorOpinion({ recommendation: w, why: "测试" });
    assert.equal(r.ok, false, `「${w}」不该被接受为对比结论`);
    assert.match(r.rejected, /无权表达的状态/);
    assert.ok(r.ignored.includes("recommendation(非法取值)"), `「${w}」要留名进审计`);
  }
  assert.ok(FORBIDDEN_WORDS.some((w) => w === "通过"), "放行类措辞必须在禁止清单里");
});

test("中文意见照收：建议合并 / 退回；非法取值回给可用编号", () => {
  assert.equal(validateComparatorOpinion({ recommendation: "建议合并" }).recommendation, "merge_suggestion");
  assert.equal(validateComparatorOpinion({ recommendation: "退回" }).recommendation, "return");
  assert.equal(validateComparatorOpinion({ recommendation: " RETURN " }).recommendation, "return", "大小写与空白宽容，但只认这两个格子");
  const bad = validateComparatorOpinion({ recommendation: "两份都对" });
  assert.equal(bad.ok, false);
  assert.match(bad.rejected, /可用：merge \/ return/);
  for (const notObject of [null, "退回", ["return"], 42]) {
    assert.equal(validateComparatorOpinion(notObject).ok, false, `${JSON.stringify(notObject)} 不是 JSON 对象`);
  }
  assert.match(validateComparatorOpinion("退回").rejected, /必须是 JSON 对象/);
});

test("分歧说明有上限与截断，长文不进产物", () => {
  const many = validateComparatorOpinion({
    recommendation: "return",
    divergences: Array.from({ length: 40 }, (_, i) => `第 ${i} 条分歧说明，内容足够长`.repeat(8)),
    why: "很长".repeat(400),
  });
  assert.equal(many.divergences.length, 12, "分歧说明只留 12 条");
  assert.ok(many.divergences.every((d) => d.length <= 240));
  assert.equal(many.why.length, 400);
});

// ---------- 引擎结论：事实不齐就退回，永远没有「通过」出口 ----------

test("两份都错的草稿：至少标出一个分歧并落退回", () => {
  const dual = dualFixture({ tableOk: false });
  const c = decideComparison(dual, { grades: ownGrades() });
  assert.equal(c.decision, "return");
  assert.equal(c.decidedBy, "engine");
  const bad = c.facts.filter((f) => !f.ok);
  assert.ok(bad.length >= 1, "两条都错时至少有一条前置事实不成立");
  assert.ok(c.reasons.some((r) => r.includes("A 的草稿")) && c.reasons.some((r) => r.includes("B 的草稿")));
  assert.ok((dual.diff.divergences ?? []).length >= 1, "结构差异本身要作为分歧写出来，不只给布尔");
  assert.equal(c.registered, false);
  assert.equal(c.canWritePassField, false);
});

test("成绩必须挂在这一路自己的草稿键上：没判卷、借成绩、同一份成绩都落退回", () => {
  const dual = dualFixture();
  const noGrade = decideComparison(dual, { grades: null });
  assert.equal(noGrade.decision, "return", "第 6 项的闸没跑过就不许放行");
  assert.ok(noGrade.reasons.some((r) => /没有自己的考卷成绩/.test(r)), JSON.stringify(noGrade.reasons));

  const borrowed = decideComparison(dual, { grades: { A: { provenance: "B-k1", runLabel: "r1" }, B: { provenance: "B-k1", runLabel: "r2" } } });
  assert.equal(borrowed.decision, "return");
  assert.ok(borrowed.reasons.some((r) => /provenance 与它自己的草稿键不一致/.test(r)), "不许拿别路那次跑的成绩充当自己的");

  const shared = decideComparison(dual, { grades: { A: { provenance: "A-k1", runLabel: "同一份成绩" }, B: { provenance: "B-k1", runLabel: "同一份成绩" } } });
  assert.equal(shared.decision, "return");
  assert.ok(shared.reasons.some((r) => /同一次跑的成绩被共享/.test(r)));

  const partial = decideComparison(dual, { grades: { A: { provenance: "A-k1", runLabel: "r1" } } });
  assert.equal(partial.decision, "return", "只有一路有成绩也不算各自过了考卷");
});

test("事实全部成立 + 模型建议合并：只落「建议合并（仍需人工终审）」，且没有通过字段", () => {
  const dual = dualFixture();
  const opinion = validateComparatorOpinion({ recommendation: "merge", why: "两份互补", divergences: ["A 匿名读 / B 注入"] });
  const c = decideComparison(dual, { opinion, grades: ownGrades() });
  assert.equal(c.decision, "merge_suggestion");
  assert.equal(c.decisionLabel, "建议合并（仍需人工终审）");
  assert.equal(c.registered, false, "合并建议不等于注册：注册是人工闸门（红线 1/8）");
  assert.equal(c.canWritePassField, false);
  assert.equal(c.downgraded_model_merge, false);
  assert.deepEqual(c.facts.map((f) => f.ok), Array(c.facts.length).fill(true));
  assert.ok(!COMPARATOR_DECISIONS.includes("pass") && !COMPARATOR_DECISIONS.includes("approve"), "结论集合里根本没有「通过」这一格");
  assert.equal(JSON.stringify(c).includes('"pass"'), false);
});

test("降级只有向下：模型说退回一定退回；隔离失败／菜单不同／换皮都落退回", () => {
  const dual = dualFixture();
  const merge = validateComparatorOpinion({ recommendation: "merge" });
  const back = validateComparatorOpinion({ recommendation: "return" });
  const forced = decideComparison(dual, { opinion: back, grades: ownGrades() });
  assert.equal(forced.decision, "return", "它唯一能往反方向推的就是退回");
  assert.equal(forced.facts.every((f) => f.ok), true, "事实都成立也照样退回：降级权不是建议权");

  const noIsolation = decideComparison(dualFixture({ isolationOk: false }), { opinion: merge, grades: ownGrades() });
  assert.equal(noIsolation.decision, "return");
  assert.ok(noIsolation.reasons.some((r) => /提示词隔离失败/.test(r)));

  const otherMenu = decideComparison(dualFixture({ menusIdentical: false }), { opinion: merge, grades: ownGrades() });
  assert.equal(otherMenu.decision, "return");
  assert.ok(otherMenu.reasons.some((r) => /菜单指纹不同/.test(r)), "可打面不同就不能把差异归给提议者");

  const reskin = decideComparison(dualFixture({ draftsDiffer: false }), { opinion: merge, grades: ownGrades() });
  assert.equal(reskin.decision, "return");
  assert.ok(reskin.reasons.some((r) => /B 是 A 换皮/.test(r)));

  const downgraded = decideComparison(dualFixture({ menusIdentical: false }), { opinion: merge, grades: ownGrades() });
  assert.equal(downgraded.downgraded_model_merge, true, "模型说了合并但事实不齐，要如实标出是引擎降的回");
});

test("两路都没跑起来就没有对比依据", () => {
  const dual = dualFixture();
  for (const p of dual.proposals) p.summary.outcome = "not_run";
  const c = decideComparison(dual, { grades: ownGrades() });
  assert.equal(c.decision, "return");
  assert.ok(c.reasons.some((r) => /都产出试打记录/.test(r)), JSON.stringify(c.reasons));
});

// ---------- 对比代理实调：异常与坏输出都不许造出绿灯 ----------

test("对比代理不可用：只少一份分歧说明，结论照样由引擎按事实落；异常原文先脱敏", async () => {
  const dual = dualFixture();
  const events = [];
  const ctx = fakeCtx({ emit: (e) => events.push(e) });
  const c = await runComparator(ctx, {
    dual,
    grades: ownGrades(),
    chatImpl: async () => {
      throw new LlmError("上游返回 Set-Cookie: sid=super-secret-token-999 后断开", { code: "http_503" });
    },
  });
  assert.equal(c.decision, "return", "草稿没判过卷，模型缺席也只是换个理由退回");
  assert.equal(c.decidedBy, "engine");
  assert.equal(c.model.ok, false);
  assert.match(c.model.rejected, /对比代理不可用/);
  assert.ok(!JSON.stringify(c).includes("super-secret-token-999"), "凭据值不许进结论");
  assert.ok(events.some((e) => e.data?.action === "compare" && e.data?.ok === false), "异常要落一条事件，不能静默");
});

test("非 JSON 输出与被拒输出都留痕在结论里，不阻断流程", async () => {
  const asked = [];
  const c1 = await runComparator(fakeCtx(), {
    dual: dualFixture(),
    grades: ownGrades(),
    chatImpl: async (x, req) => {
      asked.push(req.purpose);
      return { content: "我觉得这两份都挺不错的，可以直接放行" };
    },
  });
  assert.deepEqual(asked, ["对比两份配方草稿"]);
  assert.equal(c1.model.ok, false);
  assert.equal(c1.decision, "return");

  const c2 = await runComparator(fakeCtx(), {
    dual: dualFixture(),
    grades: ownGrades(),
    chatImpl: async () => ({ content: JSON.stringify({ recommendation: "通过", verdict: "vulnerable" }) }),
  });
  assert.equal(c2.model.ok, false);
  assert.match(c2.model.rejected, /无权表达的状态/);
  assert.ok(c2.model.ignoredFields.includes("verdict"), "表外字段要留名进审计");
  assert.equal(c2.decision, "return");
});

test("模型建议合并但事实不齐：引擎降回退回并如实标出降级", async () => {
  const c = await runComparator(fakeCtx(), {
    dual: dualFixture({ menusIdentical: false }),
    grades: ownGrades(),
    chatImpl: async () => ({ content: JSON.stringify({ recommendation: "merge", divergences: ["打法不同"], why: "可以合并" }) }),
  });
  assert.equal(c.decision, "return");
  assert.equal(c.downgraded_model_merge, true);
  assert.equal(c.model.ok, true, "意见本身合法，被拒的是它指向的格子");
  assert.equal(c.model.recommendation, "merge_suggestion");
});

// ---------- 报告：这一节永远没有「通过」这一格 ----------

test("报告渲染双路：隔离、差异、结论逐条落纸，且没有任何放行口径", () => {
  const dual = dualFixture();
  const comparison = decideComparison(dual, {
    opinion: validateComparatorOpinion({ recommendation: "return", divergences: ["A 匿名读 / B 注入"], why: "两份打的不同槽位" }),
    grades: null,
  });
  const merged = summarizeDual(dual, comparison);
  const ctx = {
    sessionId: "s_dual",
    gate: false,
    targetConfig: { start: { cmd: "node", args: ["server.js"], readyPattern: "listening" } },
    view: {
      projectRoot: "D:/tmp/shop",
      projectName: "shop",
      startedAt: 1,
      state: "pre",
      findings: [],
      evidence: [],
      phases: {},
      targets: {},
      patch: null,
      supabase: null,
      blackbox: null,
      acceptance: null,
      llm: null,
      bootstrap: null,
      rollback: null,
      error: null,
      exploration: {
        outcome: "stopped",
        requestsUsed: 1,
        rounds: 2,
        model: "fake-dual",
        modelCalls: 4,
        draft: dual.proposals[0].summary.draft,
        dual: merged,
      },
    },
  };
  const { json, markdown } = buildReport(ctx, { outcome: "vulnerable", exitCode: 1, patchStatus: null, state: "pre" });
  assert.match(markdown, /## 探索区双路/);
  assert.match(markdown, /提示词隔离/);
  assert.match(markdown, /两路菜单一致/);
  assert.match(markdown, /为什么这一节永远没有「通过」/);
  assert.match(markdown, /提议者 A 的实发序列/);
  assert.match(markdown, /A（照通用打法形状） \/ B（照靶子真实响应形状）/);
  assert.match(markdown, /对比结论 \| \*\*退回\*\*/);
  assert.ok(markdown.includes("无（草稿未判卷）"), "没判过卷要在表里如实写着，不能空着让人误会");
  assert.equal(json.exploration.dual.comparison.decision, "return");
  assert.equal(json.exploration.dual.comparison.canWritePassField, false);
  assert.equal(json.exploration.dual.comparison.registered, false);
  assert.equal(json.verdict.outcome, "vulnerable", "探索层不改判定：结论只来自判卷代码");
  assert.equal(json.verdict.patchStatus, null);
});

test("摘要行把双路事实带进结论段：隔离状态与对比结论一起写", () => {
  const dual = dualFixture({ isolationOk: false });
  const merged = summarizeDual(dual, decideComparison(dual, { grades: ownGrades() }));
  const view = { projectRoot: "D:/tmp/shop", projectName: "shop", startedAt: 1, state: "pre", findings: [], evidence: [], phases: {}, targets: {}, exploration: { dual: merged } };
  const { markdown } = buildReport({ sessionId: "s2", gate: false, targetConfig: {}, view }, { outcome: "clean", exitCode: 0, state: "pre" });
  assert.match(markdown, /探索区双路独立提案：A\/B 两路共 2 次实发/);
  assert.match(markdown, /提示词隔离失败/);
  assert.match(markdown, /对比结论=\*\*退回\*\*/);
});

