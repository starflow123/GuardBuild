/**
 * 探索区（方案第 13 项）单测：这一路只放宽「打什么」，不放宽「怎么打」。
 * 覆盖五条硬边界：双闸与 gate/黑盒结构性禁用、预算由引擎夹紧、模型只报编号（表外字段丢弃、
 * 判据不在菜单里）、产出只是草稿（不注册、不进判定链）、凭据值不落。
 */
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, mkdtempSync, rmSync, existsSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  EXPLORATION_DRAFT_RULE,
  EXPLORATION_DEFAULTS,
  EXPLORATION_HARD_CAPS,
  PRIMITIVES,
  buildDraft,
  buildMenu,
  buildResourceMenu,
  buildRoleMenu,
  buildTargetMenu,
  checkExplorationAnchors,
  draftStepOf,
  explorationBudget,
  explorationEnabled,
  runExploration,
  summarizeExploration,
  validateExploreChoice,
  writeExplorationArtifact,
} from "../lib/explorer.mjs";
import { RECIPE_VERSION, VERDICT_RULES, validateRecipe } from "../lib/actiontable.mjs";
import { LlmError } from "../lib/llm.mjs";
import { explorationSendStep } from "../lib/probe.mjs";

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

/** 一份「修复前取证阶段留下的快照」形状，与 probe.mjs 里 ctx._exploration 一致 */
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

function useExplorationEnv(on) {
  const prev = process.env.GUARDBUILD_LLM_EXPLORATION;
  if (on) process.env.GUARDBUILD_LLM_EXPLORATION = "1";
  else delete process.env.GUARDBUILD_LLM_EXPLORATION;
  return () => {
    if (prev === undefined) delete process.env.GUARDBUILD_LLM_EXPLORATION;
    else process.env.GUARDBUILD_LLM_EXPLORATION = prev;
  };
}

function useTempDataDir() {
  const dir = mkdtempSync(join(tmpdir(), "gb-explore-"));
  const prev = process.env.GUARDBUILD_DATA_DIR;
  process.env.GUARDBUILD_DATA_DIR = dir;
  return {
    dir,
    restore: () => {
      if (prev === undefined) delete process.env.GUARDBUILD_DATA_DIR;
      else process.env.GUARDBUILD_DATA_DIR = prev;
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

function scriptedChat(choices) {
  const calls = [];
  let i = 0;
  const chatImpl = async (ctx, req) => {
    calls.push(req);
    const c = i < choices.length ? choices[i] : { stop: true };
    i += 1;
    return { model: "fake-explore", content: JSON.stringify(c) };
  };
  return { chatImpl, calls, asked: () => calls.length };
}

function okStep(over = {}) {
  return { ok: true, method: "GET", path: "/api/orders/7", status: 200, bytes: 42, excerpt: '{"id":7}', error: null, ...over };
}

// ---------- 开关：双闸 + 结构性禁用 ----------

test("explorationEnabled：契约 enabled 与环境变量缺一不可，gate 与纯黑盒结构性禁用", () => {
  const restore = useExplorationEnv(false);
  try {
    const on = { targetConfig: { exploration: { enabled: true } } };
    assert.equal(explorationEnabled({}), false, "契约没表态就不跑");
    assert.equal(explorationEnabled(on), false, "只有契约不够：GUARDBUILD_LLM_EXPLORATION 也必须为 1");
    assert.equal(explorationEnabled({ targetConfig: { exploration: { enabled: false } } }), false);
  } finally {
    restore();
  }

  const r2 = useExplorationEnv(true);
  try {
    assert.equal(explorationEnabled({ targetConfig: { exploration: { enabled: true } } }), true);
    assert.equal(explorationEnabled({ gate: true, targetConfig: { exploration: { enabled: true } } }), false, "gate/CI 不许调用模型");
    assert.equal(
      explorationEnabled({ blackboxUrl: "https://third-party.test", targetConfig: { exploration: { enabled: true } } }),
      false,
      "纯黑盒（外部目标）不经过这一路"
    );
    assert.equal(explorationEnabled({ targetConfig: {} }), false);
  } finally {
    r2();
  }
});

// ---------- 预算：夹紧在引擎侧 ----------

test("explorationBudget：缺省走默认，契约写更大也只取引擎硬上限，下限兜住", () => {
  assert.deepEqual(explorationBudget(null), {
    maxRequests: EXPLORATION_DEFAULTS.maxRequests,
    maxRounds: EXPLORATION_DEFAULTS.maxRounds,
    totalBudgetMs: EXPLORATION_DEFAULTS.totalBudgetMs,
    maxOutputChars: EXPLORATION_DEFAULTS.maxOutputChars,
    maxTargets: EXPLORATION_DEFAULTS.maxTargets,
    maxResources: EXPLORATION_DEFAULTS.maxResources,
    maxDraftSteps: EXPLORATION_DEFAULTS.maxDraftSteps,
  });
  const big = explorationBudget({
    targetConfig: { exploration: { maxRequests: 9_999, maxRounds: 999, totalBudgetMs: 99_999_999, maxOutputChars: 9_999_999 } },
  });
  assert.equal(big.maxRequests, EXPLORATION_HARD_CAPS.maxRequests);
  assert.equal(big.maxRounds, EXPLORATION_HARD_CAPS.maxRounds);
  assert.equal(big.totalBudgetMs, EXPLORATION_HARD_CAPS.totalBudgetMs);
  assert.equal(big.maxOutputChars, EXPLORATION_HARD_CAPS.maxOutputChars);
  const small = explorationBudget({ targetConfig: { exploration: { maxRequests: 0, totalBudgetMs: 1 } } });
  assert.equal(small.maxRequests, 1);
  assert.equal(small.totalBudgetMs, 15_000);
});

// ---------- 菜单：只有计划里真实存在的东西可选 ----------

test("目标菜单只列计划槽位里的候选，注入/穿越只在计划声明了注入点时可选", () => {
  const menu = buildMenu(stash());
  assert.deepEqual(
    menu.targets.items.map((t) => [t.id, t.slot, t.path]),
    [
      [1, "readPath", "/api/orders/:id"],
      [2, "readPath", "/api/orders"],
      [3, "unauthReadPath", "/api/reports"],
      [4, "sqliPath", "/api/search"],
      [5, "traversalPath", "/api/file"],
    ]
  );
  const byAction = Object.fromEntries(menu.primitives.map((p) => [p.action, p.allowedTargetIds]));
  assert.deepEqual(byAction["request.anonymous"], [1, 2, 3]);
  assert.deepEqual(byAction["request.as"], [1, 2, 3]);
  assert.deepEqual(byAction["payload.inject"], [4]);
  assert.deepEqual(byAction["fs.traverse"], [5]);

  // 计划里的注入候选没声明注入点 → 这一动作根本没有可打目标
  const noRef = stash({ candidates: { ...stash().candidates, sqliPath: [{ fullPath: "/api/search", method: "GET" }] } });
  const m2 = buildMenu(noRef);
  assert.deepEqual(m2.primitives.find((p) => p.action === "payload.inject").allowedTargetIds, []);

  // 超出 maxTargets 的候选截掉
  const many = stash({
    candidates: {
      ...stash().candidates,
      readPath: Array.from({ length: 20 }, (_, i) => ({ fullPath: `/api/x${i}`, read: {} })),
    },
  });
  assert.equal(buildTargetMenu(many, { maxTargets: 4 }).items.length, 4);
});

test("身份菜单里 anonymous 恒为 1 号且不带凭据；对象菜单只有主键与归属", () => {
  const roles = buildRoleMenu(stash());
  assert.deepEqual(roles.items[0], { id: 1, role: "anonymous", identity: null });
  assert.deepEqual(roles.authedIds, [2, 3, 4]);
  assert.equal(roles.defaultAuthedId, 2);
  assert.equal(JSON.stringify(roles.items).includes("password"), false, "菜单里只有身份名字与保险库条目名，不含凭据值");
  assert.equal(buildRoleMenu({ targets: {} }).authedIds.length, 0, "没有已登录身份时授权动作不可选");

  const res = buildResourceMenu(stash(), { maxResources: 1 });
  assert.deepEqual(res.items, [{ id: 1, resourceId: "7", owner: "gb-victim" }]);
  assert.equal(buildResourceMenu({ resources: [{ id: "" }, null] }).items.length, 0);
});

// ---------- 选择校验：只认编号 ----------

test("选择校验只认编号：模型自带的 path/payload/headers/verdict 一律丢弃，只留字段名", () => {
  const menu = buildMenu(stash());
  const ok = validateExploreChoice(
    {
      primitive: 2,
      target: 1,
      role: 3,
      resource: 2,
      path: "/api/anything-else",
      payload: "' OR 1=1--",
      headers: { Cookie: "session=abc123" },
      verdict: "target-touched",
    },
    menu
  );
  assert.equal(ok.ok, true);
  assert.equal(ok.step.action, "request.as");
  assert.equal(ok.step.target.path, "/api/orders/:id");
  assert.equal(ok.step.role.role, "victim");
  assert.equal(ok.step.resource.resourceId, "8");
  assert.deepEqual(ok.ignored.sort(), ["headers", "path", "payload", "verdict"]);
  const dumped = JSON.stringify(ok.step);
  for (const v of ["anything-else", "OR 1=1", "session=abc123", "target-touched"]) {
    assert.ok(!dumped.includes(v), `走私的值不许进入执行计划：${v}`);
  }
  assert.equal(ok.step.verdictRule, undefined, "判据不是模型能给的字段");
});

test("判据不在菜单里，也不在可选键里：草稿的判据由引擎写定", () => {
  const menu = buildMenu(stash());
  assert.equal(menu.verdictRules, undefined, "菜单不许把判据当成可选项");
  const bad = validateExploreChoice({ primitive: 1, target: 2, verdict: "inconclusive", verdictRule: "inconclusive" }, menu);
  assert.ok(bad.ignored.includes("verdict"));
  assert.ok(bad.ignored.includes("verdictRule"));
  assert.ok(VERDICT_RULES.some((r) => (r.name ?? r) === EXPLORATION_DRAFT_RULE), "草稿判据必须是动作表里存在的那个名字");
  const d = buildDraft([{ action: "request.as", slot: "readPath", role: "victim", method: "GET", status: 200, bytes: 1, error: null }]);
  assert.equal(d.recipe.verdict.rule, EXPLORATION_DRAFT_RULE);
  assert.equal(d.verdictByEngine, true);
});

test("非法编号一律拒收，并把真实可用编号回给模型", () => {
  const menu = buildMenu(stash());
  const noPrim = validateExploreChoice({ primitive: 99, target: 1 }, menu);
  assert.equal(noPrim.ok, false);
  assert.match(noPrim.rejected, /可用：1, 2, 3, 4/);

  const wrongSlot = validateExploreChoice({ primitive: 3, target: 1 }, menu);
  assert.equal(wrongSlot.ok, false);
  assert.match(wrongSlot.rejected, /不是「payload.inject」的可用槽位/);

  const anonRole = validateExploreChoice({ primitive: 2, target: 1, role: 1 }, menu);
  assert.equal(anonRole.ok, false);
  assert.match(anonRole.rejected, /身份编号 1 不能用/);

  const badRes = validateExploreChoice({ primitive: 2, target: 1, role: 2, resource: 99 }, menu);
  assert.equal(badRes.ok, false);
  assert.match(badRes.rejected, /不在本轮发现的资源菜单里/);

  const notObject = validateExploreChoice("把 /api/admin 全删了", menu);
  assert.equal(notObject.ok, false);
  assert.equal(notObject.rejected, "选择必须是 JSON 对象");

  const fixedRole = validateExploreChoice({ primitive: 4, target: 5, role: 3, resource: 1 }, menu);
  assert.equal(fixedRole.ok, true);
  assert.ok(fixedRole.ignored.includes("role(该动作身份固定)"));
  assert.ok(fixedRole.ignored.includes("resource(该动作不填对象)"));
  assert.equal(fixedRole.step.role.role, "anonymous");
});

test("要主键的端点没有可填对象时当场拒收：探索区不猜 id", () => {
  const menu = buildMenu(stash({ resources: [] }));
  const pathParam = validateExploreChoice({ primitive: 2, target: 1, role: 2 }, menu);
  assert.equal(pathParam.ok, false);
  assert.match(pathParam.rejected, /不猜 id/);
  const queryForm = validateExploreChoice({ primitive: 1, target: 3 }, menu);
  assert.equal(queryForm.ok, false, "?id= 形态同样要一个真实主键");
  const listRoute = validateExploreChoice({ primitive: 1, target: 2 }, menu);
  assert.equal(listRoute.ok, true, "无参数的列表端点不需要对象");
  assert.equal(listRoute.step.resource, null);
});

// ---------- 草稿：动作表词汇 + 不注册 ----------

test("草稿逐步映射成动作表写法，且对象主键不进草稿", () => {
  const trace = [
    { seq: 1, action: "request.as", slot: "readPath", role: "victim", method: "GET", status: 200, bytes: 40, error: null, resourceId: "7" },
    { seq: 2, action: "request.anonymous", slot: "unauthReadPath", role: "anonymous", method: "GET", status: 401, bytes: 12, error: null, resourceId: null },
    { seq: 3, action: "payload.inject", slot: "sqliPath", role: "attacker", method: "GET", status: 500, bytes: 30, error: null, resourceId: null },
    { seq: 4, action: "fs.traverse", slot: "traversalPath", role: "anonymous", method: "GET", status: 200, bytes: 900, error: null, resourceId: null },
    { seq: 5, action: "request.as", slot: "readPath", role: "attacker", method: "GET", status: 200, bytes: 11, error: "连接被拒绝", resourceId: null },
    { seq: 6, action: "request.as", slot: "readPath", role: "victim", method: "GET", status: 200, bytes: 40, error: null, resourceId: "7" },
  ];
  const d = buildDraft(trace, { family: "idor-read-x" });
  assert.equal(d.tableOk, true, d.rejectionText);
  assert.equal(d.steps, 4, "重复的一步合并、失败的那一步不进草稿");
  assert.equal(d.family, "idor-read-x");
  assert.equal(d.familyDeclared, true);
  assert.equal(d.registered, false, "草稿不注册：注册要经人批准（红线 1/8）");
  const dumped = JSON.stringify(d.recipe);
  assert.equal(d.recipe.version, RECIPE_VERSION);
  assert.ok(!dumped.includes("\"resource\""), "对象主键不是动作表参数，不许出现在草稿里");
  assert.ok(dumped.includes("{slot:readPath}"), "路径用槽位引用，由引擎解析");
  assert.ok(d.recipe.steps[0].note.includes("#7"), "实发用了哪个对象记在 note 里供人核对");
  assert.equal(validateRecipe(d.recipe).ok, true);
  assert.equal(buildDraft(trace).family, "explore-undecided", "模型没给族名就标为待定，不编一个");
  assert.equal(buildDraft(trace, { maxSteps: 2 }).steps, 2);
});

test("草稿映射不出表内写法时当场拒收并留原文", () => {
  const d = buildDraft([{ action: "request.as", slot: "readPath", role: "victim", method: "GET", status: 200, bytes: 1, error: null, resource: "7" }]);
  const step = draftStepOf({ action: "unknown.action", slot: "readPath", role: "victim", method: "GET", resourceId: null }, 0);
  assert.equal(step, null, "执行器没有这一动作时映射不出行");
  assert.equal(d.tableOk, true);
});

// ---------- 实跑：预算、收手、异常、脱敏 ----------

test("超限即停：用尽的是哪一项预算要写在事件里，草稿照样落成但不注册", async () => {
  const s = stash();
  const choices = [
    { primitive: 2, target: 1, role: 3, resource: 1 },
    { primitive: 1, target: 2 },
    { primitive: 3, target: 4, role: 2 },
  ];
  const { chatImpl, asked } = scriptedChat(choices);
  const sends = [];
  const ctx = { view: {}, emit: () => {}, projectRoot: null };
  const r = await runExploration(ctx, {
    baseUrl: s.baseUrl,
    stash: s,
    chatImpl,
    model: "fake-explore",
    budget: { ...EXPLORATION_DEFAULTS, maxRequests: 2 },
    sendStep: async (plan) => {
      sends.push(plan);
      return okStep({ path: plan.slot === "sqliPath" ? "/api/search" : "/api/orders/7" });
    },
  });
  assert.equal(r.outcome, "budget_exhausted");
  assert.match(r.budgetStop, /请求数上限（2 次）/);
  assert.equal(r.requestsUsed, 2, "第三条选择不再发出请求");
  assert.equal(sends.length, 2);
  assert.equal(r.draft.steps, 2);
  assert.equal(r.draft.registered, false);
  assert.ok(ctx.view.exploration, "摘要要进视图，供报告渲染");
  assert.equal(asked(), 2, "请求数用尽后连下一轮都不问，第三条选择根本没机会发出");
});

test("轮数预算用尽与自行收手都如实记录族名", async () => {
  const s = stash();
  const a = await runExploration({ emit: () => {} }, {
    baseUrl: s.baseUrl,
    stash: s,
    chatImpl: scriptedChat([{ primitive: 1, target: 2 }]).chatImpl,
    budget: { ...EXPLORATION_DEFAULTS, maxRounds: 1 },
    sendStep: async () => okStep(),
  });
  assert.equal(a.outcome, "budget_exhausted");
  assert.match(a.budgetStop, /轮数上限（1 轮）/);

  const b = await runExploration({ emit: () => {} }, {
    baseUrl: s.baseUrl,
    stash: s,
    chatImpl: scriptedChat([{ primitive: 1, target: 2 }, { stop: true, family: "idor-read-x" }]).chatImpl,
    budget: EXPLORATION_DEFAULTS,
    sendStep: async () => okStep(),
  });
  assert.equal(b.outcome, "stopped");
  assert.equal(b.draft.family, "idor-read-x");
  assert.equal(b.budgetStop, null);
});

test("空菜单不启动：一次模型调用都不发；无执行器也不算跑过", async () => {
  const { chatImpl, asked } = scriptedChat([{ primitive: 1, target: 1 }]);
  const r = await runExploration({ emit: () => {} }, {
    baseUrl: "http://127.0.0.1:1",
    stash: { ...stash(), candidates: { readPath: [], unauthReadPath: [], sqliPath: [], traversalPath: [] } },
    chatImpl,
    sendStep: async () => okStep(),
  });
  assert.equal(r.outcome, "no_targets");
  assert.equal(asked(), 0);
  assert.equal(r.draft, null);

  const noExec = await runExploration({ emit: () => {} }, { baseUrl: "http://127.0.0.1:1", stash: stash(), chatImpl });
  assert.equal(noExec.outcome, "not_run");
  assert.equal(noExec.error, "no_executor");
});

test("模型不可用只影响探索本身：不影响判定链，也不发一次请求", async () => {
  const sent = [];
  const r = await runExploration({ emit: () => {} }, {
    baseUrl: stash().baseUrl,
    stash: stash(),
    budget: EXPLORATION_DEFAULTS,
    chatImpl: async () => {
      throw new LlmError("上游不可用", { code: "http_503" });
    },
    sendStep: async (p) => {
      sent.push(p);
      return okStep();
    },
  });
  assert.equal(r.outcome, "llm_unavailable");
  assert.match(r.error, /上游不可用/);
  assert.equal(sent.length, 0);
  assert.equal(r.trace.length, 0);
});

test("非 JSON 输出与表外写法只留痕，不进请求；被拒轮次如实计数", async () => {
  const sends = [];
  let n = 0;
  const r = await runExploration({ emit: () => {} }, {
    baseUrl: stash().baseUrl,
    stash: stash(),
    budget: { ...EXPLORATION_DEFAULTS, maxRounds: 4 },
    chatImpl: async () => {
      n += 1;
      if (n === 1) return { content: "我觉得这里有漏洞，直接打 /api/admin 就好" };
      if (n === 2) return { content: JSON.stringify({ primitive: 9, target: 9 }) };
      if (n === 3) return { content: JSON.stringify({ primitive: 1, target: 2, sql: "DROP TABLE orders" }) };
      return { content: JSON.stringify({ stop: true }) };
    },
    sendStep: async (p) => {
      sends.push(p);
      return okStep({ path: "/api/orders" });
    },
  });
  assert.equal(r.outcome, "stopped");
  assert.equal(r.rejected, 2);
  assert.equal(sends.length, 1);
  assert.deepEqual(r.ignoredFields, ["sql"]);
  assert.ok(!JSON.stringify(r.trace).includes("DROP TABLE"));
});

test("trace 与产物里的响应摘录二次脱敏：凭据值不跟着走", async () => {
  const t = useTempDataDir();
  try {
    const r = await runExploration(
      { emit: () => {}, projectRoot: "D:/targets/demo-shop", view: {} },
      {
        baseUrl: stash().baseUrl,
        stash: stash(),
        model: "fake-explore",
        budget: { ...EXPLORATION_DEFAULTS, maxRounds: 2 },
        chatImpl: scriptedChat([{ primitive: 2, target: 1, role: 3, resource: 1 }, { stop: true, family: "idor-read-x" }]).chatImpl,
        sendStep: async () =>
          okStep({ excerpt: '{"id":7,"token":"super-secret-1","password":"hunter2"} Set-Cookie: sid=abcdef' }),
      }
    );
    assert.equal(r.outcome, "stopped");
    assert.equal(r.trace.length, 1);
    const dumped = JSON.stringify({ trace: r.trace, draft: r.draft, summary: summarizeExploration(r) });
    for (const secret of ["super-secret-1", "hunter2", "abcdef"]) {
      assert.ok(!dumped.includes(secret), `凭据值不许出现在探索产物里：${secret}`);
    }
    const file = writeExplorationArtifact({ projectRoot: "D:/targets/demo-shop" }, { ...r, draftKey: r.draftKey });
    assert.ok(file && existsSync(file), "草稿要落进数据目录");
    assert.ok(file.replace(/\\/g, "/").includes("/exploration/"), "落在 GUARDBUILD_DATA_DIR/exploration 下");
    assert.ok(!file.includes("recipes"), "绝不写进 sidecar/recipes/");
    const onDisk = readFileSync(file, "utf8");
    assert.ok(!onDisk.includes("super-secret-1"), "落盘的原文同样不许带凭据值");
    const summary = summarizeExploration(r);
    assert.equal(summary.trace[0].excerpt, undefined, "摘要只留引擎侧事实，响应正文不进报告");
    assert.ok(!JSON.stringify(summary).includes("super-secret-1"));
    assert.equal(summary.draft?.verdictRule, "attack-repro", "摘要要把判据如实带进视图与报告");
    assert.equal(summary.draft?.verdictByEngine, true, "并标明这一条是引擎写死的，不是模型给的");
  } finally {
    t.restore();
  }
});

test("探索产物目录按项目聚合，旧文件只留有限的几份", () => {
  const before = readdirSafe(join(REPO_ROOT, "sidecar", "recipes"));
  const t = useTempDataDir();
  try {
    const base = { version: "gb-explore-1", outcome: "stopped", budget: EXPLORATION_DEFAULTS, trace: [], draft: buildDraft([]) };
    const f1 = writeExplorationArtifact({ projectRoot: "D:/targets/a" }, { ...base, draftKey: "k1" });
    const f2 = writeExplorationArtifact({ projectRoot: "d:/targets/A" }, { ...base, draftKey: "k2" });
    assert.ok(f1 && f2);
    assert.equal(dirname(f1), dirname(f2), "同一项目在 Windows 上归一到同一个目录");
    assert.equal(readdirSafe(dirname(f1)).length, 2);
    const noDraft = writeExplorationArtifact({ projectRoot: "D:/targets/a" }, { ...base, draft: null, draftKey: "k3" });
    assert.equal(noDraft, null, "没有草稿就不落盘");
    assert.equal(writeExplorationArtifact({ projectRoot: null }, base), null);
  } finally {
    t.restore();
  }
  assert.deepEqual(readdirSafe(join(REPO_ROOT, "sidecar", "recipes")), before, "探索区不得往注册配方目录写东西");
});

function readdirSafe(dir) {
  try {
    return readdirSync(dir).sort();
  } catch {
    return [];
  }
}

// ---------- 执行器与锚点 ----------

test("执行器不猜对象主键：要主键的端点在没有对象时拒发", async () => {
  const r = await explorationSendStep({}, {
    baseUrl: "http://127.0.0.1:1",
    step: { action: "request.as", slot: "readPath", cand: { fullPath: "/api/orders/:id" }, identity: "victim", resourceId: null },
  });
  assert.equal(r.ok, false);
  assert.match(r.error, /不猜 id/);
  const q = await explorationSendStep({}, {
    baseUrl: "http://127.0.0.1:1",
    step: { action: "request.anonymous", slot: "unauthReadPath", cand: { fullPath: "/api/reports", queryParam: { param: "id" } }, resourceId: null },
  });
  assert.equal(q.ok, false);
  const none = await explorationSendStep({}, { baseUrl: "http://127.0.0.1:1", step: { action: "request.as", slot: "readPath", cand: null } });
  assert.match(none.error, /拿不到该槽位的候选/);
  const unknown = await explorationSendStep({}, {
    baseUrl: "http://127.0.0.1:1",
    step: { action: "shell.exec", slot: "readPath", cand: { fullPath: "/api/orders" } },
  });
  assert.match(unknown.error, /执行器没有/, "菜单与代码不一致时如实报错，不假装打过");
});

test("锚点自检：菜单上写的每个动作，执行器里必须真的还有那一段", () => {
  const fs = { readFileSync: (p, e) => readFileSync(p, e) };
  const r = checkExplorationAnchors(REPO_ROOT, fs);
  assert.equal(r.ok, true, JSON.stringify(r.unresolved));
  assert.equal(r.checked, PRIMITIVES.length);
  const broken = checkExplorationAnchors(REPO_ROOT, { readFileSync: () => "/* 执行器被改写了 */" });
  assert.equal(broken.ok, false);
  assert.equal(broken.unresolved.length, PRIMITIVES.length);
  const missing = checkExplorationAnchors(REPO_ROOT, {
    readFileSync: () => {
      throw new Error("ENOENT");
    },
  });
  assert.equal(missing.ok, false);
  assert.ok(missing.unresolved.every((u) => u.action), "文件不存在也要记清是哪个动作");
});
