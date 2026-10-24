import test from "node:test";
import assert from "node:assert/strict";
import {
  attackPlanEnabled,
  applyRouteOrder,
  buildRouteMenu,
  planBudget,
  recordPlan,
  runAttackPlanner,
  validatePlanChoice,
} from "../lib/attackplan.mjs";
import { LlmError } from "../lib/llm.mjs";

function routes(n = 6, probeCap = 3) {
  const out = [];
  for (let i = 1; i <= n; i += 1) out.push({ method: "GET", path: `/api/r${i}`, source: "openapi", queryParams: i === n ? ["q"] : [] });
  out.push({ method: "POST", path: "/api/write", source: "openapi" });
  return out;
}

function menuOf(list, probeCap = 3, opts = {}) {
  return buildRouteMenu(list, probeCap, opts);
}

test("菜单只列「预算外」的 GET 路由，编号从 1 开始且不冲突", () => {
  const list = routes(6, 3);
  const menu = menuOf(list, 3);
  assert.deepEqual(menu.covered, ["/api/r1", "/api/r2", "/api/r3"]);
  assert.deepEqual(
    menu.items.map((i) => i.path),
    ["/api/r4", "/api/r5", "/api/r6"]
  );
  assert.deepEqual(
    menu.items.map((i) => i.id),
    [1, 2, 3]
  );
  assert.equal(menu.byId.get(3).path, "/api/r6");
  assert.deepEqual(menu.byId.get(3).params, ["q"]);
  // POST 不进菜单：规划只能影响读类/注入类探测的路由序
  assert.ok(!menu.items.some((i) => i.method !== "GET"));
  assert.equal(menu.routesById.get(1), list[3], "编号必须映射回引擎自己的路由对象");
});

test("菜单受 maxMenu 上限约束，probeCap 至少为 1", () => {
  const menu = menuOf(routes(10, 1), 1, { maxMenu: 2 });
  assert.equal(menu.probeCap, 1);
  assert.deepEqual(
    menu.items.map((i) => i.path),
    ["/api/r2", "/api/r3"]
  );
  assert.equal(menuOf(routes(3), 0).probeCap, 1);
});

test("选择校验只认编号：编号之外的字段一律丢弃并留痕", () => {
  const menu = menuOf(routes(6, 3), 3);
  const ok = validatePlanChoice(
    { picks: [2, 1], payload: "' OR 1=1--", method: "POST", verdict: "vulnerable", identity: "alice" },
    menu
  );
  assert.equal(ok.ok, true);
  assert.deepEqual(ok.ids, [2, 1]);
  assert.deepEqual(
    ok.picked.map((p) => p.path),
    ["/api/r5", "/api/r4"]
  );
  assert.deepEqual(ok.ignored.sort(), ["identity", "method", "payload", "verdict"]);
  // 走私的字段值不得进入任何返回值
  assert.ok(!JSON.stringify(ok).includes("OR 1=1"));
});

test("选择校验：去重、截断、非法编号与全非法拒绝", () => {
  const menu = menuOf(routes(6, 3), 3);
  const dedup = validatePlanChoice({ picks: [1, 1, 2, 2] }, menu);
  assert.deepEqual(dedup.ids, [1, 2]);
  assert.deepEqual(dedup.invalid, [1, 2]);

  const truncated = validatePlanChoice({ picks: [1, 2, 3, 1] }, menu, { maxPicks: 2 });
  assert.deepEqual(truncated.ids, [1, 2]);

  const rejected = validatePlanChoice({ picks: [999, "x", -1] }, menu);
  assert.equal(rejected.ok, false);
  assert.match(rejected.reason, /可用编号：1, 2, 3/);
  assert.deepEqual(rejected.invalid, [999, "x", -1]);

  assert.equal(validatePlanChoice({ picks: "1" }, menu).ok, false);
  assert.equal(validatePlanChoice(null, menu).ok, false);
  assert.equal(validatePlanChoice([1], menu).ok, false);
});

test("选择校验：模型主动不挑是合法结果（empty），不是失败", () => {
  const menu = menuOf(routes(6, 3), 3);
  for (const picks of [undefined, null, ""]) {
    const r = validatePlanChoice({ picks }, menu);
    assert.equal(r.ok, true);
    assert.equal(r.empty, true);
    assert.deepEqual(r.ids, []);
  }
  const r = validatePlanChoice({ picks: [], note: "都不值得先打" }, menu);
  assert.equal(r.ok, true);
  assert.equal(r.empty, true);
});

test("重排只把选中的路由提前，其余保持引擎原序且不重复", () => {
  const list = routes(6, 3);
  const menu = menuOf(list, 3);
  const ordered = applyRouteOrder(list, [3, 1], menu);
  assert.deepEqual(
    ordered.map((r) => r.path),
    ["/api/r6", "/api/r4", "/api/r1", "/api/r2", "/api/r3", "/api/r5", "/api/write"]
  );
  // 不修改入参
  assert.equal(list[0].path, "/api/r1");
  // 同一对象只出现一次
  assert.equal(new Set(ordered).size, ordered.length);
});

test("开关：gate 结构性禁用，契约优先于环境变量，默认关闭", () => {
  const saved = process.env.GUARDBUILD_LLM_ATTACKPLAN;
  try {
    delete process.env.GUARDBUILD_LLM_ATTACKPLAN;
    assert.equal(attackPlanEnabled({ gate: false }, { config: {} }), false);
    assert.equal(attackPlanEnabled({ gate: false }, { config: { blackbox: { attackPlan: true } } }), true);
    assert.equal(attackPlanEnabled({ gate: false }, { config: { blackbox: { attackPlan: { enabled: true } } } }), true);
    assert.equal(attackPlanEnabled({ gate: false }, { config: { blackbox: { attackPlan: false } } }), false);
    assert.equal(attackPlanEnabled({ gate: false }, { config: { blackbox: { attackPlan: { enabled: false } } } }), false);

    process.env.GUARDBUILD_LLM_ATTACKPLAN = "1";
    assert.equal(attackPlanEnabled({ gate: false }, { config: {} }), true);
    assert.equal(attackPlanEnabled({ gate: false }, { config: { blackbox: { attackPlan: false } } }), false);
    // gate 优先于一切配置
    assert.equal(attackPlanEnabled({ gate: true }, { config: { blackbox: { attackPlan: true } } }), false);
    process.env.GUARDBUILD_LLM_ATTACKPLAN = "0";
    assert.equal(attackPlanEnabled({ gate: false }, { config: {} }), false);
  } finally {
    if (saved === undefined) delete process.env.GUARDBUILD_LLM_ATTACKPLAN;
    else process.env.GUARDBUILD_LLM_ATTACKPLAN = saved;
  }
});

test("预算参数按契约收敛到安全范围", () => {
  const b = planBudget({ config: { blackbox: { attackPlan: { maxPicks: 99, maxMenu: 999, rounds: 9 } } } });
  assert.deepEqual(b, { maxPicks: 16, maxMenu: 40, rounds: 2 });
  const c = planBudget({ config: { blackbox: { attackPlan: { maxPicks: 0, maxMenu: 1, rounds: 0 } } } });
  assert.deepEqual(c, { maxPicks: 1, maxMenu: 5, rounds: 1 });
  assert.deepEqual(planBudget({ config: {} }), { maxPicks: 8, maxMenu: 40, rounds: 2 });
});

test("没有待排路由时完全不问模型（省一次外发）", async () => {
  let called = 0;
  const r = await runAttackPlanner(
    { gate: false },
    {
      routes: routes(3, 3),
      probeCap: 3,
      getToken: async () => "t",
      chatImpl: async () => {
        called += 1;
        return { content: '{"picks":[1]}' };
      },
    }
  );
  assert.equal(called, 0);
  assert.equal(r.asked, false);
  assert.equal(r.fallback, "no_unprobed_routes");
  assert.equal(r.ordered.length, 4);
});

test("选中的编号把路由提进预算，模型 note 不进入返回值", async () => {
  const list = routes(6, 3);
  let seen = null;
  const r = await runAttackPlanner(
    { gate: false },
    {
      routes: list,
      probeCap: 3,
      getToken: async () => "t",
      chatImpl: async (ctx, opts) => {
        seen = opts;
        return { content: '{"picks":[3],"note":"MODEL-NOTE-SECRET-5c1"}', model: "mock", usage: { total_tokens: 9 } };
      },
    }
  );
  assert.equal(r.asked, true);
  assert.equal(r.fallback, null);
  assert.deepEqual(r.picks, [{ id: 3, method: "GET", path: "/api/r6" }]);
  assert.equal(r.ordered[0].path, "/api/r6");
  assert.equal(r.ordered[1].path, "/api/r1");
  assert.equal(r.model, "mock");
  assert.deepEqual(r.usage, { total_tokens: 9 });
  assert.ok(!JSON.stringify(r).includes("MODEL-NOTE-SECRET"));
  // 发给模型的观察只含编号与路由自身线索
  assert.ok(seen.userPrompt.includes('"unprobed_routes"'));
  assert.ok(seen.userPrompt.includes("/api/r6"));
  assert.ok(!seen.userPrompt.includes("alice"));
});

test("第二轮观察带上上一轮实测证据（只给路由/用例/结论）", async () => {
  let prompt = "";
  const r = await runAttackPlanner(
    { gate: false },
    {
      routes: routes(6, 3),
      probeCap: 3,
      round: 2,
      records: [
        { endpoint: "/api/r4", caseId: "blackbox-idor-api-r4-102", verdict: "blocked" },
        { endpoint: "/api/r5", caseId: "blackbox-sqli-or-api-r5-q", verdict: "vulnerable" },
      ],
      getToken: async () => "t",
      chatImpl: async (ctx, opts) => {
        prompt = opts.userPrompt;
        return { content: '{"picks":[2]}' };
      },
    }
  );
  assert.equal(r.round, 2);
  assert.ok(prompt.includes('"round": 2'));
  assert.ok(prompt.includes("prior_evidence"));
  assert.ok(prompt.includes("blackbox-idor-api-r4-102"));
  assert.ok(prompt.includes("blocked"));
  assert.ok(!prompt.includes("bob123"));
});

test("LLM 不可用 / 返回坏 JSON / 编号全非法时回退原序且不伪造成功", async () => {
  const list = routes(6, 3);
  const base = { routes: list, probeCap: 3, getToken: async () => "t" };

  const unavailable = await runAttackPlanner(
    { gate: false },
    { ...base, chatImpl: async () => { throw new LlmError("no key", { code: "llm_missing_key" }); } }
  );
  assert.equal(unavailable.fallback, "llm_unavailable");
  assert.equal(unavailable.ordered, list);
  assert.deepEqual(unavailable.picks, []);

  const boom = await runAttackPlanner(
    { gate: false },
    { ...base, chatImpl: async () => { throw new Error("socket hang up"); } }
  );
  assert.equal(boom.fallback, "planner_error");
  assert.equal(boom.ordered, list);

  const bad = await runAttackPlanner(
    { gate: false },
    { ...base, chatImpl: async () => ({ content: "不是 JSON" }) }
  );
  assert.equal(bad.fallback, "bad_json");
  assert.equal(bad.ordered, list);

  const rejected = await runAttackPlanner(
    { gate: false },
    { ...base, chatImpl: async () => ({ content: '{"picks":[999]}' }) }
  );
  assert.equal(rejected.fallback, "choice_rejected");
  assert.match(rejected.rejected, /不在待排路由菜单内/);
  assert.equal(rejected.ordered, list);
  assert.deepEqual(rejected.picks, []);
});

test("审计与事件只写引擎侧事实：模型原文不落库", () => {
  const inserted = [];
  const events = [];
  const ctx = {
    gate: false,
    state: "blackbox",
    sessionId: "sess-plan",
    db: { insertAgentAction: (row) => inserted.push(row) },
    emit: (e) => events.push(e),
  };
  const round = {
    round: 1,
    picks: [{ id: 3, method: "GET", path: "/api/contracts" }],
    ignored: ["payload", "verdict"],
    invalid: [7],
    rejected: null,
    fallback: null,
    durationMs: 120,
  };
  recordPlan(ctx, round);
  assert.equal(inserted.length, 1);
  assert.equal(inserted[0].action, "attack_plan");
  assert.equal(inserted[0].ok, true);
  assert.match(inserted[0].subject, /\/api\/contracts/);
  assert.match(inserted[0].note, /提进预算 1 条/);
  assert.match(inserted[0].note, /丢弃字段：payload,verdict/);
  assert.equal(events.length, 1);
  assert.equal(events[0].kind, "attackplan");
  assert.equal(events[0].severity, "info");
  assert.ok(!JSON.stringify(events[0]).includes("MODEL-NOTE"));

  const fallbackRound = { ...round, round: 2, picks: [], fallback: "choice_rejected", rejected: "编号不在菜单内", ignored: [] };
  recordPlan(ctx, fallbackRound);
  assert.equal(inserted[1].ok, false);
  assert.equal(events[1].severity, "warn");
  assert.match(events[1].message, /choice_rejected/);

  // 审计写失败不改变扫描流程
  const broken = { ...ctx, db: { insertAgentAction: () => { throw new Error("db locked"); } } };
  assert.doesNotThrow(() => recordPlan(broken, round));
});
