/**
 * 覆盖范围与终态措辞单元测试：exit 0 的正常终态不得渲染成执行失败。
 * 运行：npm run test:sidecar
 */
import test from "node:test";
import assert from "node:assert/strict";

import { COVERAGE, coverageSummary, describeOutcome } from "../lib/coverage.mjs";
import { buildReport } from "../lib/report.mjs";

test("describeOutcome: 终态语义与退出码映射（README 退出码表的唯一来源）", () => {
  const coverage = describeOutcome("no_candidates");
  assert.equal(coverage.outcome, "no_candidates");
  assert.equal(coverage.kind, "coverage");
  assert.equal(coverage.exitCode, 0, "未命中覆盖范围是 exit 0");
  assert.notEqual(coverage.title, "执行失败");
  assert.notEqual(coverage.stateLabel, "执行出错");

  const clean = describeOutcome("attack_not_reproducible");
  assert.equal(clean.outcome, "not_reproducible");
  assert.equal(clean.kind, "clean");
  assert.equal(clean.exitCode, 0);
  assert.match(clean.title, /不等于安全/, "未复现不得暗示「系统安全」");

  // 「没测到」必须与「测了没复现」分开：前者 exit 2，后者 exit 0
  for (const code of ["no_endpoints", "attack_inconclusive", "plan_incomplete", "scout_routes_unverified"]) {
    const inc = describeOutcome(code);
    assert.equal(inc.outcome, "inconclusive", `${code} 应归为 inconclusive`);
    assert.equal(inc.kind, "inconclusive");
    assert.equal(inc.exitCode, 2, `${code} 是「无法证明」，必须阻断门禁`);
    assert.match(inc.title, /无法证明/);
    assert.notEqual(inc.stateLabel, "执行出错");
  }
  assert.match(describeOutcome("no_endpoints").title, /未识别到 HTTP 路由/);
  assert.match(describeOutcome("attack_inconclusive").title, /证据不足/);
  assert.match(describeOutcome("plan_incomplete").hint, /routes\[\]\.params/);
  // 模型路由被实测全部打掉：断言没有变成覆盖，不能 exit 0
  assert.match(describeOutcome("scout_routes_unverified").title, /未通过运行期实测/);
  assert.match(describeOutcome("scout_routes_unverified").hint, /openapi\.file/);

  const blocked = describeOutcome("no_patchable_candidates");
  assert.equal(blocked.outcome, "vulnerable_unfixed");
  assert.equal(blocked.kind, "blocked");
  assert.equal(blocked.exitCode, 1, "证据成立但需人工修复要阻断门禁");

  // 写回冲突：原工作区没被改，但补丁基线过期（Host 数字码在 failSession 已归一为符号名）
  const conflict = describeOutcome("conflict");
  assert.equal(conflict.outcome, "vulnerable_unfixed");
  assert.equal(conflict.kind, "blocked");
  assert.equal(conflict.exitCode, 1);
  assert.equal(conflict.title, "工作区已变化，补丁未写回");
  assert.match(conflict.hint, /git apply --check/);
  assert.match(conflict.hint, /原文件未被修改/);

  // 真正的执行失败保持原语义
  for (const code of ["login_rejected", "target_not_ready", "internal", undefined]) {
    const pres = describeOutcome(code);
    assert.equal(pres.outcome, "failed", `${code} 应归为 failed`);
    assert.equal(pres.kind, "failed");
    assert.equal(pres.exitCode, 2);
    assert.equal(pres.title, "执行失败");
  }
});

test("coverageSummary: 讲清覆盖与不覆盖，并点名 Java/Spring 边界", () => {
  const text = coverageSummary();
  assert.equal(COVERAGE.kinds.length, 13);
  assert.ok(COVERAGE.stacks.length >= 7);
  assert.match(text, /对象级越权/);
  assert.match(text, /SSRF/);
  assert.match(text, /文件上传/);
  assert.match(text, /JWT/);
  assert.match(text, /业务逻辑/);
  assert.match(text, /CORS/);
  assert.match(text, /CSRF/);
  assert.match(text, /XSS/);
  assert.match(text, /FastAPI/);
  assert.match(text, /Java \/ Spring Boot/);
  assert.match(text, /routes/);
});

/** 会话视图的最小骨架：只填 buildReport 会用到的字段 */
function makeCtx(state, findings = []) {
  return {
    sessionId: "sess-coverage",
    gate: false,
    targetConfig: null,
    view: {
      projectRoot: "D:/tmp/spring-demo",
      projectName: "spring-demo",
      startedAt: 1,
      state,
      findings,
      evidence: [],
      phases: {},
      targets: {},
      patch: null,
      supabase: null,
      blackbox: null,
      acceptance: null,
      llm: null,
      error: null,
    },
  };
}

test("buildReport: no_candidates 的终态标签不写「执行出错」，报告给出覆盖清单", () => {
  const error = {
    code: "no_candidates",
    message: "已扫描 2 个源文件，已识别 3 条路由但未发现可探测的安全候选",
    kind: "coverage",
    outcome: "no_candidates",
    title: "已扫描但未发现可探测候选",
    semanticHint: "引擎正常结束（exit 0）",
    hint: "在 guardbuild.json 声明 routes",
  };
  const { json, markdown } = buildReport(makeCtx("error"), {
    outcome: "no_candidates",
    exitCode: 0,
    error,
    state: "error",
  });
  assert.equal(json.session.state, "error", "内部状态仍记为 error（终态判定与槽位释放依赖它）");
  assert.equal(json.session.stateLabel, "已扫描 · 无安全候选");
  assert.match(markdown, /已识别出 HTTP 路由，但未发现可探测候选（exit 0，覆盖边界而非安全结论）/);
  assert.match(markdown, /不是执行失败/);
  assert.match(markdown, /不是「系统安全」的结论/);
  assert.match(markdown, /Java \/ Spring Boot/);
  assert.doesNotMatch(markdown, /诊断执行失败/);
});

test("buildReport: inconclusive（没测到）exit 2 且明确写「无法证明」，不写成已测未复现", () => {
  for (const [code, label, headlineRe] of [
    ["no_endpoints", "未识别路由 · 无法证明", /未识别到任何 HTTP 路由（exit 2，无法证明）/],
    ["attack_inconclusive", "攻击用例未跑全 · 无法证明", /攻击用例未跑全（exit 2，无法证明）/],
    ["plan_incomplete", "无法构造探测请求 · 无法证明", /候选端点无法构造探测请求（exit 2，无法证明）/],
    ["scout_routes_unverified", "模型路由全部未命中 · 无法证明", /模型给出的路由经运行期实测全部不成立（exit 2，无法证明）/],
  ]) {
    const error = { code, message: "无法完成覆盖", kind: "inconclusive", outcome: "inconclusive" };
    const { json, markdown } = buildReport(makeCtx("error"), {
      outcome: "inconclusive",
      exitCode: 2,
      error,
      state: "error",
    });
    assert.equal(json.verdict.exitCode, 2, `${code} 必须 exit 2`);
    assert.equal(json.session.stateLabel, label);
    assert.match(markdown, headlineRe);
    assert.match(markdown, /本轮\*\*无法证明\*\*/);
    assert.doesNotMatch(markdown, /已测用例未复现/, `${code} 不得混淆成「已测未复现」`);
  }
});

test("buildReport: 真实执行失败仍显示「执行出错」", () => {
  const error = { code: "login_rejected", message: "登录被拒绝", kind: "failed", title: "执行失败" };
  const { json, markdown } = buildReport(makeCtx("error"), {
    outcome: "failed",
    exitCode: 2,
    error,
    state: "error",
  });
  assert.equal(json.session.stateLabel, "执行出错");
  assert.match(markdown, /执行失败（login_rejected）/);
});

test("buildReport: 写回冲突给出「原工作区未修改 + 两条落地方式」，不套用人工修复模板文案", () => {
  const ctx = makeCtx("error");
  ctx.view.patch = {
    hash: "abc123456789",
    diff: "--- a/src/app.js\n+++ b/src/app.js\n+if (order.userId !== auth.user.id) return json(res, 403);",
    files: [{ path: "src/app.js", insertions: 1, deletions: 0 }],
    worktree: "D:/tmp/gb/worktrees/sess-coverage/fix-1",
    status: "pending_review",
    lineCount: 2,
    llm: null,
    fixLoop: null,
  };
  const error = {
    code: "conflict",
    message: "补丁无法干净地应用到工作区（可能文件已被修改）: error: patch failed: src/app.js:12",
    kind: "blocked",
    outcome: "vulnerable_unfixed",
    title: "工作区已变化，补丁未写回",
    semanticHint: "Host 在写回预检（git apply --check）阶段拒绝，原文件未被修改",
  };
  const { json, markdown } = buildReport(ctx, { outcome: "vulnerable_unfixed", exitCode: 1, error, state: "error" });
  assert.equal(json.session.stateLabel, "补丁未写回 · 工作区已变化");
  assert.equal(json.error.code, "conflict");
  assert.match(markdown, /写回预检未通过/);
  assert.match(markdown, /原工作区\*\*未被修改\*\*/);
  assert.match(markdown, /自行把上面的 Diff 合并/);
  assert.doesNotMatch(markdown, /静态候选中没有可自动修复的对象级越权端点/, "冲突不是「候选不可修复」，不得套用人工修复模板文案");
});
