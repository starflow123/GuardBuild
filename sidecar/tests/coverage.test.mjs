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

  const blocked = describeOutcome("no_patchable_candidates");
  assert.equal(blocked.outcome, "vulnerable_unfixed");
  assert.equal(blocked.kind, "blocked");
  assert.equal(blocked.exitCode, 1, "证据成立但需人工修复要阻断门禁");

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
  assert.equal(COVERAGE.kinds.length, 6);
  assert.ok(COVERAGE.stacks.length >= 7);
  assert.match(text, /对象级越权/);
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
    message: "已扫描 2 个源文件，未发现可探测的安全候选",
    kind: "coverage",
    outcome: "no_candidates",
    title: "未命中当前覆盖范围",
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
  assert.equal(json.session.stateLabel, "未命中覆盖范围");
  assert.match(markdown, /未命中当前覆盖范围（exit 0，非执行失败）/);
  assert.match(markdown, /不是执行失败/);
  assert.match(markdown, /Java \/ Spring Boot/);
  assert.doesNotMatch(markdown, /诊断执行失败/);
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
