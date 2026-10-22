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
