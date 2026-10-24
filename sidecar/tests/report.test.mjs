import test from "node:test";
import assert from "node:assert/strict";
import { buildReport } from "../lib/report.mjs";

// 写回/回滚是真实工作区的终态，报告必须如实反映「补丁已落地 / 已撤销」，
// 不能停在「等待写回」——否则 artifact 与视图、数据库三处口径不一致。

const recheck = (pass) => ({
  pass,
  attackBlocked: pass ? 6 : 2,
  attackTotal: 6,
  businessPassed: 9,
  businessTotal: 9,
  variantCounted: 4,
  variantSkipped: 0,
  claimedCount: 2,
  blockedCount: pass ? 2 : 1,
  unverifiedCount: 0,
  stillVulnerableCount: pass ? 0 : 1,
  phase: "post_writeback",
  at: Date.parse("2026-10-24T10:00:00Z"),
  attribution: {
    claimedCount: 2,
    blockedCount: pass ? 2 : 1,
    unverifiedCount: 0,
    stillVulnerableCount: pass ? 0 : 1,
    rows: [
      {
        candidate: "GET /api/orders/:id",
        claimed: true,
        preReproCases: 2,
        postCases: pass ? 2 : 1,
        file: "src/routes/orders.js",
        line: 12,
        locality: "same_file",
        hunksInFile: 1,
        hunkDistance: 3,
        status: pass ? "blocked" : "still_vulnerable",
        reason: null,
      },
      {
        candidate: "DELETE /api/orders/:id",
        claimed: true,
        preReproCases: 2,
        postCases: 2,
        file: "src/routes/orders.js",
        line: 30,
        locality: "same_file",
        hunksInFile: 1,
        hunkDistance: 5,
        status: "blocked",
        reason: null,
      },
    ],
  },
});

function ctxFor({ patchStatus, pass = true, evidence = [], rollback = null }) {
  const postWriteback = [
    {
      phase: "post_writeback",
      caseId: "attack-read-foreign-obj1",
      name: "跨用户读取订单",
      category: "idor",
      identity: "user_a",
      verdict: pass ? "blocked" : "vulnerable",
      evidenceGrade: "strong",
      actual: "403",
      decision: { routeKey: "orders.read", decision: "deny", checks: ["owner"] },
    },
  ];
  return {
    sessionId: "s_test",
    gate: false,
    targetConfig: { start: { cmd: "node", args: ["server.js"], readyPattern: "listening" }, startSource: "config" },
    view: {
      projectRoot: "D:/tmp/shop",
      projectName: "shop",
      startedAt: 1,
      state: patchStatus === "rolled_back" ? "rolled_back" : "applied",
      findings: [],
      evidence: [...evidence, ...postWriteback],
      phases: { post_writeback: { attackTotal: 6, attackBlocked: pass ? 6 : 2 } },
      targets: {},
      patch: {
        hash: "abc123def4567890",
        diff: "diff --git a/src/routes/orders.js b/src/routes/orders.js\n",
        files: [{ path: "src/routes/orders.js", insertions: 4, deletions: 1 }],
        worktree: "D:/wt/fix-1",
        status: patchStatus,
        lineCount: 5,
        strategy: "llm-coding-agent",
        autoVerify: true,
      },
      supabase: null,
      blackbox: null,
      acceptance: {
        pass: true,
        attackBlocked: 6,
        attackTotal: 6,
        businessPassed: 9,
        businessTotal: 9,
        variantCounted: 4,
        variantSkipped: 0,
        attribution: recheck(true).attribution,
        writebackRecheck: recheck(pass),
      },
      llm: null,
      bootstrap: null,
      rollback,
      error: null,
    },
  };
}

test("写回后复核通过：报告落 written_back，含真实工作区复核段与证据", () => {
  const ctx = ctxFor({
    patchStatus: "written_back",
    rollback: { available: true, backupId: "bk_20261024", files: ["src/routes/orders.js"] },
  });
  const { json, markdown } = buildReport(ctx, { outcome: "vulnerable", exitCode: 1, patchStatus: "written_back", state: "applied" });

  assert.equal(json.verdict.patchStatus, "written_back");
  assert.match(json.verdict.headline, /已写回真实工作区，写回后复攻通过/);
  assert.equal(json.summary.acceptance.writebackRecheck.pass, true);
  assert.equal(json.summary.evidence.postWriteback, 1);
  assert.equal(json.rollback.backupId, "bk_20261024");
  assert.equal(json.patch.status, "written_back");

  assert.match(markdown, /写回后复核（真实工作区）/);
  assert.match(markdown, /攻击阻断 6\/6，业务保持 9\/9 → \*\*通过\*\*/);
  assert.match(markdown, /写回后证据（post_writeback，1 条）/);
  assert.match(markdown, /## 写回与回滚/);
  assert.match(markdown, /已写回真实工作区/);
  assert.match(markdown, /bk_20261024/);
  assert.match(markdown, /`git diff` 审查/);
});

test("写回后复核未通过：报告点名建议回滚，不复用隔离验收的通过结论", () => {
  const ctx = ctxFor({
    patchStatus: "writeback_recheck_failed",
    pass: false,
    rollback: { available: true, backupId: "bk_20261024", files: ["src/routes/orders.js"] },
  });
  const { json, markdown } = buildReport(ctx, {
    outcome: "vulnerable",
    exitCode: 1,
    patchStatus: "writeback_recheck_failed",
    state: "applied",
  });

  assert.match(json.verdict.headline, /写回后复攻未通过，建议回滚/);
  assert.equal(json.summary.acceptance.writebackRecheck.pass, false);
  assert.match(markdown, /攻击阻断 2\/6，业务保持 9\/9 → \*\*未通过\*\*/);
  assert.match(markdown, /仍可越权/);
  assert.match(markdown, /建议立即执行「回滚写回」/);
});

test("写回后复核未完成：报告要求人工复测", () => {
  const ctx = ctxFor({ patchStatus: "writeback_recheck_incomplete" });
  ctx.view.acceptance.writebackRecheck = null;
  const { json, markdown } = buildReport(ctx, {
    outcome: "vulnerable",
    exitCode: 1,
    patchStatus: "writeback_recheck_incomplete",
    state: "applied",
  });

  assert.match(json.verdict.headline, /写回后复攻未能完成，需人工复测/);
  assert.match(markdown, /请手动重启项目并复测/);
  assert.match(markdown, /写回后复核未完成/);
});

test("回滚终态：报告说明工作区已恢复，不再声称已写回生效", () => {
  const ctx = ctxFor({
    patchStatus: "rolled_back",
    rollback: {
      available: false,
      backupId: "bk_20261024",
      files: ["src/routes/orders.js"],
      restored: ["src/routes/orders.js"],
      conflicts: [],
    },
  });
  const { json, markdown } = buildReport(ctx, { outcome: "vulnerable", exitCode: 1, patchStatus: "rolled_back", state: "rolled_back" });

  assert.match(json.verdict.headline, /现已回滚，工作区恢复原状/);
  assert.equal(json.patch.status, "rolled_back");
  assert.match(markdown, /已回滚（工作区恢复写回前）/);
  assert.match(markdown, /已恢复文件/);
  assert.match(markdown, /漏洞仍然存在，需重新修复/);
  assert.doesNotMatch(markdown, /写回后复攻通过/);
});

test("gate 未写回：报告不出现写回/回滚段，仍给出隔离补丁指引", () => {
  const ctx = ctxFor({ patchStatus: "pending_review" });
  ctx.view.acceptance = null;
  ctx.view.evidence = [];
  const { json, markdown } = buildReport(ctx, { outcome: "vulnerable", exitCode: 1, patchStatus: "verified", state: "writeback_pending" });

  assert.match(json.verdict.headline, /gate 未写回工作区/);
  assert.doesNotMatch(markdown, /## 写回与回滚/);
  assert.doesNotMatch(markdown, /写回后复核/);
  assert.match(markdown, /gate 未写回原工作区/);
});
