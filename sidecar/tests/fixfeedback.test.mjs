import { test } from "node:test";
import assert from "node:assert/strict";
import { buildFixFeedback, feedbackDigest } from "../lib/fixfeedback.mjs";
import { matchDiagnostics } from "../lib/autostart.mjs";

function ctxWith(logs, { throwLogs = false } = {}) {
  const calls = [];
  return {
    calls,
    tokens: { spawn: "tok-spawn" },
    procs: { worktree: { pid: 4211 } },
    rpc: {
      async request(method, params) {
        calls.push({ method, params });
        if (method === "proc.logs") {
          if (throwLogs) throw new Error("宿主拒绝：作用域过期");
          return logs;
        }
        throw new Error(`未预期的调用 ${method}`);
      },
    },
  };
}

const post = {
  evidence: [
    { caseName: "attack-idor-read", caseCategory: "attack", verdict: "regressed", actual: "200 + 他人订单", response: { status: 200 } },
    { caseName: "business-owner-read", caseCategory: "business", verdict: "passed", actual: "200", response: { status: 200 } },
    { caseName: "attack-anon-read", caseCategory: "attack", verdict: "inconclusive", actual: "401 但无拒绝语义", response: { status: 401 } },
  ],
};

test("buildFixFeedback: 带上失败用例、隔离实例日志尾部与上一轮 diff", async () => {
  const ctx = ctxWith({
    lines: [
      { stream: "stdout", line: "server listening on 127.0.0.1:8123" },
      { stream: "stderr", line: "TypeError: cannot read property 'id' of undefined" },
    ],
    exited: false,
    exitCode: null,
  });
  const fb = await buildFixFeedback(ctx, {
    post,
    verdict: { attackRegressed: 1, businessRegressed: 0 },
    round: 1,
    previousDiff: "--- a/src/orders.js\n+++ b/src/orders.js\n+if (order.userId !== auth.user.id) throw new Error('403');\n",
  });
  assert.equal(fb.round, 1);
  assert.equal(fb.attack_regressed, 1);
  assert.equal(fb.failed_cases.length, 2);
  assert.equal(fb.failed_cases[0].case, "attack-idor-read");
  assert.equal(fb.failed_cases[0].status, 200);
  assert.equal(fb.target_log_tail.length, 2);
  assert.match(fb.target_log_tail.join("\n"), /stderr: TypeError/);
  assert.ok(fb.previous_diff.includes("+if (order.userId"));
  assert.equal(fb.target_exit, null);
  assert.match(fb.instruction, /previous_diff/);
  // 只走 proc.logs，且不越权带别的 token
  assert.deepEqual(ctx.calls.map((c) => c.method), ["proc.logs"]);
  assert.equal(ctx.calls[0].params.token, "tok-spawn");
  assert.equal(ctx.calls[0].params.pid, 4211);
});

test("buildFixFeedback: 日志命中诊断码时回喂诊断（复用启动诊断规则表）", async () => {
  const ctx = ctxWith({
    lines: [
      { stream: "stderr", line: "Error: Cannot find module 'jsonwebtoken'" },
      { stream: "stderr", line: "SyntaxError: Unexpected token )" },
    ],
    exited: true,
    exitCode: 1,
  });
  const fb = await buildFixFeedback(ctx, { post, verdict: { attackRegressed: 1, businessRegressed: 1 }, round: 2 });
  assert.deepEqual(
    fb.diagnostics.map((d) => d.code).sort(),
    ["missing_dependency", "syntax_error"]
  );
  assert.deepEqual(fb.target_exit, { exitCode: 1 });
  assert.match(fb.instruction, /target_log_tail/);
});

test("buildFixFeedback: 拿不到日志不得阻断修复循环", async () => {
  const ctx = ctxWith(null, { throwLogs: true });
  const fb = await buildFixFeedback(ctx, { post, verdict: { attackRegressed: 1, businessRegressed: 0 }, round: 1 });
  assert.deepEqual(fb.target_log_tail, []);
  assert.deepEqual(fb.diagnostics, []);
  assert.equal(fb.previous_diff, null);
  assert.equal(fb.target_exit, null);
});

test("buildFixFeedback: 无隔离实例（黑盒/Supabase 轮次）时不调用 proc.logs", async () => {
  const ctx = ctxWith({ lines: [], exited: false, exitCode: null });
  ctx.procs = {};
  const fb = await buildFixFeedback(ctx, { post, verdict: { attackRegressed: 0, businessRegressed: 0 }, round: 1 });
  assert.deepEqual(ctx.calls, []);
  assert.deepEqual(fb.target_log_tail, []);
});

test("buildFixFeedback: 日志预算从尾部保留（越接近失败现场越重要）", async () => {
  const lines = Array.from({ length: 60 }, (_, i) => ({ stream: "stdout", line: `log ${i} ${"x".repeat(200)}` }));
  const ctx = ctxWith({ lines, exited: false, exitCode: null });
  const fb = await buildFixFeedback(ctx, { post, verdict: { attackRegressed: 1, businessRegressed: 0 }, round: 1 });
  assert.ok(fb.target_log_tail.length <= 20);
  assert.ok(fb.target_log_tail.join("\n").length <= 4_000);
  assert.match(fb.target_log_tail[fb.target_log_tail.length - 1], /log 59/);
});

test("buildFixFeedback: 汇总没回归但归因不成立的入口要单独回喂", async () => {
  const ctx = ctxWith({ lines: [], exited: false, exitCode: null });
  const fb = await buildFixFeedback(ctx, {
    post: { evidence: [] },
    verdict: {
      attackRegressed: 0,
      businessRegressed: 0,
      attribution: {
        failing: [
          { candidate: "GET /api/orders/:id", status: "unverified", reason: "1/1 条修复前已复现的用例未进入修复后验收" },
          { candidate: "POST /api/orders/:id/cancel", status: "still_vulnerable", reason: "修复后仍有 1/1 条越权用例复现" },
        ],
      },
    },
    round: 1,
    previousDiff: "@@ -1 +1 @@\n+x\n",
  });
  assert.deepEqual(
    fb.unattributed_candidates.map((u) => `${u.candidate}:${u.status}`),
    ["GET /api/orders/:id:unverified", "POST /api/orders/:id/cancel:still_vulnerable"]
  );
  assert.match(fb.instruction, /unattributed_candidates 中列出的入口必须自己完成翻转/);
  assert.equal(feedbackDigest(fb).unattributed, 2);
});

test("feedbackDigest: 只留计数与诊断码，不带日志原文", async () => {
  const ctx = ctxWith({
    lines: [{ stream: "stderr", line: "ECONNREFUSED 127.0.0.1:5432" }],
    exited: true,
    exitCode: 1,
  });
  const fb = await buildFixFeedback(ctx, {
    post,
    verdict: { attackRegressed: 2, businessRegressed: 0 },
    round: 1,
    previousDiff: "@@ -1 +1 @@\n+secret-ish-diff\n",
  });
  const d = feedbackDigest(fb);
  assert.equal(d.round, 1);
  assert.equal(d.failedCases, 2);
  assert.equal(d.logLines, 1);
  assert.equal(d.targetExited, true);
  assert.equal(d.targetExitCode, 1);
  assert.deepEqual(d.diagnostics, ["dependency_unreachable"]);
  assert.ok(d.diffChars > 0);
  assert.equal(JSON.stringify(d).includes("ECONNREFUSED"), false);
});

test("matchDiagnostics: 返回全部命中并可限量", () => {
  const hits = matchDiagnostics(["EADDRINUSE: address already in use :::3000", "Missing script: serve"]);
  assert.deepEqual(hits.map((h) => h.code), ["port_in_use", "script_missing"]);
  assert.equal(matchDiagnostics(["nothing interesting"]).length, 0);
  assert.equal(matchDiagnostics(["EADDRINUSE", "Cannot find module 'a'"], { limit: 1 }).length, 1);
});
