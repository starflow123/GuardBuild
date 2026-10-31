import test from "node:test";
import assert from "node:assert/strict";
import { buildReport, sanitizeErrorDetails } from "../lib/report.mjs";

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

test("身份基础：会话建立端点与回读结论写进 report.json 与 markdown", () => {
  const ctx = ctxFor({ patchStatus: "verified" });
  ctx._identityReport = {
    configured: ["att1", "org1"],
    loggedIn: [
      { name: "att1", role: "attendee", endpoint: "/auth/attendee/login", credentialKind: "cookie" },
      { name: "org1", role: "organiser", endpoint: "/auth/organiser/login", credentialKind: "cookie" },
    ],
    sessionVerification: {
      status: "verified",
      probePath: "/api/me",
      loginEndpoint: "/auth/attendee/login",
      identities: [
        { identity: "att1", anonStatus: 401, sessStatus: 200 },
        { identity: "org1", anonStatus: 401, sessStatus: 200 },
      ],
    },
  };
  const { json, markdown } = buildReport(ctx, { outcome: "vulnerable", exitCode: 1 });
  assert.equal(json.summary.identities.loggedIn.length, 2);
  assert.equal(json.summary.identities.sessionVerification.status, "verified");
  assert.match(markdown, /身份会话：2\/2 建立（att1→`\/auth\/attendee\/login`、org1→`\/auth\/organiser\/login`）/);
  assert.match(markdown, /会话真实性：已回读验证（探针 `\/api\/me`：att1 匿名 401→会话 200、org1 匿名 401→会话 200）/);
});

test("身份基础：引擎自举建号与造数据写进报告，口令明文一律不落产物", () => {
  const ctx = ctxFor({ patchStatus: "verified" });
  ctx._identityReport = {
    configured: ["alice", "bob"],
    loggedIn: [
      { name: "alice", role: "user", endpoint: "/api/login", credentialKind: "token" },
      { name: "bob", role: "user", endpoint: "/api/login", credentialKind: "token" },
    ],
    sessionVerification: { status: "verified", probePath: "/api/profile", identities: [] },
    bootstrap: { endpoint: "/api/register", endpointSource: "contract", unavailableReason: null, accounts: [], seeds: [] },
  };
  ctx._identityBootstrap = {
    byPhase: {
      pre: {
        phase: "pre",
        endpoint: "/api/register",
        endpointSource: "contract",
        unavailableReason: null,
        candidates: [],
        accounts: [
          { name: "alice", trigger: "no-declared-password", verdict: "created", status: 201, generated: true, endpoint: "/api/register" },
          { name: "bob", trigger: "no-declared-password", verdict: "created", status: 201, generated: true, endpoint: "/api/register" },
        ],
        seeds: [
          { identity: "alice", path: "/api/orders", status: 201, verdict: "written" },
          { identity: "bob", path: "/api/orders", status: 201, verdict: "written" },
        ],
        secretProtection: { alice: "ok", bob: "ok" },
      },
    },
  };
  const { json, markdown } = buildReport(ctx, { outcome: "vulnerable", exitCode: 1 });
  const ib = json.summary.identities.bootstrap;
  assert.equal(ib.attempted, true);
  assert.equal(ib.registered, 2);
  assert.equal(ib.seeded, 2);
  assert.deepEqual(ib.byPhase[0].accounts.map((a) => a.passwordSource), ["engine-generated", "engine-generated"]);
  assert.match(markdown, /身份自举：本轮由目标注册接口 `\/api\/register`（contract）建号 2 个/);
  assert.match(markdown, /口令由引擎随机生成、只进 Host 保险库（不落配置\/报告\/证据库）/);
  assert.match(markdown, /写入测试数据 2 条/);
  // 报告里不能出现任何形如引擎口令的串
  assert.doesNotMatch(JSON.stringify(json), /"password"/, "报告 JSON 不该带口令字段");
});

test("身份基础：静态建号候选有多个时报告写明引擎不猜", () => {
  const ctx = ctxFor({ patchStatus: "verified" });
  ctx._identityReport = {
    configured: ["alice"],
    loggedIn: [{ name: "alice", role: "user", endpoint: "/api/login", credentialKind: "token" }],
    sessionVerification: { status: "verified", probePath: "/api/profile", identities: [] },
  };
  ctx._identityBootstrap = {
    byPhase: {
      pre: {
        phase: "pre",
        endpoint: null,
        endpointSource: null,
        unavailableReason: "static-ambiguous",
        candidates: ["/api/register", "/api/users/create"],
        accounts: [],
        seeds: [],
        secretProtection: {},
      },
    },
  };
  const { markdown } = buildReport(ctx, { outcome: "not_reproducible", exitCode: 0 });
  assert.match(markdown, /身份自举：未参与（静态识别到 2 个建号候选，引擎不猜：\/api\/register、\/api\/users\/create）/);
});

test("身份基础：回读未执行时如实标注原因，不写成已验证", () => {
  const ctx = ctxFor({ patchStatus: "verified" });
  ctx._identityReport = {
    configured: ["u1", "u2", "u3"],
    loggedIn: [{ name: "u1", role: null, endpoint: "/login", credentialKind: "token" }],
    sessionVerification: {
      status: "skipped",
      probePath: null,
      reason: "静态分析没有「无参数、只读、需登录」的接口可作探针",
      identities: ["u1"],
    },
  };
  const { json, markdown } = buildReport(ctx, { outcome: "vulnerable", exitCode: 1 });
  assert.equal(json.summary.identities.sessionVerification.status, "skipped");
  assert.match(markdown, /身份会话：1\/3 建立/);
  assert.match(markdown, /会话真实性：未回读（静态分析没有/);
  assert.doesNotMatch(markdown, /会话真实性：已回读验证/);
});

test("未建立任何会话：身份段不出现，报告不臆造身份结论", () => {
  const ctx = ctxFor({ patchStatus: "pending_review" });
  const { json, markdown } = buildReport(ctx, { outcome: "vulnerable", exitCode: 1 });
  assert.equal(json.summary.identities, null);
  assert.doesNotMatch(markdown, /身份会话/);
});

const startError = () => ({
  code: "target_not_ready",
  message: "目标进程未在超时内就绪",
  hint: "请检查启动契约",
  outcome: "failed",
  details: {
    cwd: "D:/tmp/shop",
    start: {
      cmd: "node",
      args: ["server.js"],
      env: { SESSION_SECRET: "super-secret-value-123", DATABASE_URL: "postgres://u:p@h/d" },
    },
    output: ["raw log line 1", "raw log line 2 token=abcdefghijklmnop0123456789"],
    diagnosis: {
      code: "missing_env",
      exitCode: 1,
      hint: "缺少环境变量",
      matched: "SESSION_SECRET is not set",
      excerpt: "booting…\nError: SESSION_SECRET is not set",
    },
  },
});

test("启动失败：报告给出诊断码与脱敏后的启动输出尾部，原始日志与环境变量值不入产物", () => {
  const ctx = ctxFor({ patchStatus: null });
  const { json, markdown } = buildReport(ctx, { outcome: "failed", exitCode: 2, error: startError(), state: "error" });
  assert.match(markdown, /启动诊断（missing_env，退出码 1）：命中原文「`SESSION_SECRET is not set`」/);
  assert.match(markdown, /启动输出尾部（已脱敏：凭据键值与长随机串打码）：/);
  assert.match(markdown, /Error: SESSION_SECRET is not set/, "崩溃原文必须出现在报告里");
  assert.equal(json.error.details.output, undefined, "原始日志数组不写进 report.json");
  assert.deepEqual(json.error.details.start.env, ["SESSION_SECRET", "DATABASE_URL"], "只留变量名，不留值");
  assert.equal(json.error.details.diagnosis.code, "missing_env", "诊断结构保留");
});

test("环境变量名单二次脱敏不退化成下标（会话事件已脱敏，报告再脱敏一次）", () => {
  const once = sanitizeErrorDetails({ start: { cmd: "node", env: { PORT: "3000", SESSION_SECRET: "s3cr3t" } } });
  assert.deepEqual(once.start.env, ["PORT", "SESSION_SECRET"]);
  const twice = sanitizeErrorDetails(once);
  assert.deepEqual(twice.start.env, ["PORT", "SESSION_SECRET"], "第二次仍要保留变量名");
  assert.deepEqual(sanitizeErrorDetails({ start: { env: ["PORT=3000", "SESSION_SECRET=s3cr3t"] } }).start.env, ["PORT", "SESSION_SECRET"]);
  assert.doesNotMatch(JSON.stringify(twice), /3000|s3cr3t/, "任何一轮都不留值");
});

test("启动失败但进程没输出日志：如实说明，不留空壳段落", () => {
  const ctx = ctxFor({ patchStatus: null });
  const err = startError();
  err.details.diagnosis.excerpt = "";
  err.details.diagnosis.matched = null;
  const { markdown } = buildReport(ctx, { outcome: "failed", exitCode: 2, error: err, state: "error" });
  assert.match(markdown, /未命中已知诊断规则/);
  assert.match(markdown, /目标进程未输出任何可记录的日志/);
});

test("正常裁决不带启动诊断时，报告不出现启动诊断段", () => {
  const ctx = ctxFor({ patchStatus: "verified" });
  const { markdown } = buildReport(ctx, { outcome: "vulnerable", exitCode: 1 });
  assert.doesNotMatch(markdown, /启动诊断（/);
});

test("LLM 启动候选：失败候选的命中原文与脱敏输出尾部进报告", () => {
  const ctx = ctxFor({ patchStatus: null });
  ctx.view.llm = {
    used: true,
    model: "deepseek-chat",
    startAttempts: [
      {
        index: 1,
        total: 2,
        cmd: "node",
        args: ["server.js"],
        ok: false,
        code: "target_not_ready",
        diagnosisCode: "missing_env",
        exitCode: 1,
        hint: "缺少环境变量",
        matched: "SESSION_SECRET is not set",
        excerpt: "booting…\nError: SESSION_SECRET is not set",
        durationMs: 1200,
      },
      { index: 2, total: 2, cmd: "node", args: ["app.js"], ok: true, durationMs: 900 },
    ],
  };
  const { json, markdown } = buildReport(ctx, { outcome: "no_candidates", exitCode: 0 });
  assert.equal(json.llm.startAttempts[0].matched, "SESSION_SECRET is not set");
  assert.match(json.llm.startAttempts[0].excerpt, /SESSION_SECRET is not set/);
  assert.equal(json.llm.startAttempts[1].excerpt, null);
  assert.match(markdown, /失败候选 1\/2（`node server\.js`）命中原文「`SESSION_SECRET is not set`」/);
  assert.match(markdown, /booting…\nError: SESSION_SECRET is not set/);
});
