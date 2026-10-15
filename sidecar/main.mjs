#!/usr/bin/env node
/**
 * GuardBuild 编排侧车（Sidecar）。
 *
 * 职责：任务编排与决策（分析 → 探测 → 补丁 → 审批 → 验收 → 写回/回滚），
 * 全部实际能力（文件/进程/网络/git/凭证）都通过 JSON-RPC 请求 Rust Host 执行，
 * Sidecar 自身不直接触碰用户文件系统、进程与凭据。
 *
 * 通信：stdin/stdout NDJSON JSON-RPC 2.0（双向）。
 */
import path from "node:path";
import { RpcPeer } from "./lib/rpc.mjs";
import { EvidenceStore } from "./lib/db.mjs";
import { StateMachine } from "./lib/statemachine.mjs";
import { analyzeProject } from "./lib/analyzer.mjs";
import { buildProbePlan, loadIdentities } from "./lib/planner.mjs";
import { loadTargetConfig, DEFAULT_START, startUsesPortSlot, renderStart } from "./lib/targetconfig.mjs";
import { parsePortFromLine, stripAnsi } from "./lib/readyline.mjs";
import { runPhase, ProbeError } from "./lib/probe.mjs";
import { createPatch, writebackPatch, rollbackWorkspace, PatchError } from "./lib/patcher.mjs";
import { emitReport } from "./lib/report.mjs";
import {
  PROTOCOL_VERSION,
  RPC_TO_HOST,
  RPC_TO_SIDECAR,
  NOTIFY_TO_HOST,
  STATE,
  STATE_LABELS,
  SCOPE_KINDS,
  SEVERITY,
  VERDICT,
  CASE_CATEGORY,
  shortId,
} from "../shared/protocol.mjs";

class SessionError extends Error {
  constructor(message, { code = "session_failed", hint = null, details = null } = {}) {
    super(message);
    this.code = code;
    this.hint = hint;
    this.details = details;
  }
}
class CancelledError extends Error {
  constructor() {
    super("会话已被用户中止");
    this.code = "cancelled";
  }
}

function truncate(text, limit) {
  if (!text) return "";
  return text.length > limit ? `${text.slice(0, limit)}…（截断）` : text;
}

// ---------- 会话状态 ----------

let active = null; // 当前会话上下文

// 终态：到达这些状态后槽位可被释放。applied 仍保留 active 以支持回滚，
// 仅在新会话启动时才回收。
const TERMINAL_STATES = new Set([
  STATE.APPLIED,
  STATE.ROLLED_BACK,
  STATE.VERIFY_FAILED,
  STATE.ABORTED,
  STATE.ERROR,
]);

function endSession(ctx) {
  if (active !== ctx) return;
  try {
    ctx.db.close();
  } catch {
    /* ignore */
  }
  active = null;
}

function createCtx(params) {
  const dataDir = process.env.GUARDBUILD_DATA_DIR || ".";
  const db = new EvidenceStore(`${dataDir}/guardbuild.db`);
  const ctx = {
    rpc: peer,
    db,
    sessionId: params.sessionId,
    projectRoot: params.projectRoot,
    projectName: params.projectRoot.replace(/[\\/]+$/, "").split(/[\\/]/).pop() ?? "project",
    tokens: { project: params.token },
    identities: loadIdentities(),
    loginConfig: null,
    analysis: null,
    plan: null,
    view: {
      sessionId: params.sessionId,
      projectRoot: params.projectRoot,
      projectName: null,
      state: STATE.STARTING,
      stateLabel: STATE_LABELS[STATE.STARTING],
      startedAt: Date.now(),
      updatedAt: Date.now(),
      findings: [],
      plan: null,
      evidence: [],
      phases: {},
      targets: {},
      patch: null,
      acceptance: null,
      error: null,
    },
    procs: {},
    cancelled: false,
    gate: params.gate === true,
    _lastDecisionSeq: 0,
  };
  ctx.view.projectName = ctx.projectName;
  ctx.sm = new StateMachine(STATE.STARTING, (from, to) => {
    ctx.db.updateSessionState(ctx.sessionId, to);
    ctx.view.state = to;
    ctx.view.stateLabel = STATE_LABELS[to] ?? to;
    emit(ctx, {
      kind: "state",
      severity: to === STATE.ERROR || to === STATE.VERIFY_FAILED ? SEVERITY.WARN : SEVERITY.INFO,
      message: `状态: ${STATE_LABELS[from] ?? from} → ${STATE_LABELS[to] ?? to}`,
      phase: to,
      data: { from, to },
    });
    pushView(ctx);
  });
  ctx.emit = (ev) => emit(ctx, ev);
  ctx.pushView = () => pushView(ctx);
  ctx.pushEvidence = (records) => {
    for (const r of records) ctx.view.evidence.push(compactEvidence(r));
    pushView(ctx);
  };
  return ctx;
}

function emit(ctx, { kind, severity = SEVERITY.INFO, message, phase = null, data = {} }) {
  const ev = { kind, severity, message, phase, data };
  try {
    ctx.rpc.notify(NOTIFY_TO_HOST.UI_EVENT, ev);
  } catch {
    /* 连接已断开 */
  }
  try {
    ctx.db.insertEvent({
      id: shortId("evt"),
      sessionId: ctx.sessionId,
      ts: Date.now(),
      kind,
      phase: phase ?? "",
      severity,
      message,
      data,
    });
  } catch {
    /* 落库失败不阻塞流程 */
  }
  process.stderr.write(`[${phase ?? "-"}/${severity}] ${message}\n`);
}

function pushView(ctx) {
  ctx.view.updatedAt = Date.now();
  try {
    ctx.rpc.notify(NOTIFY_TO_HOST.UI_STATE, ctx.view);
  } catch {
    /* ignore */
  }
}

function setState(ctx, to, note = "") {
  try {
    ctx.sm.transition(to, note);
  } catch (e) {
    emit(ctx, { kind: "state", severity: SEVERITY.WARN, message: `状态迁移异常: ${e.message}`, data: {} });
    ctx.sm.state = to;
    ctx.view.state = to;
    ctx.view.stateLabel = STATE_LABELS[to] ?? to;
    pushView(ctx);
  }
}

function ensureAlive(ctx) {
  if (ctx.cancelled) throw new CancelledError();
}

function compactEvidence(r) {
  return {
    id: r.id,
    phase: r.phase,
    caseId: r.caseId,
    category: r.caseCategory,
    name: r.caseName,
    identity: r.identity,
    method: r.method,
    endpoint: r.endpoint,
    expectation: r.expectation,
    actual: r.actual,
    verdict: r.verdict,
    evidenceGrade: r.evidenceGrade ?? null,
    crossProof: r.crossProof ?? null,
    impact: r.impact ?? null,
    request: r.request,
    response: {
      status: r.response.status,
      statusText: r.response.statusText,
      body: truncate(r.response.body, 1200),
      redacted: r.response.redacted,
      durationMs: r.response.durationMs,
    },
    decision: r.decision,
    createdAt: r.createdAt,
  };
}

// ---------- Host 能力封装 ----------

async function requestScope(ctx, kind, reason) {
  emit(ctx, { kind: "scope", severity: SEVERITY.INFO, message: `申请作用域: ${kind}（${reason}）`, data: { kind } });
  const res = await ctx.rpc.request(
    RPC_TO_HOST.AUTH_REQUEST_SCOPE,
    { token: ctx.tokens.project, kind, reason },
    { timeoutMs: 240_000 }
  );
  return res.token;
}

async function spawnTarget(ctx, { cwd, label, role = "target" }) {
  const start = ctx.targetConfig?.start ?? DEFAULT_START;
  // 契约声明了 ${GB_PORT} 槽位时，先分配空闲端口再渲染启动命令（支持多实例并存）
  let allocated = null;
  if (startUsesPortSlot(start)) {
    try {
      const res = await ctx.rpc.request(RPC_TO_HOST.PROC_ALLOC_PORT, { token: ctx.tokens.spawn }, { timeoutMs: 15_000 });
      allocated = res.port;
      emit(ctx, {
        kind: "process",
        severity: SEVERITY.INFO,
        message: `已分配空闲端口 ${allocated}（注入 ${label} 的 \${GB_PORT} 槽位）`,
        data: { port: allocated, label },
      });
    } catch (e) {
      throw new SessionError("无法分配空闲端口（启动契约使用了 ${GB_PORT} 槽位）", {
        code: "port_alloc_failed",
        hint: e.message,
        details: { cwd, label },
      });
    }
  }
  const { cmd, args, env } = renderStart(start, allocated);
  const res = await ctx.rpc.request(
    RPC_TO_HOST.PROC_SPAWN,
    {
      token: ctx.tokens.spawn,
      cmd,
      args,
      cwd,
      env,
      role,
    },
    { timeoutMs: 30_000 }
  );
  const wait = await ctx.rpc.request(
    RPC_TO_HOST.PROC_WAIT_OUTPUT,
    {
      token: ctx.tokens.spawn,
      pid: res.pid,
      pattern: start.readyPattern,
      timeoutMs: start.readyTimeoutMs,
    },
    { timeoutMs: start.readyTimeoutMs + 15_000 }
  );
  if (!wait.matched) {
    let lines = [];
    try {
      const logs = await ctx.rpc.request(RPC_TO_HOST.PROC_LOGS, { token: ctx.tokens.spawn, pid: res.pid, tail: 40 });
      lines = (logs.lines ?? []).map((l) => l.line);
    } catch {
      /* ignore */
    }
    await killProc(ctx, res.pid);
    throw new SessionError(`目标进程「${label}」未在超时内就绪`, {
      code: "target_not_ready",
      hint: `请确认目标项目可通过启动契约指定的命令在项目目录启动（缺省 \`node server.js\`，可用 guardbuild.json 覆盖），并输出就绪行（缺省 GB_LISTEN）`,
      details: { cwd, start, output: lines },
    });
  }
  // 就绪行解析优先（它是真实绑定端口）；解析不到但契约声明了槽位时回退到分配值
  let port = parsePortFromLine(wait.line);
  if (!port && allocated) port = allocated;
  if (!port) {
    await killProc(ctx, res.pid);
    throw new SessionError(`无法从就绪输出解析端口（${label}）`, {
      code: "port_parse_failed",
      hint: "可在 guardbuild.json 的 start.env 中使用 ${PORT: \"${GB_PORT}\"} 由宿主分配端口，无需依赖输出解析",
      details: { line: stripAnsi(wait.line) },
    });
  }
  const target = { pid: res.pid, port, url: `http://127.0.0.1:${port}` };
  emit(ctx, {
    kind: "process",
    severity: SEVERITY.SUCCESS,
    message: `目标实例「${label}」已就绪: ${target.url}（pid ${res.pid}）`,
    data: target,
  });
  return target;
}

async function killProc(ctx, pid) {
  if (!pid || !ctx.tokens.spawn) return;
  try {
    await ctx.rpc.request(RPC_TO_HOST.PROC_KILL, { token: ctx.tokens.spawn, pid }, { timeoutMs: 10_000 });
  } catch {
    /* 进程可能已退出 */
  }
}

async function shutdownProcs(ctx) {
  const entries = Object.values(ctx.procs).filter(Boolean);
  for (const p of entries) await killProc(ctx, p.pid);
  ctx.procs = {};
}

/** 按契约 prepare 步骤顺序执行（依赖安装/构建等），失败即中止会话 */
async function runPrepare(ctx, { cwd, label }) {
  const steps = ctx.targetConfig?.prepare ?? [];
  for (const [i, step] of steps.entries()) {
    ensureAlive(ctx);
    const stepCwd = path.isAbsolute(step.cwd) ? step.cwd : path.resolve(cwd, step.cwd);
    const cmdline = `${step.cmd} ${step.args.join(" ")}`.trim();
    emit(ctx, {
      kind: "prepare",
      severity: SEVERITY.INFO,
      message: `[${label}] 准备步骤 ${i + 1}/${steps.length}：${cmdline}`,
      phase: STATE.PROBING,
      data: { cmd: step.cmd, args: step.args, cwd: stepCwd },
    });
    const res = await ctx.rpc.request(
      RPC_TO_HOST.PROC_SPAWN,
      { token: ctx.tokens.spawn, cmd: step.cmd, args: step.args, cwd: stepCwd, role: "prepare" },
      { timeoutMs: 30_000 }
    );
    const wait = await ctx.rpc.request(
      RPC_TO_HOST.PROC_WAIT_EXIT,
      { token: ctx.tokens.spawn, pid: res.pid, timeoutMs: step.timeoutMs },
      { timeoutMs: step.timeoutMs + 15_000 }
    );
    if (!wait.exited || wait.exitCode !== 0) {
      let lines = [];
      try {
        const logs = await ctx.rpc.request(RPC_TO_HOST.PROC_LOGS, {
          token: ctx.tokens.spawn,
          pid: res.pid,
          tail: 40,
        });
        lines = (logs.lines ?? []).map((l) => l.line);
      } catch {
        /* ignore */
      }
      await killProc(ctx, res.pid);
      throw new SessionError(`[${label}] 准备步骤失败：${cmdline}`, {
        code: "prepare_failed",
        hint: wait.exited
          ? `该命令来自 guardbuild.json 的 prepare 配置（退出码 ${wait.exitCode}）；可在目标项目本地手动执行以复现错误`
          : `准备步骤超时（${step.timeoutMs}ms），可在 guardbuild.json 中提高该步骤的 timeoutMs`,
        details: { step, exitCode: wait.exitCode ?? null, output: lines },
      });
    }
    emit(ctx, {
      kind: "prepare",
      severity: SEVERITY.SUCCESS,
      message: `[${label}] 准备步骤完成：${cmdline}`,
      phase: STATE.PROBING,
      data: { exitCode: wait.exitCode },
    });
  }
}

function recordAcceptanceRows(ctx, phase, evidence) {
  for (const r of evidence) {
    try {
      ctx.db.insertAcceptance({
        id: shortId("ac"),
        sessionId: ctx.sessionId,
        caseId: r.caseId,
        category: r.caseCategory,
        name: r.caseName,
        expected: r.expectation,
        actual: r.actual,
        pass:
          r.caseCategory === CASE_CATEGORY.ATTACK ? r.verdict === VERDICT.BLOCKED : r.verdict === VERDICT.PASSED,
        evidenceId: r.id,
        createdAt: Date.now(),
      });
    } catch {
      /* ignore */
    }
  }
  return { phase, rows: evidence.length };
}

function acceptanceVerdict(summary) {
  const pass = summary.attackRegressed === 0 && summary.businessRegressed === 0 && summary.attackBlocked > 0;
  return {
    pass,
    attackBlocked: summary.attackBlocked,
    attackTotal: summary.attackBlocked + summary.attackRepro + summary.attackRegressed,
    businessPassed: summary.businessPassed,
    businessTotal: summary.businessTotal,
    counts: summary.counts,
  };
}

// ---------- 工作流各阶段 ----------

async function stageAnalyze(ctx) {
  ensureAlive(ctx);
  setState(ctx, STATE.ANALYZING);
  ctx.tokens.worktree = await requestScope(ctx, SCOPE_KINDS.WORKTREE_WRITE, "在隔离 Git worktree 中生成修复补丁");
  ctx.tokens.spawn = await requestScope(ctx, SCOPE_KINDS.PROC_SPAWN, "启动目标项目进程进行动态复现与验收");
  ctx.tokens.net = await requestScope(ctx, SCOPE_KINDS.NET_PROBE, "向本机回环地址发送诊断探测请求");

  emit(ctx, { kind: "analyze", severity: SEVERITY.INFO, message: `开始静态分析项目（${ctx.projectRoot}）`, data: {} });
  ctx.analysis = await analyzeProject(ctx);
  const cands = ctx.analysis.candidates ?? [];
  ctx.view.findings = cands.map((c) => ({
    id: shortId("fi"),
    method: c.method,
    path: c.fullPath ?? c.path,
    routePath: c.path,
    file: c.file,
    startLine: c.startLine,
    resource: c.resource,
    kind: c.kind,
    sinkCalls: c.sinkCalls,
    reason: "按对象 ID 取资源但未见归属校验（IDOR 静态线索）",
  }));
  emit(ctx, {
    kind: "analyze",
    severity: cands.length > 0 ? SEVERITY.WARN : SEVERITY.INFO,
    message:
      cands.length > 0
        ? `静态分析完成：扫描 ${ctx.analysis.fileCount} 个文件，发现 ${cands.length} 个对象级越权候选`
        : `静态分析完成：扫描 ${ctx.analysis.fileCount} 个文件，未发现对象级越权线索`,
    data: { fileCount: ctx.analysis.fileCount, candidates: ctx.view.findings },
  });
  if (cands.length === 0) {
    const d = ctx.analysis.diagnostics ?? {};
    const scanned = `已扫描 ${d.scannedFiles ?? 0} 个源文件（项目共 ${d.candidateFiles ?? 0} 个候选源文件${
      d.outputDirFiles > 0 ? `，其中产物目录 ${d.outputDirFiles} 个` : ""
    }${d.readFailures > 0 ? `，读取失败 ${d.readFailures} 个` : ""}）`;
    throw new SessionError(`${scanned}，未发现对象级资源接口线索`, {
      code: "no_candidates",
      hint: `${scanned}。请确认项目包含「按对象 ID 取资源」的 HTTP 接口（如 /api/orders/:id），或调整 guardbuild.json 的 scopes 后重试`,
    });
  }

  ctx.plan = buildProbePlan(ctx.analysis, { loginPathOverride: ctx.loginConfig?.path ?? null });
  if (!ctx.plan.readCandidate && !ctx.plan.cancelCandidate) {
    throw new SessionError("无法构建探测计划：候选端点中缺少可探测的单体资源接口", {
      code: "plan_incomplete",
      hint: `已发现 ${cands.length} 个候选端点，但均不含「按 ID 取单体资源」的路径（如 GET /api/orders/:id）。请确认项目中存在带路径参数的资源接口，或在 guardbuild.json 中补充契约`,
    });
  }
  ctx.view.plan = {
    loginPath: ctx.plan.loginPath,
    resource: ctx.plan.resource,
    readPath: ctx.plan.readCandidate?.fullPath ?? ctx.plan.readCandidate?.path ?? null,
    cancelPath: ctx.plan.cancelCandidate?.fullPath ?? ctx.plan.cancelCandidate?.path ?? null,
    listPath: ctx.plan.listEndpoint?.path ?? null,
  };
  pushView(ctx);
  return ctx.plan;
}

async function stageReproduce(ctx) {
  ensureAlive(ctx);
  setState(ctx, STATE.PROBING);
  await runPrepare(ctx, { cwd: ctx.projectRoot, label: "原始工作区" });
  const target = await spawnTarget(ctx, { cwd: ctx.projectRoot, label: "原始工作区（修复前）", role: "target-pre" });
  ctx.procs.original = target;
  ctx.view.targets.original = { ...target, role: "原始工作区（修复前）" };
  pushView(ctx);

  const pre = await runPhase(ctx, { phase: "pre", baseUrl: target.url });
  ctx.pushEvidence(pre.evidence);
  ctx.view.phases.pre = pre.summary;
  ctx.view.baseline = acceptanceVerdict(pre.summary);
  pushView(ctx);

  if (pre.summary.attackRepro === 0) {
    throw new SessionError("攻击用例在修复前即无法复现，无法建立漏洞基线", {
      code: "attack_not_reproducible",
      hint: "目标端点可能已有防护，或身份/资源发现结果不符合预期",
      details: pre.summary,
    });
  }
  setState(ctx, STATE.EVIDENCED);
  return pre;
}

async function stagePatch(ctx) {
  ensureAlive(ctx);
  setState(ctx, STATE.PATCHING);

  // 隔离验收需再启动一个实例：先停止原始实例，避免固定端口互撞
  // （原始实例在复现阶段已完成使命；写回后复核会重新拉起）
  if (ctx.procs.original) {
    await killProc(ctx, ctx.procs.original.pid);
    ctx.procs.original = null;
    ctx.view.targets.original = { ...ctx.view.targets.original, stopped: true };
    emit(ctx, {
      kind: "process",
      severity: SEVERITY.INFO,
      message: "已停止原始工作区实例（为隔离验收实例腾出端口；写回后会重新启动复核）",
      phase: STATE.PATCHING,
      data: {},
    });
    pushView(ctx);
  }

  const result = await createPatch(ctx);
  const lineCount = result.patch.diff.split("\n").filter((l) => l.startsWith("+") || l.startsWith("-")).length;
  ctx.view.patch = {
    hash: result.patch.hash,
    diff: result.patch.diff,
    files: result.patch.files,
    worktree: result.worktree,
    status: "pending_review",
    lineCount,
    fixes: result.filePatches,
    skipped: result.skipped,
  };
  pushView(ctx);

  await runPrepare(ctx, { cwd: result.worktree, label: "隔离工作区" });
  const wt = await spawnTarget(ctx, { cwd: result.worktree, label: "隔离工作区（修复候选）", role: "target-post" });
  ctx.procs.worktree = wt;
  ctx.view.targets.worktree = { ...wt, role: "隔离工作区（修复候选）" };
  pushView(ctx);

  setState(ctx, STATE.PATCH_REVIEW);
  emit(ctx, {
    kind: "patch",
    severity: SEVERITY.INFO,
    message: `补丁已就绪（patch_hash ${result.patch.hash.slice(0, 12)}…），等待您在界面审查 Diff 并授权隔离验收`,
    phase: STATE.PATCH_REVIEW,
    data: { patchHash: result.patch.hash, lineCount },
  });
  return result;
}

async function stageVerify(ctx) {
  ensureAlive(ctx);
  setState(ctx, STATE.VERIFYING);
  const wtTarget = ctx.procs.worktree;
  if (!wtTarget) throw new SessionError("隔离实例未运行，无法验收", { code: "no_worktree_target" });

  emit(ctx, { kind: "verify", severity: SEVERITY.INFO, message: "在隔离实例上执行双重验收（攻击阻断 + 业务回归）", data: {} });
  const post = await runPhase(ctx, { phase: "post", baseUrl: wtTarget.url });
  ctx.pushEvidence(post.evidence);
  ctx.view.phases.post = post.summary;
  recordAcceptanceRows(ctx, "post", post.evidence);

  const verdict = acceptanceVerdict(post.summary);
  ctx.view.acceptance = { ...verdict, phase: "post", at: Date.now() };
  pushView(ctx);

  if (!verdict.pass) {
    const failed = post.evidence
      .filter((e) => e.verdict === VERDICT.REGRESSED || e.verdict === VERDICT.INCONCLUSIVE)
      .map((e) => `${e.caseName}（${e.actual}）`);
    const err = new SessionError("修复验收未通过：存在未阻断的攻击或业务回归", {
      code: "verify_failed",
      hint: "补丁已保留在隔离 worktree 中，可回看证据调整修复策略",
      details: { failed, summary: post.summary },
    });
    await emitReport(ctx, {
      outcome: "vulnerable",
      patchStatus: "verify_failed",
      exitCode: 1,
      state: STATE.VERIFY_FAILED,
      error: { code: err.code, message: err.message, hint: err.hint, details: err.details },
    });
    setState(ctx, STATE.VERIFY_FAILED);
    throw err;
  }

  await emitReport(ctx, { outcome: "vulnerable", patchStatus: "verified", exitCode: 1, state: STATE.WRITEBACK_PENDING });
  setState(ctx, STATE.WRITEBACK_PENDING);
  emit(ctx, {
    kind: "verify",
    severity: SEVERITY.SUCCESS,
    message: `双重验收通过：攻击阻断 ${verdict.attackBlocked}/${verdict.attackTotal}，业务保持 ${verdict.businessPassed}/${verdict.businessTotal}`,
    phase: STATE.WRITEBACK_PENDING,
    data: verdict,
  });
  return post;
}

async function recheckAfterWriteback(ctx) {
  try {
    if (ctx.procs.original) {
      await killProc(ctx, ctx.procs.original.pid);
      ctx.procs.original = null;
    }
    const target = await spawnTarget(ctx, { cwd: ctx.projectRoot, label: "原始工作区（修复后复核）", role: "target-post-writeback" });
    ctx.procs.original = target;
    ctx.view.targets.original = { ...target, role: "原始工作区（修复后复核）" };
    pushView(ctx);

    const re = await runPhase(ctx, { phase: "post_writeback", baseUrl: target.url });
    ctx.pushEvidence(re.evidence);
    ctx.view.phases.post_writeback = re.summary;
    recordAcceptanceRows(ctx, "post_writeback", re.evidence);
    const verdict = acceptanceVerdict(re.summary);
    ctx.view.acceptance = { ...ctx.view.acceptance, writebackRecheck: { ...verdict, phase: "post_writeback", at: Date.now() } };
    pushView(ctx);
    emit(ctx, {
      kind: "verify",
      severity: verdict.pass ? SEVERITY.SUCCESS : SEVERITY.WARN,
      message: verdict.pass
        ? `写回后复核通过：实际工作区已阻断攻击且业务正常（攻击 ${verdict.attackBlocked}/${verdict.attackTotal}，业务 ${verdict.businessPassed}/${verdict.businessTotal}）`
        : "写回后复核未通过：实际工作区状态与隔离验收不一致，建议回滚",
      phase: "post_writeback",
      data: verdict,
    });
  } catch (e) {
    emit(ctx, {
      kind: "verify",
      severity: SEVERITY.WARN,
      message: `写回后复核未能完成：${e.message}`,
      phase: "post_writeback",
      data: { code: e.code ?? null },
    });
  } finally {
    await shutdownProcs(ctx);
  }
}

// ---------- 会话主流程 ----------

async function runFlow(ctx) {
  const sessionId = ctx.sessionId;
  try {
    ctx.db.ensureProject(ctx.projectRoot, ctx.projectRoot, ctx.projectName);
    ctx.db.ensureSession(sessionId, ctx.projectRoot, ctx.projectRoot);
    pushView(ctx);
    emit(ctx, {
      kind: "session",
      severity: SEVERITY.INFO,
      message: `编排开始：目标项目 ${ctx.projectRoot}`,
      data: { sessionId },
    });

    const targetConfig = await loadTargetConfig(ctx);
    ctx.targetConfig = targetConfig;
    ctx.loginConfig = targetConfig.login ?? null;
    if (targetConfig.identities) {
      ctx.identities = targetConfig.identities;
    }
    if (targetConfig.source === "guardbuild.json") {
      const extras = [
        targetConfig.login ? `登录端点 ${targetConfig.login.path}` : null,
        targetConfig.prepare?.length ? `准备步骤 ${targetConfig.prepare.length} 个` : null,
      ].filter(Boolean);
      emit(ctx, {
        kind: "session",
        severity: SEVERITY.INFO,
        message: `已加载启动契约 guardbuild.json：${targetConfig.start.cmd} ${targetConfig.start.args.join(" ")}（就绪模式 ${targetConfig.start.readyPattern}${extras.length ? `；${extras.join("，")}` : ""}）`,
        data: {
          start: targetConfig.start,
          login: targetConfig.login,
          prepare: targetConfig.prepare,
          identities: targetConfig.identities ? targetConfig.identities.map((i) => i.name) : null,
          scopes: targetConfig.scopes,
        },
      });
    } else if (targetConfig.source === "invalid") {
      emit(ctx, {
        kind: "session",
        severity: SEVERITY.WARN,
        message: `guardbuild.json 解析失败（${targetConfig.invalid}），回落到缺省启动契约（node server.js + GB_LISTEN）`,
        data: { invalid: targetConfig.invalid },
      });
    }

    await stageAnalyze(ctx);
    await stageReproduce(ctx);
    await stagePatch(ctx);
    // 进入 patch_review 后等待用户的 patch.approved 指令（见上方 handler）
  } catch (e) {
    // 用户已请求中止时，吊销令牌/结束进程导致的在途 RPC 失败也归为中止
    if (ctx.cancelled || e instanceof CancelledError) {
      abortSession(ctx);
      return;
    }
    failSession(ctx, e);
  }
}

async function abortSession(ctx) {
  emit(ctx, { kind: "session", severity: SEVERITY.WARN, message: "会话已中止", data: {} });
  await emitReport(ctx, { outcome: "aborted", exitCode: 2, state: STATE.ABORTED });
  if (ctx.sm.can(STATE.ABORTED)) setState(ctx, STATE.ABORTED);
  else {
    ctx.sm.state = STATE.ABORTED;
    ctx.view.state = STATE.ABORTED;
    ctx.view.stateLabel = STATE_LABELS[STATE.ABORTED];
    pushView(ctx);
  }
  shutdownProcs(ctx).catch(() => {});
  endSession(ctx);
}

async function failSession(ctx, e) {
  const payload = {
    code: e.code ?? "internal",
    message: e.message,
    hint: e.hint ?? null,
    details: e.details ?? null,
  };
  const outcome =
    payload.code === "no_candidates" ? "no_candidates"
    : payload.code === "attack_not_reproducible" ? "not_reproducible"
    : "failed";
  await emitReport(ctx, { outcome, exitCode: outcome === "failed" ? 2 : 0, state: STATE.ERROR, error: payload });
  ctx.view.error = payload;
  emit(ctx, {
    kind: "session",
    severity: SEVERITY.ERROR,
    message: `执行失败：${e.message}${e.hint ? `（建议：${e.hint}）` : ""}`,
    data: payload,
  });
  if (ctx.sm.can(STATE.ERROR)) setState(ctx, STATE.ERROR);
  else {
    ctx.sm.state = STATE.ERROR;
    ctx.view.state = STATE.ERROR;
    ctx.view.stateLabel = STATE_LABELS[STATE.ERROR];
    pushView(ctx);
  }
  shutdownProcs(ctx).catch(() => {});
  endSession(ctx);
}

// ---------- JSON-RPC ----------

const peer = new RpcPeer({ input: process.stdin, output: process.stdout });

peer.onClose = () => {
  if (active) {
    active.cancelled = true;
    shutdownProcs(active).catch(() => {});
    try {
      active.db.close();
    } catch {
      /* ignore */
    }
  }
  process.exit(0);
};

peer.onRequest(RPC_TO_SIDECAR.SESSION_START, async (params) => {
  if (active) {
    if (!TERMINAL_STATES.has(active.sm?.state)) return { ok: false, error: "已有会话进行中" };
    endSession(active);
  }
  const ctx = createCtx(params);
  active = ctx;
  runFlow(ctx).catch(() => {});
  return { ok: true, sessionId: params.sessionId };
});

async function handleSessionCancel() {
  const ctx = active;
  if (!ctx) return { ok: true };
  ctx.cancelled = true;
  // 空闲等待用户操作的阶段直接中止；运行中的阶段会在下一个检查点退出
  const idleStates = [STATE.PATCH_REVIEW, STATE.WRITEBACK_PENDING, STATE.VERIFY_FAILED];
  if (ctx.sm && idleStates.includes(ctx.sm.state)) abortSession(ctx);
  return { ok: true };
}
// Host 可能以请求（期待确认）或通知（单向）形式发送取消，两者都处理
peer.onRequest(RPC_TO_SIDECAR.SESSION_CANCEL, handleSessionCancel);
peer.onNotification(RPC_TO_SIDECAR.SESSION_CANCEL, handleSessionCancel);

peer.onRequest(RPC_TO_SIDECAR.PATCH_APPROVED, async ({ patchHash } = {}) => {
  const ctx = active;
  if (!ctx || !ctx.sm) return { ok: false, error: "会话尚未就绪" };
  if (ctx.sm.state !== STATE.PATCH_REVIEW) {
    return { ok: false, error: `当前状态 ${ctx.sm.state} 不可批准补丁` };
  }
  if (patchHash && ctx.view.patch?.hash && patchHash !== ctx.view.patch.hash) {
    return { ok: false, error: "补丁哈希不匹配（可能已过期）" };
  }
  ctx.db.insertApproval({
    id: shortId("ap"),
    sessionId: ctx.sessionId,
    action: "patch.approve",
    subject: ctx.view.patch?.worktree ?? null,
    patchHash: ctx.view.patch?.hash ?? null,
    approvedAt: Date.now(),
    via: ctx.gate ? "gate-policy" : "user-diff-approval",
  });
  // 立即响应 Host，验收在后台推进（通过事件汇报进度）
  stageVerify(ctx).catch((e) => {
    if (ctx.cancelled || e instanceof CancelledError) abortSession(ctx);
    else if (e.code === "verify_failed") {
      emit(ctx, {
        kind: "verify",
        severity: SEVERITY.ERROR,
        message: e.message,
        phase: STATE.VERIFY_FAILED,
        data: e.details ?? null,
      });
      shutdownProcs(ctx).catch(() => {});
      endSession(ctx);
    } else {
      failSession(ctx, e);
    }
  });
  return { ok: true, started: true };
});

peer.onRequest(RPC_TO_SIDECAR.WRITEBACK_APPROVED, async ({ token, patchHash } = {}) => {
  const ctx = active;
  if (!ctx || !ctx.sm) return { ok: false, error: "会话尚未就绪" };
  if (ctx.sm.state !== STATE.WRITEBACK_PENDING) {
    return { ok: false, error: `当前状态 ${ctx.sm.state} 不可写回` };
  }
  try {
    setState(ctx, STATE.APPLYING);
    const res = await writebackPatch(ctx, {
      token,
      patchHash: patchHash ?? ctx.view.patch?.hash,
      worktree: ctx.view.patch?.worktree,
      diff: ctx.view.patch?.diff,
    });
    if (ctx.view.patch) ctx.view.patch.status = "written_back";
    if (ctx.procs.worktree) {
      await killProc(ctx, ctx.procs.worktree.pid);
      ctx.procs.worktree = null;
    }
    setState(ctx, STATE.APPLIED);
    emit(ctx, {
      kind: "writeback",
      severity: SEVERITY.SUCCESS,
      message: `补丁已写回原工作区（${(res.files ?? []).join("、")}），原文件已备份（backupId ${res.backupId}）`,
      phase: STATE.APPLIED,
      data: res,
    });
    // 写回后复核：重启原工作区实例，验证真实工作区状态
    recheckAfterWriteback(ctx).catch(() => {});
    return { ok: true, backupId: res.backupId, files: res.files };
  } catch (e) {
    if (ctx.cancelled) abortSession(ctx);
    else failSession(ctx, e);
    return { ok: false, error: e.message };
  }
});

peer.onRequest(RPC_TO_SIDECAR.ROLLBACK_APPROVED, async ({ token, backupId } = {}) => {
  const ctx = active;
  if (!ctx || !ctx.sm) return { ok: false, error: "会话尚未就绪" };
  try {
    const res = await rollbackWorkspace(ctx, { token, backupId });
    if (ctx.view.patch) ctx.view.patch.status = "rolled_back";
    setState(ctx, STATE.ROLLED_BACK);
    emit(ctx, {
      kind: "rollback",
      severity: SEVERITY.SUCCESS,
      message: `已回滚 ${(res.restored ?? []).length} 个文件${(res.conflicts ?? []).length > 0 ? `（${res.conflicts.length} 个文件存在冲突，未覆盖）` : ""}`,
      phase: STATE.ROLLED_BACK,
      data: res,
    });
    await shutdownProcs(ctx);
    endSession(ctx);
    return { ok: true, ...res };
  } catch (e) {
    if (ctx.cancelled) abortSession(ctx);
    else failSession(ctx, e);
    return { ok: false, error: e.message };
  }
});

// ---------- 启动 ----------

process.on("uncaughtException", (e) => {
  process.stderr.write(`[sidecar] uncaughtException: ${e.stack ?? e.message}\n`);
});
process.on("unhandledRejection", (e) => {
  process.stderr.write(`[sidecar] unhandledRejection: ${e?.stack ?? e}\n`);
});

peer.notify(NOTIFY_TO_HOST.READY, {
  node: process.version,
  platform: process.platform,
  arch: process.arch,
  protocol: PROTOCOL_VERSION,
  pid: process.pid,
});
process.stderr.write(`[sidecar] ready (pid ${process.pid}, node ${process.version})\n`);
