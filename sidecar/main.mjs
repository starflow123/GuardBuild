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
import {
  loadTargetConfig,
  loadBlackboxConfig,
  DEFAULT_START,
  startUsesPortSlot,
  renderStart,
  normalizeStart,
  PORT_SLOT,
} from "./lib/targetconfig.mjs";
import { diagnoseStartFailure } from "./lib/autostart.mjs";
import { parsePortFromLine, stripAnsi } from "./lib/readyline.mjs";
import { runPhase, ProbeError } from "./lib/probe.mjs";
import { runSupabasePhase, isLoopbackHostname } from "./lib/supabase.mjs";
import { runScout, applyScoutResult, recordScoutVerification, MAX_START_CANDIDATES } from "./lib/scout.mjs";
import { isEnabled as llmEnabled } from "./lib/llm.mjs";
import { runBlackbox } from "./lib/blackbox.mjs";
import { coverageSummary, describeOutcome } from "./lib/coverage.mjs";
import { createPatch, writebackPatch, rollbackWorkspace, PatchError } from "./lib/patcher.mjs";
import { crossFilePatchEnabled } from "./lib/llm-patcher.mjs";
import { buildAttribution } from "./lib/attribution.mjs";
import { buildFixFeedback, feedbackDigest } from "./lib/fixfeedback.mjs";
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

const RETRYABLE_START_CODES = new Set(["target_spawn_failed", "target_not_ready", "port_parse_failed"]);
/** LLM 启动候选的总重试预算：多候选不能把 gate 的整段超时吃掉 */
const START_RETRY_BUDGET_MS = 120_000;

// 终态：到达这些状态后槽位可被释放。applied 仍保留 active 以支持回滚，
// 仅在新会话启动时才回收。
const TERMINAL_STATES = new Set([
  STATE.APPLIED,
  STATE.ROLLED_BACK,
  STATE.VERIFY_FAILED,
  STATE.COMPLETED,
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
    blackboxUrl: typeof params.blackboxUrl === "string" && params.blackboxUrl.trim() ? params.blackboxUrl.trim() : null,
    tokens: { project: params.token },
    identities: loadIdentities(),
    loginConfig: null,
    analysis: null,
    plan: null,
    supabaseLeaks: 0,
    serviceRoleLeak: null,
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
      supabase: null,
      llm: null,
      acceptance: null,
      error: null,
    },
    procs: {},
    // Docker 沙箱：本会话创建的容器名，用于失败/结束时 docker rm -f
    docker: { containers: [], seq: 0 },
    cancelled: false,
    gate: params.gate === true,
    outcomeLabel: null,
    _lastDecisionSeq: 0,
  };
  ctx.view.projectName = ctx.projectName;
  ctx.sm = new StateMachine(STATE.STARTING, (from, to) => {
    ctx.db.updateSessionState(ctx.sessionId, to);
    ctx.view.state = to;
    // 终态标签随状态同帧下发：exit 0 的语义结局（未命中覆盖范围等）不能显示成「执行出错」
    ctx.view.stateLabel = (to === STATE.ERROR && ctx.outcomeLabel) || STATE_LABELS[to] || to;
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

async function requestScope(ctx, kind, reason, host = null, extra = null) {
  emit(ctx, {
    kind: "scope",
    severity: SEVERITY.INFO,
    message: `申请作用域: ${kind}${host ? ` @ ${host}` : ""}（${reason}）`,
    data: { kind, host },
  });
  const params = { token: ctx.tokens.project, kind, reason };
  if (host) params.host = host;
  if (extra) Object.assign(params, extra);
  const res = await ctx.rpc.request(RPC_TO_HOST.AUTH_REQUEST_SCOPE, params, { timeoutMs: 240_000 });
  return res.token;
}

function urlHostAndScheme(rawUrl) {
  try {
    const u = new URL(rawUrl);
    return { host: u.hostname.toLowerCase(), scheme: u.protocol.replace(/:$/, "").toLowerCase() };
  } catch {
    return { host: null, scheme: null };
  }
}

/** Supabase 探测所需网络令牌：回环复用 net.probe（允许 http）；远程仅 https 且需 net.egress @ host */
async function ensureSupabaseToken(ctx, rawUrl) {
  const { host, scheme } = urlHostAndScheme(rawUrl);
  if (!host) {
    throw new SessionError(`无法解析 Supabase 项目 URL：${rawUrl}`, {
      code: "supabase_bad_url",
      hint: "请检查 guardbuild.json 的 supabase.url 或项目 .env 中的 SUPABASE_URL 是否为合法 URL",
    });
  }
  if (isLoopbackHostname(host)) return ctx.tokens.net;
  if (scheme !== "https") {
    throw new SessionError(`Supabase 远程探测仅支持 https：${rawUrl}`, {
      code: "supabase_insecure_url",
      hint: "明文 http 仅用于本机回环探测；远程项目请使用 https 的 Supabase URL",
    });
  }
  if (ctx.tokens.egress && ctx.tokens.egressHost === host) return ctx.tokens.egress;
  ctx.tokens.egress = await requestScope(
    ctx,
    SCOPE_KINDS.NET_EGRESS,
    `向 ${host} 发起 Supabase/PostgREST 数据暴露探测`,
    host
  );
  ctx.tokens.egressHost = host;
  return ctx.tokens.egress;
}

/** LLM 出站令牌：回环复用 net.probe（本地 mock 服务）；远程仅 https 且需 net.egress @ host */
async function ensureLlmToken(ctx, url, reason) {
  const { host, scheme } = urlHostAndScheme(url);
  if (!host) throw new Error(`无法解析 LLM 端点主机：${url}`);
  if (isLoopbackHostname(host)) {
    if (!ctx.tokens.net) {
      ctx.tokens.net = await requestScope(ctx, SCOPE_KINDS.NET_PROBE, "向本机回环的 LLM 服务发送请求");
    }
    return ctx.tokens.net;
  }
  if (scheme !== "https") throw new Error("LLM 端点必须是 https（仅回环测试允许明文 http）");
  if (ctx.tokens.egress && ctx.tokens.egressHost === host) return ctx.tokens.egress;
  const token = await requestScope(ctx, SCOPE_KINDS.NET_EGRESS, reason, host);
  ctx.tokens.egress = token;
  ctx.tokens.egressHost = host;
  return token;
}

/**
 * LLM 接入侦察（可选）：只在 guardbuild.json 的 llm.enabled=true 或环境变量
 * GUARDBUILD_LLM_SCOUT=1 时运行。无 key / 无授权 / 超时 / 非法输出一律警告并
 * 回落到确定性流程，绝不中止会话。
 */
async function stageScout(ctx, targetConfig) {
  const optIn = targetConfig.llm?.enabled === true || process.env.GUARDBUILD_LLM_SCOUT === "1";
  if (!optIn) return;

  const needsStart = targetConfig.startSource !== "contract" && targetConfig.startSource !== "auto";
  const needsLogin = !targetConfig.login;
  const needsRoutes = !targetConfig.routes && !targetConfig.openapi;
  if (!needsStart && !needsLogin && !needsRoutes) {
    emit(ctx, {
      kind: "scout",
      severity: SEVERITY.INFO,
      message: "显式契约已覆盖启动、登录与路由线索，跳过 LLM 接入侦察",
      data: {},
    });
    return;
  }

  const model = targetConfig.llm?.model ?? null;
  emit(ctx, {
    kind: "scout",
    severity: SEVERITY.INFO,
    message: `开始 LLM 接入侦察${model ? `（${model}）` : ""}：只推断启动/登录/路由，不参与漏洞判定`,
    data: { model, needsStart, needsLogin, needsRoutes },
  });

  let scout;
  try {
    scout = await runScout(ctx, {
      model,
      maxFiles: targetConfig.llm?.maxFiles ?? 8,
      getToken: (url, reason) => ensureLlmToken(ctx, url, reason),
    });
  } catch (e) {
    emit(ctx, {
      kind: "scout",
      severity: SEVERITY.WARN,
      message: `LLM 接入侦察失败，继续确定性流程：${e.message}`,
      data: { code: e.code ?? null },
    });
    return;
  }
  if (!scout) {
    emit(ctx, {
      kind: "scout",
      severity: SEVERITY.WARN,
      message: llmEnabled()
        ? "LLM 接入侦察未返回可用结果；继续确定性流程"
        : "已启用 LLM 接入侦察，但未设置 DEEPSEEK_API_KEY 且没有可用的磁盘缓存；跳过侦察，继续确定性流程",
      data: {},
    });
    return;
  }

  const fallbackStart = { start: targetConfig.start, startSource: targetConfig.startSource };
  const applied = applyScoutResult(targetConfig, scout);
  if (applied.login) ctx.loginConfig = targetConfig.login;
  ctx.scoutApplied = applied;
  ctx.scoutFallbackStart = applied.start ? fallbackStart : null;
  ctx.scoutCacheFile = scout._cacheFile ?? null;
  // 候选队列只在 LLM 启动契约真正生效时使用；显式契约/自动探测优先的会话不参与重试
  ctx.scoutStartCandidates =
    applied.start && Array.isArray(scout.starts) && scout.starts.length
      ? scout.starts.slice(0, MAX_START_CANDIDATES).map(normalizeStart)
      : null;

  const appliedDesc = [
    applied.start ? `启动 ${scout.start.cmd} ${scout.start.args.join(" ")}`.trim() : null,
    applied.login ? `登录 ${scout.login.path}` : null,
    applied.routes ? `路由 ${applied.routes} 条` : null,
  ].filter(Boolean);
  ctx.view.llm = {
    used: true,
    model: scout.model ?? model,
    source: scout._source,
    routes: scout.routes?.length ?? 0,
    applied,
    notes: scout.notes ?? [],
    warnings: scout.warnings ?? [],
    cached: !!scout.cached,
    cacheSource: scout.cacheSource ?? null,
    cachedAt: scout.savedAt ?? null,
    durationMs: scout.durationMs ?? null,
    evidenceFiles: scout.evidenceFiles ?? [],
    evidenceChars: scout.evidenceChars ?? 0,
    usage: scout.usage ?? null,
    verified: { start: false, login: false },
    rejectedStart: scout.rejectedStart ?? null,
    startAttempts: [],
  };
  pushView(ctx);
  if (scout.cached) {
    emit(ctx, {
      kind: "scout",
      severity: SEVERITY.INFO,
      message: `命中${scout.cacheSource === "disk" ? "磁盘" : "内存"}侦察缓存（${
        scout.savedAt ? new Date(scout.savedAt).toISOString() : "保存时间未知"
      }），复用后仍会实际启动/登录验证`,
      data: { cacheSource: scout.cacheSource ?? null, savedAt: scout.savedAt ?? null },
    });
  }
  emit(ctx, {
    kind: "scout",
    severity: appliedDesc.length ? SEVERITY.SUCCESS : SEVERITY.INFO,
    message: appliedDesc.length
      ? `LLM 接入侦察返回候选契约（待实际启动/登录验证）：${appliedDesc.join("，")}`
      : "LLM 接入侦察未采纳新线索（已有更可信契约或输出不可定位）",
    data: { model: scout.model ?? model, applied, cached: !!scout.cached },
  });
  for (const w of (scout.warnings ?? []).slice(0, 8)) {
    emit(ctx, { kind: "scout", severity: SEVERITY.WARN, message: w, data: {} });
  }
  if (scout.notes?.length) {
    emit(ctx, {
      kind: "scout",
      severity: SEVERITY.INFO,
      message: `LLM 侦察备注：${scout.notes.join("；")}`,
      data: { notes: scout.notes },
    });
  }
}

/** 回环主动探活：目标不打印监听日志时，用 HTTP 响应替代就绪行 */
async function canReachLocalHttp(ctx, port, timeoutMs = 2_500) {
  if (!port || !ctx.tokens?.net) return false;
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      await ctx.rpc.request(
        RPC_TO_HOST.HTTP_REQUEST,
        {
          token: ctx.tokens.net,
          method: "GET",
          url: `http://127.0.0.1:${port}/`,
          headers: {},
          redact: true,
        },
        { timeoutMs: 3_000 }
      );
      return true;
    } catch {
      await new Promise((r) => setTimeout(r, 250));
    }
  }
  return false;
}

/** Docker 容器名：guardbuild-<session8>-<role>-<seq>，Host 只允许操作此前缀。 */
function nextDockerContainerName(ctx, role) {
  const seq = ++ctx.docker.seq;
  const safeRole =
    String(role)
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 24) || "target";
  return `guardbuild-${ctx.sessionId.slice(0, 8)}-${safeRole}-${seq}`;
}

/** Docker Desktop 接受 Windows 盘符路径，但统一用正斜杠并去掉 \\?\ 扩展前缀（否则 -v 会被解析成非法 mode）。 */
function dockerMountPath(p) {
  let s = path.resolve(p).replace(/\\/g, "/");
  if (s.startsWith("//?/UNC/")) s = `//${s.slice("//?/UNC/".length)}`;
  else if (s.startsWith("//?/")) s = s.slice(4);
  return s;
}

/**
 * Docker 就绪判定：以映射后的宿主端口 HTTP 探活为准（容器日志不一定打印监听行）。
 * 同时检查 docker CLI 是否已退出，镜像/命令错误时尽快失败而不是干等超时。
 */
async function waitForDockerReady(ctx, pid, port, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (ctx.cancelled) throw new CancelledError();
    if (await canReachLocalHttp(ctx, port, 600)) return { ok: true };
    try {
      const logs = await ctx.rpc.request(
        RPC_TO_HOST.PROC_LOGS,
        { token: ctx.tokens.spawn, pid, tail: 5 },
        { timeoutMs: 5_000 }
      );
      if (logs.exited) {
        return {
          ok: false,
          exited: true,
          exitCode: Number.isInteger(logs.exitCode) ? logs.exitCode : null,
        };
      }
    } catch {
      /* 进程表查询失败不阻断就绪轮询 */
    }
    await new Promise((r) => setTimeout(r, 300));
  }
  return { ok: false, exited: false, exitCode: null };
}

async function spawnTarget(ctx, { cwd, label, role = "target" }) {
  const start = ctx.targetConfig?.start ?? DEFAULT_START;
  const spawnCwd = start.cwd ? path.resolve(cwd, start.cwd) : cwd;
  const docker = ctx.targetConfig?.docker;
  const dockerEnabled = docker?.enabled === true;
  if (dockerEnabled && docker.invalid) {
    throw new SessionError(`Docker 沙箱配置不合法：${docker.invalid}`, {
      code: "docker_config_invalid",
      hint: "请在 guardbuild.json 的 docker 中补全 image/containerPort/workdir；配置错误时 GuardBuild 不会回退到宿主机直接运行目标",
      details: { docker },
    });
  }
  // 契约声明了 ${GB_PORT} 槽位、或启用 Docker（需要宿主端口做映射）时，先分配空闲端口
  let allocated = null;
  if (startUsesPortSlot(start) || dockerEnabled) {
    try {
      const res = await ctx.rpc.request(RPC_TO_HOST.PROC_ALLOC_PORT, { token: ctx.tokens.spawn }, { timeoutMs: 15_000 });
      allocated = res.port;
      emit(ctx, {
        kind: "process",
        severity: SEVERITY.INFO,
        message: dockerEnabled
          ? `已分配宿主端口 ${allocated}（映射到容器 :${docker.containerPort}）`
          : `已分配空闲端口 ${allocated}（注入 ${label} 的 \${GB_PORT} 槽位）`,
        data: { port: allocated, label },
      });
    } catch (e) {
      throw new SessionError("无法分配空闲端口", {
        code: "port_alloc_failed",
        hint: e.message,
        details: { cwd, label },
      });
    }
  }
  // Docker 内应用固定监听 containerPort（宿主端口只做映射，注入进去反而会让映射失效）
  const { cmd, args, env } = renderStart(start, dockerEnabled ? docker.containerPort : allocated);

  let finalCmd = cmd;
  let finalArgs = args;
  let finalEnv = env;
  let containerName = null;
  if (dockerEnabled) {
    const mergedEnv = { ...env, ...docker.env, PORT: String(docker.containerPort) };
    if (mergedEnv.NODE_ENV == null) mergedEnv.NODE_ENV = "test";
    if (Object.keys(mergedEnv).length > 32) {
      throw new SessionError("Docker 沙箱环境变量过多（最多 32 个）", {
        code: "docker_config_invalid",
        hint: "请精简 guardbuild.json 的 start.env / docker.env",
      });
    }
    const innerCmd = docker.command ?? [cmd, ...args];
    containerName = nextDockerContainerName(ctx, role);
    finalCmd = "docker";
    finalArgs = [
      "run",
      "--rm",
      "--init",
      "--name",
      containerName,
      "-p",
      `127.0.0.1:${allocated}:${docker.containerPort}`,
      "-v",
      `${dockerMountPath(spawnCwd)}:${docker.workdir}`,
      "-w",
      docker.workdir,
      ...Object.entries(mergedEnv).flatMap(([k, v]) => ["-e", `${k}=${v}`]),
      docker.image,
      ...innerCmd,
    ];
    finalEnv = {};
    ctx.docker.containers.push(containerName);
    emit(ctx, {
      kind: "process",
      severity: SEVERITY.INFO,
      message: `[Docker] 启动容器 ${containerName}：${docker.image}；${spawnCwd} → ${docker.workdir}；127.0.0.1:${allocated} → 容器 :${docker.containerPort}`,
      data: {
        containerName,
        image: docker.image,
        workdir: docker.workdir,
        hostPort: allocated,
        containerPort: docker.containerPort,
        envKeys: Object.keys(mergedEnv),
      },
    });
  }
  let res;
  try {
    res = await ctx.rpc.request(
      RPC_TO_HOST.PROC_SPAWN,
      {
        token: ctx.tokens.spawn,
        cmd: finalCmd,
        args: finalArgs,
        cwd: spawnCwd,
        env: finalEnv,
        role,
      },
      { timeoutMs: 30_000 }
    );
  } catch (e) {
    const diag = diagnoseStartFailure({ output: [String(e?.message ?? e)], start });
    throw new SessionError(`无法启动目标进程「${label}」`, {
      code: "target_spawn_failed",
      hint: diag.hint,
      details: { cwd: spawnCwd, start, docker: dockerEnabled ? docker : null, diagnosis: diag },
    });
  }
  if (dockerEnabled) {
    // 容器日志可能不打印监听行：直接对映射后的宿主端口做 HTTP 探活
    const ready = await waitForDockerReady(ctx, res.pid, allocated, docker.readyTimeoutMs);
    if (!ready.ok) {
      const lines = [];
      let exitCode = ready.exitCode;
      try {
        const logs = await ctx.rpc.request(RPC_TO_HOST.PROC_LOGS, {
          token: ctx.tokens.spawn,
          pid: res.pid,
          tail: 60,
        });
        lines.push(...(logs.lines ?? []).map((l) => l.line));
        if (Number.isInteger(logs.exitCode)) exitCode = logs.exitCode;
      } catch {
        /* ignore */
      }
      await killProc(ctx, res.pid);
      const diag = diagnoseStartFailure({ output: lines, exitCode, start });
      throw new SessionError(`Docker 容器「${label}」未在超时内就绪`, {
        code: "target_not_ready",
        hint: `容器 ${containerName} 已启动，但宿主端口 ${allocated} 无 HTTP 响应。请确认容器内服务监听 0.0.0.0:${docker.containerPort}（而非 127.0.0.1），必要时调整 guardbuild.json 的 docker.containerPort/image/workdir。${
          diag.hint ? ` ${diag.hint}` : ""
        }`,
        details: {
          cwd: spawnCwd,
          start,
          docker,
          containerName,
          hostPort: allocated,
          exitCode,
          output: lines,
          diagnosis: diag,
        },
      });
    }
    const target = {
      pid: res.pid,
      port: allocated,
      url: `http://127.0.0.1:${allocated}`,
      container: containerName,
    };
    emit(ctx, {
      kind: "process",
      severity: SEVERITY.SUCCESS,
      message: `目标容器「${label}」已就绪: ${target.url} → 容器 :${docker.containerPort}（${containerName}）`,
      data: target,
    });
    return target;
  }
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
    let exited = false;
    let exitCode = null;
    try {
      const logs = await ctx.rpc.request(RPC_TO_HOST.PROC_LOGS, { token: ctx.tokens.spawn, pid: res.pid, tail: 40 });
      lines = (logs.lines ?? []).map((l) => l.line);
      exited = !!logs.exited;
      exitCode = Number.isInteger(logs.exitCode) ? logs.exitCode : null;
    } catch {
      /* ignore */
    }
    // 不打印监听日志的服务：端口由宿主分配且进程仍在运行时，用回环 HTTP 主动探活
    if (!exited && allocated && (await canReachLocalHttp(ctx, allocated))) {
      emit(ctx, {
        kind: "process",
        severity: SEVERITY.WARN,
        message: `未匹配到就绪输出，但「${label}」已通过 HTTP 探活确认可用（可能未打印监听日志）`,
        data: { port: allocated, label },
      });
      const target = { pid: res.pid, port: allocated, url: `http://127.0.0.1:${allocated}` };
      emit(ctx, {
        kind: "process",
        severity: SEVERITY.SUCCESS,
        message: `目标实例「${label}」已就绪: ${target.url}（pid ${res.pid}）`,
        data: target,
      });
      return target;
    }
    await killProc(ctx, res.pid);
    const diag = diagnoseStartFailure({ output: lines, exitCode, start });
    throw new SessionError(`目标进程「${label}」未在超时内就绪`, {
      code: "target_not_ready",
      hint: diag.hint,
      details: {
        cwd: spawnCwd,
        start,
        exitCode,
        output: lines,
        diagnosis: diag,
        autostart: ctx.targetConfig?.autostart ?? null,
      },
    });
  }
  // 就绪行解析优先（它是真实绑定端口）；解析不到但契约声明了槽位时回退到分配值
  let port = parsePortFromLine(wait.line);
  if (!port && allocated) port = allocated;
  if (!port) {
    await killProc(ctx, res.pid);
    throw new SessionError(`无法从就绪输出解析端口（${label}）`, {
      code: "port_parse_failed",
      hint: `就绪行中没有可解析的端口：可在 guardbuild.json 的 start.env 中写 PORT: "${PORT_SLOT}" 由宿主分配端口（自动探测已默认这样做），或把 start.readyPattern 指向真正打印端口的日志行`,
      details: { cwd: spawnCwd, start, line: stripAnsi(wait.line) },
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

/** 清理本会话创建的容器：先 docker rm -f，再回收 docker CLI 进程。 */
async function cleanupDockerContainers(ctx) {
  const names = ctx.docker?.containers ?? [];
  ctx.docker.containers = [];
  if (!names.length || !ctx.tokens?.spawn) return;
  for (const name of names) {
    try {
      const res = await ctx.rpc.request(
        RPC_TO_HOST.PROC_SPAWN,
        {
          token: ctx.tokens.spawn,
          cmd: "docker",
          args: ["rm", "-f", name],
          cwd: ctx.projectRoot,
          role: "docker-cleanup",
        },
        { timeoutMs: 20_000 }
      );
      await ctx.rpc.request(
        RPC_TO_HOST.PROC_WAIT_EXIT,
        { token: ctx.tokens.spawn, pid: res.pid, timeoutMs: 15_000 },
        { timeoutMs: 20_000 }
      );
    } catch {
      /* --rm 可能已自动删除，或会话已中止 */
    }
  }
}

async function shutdownProcs(ctx) {
  await cleanupDockerContainers(ctx);
  const entries = Object.values(ctx.procs).filter(Boolean);
  for (const p of entries) await killProc(ctx, p.pid);
  ctx.procs = {};
}

/**
 * 终态清理隔离 worktree：先停掉占用目录的实例，再由 Host 删除（Host 会先摘除 junction/symlink）。
 * 清理失败只告警，不覆盖会话结论；重复调用安全。
 */
async function removeWorktree(ctx) {
  const wt = ctx.view.patch?.worktree ?? ctx._worktree;
  if (!wt || ctx._worktreeCleanupAttempted) return;
  ctx._worktreeCleanupAttempted = true;
  if (ctx.procs.worktree) {
    await killProc(ctx, ctx.procs.worktree.pid);
    ctx.procs.worktree = null;
  }
  const token = ctx.tokens.worktree;
  if (!token) return;
  try {
    await ctx.rpc.request(
      RPC_TO_HOST.GIT_WORKTREE_REMOVE,
      { token, path: wt },
      { timeoutMs: 60_000 }
    );
    emit(ctx, {
      kind: "session",
      severity: SEVERITY.INFO,
      message: `已清理隔离 worktree（${wt}）`,
      data: { worktree: wt },
    });
  } catch (e) {
    // 允许后续（如新会话启动时）再试一次
    ctx._worktreeCleanupAttempted = false;
    emit(ctx, {
      kind: "session",
      severity: SEVERITY.WARN,
      message: `隔离 worktree 自动清理失败：${e.message}（可手动删除 ${wt}）`,
      data: { worktree: wt, error: e.message },
    });
  }
}

/**
 * 丢弃当前隔离 worktree（修复循环重试前）：先停实例，再交由 Host 删除。
 * 与 removeWorktree 不同，这里不设一次性哨兵，后续轮次仍可再清理。
 */
async function discardWorktree(ctx) {
  if (ctx.procs.worktree) {
    await killProc(ctx, ctx.procs.worktree.pid);
    ctx.procs.worktree = null;
  }
  const wt = ctx.view.patch?.worktree ?? ctx._worktree;
  if (!wt) return;
  try {
    await ctx.rpc.request(RPC_TO_HOST.GIT_WORKTREE_REMOVE, { token: ctx.tokens.worktree, path: wt }, { timeoutMs: 60_000 });
    emit(ctx, {
      kind: "session",
      severity: SEVERITY.INFO,
      message: `已清理未通过验收的隔离 worktree（${wt}）`,
      data: { worktree: wt },
    });
  } catch (e) {
    emit(ctx, {
      kind: "session",
      severity: SEVERITY.WARN,
      message: `未通过验收的 worktree 清理失败：${e.message}（可手动删除 ${wt}）`,
      data: { worktree: wt, error: e.message },
    });
  }
  if (ctx._worktree === wt) ctx._worktree = null;
  ctx._worktreeCleanupAttempted = false;
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
    attackRegressed: summary.attackRegressed,
    businessPassed: summary.businessPassed,
    businessTotal: summary.businessTotal,
    businessRegressed: summary.businessRegressed,
    variantCounted: summary.variantCounted ?? 0,
    variantSkipped: summary.variantSkipped ?? 0,
    counts: summary.counts,
  };
}

/** 补丁点名的候选集合（验收范围据此决定是否复跑无模板候选的用例） */
function setClaimedCandidates(ctx, result) {
  ctx._claimedCandidates = new Set(result?.claimedKeys ?? []);
}

/**
 * 双重验收 = 汇总判定 + 逐候选归因。
 * 汇总口径（攻击零回归 + 至少一条阻断）会被「修了 A 顺带挡了别的」满足，
 * 因此补丁点名的每个候选都必须自己完成「修复前打穿 → 修复后阻断」才算 verified。
 */
function acceptanceVerdictWithAttribution(ctx, summary, evidence) {
  const verdict = acceptanceVerdict(summary);
  const attribution = buildAttribution(ctx, evidence);
  return {
    ...verdict,
    pass: verdict.pass && attribution.pass,
    attribution: {
      pass: attribution.pass,
      claimedCount: attribution.claimedCount,
      blockedCount: attribution.blockedCount,
      unverifiedCount: attribution.unverifiedCount,
      stillVulnerableCount: attribution.stillVulnerableCount,
      failing: attribution.failing
        .slice(0, 12)
        .map((r) => ({ candidate: r.candidate, status: r.status, reason: r.reason })),
      rows: attribution.rows.slice(0, 24),
    },
  };
}

/** 合并同一阶段的两份 summary（本地探测 + Supabase 探测）：计数字段相加，任一份缺失则返回另一份 */
function mergeSummary(base, add) {
  if (!base) return add ?? null;
  if (!add) return base;
  const num = (v) => (Number.isFinite(v) ? v : 0);
  const counts = { ...base.counts };
  for (const [k, v] of Object.entries(add.counts ?? {})) counts[k] = num(counts[k]) + num(v);
  const grades = { ...base.grades };
  for (const [k, v] of Object.entries(add.grades ?? {})) grades[k] = num(grades[k]) + num(v);
  return {
    ...base,
    counts,
    grades,
    total: num(base.total) + num(add.total),
    attackRepro: num(base.attackRepro) + num(add.attackRepro),
    attackBlocked: num(base.attackBlocked) + num(add.attackBlocked),
    attackRegressed: num(base.attackRegressed) + num(add.attackRegressed),
    businessPassed: num(base.businessPassed) + num(add.businessPassed),
    businessRegressed: num(base.businessRegressed) + num(add.businessRegressed),
    businessTotal: num(base.businessTotal) + num(add.businessTotal),
    supabaseLeak: num(add.leaks ?? add.supabaseLeak),
    targets: { ...(base.targets ?? {}), ...(add.targets ?? {}) },
  };
}

function fixLoopView(loop, resolvedRound = null) {
  if (!loop) return null;
  return {
    maxRounds: loop.maxRounds,
    attempts: loop.rounds.length,
    resolvedRound,
    rounds: loop.rounds,
  };
}

// ---------- 工作流各阶段 ----------

async function stageAnalyze(ctx) {
  ensureAlive(ctx);
  setState(ctx, STATE.ANALYZING);
  ctx.tokens.worktree = await requestScope(ctx, SCOPE_KINDS.WORKTREE_WRITE, "在隔离 Git worktree 中生成修复补丁");
  // 跨文件补丁（S2-full）才会申请：新建文件需要带 allow_create 的作用域，
  // 只有这一个令牌能创建文件，普通写补丁的令牌拿不到该权限。
  if (crossFilePatchEnabled(ctx)) {
    ctx.tokens.worktreeCreate = await requestScope(
      ctx,
      SCOPE_KINDS.WORKTREE_WRITE,
      "跨文件补丁：在隔离 worktree 的源码目录内新建守卫/中间件文件",
      null,
      { allowCreate: true }
    );
  }
  ctx.tokens.spawn = await requestScope(ctx, SCOPE_KINDS.PROC_SPAWN, "启动目标项目进程进行动态复现与验收");
  ctx.tokens.net = await requestScope(ctx, SCOPE_KINDS.NET_PROBE, "向本机回环地址发送诊断探测请求");

  emit(ctx, { kind: "analyze", severity: SEVERITY.INFO, message: `开始静态分析项目（${ctx.projectRoot}）`, data: {} });
  ctx.analysis = await analyzeProject(ctx);
  const cands = ctx.analysis.candidates ?? [];
  const supa = ctx.analysis.supabase ?? null;
  ctx.view.findings = cands.map((c) => ({
    id: shortId("fi"),
    method: c.method,
    path: c.fullPath ?? c.path,
    routePath: c.path,
    file: c.file,
    startLine: c.startLine,
    resource: c.resource,
    kind: c.kind,
    // GraphQL 等单端点框架：URL 不携带字段身份，报告须靠 routeKeys 指认修复点
    routeKeys: c.routeKeys ?? null,
    sinkCalls: c.sinkCalls,
    reason:
      c.kind === "no-auth-suspect"
        ? "按对象 ID 取资源且未见认证守卫（无鉴权静态线索）"
        : c.kind === "traversal-suspect"
          ? "文件读取包含请求可控路径片段（路径穿越静态线索）"
          : c.kind === "sqli-suspect"
            ? "请求输入经模板/拼接进入 SQL 查询（SQL 注入静态线索）"
            : c.kind === "cmdi-suspect"
              ? "请求输入进入 shell 执行入口（命令注入静态线索）"
              : "按对象 ID 取资源但未见归属校验（IDOR 静态线索）",
  }));
  if (supa) {
    for (const t of supa.tables ?? []) {
      ctx.view.findings.push({
        id: shortId("fi"),
        method: "SUPABASE",
        path: `table:${t.name}`,
        routePath: null,
        file: t.file,
        startLine: t.line,
        resource: t.name,
        kind: "supabase-table",
        sinkCalls: [],
        reason: "Supabase 表引用（匿名可读性由动态探测验证；RLS 缺失即数据暴露）",
      });
    }
    if (supa.serviceRoleLeak) {
      ctx.view.findings.push({
        id: shortId("fi"),
        method: "SUPABASE",
        path: supa.serviceRoleLeak.name ? `env:${supa.serviceRoleLeak.name}` : `file:${supa.serviceRoleLeak.file ?? "?"}`,
        routePath: null,
        file: supa.serviceRoleLeak.file ?? null,
        startLine: supa.serviceRoleLeak.line ?? null,
        resource: "service_role",
        kind: "supabase-service-role-leak",
        sinkCalls: [],
        reason: `service_role 密钥出现在客户端可见位置（${supa.serviceRoleLeak.source}）——可绕过 RLS 读写全库`,
      });
    }
  }
  const supaNote = supa
    ? `，并检测到 Supabase（${(supa.tables ?? []).length} 个表引用${supa.serviceRoleLeak ? "，含 service_role 客户端暴露" : ""}）`
    : "";
  emit(ctx, {
    kind: "analyze",
    severity: cands.length > 0 || supa?.serviceRoleLeak ? SEVERITY.WARN : SEVERITY.INFO,
    message:
      cands.length > 0
        ? `静态分析完成：扫描 ${ctx.analysis.fileCount} 个文件，发现 ${cands.length} 个安全候选端点${supaNote}`
        : `静态分析完成：扫描 ${ctx.analysis.fileCount} 个文件，未发现对象级越权线索${supaNote}`,
    data: {
      fileCount: ctx.analysis.fileCount,
      candidates: ctx.view.findings,
      supabase: supa
        ? {
            url: supa.url,
            tables: (supa.tables ?? []).map((t) => t.name),
            probeable: !!supa.probeable,
            serviceRoleLeak: supa.serviceRoleLeak ?? null,
          }
        : null,
    },
  });
  if (cands.length === 0 && !supa) {
    const d = ctx.analysis.diagnostics ?? {};
    const scanned = `已扫描 ${d.scannedFiles ?? 0} 个源文件（项目共 ${d.candidateFiles ?? 0} 个候选源文件${
      d.outputDirFiles > 0 ? `，其中产物目录 ${d.outputDirFiles} 个` : ""
    }${d.readFailures > 0 ? `，读取失败 ${d.readFailures} 个` : ""}）`;
    throw new SessionError(`${scanned}，未发现可探测的安全候选（未命中当前覆盖范围，非执行失败）`, {
      code: "no_candidates",
      hint: `${coverageSummary()} 想让这类项目进入检测：在 guardbuild.json 用 routes / openapi.file 声明路由，或开启 llm.enabled 做接入侦察。`,
    });
  }

  if (supa) {
    ctx.view.supabase = {
      detected: true,
      url: supa.url,
      urlSource: supa.urlSource ?? null,
      tables: (supa.tables ?? []).map((t) => t.name),
      probeable: !!supa.probeable,
      anonKeyFound: !!supa.anonKey,
      leaks: 0,
      serviceRoleLeak: supa.serviceRoleLeak ?? null,
    };
  }

  ctx.plan = buildProbePlan(ctx.analysis, { loginPathOverride: ctx.loginConfig?.path ?? null });
  const supaProbeable = ctx.plan.supabase?.probeable === true;
  const supaStaticLeak = !!ctx.plan.supabase?.serviceRoleLeak;
  if (
    !ctx.plan.readCandidate &&
    !ctx.plan.cancelCandidate &&
    !ctx.plan.unauthReadCandidate &&
    !ctx.plan.traversalCandidate &&
    !ctx.plan.sqliCandidate &&
    !ctx.plan.cmdiCandidate &&
    !supaProbeable &&
    !supaStaticLeak
  ) {
    throw new SessionError("无法构建探测计划：候选端点中缺少可探测的接口", {
      code: "plan_incomplete",
      hint: `已发现 ${cands.length} 个候选端点，但均不含「按 ID 取单体资源」的路径（如 GET /api/orders/:id）、文件读取线索、SQL/命令注入线索，也未定位到可探测的 Supabase 项目（需 URL + anon key + 至少一个表引用）。请确认目标接口形态或在 guardbuild.json 中补充契约/supabase 配置`,
    });
  }
  ctx.view.plan = {
    loginPath: ctx.plan.loginPath,
    resource: ctx.plan.resource,
    readPath: ctx.plan.readCandidate?.fullPath ?? ctx.plan.readCandidate?.path ?? null,
    cancelPath: ctx.plan.cancelCandidate?.fullPath ?? ctx.plan.cancelCandidate?.path ?? null,
    unauthReadPath: ctx.plan.unauthReadCandidate?.fullPath ?? ctx.plan.unauthReadCandidate?.path ?? null,
    traversalPath: ctx.plan.traversalCandidate?.fullPath ?? ctx.plan.traversalCandidate?.path ?? null,
    sqliPath: ctx.plan.sqliCandidate?.fullPath ?? ctx.plan.sqliCandidate?.path ?? null,
    cmdiPath: ctx.plan.cmdiCandidate?.fullPath ?? ctx.plan.cmdiCandidate?.path ?? null,
    listPath: ctx.plan.listEndpoint?.path ?? null,
  };
  pushView(ctx);
  return ctx.plan;
}

/** 把启动失败压缩成可进视图/报告的一条记录；不带进程输出（可能含目标项目的敏感信息）。 */
function startFailureRecord(e) {
  const diag = e?.details?.diagnosis ?? null;
  return {
    code: e?.code ?? "unknown",
    hint: e?.hint ?? diag?.hint ?? null,
    diagnosisCode: diag?.code ?? null,
    exitCode: Number.isInteger(diag?.exitCode)
      ? diag.exitCode
      : Number.isInteger(e?.details?.exitCode)
        ? e.details.exitCode
        : null,
  };
}

/**
 * 按 scout 候选顺序实际启动，直到有一个真正就绪。
 * 只有可重试的启动错误才继续下一个候选；配置非法等错误直接抛出。
 */
async function tryScoutStartCandidates(ctx, { cwd, label, role }) {
  const candidates =
    Array.isArray(ctx.scoutStartCandidates) && ctx.scoutStartCandidates.length
      ? ctx.scoutStartCandidates
      : [ctx.targetConfig.start];
  const attempts = ctx.view.llm.startAttempts;
  const deadline = Date.now() + START_RETRY_BUDGET_MS;
  let lastError = null;
  for (let i = 0; i < candidates.length; i++) {
    ensureAlive(ctx);
    const candidate = candidates[i];
    const attempt = {
      index: i + 1,
      total: candidates.length,
      cmd: candidate.cmd,
      args: [...(candidate.args ?? [])],
      cwd: candidate.cwd ?? null,
      ok: false,
      code: null,
      diagnosisCode: null,
      exitCode: null,
      hint: null,
      durationMs: 0,
      skipped: false,
    };
    attempts.push(attempt);
    let start = candidate;
    if (i > 0) {
      const remaining = deadline - Date.now();
      if (remaining < 5_000) {
        attempt.skipped = true;
        attempt.code = "budget_exhausted";
        attempt.hint = `启动候选重试预算（${START_RETRY_BUDGET_MS}ms）已用尽，未尝试该候选`;
        pushView(ctx);
        emit(ctx, {
          kind: "scout",
          severity: SEVERITY.WARN,
          message: `启动候选 ${i + 1}/${candidates.length} 跳过：${attempt.hint}`,
          phase: STATE.PROBING,
          data: { attempt },
        });
        continue;
      }
      // 备用候选只能用剩余预算，避免一个慢候选拖垮整轮重试
      start = { ...candidate, readyTimeoutMs: Math.min(candidate.readyTimeoutMs ?? 30_000, remaining) };
      emit(ctx, {
        kind: "scout",
        severity: SEVERITY.INFO,
        message: `上次候选未通过，继续尝试启动候选 ${i + 1}/${candidates.length}：${candidate.cmd} ${(candidate.args ?? []).join(" ")}`.trim(),
        phase: STATE.PROBING,
        data: { attempt },
      });
    }
    ctx.targetConfig.start = start;
    ctx.targetConfig.startSource = "llm-scout";
    const t0 = Date.now();
    try {
      const target = await spawnTarget(ctx, { cwd, label, role });
      attempt.ok = true;
      attempt.durationMs = Date.now() - t0;
      ctx.targetConfig.start = candidate;
      pushView(ctx);
      return { target, start: candidate };
    } catch (e) {
      lastError = e;
      attempt.durationMs = Date.now() - t0;
      Object.assign(attempt, startFailureRecord(e));
      pushView(ctx);
      const retryable = RETRYABLE_START_CODES.has(e.code);
      emit(ctx, {
        kind: "scout",
        severity: retryable ? SEVERITY.WARN : SEVERITY.ERROR,
        message: `LLM 启动候选 ${i + 1}/${candidates.length} 未通过实际启动（${e.message}${
          attempt.hint ? `；诊断：${attempt.hint}` : ""
        }）`,
        phase: STATE.PROBING,
        data: { attempt },
      });
      if (!retryable) throw e;
      if (ctx.targetConfig?.docker?.enabled) await cleanupDockerContainers(ctx);
    }
  }
  return { target: null, start: null, error: lastError };
}

/** 所有 LLM 启动候选都失败时，回退到自动探测/缺省契约并重试一次。 */
async function fallbackToDeterministicStart(ctx, error) {
  if (!ctx.scoutFallbackStart) {
    throw error ?? new SessionError("LLM 启动候选全部失败，且没有可回退的确定性启动契约", {
      code: "target_spawn_failed",
      hint: "请在 guardbuild.json 中声明可用的 start 契约",
    });
  }
  const attempts = (ctx.view.llm?.startAttempts ?? []).filter((a) => !a.skipped);
  const rejected = ctx.scoutStartCandidates?.[0] ?? ctx.targetConfig.start;
  emit(ctx, {
    kind: "scout",
    severity: SEVERITY.WARN,
    message: `${attempts.length > 1 ? `${attempts.length} 个 LLM 启动候选都` : "LLM 启动契约"}未通过实际启动验证（${
      error?.message ?? "未知错误"
    }），回退到${ctx.scoutFallbackStart.startSource === "auto" ? "自动探测" : "缺省"}启动契约重试`,
    phase: STATE.PROBING,
    data: { error: error?.message ?? null, code: error?.code ?? null, attempts },
  });
  ctx.targetConfig.start = ctx.scoutFallbackStart.start;
  ctx.targetConfig.startSource = ctx.scoutFallbackStart.startSource;
  ctx.scoutApplied.start = false;
  ctx.scoutStartCandidates = null;
  ctx.scoutFallbackStart = null;
  recordScoutVerification(ctx, {
    start: false,
    rejectedStart: rejected,
    rejectedStarts: attempts.map((a) => ({
      cmd: a.cmd,
      args: a.args,
      ok: a.ok,
      code: a.code,
      diagnosisCode: a.diagnosisCode,
    })),
  });
  if (ctx.view.llm) {
    ctx.view.llm.rejectedStart = rejected;
    pushView(ctx);
  }
  return spawnTarget(ctx, { cwd: ctx.projectRoot, label: "原始工作区（修复前）", role: "target-pre" });
}

async function stageReproduce(ctx) {
  ensureAlive(ctx);
  setState(ctx, STATE.PROBING);

  const plan = ctx.plan ?? {};
  const hasLocalProbes = !!(
    plan.readCandidate ||
    plan.cancelCandidate ||
    plan.unauthReadCandidate ||
    plan.traversalCandidate ||
    plan.sqliCandidate ||
    plan.cmdiCandidate
  );
  const supa = plan.supabase ?? null;

  let pre = null;
  if (hasLocalProbes) {
    await runPrepare(ctx, { cwd: ctx.projectRoot, label: "原始工作区" });
    if (ctx.scoutApplied?.start) recordScoutVerification(ctx, { start: false });
    let target;
    let verifiedStart = null;
    if (ctx.scoutApplied?.start) {
      const res = await tryScoutStartCandidates(ctx, {
        cwd: ctx.projectRoot,
        label: "原始工作区（修复前）",
        role: "target-pre",
      });
      target = res.target;
      verifiedStart = res.start;
      if (!target) target = await fallbackToDeterministicStart(ctx, res.error);
    } else {
      target = await spawnTarget(ctx, { cwd: ctx.projectRoot, label: "原始工作区（修复前）", role: "target-pre" });
    }
    ctx.procs.original = target;
    ctx.view.targets.original = { ...target, role: "原始工作区（修复前）" };
    pushView(ctx);
    if (ctx.scoutApplied?.start) {
      recordScoutVerification(ctx, { start: true, workingStart: verifiedStart ?? ctx.targetConfig.start });
      ctx.view.llm.verified.start = true;
      pushView(ctx);
      emit(ctx, {
        kind: "scout",
        severity: SEVERITY.SUCCESS,
        message: `LLM 启动契约已验证：目标进程按「${ctx.targetConfig.start.cmd} ${ctx.targetConfig.start.args.join(" ")}」成功就绪（${target.url}）`,
        phase: STATE.PROBING,
        data: { start: ctx.targetConfig.start, url: target.url },
      });
    }

    if (ctx.scoutApplied?.login) recordScoutVerification(ctx, { login: false });
    try {
      pre = await runPhase(ctx, { phase: "pre", baseUrl: target.url });
    } catch (e) {
      if (ctx.scoutApplied?.login) recordScoutVerification(ctx, { login: !!ctx._loginVerified });
      throw e;
    }
    ctx.pushEvidence(pre.evidence);
    ctx.view.phases.pre = pre.summary;
    ctx.view.baseline = acceptanceVerdict(pre.summary);
    if (ctx.scoutApplied?.login) {
      recordScoutVerification(ctx, { login: !!ctx._loginVerified });
    }
    if (ctx.scoutApplied?.login && ctx._loginVerified) {
      ctx.view.llm.verified.login = true;
      pushView(ctx);
      emit(ctx, {
        kind: "scout",
        severity: SEVERITY.SUCCESS,
        message: `LLM 登录契约已验证：使用 guardbuild.json 提供的身份成功登录（${ctx.loginConfig.path}）`,
        phase: STATE.PROBING,
        data: { login: { ...ctx.loginConfig, path: ctx.loginConfig.path } },
      });
    } else {
      pushView(ctx);
    }
  } else {
    emit(ctx, {
      kind: "probing",
      severity: SEVERITY.INFO,
      message: "未发现可本地复现的越权/穿越/注入候选，跳过本地目标启动（仅进行 Supabase 探测）",
      phase: STATE.PROBING,
      data: {},
    });
  }

  let supaRes = null;
  if (supa?.probeable) {
    const token = await ensureSupabaseToken(ctx, supa.url);
    supaRes = await runSupabasePhase(ctx, { phase: "pre", token });
    if (supaRes.evidence.length > 0) ctx.pushEvidence(supaRes.evidence);
    ctx.view.phases.pre = mergeSummary(ctx.view.phases.pre ?? null, supaRes.summary);
    pushView(ctx);
  }
  const supaLeaks = supaRes?.leaks ?? 0;
  ctx.supabaseLeaks = supaLeaks;
  ctx.serviceRoleLeak = supa?.serviceRoleLeak ?? null;
  if (ctx.view.supabase) ctx.view.supabase = { ...ctx.view.supabase, leaks: supaLeaks };

  const mergedRepro = (pre?.summary?.attackRepro ?? 0) + supaLeaks;
  if (mergedRepro === 0 && !ctx.serviceRoleLeak) {
    throw new SessionError("攻击用例在修复前即无法复现，无法建立漏洞基线", {
      code: "attack_not_reproducible",
      hint: hasLocalProbes
        ? "目标端点可能已有防护，或身份/资源发现结果不符合预期；Supabase 各表匿名不可读出数据（RLS 已生效）"
        : "Supabase 各表匿名均不可读出数据（RLS 已生效或表为空），且未见 service_role 客户端暴露",
      details: ctx.view.phases.pre ?? supaRes?.summary ?? null,
    });
  }
  setState(ctx, STATE.EVIDENCED);
  return pre ?? supaRes;
}

async function stagePatch(ctx) {
  ensureAlive(ctx);
  setState(ctx, STATE.PATCHING);

  // Supabase 数据暴露属数据库策略/密钥管理问题，不在代码层自动修复 → 直接判定漏洞未修复（gate exit 1）
  const supaLeaks = ctx.supabaseLeaks ?? 0;
  const serviceRoleLeak = ctx.serviceRoleLeak ?? null;
  if (supaLeaks > 0 || serviceRoleLeak) {
    const leakTables = (ctx.view.supabase?.tables ?? []).slice(0, 8);
    const hints = [];
    if (supaLeaks > 0) {
      hints.push(
        `对匿名可读的表启用行级安全（RLS）并按操作建策略：ALTER TABLE <表名> ENABLE ROW LEVEL SECURITY; CREATE POLICY ... USING (auth.uid() = user_id)（泄露表：${leakTables.join("、")}）`
      );
    }
    if (serviceRoleLeak) {
      hints.push(
        `立即在 Supabase 控制台吊销并轮换 service_role 密钥（它能绕过 RLS 读写全库），将其移出客户端可见位置（source: ${serviceRoleLeak.source}${serviceRoleLeak.name ? `, env: ${serviceRoleLeak.name}` : ""}${serviceRoleLeak.file ? `, file: ${serviceRoleLeak.file}` : ""}）`
      );
    }
    throw new SessionError(
      `检测到 Supabase 数据暴露（RLS 缺失 ${supaLeaks} 个表${serviceRoleLeak ? "，且 service_role 密钥客户端暴露" : ""}）——属数据库策略/密钥管理问题，不在代码层自动修复`,
      {
        code: "no_patchable_candidates",
        hint: `${hints.join("；")}。修复后重跑 GuardBuild gate 验证（应转为 exit 0）。`,
        details: { supabaseLeaks: supaLeaks, serviceRoleLeak, leakTables },
      }
    );
  }

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
  setClaimedCandidates(ctx, result);
  const lineCount = result.patch.diff.split("\n").filter((l) => l.startsWith("+") || l.startsWith("-")).length;
  const usedLlm = !!result.usedLlm;
  const autoVerify = usedLlm && ctx.llmConfig?.autoVerify !== false;
  // 修复循环只在交互/本地模式启用；gate 始终单轮、无自主重试
  const configuredRounds = Number(ctx.llmConfig?.fixRounds);
  const maxFixRounds =
    !ctx.gate && autoVerify
      ? Number.isFinite(configuredRounds)
        ? Math.min(5, Math.max(0, Math.floor(configuredRounds)))
        : 2
      : 0;
  ctx.fixLoop = { maxRounds: maxFixRounds, round: 0, rounds: [] };
  ctx.view.patch = {
    hash: result.patch.hash,
    diff: result.patch.diff,
    files: result.patch.files,
    worktree: result.worktree,
    status: "pending_review",
    lineCount,
    fixes: result.filePatches,
    claimed: result.claimedKeys ?? [],
    skipped: result.skipped,
    strategy: result.filePatches.flatMap((f) => f.fixes.map((x) => x.strategy)).join(",") || "none",
    llm: result.llm?.enabled ? result.llm : null,
    autoVerify,
    scope: result.scope ?? null,
    fixLoop: fixLoopView(ctx.fixLoop),
  };
  pushView(ctx);

  await runPrepare(ctx, { cwd: result.worktree, label: "隔离工作区" });
  const wt = await spawnTarget(ctx, { cwd: result.worktree, label: "隔离工作区（修复候选）", role: "target-post" });
  ctx.procs.worktree = wt;
  ctx.view.targets.worktree = { ...wt, role: "隔离工作区（修复候选）" };
  pushView(ctx);

  // LLM 编码代理产出的补丁：先自动跑双重验收（攻击失效 + 业务不回归），通过后才进人工审查。
  // 确定性模板补丁保持原样（人工批准后再验收），避免改变既有 gate/交互流程语义。
  if (autoVerify) {
    emit(ctx, {
      kind: "patch",
      severity: SEVERITY.INFO,
      message: `补丁含 LLM 编码代理产出的意图（patch_hash ${result.patch.hash.slice(0, 12)}…），自动执行双重验收；通过后再交您审查 Diff 与写回`,
      phase: STATE.PATCHING,
      data: { patchHash: result.patch.hash, lineCount, strategy: ctx.view.patch.strategy, llm: result.llm },
    });
    return { ...result, autoVerify: true };
  }

  setState(ctx, STATE.PATCH_REVIEW);
  emit(ctx, {
    kind: "patch",
    severity: SEVERITY.INFO,
    message: `补丁已就绪（patch_hash ${result.patch.hash.slice(0, 12)}…），等待您在界面审查 Diff 并授权隔离验收`,
    phase: STATE.PATCH_REVIEW,
    data: { patchHash: result.patch.hash, lineCount },
  });
  return { ...result, autoVerify: false };
}

async function stageVerify(ctx) {
  ensureAlive(ctx);
  setState(ctx, STATE.VERIFYING);

  for (;;) {
    const wtTarget = ctx.procs.worktree;
    if (!wtTarget) throw new SessionError("隔离实例未运行，无法验收", { code: "no_worktree_target" });
    const loop = ctx.fixLoop ?? null;
    const roundNo = (loop?.round ?? 0) + 1;
    const roundText = loop?.maxRounds > 0 ? `（第 ${roundNo} 轮，最多 ${loop.maxRounds + 1} 轮）` : "";

    emit(ctx, {
      kind: "verify",
      severity: SEVERITY.INFO,
      message: `在隔离实例上执行双重验收${roundText}（攻击阻断 + 业务回归）`,
      phase: STATE.VERIFYING,
      data: { round: roundNo },
    });
    const post = await runPhase(ctx, { phase: "post", baseUrl: wtTarget.url });
    ctx.pushEvidence(post.evidence);
    ctx.view.phases.post = post.summary;
    recordAcceptanceRows(ctx, "post", post.evidence);

    const verdict = acceptanceVerdictWithAttribution(ctx, post.summary, post.evidence);
    ctx.view.acceptance = { ...verdict, phase: "post", at: Date.now(), round: roundNo };
    pushView(ctx);

    if (verdict.pass) {
      if (loop) loop.rounds.push({ round: roundNo, patchHash: ctx.view.patch?.hash ?? null, pass: true, verdict });
      if (ctx.view.patch) ctx.view.patch.fixLoop = fixLoopView(loop, roundNo);
      pushView(ctx);

      await emitReport(ctx, { outcome: "vulnerable", patchStatus: "verified", exitCode: 1, state: STATE.WRITEBACK_PENDING });
      // gate 模式结构化禁止写回，验收通过即可清理；交互模式需保留到用户授权写回之后
      if (ctx.gate) await removeWorktree(ctx);
      setState(ctx, STATE.WRITEBACK_PENDING);
      emit(ctx, {
        kind: "verify",
        severity: SEVERITY.SUCCESS,
        message: `双重验收通过：攻击阻断 ${verdict.attackBlocked}/${verdict.attackTotal}，业务保持 ${verdict.businessPassed}/${verdict.businessTotal}${
          loop && loop.rounds.length > 1 ? `（经 ${roundNo} 轮修正）` : ""
        }`,
        phase: STATE.WRITEBACK_PENDING,
        data: verdict,
      });
      return post;
    }

    const failed = post.evidence
      .filter((e) => e.verdict === VERDICT.REGRESSED || e.verdict === VERDICT.INCONCLUSIVE)
      .map((e) => `${e.caseName}（${e.actual}）`);
    // 归因不成立的候选即使汇总计数好看也要回喂：否则代理收到「全绿」却不知道自己没修到那条入口
    for (const r of verdict.attribution.failing) {
      failed.unshift(`归因不成立：${r.candidate} —— ${r.reason}`);
    }
    if (loop) {
      loop.rounds.push({
        round: roundNo,
        patchHash: ctx.view.patch?.hash ?? null,
        pass: false,
        verdict,
        failed: failed.slice(0, 8),
        llm: ctx.view.patch?.llm
          ? {
              model: ctx.view.patch.llm.model ?? null,
              appliedOps: ctx.view.patch.llm.appliedOps ?? 0,
              rejected: (ctx.view.patch.llm.rejected ?? []).length,
            }
          : null,
        at: Date.now(),
      });
    }

    const canRetry = !ctx.gate && loop && loop.maxRounds > 0 && loop.round < loop.maxRounds;
    if (canRetry) {
      const nextRound = roundNo + 1;
      emit(ctx, {
        kind: "verify",
        severity: SEVERITY.WARN,
        message: `第 ${roundNo} 轮验收未通过（攻击回归 ${verdict.attackRegressed}，业务回归 ${verdict.businessRegressed}${
          verdict.attribution.failing.length ? `，${verdict.attribution.failing.length} 个点名入口归因不成立` : ""
        }）；把失败证据回传给编码代理生成第 ${nextRound} 轮补丁`,
        phase: STATE.VERIFYING,
        data: { round: roundNo, failed: failed.slice(0, 8), remaining: loop.maxRounds - loop.round },
      });

      let result;
      try {
        const feedback = await buildFixFeedback(ctx, {
          post,
          verdict,
          round: roundNo,
          previousDiff: ctx.view.patch?.diff ?? null,
        });
        const prevRound = loop.rounds[loop.rounds.length - 1];
        if (prevRound && prevRound.round === roundNo) prevRound.feedback = feedbackDigest(feedback);
        result = await createPatch(ctx, { feedback });
      } catch (e) {
        const err = new SessionError(`修复循环在第 ${nextRound} 轮中止：${e.message}`, {
          code: "verify_failed",
          hint: e.hint ?? "上一轮补丁未通过验收，且未能生成修订补丁；请人工查看 post 证据",
          details: { cause: e.code ?? null, causeDetails: e.details ?? null, rounds: loop.rounds },
        });
        if (ctx.view.patch) ctx.view.patch.fixLoop = fixLoopView(loop);
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

      loop.round += 1;
      await discardWorktree(ctx);
      setClaimedCandidates(ctx, result);
      const lineCount = result.patch.diff.split("\n").filter((l) => l.startsWith("+") || l.startsWith("-")).length;
      ctx.view.patch = {
        hash: result.patch.hash,
        diff: result.patch.diff,
        files: result.patch.files,
        worktree: result.worktree,
        status: "pending_review",
        lineCount,
        fixes: result.filePatches,
        claimed: result.claimedKeys ?? [],
        skipped: result.skipped,
        strategy: result.filePatches.flatMap((f) => f.fixes.map((x) => x.strategy)).join(",") || "none",
        llm: result.llm?.enabled ? result.llm : null,
        autoVerify: true,
        scope: result.scope ?? null,
        fixLoop: fixLoopView(loop),
      };
      pushView(ctx);
      emit(ctx, {
        kind: "patch",
        severity: SEVERITY.INFO,
        message: `编码代理已根据失败证据重写补丁（第 ${nextRound} 轮，patch_hash ${result.patch.hash.slice(0, 12)}…），重启隔离实例复测`,
        phase: STATE.VERIFYING,
        data: { round: nextRound, patchHash: result.patch.hash, llm: result.llm },
      });

      await runPrepare(ctx, { cwd: result.worktree, label: `隔离工作区（第 ${nextRound} 轮）` });
      const wt = await spawnTarget(ctx, {
        cwd: result.worktree,
        label: `隔离工作区（第 ${nextRound} 轮）`,
        role: "target-post",
      });
      ctx.procs.worktree = wt;
      ctx.view.targets.worktree = { ...wt, role: `隔离工作区（第 ${nextRound} 轮）` };
      pushView(ctx);
      continue;
    }

    if (ctx.view.patch) ctx.view.patch.fixLoop = fixLoopView(loop);
    const err = new SessionError("修复验收未通过：存在未阻断的攻击或业务回归", {
      code: "verify_failed",
      hint: "补丁已保留在隔离 worktree 中，可回看证据调整修复策略",
      details: { failed, summary: post.summary, rounds: loop?.rounds ?? [] },
    });
    await emitReport(ctx, {
      outcome: "vulnerable",
      patchStatus: "verify_failed",
      exitCode: 1,
      state: STATE.VERIFY_FAILED,
      error: { code: err.code, message: err.message, hint: err.hint, details: err.details },
    });
    // gate 会在状态跃迁时立即退出，必须先清掉临时 worktree；交互模式保留现场供审查
    if (ctx.gate) await removeWorktree(ctx);
    setState(ctx, STATE.VERIFY_FAILED);
    throw err;
  }
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
    const verdict = acceptanceVerdictWithAttribution(ctx, re.summary, re.evidence);
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

// ---------- 纯黑盒外部模式 ----------

/**
 * 纯黑盒模式：只对已运行目标发起外部 HTTP 攻击，不读源码、不启动目标、不生成补丁。
 * guardbuild.json 仅用于读取 login/identities/blackbox 配置；证据全部来自外部请求。
 */
async function runBlackboxFlow(ctx, rawUrl) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new SessionError(`黑盒目标 URL 非法：${rawUrl}`, {
      code: "blackbox_bad_url",
      hint: "请传入完整 URL（如 https://example.com 或 http://127.0.0.1:3000）",
    });
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new SessionError(`黑盒模式仅支持 http/https：${parsed.protocol}`, {
      code: "blackbox_bad_url",
      hint: "请使用 http(s) URL 指向已运行的目标服务",
    });
  }
  if (parsed.username || parsed.password) {
    throw new SessionError("黑盒目标 URL 不能内嵌账号密码", {
      code: "blackbox_bad_url",
      hint: "请在 guardbuild.json 的 identities 中提供测试身份，由 Host 保险库注入凭据",
    });
  }
  const baseUrl = `${parsed.origin}${parsed.pathname === "/" ? "" : parsed.pathname.replace(/\/+$/, "")}`;
  const host = parsed.hostname.toLowerCase();

  setState(ctx, STATE.PROBING);
  emit(ctx, {
    kind: "session",
    severity: SEVERITY.INFO,
    message: `纯黑盒外部模式：目标 ${baseUrl}（不读源码、不启动本地服务、不生成补丁）`,
    data: { sessionId: ctx.sessionId, blackbox: true, host },
  });

  if (isLoopbackHostname(host)) {
    ctx.tokens.http = await requestScope(ctx, SCOPE_KINDS.NET_PROBE, `向本机回环目标 ${host} 发起黑盒攻击探测`);
  } else {
    if (parsed.protocol !== "https:") {
      throw new SessionError("远程黑盒目标仅支持 https（明文 http 仅限本机回环）", {
        code: "blackbox_insecure_url",
        hint: "请使用 https URL；本机调试可用 http://127.0.0.1:<port>",
      });
    }
    ctx.tokens.http = await requestScope(
      ctx,
      SCOPE_KINDS.NET_EGRESS,
      `向 ${host} 发起黑盒攻击探测`,
      host
    );
  }

  const cfg = await loadBlackboxConfig(ctx);
  if (cfg.source === "invalid") {
    emit(ctx, {
      kind: "session",
      severity: SEVERITY.WARN,
      message: `guardbuild.json 解析失败（${cfg.invalid}）：黑盒模式将使用内建演示身份尝试登录`,
      data: { invalid: cfg.invalid },
    });
  } else if (cfg.source === "none") {
    emit(ctx, {
      kind: "session",
      severity: SEVERITY.INFO,
      message: "项目目录未提供 guardbuild.json：仅做未认证攻击面探测，并使用内建演示身份尝试登录",
      data: {},
    });
  }
  if (cfg.login) ctx.loginConfig = cfg.login;
  if (cfg.identities) ctx.identities = cfg.identities;

  const allowMutation =
    process.env.GUARDBUILD_BLACKBOX_MUTATE === "1" || cfg.blackbox?.allowMutation === true;
  const configuredMaxRoutes = Number.isFinite(cfg.blackbox?.maxRoutes) ? cfg.blackbox.maxRoutes : null;
  // 先落一份最小视图：扫描（含不可达）失败时报告仍能按黑盒模式渲染。
  ctx.view.blackbox = {
    mode: "blackbox",
    url: baseUrl,
    routeCount: 0,
    routes: [],
    openapiFound: false,
    openapiRouteCount: 0,
    frontendRouteCount: 0,
    frontendScripts: 0,
    findings: [],
    evidenceCount: 0,
    login: null,
    rateLimited: false,
    allowMutation,
    maxRoutes: configuredMaxRoutes,
    reachable: null,
    outcome: null,
    exitCode: null,
  };
  const result = await runBlackbox(ctx, baseUrl, { config: cfg, allowMutation });

  if (!result.reachable) {
    ctx.view.blackbox.reachable = false;
    ctx.view.blackbox.outcome = "failed";
    ctx.view.blackbox.exitCode = 2;
    pushView(ctx);
    throw new SessionError(`黑盒目标不可达：${baseUrl}`, {
      code: "blackbox_unreachable",
      hint: "请确认目标服务已启动、URL/端口正确；远程目标需 https 且 Host 已授予 net.egress:<host> 作用域",
    });
  }

  const outcome = result.findings.length > 0 ? "vulnerable_unfixed" : "no_findings";
  const exitCode = result.findings.length > 0 ? 1 : 0;
  ctx.view.targets.blackbox = { url: baseUrl, role: "外部黑盒目标" };
  ctx.view.phases.blackbox = result.summary;
  ctx.view.blackbox = {
    mode: "blackbox",
    url: baseUrl,
    routeCount: result.routes.length,
    routes: result.routes.map((r) => ({ method: r.method, path: r.path, source: r.source ?? null })),
    openapiFound: result.openapiFound,
    openapiRouteCount: result.openapiRouteCount,
    frontendRouteCount: result.frontendRouteCount ?? 0,
    frontendScripts: result.frontendScripts ?? 0,
    findings: result.findings,
    evidenceCount: result.evidence.length,
    login: result.login,
    rateLimited: result.rateLimited,
    allowMutation: result.configuredMutation,
    maxRoutes: result.maxRoutes ?? configuredMaxRoutes,
    reachable: true,
    outcome,
    exitCode,
  };
  ctx.pushEvidence(result.evidence);
  pushView(ctx);

  emit(ctx, {
    kind: "session",
    severity: result.findings.length > 0 ? SEVERITY.ERROR : SEVERITY.SUCCESS,
    message:
      result.findings.length > 0
        ? `黑盒扫描完成：${result.routes.length} 条路由，发现 ${result.findings.length} 个可复现漏洞`
        : `黑盒扫描完成：${result.routes.length} 条路由，未发现可复现漏洞（仅覆盖本次探测面）`,
    data: { ...result.summary, outcome, exitCode },
  });

  setState(ctx, STATE.EVIDENCED);
  await emitReport(ctx, { outcome, exitCode, state: STATE.COMPLETED });
  setState(ctx, STATE.COMPLETED);
  await shutdownProcs(ctx);
  endSession(ctx);
}

// ---------- 会话主流程 ----------

async function runFlow(ctx) {
  const sessionId = ctx.sessionId;
  try {
    ctx.db.ensureProject(ctx.projectRoot, ctx.projectRoot, ctx.projectName);
    ctx.db.ensureSession(sessionId, ctx.projectRoot, ctx.projectRoot);
    pushView(ctx);

    const blackboxUrl = ctx.blackboxUrl || process.env.GUARDBUILD_BLACKBOX_URL;
    if (blackboxUrl) {
      await runBlackboxFlow(ctx, blackboxUrl);
      return;
    }

    emit(ctx, {
      kind: "session",
      severity: SEVERITY.INFO,
      message: `编排开始：目标项目 ${ctx.projectRoot}`,
      data: { sessionId },
    });

    const targetConfig = await loadTargetConfig(ctx);
    ctx.targetConfig = targetConfig;
    if (targetConfig.docker?.enabled) {
      ctx.view.targets.docker = {
        enabled: true,
        image: targetConfig.docker.image,
        containerPort: targetConfig.docker.containerPort,
        workdir: targetConfig.docker.workdir,
      };
      emit(ctx, {
        kind: "session",
        severity: SEVERITY.INFO,
        message: `[Docker] 沙箱已启用：${targetConfig.docker.image}；项目挂载到 ${targetConfig.docker.workdir}；容器监听 ${targetConfig.docker.containerPort}（宿主端口动态分配）；就绪判定为 HTTP 探活`,
        data: { docker: ctx.view.targets.docker },
      });
    }
    ctx.loginConfig = targetConfig.login ?? null;
    ctx.llmConfig = targetConfig.llm ?? null;
    ctx.llmGetToken = (url, reason) => ensureLlmToken(ctx, url, reason);
    if (targetConfig.identities) {
      ctx.identities = targetConfig.identities;
    }
    const autostart = targetConfig.autostart ?? null;
    const startDesc =
      `${targetConfig.start.cmd} ${targetConfig.start.args.join(" ")}`.trim() +
      (targetConfig.start.cwd ? `（工作目录 ${targetConfig.start.cwd}）` : "");
    if (targetConfig.source === "invalid") {
      emit(ctx, {
        kind: "session",
        severity: SEVERITY.WARN,
        message: `guardbuild.json 解析失败（${targetConfig.invalid}），${
          targetConfig.startSource === "auto" ? "已自动探测启动方式" : "回落到缺省启动契约（node server.js + GB_LISTEN）"
        }`,
        data: { invalid: targetConfig.invalid, startSource: targetConfig.startSource },
      });
    }
    if (targetConfig.startSource === "auto") {
      emit(ctx, {
        kind: "session",
        severity: SEVERITY.INFO,
        message: `未在契约中声明 start，已自动探测启动方式：${startDesc}（依据 ${autostart?.origin ?? "项目文件"}）`,
        data: {
          start: targetConfig.start,
          startSource: "auto",
          autostart,
          login: targetConfig.login,
          prepare: targetConfig.prepare,
          identities: targetConfig.identities ? targetConfig.identities.map((i) => i.name) : null,
          scopes: targetConfig.scopes,
        },
      });
    } else if (targetConfig.source === "guardbuild.json") {
      const extras = [
        targetConfig.login ? `登录端点 ${targetConfig.login.path}` : null,
        targetConfig.prepare?.length ? `准备步骤 ${targetConfig.prepare.length} 个` : null,
      ].filter(Boolean);
      emit(ctx, {
        kind: "session",
        severity: SEVERITY.INFO,
        message: `已加载启动契约 guardbuild.json：${startDesc}（就绪模式 ${targetConfig.start.readyPattern}${extras.length ? `；${extras.join("，")}` : ""}）`,
        data: {
          start: targetConfig.start,
          startSource: "contract",
          login: targetConfig.login,
          prepare: targetConfig.prepare,
          identities: targetConfig.identities ? targetConfig.identities.map((i) => i.name) : null,
          scopes: targetConfig.scopes,
        },
      });
    } else if (targetConfig.startSource === "default" && targetConfig.source === "default") {
      emit(ctx, {
        kind: "session",
        severity: SEVERITY.INFO,
        message: `未发现 guardbuild.json，也未能自动探测启动方式，回落到缺省契约（node server.js + GB_LISTEN）；如项目启动命令不同，请添加 guardbuild.json 的 start`,
        data: { start: targetConfig.start, startSource: "default", autostart },
      });
    }
    if (targetConfig.startSource !== "contract") {
      for (const w of (autostart?.warnings ?? []).slice(0, 4)) {
        emit(ctx, { kind: "session", severity: SEVERITY.WARN, message: w, data: { startSource: targetConfig.startSource } });
      }
      if (autostart?.alternatives?.length) {
        emit(ctx, {
          kind: "session",
          severity: SEVERITY.INFO,
          message: `其他可用启动方式：${autostart.alternatives.slice(0, 4).join("；")}`,
          data: { alternatives: autostart.alternatives },
        });
      }
    }

    await stageScout(ctx, targetConfig);
    await stageAnalyze(ctx);
    await stageReproduce(ctx);
    const patchResult = await stagePatch(ctx);
    // 未走自动验收时，进入 patch_review 后等待用户的 patch.approved 指令（见上方 handler）
    if (patchResult?.autoVerify) await stageVerify(ctx);
  } catch (e) {
    // 用户已请求中止时，吊销令牌/结束进程导致的在途 RPC 失败也归为中止
    if (ctx.cancelled || e instanceof CancelledError) {
      abortSession(ctx);
      return;
    }
    // 自动双重验收未通过：报告与终态（verify_failed）已在 stageVerify 内落定，
    // 不能再改写为「执行失败」——否则报告丢漏洞裁决，gate 还可能因状态竞态退成 2
    if (e.code === "verify_failed") {
      shutdownProcs(ctx).catch(() => {});
      endSession(ctx);
      return;
    }
    failSession(ctx, e);
  }
}

async function abortSession(ctx) {
  emit(ctx, { kind: "session", severity: SEVERITY.WARN, message: "会话已中止", data: {} });
  await emitReport(ctx, { outcome: "aborted", exitCode: 2, state: STATE.ABORTED });
  await removeWorktree(ctx);
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
  // Host 错误走 JSON-RPC 数字码，符号名在 data.code_name（conflict / scope_denied …）
  const code = typeof e.code === "number" ? e.data?.code_name ?? String(e.code) : e.code ?? "internal";
  const pres = describeOutcome(code);
  const payload = {
    code,
    message: e.message,
    hint: e.hint ?? null,
    details: e.details ?? null,
    outcome: pres.outcome,
    kind: pres.kind,
    title: pres.title,
    semanticHint: pres.hint,
  };
  await emitReport(ctx, {
    outcome: pres.outcome,
    exitCode: pres.exitCode,
    state: STATE.ERROR,
    error: payload,
  });
  ctx.view.error = payload;
  emit(ctx, {
    kind: "session",
    severity: pres.severity === "error" ? SEVERITY.ERROR : SEVERITY.WARN,
    message: `${pres.title}：${e.message}${e.hint ? `（建议：${e.hint}）` : ""}`,
    data: payload,
  });
  await removeWorktree(ctx);
  // 内部状态仍记为 error（便于会话槽位释放与终态判定），但面向用户的标签要说清语义：
  // exit 0 的「未命中覆盖范围 / 未发现可复现漏洞」不是执行失败。
  ctx.outcomeLabel = pres.kind === "failed" ? null : pres.stateLabel;
  if (ctx.sm.can(STATE.ERROR)) {
    setState(ctx, STATE.ERROR);
  } else {
    ctx.sm.state = STATE.ERROR;
    ctx.view.state = STATE.ERROR;
    ctx.view.stateLabel = ctx.outcomeLabel || STATE_LABELS[STATE.ERROR];
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
    // 旧会话若保留了 worktree（如交互式 verify_failed），新会话启动时一并清理
    await removeWorktree(active);
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
  // 空闲等待用户操作的阶段直接中止；运行中的阶段会在下一个检查点退出。
  // 必须 await：Host 在收到确认后立即吊销令牌，worktree 清理需在此之前完成。
  const idleStates = [STATE.PATCH_REVIEW, STATE.WRITEBACK_PENDING, STATE.VERIFY_FAILED];
  if (ctx.sm && idleStates.includes(ctx.sm.state)) await abortSession(ctx);
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
    await removeWorktree(ctx);
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
    await removeWorktree(ctx);
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
