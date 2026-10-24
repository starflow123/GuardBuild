/**
 * 有界启动代理（S3-full）：目标起不来时，让模型在「引擎生成的动作菜单」里逐步选动作，
 * 把「先装依赖 / 先构建 / 换个启动入口」这类接入障碍处理掉。
 *
 * 硬约束（与 docs/agentic-full-plan.md §0 一致）：
 *  - 模型只报编号，命令行由引擎按菜单拼装；模型自带的 cmd/args/shell 一律丢弃并留痕；
 *  - 每一步都真实执行、真实记录；代理的自评不进结论——「起好了」只由 tryStart 实际拉起 + 就绪判定说了算；
 *  - 预算耗尽/动作被拒都不伪造成功，返回 not_started 让调用方回退到确定性契约；
 *  - gate/CI 不启用（bootstrapEnabled 里结构性禁用），默认关闭需显式开启；
 *  - 只读动作走 project.read 令牌，路径守卫排除 .env / node_modules / .git / 密钥文件。
 */
import path from "node:path";

import { RPC_TO_HOST, SEVERITY } from "../../shared/protocol.mjs";
import { chat, LlmError, parseJson } from "./llm.mjs";
import { buildActionMenu, renderMenuForPrompt, validateActionChoice } from "./execmenu.mjs";
import { normalizeStart } from "./targetconfig.mjs";

export const BOOTSTRAP_DEFAULTS = {
  maxSteps: 6,
  stepTimeoutMs: 120_000,
  totalBudgetMs: 8 * 60_000,
  maxOutputChars: 60_000,
};

const MANIFEST_FILES = [
  "package.json",
  "package-lock.json",
  "npm-shrinkwrap.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "requirements.txt",
  "pyproject.toml",
  "uv.lock",
  "Procfile",
];
const MAX_MANIFEST_CHARS = 8_000;
const LOG_TAIL_CHARS = 1_200;
const MAX_OBSERVE_CHARS = 20_000;

/** 交互模式下的有界启动代理开关：gate 结构性禁用 */
export function bootstrapEnabled(ctx) {
  if (ctx?.gate === true) return false;
  const cfg = ctx?.targetConfig?.bootstrap ?? null;
  if (cfg?.enabled === true) return true;
  if (cfg?.enabled === false) return false;
  return process.env.GUARDBUILD_LLM_BOOTSTRAP === "1";
}

function budgetOf(ctx, over = {}) {
  const cfg = ctx?.targetConfig?.bootstrap ?? {};
  const clamp = (v, lo, hi, dft) => (Number.isFinite(v) ? Math.min(hi, Math.max(lo, Math.floor(v))) : dft);
  return {
    maxSteps: clamp(over.maxSteps ?? cfg.maxSteps, 1, 10, BOOTSTRAP_DEFAULTS.maxSteps),
    stepTimeoutMs: clamp(over.stepTimeoutMs ?? cfg.stepTimeoutMs, 5_000, 600_000, BOOTSTRAP_DEFAULTS.stepTimeoutMs),
    totalBudgetMs: clamp(over.totalBudgetMs ?? cfg.totalBudgetMs, 30_000, 1_800_000, BOOTSTRAP_DEFAULTS.totalBudgetMs),
    maxOutputChars: clamp(over.maxOutputChars ?? cfg.maxOutputChars, 5_000, 200_000, BOOTSTRAP_DEFAULTS.maxOutputChars),
  };
}

const SYSTEM_PROMPT = `你在帮一个安全测试引擎把一个本地项目真正跑起来，让它能在沙箱内监听端口。
硬性规则：
1. 你只能从给定菜单里挑选动作并报编号（exec 报 id，start 报 candidate），不要自己写命令行、不要给参数。
2. 你可以 read/list 项目根内的相对路径来弄清缺什么，但不能读 .env、node_modules、.git、密钥文件。
3. 安装/构建要按依赖清单来：有锁文件就 npm ci，没锁文件用 npm install；Python 用 requirements.txt 或 uv.lock。
4. 不要试图修改源码，不要下载额外工具，不要访问外部服务；这只解决「起不来」，不解决漏洞本身。
5. 认为没法继续（缺凭据、缺外部服务、需要改代码）就报 giveup 并说明原因，不要瞎试。
只返回一个 JSON 对象：{"action":"exec","id":1} | {"action":"start","candidate":2} |
{"action":"read","path":"src/x.js"} | {"action":"list","path":"src"} | {"action":"giveup","note":"原因"}。
不要输出 JSON 以外的内容。`;

function tail(text, n = LOG_TAIL_CHARS) {
  const s = String(text ?? "");
  return s.length > n ? s.slice(-n) : s;
}

/** 提示词超限保前缀（目标与菜单在开头，比历史更重要），并显式标注被截断 */
function clamp(text, n) {
  const s = String(text ?? "");
  return s.length > n ? `${s.slice(0, n)}\n/* …(观察内容超限，已截去 ${s.length - n} 字符)… */` : s;
}

function linesText(lines) {
  return (lines ?? []).map((l) => (typeof l === "string" ? l : l?.line ?? "")).filter(Boolean).join("\n");
}

/**
 * @param {object} ctx 会话上下文（需要 rpc/tokens/projectRoot/emit/db）
 * @param {object} opts
 * @param {string} opts.reason 为什么进入代理（诊断码 + 摘要）
 * @param {Array<object>} opts.starts 引擎已有的启动候选（cmd/args/cwd）
 * @param {(entry:object) => Promise<{ok:boolean, target?:object, start?:object, error?:string, hint?:string}>} opts.tryStart
 *        由调用方提供：真实拉起该候选并判定就绪，代理不得自评成功
 * @param {(url:string, reason:string) => Promise<string>} opts.getToken 出站令牌
 * @param {string} [opts.model]
 * @param {typeof chat} [opts.chatImpl] LLM 调用注入点（单测用，默认走 DeepSeek over Host）
 * @param {(ctx:object) => Promise<Array<{rel:string, content:string}>>} [opts.readManifestsImpl] 清单读取注入点
 */
export async function runBootstrapAgent(
  ctx,
  { reason, starts = [], tryStart, getToken, model = null, onStep = null, chatImpl = chat, readManifestsImpl = readManifests } = {}
) {
  const budget = budgetOf(ctx);
  const summary = {
    enabled: true,
    reason: String(reason ?? "").slice(0, 300),
    model: model ?? null,
    maxSteps: budget.maxSteps,
    stepsUsed: 0,
    rejected: 0,
    actions: [],
    outcome: "not_started",
    remainingMs: budget.totalBudgetMs,
    usedOutputChars: 0,
    startedAt: Date.now(),
  };
  const emitStep = (data, message, severity = SEVERITY.INFO) => {
    summary.actions.push({ step: summary.stepsUsed, ...data });
    try {
      ctx.db?.insertAgentAction?.({
        id: `act_${Date.now().toString(36)}_${summary.actions.length}`,
        sessionId: ctx.sessionId,
        step: summary.stepsUsed,
        action: data.action,
        subject: data.subject ?? null,
        ok: data.ok === true,
        exitCode: data.exitCode ?? null,
        durationMs: data.durationMs ?? null,
        budgetRemainingMs: Math.max(0, budget.totalBudgetMs - (Date.now() - summary.startedAt)),
        note: data.note ?? null,
        createdAt: Date.now(),
      });
    } catch {
      /* 审计失败不改变裁决：证据表只服务于事后回看 */
    }
    ctx.emit?.({ kind: "bootstrap", severity, message, phase: ctx.state ?? null, data });
    if (typeof onStep === "function") onStep(data);
  };

  const menu = buildActionMenu({ manifests: await readManifestsImpl(ctx), starts });
  const history = [];
  let lastFailure = { text: summary.reason, diagnosis: null };

  // 去重不是「一票否决」：安装/构建成功后，目标状态可能已经变了。
  // 同一动作最多实跑 2 次，且重试必须发生在「最近一次成功 exec」之后，否则仍然短路。
  const MAX_ATTEMPTS_PER_KEY = 2;
  const attempts = new Map(); // dedupeKey -> { count, lastStep }
  let lastExecOkStep = 0;
  const repeatGate = (key) => {
    const prior = attempts.get(key);
    if (!prior) return { run: true };
    if (prior.count >= MAX_ATTEMPTS_PER_KEY) return { run: false, why: "cap" };
    if (lastExecOkStep > prior.lastStep) return { run: true };
    return { run: false, why: "no_state_change" };
  };
  const markAttempt = (key) => {
    const prior = attempts.get(key);
    attempts.set(key, { count: (prior?.count ?? 0) + 1, lastStep: summary.stepsUsed });
  };
  const repeatNote = (why) =>
    why === "cap"
      ? `已达到重试上限（${MAX_ATTEMPTS_PER_KEY} 次），不再重复`
      : "已经执行过，且之后没有成功的安装/构建改变状态，重复执行不解决问题";

  const elapsed = () => Date.now() - summary.startedAt;
  const outOfBudget = () => {
    if (summary.stepsUsed >= budget.maxSteps) return `步数上限（${budget.maxSteps}）已用尽`;
    if (elapsed() >= budget.totalBudgetMs) return `总时长预算（${Math.round(budget.totalBudgetMs / 1000)}s）已用尽`;
    if (summary.usedOutputChars >= budget.maxOutputChars) return `累计输出预算（${budget.maxOutputChars} 字符）已用尽`;
    return null;
  };

  while (true) {
    const stop = outOfBudget();
    if (stop) {
      summary.outcome = "budget_exhausted";
      summary.budgetStop = stop;
      emitStep({ action: "budget", subject: stop, ok: false }, `启动代理止步：${stop}`, SEVERITY.WARN);
      break;
    }
    summary.stepsUsed += 1;

    const observation = {
      goal: "让项目在沙箱内监听端口并可通过 HTTP 访问；只做能解决「起不来」的最小动作",
      project_root: ctx.projectRoot,
      menu: renderMenuForPrompt(menu),
      last_failure: lastFailure,
      history: history.slice(-6),
      budget: {
        steps_used: summary.stepsUsed,
        steps_left: budget.maxSteps - summary.stepsUsed,
        seconds_left: Math.max(0, Math.round((budget.totalBudgetMs - elapsed()) / 1000)),
      },
    };
    let choice;
    try {
      const res = await chatImpl(ctx, {
        systemPrompt: SYSTEM_PROMPT,
        userPrompt: clamp(JSON.stringify(observation, null, 1), MAX_OBSERVE_CHARS),
        getToken,
        model,
        maxTokens: 400,
        purpose: "启动代理选动作",
      });
      summary.model = res.model ?? summary.model;
      choice = parseJson(res.content);
    } catch (e) {
      summary.outcome = e instanceof LlmError ? "llm_unavailable" : "agent_error";
      summary.error = String(e?.message ?? e).slice(0, 300);
      emitStep({ action: "ask", subject: summary.error, ok: false }, `启动代理未获得可用选择：${summary.error}`, SEVERITY.WARN);
      break;
    }

    const checked = validateActionChoice(choice, menu);
    if (!checked.ok) {
      summary.rejected += 1;
      lastFailure = { text: `上一步选择被拒：${checked.reason}`, diagnosis: "choice_rejected" };
      // 只回喂动作名，不把模型原文塞进观察历史（观察历史会进下一轮提示词与事件库）
      history.push({ step: summary.stepsUsed, action: String(choice?.action ?? "unknown"), rejected: checked.reason });
      emitStep(
        { action: "rejected", subject: `action=${String(choice?.action ?? "unknown")}`, ok: false, note: checked.reason },
        `启动代理的选择被拒（第 ${summary.stepsUsed} 步）：${checked.reason}`,
        SEVERITY.WARN
      );
      continue;
    }
    if (checked.ignored.length) {
      emitStep(
        { action: "sanitize", subject: checked.ignored.join(","), ok: true, note: "模型自带的命令字段已丢弃，只按菜单编号执行" },
        `启动代理想自己拼命令（${checked.ignored.join("、")}），已丢弃这些字段并按菜单编号执行`,
        SEVERITY.WARN
      );
    }

    const step = checked.step;
    if (step.action === "giveup") {
      summary.outcome = "gave_up";
      summary.note = step.note;
      emitStep({ action: "giveup", subject: step.note, ok: false }, `启动代理放弃接管：${step.note || "未说明原因"}`, SEVERITY.WARN);
      break;
    }

    if (step.action === "read" || step.action === "list") {
      const res = await observeFile(ctx, step);
      summary.usedOutputChars += res.chars;
      lastFailure = { text: `已回喂${step.action === "read" ? "文件" : "目录"}内容：${step.path}`, diagnosis: null };
      history.push({ step: summary.stepsUsed, [step.action]: step.path, result: res.text });
      emitStep(
        { action: step.action, subject: step.path, ok: res.ok, note: res.error ?? `${res.chars} 字符` },
        `启动代理只读查看 ${step.action === "read" ? "文件" : "目录"} ${step.path}${res.ok ? "" : `（${res.error}）`}`
      );
      continue;
    }

    if (step.action === "exec") {
      const key = `exec:${step.entry.id}`;
      const gate = repeatGate(key);
      if (!gate.run) {
        lastFailure = { text: `${step.entry.shape} ${repeatNote(gate.why)}`, diagnosis: "repeat_short_circuit" };
        emitStep({ action: "exec", subject: step.entry.shape, ok: false, dedupeKey: key, note: "重复动作短路" }, `启动代理重复选择「${step.entry.shape}」，已短路：${repeatNote(gate.why)}`, SEVERITY.WARN);
        continue;
      }
      markAttempt(key);
      const run = await execAction(ctx, step.entry, budget);
      if (run.exited && run.exitCode === 0) lastExecOkStep = summary.stepsUsed;
      summary.usedOutputChars += run.chars;
      history.push({ step: summary.stepsUsed, exec: step.entry.shape, exitCode: run.exitCode, output: run.tail, dedupeKey: key });
      lastFailure =
        run.exitCode === 0
          ? { text: `上一步 ${step.entry.shape} 执行成功（退出码 0），现在可以试启动`, diagnosis: null }
          : { text: `上一步 ${step.entry.shape} 失败（${run.error ?? `退出码 ${run.exitCode}`}）`, diagnosis: run.diagnosis ?? "exec_failed", tail: run.tail };
      emitStep(
        {
          action: "exec",
          subject: step.entry.shape,
          ok: run.exitCode === 0 && run.exited,
          exitCode: run.exitCode,
          durationMs: run.durationMs,
          note: run.error ?? tail(run.tail, 200),
        },
        `启动代理执行「${step.entry.shape}」：${run.exitCode === 0 && run.exited ? "完成" : `未成功（${run.error ?? `退出码 ${run.exitCode}`}）`}`,
        run.exitCode === 0 && run.exited ? SEVERITY.SUCCESS : SEVERITY.WARN
      );
      continue;
    }

    // start：真实拉起由调用方判定，代理不参与结论
    const key = `start:${step.entry.id}`;
    const gate = repeatGate(key);
    if (!gate.run) {
      lastFailure = {
        text:
          gate.why === "cap"
            ? `启动候选 ${step.entry.shape} ${repeatNote(gate.why)}`
            : `启动候选 ${step.entry.shape} 已试过且未就绪；之后没有成功的安装/构建改变状态，重复试启动没有意义`,
        diagnosis: "repeat_short_circuit",
      };
      emitStep({ action: "start", subject: step.entry.shape, ok: false, dedupeKey: key, note: "重复动作短路" }, `启动代理重复选择启动候选「${step.entry.shape}」，已短路：${repeatNote(gate.why)}`, SEVERITY.WARN);
      continue;
    }
    markAttempt(key);
    const t0 = Date.now();
    let res = null;
    let err = null;
    try {
      res = await tryStart(step.entry);
    } catch (e) {
      err = e;
    }
    const ok = !!res?.ok && !!res?.target;
    history.push({
      step: summary.stepsUsed,
      start: step.entry.shape,
      ok,
      error: err?.message ?? res?.error ?? null,
      dedupeKey: key,
    });
    summary.usedOutputChars += String(err?.message ?? res?.error ?? "").length;
    emitStep(
      {
        action: "start",
        subject: step.entry.shape,
        ok,
        durationMs: Date.now() - t0,
        note: err?.hint ?? err?.message ?? res?.error ?? null,
      },
      ok
        ? `启动代理选的候选 ${step.entry.shape} 已实际拉起并就绪（${res.target.url ?? "无 URL"}）`
        : `启动代理选的候选 ${step.entry.shape} 未通过实际启动验证：${err?.message ?? res?.error ?? "未知原因"}`,
      ok ? SEVERITY.SUCCESS : SEVERITY.WARN
    );
    if (ok) {
      summary.outcome = "started";
      summary.start = res.start ?? normalizeStart(step.entry);
      summary.url = res.target.url ?? null;
      break;
    }
    lastFailure = {
      text: `候选 ${step.entry.shape} 启动失败：${err?.message ?? res?.error ?? "未知原因"}`,
      diagnosis: err?.code ?? res?.code ?? "target_not_ready",
      hint: err?.hint ?? null,
      tail: tail(linesText(err?.output ?? res?.output)),
    };
  }

  summary.durationMs = Date.now() - summary.startedAt;
  summary.remainingMs = Math.max(0, budget.totalBudgetMs - elapsed());
  summary.budget = budget;
  summary.menuSize = menu.actions.length;
  summary.startCandidateSize = menu.starts.length;
  return summary;
}

async function readManifests(ctx) {
  const out = [];
  const base = String(ctx.projectRoot ?? "").replace(/[\\/]+$/, "");
  for (const rel of MANIFEST_FILES) {
    let text = null;
    try {
      const res = await ctx.rpc.request(
        RPC_TO_HOST.FS_READ,
        { token: ctx.tokens.project, path: `${base}/${rel}`, redact: true },
        { timeoutMs: 15_000 }
      );
      text = typeof res?.content === "string" ? res.content.slice(0, MAX_MANIFEST_CHARS) : null;
    } catch {
      // 清单文件不存在/读不到：仍然记为「存在未知内容」以外的事实——只在能读到内容时收录
      continue;
    }
    if (text == null) continue;
    out.push({ rel, content: text });
  }
  return out;
}

async function observeFile(ctx, step) {
  const base = String(ctx.projectRoot ?? "").replace(/[\\/]+$/, "");
  try {
    if (step.action === "read") {
      const res = await ctx.rpc.request(
        RPC_TO_HOST.FS_READ,
        { token: ctx.tokens.project, path: `${base}/${step.path}`, redact: true },
        { timeoutMs: 15_000 }
      );
      const text = tail(String(res?.content ?? ""), MAX_MANIFEST_CHARS);
      return { ok: true, text, chars: text.length };
    }
    const res = await ctx.rpc.request(
      RPC_TO_HOST.FS_LIST,
      { token: ctx.tokens.project, path: `${base}/${step.path}`, depth: 2 },
      { timeoutMs: 20_000 }
    );
    const entries = (res?.entries ?? [])
      .map((e) => `${String(e?.path ?? "").replace(base, "").replace(/^[/\\]+/, "")}${e?.kind === "dir" ? "/" : ""}`)
      .filter((x) => x && !x.includes(".."))
      .slice(0, 120);
    const text = entries.join("\n");
    return { ok: true, text, chars: text.length };
  } catch (e) {
    return { ok: false, text: "", chars: 0, error: String(e?.message ?? e).slice(0, 160) };
  }
}

/** 执行菜单里的一条动作：与确定性 prepare 步骤同一套 RPC 与令牌 */
async function execAction(ctx, entry, budget) {
  const cwd = path.isAbsolute(entry.cwd ?? "")
    ? entry.cwd
    : path.resolve(ctx.projectRoot, entry.cwd ?? ".");
  const cmdline = [entry.cmd, ...entry.args].join(" ");
  let pid = null;
  const t0 = Date.now();
  try {
    const spawned = await ctx.rpc.request(
      RPC_TO_HOST.PROC_SPAWN,
      { token: ctx.tokens.spawn, cmd: entry.cmd, args: entry.args, cwd, role: "bootstrap" },
      { timeoutMs: 30_000 }
    );
    pid = spawned?.pid ?? null;
    const wait = await ctx.rpc.request(
      RPC_TO_HOST.PROC_WAIT_EXIT,
      { token: ctx.tokens.spawn, pid, timeoutMs: budget.stepTimeoutMs },
      { timeoutMs: budget.stepTimeoutMs + 15_000 }
    );
    let lines = [];
    try {
      const logs = await ctx.rpc.request(RPC_TO_HOST.PROC_LOGS, { token: ctx.tokens.spawn, pid, tail: 40 });
      lines = (logs?.lines ?? []).map((l) => l?.line ?? "");
    } catch {
      /* 日志读不到不影响执行结论 */
    }
    if (!wait?.exited) {
      try {
        await ctx.rpc.request(RPC_TO_HOST.PROC_KILL, { token: ctx.tokens.spawn, pid });
      } catch {
        /* ignore */
      }
      return {
        exited: false,
        exitCode: null,
        tail: tail(linesText(lines)),
        chars: linesText(lines).length,
        durationMs: Date.now() - t0,
        error: `超时（${budget.stepTimeoutMs}ms）已终止：${cmdline}`,
        diagnosis: "exec_timeout",
      };
    }
    const text = linesText(lines);
    return {
      exited: true,
      exitCode: wait.exitCode ?? null,
      tail: tail(text),
      chars: text.length,
      durationMs: Date.now() - t0,
      error: null,
    };
  } catch (e) {
    if (pid) {
      try {
        await ctx.rpc.request(RPC_TO_HOST.PROC_KILL, { token: ctx.tokens.spawn, pid });
      } catch {
        /* ignore */
      }
    }
    return {
      exited: false,
      exitCode: null,
      tail: "",
      chars: 0,
      durationMs: Date.now() - t0,
      error: String(e?.message ?? e).slice(0, 200),
      diagnosis: e?.code ?? "exec_failed",
    };
  }
}
