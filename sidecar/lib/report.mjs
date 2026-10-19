/**
 * 报告渲染器：把会话视图渲染为 report.json + report.md，经 report.emit 交由
 * Host 校验（会话一致性、大小上限）并写入 report_dir。
 *
 * 时序约定：调用方必须在 setState(终态) 之前 await emitReport——
 * report.emit 是「请求-应答」调用，Host 响应返回即代表文件已落盘，
 * 因此 gate 观察到终态时报告必然已经存在（不受通知并行处理影响）。
 *
 * 渲染失败不影响工作流裁决：内部捕获并降级为 warn 事件。
 */
import { PROTOCOL_VERSION, RPC_TO_HOST, SEVERITY, STATE_LABELS } from "../../shared/protocol.mjs";

const MD_EVIDENCE_CAP = 20;

const GRADE_LABELS = { strong: "决策轨迹", "cross-proven": "内容归属", "http-only": "仅HTTP" };

function fmtTime(ms) {
  try {
    return new Date(ms).toISOString();
  } catch {
    return String(ms);
  }
}

function esc(v) {
  return String(v ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
}

function headline(outcome, patchStatus, supabase) {
  const supaCritical = supabase && ((supabase.leaks ?? 0) > 0 || supabase.serviceRoleLeak);
  switch (outcome) {
    case "vulnerable":
      return patchStatus === "verify_failed"
        ? "发现可利用的对象级越权（IDOR）漏洞；修复补丁未通过双重验收，需人工审查证据"
        : "发现可利用的对象级越权（IDOR）漏洞，已生成双重验收通过的修复补丁（gate 未写回工作区）";
    case "no_candidates":
      return "静态分析未发现可探测的安全候选端点（对象级越权 / 注入 / 路径穿越线索）。若项目是未识别框架，可在 guardbuild.json 提供 openapi.file 或 routes 字段声明路由后重试";
    case "vulnerable_unfixed":
      if (supaCritical) {
        return supabase.leaks > 0
          ? `发现 Supabase 数据暴露（${supabase.leaks} 个表匿名可读，RLS 缺失${supabase.serviceRoleLeak ? "；并检出 service_role 密钥客户端暴露" : ""}）——属数据库策略/密钥问题，不在代码层自动修复`
          : "发现 Supabase service_role 密钥客户端暴露（可绕过 RLS 读写全库）——需轮换密钥，不在代码层自动修复";
      }
      return "发现可复现的漏洞证据；但候选中没有可自动修复的对象级越权端点，未生成修复补丁";
    case "not_reproducible":
      if (supabase && !supaCritical) {
        return "存在 Supabase 线索，但匿名探测未读出数据（RLS 已生效）且未见 service_role 暴露（可能已有防护）";
      }
      return "存在静态候选，但攻击在运行期不可复现（可能已有运行期防护）";
    case "failed":
      return "诊断执行失败，未能完成漏洞验证闭环";
    case "aborted":
      return "会话被中止，报告不完整";
    default:
      return outcome;
  }
}

function suggestions(r) {
  const { outcome, patchStatus } = r.verdict;
  const supabase = r.supabase ?? null;
  const lines = [];
  if (outcome === "vulnerable" && patchStatus === "verified") {
    lines.push(`- 隔离 worktree 中已存在通过双重验收的修复补丁（\`${r.patch?.hash?.slice(0, 12)}…\`），gate 未写回原工作区。`);
    lines.push(`- 补丁位置：\`${r.patch?.worktree}\`；可将修改应用到工作区后提交。`);
    lines.push("- 修复落地后重跑 GuardBuild gate，应得到 exit 0（no_candidates / not_reproducible）。");
  } else if (outcome === "vulnerable") {
    lines.push("- 补丁未通过双重验收（存在未阻断攻击或业务回归），请对照 post 证据中的 regressed/inconclusive 用例人工审查。");
    lines.push(`- 补丁保留在隔离 worktree：\`${r.patch?.worktree}\`。`);
  } else if (outcome === "no_candidates") {
    lines.push("- 当前策略覆盖对象级越权（IDOR）/ 无鉴权读取 / 路径穿越 / SQL 与命令注入 / Supabase 数据暴露等场景类；如需其它漏洞类别，请扩展策略包与契约。");
  } else if (outcome === "vulnerable_unfixed") {
    if (supabase && ((supabase.leaks ?? 0) > 0 || supabase.serviceRoleLeak)) {
      if ((supabase.leaks ?? 0) > 0) {
        lines.push(
          `- 匿名（仅携公开 anon key）可读出 Supabase 表数据，证明 RLS（行级安全）缺失或策略过宽：${(supabase.tables ?? []).join("、")}。`
        );
        lines.push(
          "- 在数据库侧启用并配置 RLS（无法在应用代码中修复）：`ALTER TABLE <表名> ENABLE ROW LEVEL SECURITY;` 后为 SELECT/INSERT/UPDATE/DELETE `CREATE POLICY ... USING (auth.uid() = user_id)`。"
        );
      }
      if (supabase.serviceRoleLeak) {
        lines.push(
          `- 检出 service_role 密钥出现在客户端可见位置（${supabase.serviceRoleLeak.source}）：它能绕过 RLS 读写全库，请立即在 Supabase 控制台吊销并轮换，切勿置于 NEXT_PUBLIC_/VITE_/REACT_APP_ 等前端环境变量或前端源码中。`
        );
      }
      lines.push("- 加固后重跑 GuardBuild gate，应转为 exit 0（not_reproducible / no_candidates）。");
    } else {
      lines.push("- 漏洞证据已建立（修复前攻击成功），但静态候选中没有可自动修复的对象级越权端点（自动修复仅覆盖带认证的 IDOR 场景）。");
      lines.push("- 请对照 report.json 中各攻击用例（如纵向越权、无鉴权读取、路径穿越、SQL/命令注入）定位端点并人工加固，再重跑 GuardBuild gate 验证。");
    }
  } else if (outcome === "not_reproducible") {
    if (supabase) {
      lines.push("- Supabase 匿名探测未读出数据（RLS 生效或表为空），未见 service_role 暴露；如仍有顾虑，请在数据库侧核对 RLS 策略与密钥管理。");
    } else {
      lines.push("- 攻击在修复前即不可复现，未建立漏洞基线；请核对 guardbuild.json 的身份契约与目标的资源发现接口。");
    }
  } else if (outcome === "failed") {
    lines.push(`- 执行失败（${r.error?.code}）：${r.error?.message ?? ""}${r.error?.hint ? `；建议：${r.error.hint}` : ""}`);
  } else {
    lines.push("- 会话被中止，未完成裁决；可重新运行。");
  }
  return lines.join("\n");
}

function evidenceTable(rows) {
  if (!rows.length) return "_无_\n";
  const shown = rows.slice(0, MD_EVIDENCE_CAP);
  const head =
    "| 用例 | 类别 | 身份 | 判定 | 级别 | 实际 | 服务端决策 |\n| --- | --- | --- | --- | --- | --- | --- |";
  const body = shown
    .map((e) => {
      const decision = e.decision
        ? `${e.decision.routeKey ?? "?"}: ${e.decision.decision}${Array.isArray(e.decision.checks) ? ` [${e.decision.checks.join(",")}]` : ""}`
        : "—";
      const grade = e.evidenceGrade ? GRADE_LABELS[e.evidenceGrade] ?? e.evidenceGrade : "—";
      const actual = e.crossProof ? `${e.actual}（交叉证明：${e.crossProof}）` : e.actual;
      return `| ${esc(e.name)} | ${esc(e.category)} | ${esc(e.identity)} | ${esc(e.verdict)} | ${esc(grade)} | ${esc(actual)} | ${esc(decision)} |`;
    })
    .join("\n");
  const rest = rows.length > shown.length ? `\n\n_其余 ${rows.length - shown.length} 条见 report.json。_\n` : "\n";
  return `${head}\n${body}\n${rest}`;
}

function renderLlmSection(llm) {
  const applied = [
    llm.applied?.start ? "启动契约" : null,
    llm.applied?.login ? "登录契约" : null,
    llm.applied?.routes ? `路由 ${llm.applied.routes} 条` : null,
  ].filter(Boolean);
  const cache = llm.cached
    ? `${llm.cacheSource === "disk" ? "磁盘" : "内存"}缓存${llm.cachedAt ? `（${fmtTime(llm.cachedAt)}）` : ""}`
    : "本次调用";
  const lines = [
    "## LLM 接入侦察\n",
    "| 项目 | 值 |",
    "| --- | --- |",
    `| 模型 | ${esc(llm.model ?? "—")} |`,
    `| 应用 | ${esc(applied.join("、") || "无")} |`,
    `| 启动验证 | ${llm.verified?.start ? "已通过实际启动验证" : "未通过/未验证"} |`,
    `| 登录验证 | ${llm.verified?.login ? "已通过实际登录验证" : "未通过/未验证"} |`,
    `| 路由线索 | ${llm.routeCount ?? 0} 条（仅用于定位动态探测目标，不参与自动改码） |`,
    `| 来源 | ${esc(cache)} |`,
    `| Token | ${llm.usage?.total_tokens ?? "—"} |`,
    `| 证据 | ${llm.evidenceFiles?.length ?? 0} 个文件 / ${llm.evidenceChars ?? 0} 字符 |`,
    "",
  ];
  if (llm.rejectedStart) {
    const rejected = llm.rejectedStart;
    lines.push(
      `- 启动回退：LLM 启动契约未通过实际启动验证（\`${esc(rejected.cmd ?? "?")} ${esc((rejected.args ?? []).join(" "))}\`）。`
    );
  }
  if (llm.warnings?.length) {
    lines.push("\n**侦察警告**\n", ...llm.warnings.slice(0, 10).map((w) => `- ${esc(w)}`), "");
  }
  if (llm.notes?.length) {
    lines.push("\n**侦察备注**\n", ...llm.notes.slice(0, 5).map((n) => `- ${esc(n)}`), "");
  }
  return lines.join("\n");
}

function renderMarkdown(r) {
  const acc = r.acceptance;
  const pre = r.evidence.pre ?? [];
  const post = r.evidence.post ?? [];
  const preVuln = pre.filter((e) => e.verdict === "vulnerable").length;
  const parts = [];

  parts.push(`# GuardBuild 安全诊断报告\n`);
  parts.push(`> **结论：${r.verdict.headline}**\n`);
  parts.push(
    [
      "| 项目 | 值 |",
      "| --- | --- |",
      `| 生成时间 | ${fmtTime(r.generatedAt)} |`,
      `| 目标项目 | ${esc(r.session.projectName)}（\`${esc(r.session.projectRoot)}\`） |`,
      `| 会话 | ${esc(r.session.id)} |`,
      `| 终态 | ${esc(r.session.stateLabel)}（${esc(r.session.state)}） |`,
      `| 退出码 | ${r.verdict.exitCode}（0=无漏洞证据 / 1=漏洞证据成立 / 2=执行失败） |`,
      `| 模式 | ${r.tool.gate ? "CI gate（策略授权，禁止写回）" : "交互会话"} |`,
      `| 协议 | ${r.tool.protocolVersion} |`,
      "",
    ].join("\n")
  );

  parts.push(`## 摘要\n`);
  const summaryLines = [`- 静态发现：${r.summary.findingCount} 个安全候选端点`];
  summaryLines.push(`- 修复前证据（pre）：${pre.length} 条，其中 vulnerable ${preVuln} 条`);
  const preGrades = r.summary.phases?.pre?.grades;
  if (preGrades) {
    summaryLines.push(
      `- 证据级别（pre）：决策轨迹 ${preGrades.strong ?? 0} 条 / 内容归属 ${preGrades["cross-proven"] ?? 0} 条 / 仅 HTTP ${preGrades["http-only"] ?? 0} 条`
    );
  }
  if (acc) {
    summaryLines.push(
      `- 双重验收：攻击阻断 ${acc.attackBlocked}/${acc.attackTotal}，业务保持 ${acc.businessPassed}/${acc.businessTotal} → ${acc.pass ? "通过" : "未通过"}`
    );
  }
  if (r.patch) summaryLines.push(`- 补丁：\`${r.patch.hash?.slice(0, 12)}…\`（${r.patch.files?.length ?? 0} 个文件，${esc(r.patch.status)}）`);
  const sb = r.summary.supabase;
  if (sb?.detected) {
    const bits = [`URL \`${esc(sb.url ?? "—")}\``, `表引用 ${sb.tables?.length ?? 0} 个`];
    if (sb.serviceRoleLeak) bits.push(`service_role 暴露（${esc(sb.serviceRoleLeak.source)}）`);
    if (sb.leaks) bits.push(`匿名可读 ${sb.leaks} 个表`);
    summaryLines.push(`- Supabase：${bits.join("，")}`);
  }
  if (r.summary.start) summaryLines.push(`- 启动契约：\`${esc(r.summary.start.cmd)} ${esc((r.summary.start.args ?? []).join(" "))}\`（就绪模式 ${esc(r.summary.start.readyPattern)}）`);
  if (r.llm?.used) {
    const applied = [
      r.llm.applied?.start ? "启动" : null,
      r.llm.applied?.login ? "登录" : null,
      r.llm.applied?.routes ? `路由 ${r.llm.applied.routes} 条` : null,
    ].filter(Boolean);
    summaryLines.push(
      `- LLM 接入侦察：${esc(r.llm.model ?? "未知模型")}，应用 ${esc(applied.join("、") || "无")}；启动 ${r.llm.verified?.start ? "已验证" : "未验证"}，登录 ${r.llm.verified?.login ? "已验证" : "未验证"}${r.llm.cached ? `（${r.llm.cacheSource === "disk" ? "磁盘" : "内存"}缓存）` : ""}`
    );
  }
  if (r.error) summaryLines.push(`- 错误：\`${esc(r.error.code)}\` — ${esc(r.error.message)}`);
  parts.push(summaryLines.join("\n") + "\n");

  if (r.llm?.used) parts.push(renderLlmSection(r.llm));

  if (r.summary.findings.length) {
    parts.push(`## 静态发现（${r.summary.findings.length}）\n`);
    parts.push(
      [
        "| 端点 | 位置 | 原因 |",
        "| --- | --- | --- |",
        ...r.summary.findings.map(
          (f) => `| ${esc(f.method)} ${esc(f.path)} | ${esc(f.file)}:${esc(f.startLine)} | ${esc(f.reason)} |`
        ),
        "",
      ].join("\n")
    );
  }

  parts.push(`## 修复前证据（pre，${pre.length} 条）\n`);
  parts.push(evidenceTable(pre));

  if (r.patch) {
    parts.push(`## 修复补丁\n`);
    const fileDesc = (r.patch.files ?? [])
      .map((f) => (typeof f === "string" ? `\`${f}\`` : `\`${f.path}\`（+${f.insertions}/-${f.deletions}）`))
      .join("、");
    parts.push(
      [
        `- 哈希：\`${r.patch.hash}\``,
        `- 文件：${fileDesc || "—"}`,
        `- 隔离位置：\`${esc(r.patch.worktree)}\``,
        `- 状态：${esc(r.patch.status)}（${r.patch.lineCount ?? 0} 行改动）`,
        "",
        "<details><summary>Diff</summary>",
        "",
        "```diff",
        r.patch.diff ?? "",
        "```",
        "",
        "</details>",
        "",
      ].join("\n")
    );
  }

  if (acc) {
    parts.push(`## 双重验收（post）\n`);
    parts.push(
      `攻击阻断 ${acc.attackBlocked}/${acc.attackTotal}，业务保持 ${acc.businessPassed}/${acc.businessTotal} → **${acc.pass ? "通过" : "未通过"}**\n`
    );
    parts.push(evidenceTable(post));
  } else if (post.length) {
    parts.push(`## 修复后证据（post，${post.length} 条）\n`);
    parts.push(evidenceTable(post));
  }

  parts.push(`## 结论与建议\n\n${suggestions(r)}\n`);
  return parts.join("\n");
}

/** 构造 report.json 结构（不落盘） */
export function buildReport(ctx, { outcome, exitCode, patchStatus = null, error = null, state = null }) {
  const view = ctx.view;
  const evidence = Array.isArray(view.evidence) ? view.evidence : [];
  const byPhase = (p) => evidence.filter((e) => e.phase === p);
  const finalState = state ?? view.state;
  const start = ctx.targetConfig?.start ?? null;
  const supabase = view.supabase ?? null;
  const r = {
    schema: "guardbuild.report/1",
    generatedAt: Date.now(),
    tool: { name: "GuardBuild", protocolVersion: PROTOCOL_VERSION, gate: !!ctx.gate },
    session: {
      id: ctx.sessionId,
      projectRoot: view.projectRoot,
      projectName: view.projectName,
      startedAt: view.startedAt,
      finishedAt: Date.now(),
      state: finalState,
      stateLabel: STATE_LABELS[finalState] ?? finalState,
    },
    verdict: {
      outcome,
      exitCode,
      patchStatus,
      headline: headline(outcome, patchStatus, supabase),
    },
    summary: {
      findingCount: (view.findings ?? []).length,
      findings: view.findings ?? [],
      evidence: { pre: byPhase("pre").length, post: byPhase("post").length, postWriteback: byPhase("post_writeback").length },
      phases: view.phases ?? {},
      acceptance: view.acceptance ?? null,
      supabase,
      start: start
        ? { cmd: start.cmd, args: start.args, cwd: start.cwd ?? null, readyPattern: start.readyPattern }
        : null,
      startSource: ctx.targetConfig?.startSource ?? null,
    },
    llm: view.llm
      ? {
          used: !!view.llm.used,
          model: view.llm.model ?? null,
          source: view.llm.source ?? null,
          cached: !!view.llm.cached,
          cacheSource: view.llm.cacheSource ?? null,
          cachedAt: view.llm.cachedAt ?? null,
          durationMs: view.llm.durationMs ?? null,
          routeCount: view.llm.routes ?? 0,
          applied: view.llm.applied ?? { start: false, login: false, routes: 0 },
          verified: view.llm.verified ?? { start: false, login: false },
          rejectedStart: view.llm.rejectedStart ?? null,
          evidenceFiles: view.llm.evidenceFiles ?? [],
          evidenceChars: view.llm.evidenceChars ?? 0,
          usage: view.llm.usage ?? null,
          notes: view.llm.notes ?? [],
          warnings: view.llm.warnings ?? [],
        }
      : null,
    supabase,
    evidence: { pre: byPhase("pre"), post: byPhase("post"), postWriteback: byPhase("post_writeback") },
    patch: view.patch
      ? {
          hash: view.patch.hash,
          files: view.patch.files,
          worktree: view.patch.worktree,
          status: view.patch.status,
          lineCount: view.patch.lineCount,
          diff: view.patch.diff,
        }
      : null,
    acceptance: view.acceptance ?? null,
    targets: view.targets ?? {},
    error,
  };
  return { json: r, markdown: renderMarkdown(r) };
}

/**
 * 渲染并落盘报告。必须在 setState(终态) 之前 await。
 * @param {object} ctx 会话上下文
 * @param {{outcome:string, exitCode:number, patchStatus?:string|null, error?:object|null, state?:string|null}} outcome
 */
export async function emitReport(ctx, outcome) {
  try {
    const { json, markdown } = buildReport(ctx, outcome);
    const res = await ctx.rpc.request(
      RPC_TO_HOST.REPORT_EMIT,
      { sessionId: ctx.sessionId, json, markdown },
      { timeoutMs: 15_000 }
    );
    if (res?.written) {
      ctx.emit({
        kind: "report",
        severity: SEVERITY.SUCCESS,
        message: `诊断报告已写入：${res.mdPath}`,
        data: { jsonPath: res.jsonPath, mdPath: res.mdPath, outcome: outcome.outcome, exitCode: outcome.exitCode },
      });
    } else if (res?.reason) {
      ctx.emit({
        kind: "report",
        severity: SEVERITY.INFO,
        message: `未配置报告目录，跳过报告落盘（${res.reason}）`,
        data: { outcome: outcome.outcome, exitCode: outcome.exitCode },
      });
    }
  } catch (e) {
    ctx.emit({
      kind: "report",
      severity: SEVERITY.WARN,
      message: `报告落盘失败（不影响裁决）：${e.message}`,
      data: { outcome: outcome.outcome },
    });
  }
}
