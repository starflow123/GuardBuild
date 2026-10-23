/**
 * 报告渲染器：把会话视图渲染为 report.json + report.md，经 report.emit 交由
 * Host 校验（会话一致性、大小上限）并写入 report_dir。
 */

/** 为每条 vulnerable 证据生成可直接复制的 curl 复现命令 */
function buildPocList(preEvidence, baseUrl) {
  return preEvidence
    .filter((e) => e.verdict === "vulnerable")
    .map((e) => {
      const method = (e.method ?? "GET").toUpperCase();
      const url = `${baseUrl ?? ""}${e.endpoint ?? ""}`;
      const headers = e.identity ? `-H "Authorization: Bearer <${e.identity}_token>"` : "";
      const body = e.body ? `-H "Content-Type: application/json" -d '${typeof e.body === "string" ? e.body : JSON.stringify(e.body)}'` : "";
      return {
        id: e.caseId ?? null,
        name: e.name ?? "",
        severity: "high",
        curl: `curl -X ${method} ${url} ${headers} ${body}`.replace(/\s+/g, " ").trim(),
      };
    });
}

import { PROTOCOL_VERSION, RPC_TO_HOST, SEVERITY, STATE_LABELS } from "../../shared/protocol.mjs";
import { buildFixBriefs } from "./fixbrief.mjs";
import { coverageSummary, describeOutcome } from "./coverage.mjs";

const MD_EVIDENCE_CAP = 20;
const MD_FIX_BRIEF_CAP = 10;

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

/** 报告表格里的定宽字段：动作对象/备注可能很长，截断即可，不做省略号以外的加工 */
function truncate(v, n) {
  const s = String(v ?? "");
  return s.length > n ? `${s.slice(0, n)}…` : s;
}

/** 归因结论的中文措辞（与 attribution.mjs 的 status 一一对应） */
const ATTRIBUTION_LABELS = {
  blocked: "已翻转",
  still_vulnerable: "仍可越权",
  unverified: "归因不成立",
  not_reproduced: "修复前未复现",
};

function headline(outcome, patchStatus, supabase, blackbox = null) {
  if (blackbox) {
    if (outcome === "vulnerable_unfixed") {
      return `黑盒外部扫描发现 ${blackbox.findings?.length ?? 0} 个可利用漏洞（证据来自对运行实例的外部请求）`;
    }
    if (outcome === "no_findings") {
      return `黑盒外部扫描未发现可复现漏洞（${blackbox.routeCount ?? 0} 条路由；仅代表本次已探测攻击面）`;
    }
    if (outcome === "failed") return "黑盒扫描执行失败，未能完成外部验证闭环";
    if (outcome === "aborted") return "黑盒扫描被中止，报告不完整";
  }
  const supaCritical = supabase && ((supabase.leaks ?? 0) > 0 || supabase.serviceRoleLeak);
  switch (outcome) {
    case "vulnerable":
      return patchStatus === "verify_failed"
        ? "发现可利用的对象级越权（IDOR）漏洞；修复补丁未通过双重验收，需人工审查证据"
        : "发现可利用的对象级越权（IDOR）漏洞，已生成双重验收通过的修复补丁（gate 未写回工作区）";
    case "no_candidates":
      return "未命中当前覆盖范围（exit 0，非执行失败）：静态分析未发现可探测的安全候选端点。项目形态不在适配器覆盖内时属正常结果；未识别框架可在 guardbuild.json 用 routes / openapi.file 声明路由，或开启 llm.enabled 做接入侦察";
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

/** 覆盖口径必须来自实际执行过的探测族，不能在报告里凭空罗列「都测过了」 */
function coverageText(coverage) {
  if (!Array.isArray(coverage) || coverage.length === 0) {
    return "未认证读取、跨用户读取（IDOR）、路径穿越、SQL 注入、敏感文件/调试端点暴露";
  }
  return coverage.join("、");
}

function suggestions(r) {
  const { outcome, patchStatus } = r.verdict;
  const supabase = r.supabase ?? null;
  const lines = [];
  if (r.error?.code === "conflict") {
    lines.push(`- 写回预检未通过（Host 在 \`git apply --check\` 阶段拒绝）：${r.error.message ?? ""}`);
    lines.push(`- 原工作区**未被修改**、漏洞仍在；补丁保留在隔离 worktree：\`${r.patch?.worktree ?? "—"}\`。`);
    lines.push("- 两种落地方式：按当前代码重跑一次会话（重新生成 + 重新验收），或自行把上面的 Diff 合并进工作区后用同一用例复测。");
    return lines.join("\n");
  }
  if (r.blackbox) {
    const bb = r.blackbox;
    if (outcome === "vulnerable_unfixed") {
      for (const f of (bb.findings ?? []).slice(0, 8)) {
        lines.push(`- 已复现：${f.type}（${f.method} ${f.path}）—— ${f.detail}`);
      }
      lines.push("- 黑盒模式只取证、不改码：请在源码/配置/数据库策略中修复上述端点，再重跑同一 URL 验证。");
      if (!bb.allowMutation) {
        lines.push("- 写操作类越权（跨用户 PUT/PATCH/DELETE、匿名写入）默认未执行（会修改甚至销毁目标数据）；如需覆盖，设置 blackbox.allowMutation=true 或 GUARDBUILD_BLACKBOX_MUTATE=1 后重跑（DELETE 还需 blackbox.allowDestructive=true 或 GUARDBUILD_BLACKBOX_DELETE=1）。");
      } else if (!bb.allowDestructive) {
        lines.push("- 已开启写操作探测，但跨用户 DELETE 仍未执行（不可回滚）；如需覆盖再加 blackbox.allowDestructive=true 或 GUARDBUILD_BLACKBOX_DELETE=1。");
      }
    } else if (outcome === "no_findings") {
      lines.push(`- 本次覆盖：${coverageText(bb.coverage)}。`);
      if (!bb.allowMutation) lines.push("- 写操作类越权（跨用户 PUT/PATCH/DELETE、匿名写入）本轮未执行，属未覆盖项。");
      lines.push("- 未发现不代表无漏洞：黑盒结果受路由发现、测试身份、资源可发现性与攻击面启发式限制；建议补充 guardbuild.json 的 login/identities/blackbox.loginPaths 或 OpenAPI 文档后重跑。");
    } else if (outcome === "failed") {
      lines.push(`- 执行失败（${r.error?.code}）：${r.error?.message ?? ""}${r.error?.hint ? `；建议：${r.error.hint}` : ""}`);
    } else {
      lines.push("- 黑盒扫描未完成裁决；可重新运行。");
    }
    return lines.join("\n");
  }
  if (outcome === "vulnerable" && patchStatus === "verified") {
    lines.push(`- 隔离 worktree 中已存在通过双重验收的修复补丁（\`${r.patch?.hash?.slice(0, 12)}…\`），gate 未写回原工作区。`);
    lines.push(`- 补丁位置：\`${r.patch?.worktree}\`；可将修改应用到工作区后提交。`);
    lines.push("- 修复落地后重跑 GuardBuild gate，应得到 exit 0（no_candidates / not_reproducible）。");
  } else if (outcome === "vulnerable") {
    lines.push("- 补丁未通过双重验收（存在未阻断攻击或业务回归），请对照 post 证据中的 regressed/inconclusive 用例人工审查。");
    lines.push(`- 补丁保留在隔离 worktree：\`${r.patch?.worktree}\`。`);
  } else if (outcome === "no_candidates") {
    lines.push("- 这是 exit 0 的正常终态（未命中覆盖范围），不是执行失败：引擎完成了源码扫描，只是没识别出可探测的对象级接口。");
    lines.push(`- ${coverageSummary()}`);
    lines.push(
      "- 让这类项目进入检测：在 guardbuild.json 用 `routes` 或 `openapi.file` 显式声明路由；未知框架可开启 `llm.enabled` 做接入侦察；纯前端 + 托管后端（如 Supabase）请核对 `identities` 与登录契约。"
    );
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
  if (Array.isArray(llm.startAttempts) && llm.startAttempts.length) {
    lines.push(
      "**启动候选实际验证**（按侦察给出的顺序逐个真实启动，首个就绪即止）\n",
      "| # | 命令 | 结果 | 诊断 | 耗时 |",
      "| --- | --- | --- | --- | --- |"
    );
    for (const a of llm.startAttempts) {
      const cmd = `${a.cmd ?? "?"} ${(a.args ?? []).join(" ")}`.trim();
      const result = a.skipped ? "跳过（预算不足）" : a.ok ? "已就绪" : "失败";
      const diag = a.ok
        ? "—"
        : esc(
            [a.diagnosisCode ?? a.code ?? "—", a.exitCode != null ? `exit ${a.exitCode}` : null]
              .filter(Boolean)
              .join(" · ")
          );
      lines.push(
        `| ${a.index ?? "?"}/${a.total ?? "?"} | \`${esc(cmd)}\` | ${result} | ${a.skipped ? esc(a.hint ?? "—") : diag} | ${
          a.durationMs != null ? `${a.durationMs}ms` : "—"
        } |`
      );
    }
    lines.push("");
  } else if (llm.rejectedStart) {
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

const BOOTSTRAP_OUTCOME_LABEL = {
  started: "已把项目拉起来（实跑就绪）",
  budget_exhausted: "预算用尽，仍未就绪",
  gave_up: "代理判断无法继续，主动收手",
  llm_unavailable: "LLM 不可用，未进入代理循环",
  agent_error: "代理执行出错",
  not_started: "未拉起",
};

/** 有界启动代理（S3-full）：动作序列与预算如实呈报，成功只认引擎实跑就绪 */
function renderBootstrapSection(b) {
  const label = BOOTSTRAP_OUTCOME_LABEL[b.outcome] ?? b.outcome ?? "—";
  const lines = [
    "## 有界启动代理\n",
    "| 项目 | 值 |",
    "| --- | --- |",
    `| 触发原因 | ${esc(b.reason ?? "—")} |`,
    `| 模型 | ${esc(b.model ?? "—")} |`,
    `| 结局 | ${esc(label)}${b.outcome === "started" ? "（由真实启动+就绪判定位定，非模型自评）" : ""} |`,
    `| 步数 | ${b.stepsUsed ?? 0} / ${b.maxSteps ?? "—"} |`,
    `| 被拒选择 | ${b.rejected ?? 0} 条 |`,
    `| 动作菜单 | exec ${b.menuSize ?? 0} 条 / start ${b.startMenuSize ?? 0} 条 |`,
    `| 用时 | ${b.durationMs != null ? `${b.durationMs}ms` : "—"} |`,
    `| 剩余预算 | ${b.remainingMs != null ? `${Math.round(b.remainingMs / 1000)}s` : "—"} |`,
    `| 就绪地址 | ${b.url ? `\`${esc(b.url)}\`` : "—"} |`,
    "",
  ];
  if (b.budgetStop) lines.push(`- 预算停止条件：${esc(b.budgetStop)}`);
  if (b.error) lines.push(`- 代理错误：${esc(b.error)}`);
  if (b.note) lines.push(`- 代理收手说明：${esc(b.note)}`);
  if (b.budgetStop || b.error || b.note) lines.push("");
  if (Array.isArray(b.actions) && b.actions.length) {
    lines.push(
      "**动作序列**（命令行一律由引擎按仓库清单拼装，模型只能报编号；下表记录实际执行的那条）\n",
      "| 步 | 动作 | 对象 | 结果 | 退出码 | 耗时 | 备注 |",
      "| --- | --- | --- | --- | --- | --- | --- |"
    );
    for (const a of b.actions) {
      lines.push(
        `| ${a.step ?? "?"} | ${esc(a.action ?? "—")} | \`${esc(truncate(a.subject ?? "—", 80))}\` | ${
          a.ok ? "成功" : "未成功"
        } | ${a.exitCode ?? "—"} | ${a.durationMs != null ? `${a.durationMs}ms` : "—"} | ${esc(truncate(a.note ?? "—", 120))} |`
      );
    }
    lines.push("");
  }
  if (b.start) {
    lines.push(
      `- 最终生效的启动契约：\`${esc(b.start.cmd ?? "?")} ${esc((b.start.args ?? []).join(" "))}\`（startSource = \`bootstrap-agent\`，后续修复验收沿用这一条）`
    );
    lines.push("");
  }
  return lines.join("\n");
}

function summarizeBootstrap(b) {
  if (!b) return null;
  return {
    reason: b.reason ?? null,
    model: b.model ?? null,
    outcome: b.outcome ?? null,
    stepsUsed: b.stepsUsed ?? 0,
    maxSteps: b.maxSteps ?? null,
    rejected: b.rejected ?? 0,
    durationMs: b.durationMs ?? null,
    remainingMs: b.remainingMs ?? null,
    budgetStop: b.budgetStop ?? null,
    error: b.error ?? null,
    note: b.note ?? null,
    url: b.url ?? null,
    menuSize: b.menuSize ?? 0,
    startMenuSize: b.startCandidateSize ?? 0,
    budget: b.budget ?? null,
    start: b.start
      ? { cmd: b.start.cmd, args: b.start.args ?? [], cwd: b.start.cwd ?? null }
      : null,
    actions: (b.actions ?? []).slice(0, 12).map((a) => ({
      step: a.step ?? null,
      action: a.action ?? null,
      subject: a.subject ?? null,
      ok: !!a.ok,
      exitCode: a.exitCode ?? null,
      durationMs: a.durationMs ?? null,
      note: a.note ?? null,
    })),
  };
}

function summarizeLlmPatch(llm) {
  if (!llm || !llm.enabled) return null;
  return {
    model: llm.model ?? null,
    requestedFiles: (llm.requestedFiles ?? []).length,
    appliedFiles: (llm.appliedFiles ?? []).map((f) => ({ file: f.file, ops: f.ops })),
    appliedOps: llm.appliedOps ?? 0,
    usage: (llm.usage ?? []).slice(0, 8),
    rejected: (llm.rejected ?? []).slice(0, 12),
    failures: (llm.failures ?? []).slice(0, 8),
    toolRounds: llm.toolRounds ?? 0,
    // 跨文件/新建文件（S2-full）：写集里到底动了哪些已有文件、新建了哪些，全部留痕可审计
    crossFile: llm.crossFile === true,
    crossFileFiles: (llm.crossFileFiles ?? []).map((f) => ({ from: f.from, to: f.to, role: f.role, ops: f.ops })),
    createdFiles: (llm.createdFiles ?? []).slice(0, 12),
    // 只读自查留痕：模型看了哪些文件、哪些请求被路径守卫挡下（内容不进报告）
    toolCalls: (llm.toolCalls ?? []).slice(0, 24).map((t) => ({
      file: t.file ?? null,
      tool: t.tool ?? null,
      path: t.path ?? null,
      ok: !!t.ok,
      chars: t.chars ?? null,
      entries: t.entries ?? null,
      reason: t.reason ?? null,
    })),
  };
}

function renderLlmPatchSection(llm) {
  const lines = [
    "## LLM 编码代理（补丁意图）\n",
    "| 项目 | 值 |",
    "| --- | --- |",
    `| 模型 | ${esc(llm.model ?? "—")} |`,
    `| 请求文件 | ${llm.requestedFiles} 个 |`,
    `| 采纳补丁 | ${llm.appliedOps} 处（${llm.appliedFiles.map((f) => `${f.file}×${f.ops}`).join("、") || "无"}） |`,
    ...(llm.toolRounds
      ? [
          `| 只读自查 | ${llm.toolRounds} 轮，${(llm.toolCalls ?? []).length} 次调用（${
            (llm.toolCalls ?? [])
              .map((t) => `${t.tool ?? "?"} ${t.path ?? "?"}${t.ok ? "" : "（被拒）"}`)
              .join("、") || "无"
          }）——只读 worktree 内源码，写入范围未变 |`,
        ]
      : []),
    ...(llm.crossFile
      ? [
          `| 写入范围 | 已开启跨文件补丁：候选文件外的已有文件 ${
            (llm.crossFileFiles ?? []).length
          } 个（${(llm.crossFileFiles ?? [])
            .map((f) => `${f.to}·${f.role}`)
            .join("、") || "无"}），新建 ${(llm.createdFiles ?? []).length} 个（${
            (llm.createdFiles ?? []).join("、") || "无"
          }）——均限于候选的依赖闭包写集与已扫描源码目录 |`,
        ]
      : []),
    ...(llm.usage?.length
      ? [
          `| Token 用量 | ${llm.usage
            .map((u) => `${u.file}: prompt ${u.prompt_tokens ?? "?"} / completion ${u.completion_tokens ?? "?"}`)
            .join("；")} |`,
        ]
      : []),
    `| 校验拒绝 | ${(llm.rejected ?? []).length} 条 |`,
    "",
  ];
  if (llm.appliedFiles?.length) {
    lines.push(
      "- 工作方式：模型只提交 `file + search + replace` 的补丁意图，Sidecar 在隔离副本的真实字节上校验锚点唯一、目标为源码文件、改动规模受限，再由 Host 写入隔离 worktree；补丁仍须通过「攻击阻断 + 业务不回归」双重验收。",
      ""
    );
  }
  const rejects = (llm.rejected ?? []).slice(0, 8);
  if (rejects.length) {
    lines.push("**被拒绝的补丁意图**\n", ...rejects.map((r) => `- ${esc(r.file)}：${esc(r.reason)}`), "");
  }
  if (llm.failures?.length) {
    lines.push("**未产出补丁的文件**\n", ...llm.failures.slice(0, 6).map((f) => `- ${esc(f.file)}：${esc(f.reason)}`), "");
  }
  return lines.join("\n");
}

/** 改动范围画像：人工审查的第一问不是「diff 长什么样」，而是「这次动了哪些文件、它们还被谁用着」 */
function renderScopeLines(scope) {
  if (!scope) return [];
  const untouched = (scope.files ?? []).filter((f) => f.untouched).map((f) => f.file);
  const lines = [
    `- 改动范围：候选文件 ${(scope.candidateFiles ?? []).length} 个、依赖闭包内已有文件 ${
      (scope.closureFiles ?? []).length
    } 个（${(scope.closureFiles ?? []).map((f) => `\`${f}\``).join("、") || "无"}）、新建 ${(scope.newFiles ?? []).length} 个（${
      (scope.newFiles ?? []).map((f) => `\`${f}\``).join("、") || "无"
    }）${scope.crossFile ? "——跨文件写权限由 llm.patchCrossFile 开启，范围严格限于候选的依赖闭包写集" : ""}`,
  ];
  if (untouched.length) {
    lines.push(`  - 漏洞文件本身未改动（${untouched.map((f) => `\`${f}\``).join("、")}）：修法落在挂载点/共享模块，逐候选归因仍按入口翻转判定`);
  }
  if (scope.sharedFiles?.length) {
    lines.push(
      `  - 共享文件影响面：${scope.sharedFiles
        .map((s) => `\`${s.file}\` 被 ${s.inDegree} 处 import`)
        .join("；")}（入度越高越要确认其它调用方不受影响）`
    );
  }
  if (scope.rejectedCount) {
    lines.push(`  - 另有 ${scope.rejectedCount} 条补丁意图在校验层被拒（越界/锚点歧义/规模超限），未写入任何文件`);
  }
  return lines;
}

function inlineCode(value) {
  return `\`${String(value ?? "").replace(/`/g, "\\`")}\``;
}

function renderFixBriefs(briefs) {
  if (!briefs?.length) return null;
  const lines = [
    `## 修复简报（${briefs.length}）\n`,
    "> 每条含风险说明、建议排查的代码形态、修复方向、复现命令与修复后复测方法；完整字段见 `report.json` 的 `summary.fixBriefs`。\n",
  ];
  for (const [i, b] of briefs.slice(0, MD_FIX_BRIEF_CAP).entries()) {
    const endpoint = [b.method, b.path].filter(Boolean).join(" ");
    const loc = b.file ? inlineCode(`${b.file}${b.startLine ? `:${b.startLine}` : ""}`) : null;
    lines.push(`### ${i + 1}. ${b.familyLabel}${endpoint ? `：${endpoint}` : ""}\n`);
    lines.push(`- 证据类型：${b.type}`);
    if (loc) lines.push(`- 位置：${loc}`);
    lines.push(`- 风险：${b.risk}`);
    lines.push("- 建议排查的代码形态：");
    for (const s of b.inspect ?? []) lines.push(`  - ${s}`);
    lines.push(`- 修复方向：${b.fix}`);
    if (b.reproduce) lines.push(`- 复现：${inlineCode(b.reproduce)}`);
    lines.push(`- 修复后复测：${inlineCode(b.verify)}`);
    lines.push(`- 复测预期：${b.verifyExpectation}`);
    lines.push("");
  }
  if (briefs.length > MD_FIX_BRIEF_CAP) {
    lines.push(`_其余 ${briefs.length - MD_FIX_BRIEF_CAP} 条见 report.json 的 summary.fixBriefs。_\n`);
  }
  return lines.join("\n");
}

function renderMarkdown(r) {
  const acc = r.acceptance;
  const bb = r.blackbox ?? null;
  const bbEvidence = r.evidence.blackbox ?? [];
  const pre = r.evidence.pre ?? [];
  const post = r.evidence.post ?? [];
  const preVuln = pre.filter((e) => e.verdict === "vulnerable").length;
  const parts = [];

  parts.push(`# ${bb ? "GuardBuild 黑盒安全扫描报告" : "GuardBuild 安全诊断报告"}\n`);
  parts.push(`> **结论：${r.verdict.headline}**\n`);
  parts.push(
    [
      "| 项目 | 值 |",
      "| --- | --- |",
      `| 生成时间 | ${fmtTime(r.generatedAt)} |`,
      `| 目标项目 | ${esc(r.session.projectName)}（\`${esc(r.session.projectRoot)}\`） |`,
      ...(bb ? [`| 扫描目标 | \`${esc(bb.url)}\` |`] : []),
      `| 会话 | ${esc(r.session.id)} |`,
      `| 终态 | ${esc(r.session.stateLabel)}（${esc(r.session.state)}） |`,
      `| 退出码 | ${r.verdict.exitCode}（0=无漏洞证据 / 1=漏洞证据成立 / 2=执行失败） |`,
      `| 模式 | ${bb ? "纯黑盒外部扫描（不读源码 / 不启动目标 / 不生成补丁）" : r.tool.gate ? "CI gate（策略授权，禁止写回）" : "交互会话"} |`,
      ...(r.targets?.docker?.enabled
        ? [
            `| Docker 沙箱 | \`${esc(r.targets.docker.image)}\`；项目 → \`${esc(r.targets.docker.workdir)}\`；容器端口 ${r.targets.docker.containerPort}（仅供运行时隔离，不构成对恶意代码的安全边界） |`,
          ]
        : []),
      `| 协议 | ${r.tool.protocolVersion} |`,
      "",
    ].join("\n")
  );

  parts.push(`## 摘要\n`);
  const bruteRouteCount = (bb?.routes ?? []).filter((x) => x.source === "brute").length;
  const summaryLines = bb
    ? [
        `- 扫描目标：\`${esc(bb.url)}\``,
        `- 路由发现：${bb.routeCount ?? 0} 条（OpenAPI ${bb.openapiRouteCount ?? 0} 条 / 前端提取 ${bb.frontendRouteCount ?? 0} 条 / 目录探测 ${bruteRouteCount} 条）`,
        `- 黑盒证据：${bbEvidence.length} 条，其中 vulnerable ${bbEvidence.filter((e) => e.verdict === "vulnerable").length} 条`,
        `- 登录：${
          bb.login?.ok
            ? `成功（${esc(bb.login.path)}；身份 ${esc((bb.login.identities ?? []).map((i) => i.name).join("、") || "—")}）`
            : "失败或未配置（跨用户越权用例已跳过）"
        }`,
        `- 写操作探测：${
          bb.allowMutation
            ? `已开启（PUT/PATCH${bb.allowDestructive ? " + 不可回滚的 DELETE" : "；DELETE 未开启"}，会修改目标数据并尽力恢复）`
            : "关闭（默认只读探测）"
        }`,
        `- 本轮攻击面：${coverageText(bb.coverage)}`,
        `- 目标可达：${
          bb.reachable === false
            ? "否（连接失败，未执行探测）"
            : `是${bb.rateLimited ? "；命中速率限制（429）" : "；未观察到 429"}`
        }`,
      ]
    : [`- 静态发现：${r.summary.findingCount} 个安全候选端点`];
  if (!bb) {
    summaryLines.push(`- 修复前证据（pre）：${pre.length} 条，其中 vulnerable ${preVuln} 条`);
    const preGrades = r.summary.phases?.pre?.grades;
    if (preGrades) {
      summaryLines.push(
        `- 证据级别（pre）：决策轨迹 ${preGrades.strong ?? 0} 条 / 内容归属 ${preGrades["cross-proven"] ?? 0} 条 / 仅 HTTP ${preGrades["http-only"] ?? 0} 条`
      );
    }
  }
  if (acc) {
    summaryLines.push(
      `- 双重验收：攻击阻断 ${acc.attackBlocked}/${acc.attackTotal}，业务保持 ${acc.businessPassed}/${acc.businessTotal} → ${acc.pass ? "通过" : "未通过"}`
    );
    if (acc.variantCounted || acc.variantSkipped) {
      summaryLines.push(
        `- 验收含同源攻击变体 ${acc.variantCounted} 条（换对象 / 换 ID 写法 / 换参数通道）${
          acc.variantSkipped ? `，另 ${acc.variantSkipped} 条因修复前未复现未计入` : ""
        }`
      );
    }
  }
  if (r.patch) {
    const llmBits = r.patch.llm
      ? `；LLM 编码代理采纳 ${r.patch.llm.appliedOps} 处、拒绝 ${r.patch.llm.rejected?.length ?? 0} 条`
      : "";
    summaryLines.push(
      `- 补丁：\`${r.patch.hash?.slice(0, 12)}…\`（${r.patch.files?.length ?? 0} 个文件，${esc(r.patch.status)}；策略 ${esc(r.patch.strategy ?? "—")}${llmBits}）`
    );
    if (r.patch.fixLoop?.rounds?.length) {
      summaryLines.push(
        `- 修复循环：${r.patch.fixLoop.attempts} 轮（重试上限 ${r.patch.fixLoop.maxRounds}；${
          r.patch.fixLoop.resolvedRound ? `第 ${r.patch.fixLoop.resolvedRound} 轮通过` : "未收敛"
        }）`
      );
    }
  }
  const sb = r.summary.supabase;
  if (!bb && sb?.detected) {
    const bits = [`URL \`${esc(sb.url ?? "—")}\``, `表引用 ${sb.tables?.length ?? 0} 个`];
    if (sb.serviceRoleLeak) bits.push(`service_role 暴露（${esc(sb.serviceRoleLeak.source)}）`);
    if (sb.leaks) bits.push(`匿名可读 ${sb.leaks} 个表`);
    summaryLines.push(`- Supabase：${bits.join("，")}`);
  }
  if (!bb && r.summary.start) summaryLines.push(`- 启动契约：\`${esc(r.summary.start.cmd)} ${esc((r.summary.start.args ?? []).join(" "))}\`（就绪模式 ${esc(r.summary.start.readyPattern)}）`);
  if (!bb && r.llm?.used) {
    const applied = [
      r.llm.applied?.start ? "启动" : null,
      r.llm.applied?.login ? "登录" : null,
      r.llm.applied?.routes ? `路由 ${r.llm.applied.routes} 条` : null,
    ].filter(Boolean);
    summaryLines.push(
      `- LLM 接入侦察：${esc(r.llm.model ?? "未知模型")}，应用 ${esc(applied.join("、") || "无")}；启动 ${r.llm.verified?.start ? "已验证" : "未验证"}，登录 ${r.llm.verified?.login ? "已验证" : "未验证"}${r.llm.cached ? `（${r.llm.cacheSource === "disk" ? "磁盘" : "内存"}缓存）` : ""}`
    );
  }
  if (!bb && r.bootstrap) {
    summaryLines.push(
      `- 有界启动代理：${esc(BOOTSTRAP_OUTCOME_LABEL[r.bootstrap.outcome] ?? r.bootstrap.outcome ?? "—")}（${r.bootstrap.stepsUsed ?? 0}/${r.bootstrap.maxSteps ?? "—"} 步，菜单 ${r.bootstrap.menuSize ?? 0} 个动作）`
    );
  }
  if (r.error) summaryLines.push(`- 错误：\`${esc(r.error.code)}\` — ${esc(r.error.message)}`);
  parts.push(summaryLines.join("\n") + "\n");

  if (!bb && r.llm?.used) parts.push(renderLlmSection(r.llm));
  if (!bb && r.bootstrap) parts.push(renderBootstrapSection(r.bootstrap), "");

  if (!bb && r.summary.findings.length) {
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
    const fix = renderFixBriefs(r.summary.fixBriefs);
    if (fix) parts.push(fix);
  }

  if (bb) {
    parts.push(`## 黑盒发现（${bb.findings?.length ?? 0}）\n`);
    if (bb.findings?.length) {
      parts.push(
        [
          "| 类型 | 方法 | 路径 | 证据级别 | 详情 |",
          "| --- | --- | --- | --- | --- |",
          ...bb.findings.map(
            (f) =>
              `| ${esc(f.type)} | ${esc(f.method)} | ${esc(f.path)} | ${esc(GRADE_LABELS[f.evidenceGrade] ?? f.evidenceGrade ?? "—")} | ${esc(f.detail)} |`
          ),
          "",
        ].join("\n")
      );
    } else {
      parts.push("_未发现可复现漏洞。_\n");
    }
    const fix = renderFixBriefs(r.summary.fixBriefs);
    if (fix) parts.push(fix);
    parts.push(`## 黑盒探测证据（${bbEvidence.length} 条）\n`);
    parts.push(evidenceTable(bbEvidence));
  } else {
    parts.push(`## 修复前证据（pre，${pre.length} 条）\n`);
    parts.push(evidenceTable(pre));
  }

  if (r.patch) {
    parts.push(`## 修复补丁\n`);
    const fileDesc = (r.patch.files ?? [])
      .map((f) => (typeof f === "string" ? `\`${f}\`` : `\`${f.path}\`（+${f.insertions}/-${f.deletions}）`))
      .join("、");
    parts.push(
      [
        `- 哈希：\`${r.patch.hash}\``,
        `- 策略：${esc(r.patch.strategy ?? "—")}${r.patch.autoVerify ? "（LLM 编码代理补丁已自动执行双重验收，通过后才进入人工审查）" : ""}`,
        ...(r.patch.fixes?.length
          ? [
              `- 逐候选：${r.patch.fixes
                  .flatMap((f) => (f.candidates ?? []).map((c) => `\`${c.candidate}\`→${esc(c.strategy)}（${f.file}）`))
                  .join("；")}`,
            ]
          : []),
        ...(r.patch.skipped?.length
          ? [`- 未产出补丁的候选：${r.patch.skipped.length} 个（原因见 report.json 的 patch.skipped）`]
          : []),
        `- 文件：${fileDesc || "—"}`,
        ...renderScopeLines(r.patch.scope),
        `- 隔离位置：\`${esc(r.patch.worktree)}\``,
        `- 状态：${esc(r.patch.status)}（${r.patch.lineCount ?? 0} 行改动）`,
        ...(r.patch.fixLoop?.rounds?.length
          ? [
              `- 修复循环：共 ${r.patch.fixLoop.attempts} 轮（重试上限 ${r.patch.fixLoop.maxRounds}；${
                r.patch.fixLoop.resolvedRound ? `第 ${r.patch.fixLoop.resolvedRound} 轮通过` : "未收敛"
              }）`,
              ...r.patch.fixLoop.rounds.flatMap((x) => {
                const v = x.verdict ?? {};
                const failedText =
                  !x.pass && x.failed?.length ? `；失败用例：${x.failed.slice(0, 3).map((f) => esc(f)).join("；")}` : "";
                const line = `  - 第 ${x.round} 轮：${x.pass ? "通过" : "未通过"}（攻击阻断 ${v.attackBlocked ?? 0}/${v.attackTotal ?? 0}，业务保持 ${v.businessPassed ?? 0}/${v.businessTotal ?? 0}；patch \`${String(x.patchHash ?? "").slice(0, 12)}…\`）${failedText}`;
                if (!x.feedback || x.pass) return [line];
                const fb = x.feedback;
                return [
                  line,
                  `    - 回喂下一轮的证据：失败用例 ${fb.failedCases ?? 0} 条、隔离实例日志 ${fb.logLines ?? 0} 行${
                    fb.targetExited ? `（进程已退出，退出码 ${fb.targetExitCode ?? "?"}）` : ""
                  }${fb.diagnostics?.length ? `；诊断码 ${fb.diagnostics.join("、")}` : ""}；上一轮 diff ${fb.diffChars ?? 0} 字符`,
                ];
              }),
            ]
          : []),
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
    if (r.patch.llm) parts.push(renderLlmPatchSection(r.patch.llm), "");
  }

  if (acc) {
    parts.push(`## 双重验收（post）\n`);
    parts.push(
      `攻击阻断 ${acc.attackBlocked}/${acc.attackTotal}，业务保持 ${acc.businessPassed}/${acc.businessTotal} → **${acc.pass ? "通过" : "未通过"}**\n`
    );
    if (acc.variantCounted || acc.variantSkipped) {
      parts.push(
        `同源攻击变体 ${acc.variantCounted} 条参与验收（换对象 / 换 ID 写法 / 换参数通道；变体由引擎按模板生成，模型不参与编写用例）${
          acc.variantSkipped ? `；${acc.variantSkipped} 条修复前未复现，不计入阻断` : ""
        }。正向断言：本人读取仍返回完整对象且字段不少于修复前基线，防止用「整端点拒绝」或「删字段」冒充修复。\n`
      );
    }
    const at = acc.attribution;
    if (at && (at.claimedCount || at.rows?.length)) {
      parts.push(
        `**逐候选归因**：补丁点名 ${at.claimedCount} 个入口，其中 ${at.blockedCount} 个完成了自己的「修复前打穿 → 修复后阻断」翻转${
          at.unverifiedCount ? `；${at.unverifiedCount} 个归因不成立` : ""
        }${at.stillVulnerableCount ? `；${at.stillVulnerableCount} 个修复后仍可越权` : ""}。总体计数变好不算修复——只有该候选自身的用例翻转才计入「已修复」。\n`
      );
      const rows = (at.rows ?? []).filter((x) => x.claimed);
      if (rows.length) {
        parts.push(
          `| 补丁点名的入口 | 修复前复现用例 | 修复后判定 | 源码位置 | 补丁命中 | 结论 |\n| --- | --- | --- | --- | --- | --- |\n` +
            rows
              .map((x) =>
                `| \`${esc(x.candidate)}\` | ${x.preReproCases} | ${x.postCases}/${x.preReproCases} 阻断 | ${
                  x.file ? `\`${esc(x.file)}${Number.isFinite(x.line) ? `:${x.line}` : ""}\`` : "—"
                } | ${
                  x.locality === "same_file"
                    ? `同文件 ${x.hunksInFile} 处${Number.isFinite(x.hunkDistance) ? `（距漏洞行 ${x.hunkDistance}）` : ""}`
                    : x.locality === "other_file"
                      ? "改动未落在该文件"
                      : "—"
                } | ${ATTRIBUTION_LABELS[x.status] ?? x.status}${x.reason ? `：${esc(x.reason)}` : ""} |`
              )
              .join("\n") +
            "\n"
        );
      }
    }
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
  // exit 0 的正常终态（未命中覆盖范围 / 未发现可复现漏洞）不写「执行出错」
  const errPres = error?.code ? describeOutcome(error.code) : null;
  const stateLabel =
    errPres && errPres.kind !== "failed" ? errPres.stateLabel : STATE_LABELS[state ?? view.state] ?? (state ?? view.state);
  const byPhase = (p) => evidence.filter((e) => e.phase === p);
  const finalState = state ?? view.state;
  const start = ctx.targetConfig?.start ?? null;
  const supabase = view.supabase ?? null;
  const blackbox = view.blackbox ?? null;
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
      stateLabel,
    },
    verdict: {
      outcome,
      exitCode,
      patchStatus,
      headline: headline(outcome, patchStatus, supabase, blackbox),
    },
    summary: {
      findingCount: (view.findings ?? []).length,
      findings: view.findings ?? [],
      evidence: {
        blackbox: byPhase("blackbox").length,
        pre: byPhase("pre").length,
        post: byPhase("post").length,
        postWriteback: byPhase("post_writeback").length,
      },
      phases: view.phases ?? {},
      acceptance: view.acceptance ?? null,
      supabase,
      blackbox: blackbox
        ? {
            url: blackbox.url,
            routeCount: blackbox.routeCount ?? 0,
            openapiFound: !!blackbox.openapiFound,
            openapiRouteCount: blackbox.openapiRouteCount ?? 0,
            frontendRouteCount: blackbox.frontendRouteCount ?? 0,
            frontendScripts: blackbox.frontendScripts ?? 0,
            routeSources: (blackbox.routes ?? []).reduce((acc, r) => {
              const key = r.source ?? "unknown";
              acc[key] = (acc[key] ?? 0) + 1;
              return acc;
            }, {}),
            findingCount: (blackbox.findings ?? []).length,
            login: blackbox.login ?? null,
            rateLimited: !!blackbox.rateLimited,
            allowMutation: !!blackbox.allowMutation,
            allowDestructive: !!blackbox.allowDestructive,
            coverage: blackbox.coverage ?? null,
          }
        : null,
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
          startAttempts: (view.llm.startAttempts ?? []).slice(0, 8).map((a) => ({
            index: a.index ?? null,
            total: a.total ?? null,
            cmd: a.cmd ?? null,
            args: a.args ?? [],
            cwd: a.cwd ?? null,
            ok: !!a.ok,
            skipped: !!a.skipped,
            code: a.code ?? null,
            diagnosisCode: a.diagnosisCode ?? null,
            exitCode: a.exitCode ?? null,
            hint: a.hint ?? null,
            durationMs: a.durationMs ?? null,
          })),
          evidenceFiles: view.llm.evidenceFiles ?? [],
          evidenceChars: view.llm.evidenceChars ?? 0,
          usage: view.llm.usage ?? null,
          notes: view.llm.notes ?? [],
          warnings: view.llm.warnings ?? [],
        }
      : null,
    bootstrap: summarizeBootstrap(view.bootstrap),
    supabase,
    blackbox,
    evidence: {
      blackbox: byPhase("blackbox"),
      pre: byPhase("pre"),
      post: byPhase("post"),
      postWriteback: byPhase("post_writeback"),
    },
    poc: blackbox
      ? buildPocList(byPhase("blackbox"), blackbox.url)
      : buildPocList(byPhase("pre"), view.targets?.original?.url),
    patch: view.patch
      ? {
          hash: view.patch.hash,
          files: view.patch.files,
          worktree: view.patch.worktree,
          status: view.patch.status,
          lineCount: view.patch.lineCount,
          diff: view.patch.diff,
          strategy: view.patch.strategy ?? null,
          autoVerify: !!view.patch.autoVerify,
          fixes: (view.patch.fixes ?? []).map((f) => ({
            file: f.file,
            appliedOps: f.appliedOps ?? (f.fixes ?? []).length,
            candidates: (f.fixes ?? []).map((x) => ({
              candidate: x.candidate,
              candidateKey: x.candidateKey ?? null,
              strategy: x.strategy,
            })),
          })),
          skipped: (view.patch.skipped ?? []).slice(0, 12).map((s) => ({
            candidate: s.candidate ?? null,
            file: s.file ?? null,
            reason: s.reason ?? null,
          })),
          llm: summarizeLlmPatch(view.patch.llm),
          fixLoop: view.patch.fixLoop ?? null,
          // 风险画像：改动范围（角色 + 入度 + 新建），人工据此判断「这一屏 diff 之外还动了什么」
          scope: view.patch.scope ?? null,
        }
      : null,
    acceptance: view.acceptance ?? null,
    targets: view.targets ?? {},
    error,
  };
  r.summary.fixBriefs = buildFixBriefs(r);
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
