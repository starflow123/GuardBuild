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

function suggestions(r) {
  const { outcome, patchStatus } = r.verdict;
  const supabase = r.supabase ?? null;
  const lines = [];
  if (r.blackbox) {
    const bb = r.blackbox;
    if (outcome === "vulnerable_unfixed") {
      for (const f of (bb.findings ?? []).slice(0, 8)) {
        lines.push(`- 已复现：${f.type}（${f.method} ${f.path}）—— ${f.detail}`);
      }
      lines.push("- 黑盒模式只取证、不改码：请在源码/配置/数据库策略中修复上述端点，再重跑同一 URL 验证。");
      if (!bb.allowMutation) {
        lines.push("- 写操作类越权（PUT/POST）默认未执行（避免修改目标数据）；如需覆盖，设置 blackbox.allowMutation=true 或 GUARDBUILD_BLACKBOX_MUTATE=1 后重跑。");
      }
    } else if (outcome === "no_findings") {
      lines.push("- 本次覆盖：未认证读取、跨用户读取（IDOR）、路径穿越、SQL 注入（错误/布尔盲注）、敏感文件/调试端点暴露；可选写操作越权默认关闭。");
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
        `- 写操作探测：${bb.allowMutation ? "已开启（会修改目标数据并尽力恢复）" : "关闭（默认只读探测）"}`,
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
  if (r.error) summaryLines.push(`- 错误：\`${esc(r.error.code)}\` — ${esc(r.error.message)}`);
  parts.push(summaryLines.join("\n") + "\n");

  if (!bb && r.llm?.used) parts.push(renderLlmSection(r.llm));

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
          evidenceFiles: view.llm.evidenceFiles ?? [],
          evidenceChars: view.llm.evidenceChars ?? 0,
          usage: view.llm.usage ?? null,
          notes: view.llm.notes ?? [],
          warnings: view.llm.warnings ?? [],
        }
      : null,
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
            candidates: (f.fixes ?? []).map((x) => ({ candidate: x.candidate, strategy: x.strategy })),
          })),
          skipped: (view.patch.skipped ?? []).slice(0, 12).map((s) => ({
            candidate: s.candidate ?? null,
            file: s.file ?? null,
            reason: s.reason ?? null,
          })),
          llm: summarizeLlmPatch(view.patch.llm),
          fixLoop: view.patch.fixLoop ?? null,
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
