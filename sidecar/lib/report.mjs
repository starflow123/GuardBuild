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

/** Host 在 Windows 上用 \\?\ 扩展长度路径遍历目录，文件定位会带上这个前缀：给人看的报告要剥掉 */
function humanPath(v) {
  return String(v ?? "").replace(/^\\\\\?\\/, "");
}

/** 归因结论的中文措辞（与 attribution.mjs 的 status 一一对应） */
const ATTRIBUTION_LABELS = {
  blocked: "已翻转",
  still_vulnerable: "仍可越权",
  unverified: "归因不成立",
  not_reproduced: "修复前未复现",
};

/** 补丁落盘状态的中文措辞（view.patch.status） */
const PATCH_STATUS_LABELS = {
  pending_review: "待人工审查（隔离 worktree，未写回）",
  written_back: "已写回真实工作区",
  writeback_recheck_failed: "已写回真实工作区，但写回后复核未通过",
  writeback_recheck_incomplete: "已写回真实工作区，但写回后复核未完成",
  rolled_back: "已回滚（工作区恢复写回前）",
};

function headline(outcome, patchStatus, supabase, blackbox = null, errorCode = null) {
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
      if (patchStatus === "verify_failed") {
        return "发现可利用的对象级越权（IDOR）漏洞；修复补丁未通过双重验收，需人工审查证据";
      }
      if (patchStatus === "written_back") {
        return "发现可利用的对象级越权（IDOR）漏洞；修复补丁已写回真实工作区，写回后复攻通过";
      }
      if (patchStatus === "writeback_recheck_failed") {
        return "发现可利用的对象级越权（IDOR）漏洞；修复补丁已写回真实工作区，但写回后复攻未通过，建议回滚";
      }
      if (patchStatus === "writeback_recheck_incomplete") {
        return "发现可利用的对象级越权（IDOR）漏洞；修复补丁已写回真实工作区，但写回后复攻未能完成，需人工复测";
      }
      if (patchStatus === "rolled_back") {
        return "发现可利用的对象级越权（IDOR）漏洞；修复补丁曾写回真实工作区，现已回滚，工作区恢复原状";
      }
      return "发现可利用的对象级越权（IDOR）漏洞，已生成双重验收通过的修复补丁（gate 未写回工作区）";
    case "no_candidates":
      return "已识别出 HTTP 路由，但未发现可探测候选（exit 0，覆盖边界而非安全结论）：候选需要「静态形状 + 攻击用例」同时命中；可在 guardbuild.json 用 routes / openapi.file 声明接口，或开启 llm.enabled 做接入侦察";
    case "inconclusive":
      if (errorCode === "no_endpoints") {
        return "未识别到任何 HTTP 路由（exit 2，无法证明）：引擎无法确认被测系统已被覆盖，本轮结论不能当作安全";
      }
      if (errorCode === "plan_incomplete") {
        return "候选端点无法构造探测请求（exit 2，无法证明）：多段路径缺少参数取值来源，本轮没有真正打到目标";
      }
      if (errorCode === "no_list_endpoint") {
        return "未定位到按归属过滤的列表接口（exit 2，无法证明）：静态、契约与运行期自动发现都没能确定资源列表，本轮没有真正测到";
      }
      if (errorCode === "param_binding_unverified") {
        return "多段路径参数取值来源未通过实测（exit 2，无法证明）：已用真实对象试过字段映射，响应里没有可对应的字段，引擎不会猜";
      }
      if (errorCode === "static_routes_unverified") {
        return "静态推断的路由经运行期实测全部不成立（exit 2，无法证明）：本轮发出的每个请求都落在不存在的地址上，没有打到目标就不能当作安全";
      }
      if (errorCode === "scout_routes_unverified") {
        return "模型给出的路由经运行期实测全部不成立（exit 2，无法证明）：本轮没有可打的真实接口，报告列出每条路由的实测状态码";
      }
      return "攻击用例未跑全（exit 2，无法证明）：计划中的用例因身份 / 资源 / 运行期契约不足被跳过，本轮既没有复现漏洞，也没有真正测到它们";
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
      return "已测用例在运行实例上未复现（exit 0，不等于安全）：可能已有运行期防护，但只代表本轮发出的攻击打不通，未覆盖到的攻击面仍未知";
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
    if (bb.attackPlan?.rounds?.length) {
      const picked = (bb.attackPlan.appliedPicks ?? []).length;
      lines.push(
        picked
          ? `- 攻击规划代理：${bb.attackPlan.llmCalls ?? 0} 次调用把 ${picked} 条「按引擎原序拿不到预算」的路由提进探测队列（模型只挑路由编号，攻击内容与判据由引擎生成）。`
          : `- 攻击规划代理：本轮未改动探测预算（${bb.attackPlan.rounds.map((x) => x.fallback ?? "未挑选").join("、")}），按引擎原序探测。`
      );
    } else if ((bb.routeCount ?? 0) > (bb.probeCap ?? 14)) {
      lines.push(
        `- 路由 ${bb.routeCount} 条、每类探测预算 ${bb.probeCap ?? 14} 条：预算外的路由本轮未被打。可用 blackbox.attackPlan=true 或 GUARDBUILD_LLM_ATTACKPLAN=1 让规划代理按线索重排预算（仅交互模式，gate 不启用）。`
      );
    }
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
    lines.push(...startDiagnosisLines(r));
    return lines.join("\n");
  }
  if (outcome === "vulnerable" && patchStatus === "written_back") {
    const re = r.acceptance?.writebackRecheck;
    const backup = r.rollback?.backupId;
    lines.push(
      `- 补丁已写回真实工作区并通过写回后复攻${
        re ? `（攻击阻断 ${re.attackBlocked}/${re.attackTotal}，业务保持 ${re.businessPassed}/${re.businessTotal}）` : ""
      }。`
    );
    lines.push("- 写回只改工作区文件、不自动提交：请用 `git diff` 审查后按你的发布流程提交。");
    if (backup) lines.push(`- 写回前原文件已备份（backupId \`${backup}\`），如需撤销可在会话中点「回滚写回」。`);
  } else if (outcome === "vulnerable" && patchStatus === "writeback_recheck_failed") {
    const re = r.acceptance?.writebackRecheck;
    lines.push(
      `- 写回后复攻未通过：真实工作区状态与隔离验收不一致${
        re ? `（攻击阻断 ${re.attackBlocked}/${re.attackTotal}，业务保持 ${re.businessPassed}/${re.businessTotal}）` : ""
      }。`
    );
    lines.push("- 建议立即执行「回滚写回」恢复原文件，再回到隔离副本排查差异（环境变量、构建产物、运行配置等）。");
    if (r.rollback?.backupId) lines.push(`- 回滚备份：\`${r.rollback.backupId}\`。`);
  } else if (outcome === "vulnerable" && patchStatus === "writeback_recheck_incomplete") {
    lines.push("- 补丁已写回，但写回后复攻未能完成（目标未启动或探测异常），当前工作区状态未经实测确认。");
    lines.push("- 请手动重启项目并复测；如结果不符合预期可执行「回滚写回」。");
    if (r.rollback?.backupId) lines.push(`- 回滚备份：\`${r.rollback.backupId}\`。`);
  } else if (outcome === "vulnerable" && patchStatus === "rolled_back") {
    lines.push("- 补丁已回滚：真实工作区恢复到写回前状态，漏洞仍然存在。");
    lines.push("- 请基于 post 证据调整修复方案后重跑；原文件备份仍保留在数据目录。");
  } else if (outcome === "vulnerable" && patchStatus === "verified") {
    lines.push(`- 隔离 worktree 中已存在通过双重验收的修复补丁（\`${r.patch?.hash?.slice(0, 12)}…\`），gate 未写回原工作区。`);
    lines.push(`- 补丁位置：\`${r.patch?.worktree}\`；可将修改应用到工作区后提交。`);
    lines.push("- 修复落地后重跑 GuardBuild gate，应得到 exit 0（no_candidates / not_reproducible）。");
  } else if (outcome === "vulnerable") {
    lines.push("- 补丁未通过双重验收（存在未阻断攻击或业务回归），请对照 post 证据中的 regressed/inconclusive 用例人工审查。");
    lines.push(`- 补丁保留在隔离 worktree：\`${r.patch?.worktree}\`。`);
  } else if (outcome === "no_candidates") {
    lines.push("- 这是 exit 0 的覆盖边界说明，既不是执行失败，也不是「系统安全」的结论：引擎完成了源码扫描与路由识别，但没有候选同时命中「静态形状 + 攻击用例」。");
    lines.push(`- ${coverageSummary()}`);
    lines.push(
      "- 让这类项目进入检测：在 guardbuild.json 用 `routes` 或 `openapi.file` 显式声明路由；未知框架可开启 `llm.enabled` 做接入侦察；纯前端 + 托管后端（如 Supabase）请核对 `identities` 与登录契约。"
    );
  } else if (outcome === "inconclusive") {
    if (r.error?.code === "no_endpoints") {
      lines.push("- 本轮**无法证明**被测系统已被覆盖（exit 2）：引擎没有识别出任何 HTTP 路由，因此一条攻击请求都没有发出。");
      lines.push("- 补齐入口后重跑：`routes`（对象级接口同时给 `params` 绑定）或 `openapi.file`；资源发现可另配 `listEndpoint`；未知框架可开启 `llm.enabled` 做接入侦察。");
    } else if (r.error?.code === "plan_incomplete") {
      lines.push("- 本轮**无法证明**被测系统已测到位（exit 2）：候选端点存在，但没有能构造出可寻址请求的接口，引擎没有发出攻击。");
      lines.push(
        "- 多段路径（如 `/orgs/:orgId/orders/:orderId`）必须在 `routes[].params` 给每个参数声明取值来源（字段名简写 / `{\"from\":\"item\",\"field\":\"org_id\"}` / `{\"from\":\"const\",\"value\":\"v2\"}`）；单参数接口确认路径里有 `:param` 或声明了 `query`。"
      );
    } else if (r.error?.code === "no_list_endpoint") {
      lines.push("- 本轮**无法证明**被测系统已测到位（exit 2）：静态分析与运行期自动发现都没能确定按归属过滤的列表接口，资源归属发现没有着落。");
      lines.push(
        "- 在 guardbuild.json 用 `listEndpoint` 显式声明列表端点（可带分页/过滤 `query`），或在 `routes` 里补充路由后重跑；响应字段异常时配 `responses.list`。"
      );
    } else if (r.error?.code === "param_binding_unverified") {
      lines.push("- 本轮**无法证明**被测系统已测到位（exit 2）：引擎已用本人列表里的真实对象实测过多段路径的参数绑定，响应里没有与参数对应的字段，引擎不会猜。");
      lines.push(
        "- 在 guardbuild.json 的 `routes[].params` 为每个参数声明取值来源（字段名简写 / `{\"from\":\"item\",\"field\":\"org_id\"}` / `{\"from\":\"const\",\"value\":\"v2\"}`）后重跑。"
      );
    } else {
      lines.push("- 本轮**无法证明**被测系统已测到位（exit 2）：计划中的攻击用例因身份 / 可读资源 / 运行期契约不足被跳过，未真正执行。");
      lines.push(
        "- 按跳过原因补齐：`identities` 至少两个不同用户、可读资源列表（`listEndpoint` 连同分页 / 过滤 `query`）、响应字段（`responses.id` / `responses.owner`）、多参数路由绑定（`routes[].params`），然后重跑。"
      );
    }
    lines.push(`- 覆盖口径：${coverageSummary()}`);
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
      lines.push("- 请对照 report.json 中各攻击用例（如纵向越权、无鉴权读取、路径穿越、SQL/命令注入、CORS、CSRF、反射型 XSS）定位端点并人工加固，再重跑 GuardBuild gate 验证。");
    }
  } else if (outcome === "not_reproducible") {
    if (supabase) {
      lines.push("- Supabase 匿名探测未读出数据（RLS 生效或表为空），未见 service_role 暴露；如仍有顾虑，请在数据库侧核对 RLS 策略与密钥管理。");
    } else {
      lines.push("- 已测用例未复现，但这不是「系统安全」的证明：只说明本轮发出的攻击在运行实例上打不通（可能已有运行期防护），未覆盖的攻击面仍未知。");
      lines.push("- 如怀疑存在未测到的入口，请核对 guardbuild.json 的身份契约、可读资源接口（`listEndpoint`）与响应字段（`responses`）。");
    }
  } else if (outcome === "failed") {
    lines.push(`- 执行失败（${r.error?.code}）：${r.error?.message ?? ""}${r.error?.hint ? `；建议：${r.error.hint}` : ""}`);
  } else {
    lines.push("- 会话被中止，未完成裁决；可重新运行。");
  }
  lines.push(...startDiagnosisLines(r));
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

/** 逐候选归因：总体计数变好不算修复，只有候选自身的用例翻转才计入 */
function renderAttributionSection(at) {
  if (!at || (!at.claimedCount && !at.rows?.length)) return null;
  const lines = [
    `**逐候选归因**：补丁点名 ${at.claimedCount} 个入口，其中 ${at.blockedCount} 个完成了自己的「修复前打穿 → 修复后阻断」翻转${
      at.unverifiedCount ? `；${at.unverifiedCount} 个归因不成立` : ""
    }${
      at.stillVulnerableCount ? `；${at.stillVulnerableCount} 个修复后仍可越权` : ""
    }。总体计数变好不算修复——只有该候选自身的用例翻转才计入「已修复」。`,
    "",
  ];
  const rows = (at.rows ?? []).filter((x) => x.claimed);
  if (rows.length) {
    lines.push(
      `| 补丁点名的入口 | 修复前复现用例 | 修复后判定 | 源码位置 | 补丁命中 | 结论 |`,
      `| --- | --- | --- | --- | --- | --- |`,
      ...rows.map(
        (x) =>
          `| \`${esc(x.candidate)}\` | ${x.preReproCases} | ${x.postCases}/${x.preReproCases} 阻断 | ${
            x.file ? `\`${esc(x.file)}${Number.isFinite(x.line) ? `:${x.line}` : ""}\`` : "—"
          } | ${
            x.locality === "same_file"
              ? `同文件 ${x.hunksInFile} 处${Number.isFinite(x.hunkDistance) ? `（距漏洞行 ${x.hunkDistance}）` : ""}`
              : x.locality === "other_file"
                ? "改动未落在该文件"
                : "—"
          } | ${ATTRIBUTION_LABELS[x.status] ?? x.status}${x.reason ? `：${esc(x.reason)}` : ""} |`
      ),
      ""
    );
  }
  return lines.join("\n");
}

const ROUTE_DROP_LABEL = {
  not_found: "实测未命中（目标回不存在响应）",
  method_not_allowed: "方法不被允许",
  no_probe_id: "无真实资源 id 可填充，无法验证",
  request_failed: "复核请求失败",
  budget: "复核请求预算用尽",
};

function routeVerifySummary(rv) {
  if (!rv) return "未进行（本轮无 LLM 路由线索，或目标未启动）";
  const parts = [`送检 ${rv.checked ?? 0} 条，命中 ${rv.kept ?? 0} 条，丢弃 ${rv.dropped?.length ?? 0} 条`];
  if (rv.requestsUsed != null) parts.push(`复核请求 ${rv.requestsUsed} 个`);
  return parts.join("，");
}

function renderRouteVerification(rv) {
  if (!rv) return [];
  const rows = [];
  for (const d of rv.detail ?? []) {
    const auth =
      d.auth === "open" ? "匿名可取数（无鉴权确认）" : d.auth === "protected" ? "匿名被拒（需登录确认）" : "鉴权未定性";
    const owner =
      d.ownerFilter === false
        ? "两身份列表一致（未过滤）"
        : d.ownerFilter === true
          ? "两身份列表互斥（过滤生效）"
          : "归属未测";
    rows.push(
      `| \`${esc(d.declaredPath ?? d.key)}\` | ${d.status ?? "—"} | ${esc(auth)} | ${esc(owner)} |`
    );
  }
  for (const d of rv.dropped ?? []) {
    rows.push(
      `| \`${esc(d.key)}\` | — | 已丢弃 | ${esc(ROUTE_DROP_LABEL[d.reason] ?? d.reason ?? "—")}${
        d.detail ? `（${esc(d.detail)}）` : ""
      } |`
    );
  }
  if (!rows.length) return [];
  return [
    "\n**LLM 路由运行期实测**（判定只来自真实响应；丢弃即表示目标实例上没有这条路由）\n",
    "| 路由 | 带身份状态码 | 鉴权实测 | 归属过滤实测 |",
    "| --- | --- | --- | --- |",
    ...rows,
    "",
  ];
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
    `| 路由实测 | ${routeVerifySummary(llm.routeVerification)} |`,
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
    const withText = llm.startAttempts.filter((a) => !a.ok && !a.skipped && (a.excerpt || a.matched));
    for (const a of withText) {
      const tail = String(a.excerpt ?? "")
        .split("\n")
        .map((l) => String(l).trimEnd())
        .filter((l) => l.trim() !== "");
      lines.push(
        `失败候选 ${a.index ?? "?"}/${a.total ?? "?"}（\`${esc(`${a.cmd ?? "?"} ${(a.args ?? []).join(" ")}`.trim())}\`）${
          a.matched ? `命中原文「\`${esc(String(a.matched))}\`」` : "未命中已知诊断规则"
        }，启动输出尾部（已脱敏）：`,
        "",
        ...(tail.length ? ["```", ...tail, "```", ""] : ["_进程未输出日志_", ""])
      );
    }
  } else if (llm.rejectedStart) {
    const rejected = llm.rejectedStart;
    lines.push(
      `- 启动回退：LLM 启动契约未通过实际启动验证（\`${esc(rejected.cmd ?? "?")} ${esc((rejected.args ?? []).join(" "))}\`）。`
    );
  }
  lines.push(...renderRouteVerification(llm.routeVerification));
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

/** 攻击规划（M2）：呈报「模型挑了哪些路由」，不呈报模型原文；是否算漏洞仍由实测证据决定 */
function renderAttackPlanSection(p) {
  if (!p || !Array.isArray(p.rounds) || !p.rounds.length) return "";
  const lines = [
    "## 攻击规划代理（仅分配探测预算）\n",
    "| 项目 | 值 |",
    "| --- | --- |",
    `| 模型 | ${esc(p.model ?? "—")} |`,
    `| LLM 调用 | ${p.llmCalls ?? 0} 次（每类探测预算 ${p.probeCap ?? "—"} 条路由） |`,
    `| 提进预算的路由 | ${(p.appliedPicks ?? []).length} 条 |`,
    `| 丢弃的模型自带字段 | ${(p.ignoredFields ?? []).length ? p.ignoredFields.map((f) => `\`${esc(f)}\``).join("、") : "无"} |`,
    "",
    "| 轮 | 待排路由 | 采纳的选择 | 非法编号 | 丢弃字段 | 未采纳原因 | 耗时 |",
    "| --- | --- | --- | --- | --- | --- | --- |",
  ];
  for (const r of p.rounds) {
    lines.push(
      `| ${r.round} | ${r.menuSize ?? 0} 条 | ${
        (r.picks ?? []).length ? (r.picks ?? []).map((x) => `\`${esc(x.path)}\``).join("<br>") : "—"
      } | ${(r.invalid ?? []).length} | ${(r.ignored ?? []).length ? (r.ignored ?? []).map((f) => esc(f)).join(",") : "—"} | ${
        r.fallback ? esc(r.fallback) : "—"
      } | ${r.durationMs != null ? `${r.durationMs}ms` : "—"} |`
    );
  }
  lines.push(
    "",
    "- 模型只能从引擎已发现的路由里挑编号；载荷、方法、请求内容与判据全部由引擎生成，漏洞结论只来自实测证据（**非模型自评**）。",
    "- 该能力默认关闭，且 gate/CI 结构性禁用（`blackbox.attackPlan` 或 `GUARDBUILD_LLM_ATTACKPLAN=1`，仅交互模式生效）。",
    ""
  );
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
    const loc = b.file ? inlineCode(`${humanPath(b.file)}${b.startLine ? `:${b.startLine}` : ""}`) : null;
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
      `| 目标项目 | ${esc(r.session.projectName)}（\`${esc(humanPath(r.session.projectRoot))}\`） |`,
      ...(bb ? [`| 扫描目标 | \`${esc(bb.url)}\` |`] : []),
      `| 会话 | ${esc(r.session.id)} |`,
      `| 终态 | ${esc(r.session.stateLabel)}（${esc(r.session.state)}） |`,
      `| 退出码 | ${r.verdict.exitCode}（0=已测未复现 / 1=漏洞证据成立 / 2=无法证明或执行失败） |`,
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
  const robotsRouteCount = (bb?.routes ?? []).filter((x) => x.source === "robots").length;
  const sitemapRouteCount = (bb?.routes ?? []).filter((x) => x.source === "sitemap").length;
  const summaryLines = bb
    ? [
        `- 扫描目标：\`${esc(bb.url)}\``,
        `- 路由发现：${bb.routeCount ?? 0} 条（OpenAPI ${bb.openapiRouteCount ?? 0} 条 / 前端提取 ${bb.frontendRouteCount ?? 0} 条 / robots ${robotsRouteCount} 条 / sitemap ${sitemapRouteCount} 条 / 目录探测 ${bruteRouteCount} 条）`,
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
    const re = acc.writebackRecheck;
    if (re) {
      summaryLines.push(
        `- 写回后复核（真实工作区）：攻击阻断 ${re.attackBlocked ?? 0}/${re.attackTotal ?? 0}，业务保持 ${re.businessPassed ?? 0}/${re.businessTotal ?? 0} → ${
          re.pass ? "通过" : "未通过"
        }`
      );
    }
  }
  if (r.patch) {
    const llmBits = r.patch.llm
      ? `；LLM 编码代理采纳 ${r.patch.llm.appliedOps} 处、拒绝 ${r.patch.llm.rejected?.length ?? 0} 条`
      : "";
    summaryLines.push(
      `- 补丁：\`${r.patch.hash?.slice(0, 12)}…\`（${r.patch.files?.length ?? 0} 个文件，${esc(PATCH_STATUS_LABELS[r.patch.status] ?? r.patch.status)}；策略 ${esc(r.patch.strategy ?? "—")}${llmBits}）`
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
  if (!bb && r.summary.resourceContract?.idField) {
    const rc = r.summary.resourceContract;
    const sourceLabel =
      rc.source === "llm-hinted-verified"
        ? "模型假设 + 逐条真实验证"
        : rc.source === "cached-confirmed"
          ? "缓存复用 + 真实复核"
          : "双身份真实验证";
    const bits = [
      `列表 \`${esc(rc.listPath ?? "—")}\`${rc.listQuery ? `（${esc(JSON.stringify(rc.listQuery))}）` : ""}`,
      `主键 \`${esc(rc.idField)}\``,
      rc.ownerField ? `归属 \`${esc(rc.ownerField)}\`` : null,
      rc.entityPath ? `实体 \`${esc(rc.entityPath)}\`` : null,
      rc.needsPagination ? "需分页参数" : null,
      `共 ${rc.requestsUsed ?? 0} 个请求实测`,
    ].filter(Boolean);
    summaryLines.push(`- 资源契约自动发现：${bits.join(" · ")}（${sourceLabel}）`);
  }
  const idr = r.summary.identities;
  if (!bb && idr) {
    const on = idr.loggedIn ?? [];
    const sv = idr.sessionVerification;
    const who = on.map((i) => `${esc(i.name)}→\`${esc(i.endpoint ?? "?")}\``).join("、");
    const verify =
      sv?.status === "verified"
        ? `已回读验证（探针 \`${esc(sv.probePath ?? "?")}\`：${(sv.identities ?? [])
            .slice(0, 4)
            .map((c) => `${esc(c.identity)} 匿名 ${c.anonStatus}→会话 ${c.sessStatus}`)
            .join("、")}）`
        : sv?.status === "skipped"
          ? `未回读（${esc(sv.reason ?? "无可用探针")}）`
          : "未回读（登录未成功或异常中止）";
    summaryLines.push(
      `- 身份会话：${on.length}/${(idr.configured ?? []).length} 建立${who ? `（${who}）` : ""}；会话真实性：${verify}`
    );
    const ib = idr.bootstrap;
    const firstPhase = ib?.byPhase?.[0];
    if (ib?.attempted) {
      const detail = (firstPhase?.accounts ?? [])
        .map((a) => `${esc(a.name)}：${esc(a.verdict ?? "—")}${a.status ? ` (HTTP ${a.status})` : ""}`)
        .join("、");
      const generated = (firstPhase?.accounts ?? []).filter((a) => a.passwordSource === "engine-generated").length;
      // #183：数据是契约声明写的，还是本轮引擎实跑复读选定的写接口造的——读者要能分清
      const obsSeeds = (firstPhase?.seeds ?? []).filter((s) => s.source === "observed");
      const obsWritten = obsSeeds.filter((s) => s.verdict === "written").length;
      const obsEndpoint = [...new Set(obsSeeds.filter((s) => s.verdict === "written").map((s) => s.endpoint))].join("、");
      const obsVia = [...new Set(obsSeeds.filter((s) => s.verdict === "written").map((s) => s.readBackVia).filter(Boolean))].join("、");
      summaryLines.push(
        `- 身份自举：本轮由目标注册接口 \`${esc(firstPhase?.endpoint ?? "?")}\`（${esc(firstPhase?.endpointSource ?? "—")}）建号 ${ib.registered} 个${
          generated ? `，其中 ${generated} 个口令由引擎随机生成、只进 Host 保险库（不落配置/报告/证据库）` : ""
        }；写入测试数据 ${ib.seeded} 条${
          obsWritten > 0
            ? `，其中 ${obsWritten} 条经观测选定（\`${esc(obsEndpoint)}\`${obsVia ? ` → 复读 \`${esc(obsVia)}\`` : ""}：写入后本人列表回读到标记、其他身份未见）`
            : ""
        }。判定明细：${detail}`
      );
      const so = firstPhase?.seedObservation;
      if (so && (so.attempted === false || obsSeeds.length > 0)) {
        const bits =
          so.attempted === false
            ? [`未参与（${esc(so.blocked ?? "—")}）`]
            : obsSeeds
                .filter((s) => s.verdict !== "written")
                .map((s) => `${esc(s.identity)}→\`${esc(s.endpoint)}\`：${esc(s.verdict ?? "—")}`);
        summaryLines.push(
          `- 种子数据观测兜底：${bits.join("；")}${
            so.attempted === false
              ? ""
              : "；未通过复读归因的写入不会被当成「名下对象」用，相关越权用例将按「测不了」收场"
          }`
        );
      }
    } else if (firstPhase?.unavailableReason === "static-ambiguous") {
      // 登录本轮靠声明口令成功了，但静态看到了多个建号候选：读者需要知道引擎没有猜、
      // 因此「换空库重跑」时这条路并不会自动生效。
      summaryLines.push(
        `- 身份自举：未参与（静态识别到 ${(firstPhase.candidates ?? []).length} 个建号候选，引擎不猜：${esc((firstPhase.candidates ?? []).join("、"))}）；需要自举时请在 guardbuild.json 声明 register.path`
      );
    }
    // #182 注册兜底代理：问过模型没有、采纳了哪个端点、没采纳的原因——都只写引擎侧事实
    const ra = firstPhase?.registerAgent;
    if (ra?.used) {
      const bits = [
        ra.source === "cache" ? "复用已实测验证的缓存提案" : `问过模型 ${ra.rounds ?? 0} 轮`,
        `候选菜单 ${ra.menuSize ?? 0} 个 POST 路由`,
        ra.adoptedEndpoint ? `采纳 \`${esc(ra.adoptedEndpoint)}\`` : "未采纳任何端点",
        ra.fallback ? `原因 ${esc(ra.fallback)}` : null,
        (ra.tried ?? []).length ? `实跑判定 ${ra.tried.map((t) => `${esc(t.endpoint)}→${esc(t.verdict ?? "—")}`).join("、")}` : null,
        (ra.ignoredKeys ?? []).length ? `丢弃越界键 ${esc(ra.ignoredKeys.join("、"))}` : null,
        (ra.droppedFields ?? []).length ? `丢弃非法字段映射 ${ra.droppedFields.length} 处` : null,
      ].filter(Boolean);
      summaryLines.push(`- 注册兜底代理：${bits.join("；")}（模型只选端点与字段名，采纳由引擎实跑注册+登录决定）`);
    }
  }
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
          (f) => `| ${esc(f.method)} ${esc(f.path)} | ${esc(humanPath(f.file))}:${esc(f.startLine)} | ${esc(f.reason)} |`
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
    const planMd = renderAttackPlanSection(bb.attackPlan);
    if (planMd) parts.push(planMd);
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
        `- 状态：${esc(PATCH_STATUS_LABELS[r.patch.status] ?? r.patch.status)}（${r.patch.lineCount ?? 0} 行改动）`,
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
    const attributionMd = renderAttributionSection(acc.attribution);
    if (attributionMd) parts.push(attributionMd);
    parts.push(evidenceTable(post));
  } else if (post.length) {
    parts.push(`## 修复后证据（post，${post.length} 条）\n`);
    parts.push(evidenceTable(post));
  }

  const recheck = acc?.writebackRecheck ?? null;
  const postWriteback = r.evidence.postWriteback ?? [];
  if (recheck) {
    parts.push(`## 写回后复核（真实工作区）\n`);
    parts.push(
      `攻击阻断 ${recheck.attackBlocked ?? 0}/${recheck.attackTotal ?? 0}，业务保持 ${recheck.businessPassed ?? 0}/${recheck.businessTotal ?? 0} → **${
        recheck.pass ? "通过" : "未通过"
      }**${recheck.at ? `（复核时间 ${fmtTime(recheck.at)}）` : ""}\n`
    );
    parts.push(
      "隔离 worktree 的验收只代表补丁本身；这一节把同一组攻击与业务用例重新打到**实际工作区**启动的实例上，两者一致才算修复真正落地。\n"
    );
    const recheckAttribution = renderAttributionSection(recheck.attribution);
    if (recheckAttribution) parts.push(recheckAttribution);
    parts.push(`### 写回后证据（post_writeback，${postWriteback.length} 条）\n`);
    parts.push(evidenceTable(postWriteback));
  } else if (postWriteback.length) {
    parts.push(`## 写回后证据（post_writeback，${postWriteback.length} 条）\n`);
    parts.push(evidenceTable(postWriteback));
  }

  const wbStatus = r.patch?.status;
  const writtenBackStatuses = new Set(["written_back", "writeback_recheck_failed", "writeback_recheck_incomplete", "rolled_back"]);
  if (writtenBackStatuses.has(wbStatus)) {
    const backup = r.rollback?.backupId ?? null;
    const backupFiles = r.rollback?.files ?? [];
    parts.push(`## 写回与回滚\n`);
    parts.push(
      [
        `- 写回状态：${PATCH_STATUS_LABELS[wbStatus] ?? wbStatus}`,
        ...(backup ? [`- 回滚备份：\`${esc(backup)}\`${backupFiles.length ? `（${backupFiles.map((f) => `\`${esc(f)}\``).join("、")}）` : ""}`] : []),
        ...(wbStatus === "rolled_back" && r.rollback?.restored?.length
          ? [`- 已恢复文件：${r.rollback.restored.map((f) => `\`${esc(f)}\``).join("、")}`]
          : []),
        ...(wbStatus === "rolled_back" && r.rollback?.conflicts?.length
          ? [`- 回滚冲突（写回后文件又被改过，未覆盖）：${r.rollback.conflicts.map((f) => `\`${esc(f)}\``).join("、")}`]
          : []),
        wbStatus === "rolled_back"
          ? "- 回滚已把工作区文件恢复到写回前状态（内容有变动的文件不会被覆盖，会作为冲突上报）；漏洞仍然存在，需重新修复。"
          : "- 写回只改工作区文件、不自动提交：请用 `git diff` 审查后按发布流程提交；如需撤销，在会话中点「回滚写回」。",
        "",
      ].join("\n")
    );
  }

  parts.push(`## 结论与建议\n\n${suggestions(r)}\n`);
  return parts.join("\n");
}

/**
 * 报告与会话事件是会被存档、分享、入库的产物：原始日志数组和启动契约的环境变量值不进去，
 * 只保留脱敏后的日志尾部（diagnosis.excerpt）与变量名列表。
 */
export function sanitizeErrorDetails(details) {
  if (!details || typeof details !== "object") return null;
  const out = { ...details };
  for (const k of ["output", "lines", "stdout", "stderr"]) delete out[k];
  for (const k of ["start", "docker", "candidate"]) {
    const v = out[k];
    if (v && typeof v === "object" && v.env && typeof v.env === "object") {
      // 幂等：事件层可能已经把它压成变量名数组，二次序列化不能再退化成下标
      const names = (Array.isArray(v.env) ? v.env : Object.keys(v.env)).map((e) =>
        String(e).split("=")[0]
      );
      out[k] = { ...v, env: names };
    }
  }
  return out;
}

/** 启动失败原文：报告要给出崩在哪一行，而不是只留一个错误码 */
function startDiagnosisLines(r) {
  const d = r.error?.details?.diagnosis;
  if (!d) return [];
  const tail = (Array.isArray(d.excerpt) ? d.excerpt : String(d.excerpt ?? "").split("\n"))
    .map((l) => String(l ?? ""))
    .filter((l) => l.trim() !== "");
  return [
    `- 启动诊断（${d.code ?? "unknown"}${Number.isInteger(d.exitCode) ? `，退出码 ${d.exitCode}` : ""}）${
      d.matched ? `：命中原文「\`${esc(String(d.matched).slice(0, 200))}\`」` : "：未命中已知诊断规则"
    }`,
    ...(tail.length
      ? ["- 启动输出尾部（已脱敏：凭据键值与长随机串打码）：", "", "```", ...tail, "```", ""]
      : ["- 目标进程未输出任何可记录的日志。"]),
  ];
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
      headline: headline(outcome, patchStatus, supabase, blackbox, error?.code ?? null),
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
            frontendNextManifest: blackbox.frontendNextManifest ?? 0,
            seoRouteCount: blackbox.seoRouteCount ?? 0,
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
            attackPlan: blackbox.attackPlan ?? null,
          }
        : null,
      start: start
        ? { cmd: start.cmd, args: start.args, cwd: start.cwd ?? null, readyPattern: start.readyPattern }
        : null,
      startSource: ctx.targetConfig?.startSource ?? null,
      resourceContract: ctx._resourceContract
        ? {
            source: ctx._resourceContract.source ?? null,
            listPath: ctx._resourceContract.listPath ?? null,
            listQuery: ctx._resourceContract.listQuery ?? null,
            idField: ctx._resourceContract.idField ?? null,
            ownerField: ctx._resourceContract.ownerField ?? null,
            entityPath: ctx._resourceContract.entityPath ?? null,
            needsPagination: !!ctx._resourceContract.needsPagination,
            requestsUsed: ctx._resourceContract.requestsUsed ?? 0,
            applied: ctx._resourceContract.applied ?? [],
          }
        : null,
      identities: ctx._identityReport
        ? {
            configured: ctx._identityReport.configured ?? [],
            loggedIn: (ctx._identityReport.loggedIn ?? []).map((i) => ({
              name: i.name,
              role: i.role ?? null,
              endpoint: i.endpoint ?? null,
              credentialKind: i.credentialKind ?? null,
            })),
            sessionVerification: ctx._identityReport.sessionVerification
              ? {
                  status: ctx._identityReport.sessionVerification.status ?? null,
                  probePath: ctx._identityReport.sessionVerification.probePath ?? null,
                  loginEndpoint: ctx._identityReport.sessionVerification.loginEndpoint ?? null,
                  reason: ctx._identityReport.sessionVerification.reason ?? null,
                  identities: (ctx._identityReport.sessionVerification.identities ?? []).slice(0, 8),
                }
              : null,
            // 身份自举（#179）：账号是声明的还是引擎在沙箱里现注册的、造了几条数据。
            // 口令本身一律不进报告——只留「引擎生成」这个来源标记。
            bootstrap: (() => {
              const byPhase = ctx._identityBootstrap?.byPhase ?? {};
              const clean = (p) => ({
                phase: p.phase,
                endpoint: p.endpoint,
                endpointSource: p.endpointSource,
                unavailableReason: p.unavailableReason,
                candidates: (p.candidates ?? []).slice(0, 8),
                accounts: (p.accounts ?? []).map((a) => ({
                  name: a.name,
                  trigger: a.trigger ?? null,
                  verdict: a.verdict ?? a.reason ?? null,
                  status: a.status ?? null,
                  endpoint: a.endpoint ?? p.endpoint ?? null,
                  endpointSource: a.endpointSource ?? p.endpointSource ?? null,
                  passwordSource: a.generated ? "engine-generated" : "declared",
                  unresolvedFields: a.fields ?? null,
                })),
                seeds: (p.seeds ?? []).map((s) => ({
                  identity: s.identity,
                  endpoint: s.path,
                  verdict: s.verdict,
                  status: s.status ?? null,
                  // contract＝契约 register.seed 声明的；observed＝#183 本轮实跑复读选定的
                  source: s.source ?? "contract",
                  // 观测兜底经哪条读取通道复读选定（通道本身也是实测选出来的，不是写死的）
                  readBackVia: s.readBackVia ?? null,
                  fields: (s.fields ?? []).slice(0, 6),
                  ownerSeen: s.ownerSeen ?? null,
                  othersSeen: (s.othersSeen ?? []).slice(0, 6),
                })),
                // #183 观测兜底这一层自身的经过：有没有参与、被什么挡住、试了哪些写接口
                seedObservation: p.seedObservation
                  ? {
                      attempted: p.seedObservation.attempted === true,
                      blocked: p.seedObservation.blocked ?? null,
                      listEndpoint: p.seedObservation.listEndpoint ?? null,
                      channels: (p.seedObservation.channels ?? []).slice(0, 4),
                      candidates: (p.seedObservation.candidates ?? []).slice(0, 6),
                      identities: (p.seedObservation.identities ?? []).slice(0, 8),
                    }
                  : null,
                secretProtection: p.secretProtection ?? {},
                // #182 注册兜底代理：只留引擎侧事实（端点、实跑判定、被丢掉的键名）。
                // 模型原文（note）与目标报错文本一律不进报告；口令从来不在这些字段里。
                registerAgent: p.agent
                  ? {
                      enabled: p.agent.enabled === true,
                      used: p.agent.asked === true || p.agent.cacheHit === true,
                      source: p.agent.source ?? null,
                      rounds: p.agent.rounds ?? 0,
                      fallback: p.agent.fallback ?? null,
                      menuSize: p.agent.menuSize ?? 0,
                      tried: (p.agent.tried ?? []).slice(0, 8),
                      adoptedEndpoint: p.agent.adoptedEndpoint ?? null,
                      ignoredKeys: (p.agent.ignored ?? []).slice(0, 12),
                      droppedFields: (p.agent.droppedFields ?? []).slice(0, 12),
                      cacheHit: p.agent.cacheHit === true,
                      cacheVerified: p.agent.cacheVerified === true,
                      model: p.agent.model ?? null,
                    }
                  : null,
              });
              const phases = Object.values(byPhase).map(clean);
              return {
                attempted: phases.some((p) => (p.accounts?.length ?? 0) > 0),
                registered: phases.reduce(
                  (n, p) => n + (p.accounts ?? []).filter((a) => a.verdict === "created").length,
                  0
                ),
                seeded: phases.reduce((n, p) => n + (p.seeds ?? []).filter((s) => s.verdict === "written").length, 0),
                byPhase: phases,
              };
            })(),
          }
        : null,
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
            matched: a.matched ?? null,
            excerpt: a.excerpt ?? null,
            durationMs: a.durationMs ?? null,
          })),
          evidenceFiles: view.llm.evidenceFiles ?? [],
          evidenceChars: view.llm.evidenceChars ?? 0,
          usage: view.llm.usage ?? null,
          notes: view.llm.notes ?? [],
          warnings: view.llm.warnings ?? [],
          // 路由线索的运行期实测结论（存在性 / 鉴权 / 归属过滤，全部来自真实请求）
          routeVerification: view.llm.routeVerification ?? null,
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
    rollback: view.rollback ?? null,
    error: error ? { ...error, details: sanitizeErrorDetails(error.details) } : null,
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
