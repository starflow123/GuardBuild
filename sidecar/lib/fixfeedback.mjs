/**
 * 修复循环反馈（把失败轮次的现场回喂给编码代理）。
 *
 * 日志来自 Host 的 proc.logs：每条行在进入环形缓冲前已由 Redactor 脱敏
 * （src-tauri/src/core/host.rs 的 resolve_log，保险库秘密值整值替换），
 * 因此这里只搬运文本，不再拼接任何原文秘密。
 */
import { RPC_TO_HOST, VERDICT } from "../../shared/protocol.mjs";
import { matchDiagnostics } from "./autostart.mjs";

const LOG_TAIL_LINES = 20;
const LOG_LINE_CHARS = 240;
const LOG_TOTAL_CHARS = 4_000;
const DIFF_CHARS = 3_000;

function clip(text, n) {
  const s = String(text ?? "");
  return s.length > n ? `${s.slice(0, n)}\n…(截断，共 ${s.length} 字符)…` : s;
}

/** 从尾部往前取，保证总长不超预算（越靠后的日志越接近失败现场） */
function takeTailWithinBudget(lines, budget) {
  const out = [];
  let used = 0;
  for (let i = lines.length - 1; i >= 0; i--) {
    used += lines[i].length + 1;
    if (used > budget) break;
    out.unshift(lines[i]);
  }
  return out;
}

/** 取隔离实例日志尾部（保留 stdout/stderr 标记与原始行序）；取不到就按无日志处理 */
async function readTargetLogTail(ctx) {
  const pid = ctx.procs?.worktree?.pid ?? null;
  if (!pid || !ctx.tokens?.spawn) return { lines: [], exited: null };
  let res;
  try {
    res = await ctx.rpc.request(RPC_TO_HOST.PROC_LOGS, { token: ctx.tokens.spawn, pid, tail: 200 });
  } catch {
    // 日志不可得不能阻断修复循环：降级为「无日志」
    return { lines: [], exited: null };
  }
  const raw = (Array.isArray(res?.lines) ? res.lines : []).map((l) => ({
    stream: String(l?.stream ?? "stdout"),
    line: clip(l?.line, LOG_LINE_CHARS),
  }));
  return {
    lines: raw.slice(-LOG_TAIL_LINES).map((l) => `${l.stream}: ${l.line}`),
    exited: res?.exited ? { exitCode: res?.exitCode ?? null } : null,
  };
}

/**
 * @returns {Promise<object>} 作为 previous_attempt 注入补丁提示词的反馈
 */
export async function buildFixFeedback(ctx, { post, verdict, round, previousDiff = null }) {
  const failed = (post?.evidence ?? [])
    .filter((e) => e.verdict === VERDICT.REGRESSED || e.verdict === VERDICT.INCONCLUSIVE)
    .slice(0, 8)
    .map((e) => ({
      case: e.caseName ?? e.caseId ?? null,
      category: e.caseCategory ?? null,
      verdict: e.verdict,
      actual: e.actual ?? null,
      status: e.response?.status ?? null,
    }));

  const log = await readTargetLogTail(ctx);
  const tail = takeTailWithinBudget(log.lines, LOG_TOTAL_CHARS);
  const diagnostics = matchDiagnostics(tail);
  const diff = previousDiff ? clip(previousDiff, DIFF_CHARS) : null;

  // 归因不成立的候选：汇总计数可能照样好看（修了 A 顺带挡了别的），但被点名的入口自己没翻转
  const unattributed = (verdict.attribution?.failing ?? []).map((r) => ({
    candidate: r.candidate,
    status: r.status,
    reason: r.reason,
  }));

  const evidence = [];
  if (diff) evidence.push("previous_diff 是上一轮实际落地的改动");
  if (tail.length) evidence.push("target_log_tail 是修复后隔离实例的真实输出");
  if (diagnostics.length) evidence.push(`diagnostics 给出日志命中的诊断码（${diagnostics.map((d) => d.code).join("、")}）`);
  if (log.exited) evidence.push(`隔离实例已退出（退出码 ${log.exited.exitCode ?? "?"}），说明上一轮补丁让应用无法运行`);
  if (unattributed.length) {
    evidence.push(
      `unattributed_candidates 列出补丁声明要修、但没能自己完成「修复前打穿 → 修复后阻断」翻转的入口（${unattributed.length} 个）`
    );
  }

  return {
    round,
    reason: "上一轮补丁未通过双重验收",
    attack_regressed: verdict.attackRegressed,
    business_regressed: verdict.businessRegressed,
    failed_cases: failed,
    unattributed_candidates: unattributed,
    target_log_tail: tail,
    target_exit: log.exited,
    diagnostics,
    previous_diff: diff,
    instruction:
      "请重新生成最小补丁：所有攻击用例必须被拒绝（401/403/空结果），业务基线必须保持原有 2xx 与响应契约。" +
      (evidence.length
        ? `修订时请依据 previous_attempt 里的 ${evidence.join("；")}，给出与上一轮不同且更完整的修法；`
        : "不要重复上一轮的改动方式；") +
      (unattributed.length
        ? "unattributed_candidates 中列出的入口必须自己完成翻转（改了别的东西让它们顺带不通不算修好）；"
        : "") +
      "不要改动其它逻辑，不要新增依赖。",
  };
}

/** 反馈摘要：进 view/report 与 e2e 断言用，不含日志原文 */
export function feedbackDigest(fb) {
  if (!fb) return null;
  return {
    round: fb.round ?? null,
    failedCases: (fb.failed_cases ?? []).length,
    unattributed: (fb.unattributed_candidates ?? []).length,
    logLines: (fb.target_log_tail ?? []).length,
    targetExited: !!fb.target_exit,
    targetExitCode: fb.target_exit?.exitCode ?? null,
    diagnostics: (fb.diagnostics ?? []).map((d) => d.code),
    diffChars: fb.previous_diff ? fb.previous_diff.length : 0,
  };
}
