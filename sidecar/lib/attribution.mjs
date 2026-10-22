/**
 * 补丁归因校验。
 *
 * 双重验收只看「总体变好」会放过两种假通过：
 *  1. 补丁修的是 A 端点，B 端点的用例被顺带挡掉（或因身份/数据变化判不出），总体攻击阻断数上升，
 *     于是报告写「已修复」，B 的漏洞代码一行没动；
 *  2. 补丁声明修了某候选，但该候选修复前就没复现（无从证明翻转发生过）。
 *
 * 因此验收要落到「每个候选自身」：补丁点名的候选，必须满足
 *   修复前它自己的攻击用例确实打穿 → 修复后同一批用例全部阻断，
 * 判定为 inconclusive（拿不到可比证据）或用例缺席都不算通过。
 * 另附源码定位信息（补丁 hunk 是否落在该候选的文件 / 距漏洞行多远），只作呈现、不作否决——
 * 真实修复常落在同文件的取数辅助函数里，硬否决会误伤。
 */
import { candKey } from "./planner.mjs";
import { CASE_CATEGORY, VERDICT } from "../../shared/protocol.mjs";

/** unified diff → 每文件的新侧行区间（`@@ -a,b +c,d @@`） */
export function parseDiffHunks(diff) {
  const out = new Map();
  let file = null;
  for (const line of String(diff ?? "").split(/\r?\n/)) {
    if (line.startsWith("+++ ")) {
      const raw = line.slice(4).trim();
      // git 用 b/ 前缀标新侧；删除的文件是 /dev/null，没有新侧行区间
      file = !raw || raw === "/dev/null" ? null : raw.replace(/^b[\\/]/, "").replace(/^\/+/, "");
      if (file && !out.has(file)) out.set(file, []);
      continue;
    }
    if (line.startsWith("--- ") || line.startsWith("diff ") || line.startsWith("index ")) continue;
    if (!file || !line.startsWith("@@")) continue;
    const m = line.match(/@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/);
    if (!m) continue;
    const start = Number(m[1]);
    const count = Number.isFinite(Number(m[2])) ? Number(m[2]) : 1;
    out.get(file).push({ start, end: start + Math.max(0, count - 1) });
  }
  return out;
}

/** 候选的源码路径（常为 `\\?\D:\...\src\app.js` 这类绝对路径）与 diff 里的仓库相对路径对齐 */
function normPath(p) {
  return String(p ?? "")
    .replace(/^\\\\\?\\/, "")
    .replace(/\\/g, "/")
    .replace(/^\/+/, "")
    .toLowerCase();
}

/**
 * 该候选源码位置与补丁 hunk 的关系：同文件（并给出距最近 hunk 的行距）/ 异文件 / 无源码位置。
 * diff 用仓库相对路径、候选用绝对路径，按尾段匹配对齐（Windows 扩展路径前缀也在此消化掉）。
 */
export function patchLocality(cand, hunksByFile) {
  const raw = cand?.file;
  if (!raw) return { inCandidateFile: false, hasSource: false, distance: null, hunks: 0, relPath: null };
  const target = normPath(raw);
  let ranges = [];
  let relPath = null;
  for (const [p, r] of hunksByFile) {
    const rel = normPath(p);
    if (rel === target || target.endsWith("/" + rel)) {
      ranges = ranges.concat(r);
      relPath = relPath ?? p;
    }
  }
  if (ranges.length === 0) {
    return { inCandidateFile: false, hasSource: true, distance: null, hunks: 0, relPath: null };
  }
  const line = Number.isFinite(cand.startLine) ? cand.startLine : null;
  const distance =
    line == null
      ? null
      : Math.min(
          ...ranges.map((r) => (line < r.start ? r.start - line : line > r.end ? line - r.end : 0))
        );
  return { inCandidateFile: true, hasSource: true, distance, hunks: ranges.length, relPath };
}

/**
 * 构建逐候选归因表。
 * @param ctx          会话上下文（读 _preCaseMeta / _preCaseVerdicts / _claimedCandidates / plan / view.patch.diff）
 * @param postEvidence 修复后阶段的证据记录（含 caseId）
 */
export function buildAttribution(ctx, postEvidence) {
  const claimed = ctx._claimedCandidates instanceof Set ? ctx._claimedCandidates : new Set();
  const meta = ctx._preCaseMeta instanceof Map ? ctx._preCaseMeta : new Map();
  const preVerdicts = ctx._preCaseVerdicts instanceof Map ? ctx._preCaseVerdicts : new Map();
  const hunksByFile = parseDiffHunks(ctx.view?.patch?.diff ?? "");

  const attackByCand = new Map();
  for (const [caseId, m] of meta) {
    if (m.category !== CASE_CATEGORY.ATTACK || !m.candidateKey) continue;
    const arr = attackByCand.get(m.candidateKey) ?? [];
    arr.push({ caseId, pre: preVerdicts.get(caseId) ?? null, name: m.name });
    attackByCand.set(m.candidateKey, arr);
  }

  const postByCase = new Map();
  for (const e of postEvidence ?? []) postByCase.set(e.caseId, e.verdict);

  const candByKey = new Map();
  for (const c of ctx.plan?.candidates ?? []) candByKey.set(candKey(c), c);

  const rows = [];
  for (const [key, cases] of attackByCand) {
    const repro = cases.filter((c) => c.pre === VERDICT.VULNERABLE);
    if (repro.length === 0) {
      if (claimed.has(key)) {
        rows.push({
          candidateKey: key,
          candidate: key,
          claimed: true,
          status: "not_reproduced",
          reason: "修复前未复现该入口的越权，无法证明补丁带来翻转",
          preReproCases: 0,
          postCases: 0,
          ...localityRow(candByKey.get(key), hunksByFile),
        });
      }
      continue;
    }
    const posts = repro.map((c) => postByCase.get(c.caseId) ?? null);
    const blocked = posts.filter((v) => v === VERDICT.BLOCKED).length;
    const missing = posts.filter((v) => v == null).length;
    const inconclusive = posts.filter((v) => v === VERDICT.INCONCLUSIVE).length;
    const leaking = posts.filter((v) => v === VERDICT.VULNERABLE || v === VERDICT.REGRESSED).length;
    const isClaimed = claimed.has(key);
    let status;
    let reason = null;
    if (leaking > 0) {
      status = "still_vulnerable";
      reason = `修复后仍有 ${leaking}/${repro.length} 条越权用例复现`;
    } else if (missing > 0 || inconclusive > 0) {
      status = "unverified";
      reason = missing > 0 && inconclusive > 0
        ? `${missing} 条未进入修复后验收、${inconclusive} 条判定不可比`
        : missing > 0
          ? `${missing}/${repro.length} 条修复前已复现的用例未进入修复后验收`
          : `${inconclusive}/${repro.length} 条修复后判定为 inconclusive（响应不足以证明阻断）`;
    } else if (blocked === repro.length) {
      status = "blocked";
    } else {
      status = "unverified";
      reason = "修复后结论不一致，无法归因";
    }
    rows.push({
      candidateKey: key,
      candidate: key,
      claimed: isClaimed,
      status,
      reason,
      preReproCases: repro.length,
      postCases: posts.filter((v) => v != null).length,
      ...localityRow(candByKey.get(key), hunksByFile),
    });
  }

  const claimedRows = rows.filter((r) => r.claimed);
  const failing = claimedRows.filter((r) => r.status === "still_vulnerable" || r.status === "unverified");
  // 补丁点名了候选，但该候选在修复前没有任何复现用例（既没进归因表也没被判过）
  for (const key of claimed) {
    if (rows.some((r) => r.candidateKey === key)) continue;
    failing.push({
      candidateKey: key,
      candidate: key,
      claimed: true,
      status: "unverified",
      reason: "补丁声明修复该入口，但修复前阶段没有它的攻击用例，验收无从归属",
      preReproCases: 0,
      postCases: 0,
      ...localityRow(candByKey.get(key), hunksByFile),
    });
  }

  return {
    rows: rows.sort((a, b) => Number(b.claimed) - Number(a.claimed) || a.candidate.localeCompare(b.candidate)),
    claimedCount: claimed.size,
    blockedCount: rows.filter((r) => r.claimed && r.status === "blocked").length,
    unverifiedCount: failing.filter((r) => r.status === "unverified").length,
    stillVulnerableCount: failing.filter((r) => r.status === "still_vulnerable").length,
    pass: failing.length === 0,
    failing,
  };
}

function localityRow(cand, hunksByFile) {
  if (!cand) return { file: null, line: null, locality: "unknown" };
  const loc = patchLocality(cand, hunksByFile);
  return {
    // 展示仓库相对路径（候选自带的是绝对路径，含用户目录，不进报告）
    file: loc.relPath ?? (cand.file ? String(cand.file).replace(/\\/g, "/").split("/").slice(-2).join("/") : null),
    line: Number.isFinite(cand.startLine) ? cand.startLine : null,
    locality: !loc.hasSource ? "no_source" : loc.inCandidateFile ? "same_file" : "other_file",
    hunkDistance: loc.distance,
    hunksInFile: loc.hunks,
  };
}
