#!/usr/bin/env node
/**
 * 判卷层（方案第 6、7 项）：拿考卷验配方，不是拿配方验项目。
 *
 * 一张考卷 = 一份**已注册配方** + 漏洞版靶子 + 加固版（由漏洞版插一处补丁派生）+ 干净对照。
 * 四道闸由 sidecar/lib/grader.mjs 写死，本脚本只做三件事：铺工作区、实跑 gate、把观察喂给判卷器。
 *
 * 与白盒/黑盒基准的区别要说清楚：那两个量的是「引擎在标注靶场上的召回与误报」，
 * 这个量的是「某一张配方的判据本身站不站得住」。所以加固版必须是派生的——
 * 手写一份「加固版」可以让它碰巧什么都不报，派生只能靠那一处补丁，改不动就红。
 *
 * 零模型调用：与 benchmark.mjs 同一套环境变量（清空密钥与开关），结论必须可复现。
 * 闭环两层照旧进仓库：账本 benchmarks/failure-ledger.jsonl、绿名单 benchmarks/green-baseline.json，
 * 本层的套件名记作 `grader`（绿名单键形如 grader/<考卷 id>#<用例 id>）。
 *
 * 考卷分两堆（第 8 项）：`split: "dev"` 的失败照常进失败账本——账本是后续调优（第 11 项）唯一读得到的
 * 输入；`split: "frozen"` 的冻结集只判分、不进账本，调优永远看不到它长什么样。这是「过拟合考卷」
 * 那条风险唯一的防线，所以 split 是必填字段，没有默认值。
 *
 * 用法:
 *   node scripts/benchmark-grader.mjs
 *   node scripts/benchmark-grader.mjs --only=idor-read--legacy-shop
 *   node scripts/benchmark-grader.mjs --repeat=3      # 覆盖考卷声明的次数（仍受 2..4 约束）
 *   node scripts/benchmark-grader.mjs --keep / --rebaseline
 *   node scripts/benchmark-grader.mjs --draft=<探索产物 json>[,...]
 *     判草稿（#202）：一张未注册的探索草稿怎么拿到考卷成绩。这条路上三条红线一条不松——
 *     只跑**开发集**（冻结集是期末考，不被没注册资格的草稿预先读）、判据仍是 probe.mjs 里那段写死代码
 *     （草稿只顶替「执行表」这一层）、成绩只写在草稿同目录的 `grades/` 下且不进账本与绿名单。
 *     注册仍是人工动作：`scripts/register-recipe.mjs` 读这条成绩，判卷没过就拒绝落 `sidecar/recipes/`。
 */
import { spawn, spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { variantBaseCaseId } from "../sidecar/lib/attackvariants.mjs";
import { deriveHardened, EXAM_DIR, feedsTuning, loadExams, resolveExamFixture } from "../sidecar/lib/exam.mjs";
import {
  buildCaseIdMap,
  checkDraftGradeAnchors,
  DRAFT_GRADE_VERSION,
  familySlotForDraft,
  normalizeCaseId,
  recipeSha256,
  writeGradeRecord,
} from "../sidecar/lib/draftgrade.mjs";
import { appendLedger, classifyRun, greenKeysOf, redactSecrets } from "../sidecar/lib/failureledger.mjs";
import { GATES, GRADE_VERSION, gradeExam, notGradedResult, VARIANTS } from "../sidecar/lib/grader.mjs";
import { listRecipeIds, loadRecipe, RECIPES_OVERLAY_ENV, resetRecipeOverlayHits } from "../sidecar/lib/recipes.mjs";
import { gateAgainstBaseline } from "../sidecar/lib/regression.mjs";
import { consoleLoopLines, loopSection } from "./lib/loopsummary.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const benchRoot = path.join(repoRoot, ".grader");
const SUITE = "grader";
const ledgerPath = path.join(repoRoot, "benchmarks", "failure-ledger.jsonl");
const baselinePath = path.join(repoRoot, "benchmarks", "green-baseline.json");

function argValue(name) {
  const hit = process.argv.slice(2).find((a) => a.startsWith(`${name}=`));
  return hit ? hit.slice(name.length + 1) : null;
}

const only = new Set((argValue("--only") ?? "").split(",").map((s) => s.trim()).filter(Boolean));
const keep = process.argv.includes("--keep");
const rebaseline = process.argv.includes("--rebaseline");
const repeatOverride = argValue("--repeat") ? Number(argValue("--repeat")) : null;
/** --exams=<目录>：拿一批非仓库考卷做反证实验（判卷器会不会红）。这一模式不写账本、不动绿名单 */
const examsDir = argValue("--exams") ? path.resolve(argValue("--exams")) : null;
const lab = !!examsDir;
/** --draft=<探索产物 json>[,...]：判草稿模式（#202）。同样不写账本、不动绿名单——草稿还没注册资格，它的红不是「引擎回退」 */
const draftFiles = (argValue("--draft") ?? "").split(",").map((s) => s.trim()).filter(Boolean);
const draftMode = draftFiles.length > 0;

/** 考卷自己声明连跑次数，--repeat 覆盖；G4 至少要两次才算「结论一致」 */
const repeatOf = (exam) => Math.max(2, Math.min(4, repeatOverride ?? exam.repeat ?? 2));

function resolveHeadlessBin() {
  if (process.env.GUARDBUILD_HEADLESS_BIN) return process.env.GUARDBUILD_HEADLESS_BIN;
  const name = process.platform === "win32" ? "guardbuild-headless.exe" : "guardbuild-headless";
  const debug = path.join(repoRoot, "src-tauri", "target", "debug", name);
  return existsSync(debug) ? debug : path.join(repoRoot, "src-tauri", "target", "release", name);
}
const exe = resolveHeadlessBin();

function git(args, cwd) {
  const r = spawnSync("git", ["-c", "core.longpaths=true", ...args], { cwd, encoding: "utf8" });
  if (r.status !== 0) throw new Error(`git ${args.join(" ")} 失败: ${r.stderr || r.stdout}`);
  return r.stdout;
}

/** 每次实跑都用一份干净副本：G4 要比的是「同一张考卷重考一次结论相同」，不能共享上一轮的脏状态 */
function makeWorkspace(label, fixtureAbs, patch) {
  const ws = path.join(benchRoot, "workspaces", label);
  rmSync(ws, { recursive: true, force: true });
  mkdirSync(path.dirname(ws), { recursive: true });
  cpSync(fixtureAbs, ws, { recursive: true });
  git(["init", "-q"], ws);
  git(["config", "user.email", "grader@guardbuild.local"], ws);
  git(["config", "user.name", "GuardBuild Grader"], ws);
  git(["config", "core.autocrlf", "false"], ws);
  git(["add", "-A"], ws);
  git(["commit", "-qm", `${label} 考卷基线`], ws);
  if (!patch) return { ws, diff: null };
  const derived = deriveHardened({ workspace: ws, patches: patch });
  git(["add", "-A"], ws);
  git(["commit", "-qm", "派生加固版：考卷声明的那一处补丁"], ws);
  return { ws, diff: derived.diff };
}

/**
 * 每次实跑的超时：一张考卷 3 变体 × 2 次，慢靶子也够起来了。
 * 提到模块作用域是因为判草稿模式（`--draft`）与官方口径共用同一份跑卷循环，两处不该各写一个数。
 */
const RUN_TIMEOUT_MS = 240_000;

function runGate(label, workspace, timeoutMs, extraEnv = {}) {
  const dataDir = path.join(benchRoot, "data", label);
  const reportDir = path.join(benchRoot, "reports", label);
  rmSync(dataDir, { recursive: true, force: true });
  rmSync(reportDir, { recursive: true, force: true });
  mkdirSync(dataDir, { recursive: true });

  return new Promise((resolve) => {
    const startedAt = Date.now();
    const child = spawn(exe, ["--gate", "--project", workspace, "--report", reportDir], {
      cwd: repoRoot,
      env: {
        ...process.env,
        ...extraEnv,
        GUARDBUILD_DATA_DIR: dataDir,
        GUARDBUILD_SIDECAR: path.join(repoRoot, "sidecar", "main.mjs"),
        GUARDBUILD_LLM_SCOUT: "",
        GUARDBUILD_LLM_PATCH: "",
        GUARDBUILD_LLM_EXPLORATION: "",
        DEEPSEEK_API_KEY: "",
        DEEPSEEK_BASE_URL: "",
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (b) => { stdout += b.toString(); });
    child.stderr.on("data", (b) => { stderr += b.toString(); });
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill();
    }, timeoutMs);
    child.on("error", (e) => {
      clearTimeout(timer);
      resolve({ error: e.message, timedOut, durationMs: Date.now() - startedAt, stdout, stderr });
    });
    child.on("exit", (code) => {
      clearTimeout(timer);
      const gateLine = stdout.split("\n").filter((l) => l.startsWith("GB_GATE ")).pop();
      let gate = null;
      if (gateLine) {
        try { gate = JSON.parse(gateLine.slice("GB_GATE ".length)); } catch { /* 交给 report.json 判 */ }
      }
      let report = null;
      const reportPath = path.join(reportDir, "report.json");
      if (existsSync(reportPath)) {
        try { report = JSON.parse(readFileSync(reportPath, "utf8")); } catch { /* 缺证据就是缺证据 */ }
      }
      resolve({ code, gate, report, reportPath: existsSync(reportPath) ? reportPath : null, timedOut, durationMs: Date.now() - startedAt, stdout, stderr });
    });
  });
}

/** 把一次 gate 收成判卷器要的观察：用例判定折叠同源变体，原始判定表留着比一致性
 *  idMap：判草稿时把草稿的步骤号换算回考卷的规范编号（报告的证据表仍留原号，换算只发生在判卷这一侧） */
function observe(variant, attempt, run, idMap = null) {
  const pre = run.report?.evidence?.pre ?? [];
  const fold = (id) => variantBaseCaseId(normalizeCaseId(id, idMap));
  const vulnerableCaseIds = [...new Set(pre.filter((e) => e.verdict === "vulnerable").map((e) => fold(e.caseId)))];
  const caseVerdicts = {};
  for (const e of pre) if (e.caseId) caseVerdicts[fold(e.caseId)] = e.verdict;
  return {
    variant,
    attempt,
    exit: run.code ?? null,
    outcome: run.report?.verdict?.outcome ?? null,
    vulnerableCaseIds,
    caseVerdicts,
    reportPresent: !!run.report,
    timedOut: !!run.timedOut,
    error: run.error ?? null,
    businessRegressed: pre.filter((e) => e.category === "business" && e.verdict === "regressed").map((e) => e.caseId),
    durationMs: run.durationMs,
    report: run.report,
    reportPath: run.reportPath,
    gate: run.gate,
  };
}

function pct(n, d) {
  return d === 0 ? "—" : `${((n / d) * 100).toFixed(1)}%`;
}

/**
 * 逐题取证：同一族探针在漏洞版 / 加固版 / 干净对照上各拿到什么实际响应。
 * 四道闸的勾不是绿灯本身——报告要能看出「加固版确实挨了同一发，且被目标拒了」，
 * 而不是「加固版没报，因为它压根没打到」。
 */
function probeTable(runs, expect, idMap = null) {
  const rows = [];
  for (const variant of ["vulnerable", "hardened", "clean"]) {
    const run = runs.find((r) => r.variant === variant && r.reportPresent && !r.timedOut && !r.error);
    if (!run) {
      rows.push({ variant, outcome: null, exit: null, probes: "没有可用实跑（靶子没起来 / 超时 / 未产出 report），这一格不算证据" });
      continue;
    }
    const entries = (run.report?.evidence?.pre ?? []).filter((e) => expect.includes(variantBaseCaseId(normalizeCaseId(e.caseId, idMap))));
    rows.push({
      variant,
      outcome: run.outcome ?? null,
      exit: run.exit ?? null,
      probes:
        entries
          .map((e) => {
            const counted = variantBaseCaseId(normalizeCaseId(e.caseId, idMap));
            const shown = counted !== e.caseId ? `\`${e.caseId}\`→计入 \`${counted}\`` : `\`${e.caseId}\``;
            return `${shown} → ${e.verdict}（HTTP ${e.response?.status ?? "—"}${e.identity ? `，身份 ${e.identity}` : ""}${e.evidenceGrade ? `，证据分级 ${e.evidenceGrade}` : "，证据分级 —"}）`;
          })
          .join("<br>") || "本族探针没有一条落地",
    });
  }
  return rows;
}

/**
 * 闸不通过、但在「打不中 / 误报」两类里没有任何体现的失败，得自己进账本。
 *
 * classifyRun 只认 dynamic 里的 missed / falsePositives：G1 打不中、G2 加固仍报、G3 凭空造
 * 都能从那里落到账本上。剩下的三种红法——某个变体一次都没跑、加固版一条攻击都没发出去的「假零报」、
 * 两次跑结论不一致——在 dynamic 里是空的。不补这一步，一张红考卷会在账本上表现成「零条失败记录」，
 * 那就是判卷层自己的假绿灯。类别仍用冻结的那五类：闸没过＝这一轮没证明任何事，归「测不了」。
 */
const GATE_TAGS = { hardened_zero: "G2", clean_control: "G3", consistent: "G4" };

function gateLedgerRecords({ exam, grade, result }) {
  const records = [];
  for (const [gateName, tag] of Object.entries(GATE_TAGS)) {
    const g = grade?.gates?.[gateName] ?? {};
    if (g.ok === true) continue;
    const detail = g.detail ?? {};
    if (gateName === "hardened_zero" && (detail.reported?.length ?? 0) > 0) continue; // 已按「误报」入账
    if (gateName === "clean_control" && (detail.fabricated?.length ?? 0) > 0) continue; // 同上
    const why =
      (grade?.reasons ?? []).find((r) => r.startsWith(`${tag} `)) ??
      `${tag}（${gateName}）未通过，status=${g.status ?? "unknown"}，判卷器没写出理由`;
    const text = redactSecrets(why);
    records.push({
      suite: SUITE,
      target: exam.examId,
      caseKey: gateName,
      category: "inconclusive",
      cause: g.status === "not_graded" ? `gate_${gateName}_not_graded` : `gate_${gateName}_failed`,
      detail: text.length > 400 ? `${text.slice(0, 400)}…（截断，原文 ${text.length} 字）` : text,
      evidence: { gate: gateName, status: g.status ?? null, ...detail, diffs: (detail.diffs ?? []).map((d) => redactSecrets(String(d)).slice(0, 200)) },
      exit: { actual: result?.exit?.actual ?? null, expected: 1 },
      outcome: { actual: result?.outcome?.actual ?? null, expected: null },
      durationMs: result?.durationMs ?? null,
      corpus: { expectedExit: 1, expectedCases: exam.vulnerable.expect, forbidden: null },
    });
  }
  return records;
}

/**
 * 一张考卷跑满 `repeat × 3 变体`：官方判卷与判草稿共用这一条循环（草稿只是多给一份顶替目录与一张编号映射）。
 * 每一次实跑都重铺一份工作区：判卷要比的是「同一张考卷重考一次结论相同」，不能带着上一轮打过之后的状态。
 * @param {string} [p.labelPrefix] 成绩目录前缀：一张草稿一个前缀，两份草稿不会共用同一次实跑
 * @param {object} [p.extraEnv] 传给子进程的环境变量（判草稿时只有 GUARDBUILD_RECIPES_OVERLAY 这一项）
 * @param {object} [p.idMap] 草稿步骤号 → 考卷规范号；不传就是官方口径，编号原样进判卷器
 */
async function runExamVariants(exam, { labelPrefix = "", extraEnv = {}, idMap = null, repeat = 2 } = {}) {
  const runs = [];
  let hardenedDiff = null;
  let examInvalid = null;
  const startedAt = Date.now();
  const label = (variant, attempt) => `${labelPrefix}${exam.examId}--${variant}--${attempt}`;
  try {
    // 先派生一次并留差异记录：补丁锚点对不上就是考卷失效，四道闸一条都不算过
    const firstHard = makeWorkspace(label("hardened", 1), exam.vulnerableAbs, exam.hardened.patches);
    hardenedDiff = firstHard.diff;
    for (const variant of VARIANTS) {
      for (let attempt = 1; attempt <= repeat; attempt++) {
        const l = label(variant, attempt);
        const ws =
          variant === "hardened" && attempt === 1
            ? firstHard.ws
            : makeWorkspace(
                l,
                variant === "clean" ? exam.cleanAbs : exam.vulnerableAbs,
                variant === "hardened" ? exam.hardened.patches : null
              ).ws;
        runs.push(observe(variant, attempt, await runGate(l, ws, RUN_TIMEOUT_MS, extraEnv), idMap));
      }
    }
  } catch (e) {
    examInvalid = e?.reasons?.length ? e.reasons.join("；") : e.message;
  }
  return { runs, examInvalid, hardenedDiff, startedAt };
}

/**
 * 判草稿时「这一轮真的在考草稿」的证据：子进程 report 里的顶替装载记录。
 * 查不到就整张草稿判「没有成绩」——静默退回注册配方却把成绩记到草稿头上，是这条通路最坏的一块假绿灯。
 */
function overlayProof(runs, { recipeId, draftKey }) {
  for (const r of runs) {
    const hits = r.report?.summary?.recipeOverlay;
    if (!Array.isArray(hits) || !hits.length) continue;
    const hit = hits.find((h) => h?.recipeId === recipeId && String(h?.overlayOf ?? "") === String(draftKey));
    if (hit) return { ok: true, seenIn: `${r.variant}#${r.attempt}`, envelope: hit.envelope ?? null };
  }
  return {
    ok: false,
    whyNot:
      (runs.find((r) => Array.isArray(r.report?.summary?.recipeOverlay) && r.report.summary.recipeOverlay.length)?.report?.summary?.recipeOverlay ?? []).length
        ? `子进程用过顶替目录，但顶的不是这一族/这一张草稿（期望 ${recipeId} ← ${draftKey}）`
        : "子进程没有从顶替目录装载任何配方：这一轮跑的仍是注册配方，成绩不能记到草稿头上",
  };
}

/** G2 那一格的证据形态要说人话：绿灯背后到底是哪一种「没报」 */
const G2_EVIDENCE_FORM = {
  reported: "加固版仍报本族用例——补丁没修上",
  business_regressed: "加固版业务用例回退——靶子被改坏，零报不可信",
  no_attack_traffic: "加固版一条攻击请求都没落地——零报不是证据，这一闸等于没考",
  probed_and_rejected: "同一发探针打到加固版、被目标在运行期拒掉——最强形状",
  family_candidate_gone: "补丁让静态层不再把该路由当候选，本族探针没落地——靠「其余攻击仍在打 + 业务未回退 + 本族零报」通过",
};

function buildMarkdown(meta, results, notGraded) {
  const lines = [];
  lines.push("# GuardBuild 判卷报告（考卷层）");
  lines.push("");
  lines.push(`- 生成时间：${meta.generatedAt}`);
  lines.push(`- 代码版本：${meta.gitHead || "unknown"}`);
  lines.push(`- 判卷器：\`${meta.gradeVersion}\` · 考卷：\`${meta.examVersion}\`（${meta.examCount} 张，覆盖 ${meta.recipeCovered}/${meta.recipeTotal} 份已注册配方）`);
  lines.push(`- 判定：四道闸全过 + 绿名单不回退 → ${meta.gateOk ? "通过" : "未通过"}`);
  lines.push("");
  lines.push("## 汇总");
  lines.push("");
  lines.push("| 指标 | 值 |");
  lines.push("| --- | --- |");
  lines.push(`| 考卷通过 | ${meta.passed}/${meta.examCount} |`);
  lines.push(`| 四道闸逐条通过率 | ${GATES.map((g) => `${g} ${meta.gateCounts[g]}/${meta.examCount}`).join(" · ")} |`);
  lines.push(`| 开发集 / 冻结集 | ${meta.devCount} 张（失败进账本，调优读得到） / ${meta.frozenCount} 张（只判分，不进账本） |`);
  lines.push(`| 缺考卷的配方 | ${notGraded.length} |`);
  lines.push("");
  lines.push("## 考卷明细");
  lines.push("");
  lines.push("| 考卷 | 配方 | 堆 | G1 打中 | G2 加固零报 | G3 干净对照 | G4 两次一致 | 用时 | 结论 |");
  lines.push("| --- | --- | --- | --- | --- | --- | --- | --- | --- |");
  for (const r of results) {
    const g = r.grade?.gates ?? {};
    const cell = (key) => (g[key]?.status === "passed" ? "✓" : g[key]?.status === "failed" ? "✗" : g[key]?.status ?? "—");
    lines.push(
      `| ${r.id} | ${r.grade?.recipe ?? "—"} | ${r.split === "frozen" ? "冻结" : "开发"} | ${cell("hit")} | ${cell("hardened_zero")} | ${cell("clean_control")} | ${cell("consistent")} | ${(r.durationMs / 1000).toFixed(1)}s | ${r.pass ? "通过" : r.grade?.graded ? "不通过" : "没考"} |`
    );
  }
  lines.push("");
  lines.push("## 逐题取证（每个变体挨的是同一族探针）");
  lines.push("");
  lines.push("- 这一节是给绿灯配的证据：勾只说明判据过了，下面的表说明**加固版真的挨了同一发探针、且被目标拒掉**，不是没打到。");
  lines.push("- 两种「零报」不是一回事：`probed_and_rejected` = 同一发探针打到加固版被运行期拒掉；`family_candidate_gone` = 补丁让静态层不再把该路由当候选，本族探针根本没生成，这一闸靠的是「其余攻击仍在打 + 业务未回退 + 本族零报」。后者弱一档，第 8 项要专门补一份前者形状的考卷。");
  lines.push("");
  for (const r of results) {
    lines.push(`### ${r.id}`);
    lines.push("");
    lines.push("| 变体 | 终态 | 退出码 | 本族探针实际结果 |");
    lines.push("| --- | --- | --- | --- |");
    for (const p of r.probes ?? []) lines.push(`| ${p.variant} | ${p.outcome ?? "—"} | ${p.exit ?? "—"} | ${p.probes} |`);
    lines.push("");
    const g2 = r.grade?.gates?.hardened_zero ?? {};
    const g3 = r.grade?.gates?.clean_control ?? {};
    lines.push(
      `- G2「加固零报」的证据形态：\`${g2.detail?.evidence ?? "没有可用实跑"}\`——${G2_EVIDENCE_FORM[g2.detail?.evidence] ?? "加固版没有可核对的实跑，这一格没有证据"}${
        Number.isFinite(g2.detail?.attackLanded) ? `（加固版落地攻击请求 ${g2.detail.attackLanded} 条、业务用例通过 ${g2.detail.businessPassed ?? 0} 条）` : ""
      }`
    );
    lines.push(
      `- G3「不凭空造」的证据形态：干净对照落地攻击请求 ${Number.isFinite(g3.detail?.attackLanded) ? g3.detail.attackLanded : "—"} 条，${
        g3.ok ? "在此前提下本族与别族都是一条 vulnerable 都没有" : "这一闸没过，见下方理由"
      }`
    );
    lines.push("");
    lines.push("");
    lines.push(
      r.split === "frozen"
        ? "- 这一张在**冻结集**里：红了也不写进失败账本。账本是后续调优唯一读得到的输入，冻结集的失败只对读报告的人可见。"
        : "- 这一张在**开发集**里：失败按类别写进失败账本，供后续调优读取。"
    );
    if (r.hardenedDiff) lines.push(`派生的加固版相对漏洞版只改了这些：\n\n\`\`\`\n${r.hardenedDiff}\n\`\`\``);
    if (r.grade?.reasons?.length) {
      lines.push("");
      lines.push("判卷器给出的理由：");
      for (const why of r.grade.reasons) lines.push(`- ${why}`);
    }
    lines.push("");
  }
  if (notGraded.length) {
    lines.push("## 没有考卷的配方（不算通过，只是没考）");
    lines.push("");
    for (const n of notGraded) lines.push(`- \`${n.recipe}\`：${n.reasons[0]}`);
    lines.push("");
    lines.push("- 缺考卷 = 这一族的判据没有被任何已知答案考过。已记进失败账本（类别「测不了」），不会因为报告好看而消失。");
    lines.push("");
  }
  lines.push(...loopSection({ loop: meta.loop }));
  lines.push("## 说明");
  lines.push("");
  lines.push("- 加固版**由漏洞版工作区复制后插一处补丁派生**（第 7 项），考卷里只写锚点与插入内容，不写第二份靶子。");
  lines.push("- G2 只判这张考卷那一族的用例：补丁修的是本族，靶子里别的族照旧是漏洞，退出码仍是 1。");
  lines.push("- G3 对干净对照判的是「任何一条 vulnerable 都不许出现」，不限本族——什么都没埋的靶子报出东西就是凭空造。");
  lines.push("- G4 逐条比对用例判定与退出码；跑不满次数不是「通过」，是「没考够」。");
  lines.push("- 零报要有生命体征：G2/G3 先数这一份变体实际落地的攻击请求条数，一条都没发出去就判 `not_graded`（没考），靶子被补丁改崩到业务用例回退就判 `failed`。");
  lines.push("- 每一道没过的闸都往账本落一条记录（类别「测不了」，cause 记 `gate_<闸名>_<failed|not_graded>`），红考卷不会在账本上表现成「零条失败」。");
  lines.push("- 上一条只对**开发集**成立：冻结集的考卷四道闸照判、绿名单照比，但一条账都不记——调优（第 11 项）读得到的只有账本，冻结集不进账本就等于没被读过。");
  lines.push("- 本层零模型调用：运行时清空 LLM 密钥与环境开关，同一张考卷同一份补丁必须能重放。");
  lines.push("");
  return lines.join("\n");
}

/** 草稿判卷的「这条路走不通」：与真正的崩溃区分开——前者要如实记成没有成绩，后者要报异常 */
class DraftRefused extends Error {}

function relPath(p) {
  return path.relative(repoRoot, p).replace(/\\/g, "/");
}

/**
 * 一张草稿 → 一份考卷成绩（#202）。
 *
 * 与官方口径的四处不同，每一处都是这条路的假绿灯闸门：
 *  1. 执行表来自顶替目录里的草稿而不是 `sidecar/recipes/`。**顶没顶替成功不由父进程说了算**：
 *     子进程必须在自己的 report 里承认从顶替目录装载了这一族（`overlayProof`），查不到就当没有成绩——
 *     静默退回注册配方、再把成绩记到草稿头上，是这条路最坏的一种绿。
 *  2. 只跑该族的**开发集**考卷：冻结集是期末卷，不给还没有注册资格的草稿预先读。
 *  3. 用例编号按 `exp-N → 考卷规范号` 换算后才进判卷器：考卷的已知答案不动（红线 1），
 *     报告的证据表仍留草稿原号（换算只发生在判卷这一侧）。
 *  4. 不写失败账本、不动绿名单：草稿的红是「这条打法还没被证明」，不是「引擎回退了」。
 */
async function gradeOneDraft(file, { index, devExams, probeSource }) {
  const abs = path.resolve(file);
  const startedAt = Date.now();
  const r = {
    artifact: relPath(abs),
    draftKey: null,
    model: null,
    proposalId: null,
    familySlot: null,
    draftFamily: null,
    action: null,
    caseIdMap: null,
    overlayDir: null,
    overlayProof: null,
    exams: [],
    pass: false,
    whyNot: null,
    gradeFile: null,
    durationMs: 0,
  };
  let record = null;
  try {
    let art = null;
    try {
      art = JSON.parse(readFileSync(abs, "utf8"));
    } catch (e) {
      throw new DraftRefused(`探索产物读不出来（${relPath(abs)}）：${e.message}`);
    }
    r.draftKey = typeof art?.draftKey === "string" ? art.draftKey : null;
    r.model = art?.model ?? null;
    r.proposalId = art?.proposal?.id ?? null;
    const recipe = art?.draft?.recipe;
    if (!r.draftKey || !recipe || !Array.isArray(recipe.steps)) throw new DraftRefused("产物缺 draftKey 或 draft.recipe：这不是探索区落下来的草稿产物");
    if (art.draft.registered !== false) {
      throw new DraftRefused("草稿自称已注册：已注册的配方走官方口径（考卷直接引用配方名），判草稿这条路只给未注册的草稿开（红线 2/8）");
    }
    if (art.draft.tableOk !== true) {
      throw new DraftRefused(`草稿被动作表拒收（${(art.draft.rejections ?? []).length} 处）：表都填不对，判卷考不了它`);
    }
    const slot = familySlotForDraft(recipe, { probeSource });
    if (!slot.ok) throw new DraftRefused(slot.whyNot);
    r.familySlot = slot.recipeId;
    r.draftFamily = recipe.family ?? null;
    r.action = slot.action;
    const candidates = devExams.filter((e) => e.recipe === slot.recipeId);
    if (!candidates.length) throw new DraftRefused(`开发集里没有 \`${slot.recipeId}\` 这一族的考卷：没有已知答案就判不了卷`);
    const map = buildCaseIdMap({ registeredRecipe: index.get(slot.recipeId)?.recipe ?? null, draftRecipe: recipe, action: slot.action });
    if (!map.ok) throw new DraftRefused(map.whyNot);
    r.caseIdMap = { from: map.from, to: map.to };

    const overlayDir = path.join(benchRoot, "draft-overlay", r.draftKey);
    rmSync(overlayDir, { recursive: true, force: true });
    mkdirSync(overlayDir, { recursive: true });
    writeFileSync(
      path.join(overlayDir, `${slot.recipeId}.json`),
      JSON.stringify({ gradingOnly: true, familySlot: slot.recipeId, draftKey: r.draftKey, recipe }, null, 1),
      "utf8"
    );
    r.overlayDir = relPath(overlayDir);
    resetRecipeOverlayHits();

    const labelPrefix = `draft-${r.draftKey.slice(0, 16)}--`;
    const extraEnv = { [RECIPES_OVERLAY_ENV]: overlayDir };
    const allRuns = [];
    for (const exam of candidates) {
      exam.vulnerableAbs = resolveExamFixture(repoRoot, exam.vulnerable.fixture);
      exam.cleanAbs = resolveExamFixture(repoRoot, exam.clean.fixture);
      const { runs, examInvalid, hardenedDiff } = await runExamVariants(exam, { labelPrefix, extraEnv, idMap: map, repeat: repeatOf(exam) });
      allRuns.push(...runs);
      const grade = gradeExam({ exam, recipeCaseIds: index.get(exam.recipe)?.caseIds ?? [], runs, examInvalid });
      r.exams.push({
        examId: exam.examId,
        split: exam.split,
        repeat: repeatOf(exam),
        pass: grade.pass === true,
        gates: Object.fromEntries(GATES.map((g) => [g, grade.gates?.[g]?.status ?? "unknown"])),
        reasons: grade.reasons ?? [],
        probes: probeTable(runs, exam.vulnerable.expect, map),
        hardenedDiff,
        g2Evidence: grade.gates?.hardened_zero?.detail?.evidence ?? null,
        g3AttackLanded: grade.gates?.clean_control?.detail?.attackLanded ?? null,
      });
    }
    r.overlayProof = overlayProof(allRuns, { recipeId: slot.recipeId, draftKey: r.draftKey });
    if (!r.overlayProof.ok) r.whyNot = `没有成绩：${r.overlayProof.whyNot}`;
    r.pass = r.overlayProof.ok === true && r.exams.length > 0 && r.exams.every((e) => e.pass === true && e.split !== "frozen");

    record = {
      gradeVersion: GRADE_VERSION,
      draftKey: r.draftKey,
      recipeSha256: recipeSha256(recipe),
      familySlot: slot.recipeId,
      draftFamily: recipe.family ?? null,
      action: slot.action,
      model: r.model,
      proposalId: r.proposalId,
      runLabel: labelPrefix.replace(/-+$/, ""),
      overlayDir: r.overlayDir,
      overlayProof: r.overlayProof,
      caseIdMap: r.caseIdMap,
      exams: r.exams.map((e) => ({ examId: e.examId, split: e.split, repeat: e.repeat, pass: e.pass, gates: e.gates, reasons: e.reasons })),
      pass: r.pass,
      whyNot: r.pass ? null : r.whyNot ?? `${r.exams.filter((e) => !e.pass).map((e) => e.examId).join("、")} 未通过四道闸`,
      gradedAt: Date.now(),
      durationMs: Date.now() - startedAt,
      registered: false,
      note:
        "这条成绩由 benchmark-grader 的 --draft 模式产出：考的是这张未注册草稿顶替某一族执行表之后的实跑，" +
        "判据仍是 probe.mjs 里那段写死代码，考卷仍是 benchmarks/exams/ 里的人工文件。" +
        "它只说明「这一族的判据在这张草稿上站得住（或站不住）」，注册与否仍是人工动作（红线 2/8）。",
    };
  } catch (e) {
    if (!(e instanceof DraftRefused)) {
      r.whyNot = `判卷过程异常：${e?.reasons?.length ? e.reasons.join("；") : e?.message ?? e}`;
    } else {
      r.whyNot = `没有成绩：${e.message}`;
    }
    r.pass = false;
  }
  r.durationMs = Date.now() - startedAt;
  if (record) {
    const w = writeGradeRecord({ gradeDir: path.join(path.dirname(abs), "grades"), record });
    if (w.ok) r.gradeFile = relPath(w.file);
    else r.whyNot = `成绩落盘被拒：${w.whyNot}`;
  }
  return r;
}

function draftMarkdown(results, meta) {
  const lines = [];
  lines.push("# GuardBuild 判卷报告（草稿判卷层 · #202）");
  lines.push("");
  lines.push(`- 生成时间：${meta.generatedAt}`);
  lines.push(`- 代码版本：${meta.gitHead || "unknown"}`);
  lines.push(`- 判卷器：\`${GRADE_VERSION}\` · 成绩记录：\`${meta.recordVersion}\` · 草稿 ${results.length} 张`);
  lines.push(`- 结论：${meta.pass ? "全部草稿过卷" : "有草稿没过卷或没得考"}（成绩记录仍已落盘，注册工具会读它）`);
  lines.push("");
  lines.push("| 草稿 | 提议者 | 顶替族 | 编号换算 | 考卷（仅开发集） | 四道闸 | 顶替证据 | 结论 | 用时 |");
  lines.push("| --- | --- | --- | --- | --- | --- | --- | --- | --- |");
  for (const r of results) {
    const marks = r.exams.map((e) => GATES.map((g, i) => `G${i + 1}${e.gates[g] === "passed" ? "✓" : "✗"}`).join("")).join(" ");
    lines.push(
      `| \`${String(r.draftKey ?? "—").slice(0, 12)}\` | ${r.proposalId ?? "single"} | ${r.familySlot ?? "—"} | \`${r.caseIdMap?.from ?? "—"}\`→\`${r.caseIdMap?.to ?? "—"}\` | ${
        r.exams.map((e) => e.examId).join("<br>") || "—"
      } | ${marks || "—"} | ${r.overlayProof?.ok ? `已核实（${r.overlayProof.seenIn}）` : r.overlayProof ? "**未核实**" : "未走到这一步"} | ${r.pass ? "过卷" : "没过卷"} | ${(r.durationMs / 1000).toFixed(1)}s |`
    );
  }
  lines.push("");
  for (const r of results) {
    lines.push(`## \`${r.draftKey ?? path.basename(r.artifact)}\``);
    lines.push("");
    lines.push(`- 产物：\`${r.artifact}\` · 成绩：${r.gradeFile ? `\`${r.gradeFile}\`` : "无（没走到落盘这一步）"}`);
    lines.push(`- 草稿自报族名 \`${r.draftFamily ?? "—"}\`，实际顶替的族是 \`${r.familySlot ?? "—"}\`（按**动作** \`${r.action ?? "—"}\` 映射，不按模型写的名字）`);
    if (r.whyNot) lines.push(`- 为什么没有成绩：${r.whyNot}`);
    for (const e of r.exams) {
      lines.push("");
      lines.push(`### ${e.examId}（${e.split === "frozen" ? "冻结集" : "开发集"}，连跑 ${e.repeat} 次）→ ${e.pass ? "过" : "没过"}`);
      lines.push("");
      lines.push("| 变体 | 终态 | 退出码 | 本族探针实际结果 |");
      lines.push("| --- | --- | --- | --- |");
      for (const p of e.probes ?? []) lines.push(`| ${p.variant} | ${p.outcome ?? "—"} | ${p.exit ?? "—"} | ${p.probes} |`);
      lines.push("");
      lines.push(`- G2 证据形态：\`${e.g2Evidence ?? "没有可用实跑"}\`——${G2_EVIDENCE_FORM[e.g2Evidence] ?? "这一格没有证据"}`);
      lines.push(`- G3 干净对照落地攻击请求 ${Number.isFinite(e.g3AttackLanded) ? e.g3AttackLanded : "—"} 条`);
      if (e.reasons?.length) {
        lines.push("- 判卷器理由：");
        for (const why of e.reasons) lines.push(`  - ${why}`);
      }
      if (e.hardenedDiff) lines.push(`派生的加固版相对漏洞版只改了这些：\n\n\`\`\`\n${e.hardenedDiff}\n\`\`\``);
    }
    lines.push("");
  }
  lines.push("## 这一层的边界");
  lines.push("");
  lines.push("- 草稿从没注册过，执行器只认 `sidecar/recipes/` 里的表；顶替目录（`GUARDBUILD_RECIPES_OVERLAY`）是**判卷专用**的入口，信封必须写 `gradingOnly: true` 与它顶替哪一族。");
  lines.push("- 每一次实跑的 report 里都会带 `summary.recipeOverlay`（用过哪些顶替、顶的是哪一张草稿）；本层拿它核实「考的确实是这张草稿」。查不到就判「没有成绩」，不静默退回注册配方。");
  lines.push("- 只跑开发集：冻结集的卷子不读给没有注册资格的草稿——账本是调优唯一读得到的输入，提前读过期末卷就是过拟合。");
  lines.push("- 用例编号换算（`exp-N` → 考卷规范号）只发生在判卷这一侧；报告的证据表与成绩里的原始编号仍是草稿自己那批。");
  lines.push("- 本层不写失败账本、不动绿名单；注册是人工动作，`scripts/register-recipe.mjs` 读这条成绩后才决定要不要往 `sidecar/recipes/` 落文件。");
  lines.push("- 哪些草稿压根没这条路：动作还没配方化的（例：`request.anonymous` 的匿名读族，M5 第 199 项）如实拒收，不硬塞给别的族考。");
  lines.push("");
  return lines.join("\n");
}

async function draftMain() {
  if (String(process.env[RECIPES_OVERLAY_ENV] ?? "").trim()) {
    throw new Error(
      `判草稿模式要自己铺顶替目录，父进程却已经设了 ${RECIPES_OVERLAY_ENV}：那样考的是别人指定的执行表，不是手上这张草稿。请去掉这个环境变量再跑。`
    );
  }
  const probeSource = readFileSync(path.join(repoRoot, "sidecar", "lib", "probe.mjs"), "utf8");
  const anchors = checkDraftGradeAnchors({ probeSource });
  if (!anchors.ok) {
    throw new Error(
      `顶替表与执行器对不上（核对 ${anchors.checked} 项，${anchors.unresolved.length} 项不过）：${anchors.unresolved
        .map((u) => `${u.action}→${u.why}`)
        .join("；")}——先修表再判卷，否则考的是错的那一族`
    );
  }
  const index = buildRecipeIndex();
  const allExams = loadExams({ repoRoot, lookupRecipe: (id) => index.get(id) ?? null });
  const devExams = allExams.filter((e) => feedsTuning(e));
  if (!keep) rmSync(benchRoot, { recursive: true, force: true });
  mkdirSync(benchRoot, { recursive: true });
  console.log(
    `[GRADER] 判草稿 ${draftFiles.length} 张 · 可用开发集考卷 ${devExams.length} 张（冻结集 ${allExams.length - devExams.length} 张不参与这一模式）· 宿主 ${exe}`
  );

  const results = [];
  for (const [i, f] of draftFiles.entries()) {
    process.stdout.write(`[GRADER] ${i + 1}/${draftFiles.length} 草稿 ${path.basename(f)}…`);
    const r = await gradeOneDraft(f, { index, devExams, probeSource });
    results.push(r);
    console.log(
      ` ${r.draftKey ? `\`${String(r.draftKey).slice(0, 12)}\`` : "?"} → ${r.familySlot ?? "无对应族"}${
        r.caseIdMap ? `（${r.caseIdMap.from}→${r.caseIdMap.to}）` : ""
      }：${r.exams.length} 张卷 · ${r.exams.every((e) => e.pass) && r.exams.length ? "四道闸全过" : r.exams.map((e) => `${e.examId}=${e.pass ? "过" : "没过"}`).join(" ")} · ${
        r.pass ? "过卷" : "没有可采信的成绩"
      }`
    );
    if (!r.pass) console.log(`        ${r.whyNot ?? r.exams.flatMap((e) => e.reasons ?? []).join("；")}`);
  }

  const gitHead = spawnSync("git", ["-c", "core.longpaths=true", "rev-parse", "--short", "HEAD"], { cwd: repoRoot, encoding: "utf8" }).stdout?.trim() || null;
  const meta = {
    mode: "draft",
    generatedAt: new Date().toISOString(),
    gitHead,
    gradeVersion: GRADE_VERSION,
    recordVersion: DRAFT_GRADE_VERSION,
    draftCount: results.length,
    pass: results.length > 0 && results.every((r) => r.pass),
  };
  writeFileSync(path.join(benchRoot, "draft-report.json"), JSON.stringify({ ...meta, results }, null, 2));
  writeFileSync(path.join(benchRoot, "draft-report.md"), draftMarkdown(results, meta));
  for (const r of results) {
    console.log(
      `[GRADER] ${String(r.draftKey ?? r.artifact)}：${r.pass ? "成绩=过卷" : "成绩=没过/无"}${r.gradeFile ? ` → ${r.gradeFile}` : ""}${r.overlayDir ? `（顶替目录 ${r.overlayDir}）` : ""}`
    );
  }
  console.log(`[GRADER] 判草稿模式：不写失败账本、不动绿名单（草稿的红不等于引擎回退）`);
  console.log(`[GRADER] 报告：${path.join(benchRoot, "draft-report.json")}`);
  console.log(`[GRADER]       ${path.join(benchRoot, "draft-report.md")}`);
  return meta.pass ? 0 : 1;
}

/** 已注册配方索引：考卷校验（族名与用例编号必须出自这张表）与草稿编号换算都读它 */
function buildRecipeIndex() {
  const index = new Map();
  for (const id of listRecipeIds()) {
    const recipe = loadRecipe(id);
    index.set(id, { recipeId: id, family: recipe.family, recipe, caseIds: (recipe.steps ?? []).map((s) => s.id) });
  }
  return index;
}

async function main() {
  if (!existsSync(exe)) {
    throw new Error(`未找到无头宿主: ${exe}（先 cargo build --no-default-features --bin guardbuild-headless）`);
  }
  if (draftMode) return draftMain();

  const index = buildRecipeIndex();

  // 官方口径下 --exams 没给值：必须传 undefined 才会落回 loadExams 的默认目录，
  // 传 null 会让 existsSync(null) 为假，整批考卷静默消失，报告就成了「0 张全绿」。
  let exams = loadExams({ repoRoot, dir: examsDir ?? undefined, lookupRecipe: (id) => index.get(id) ?? null });
  if (only.size > 0) {
    exams = exams.filter((e) => only.has(e.examId));
    if (!exams.length) throw new Error(`--only 未匹配任何考卷: ${[...only].join(",")}`);
  }
  const examCountAll = exams.length;
  if (!lab && examCountAll === 0) {
    // 一张卷子都没装到 = 这一层没有开工，不是「所有配方都缺卷」。
    // 让它当场红掉，否则后面的缺卷归档会把一次加载失败写成四条真实的「测不了」历史。
    throw new Error(`benchmarks/exams/ 下一张考卷都没有（${EXAM_DIR}）：判卷层没有可判的卷子，不是配方缺卷子`);
  }

  if (!keep) rmSync(benchRoot, { recursive: true, force: true });
  mkdirSync(benchRoot, { recursive: true });

  console.log(`[GRADER] ${exams.length} 张考卷（开发 ${exams.filter((e) => e.split !== "frozen").length} / 冻结 ${exams.filter((e) => e.split === "frozen").length}）· ${exams.reduce((n, e) => n + repeatOf(e) * 3, 0)} 次实跑（每张 ${exams.map(repeatOf).join("/")} 次 × 3 变体），宿主 ${exe}`);

  const results = [];
  const ledgerRecords = [];
  for (const [i, exam] of exams.entries()) {
    exam.vulnerableAbs = resolveExamFixture(repoRoot, exam.vulnerable.fixture);
    exam.cleanAbs = resolveExamFixture(repoRoot, exam.clean.fixture);
    const repeat = repeatOf(exam);
    const recipe = index.get(exam.recipe);
    process.stdout.write(`[GRADER] ${i + 1}/${exams.length} ${exam.examId}（${exam.recipe}）…`);

    const { runs, examInvalid, hardenedDiff, startedAt } = await runExamVariants(exam, { repeat });

    const grade = gradeExam({ exam, recipeCaseIds: recipe?.caseIds ?? [], runs, examInvalid });
    const hitIds = grade.gates?.hit?.ok ? exam.vulnerable.expect : [];
    const missed = grade.gates?.hit?.detail?.missed ?? [];
    const reported = grade.gates?.hardened_zero?.detail?.reported ?? [];
    const fabricated = grade.gates?.clean_control?.detail?.fabricated ?? [];
    const vulnRuns = runs.filter((r) => r.variant === "vulnerable");
    const broken = runs.find((r) => r.timedOut || r.error);
    const result = {
      id: exam.examId,
      split: exam.split,
      pass: grade.pass === true,
      durationMs: Date.now() - startedAt,
      exit: {
        actual: vulnRuns[0]?.exit ?? null,
        expected: 1,
        ok: vulnRuns.some((r) => r.exit === 1) && !broken,
        timedOut: !!broken?.timedOut,
        error: broken?.error ?? examInvalid ?? null,
      },
      outcome: { actual: vulnRuns[0]?.outcome ?? null, expected: null, ok: true },
      dynamic: {
        expected: exam.vulnerable.expect,
        actual: [...new Set(vulnRuns.flatMap((r) => r.vulnerableCaseIds))],
        matched: hitIds,
        missed: missed.map((caseId) => ({ caseId, verdict: vulnRuns.at(-1)?.caseVerdicts?.[caseId] ?? "未生成" })),
        falsePositives: [...reported, ...fabricated].map((caseId) => ({ caseId })),
      },
      businessRegressed: [...new Set(runs.flatMap((r) => r.businessRegressed ?? []))],
      probes: probeTable(runs, exam.vulnerable.expect),
      grade,
      hardenedDiff,
      reportPath: vulnRuns.at(-1)?.reportPath ?? null,
    };
    results.push(result);
    // 报告与账本共用同一份闸级记录：报告里那条红和账本里那条红必须是同一件事，不能各算各的
    result.gateLedger = examInvalid ? [] : gateLedgerRecords({ exam, grade, result });

    // 冻结集只判分不进账本：账本是调优唯一读得到的输入，拿冻结集的失败去调提示词＝提前读过答案
    const tuned = feedsTuning(exam);
    if (examInvalid) {
      if (tuned) ledgerRecords.push({
        suite: SUITE,
        target: exam.examId,
        caseKey: "-",
        category: "inconclusive",
        cause: "exam_invalid",
        detail: `考卷本身失效，四道闸一条没算：${examInvalid}`,
        evidence: null,
        exit: { actual: null, expected: 1 },
        outcome: { actual: null, expected: null },
        durationMs: result.durationMs,
        corpus: { expectedExit: 1, expectedCases: exam.vulnerable.expect, forbidden: null },
      });
    } else if (tuned) {
      ledgerRecords.push(
        ...classifyRun({
          suite: SUITE,
          target: { id: exam.examId, expectedExit: 1, expectedVulnerableCases: exam.vulnerable.expect },
          result,
          report: vulnRuns.at(-1)?.report ?? null,
          gate: vulnRuns.at(-1)?.gate ?? null,
        }),
        ...result.gateLedger
      );
    }

    // 闸名首字母会撞车（hit / hardened_zero 都是 h），报告与控制台一律用 G1..G4 标号
    const marks = GATES.map((g, idx) => `G${idx + 1}${grade.gates[g].ok ? "✓" : "✗"}`).join(" ");
    console.log(` ${marks} ${grade.pass ? "✓" : "✗"}${examInvalid ? `（考卷无效：${examInvalid}）` : ""}${tuned ? "" : " [冻结集：不记账]"}`);
    if (!grade.pass) for (const why of grade.reasons) console.log(`        ${why}`);
  }

  // 注册了配方却没有考卷：判卷器一条闸都不给过，并单独记一条「测不了」，不让它消失
  // 局部跑（--only）没资格下这个结论——它压根没覆盖全部考卷
  const notGraded = only.size === 0 && !lab
    ? listRecipeIds()
        .filter((id) => !exams.some((e) => e.recipe === id))
        .map((id) => notGradedResult({ recipe: id, family: index.get(id)?.family ?? null, why: "benchmarks/exams/ 下没有引用这张配方的考卷（补齐属第 8 项）" }))
    : [];
  for (const n of notGraded) {
    ledgerRecords.push({
      suite: SUITE,
      target: `recipe:${n.recipe}`,
      caseKey: "-",
      category: "inconclusive",
      cause: "no_exam",
      detail: n.reasons[0],
      evidence: null,
      exit: { actual: null, expected: null },
      outcome: { actual: null, expected: null },
      durationMs: 0,
      corpus: { expectedExit: null, expectedCases: null, forbidden: null },
    });
  }

  const passed = results.filter((r) => r.pass).length;
  const pass = results.length > 0 && results.every((r) => r.pass);
  const gateCounts = Object.fromEntries(GATES.map((g) => [g, results.filter((r) => r.grade?.gates?.[g]?.ok).length]));
  const gitHead = spawnSync("git", ["-c", "core.longpaths=true", "rev-parse", "--short", "HEAD"], { cwd: repoRoot, encoding: "utf8" }).stdout?.trim() || null;

  // 实验室模式（--exams）不配写闭环产物：那批卷子是拿来验证「判卷器会不会红」的，
  // 一旦进账本或绿名单，就把一次人为的失败当成了真实历史。
  const ledger = lab
    ? null
    : appendLedger({
        filePath: ledgerPath,
        records: ledgerRecords,
        gitHead,
        partial: only.size > 0,
        cleanRun: pass && only.size === 0,
        resolveSuite: SUITE,
      });
  const regression = lab
    ? null
    : gateAgainstBaseline({
        filePath: baselinePath,
        suite: SUITE,
        currentKeys: greenKeysOf({ suite: SUITE, results }),
        coveredTargets: new Set(results.map((r) => r.id)),
        corpusVersion: `${examCountAll} 张考卷`,
        gitHead,
        allPass: pass,
        partial: only.size > 0,
        rebaseline,
      });
  const loop = {
    suite: SUITE,
    ledger,
    regression,
    ledgerPath: path.relative(repoRoot, ledgerPath).replace(/\\/g, "/"),
    baselinePath: path.relative(repoRoot, baselinePath).replace(/\\/g, "/"),
  };
  const gateOk = pass && (lab || regression.ok);

  const meta = {
    generatedAt: new Date().toISOString(),
    gitHead,
    gradeVersion: results[0]?.grade?.version ?? null,
    examVersion: "gb-exam-1",
    examCount: results.length,
    recipeTotal: index.size,
    recipeCovered: new Set(exams.map((e) => e.recipe)).size,
    devCount: exams.filter((e) => e.split !== "frozen").length,
    frozenCount: exams.filter((e) => e.split === "frozen").length,
    passed,
    pass,
    gateOk,
    gateCounts,
    loop,
  };
  // 落盘的只有判卷用的字段：每次跑的完整 report（含请求头与响应体）留在内存，不进报告
  writeFileSync(path.join(benchRoot, "grader-report.json"), JSON.stringify({ ...meta, results, notGraded }, null, 2));
  writeFileSync(path.join(benchRoot, "grader-report.md"), buildMarkdown(meta, results, notGraded));

  console.log(`[GRADER] 考卷通过 ${passed}/${results.length}（${pct(passed, results.length)}）· 配方有卷 ${meta.recipeCovered}/${meta.recipeTotal}`);
  if (notGraded.length) console.log(`[GRADER] 缺考卷（不算通过，只是没考）：${notGraded.map((n) => n.recipe).join("、")}`);
  for (const line of consoleLoopLines(loop)) console.log(line);
  console.log(`[GRADER] 报告：${path.join(benchRoot, "grader-report.json")}`);
  console.log(`[GRADER]       ${path.join(benchRoot, "grader-report.md")}`);
  if (lab) {
    console.log(`[GRADER] 实验室模式（--exams=${examsDir}）：不写账本、不动绿名单`);
    // 反证实验也得看见「这条红会不会留进账本」：不写，但把正式跑会写的条目原样列出来
    console.log(
      `[GRADER] 若为正式跑，本轮会写进账本 ${ledgerRecords.length} 条：${
        ledgerRecords.map((r) => `${r.category}/${r.cause}@${r.target}${r.caseKey === "-" ? "" : `#${r.caseKey}`}`).join("、") || "（一条都没有）"
      }`
    );
  }
  if (regression && !regression.ok && pass) console.log(`[GRADER] 本轮全绿但相对绿名单回退：${regression.regressions.join("、")} ❌`);
  console.log(gateOk ? "[GRADER] 全部通过 ✅" : `[GRADER] 未通过：${results.filter((r) => !r.pass).map((r) => r.id).join("、") || "回退否决"} ❌`);
  return gateOk ? 0 : 1;
}

main()
  .then((code) => process.exit(code))
  .catch((e) => {
    console.error(`[GRADER] 异常：${e?.stack ?? e?.message ?? e}`);
    if (e?.reasons) for (const r of e.reasons) console.error(`  - ${r}`);
    process.exit(2);
  });
