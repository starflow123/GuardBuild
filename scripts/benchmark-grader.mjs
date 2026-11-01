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
 */
import { spawn, spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { variantBaseCaseId } from "../sidecar/lib/attackvariants.mjs";
import { deriveHardened, EXAM_DIR, feedsTuning, loadExams, resolveExamFixture } from "../sidecar/lib/exam.mjs";
import { appendLedger, classifyRun, greenKeysOf, redactSecrets } from "../sidecar/lib/failureledger.mjs";
import { GATES, gradeExam, notGradedResult } from "../sidecar/lib/grader.mjs";
import { listRecipeIds, loadRecipe } from "../sidecar/lib/recipes.mjs";
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

function runGate(label, workspace, timeoutMs) {
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

/** 把一次 gate 收成判卷器要的观察：用例判定折叠同源变体，原始判定表留着比一致性 */
function observe(variant, attempt, run) {
  const pre = run.report?.evidence?.pre ?? [];
  const vulnerableCaseIds = [...new Set(pre.filter((e) => e.verdict === "vulnerable").map((e) => variantBaseCaseId(e.caseId)))];
  const caseVerdicts = {};
  for (const e of pre) if (e.caseId) caseVerdicts[e.caseId] = e.verdict;
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
function probeTable(runs, expect) {
  const rows = [];
  for (const variant of ["vulnerable", "hardened", "clean"]) {
    const run = runs.find((r) => r.variant === variant && r.reportPresent && !r.timedOut && !r.error);
    if (!run) {
      rows.push({ variant, outcome: null, exit: null, probes: "没有可用实跑（靶子没起来 / 超时 / 未产出 report），这一格不算证据" });
      continue;
    }
    const entries = (run.report?.evidence?.pre ?? []).filter((e) => expect.includes(variantBaseCaseId(e.caseId)));
    rows.push({
      variant,
      outcome: run.outcome ?? null,
      exit: run.exit ?? null,
      probes:
        entries
          .map((e) => `\`${e.caseId}\` → ${e.verdict}（HTTP ${e.response?.status ?? "—"}${e.identity ? `，身份 ${e.identity}` : ""}）`)
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

async function main() {
  if (!existsSync(exe)) {
    throw new Error(`未找到无头宿主: ${exe}（先 cargo build --no-default-features --bin guardbuild-headless）`);
  }

  const index = new Map();
  for (const id of listRecipeIds()) {
    const recipe = loadRecipe(id);
    index.set(id, { recipeId: id, family: recipe.family, caseIds: (recipe.steps ?? []).map((s) => s.id) });
  }

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

  /** 考卷自己声明连跑次数，--repeat 覆盖；G4 至少要两次才算「结论一致」 */
  const repeatOf = (exam) => Math.max(2, Math.min(4, repeatOverride ?? exam.repeat ?? 2));
  console.log(`[GRADER] ${exams.length} 张考卷（开发 ${exams.filter((e) => e.split !== "frozen").length} / 冻结 ${exams.filter((e) => e.split === "frozen").length}）· ${exams.reduce((n, e) => n + repeatOf(e) * 3, 0)} 次实跑（每张 ${exams.map(repeatOf).join("/")} 次 × 3 变体），宿主 ${exe}`);

  const RUN_TIMEOUT_MS = 240_000;

  /** 每一次实跑都重铺一份工作区：判卷要比的是「同一张考卷重考一次结论相同」，不能带着上一轮打过之后的状态 */
  function buildVariantWorkspace(exam, variant, attempt) {
    const label = `${exam.examId}--${variant}--${attempt}`;
    if (variant === "hardened") return { label, ws: makeWorkspace(label, exam.vulnerableAbs, exam.hardened.patches).ws };
    return { label, ws: makeWorkspace(label, variant === "clean" ? exam.cleanAbs : exam.vulnerableAbs).ws };
  }

  const results = [];
  const ledgerRecords = [];
  for (const [i, exam] of exams.entries()) {
    exam.vulnerableAbs = resolveExamFixture(repoRoot, exam.vulnerable.fixture);
    exam.cleanAbs = resolveExamFixture(repoRoot, exam.clean.fixture);
    const repeat = repeatOf(exam);
    const recipe = index.get(exam.recipe);
    process.stdout.write(`[GRADER] ${i + 1}/${exams.length} ${exam.examId}（${exam.recipe}）…`);

    let examInvalid = null;
    const runs = [];
    const startedAt = Date.now();
    let hardenedDiff = null;
    try {
      // 先派生一次并留差异记录：补丁锚点对不上就是考卷失效，四道闸一条都不算过
      const firstHard = makeWorkspace(`${exam.examId}--hardened--1`, exam.vulnerableAbs, exam.hardened.patches);
      hardenedDiff = firstHard.diff;
      for (const variant of ["vulnerable", "hardened", "clean"]) {
        for (let attempt = 1; attempt <= repeat; attempt++) {
          const { label, ws } =
            variant === "hardened" && attempt === 1 ? { label: `${exam.examId}--hardened--1`, ws: firstHard.ws } : buildVariantWorkspace(exam, variant, attempt);
          runs.push(observe(variant, attempt, await runGate(label, ws, RUN_TIMEOUT_MS)));
        }
      }
    } catch (e) {
      examInvalid = e?.reasons?.length ? e.reasons.join("；") : e.message;
    }

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
