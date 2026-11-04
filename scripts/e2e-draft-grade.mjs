#!/usr/bin/env node
/**
 * 草稿 → 判卷 → 注册通路（方案第 6/9/10 项，缺陷 #202 的扩版）端到端演练。
 *
 * 这一轮跑的是**真判卷器 + 真宿主 + 真考卷**：一张未注册的探索草稿，经顶替目录
 * （`GUARDBUILD_RECIPES_OVERLAY`）成为 `idor-read` 这一族本轮的执行表，在开发集考卷上
 * 实跑 6 次（漏洞/加固/干净 × 2 次），四道闸全过才落成一条成绩；然后注册工具在
 * 「没有成绩 / 成绩与草稿不符 / 差集没点名 / 少打确认字」这四种状态下的每一次拒收都要当场复现。
 *
 * 与 `e2e-dual` 的分工写清楚，免得两边都被当成同一件事：
 *  - `e2e-dual` 证明**扫描这一侧**读不到成绩就退回（它不产成绩）；
 *  - 这一轮证明**成绩是真考出来的**，且顶替目录里跑确实是那张草稿（子进程自己的 report 承认）；
 *  - 注册这一步只到人打齐 `--write --confirm=REGISTER` 为止，**不真往 `sidecar/recipes/` 落文件**：
 *    真要注册是人的动作，演练把它写成仓库里的配方就等于演练自己造了个绿灯。
 *
 * 安全边界：全程本机、无密钥（判卷器自己会把 DEEPSEEK_* 清空）、只打 fixtures/ 里的自建靶场。
 *
 * 用法: node scripts/e2e-draft-grade.mjs
 */
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { EXPLORATION_VERSION, EXPLORATION_DRAFT_RULE, explorationArtifactDir } from "../sidecar/lib/explorer.mjs";
import { validateRecipe } from "../sidecar/lib/actiontable.mjs";
import { readGradeRecord } from "../sidecar/lib/draftgrade.mjs";
import { RECIPES_OVERLAY_ENV } from "../sidecar/lib/recipes.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const workDir = path.join(repoRoot, ".demo-draft-grade");
const projectRoot = path.join(workDir, "target"); // 只用来定草稿目录的哈希名，不需要真存在
process.env.GUARDBUILD_DATA_DIR = workDir; // 草稿目录按数据目录定位：与真探索区同一个算法，不另写一份
const graderScript = path.join(repoRoot, "scripts", "benchmark-grader.mjs");
const registerScript = path.join(repoRoot, "scripts", "register-recipe.mjs");

const checks = [];
function check(name, cond, detail = "") {
  checks.push({ name, pass: !!cond });
  console.log(`${cond ? "  ✓" : "  ✗"} ${name}${cond ? "" : ` — ${detail}`}`);
  return !!cond;
}

const sha = (buf) => createHash("sha256").update(buf).digest("hex").slice(0, 16);
const shaFile = (p) => sha(readFileSync(p));

/** 一张草稿的配方形状：与探索区产出同一形状（步骤号 exp-N、判据由引擎写死、自称未注册） */
function draftRecipe(axes) {
  const steps = [
    { id: "exp-1", action: "request.as", method: "GET", path: "{slot:readPath}", identity: "attacker", note: "以 attacker 身份读 victim 名下订单" },
    ...axes.map((axis) => ({ id: `exp-1-${axis}`, action: "request.variant", uses: "exp-1", axis, label: `换${axis}轴`, requiresPreRepro: true })),
    { id: "exp-1-proof", action: "readback.ownership", uses: "exp-1", field: "{plan.ownerField}", note: "归属人自己复读同一对象" },
  ];
  return {
    version: "gb-recipe-1",
    family: axes.length === 3 ? "read-others-order-as-attacker" : "read-only-one-extra-object",
    generatedBy: `${EXPLORATION_VERSION}（探索区自动草稿，非人工定稿）`,
    steps,
    verdict: { rule: EXPLORATION_DRAFT_RULE },
  };
}

function draftKeyForMenu(seed) {
  return `A-${createHash("sha256").update(seed).digest("hex").slice(0, 32)}`;
}

/** 落一份「探索区产物」形状的文件，返回绝对路径 */
function writeArtifact(recipe, draftKey) {
  const v = validateRecipe(recipe);
  if (!v.ok) throw new Error(`样例草稿自身没过动作表：${JSON.stringify(v.rejections)}`);
  const dir = explorationArtifactDir(projectRoot);
  mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `${draftKey}.json`);
  writeFileSync(
    file,
    JSON.stringify(
      {
        version: EXPLORATION_VERSION,
        savedAt: Date.now(),
        draftKey,
        model: "e2e-draft-grade-sample",
        proposal: { id: "A", basis: "演练样例：一条基线打法 + N 条变体轴 + 归属人复读" },
        menuFingerprint: createHash("sha256").update(draftKey).digest("hex").slice(0, 32),
        outcome: "draft_passed_table",
        requestsUsed: 1,
        modelCalls: 0,
        durationMs: 0,
        ignoredFields: [],
        rejectedChoices: 0,
        trace: [],
        draft: {
          recipe,
          family: recipe.family,
          familyDeclared: true,
          verdictRule: EXPLORATION_DRAFT_RULE,
          verdictByEngine: true,
          steps: recipe.steps.length,
          tableOk: true,
          rejections: [],
          registered: false,
        },
      },
      null,
      1
    ),
    "utf8"
  );
  return file;
}

function runNode(script, args, { env = {} } = {}) {
  const cleanEnv = { ...process.env, ...env };
  delete cleanEnv[RECIPES_OVERLAY_ENV]; // 判卷器与注册工具在顶替状态下都应当拒跑，别让环境替它们开门
  const r = spawnSync(process.execPath, [script, ...args], { cwd: repoRoot, encoding: "utf8", env: cleanEnv, timeout: 1_500_000 });
  return { code: r.status, out: `${r.stdout ?? ""}${r.stderr ?? ""}` };
}

function main() {
  rmSync(workDir, { recursive: true, force: true });
  mkdirSync(workDir, { recursive: true });

  const fullKey = draftKeyForMenu("e2e-draft-grade-full");
  const shortKey = draftKeyForMenu("e2e-draft-grade-short");
  const fullRecipe = draftRecipe(["obj", "enc", "chan"]);
  const shortRecipe = draftRecipe(["obj"]);
  const fullFile = writeArtifact(fullRecipe, fullKey);
  const shortFile = writeArtifact(shortRecipe, shortKey);
  const gradesDir = path.join(path.dirname(fullFile), "grades");

  const recipesBefore = {};
  for (const f of listRecipeFiles()) recipesBefore[path.basename(f)] = shaFile(f);
  const ledgerBefore = shaFile(path.join(repoRoot, "benchmarks", "failure-ledger.jsonl"));
  const baselineBefore = shaFile(path.join(repoRoot, "benchmarks", "green-baseline.json"));

  // ============ 1) 真判卷：两张草稿各考一遍开发集 ============
  console.log("\n[DRAFT-GRADE] 1/4 判卷器 --draft 真跑（两张草稿 × 一张开发卷 × 3 变体 × 2 次）…");
  const g = runNode(graderScript, [`--draft=${fullFile},${shortFile}`]);
  console.log(g.out.split("\n").filter((l) => l.startsWith("[GRADER]")).map((l) => `    ${l}`).join("\n"));
  check("判卷器退出码 0（两张都过卷）", g.code === 0, `code=${g.code}`);

  const recFull = readGradeRecord({ gradeDir: gradesDir, draftKey: fullKey, recipe: fullRecipe });
  const recShort = readGradeRecord({ gradeDir: gradesDir, draftKey: shortKey, recipe: shortRecipe });
  check("两张草稿都落了一条可采信成绩（哈希/草稿键/判卷器版本四项对得上）", recFull.ok === true && recShort.ok === true, `full=${recFull.whyNot ?? "ok"} short=${recShort.whyNot ?? "ok"}`);
  const rf = recFull.record ?? {};
  check("成绩顶替的是按动作映射出来的那一族，不是模型自报的族名", rf.familySlot === "idor-read" && rf.action === "request.as" && rf.draftFamily === "read-others-order-as-attacker", JSON.stringify({ familySlot: rf.familySlot, draftFamily: rf.draftFamily }));
  check("成绩只来自开发集：冻结卷一条都不给未注册草稿读", (rf.exams ?? []).length > 0 && (rf.exams ?? []).every((e) => e.split === "dev"), JSON.stringify((rf.exams ?? []).map((e) => [e.examId, e.split])));
  check("四道闸逐条过了这一张草稿（不是「没跑所以没红」）", (rf.exams ?? []).every((e) => Object.values(e.gates ?? {}).every((s) => s === "passed")), JSON.stringify((rf.exams ?? []).map((e) => e.gates)));
  check("成绩里的顶替证据是子进程自己承认的（report.summary.recipeOverlay）", rf.overlayProof?.ok === true && rf.overlayProof?.envelope === "idor-read.json", JSON.stringify(rf.overlayProof));
  check("成绩自称未注册：判卷器无权写注册状态", rf.registered === false, `registered=${rf.registered}`);
  check("编号换算落在成绩里（exp-1 → attack-read-foreign）", rf.caseIdMap?.from === "exp-1" && rf.caseIdMap?.to === "attack-read-foreign", JSON.stringify(rf.caseIdMap));
  check("两张草稿是两次独立实跑（实跑标签不同，不是共享一份成绩）", String(rf.runLabel ?? "") !== String(recShort.record?.runLabel ?? "") && /^draft-/.test(String(rf.runLabel ?? "")), `${rf.runLabel} / ${recShort.record?.runLabel}`);

  // 子进程 report 里那条顶替披露：报告「用过顶替目录」与「顶的是哪张草稿」都要落在纸上
  const childReportPath = path.join(repoRoot, ".grader", "reports", `${rf.runLabel}--idor-read--legacy-shop--vulnerable--1`, "report.json");
  const childReport = existsSync(childReportPath) ? JSON.parse(readFileSync(childReportPath, "utf8")) : null;
  const overlay = childReport?.summary?.recipeOverlay ?? [];
  check("真跑那一轮的 report 披露了顶替来源（族 + 草稿键 + 信封文件名）", overlay.some((h) => h.recipeId === "idor-read" && h.overlayOf === fullKey && h.envelope === "idor-read.json"), JSON.stringify(overlay));

  // ============ 2) 没有成绩 / 成绩不背书：注册工具拒在门口 ============
  console.log("\n[DRAFT-GRADE] 2/4 注册核对：没有成绩、成绩与草稿不符，两种都得拒…");
  const noGradeKey = draftKeyForMenu("e2e-draft-grade-nograde");
  const noGradeFile = writeArtifact(fullRecipe, noGradeKey);
  const r1 = runNode(registerScript, [`--draft=${noGradeFile}`]);
  check("没判过卷：退出码非 0 且理由是「还没有考卷成绩」", r1.code !== 0 && /还没有考卷成绩|没有可采信的考卷成绩/.test(r1.out), `code=${r1.code}`);

  // 拿已过卷那份的产物改成另一张表（判卷之后草稿又被改）：旧成绩不给新内容背书
  const tampered = JSON.parse(readFileSync(fullFile, "utf8"));
  tampered.draft.recipe = shortRecipe;
  writeFileSync(fullFile, JSON.stringify(tampered, null, 1), "utf8");
  const r2 = runNode(registerScript, [`--draft=${fullFile}`]);
  check("判卷之后草稿被改过：哈希对不上就作废（退出码非 0）", r2.code !== 0 && /哈希与手上这张不符/.test(r2.out), `code=${r2.code}`);
  writeArtifact(fullRecipe, fullKey); // 还原成考过的那张

  // ============ 3) 差集与确认字：注册是整表替换，不是顺手覆盖 ============
  console.log("\n[DRAFT-GRADE] 3/4 差集点名与人工确认：演练到此为止，不落配方文件…");
  const preview = path.join(workDir, "candidate-idor-read.json");
  const r3 = runNode(registerScript, [`--draft=${fullFile}`, `--preview=${preview}`]);
  check("已过卷 + 差集为空：核对全过，但本轮不注册（未给 --write）", r3.code === 0 && /可以注册，但本轮没有注册/.test(r3.out), `code=${r3.code}`);
  const candidate = existsSync(preview) ? JSON.parse(readFileSync(preview, "utf8")) : null;
  check("候选表的用例编号换回考卷认的规范号（不留 exp-N）", !!candidate && candidate.steps.every((s) => !/^exp-/.test(String(s.id))) && candidate.steps[0]?.id === "attack-read-foreign", JSON.stringify((candidate?.steps ?? []).map((s) => s.id)));
  check("候选表带着出处（草稿键 + 成绩文件 + 丢掉的步骤）", !!candidate?.registeredFrom && candidate.registeredFrom.draftKey === fullKey && Array.isArray(candidate.registeredFrom.droppedSteps), JSON.stringify(candidate?.registeredFrom ?? null));
  check("候选表的判据仍是这一族写死的那条（模型写的 verdict 进不了配方）", candidate?.verdict?.rule === "attack-repro", `rule=${candidate?.verdict?.rule}`);

  const r4 = runNode(registerScript, [`--draft=${shortFile}`]);
  check("草稿比注册表少两条变体轴：不点名就拒收", r4.code !== 0 && /会丢掉/.test(r4.out) && /attack-read-foreign-enc/.test(r4.out) && /能力差集已被人逐条点名.*✗/s.test(r4.out), `code=${r4.code}`);
  const r5 = runNode(registerScript, [`--draft=${shortFile}`, "--drop=attack-read-foreign-enc"]);
  check("只点名一条：少点一条照样拒收（差集要逐条对账）", r5.code !== 0 && /少 2 条步骤/.test(r5.out), `code=${r5.code}`);
  const r6 = runNode(registerScript, [`--draft=${shortFile}`, "--drop=attack-read-foreign-enc,attack-read-foreign-chan"]);
  check("逐条点名之后：可注册，但仍要人给 --write", r6.code === 0 && /可以注册，但本轮没有注册/.test(r6.out), `code=${r6.code}`);
  const r7 = runNode(registerScript, [`--draft=${shortFile}`, "--drop=attack-read-foreign-enc,attack-read-foreign-chan", "--write"]);
  check("--write 但没打 --confirm=REGISTER：不写", r7.code === 0 && /还缺 .--confirm=REGISTER./.test(r7.out) && /未注册/.test(r7.out), `code=${r7.code}`);

  // ============ 4) 这一轮没碰过的东西：配方表、账本、绿名单 ============
  console.log("\n[DRAFT-GRADE] 4/4 演练没往仓库里留副作用…");
  const recipesAfter = {};
  for (const f of listRecipeFiles()) recipesAfter[path.basename(f)] = shaFile(f);
  check("sidecar/recipes/ 一个字节都没变（注册是人的动作，演练不自造绿灯）", JSON.stringify(recipesBefore) === JSON.stringify(recipesAfter), `${Object.keys(recipesBefore).length} 张配方的哈希逐张比过`);
  check("判草稿模式不写失败账本", shaFile(path.join(repoRoot, "benchmarks", "failure-ledger.jsonl")) === ledgerBefore, "草稿的红是「还没被证明」，不是「引擎回退了」");
  check("判草稿模式不动绿名单", shaFile(path.join(repoRoot, "benchmarks", "green-baseline.json")) === baselineBefore, "");

  const failed = checks.filter((c) => !c.pass);
  console.log(`\n[DRAFT-GRADE] ${checks.length - failed.length}/${checks.length} 通过`);
  if (failed.length) {
    for (const f of failed) console.log(`  未通过：${f.name}`);
    process.exit(1);
  }
  console.log("[DRAFT-GRADE] 草稿→判卷→注册这条通路整条跑通：成绩是真考的，注册是人打齐三个字才发生的。");
}

function listRecipeFiles() {
  const dir = path.join(repoRoot, "sidecar", "recipes");
  return readdirSync(dir)
    .filter((n) => n.endsWith(".json"))
    .sort()
    .map((n) => path.join(dir, n));
}

main();
