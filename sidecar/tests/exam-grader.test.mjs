import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ExamRejected, deriveHardened, feedsTuning, loadExams, resolveExamFixture, validateExam, EXAM_VERSION } from "../lib/exam.mjs";
import { GATES, gradeExam, notGradedResult, summarizeGrades } from "../lib/grader.mjs";
import { listRecipeIds, loadRecipe } from "../lib/recipes.mjs";

// M2 第 6、7 项（#192）：判卷器四道闸 + 加固版由补丁派生。
// 这一层存在的理由只有一个：配方的判据必须能被一份「已知答案的考卷」独立否决。
// 所以测试的重心不是「算得对」，而是「算不出绿灯的那些情况真的不给绿灯」。

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

const recipeCaseIds = ["attack-read-foreign", "attack-read-foreign-obj", "attack-read-foreign-enc", "attack-read-foreign-chan", "attack-read-foreign-proof"];
const lookupRecipe = (id) => (id === "idor-read" ? { recipeId: id, family: "idor-read", caseIds: recipeCaseIds } : null);

const baseExam = (over = {}) => ({
  version: EXAM_VERSION,
  examId: "idor-read--legacy-shop",
  recipe: "idor-read",
  family: "idor-read",
  split: "dev",
  vulnerable: { fixture: "fixtures/legacy-shop", expect: ["attack-read-foreign"] },
  hardened: {
    derivedFrom: "vulnerable",
    patch: { file: "src/app.js", search: "const order = findOrderById(orderId);", insertAfter: "\n    if (order.userId !== auth.user.id) return json(res, 403); " },
  },
  clean: { fixture: "fixtures/clean-shop" },
  repeat: 2,
  ...over,
});

// 归一化后的考卷（判卷器吃的是这个，不是原始 JSON）
const normalized = (over = {}) => ({
  examId: "idor-read--legacy-shop",
  recipe: "idor-read",
  family: "idor-read",
  vulnerable: { fixture: "fixtures/legacy-shop", expect: ["attack-read-foreign"] },
  hardened: { derivedFrom: "vulnerable", patches: [{ file: "a.js", search: "x", insertAfter: "y" }] },
  clean: { fixture: "fixtures/clean-shop" },
  repeat: 2,
  ...over,
});

const run = (variant, attempt, over = {}) => ({
  variant,
  attempt,
  exit: variant === "clean" ? 0 : 1,
  outcome: variant === "clean" ? "not_reproducible" : "vulnerable_unfixed",
  // 真实一次跑的形状：漏洞版本族打中；加固版本族候选被补丁抹掉但别的族仍在打；干净对照全都拒。
  // 「一条攻击都没发出去」的观察在判卷器里必须算「没考」，所以这里的绿灯样本要带得上攻击流量。
  vulnerableCaseIds:
    variant === "vulnerable" ? ["attack-read-foreign", "attack-cancel-foreign"] : variant === "hardened" ? ["attack-cancel-foreign"] : [],
  caseVerdicts:
    variant === "vulnerable"
      ? { "attack-read-foreign": "vulnerable", "attack-cancel-foreign": "vulnerable", "business-read-own": "passed" }
      : variant === "hardened"
        ? { "attack-cancel-foreign": "vulnerable", "business-read-own": "passed" }
        : { "attack-read-foreign": "blocked", "business-read-own": "passed" },
  reportPresent: true,
  timedOut: false,
  error: null,
  ...over,
});

/** 一份四道闸全过的观察集合：三次变体各跑两遍 */
const greenRuns = () => [
  run("vulnerable", 1),
  run("vulnerable", 2),
  run("hardened", 1),
  run("hardened", 2),
  run("clean", 1),
  run("clean", 2),
];

// —— 判卷器：四道闸各自能不能独立把一份配方判死 ——

test("G1：漏洞版打不中的配方判不通过，哪怕别的闸都好", () => {
  const runs = greenRuns().map((r) => (r.variant === "vulnerable" ? { ...r, vulnerableCaseIds: [], caseVerdicts: { "attack-read-foreign": "blocked" } } : r));
  const g = gradeExam({ exam: normalized(), recipeCaseIds, runs });
  assert.equal(g.pass, false);
  assert.equal(g.gates.hit.ok, false);
  assert.deepEqual(g.gates.hit.detail.missed, ["attack-read-foreign"]);
  assert.ok(g.reasons.some((r) => r.startsWith("G1 漏洞版没打中")));
});

test("G1：两次跑里只打中一次也算没打中（不是取并集蒙绿灯）", () => {
  const runs = greenRuns().map((r) => (r.variant === "vulnerable" && r.attempt === 2 ? { ...r, vulnerableCaseIds: [], caseVerdicts: {} } : r));
  const g = gradeExam({ exam: normalized(), recipeCaseIds, runs });
  assert.equal(g.gates.hit.ok, false);
  assert.equal(g.pass, false);
});

test("G2：加固版仍报这一族就判不通过", () => {
  const runs = greenRuns().map((r) => (r.variant === "hardened" ? { ...r, vulnerableCaseIds: ["attack-read-foreign"], caseVerdicts: { "attack-read-foreign": "vulnerable" } } : r));
  const g = gradeExam({ exam: normalized(), recipeCaseIds, runs });
  assert.equal(g.gates.hardened_zero.ok, false);
  assert.deepEqual(g.gates.hardened_zero.detail.reported, ["attack-read-foreign"]);
  assert.equal(g.pass, false);
});

test("G2：加固版报的是别的族（补丁只修本族）不算失败", () => {
  const runs = greenRuns().map((r) => (r.variant === "hardened" ? { ...r, vulnerableCaseIds: ["attack-cancel-foreign"], caseVerdicts: { "attack-cancel-foreign": "vulnerable" } } : r));
  const g = gradeExam({ exam: normalized(), recipeCaseIds, runs });
  assert.equal(g.gates.hardened_zero.ok, true);
  assert.equal(g.pass, true);
});

test("G3：干净对照凭空造出漏洞就判不通过，且不限本族", () => {
  const runs = greenRuns().map((r) => (r.variant === "clean" ? { ...r, vulnerableCaseIds: ["attack-anonymous-read"], caseVerdicts: { "attack-anonymous-read": "vulnerable" } } : r));
  const g = gradeExam({ exam: normalized(), recipeCaseIds, runs });
  assert.equal(g.gates.clean_control.ok, false);
  assert.deepEqual(g.gates.clean_control.detail.fabricated, ["attack-anonymous-read"]);

  // 没有具体用例编号、但终态自称有漏洞，同样是凭空造
  const g2 = gradeExam({ exam: normalized(), recipeCaseIds, runs: greenRuns().map((r) => (r.variant === "clean" ? { ...r, outcome: "vulnerable_unfixed" } : r)) });
  assert.equal(g2.gates.clean_control.ok, false);
  assert.ok(g2.gates.clean_control.detail.fabricated.some((x) => String(x).startsWith("终态")));
});

test("G4：连跑两次结论不一致就判不通过（用例判定与退出码都算结论）", () => {
  const runs = greenRuns().map((r) => (r.variant === "vulnerable" && r.attempt === 2 ? { ...r, exit: 2 } : r));
  const g = gradeExam({ exam: normalized(), recipeCaseIds, runs });
  assert.equal(g.gates.consistent.ok, false);
  assert.ok(g.gates.consistent.detail.diffs.some((d) => d.includes("退出码")));

  // 判定从 blocked 漂到 inconclusive：不是「报了漏洞」（G3 仍过），但两次结论确实不同 → G4 必须红
  const flip = greenRuns().map((r) =>
    r.variant === "clean" && r.attempt === 2 ? { ...r, caseVerdicts: { "attack-read-foreign": "inconclusive", "business-read-own": "passed" } } : r
  );
  const g2 = gradeExam({ exam: normalized(), recipeCaseIds, runs: flip });
  assert.equal(g2.gates.consistent.ok, false);
  assert.ok(g2.gates.consistent.detail.diffs.some((d) => d.includes("attack-read-foreign")));
});

test("跑不满 repeat 次不是绿灯，是「没考够」", () => {
  const g = gradeExam({ exam: normalized(), recipeCaseIds, runs: greenRuns().slice(0, 5) });
  assert.equal(g.pass, false);
  assert.ok(g.reasons.some((r) => r.includes("跑不满 repeat=2")));
});

test("缺一个变体的实跑 = graded:false，理由里明写「没考不等于考过」", () => {
  const g = gradeExam({ exam: normalized(), recipeCaseIds, runs: greenRuns().filter((r) => r.variant !== "clean") });
  assert.equal(g.graded, false);
  assert.equal(g.pass, false);
  assert.ok(g.reasons.some((r) => r.includes("没考不等于考过")));
  assert.equal(g.gates.clean_control.status, "not_graded");
});

test("靶子起不来 / 没产出 report 的观察不许当成「加固版零报」", () => {
  // 这一条是判卷器最容易造假绿灯的地方：加固版跑崩了 → 没报任何用例 → G2 看着像过
  const crashed = greenRuns().map((r) => (r.variant === "hardened" ? { ...r, vulnerableCaseIds: [], caseVerdicts: {}, reportPresent: false, exit: 2 } : r));
  const g = gradeExam({ exam: normalized(), recipeCaseIds, runs: crashed });
  assert.equal(g.gates.hardened_zero.ok, false);
  assert.equal(g.gates.hardened_zero.status, "not_graded");
  assert.ok(g.reasons.some((r) => r.includes("hardened") && r.includes("没有一次可用实跑")));

  const timedOut = greenRuns().map((r) => (r.variant === "clean" && r.attempt === 2 ? { ...r, timedOut: true, reportPresent: false } : r));
  const g2 = gradeExam({ exam: normalized(), recipeCaseIds, runs: timedOut });
  assert.equal(g2.gates.consistent.ok, false, "只剩一次可用跑，一致性无从验证");
});

test("四道闸全过才叫通过；闸名是冻结的四条", () => {
  const g = gradeExam({ exam: normalized(), recipeCaseIds, runs: greenRuns() });
  assert.equal(g.pass, true);
  assert.equal(g.graded, true);
  assert.deepEqual(GATES, ["hit", "hardened_zero", "clean_control", "consistent"]);
  assert.deepEqual(Object.keys(g.gates), GATES);
});

test("G2：加固版一条攻击请求都没发出去，「零报」判成没考而不是通过", () => {
  // 补丁把靶子改崩、或把攻击面整个抹掉，都表现为「加固版什么都不报」。
  // 这一闸要的是「引擎还在打而这一族不报」，不是「没有流量」。
  const silent = greenRuns().map((r) =>
    r.variant === "hardened" ? { ...r, vulnerableCaseIds: [], caseVerdicts: { "business-read-own": "passed" }, outcome: "no_findings" } : r
  );
  const g = gradeExam({ exam: normalized(), recipeCaseIds, runs: silent });
  assert.equal(g.gates.hardened_zero.ok, false);
  assert.equal(g.gates.hardened_zero.status, "not_graded");
  assert.equal(g.gates.hardened_zero.detail.attackLanded, 0);
  assert.ok(g.reasons.some((r) => r.startsWith("G2 加固版一条攻击请求都没发出去")));
  assert.equal(g.pass, false);
});

test("G2：加固版业务用例回退＝补丁把功能改坏了，零报不可信", () => {
  const broken = greenRuns().map((r) =>
    r.variant === "hardened" ? { ...r, vulnerableCaseIds: [], caseVerdicts: { "attack-cancel-foreign": "vulnerable", "business-read-own": "regressed" } } : r
  );
  const g = gradeExam({ exam: normalized(), recipeCaseIds, runs: broken });
  assert.equal(g.gates.hardened_zero.ok, false);
  assert.equal(g.gates.hardened_zero.status, "failed");
  assert.deepEqual(g.gates.hardened_zero.detail.regressed, ["business-read-own"]);
  assert.ok(g.reasons.some((r) => r.startsWith("G2 加固版业务用例回退")));
});

test("G2：本族探针没落地但别的族仍在打→算过，但要把证据形态与备注写出来", () => {
  // 真实形态：一处归属校验让静态层不再把该路由当候选，本族一条探针都不发。
  // 判它过的前提是「靶子活着、别的族仍在打、业务没回退」，且报告必须说明这不是「同一发被拒」。
  const g = gradeExam({ exam: normalized(), recipeCaseIds, runs: greenRuns() });
  assert.equal(g.gates.hardened_zero.ok, true);
  assert.equal(g.gates.hardened_zero.detail.evidence, "family_candidate_gone");
  assert.ok(g.reasons.some((r) => r.startsWith("G2 备注") && r.includes("第 8 项")));
});

test("G3：干净对照零攻击流量时，「没造假」同样判成没考", () => {
  const quiet = greenRuns().map((r) => (r.variant === "clean" ? { ...r, caseVerdicts: { "business-read-own": "passed" } } : r));
  const g = gradeExam({ exam: normalized(), recipeCaseIds, runs: quiet });
  assert.equal(g.gates.clean_control.ok, false);
  assert.equal(g.gates.clean_control.status, "not_graded");
  assert.ok(g.reasons.some((r) => r.startsWith("G3 干净对照一条攻击请求都没落地")));
});

test("考卷本身无效（补丁锚点对不上）时四道闸一条都不算过", () => {
  const g = gradeExam({ exam: normalized(), recipeCaseIds, runs: greenRuns(), examInvalid: "补丁锚点未匹配（src/app.js）" });
  assert.equal(g.pass, false);
  assert.equal(g.graded, false);
  assert.equal(g.gates.hit.status, "invalid_exam");
  assert.ok(g.reasons[0].includes("补丁锚点未匹配"));
});

test("缺考卷的配方自己带一条「没有考卷」，不在汇总里消失", () => {
  const n = notGradedResult({ recipe: "sqli-injection", family: "sqli-injection", why: "白盒没有 SQLi 靶子" });
  assert.equal(n.graded, false);
  assert.equal(n.pass, false);
  assert.ok(summarizeGrades([n]).includes("没考"));
  assert.ok(summarizeGrades([n]).includes("sqli-injection"));
});

// —— 考卷校验：装载即拒收，表外键不留情面 ——

test("未注册的配方不能当考卷依据（红线 2）", () => {
  const v = validateExam({ ...baseExam(), recipe: "ghost-family" }, { lookupRecipe });
  assert.equal(v.ok, false);
  assert.ok(v.rejections.some((r) => r.includes("未注册")));
});

test("考卷声明的用例编号必须是配方真能产出的那些", () => {
  const v = validateExam({ ...baseExam(), vulnerable: { fixture: "fixtures/legacy-shop", expect: ["attack-sql-injection"] } }, { lookupRecipe });
  assert.equal(v.ok, false);
  assert.ok(v.rejections.some((r) => r.includes("配方产不出的用例编号")));

  const dup = validateExam({ ...baseExam(), vulnerable: { fixture: "fixtures/legacy-shop", expect: ["attack-read-foreign", "attack-read-foreign"] } }, { lookupRecipe });
  assert.ok(dup.rejections.some((r) => r.includes("重复编号")));

  const empty = validateExam({ ...baseExam(), vulnerable: { fixture: "fixtures/legacy-shop", expect: [] } }, { lookupRecipe });
  assert.equal(empty.ok, false);
});

test("加固版不许自己指靶子：手写两份就地拒收（第 7 项）", () => {
  const v = validateExam(
    { ...baseExam(), hardened: { fixture: "fixtures/legacy-shop-hardened", derivedFrom: "vulnerable", patch: baseExam().hardened.patch } },
    { lookupRecipe }
  );
  assert.equal(v.ok, false);
  assert.ok(v.rejections.some((r) => r.includes("禁止手写两份")));
});

test("派生补丁只能有一处、字段齐全、derivedFrom 写死 vulnerable", () => {
  const two = validateExam({ ...baseExam(), hardened: { derivedFrom: "vulnerable", patch: [baseExam().hardened.patch, baseExam().hardened.patch] } }, { lookupRecipe });
  assert.ok(two.rejections.some((r) => r.includes("只能有 1 处")));

  const missing = validateExam({ ...baseExam(), hardened: { derivedFrom: "vulnerable", patch: { file: "a.js", search: "x" } } }, { lookupRecipe });
  assert.ok(missing.rejections.some((r) => r.includes("insertAfter 缺失")));

  const wrongSource = validateExam({ ...baseExam(), hardened: { derivedFrom: "clean", patch: baseExam().hardened.patch } }, { lookupRecipe });
  assert.ok(wrongSource.rejections.some((r) => r.includes("derivedFrom")));
});

test("干净对照不许声明「这里该打中」；多余键与别的族一样拒收", () => {
  const v = validateExam({ ...baseExam(), clean: { fixture: "fixtures/clean-shop", expect: ["attack-read-foreign"] } }, { lookupRecipe });
  assert.ok(v.rejections.some((r) => r.includes("clean 不许声明 expect")));

  const extra = validateExam({ ...baseExam(), timeoutMs: 1000 }, { lookupRecipe });
  assert.ok(extra.rejections.some((r) => r.includes("表外键 timeoutMs")));

  const otherFamily = validateExam({ ...baseExam(), family: "path-traversal" }, { lookupRecipe });
  assert.ok(otherFamily.rejections.some((r) => r.includes("族名")));

  const noVersion = validateExam({ ...baseExam(), version: "gb-exam-2" }, { lookupRecipe });
  assert.ok(noVersion.rejections.some((r) => r.includes("version 必须是")));
});

test("repeat 只在 2..4：连跑两次才算一致，跑满一堆不是调优的口子", () => {
  assert.ok(validateExam({ ...baseExam(), repeat: 1 }, { lookupRecipe }).rejections.some((r) => r.includes("repeat")));
  assert.ok(validateExam({ ...baseExam(), repeat: 5 }, { lookupRecipe }).rejections.some((r) => r.includes("repeat")));
  assert.equal(validateExam({ ...baseExam(), repeat: 3 }, { lookupRecipe }).ok, true);
});

test("考卷里的靶子只能在 fixtures/ 下：不许把靶子指到私人项目", () => {
  assert.equal(resolveExamFixture(repoRoot, "fixtures/legacy-shop").includes("legacy-shop"), true);
  assert.equal(resolveExamFixture(repoRoot, "../private-shop"), null);
  assert.equal(resolveExamFixture(repoRoot, "sidecar/main.mjs"), null);
  assert.equal(resolveExamFixture(repoRoot, "fixtures"), null);
});

// —— 派生器：锚点必须唯一命中，否则考卷失效 ——

test("deriveHardened：命中一处就写入并留下差异记录", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "gb-derive-"));
  try {
    writeFileSync(path.join(dir, "app.js"), "const order = findOrderById(orderId);\nreturn order;\n", "utf8");
    const r = deriveHardened({ workspace: dir, patches: [{ file: "app.js", search: "const order = findOrderById(orderId);", insertAfter: "\nif (!order) return 404;" }] });
    const after = readFileSync(path.join(dir, "app.js"), "utf8");
    assert.ok(after.includes("if (!order) return 404;"));
    assert.ok(r.diff.includes("app.js"));
    assert.equal(r.records[0].afterChars, r.records[0].beforeChars + "\nif (!order) return 404;".length);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// —— 第 8 项：开发集 / 冻结集切分 ——

test("split 必填：没标堆的考卷整张拒收，不给默认值", () => {
  const noSplit = { ...baseExam() };
  delete noSplit.split;
  assert.ok(validateExam(noSplit, { lookupRecipe }).rejections.some((r) => r.includes("split 必须是")));

  const bogus = validateExam({ ...baseExam(), split: "training" }, { lookupRecipe });
  assert.ok(bogus.rejections.some((r) => r.includes("split 必须是")));

  const ok = validateExam({ ...baseExam(), split: "frozen" }, { lookupRecipe });
  assert.equal(ok.ok, true, JSON.stringify(ok.rejections));
  assert.equal(ok.normalized.split, "frozen");
});

test("feedsTuning：开发集进调优输入，冻结集只判分", () => {
  assert.equal(feedsTuning({ split: "dev" }), true);
  assert.equal(feedsTuning({ split: "frozen" }), false);
  // 只有显式 frozen 才抑制记账：字段缺失时宁可照常记账，也不要悄悄把失败藏起来（装载层已会拒收缺 split 的考卷）
  assert.equal(feedsTuning({}), true);
  assert.equal(feedsTuning(null), true);
});

/** 真实考卷目录 + 真实配方索引：验收测试读的是仓库现状，不是造出来的样本 */
const repoExams = () => {
  const index = new Map();
  for (const id of listRecipeIds()) {
    const r = loadRecipe(id);
    index.set(id, { recipeId: id, family: r.family, caseIds: (r.steps ?? []).map((s) => s.id) });
  }
  return loadExams({ repoRoot, lookupRecipe: (id) => index.get(id) ?? null });
};

test("验收：真实仓库里冻结集的失败从未被写进失败账本", () => {
  const exams = repoExams();
  const frozen = exams.filter((e) => e.split === "frozen").map((e) => e.examId);
  assert.ok(frozen.length >= 1, "一张冻结考卷都没有，切分就是空话");
  // 冻结集必须覆盖到每一个族：只冻一族等于另两族随时可被过拟合
  const families = new Set(exams.map((e) => e.family));
  const frozenFamilies = new Set(exams.filter((e) => e.split === "frozen").map((e) => e.family));
  for (const f of families) assert.equal(frozenFamilies.has(f), true, `族 ${f} 没有冻结集考卷`);

  const ledger = readFileSync(path.join(repoRoot, "benchmarks", "failure-ledger.jsonl"), "utf8")
    .split("\n")
    .filter((l) => l.trim())
    .map((l) => JSON.parse(l));
  for (const rec of ledger) {
    assert.equal(
      frozen.includes(rec.target),
      false,
      `冻结考卷 ${rec.target} 的失败出现在调优输入（失败账本）里：切分失效`
    );
  }
});

test("每族至少两份形状不同的考卷（第 8 项的「补齐」那一半）", () => {
  const exams = repoExams();
  const byFamily = new Map();
  for (const e of exams) {
    if (!byFamily.has(e.family)) byFamily.set(e.family, []);
    byFamily.get(e.family).push(e);
  }
  assert.ok(byFamily.size >= 3, `只覆盖 ${byFamily.size} 族`);
  for (const [family, list] of byFamily) {
    assert.ok(list.length >= 2, `族 ${family} 只有 ${list.length} 张考卷`);
    const shapes = new Set(list.map((e) => `${e.vulnerable.fixture}|${e.hardened.patches.map((p) => `${p.file}:${p.search}`).join(",")}`));
    assert.equal(shapes.size, list.length, `族 ${family} 的考卷有重复形状：靶子与补丁锚点必须两两不同`);
  }
});

test("deriveHardened：锚点对不上 / 命中多处都抛错，绝不返回「和漏洞版一模一样」", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "gb-derive-"));
  try {
    assert.throws(() => deriveHardened({ workspace: dir, patches: [{ file: "nope.js", search: "x", insertAfter: "y" }] }), ExamRejected);

    writeFileSync(path.join(dir, "a.js"), "x\nx\n", "utf8");
    assert.throws(
      () => deriveHardened({ workspace: dir, patches: [{ file: "a.js", search: "x", insertAfter: "y" }] }),
      /出现 2 次/
    );
    assert.equal(readFileSync(path.join(dir, "a.js"), "utf8"), "x\nx\n", "抛错前不许已经改过文件");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// —— 仓库里的真考卷：与 checkAllRecipes 同规矩，「每张卷都进得了判卷器」 ——

test("benchmarks/exams/ 下每张考卷都装载得进判卷器，且指向真实靶子", () => {
  const index = new Map(listRecipeIds().map((id) => [id, { recipeId: id, family: loadRecipe(id).family, caseIds: (loadRecipe(id).steps ?? []).map((s) => s.id) }]));
  const exams = loadExams({ repoRoot, lookupRecipe: (id) => index.get(id) ?? null });
  assert.ok(exams.length >= 1, "至少一张考卷，否则这一层等于没开工");
  for (const e of exams) {
    assert.ok(index.has(e.recipe), `${e.examId} 引用了未注册配方`);
    assert.equal(e.hardened.derivedFrom, "vulnerable");
    assert.equal(e.hardened.patches.length, 1);
    for (const rel of [e.vulnerable.fixture, e.clean.fixture]) {
      const abs = resolveExamFixture(repoRoot, rel);
      assert.ok(abs && readFileSync(path.join(abs, "package.json"), "utf8").length > 0, `${rel} 不是可跑的靶子`);
    }
    // 加固版补丁的锚点必须在漏洞版源码里唯一命中——考卷提交进仓库就得当场能派生
    const file = readFileSync(path.join(repoRoot, e.vulnerable.fixture, e.hardened.patches[0].file), "utf8");
    assert.equal(file.split(e.hardened.patches[0].search).length - 1, 1, `${e.examId} 的补丁锚点在 ${e.hardened.patches[0].file} 里不是唯一命中`);
  }
});

test("loadExams 的目录传成 null 要落回仓库目录，不许静默返回空批次", () => {
  // 一次 dir:null 会让 existsSync(null) 为假，整批考卷凭空消失，
  // 判卷报告就成了「0 张考卷、全部缺卷」——把加载失败写成了真实的失败账本。
  const index = new Map(listRecipeIds().map((id) => [id, { recipeId: id, family: loadRecipe(id).family, caseIds: (loadRecipe(id).steps ?? []).map((s) => s.id) }]));
  const official = loadExams({ repoRoot, lookupRecipe: (id) => index.get(id) ?? null });
  for (const dir of [null, undefined]) {
    assert.equal(loadExams({ repoRoot, dir, lookupRecipe: (id) => index.get(id) ?? null }).length, official.length, `dir=${String(dir)} 应当读同一批卷子`);
  }
});

test("坏考卷整批拒收：一份不合规矩就没有半份考卷能装载", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "gb-exams-"));
  try {
    mkdirSync(dir, { recursive: true });
    writeFileSync(path.join(dir, "good.json"), JSON.stringify(baseExam()), "utf8");
    writeFileSync(path.join(dir, "bad.json"), JSON.stringify({ ...baseExam(), examId: "bad", hardened: { fixture: "fixtures/x", derivedFrom: "vulnerable", patch: baseExam().hardened.patch } }), "utf8");
    assert.throws(() => loadExams({ repoRoot, dir, lookupRecipe }), ExamRejected);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
