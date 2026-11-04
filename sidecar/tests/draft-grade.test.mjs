/**
 * 草稿判卷通路（任务 #202）的纯层测试。
 * 运行：npm run test:sidecar
 *
 * 这一层只做一件事：让「一张没注册的探索草稿」能拿到考卷成绩，同时保证它拿到的成绩
 * 确实来自它自己那一次实跑。所以测试的重心和判卷层一样，不在「算得对」，而在
 * **「四种冒充都不给过」**：借别的路的成绩、考完又改了草稿、判卷器换了版本、
 * 顶替目录静默退回注册配方。每一条放过去都是一块新的假绿灯。
 */
import test from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  DRAFT_GRADE_VERSION,
  FAMILY_SLOT_BY_ACTION,
  buildCaseIdMap,
  canonicalBaseId,
  checkDraftGradeAnchors,
  familySlotForDraft,
  gradeRecordFile,
  normalizeCaseId,
  normalizeCaseIds,
  readGradeRecord,
  recipeSha256,
  validateGradeRecord,
  writeGradeRecord,
} from "../lib/draftgrade.mjs";
import { GRADE_VERSION } from "../lib/grader.mjs";
import { RECIPES_OVERLAY_ENV, RecipeRejected, loadRecipe, recipeOverlayHits, resetRecipeOverlayHits } from "../lib/recipes.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const probeSource = readFileSync(path.join(repoRoot, "sidecar", "lib", "probe.mjs"), "utf8");

/** 一张「越权读」草稿：动作与注册表同族，但步骤 id 是探索区的 exp-N */
const draftRecipe = (over = {}) => ({
  version: "gb-recipe-1",
  family: "read-by-who-asked",
  generatedBy: "gb-explore-1（探索区自动草稿，非人工定稿）",
  steps: [
    { id: "exp-1", action: "request.as", method: "GET", path: "{slot:readPath}", identity: "attacker", note: "以 attacker 身份读 victim 的对象" },
    { id: "exp-2", action: "request.as", method: "GET", path: "{slot:readPath}", identity: "victim", note: "本人读自己的（正向对照）" },
  ],
  verdict: { rule: "attack-repro" },
  ...over,
});

const KEY = "A-0123456789abcdef0123456789abcdef";

const gradeRecord = (over = {}) => ({
  version: DRAFT_GRADE_VERSION,
  gradeVersion: GRADE_VERSION,
  draftKey: KEY,
  recipeSha256: recipeSha256(draftRecipe()),
  familySlot: "idor-read",
  action: "request.as",
  runLabel: `draft-${KEY.slice(0, 16)}`,
  exams: [{ examId: "idor-read--legacy-shop", split: "dev", pass: true, gates: { hit: "passed" } }],
  pass: true,
  registered: false,
  ...over,
});

test("顶替表与执行器对得上：每条 anchorToken 还在那段写死代码里", () => {
  const r = checkDraftGradeAnchors({ probeSource });
  assert.equal(r.ok, true, JSON.stringify(r.unresolved));
  assert.equal(r.checked, Object.keys(FAMILY_SLOT_BY_ACTION).length);
  // 表被掏空（换成一份没有锚点的源码）必须红，而不是「没核对到就算过」
  const empty = checkDraftGradeAnchors({ probeSource: "// 这一族还没接进执行器" });
  assert.equal(empty.ok, false);
  assert.equal(empty.unresolved.length, Object.keys(FAMILY_SLOT_BY_ACTION).length);
});

test("草稿按动作映射到族槽位；族名是模型写的措辞，不作数", () => {
  const s = familySlotForDraft(draftRecipe(), { probeSource });
  assert.equal(s.ok, true);
  assert.equal(s.recipeId, "idor-read");
  assert.equal(s.action, "request.as");
  assert.equal(s.draftBaseId, "exp-1"); // 执行位取第一条，与 baselineStep 同一规矩
  // 模型把族名改成别的说法，映射结果不变：映射读的是动作
  const renamed = familySlotForDraft(draftRecipe({ family: "totally-different-name" }), { probeSource });
  assert.deepEqual(renamed, s);
});

test("匿名读一族如实拒收：没有可顶替的表就说没有，不硬塞给越权读", () => {
  const anon = { ...draftRecipe(), steps: [{ id: "exp-1", action: "request.anonymous", method: "GET", path: "{slot:unauthReadPath}" }] };
  const s = familySlotForDraft(anon, { probeSource });
  assert.equal(s.ok, false);
  assert.match(s.whyNot, /199/); // 指向 M5 那一格，让人知道缺的是哪一项
  assert.doesNotMatch(s.whyNot, /idor-read/); // 绝不冒充成另一族
});

test("带变体轴与交叉证明的完整草稿：还是那一族，不许读成「跨了 3 族」", () => {
  // 注册表 `idor-read.json` 自己就是 `request.as` + `request.variant` + `readback.ownership` 的形状。
  // 把辅助动作也当族来算，真实的草稿会在门口被拒收——那是「草稿过不了考卷」的另一块假红。
  const full = draftRecipe({
    steps: [
      { id: "exp-1", action: "request.as", method: "GET", path: "{slot:readPath}", identity: "attacker" },
      { id: "exp-1-obj", action: "request.variant", uses: "exp-1", axis: "obj", label: "换受害人名下另一个对象", requiresPreRepro: true },
      { id: "exp-1-proof", action: "readback.ownership", uses: "exp-1", field: "{plan.ownerField}" },
    ],
  });
  const s = familySlotForDraft(full, { probeSource });
  assert.equal(s.ok, true, JSON.stringify(s.whyNot ?? null));
  assert.equal(s.recipeId, "idor-read");
  assert.equal(s.action, "request.as", "映射只认打击动作，辅助动作不参与");
  assert.equal(s.draftBaseId, "exp-1");
  assert.deepEqual(s.supporting, ["request.variant", "readback.ownership"]);

  // 只有辅助步：没有打击步就没有可顶替的执行表，如实拒收而不是随便挑一族
  const onlySupport = { ...draftRecipe(), steps: [{ id: "exp-1", action: "readback.ownership", uses: "exp-0", field: "{plan.ownerField}" }] };
  const r = familySlotForDraft(onlySupport, { probeSource });
  assert.equal(r.ok, false);
  assert.match(r.whyNot, /没有打击步/);

  // 表外的新动作（既非打击族也非辅助）仍然拒收，且理由要说清缺的是执行器
  const novel = { ...draftRecipe(), steps: [{ id: "exp-1", action: "token.forge", method: "GET", path: "{slot:readPath}", note: "伪造 token" }] };
  const n = familySlotForDraft(novel, { probeSource });
  assert.equal(n.ok, false);
  assert.match(n.whyNot, /token\.forge/);
  assert.match(n.whyNot, /能力请求单/);

  // 混用两族的打击步 + 辅助步：仍然按打击动作判跨族
  const mixed = { ...draftRecipe(), steps: [{ id: "exp-1", action: "request.as", method: "GET", path: "{slot:readPath}", identity: "attacker" }, { id: "exp-2", action: "fs.traverse", method: "GET", path: "{slot:traversalPath}", param: "{plan.param}", canary: "package.json" }, { id: "exp-1-proof", action: "readback.ownership", uses: "exp-1", field: "{plan.ownerField}" }] };
  const m = familySlotForDraft(mixed, { probeSource });
  assert.equal(m.ok, false);
  assert.match(m.whyNot, /跨了 2 族/);
});

test("跨族草稿拒收：一次判卷只顶替一族一张考卷", () => {  const mixed = { ...draftRecipe(), steps: [{ id: "exp-1", action: "request.as", path: "{slot:readPath}", method: "GET" }, { id: "exp-2", action: "fs.traverse", path: "{slot:traversalPath}", method: "GET", param: "{plan.param}", canary: "package.json" }] };
  const s = familySlotForDraft(mixed, { probeSource });
  assert.equal(s.ok, false);
  assert.match(s.whyNot, /跨了 2 族/);
});

test("用例编号换算：基号与 -N 后缀、变体号一起换，前缀相近的号不被误吞", () => {
  const registered = loadRecipe("idor-read");
  const map = buildCaseIdMap({ registeredRecipe: registered, draftRecipe: draftRecipe(), action: "request.as" });
  assert.equal(map.ok, true);
  assert.equal(map.from, "exp-1");
  assert.equal(map.to, "attack-read-foreign");
  assert.equal(normalizeCaseId("exp-1", map), "attack-read-foreign");
  assert.equal(normalizeCaseId("exp-1-2", map), "attack-read-foreign-2"); // 同一槽位的第二个候选
  assert.equal(normalizeCaseId("exp-1-obj1", map), "attack-read-foreign-obj1"); // 变体号跟着基号走
  assert.equal(normalizeCaseId("exp-10", map), "exp-10", "exp-1 的映射不许把 exp-10 一起吞掉");
  assert.equal(normalizeCaseId("business-list-own", map), "business-list-own", "非本族编号原样保留");
  assert.deepEqual(normalizeCaseIds({ "exp-1": "vulnerable", "exp-2": "blocked" }, map), { "attack-read-foreign": "vulnerable", "exp-2": "blocked" });
  // 没有映射时（官方口径）必须一个字符都不动
  assert.equal(normalizeCaseId("attack-read-foreign", null), "attack-read-foreign");
  assert.equal(canonicalBaseId(registered, "request.as"), "attack-read-foreign");
});

test("配方哈希不看键序：同一张表从文件或从内存来都得到同一个值", () => {
  const a = { version: "gb-recipe-1", family: "f", steps: [], verdict: { rule: "attack-repro" } };
  const b = { verdict: { rule: "attack-repro" }, steps: [], family: "f", version: "gb-recipe-1" };
  assert.equal(recipeSha256(a), recipeSha256(b));
  assert.notEqual(recipeSha256(a), recipeSha256({ ...a, family: "f2" }));
});

test("成绩目录只认合法草稿键：短键、带路径分隔的键都不落盘", () => {
  assert.equal(gradeRecordFile("/tmp/x", "A-0123456789abcdef0123456789abcdef").endsWith(`${KEY}.json`), true);
  assert.equal(gradeRecordFile("/tmp/x", "ab"), null);
  assert.equal(gradeRecordFile("/tmp/x", "../escape"), null);
  assert.equal(gradeRecordFile("", KEY), null);
});

test("成绩写读往返：哈希、草稿键、判卷器版本任一对不上就当没有成绩", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "gb-grade-"));
  try {
    const w = writeGradeRecord({ gradeDir: dir, record: gradeRecord() });
    assert.equal(w.ok, true);
    const r = readGradeRecord({ gradeDir: dir, draftKey: KEY, recipe: draftRecipe() });
    assert.equal(r.ok, true);
    assert.equal(r.record.familySlot, "idor-read");

    // 考完之后改了草稿（哪怕只改一句 note）→ 旧成绩不给新草稿背书
    const tampered = readGradeRecord({ gradeDir: dir, draftKey: KEY, recipe: draftRecipe({ steps: [...draftRecipe().steps, { id: "exp-3", action: "request.as", method: "POST", path: "{slot:readPath}" }] }) });
    assert.equal(tampered.ok, false);
    assert.match(tampered.whyNot, /哈希/);

    assert.equal(validateGradeRecord(gradeRecord({ draftKey: "B-" + KEY.slice(2) }), { draftKey: KEY, recipe: draftRecipe() }).ok, false, "不许借另一路的成绩");
    assert.equal(validateGradeRecord(gradeRecord({ gradeVersion: "gb-grade-0" }), { draftKey: KEY, recipe: draftRecipe() }).ok, false, "判卷器换版本要重考");
    assert.equal(validateGradeRecord(gradeRecord({ exams: [] }), { draftKey: KEY, recipe: draftRecipe() }).ok, false, "没有考卷等于没考");
    assert.equal(validateGradeRecord(gradeRecord({ pass: undefined }), { draftKey: KEY, recipe: draftRecipe() }).ok, false, "没有总判定");
    assert.equal(validateGradeRecord(gradeRecord({ registered: true }), { draftKey: KEY, recipe: draftRecipe() }).ok, false, "判卷器无权写注册状态");
    assert.equal(validateGradeRecord(gradeRecord({ version: "gb-draft-grade-0" }), { draftKey: KEY, recipe: draftRecipe() }).ok, false);
    // 红成绩仍是「有成绩」：过卷与否由 decideComparison 那一步判，不在读这一层抹掉
    const red = validateGradeRecord(gradeRecord({ pass: false, whyNot: "G2 没过" }), { draftKey: KEY, recipe: draftRecipe() });
    assert.equal(red.ok, true);
    assert.equal(readGradeRecord({ gradeDir: dir, draftKey: "A-ffffffffffffffffffffffffffffffff", recipe: draftRecipe() }).ok, false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("判卷顶替目录：装载的是草稿那张表，校验一步不少", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "gb-overlay-"));
  const envelope = { gradingOnly: true, familySlot: "idor-read", draftKey: KEY, recipe: draftRecipe() };
  try {
    // 没设环境变量：常规扫描读注册配方，顶替目录完全不存在于这条路径上
    delete process.env[RECIPES_OVERLAY_ENV];
    resetRecipeOverlayHits();
    assert.equal(loadRecipe("idor-read").steps[0].id, "attack-read-foreign");
    assert.deepEqual(recipeOverlayHits(), []);

    process.env[RECIPES_OVERLAY_ENV] = dir;
    resetRecipeOverlayHits();
    // 目录里还没有这一族的信封：读注册配方，且不算顶替（「没顶替」与「顶替失败」是两件事）
    assert.equal(loadRecipe("idor-read").steps[0].id, "attack-read-foreign");
    assert.deepEqual(recipeOverlayHits(), []);

    writeFileSync(path.join(dir, "idor-read.json"), JSON.stringify(envelope));
    resetRecipeOverlayHits();
    const shadowed = loadRecipe("idor-read");
    assert.equal(shadowed.steps[0].id, "exp-1", "顶替目录里那张表才是这一轮的执行表");
    assert.equal(shadowed.verdict.rule, "attack-repro");
    const hits = recipeOverlayHits();
    assert.equal(hits.length, 1);
    assert.equal(hits[0].recipeId, "idor-read");
    assert.equal(hits[0].overlayOf, KEY, "报告要能说出顶的是哪一张草稿——不能只说「用过顶替目录」");

    // 判据名对不上：顶替不等于可以改判据（红线 1）。用表内合法的另一个判据名，
    // 免得被动作表的「表外判据」先拦掉——那条查的是拼写，这一条查的是「谁说了算」。
    writeFileSync(path.join(dir, "idor-read.json"), JSON.stringify({ ...envelope, recipe: { ...draftRecipe(), verdict: { rule: "cross-proof" } } }));
    resetRecipeOverlayHits();
    assert.throws(() => loadRecipe("idor-read"), /判据名不符/);

    // 缺 gradingOnly：手写一份丢进目录不等于注册（红线 2/8）
    writeFileSync(path.join(dir, "idor-read.json"), JSON.stringify({ familySlot: "idor-read", recipe: draftRecipe() }));
    resetRecipeOverlayHits();
    assert.throws(() => loadRecipe("idor-read"), /gradingOnly/);

    // 信封说的族与文件名不符：顶替对象必须自己说得清顶的是哪一族
    writeFileSync(path.join(dir, "idor-read.json"), JSON.stringify({ ...envelope, familySlot: "sqli-injection" }));
    resetRecipeOverlayHits();
    assert.throws(() => loadRecipe("idor-read"), /族槽位/);

    // 表外的东西照样被动作表拒收（草稿没有特权）
    writeFileSync(path.join(dir, "idor-read.json"), JSON.stringify({ ...envelope, recipe: { ...draftRecipe(), steps: [{ id: "exp-1", action: "request.as", method: "GET", path: "/api/orders/7", identity: "attacker" }] } }));
    resetRecipeOverlayHits();
    assert.throws(() => loadRecipe("idor-read"), /执行器只按计划槽位/);
  } finally {
    delete process.env[RECIPES_OVERLAY_ENV];
    resetRecipeOverlayHits();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("顶替目录指向不存在的地点：当场抛错，绝不静默退回注册配方", () => {
  const missing = path.join(repoRoot, ".grader", "definitely-not-here");
  rmSync(missing, { recursive: true, force: true });
  process.env[RECIPES_OVERLAY_ENV] = missing;
  try {
    assert.throws(
      () => loadRecipe("idor-read"),
      (e) => e instanceof RecipeRejected && /静默退回注册配方/.test(e.message),
      "「考的是草稿」被写成「考的是注册配方」就是这条通路最坏的一块假绿灯"
    );
  } finally {
    delete process.env[RECIPES_OVERLAY_ENV];
    resetRecipeOverlayHits();
  }
});
