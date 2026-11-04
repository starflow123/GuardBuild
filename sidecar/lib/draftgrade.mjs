/**
 * 草稿判卷通路（任务 #202，第 14 项验收的后半句「各自过考卷」）：
 * 一张探索区草稿怎么变成一条可核对的考卷成绩，以及那条成绩怎么被双路结论读进去。
 *
 * 为什么需要这一层：判卷器只认 `sidecar/recipes/` 里已注册的配方，而探索区的产出永远是草稿
 * （`registered:false`，红线 2/8）。两边都没错，中间缺的是通路——双路的对比结论因此永远停在
 * 「没有自己的考卷成绩」。这一层把通路补上，同时把三条红线原样保住：
 *  - **判据不动**（红线 1）：草稿顶替的是某族的**执行表**，判定仍走 probe.mjs 里那段写死的代码；
 *  - **考卷不新造**（红线 1）：只复用 `benchmarks/exams/` 里人工写好的卷子，且只用开发集——
 *    冻结集是期末考，不能被一张还没拿到注册资格的草稿预先读过；
 *  - **结论只由判卷器落笔**（红线 4）：成绩记录由 `scripts/benchmark-grader.mjs --draft` 写，
 *    常规扫描这一侧**只读**，读不到就当没有成绩（退回），绝不自己造一条。
 *
 * 用例编号为什么要归一化：注册配方把基线步骤 id 写死成 `attack-read-foreign`，考卷的已知答案按它写；
 * 草稿的步骤 id 是 `exp-1`（探索区按试打顺序编号）。判卷前把「本轮实际落地的编号」映射回考卷的规范编号，
 * 报告的证据表仍按草稿原号落盘——映射是判卷侧的一步换算，不是替草稿改写事实。
 */
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, statSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { stepsWithAction, VERDICT_IMPL } from "./recipes.mjs";
import { GRADE_VERSION } from "./grader.mjs";

export const DRAFT_GRADE_VERSION = "gb-draft-grade-1";

/**
 * 草稿的动作 → 它能顶替哪一族的注册表。
 * 按**动作**映射而不是按模型给的 `family` 名字：族 id 在 `probe.mjs::buildCases` 里写死
 * （`baselineStep("idor-read")` 那三行），单测逐条回读锚点，防止「表里说能顶替、执行器已经不这么取表」。
 * 没进这张表的动作（例：`request.anonymous` 的匿名读族）判不了卷——那一族还是专用代码，
 * 没有可顶替的配方文件，如实拒收而不是硬塞给别的族。
 */
export const FAMILY_SLOT_BY_ACTION = {
  "request.as": { recipeId: "idor-read", anchorToken: 'baselineStep("idor-read")' },
  "payload.inject": { recipeId: "sqli-injection", anchorToken: 'baselineStep("sqli-injection", "payload.inject")' },
  "fs.traverse": { recipeId: "path-traversal", anchorToken: 'baselineStep("path-traversal", "fs.traverse")' },
};

/**
 * 辅助动作：它们挂在某一族的打击步上（换轴变体、归属人复读），本身不立一族。
 * 注册表里就有这种形状——`idor-read.json` 是 `request.as` + `request.variant` + `readback.ownership`，
 * 判卷按族顶替执行表时只认那个打击动作。所以一张草稿同时写了变体轴/交叉证明，不能读成「跨了 3 族」。
 * 表外又不在打击动作里的（例：`token.forge`）仍然是拒收：那说明这一族还没配方化，缺的是执行器。
 */
export const SUPPORTING_ACTIONS = ["request.variant", "readback.ownership"];

const DRAFT_KEY_RE = /^[A-Za-z0-9_-]{8,64}$/;

/** 配方内容的稳定哈希：键序不参与（同一张表从文件或从内存来都要得到同一个值） */
export function recipeSha256(recipe) {
  const norm = (v) => {
    if (Array.isArray(v)) return v.map(norm);
    if (v && typeof v === "object") return Object.fromEntries(Object.keys(v).sort().map((k) => [k, norm(v[k])]));
    return v ?? null;
  };
  return createHash("sha256").update(JSON.stringify(norm(recipe))).digest("hex");
}

/**
 * 这张草稿能顶替哪一族。返回 `{ok:false, whyNot}` 的三种情况都要写清下一步该做什么，
 * 不许只回一句「不支持」：提议者（和人）要知道缺的是执行器、是拆分、还是考卷。
 */
export function familySlotForDraft(recipe, { probeSource = "" } = {}) {
  const steps = Array.isArray(recipe?.steps) ? recipe.steps : [];
  if (!steps.length) return { ok: false, whyNot: "草稿一步都没有：没有打法可考" };
  const actions = [...new Set(steps.map((s) => s?.action).filter(Boolean))];
  const striking = actions.filter((a) => FAMILY_SLOT_BY_ACTION[a]);
  const supporting = actions.filter((a) => SUPPORTING_ACTIONS.includes(a));
  const unmapped = actions.filter((a) => !FAMILY_SLOT_BY_ACTION[a] && !SUPPORTING_ACTIONS.includes(a));
  if (unmapped.length) {
    const why = (a) =>
      a === "request.anonymous"
        ? `${a}（匿名读一族仍是专用代码，没有可顶替的配方表，见 M5 第 199 项）`
        : `${a}（既不是某一族的打击动作，也不在辅助动作 ${SUPPORTING_ACTIONS.join("/")} 里）`;
    return {
      ok: false,
      whyNot: `草稿里的 ${unmapped.map(why).join("、")} 没有可顶替的注册配方：判卷只能拿草稿顶替某一族的执行表，这一族还没配方化 → 走能力请求单或等 M5 配方化`,
      actions,
    };
  }
  if (!striking.length) {
    return {
      ok: false,
      whyNot: `草稿只有辅助步（${supporting.join("/") || "无"}）而没有打击步（已配方化的打击动作：${Object.keys(FAMILY_SLOT_BY_ACTION).join("/")}）：没有可顶替的执行表`,
      actions,
    };
  }
  const slots = [...new Set(striking.map((a) => FAMILY_SLOT_BY_ACTION[a].recipeId))];
  if (slots.length > 1) {
    return { ok: false, whyNot: `草稿跨了 ${slots.length} 族（${slots.join("、")}）：一次判卷只顶替一族一张考卷，请把草稿拆成单族`, actions };
  }
  const recipeId = slots[0];
  // 锚点按「动作 → 族」那条表项取，不能拿族名去下标（表是以动作作键的）。
  const anchor = striking.map((a) => FAMILY_SLOT_BY_ACTION[a]).find((e) => e.recipeId === recipeId).anchorToken;
  if (probeSource && !probeSource.includes(anchor)) {
    return { ok: false, whyNot: `执行器里已经找不到 ${anchor}：顶替表与代码对不上，判卷会考错东西（先修表再判卷）` };
  }
  if (!VERDICT_IMPL[recipeId]) return { ok: false, whyNot: `族 ${recipeId} 还没有写死的判卷实现（VERDICT_IMPL 缺项）` };
  const action = striking[0];
  const draftBase = stepsWithAction(recipe, action)[0]?.id ?? null;
  if (!draftBase) return { ok: false, whyNot: `草稿里没有 ${action} 这一步的执行位` };
  return { ok: true, recipeId, action, draftBaseId: draftBase, actions, supporting };
}

/** 注册表里同一动作的基线步骤 id（考卷的已知答案按它写） */
export function canonicalBaseId(registeredRecipe, action) {
  return stepsWithAction(registeredRecipe, action)[0]?.id ?? null;
}

/**
 * 用例编号映射表：草稿基线号 → 考卷规范号。
 * 只映射「以草稿基线号开头、且后面是结束或 -」的编号，所以 `exp-1` 命中而 `exp-10` 不会误命中；
 * 多候选后缀（`exp-1-2`）与变体号（`exp-1-obj1`）跟着基线号一起换，映射后仍是考卷认识的那批编号。
 */
export function buildCaseIdMap({ registeredRecipe, draftRecipe, action }) {
  const to = canonicalBaseId(registeredRecipe, action);
  const slot = familySlotForDraft(draftRecipe);
  if (!slot.ok) return { ok: false, whyNot: slot.whyNot };
  if (!to) return { ok: false, whyNot: `注册配方里找不到 ${action} 的基线步骤 id：考卷的已知答案无从映射` };
  return { ok: true, from: slot.draftBaseId, to, recipeId: slot.recipeId };
}

export function normalizeCaseId(id, map) {
  const s = String(id ?? "");
  if (!map?.from || !map?.to) return s;
  if (s === map.from) return map.to;
  if (s.startsWith(`${map.from}-`)) return `${map.to}${s.slice(map.from.length)}`;
  return s;
}

/** 判定表整体换算（判卷器只看换算后的编号；原始编号留在报告证据里） */
export function normalizeCaseIds(verdicts, map) {
  const out = {};
  for (const [id, v] of Object.entries(verdicts ?? {})) out[normalizeCaseId(id, map)] = v;
  return out;
}

/** 成绩记录落在草稿产物同目录的 grades/ 子目录里：判卷器写、扫描侧只读 */
export function gradeRecordFile(gradeDir, draftKey) {
  if (typeof gradeDir !== "string" || !gradeDir) return null;
  if (!DRAFT_KEY_RE.test(String(draftKey ?? ""))) return null;
  return join(gradeDir, `${draftKey}.json`);
}

function atomicWriteJson(file, data) {
  const tmp = `${file}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(data, null, 1), "utf8");
  renameSync(tmp, file);
}

/** 判卷器落成绩：provenance 就是这一路自己的草稿键，注册状态恒为 false */
export function writeGradeRecord({ gradeDir, record }) {
  const file = gradeRecordFile(gradeDir, record?.draftKey);
  if (!file) return { ok: false, whyNot: "成绩落盘被拒：草稿键或成绩目录不合法（不落半成品，也不落到别处）" };
  mkdirSync(dirname(file), { recursive: true });
  atomicWriteJson(file, { ...record, version: DRAFT_GRADE_VERSION });
  return { ok: true, file };
}

/**
 * 读一条成绩并核对它确实属于手上这张草稿：
 * 版本、判卷器版本、草稿键、配方内容哈希四项都要对得上，任一对不上就当作「没有成绩」。
 * 哈希不符意味着草稿在判卷之后被改过（或换了模型/换了菜单）——旧成绩不能给新草稿背书。
 */
export function validateGradeRecord(rec, { draftKey, recipe, gradeVersion = GRADE_VERSION } = {}) {
  if (!rec || typeof rec !== "object") return { ok: false, whyNot: "没有成绩记录" };
  if (rec.version !== DRAFT_GRADE_VERSION) return { ok: false, whyNot: `成绩记录版本不符（${rec.version} ≠ ${DRAFT_GRADE_VERSION}）` };
  if (rec.gradeVersion !== gradeVersion) return { ok: false, whyNot: `判卷器已换版本（成绩是 ${rec.gradeVersion}，当前 ${gradeVersion}）：这张草稿要重考` };
  if (String(rec.draftKey ?? "") !== String(draftKey ?? "")) return { ok: false, whyNot: "成绩的草稿键与手上这张不一致（不许借别的路的成绩）" };
  const sha = recipeSha256(recipe ?? null);
  if (!recipe || String(rec.recipeSha256 ?? "") !== sha) return { ok: false, whyNot: "成绩的配方哈希与手上这张不符：判卷之后草稿变过，旧成绩不背书" };
  if (!Array.isArray(rec.exams) || !rec.exams.length) return { ok: false, whyNot: "成绩里没有一张考卷：等于没考" };
  if (typeof rec.pass !== "boolean") return { ok: false, whyNot: "成绩没有总判定" };
  if (rec.registered !== false) return { ok: false, whyNot: "成绩记录自称已注册：判卷器无权注册，这条记录被污染" };
  return { ok: true };
}

export function readGradeRecord({ gradeDir, draftKey, recipe }) {
  const file = gradeRecordFile(gradeDir, draftKey);
  if (!file || !existsSync(file) || !statSync(file).isFile()) return { ok: false, whyNot: "这条草稿还没有考卷成绩", file: file ?? null };
  let rec = null;
  try {
    rec = JSON.parse(readFileSync(file, "utf8"));
  } catch (e) {
    return { ok: false, whyNot: `成绩记录读不出来：${e.message}`, file };
  }
  const v = validateGradeRecord(rec, { draftKey, recipe });
  return v.ok ? { ok: true, record: rec, file } : { ok: false, whyNot: v.whyNot, file };
}

/** 锚点回读：顶替表里的每条 anchorToken 必须还在执行器里（与动作表同一套规矩，防表格漂移） */
export function checkDraftGradeAnchors({ probeSource }) {
  const unresolved = [];
  for (const [action, m] of Object.entries(FAMILY_SLOT_BY_ACTION)) {
    if (!VERDICT_IMPL[m.recipeId]) unresolved.push({ action, why: `族 ${m.recipeId} 在 VERDICT_IMPL 里没有判卷实现` });
    else if (!String(probeSource ?? "").includes(m.anchorToken)) unresolved.push({ action, why: `执行器里找不到 ${m.anchorToken}` });
  }
  return { ok: unresolved.length === 0, checked: Object.keys(FAMILY_SLOT_BY_ACTION).length, unresolved };
}
