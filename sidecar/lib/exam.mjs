/**
 * 考卷（方案第 6、7 项）：一份**已注册配方**绑定一份考卷——漏洞版 / 加固版 / 干净对照。
 *
 * 与 recipes.mjs 同规矩：装载即校验，表外键、指向别处的加固版、声明「干净版该打中」都当场
 * 拒收，绝不「忽略多余键」。
 *
 * 冻结边界（红线 1、2）：考卷答案是仓库里的人工文件，只有这里读，运行期没有任何代码路径写它；
 * 判卷用的请求序列必须来自已注册配方；考卷声明的用例编号必须是该配方真能产出的那些——
 * 配方改了 id 而考卷没跟上要在这里当场红，而不是让判卷器永远判「打不中」。
 */
import { existsSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const EXAM_VERSION = "gb-exam-1";
export const EXAM_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "benchmarks", "exams");

const TOP_KEYS = ["version", "examId", "recipe", "family", "split", "vulnerable", "hardened", "clean", "repeat", "note"];
/**
 * 考卷分两堆（第 8 项）：dev 可以反复看、失败可以进调优；frozen 只判分，永远不进调优的输入。
 * 必填、没有默认值：一张没标过堆的考卷会被默认算成「能拿来调」，那正是过拟合的入口。
 */
export const EXAM_SPLITS = ["dev", "frozen"];
const VULNERABLE_KEYS = ["fixture", "expect", "note"];
const HARDENED_KEYS = ["derivedFrom", "patch", "note"];
const PATCH_KEYS = ["file", "search", "insertAfter"];
const CLEAN_KEYS = ["fixture", "note"];
/** 规格原文是「自动插一处补丁」；多于一处就不是「加固版跟着漏洞版走」，而是重写了一份靶子 */
export const MAX_DERIVED_PATCHES = 1;
/** G4 要连跑两次；上限是防有人拿重复跑当性能调优的口子 */
export const REPEAT_MIN = 2;
export const REPEAT_MAX = 4;

/**
 * 这张考卷的结果能不能进失败账本（= 调优唯一读得到的输入）。
 * 冻结集只判分不记账：拿冻结集上的失败去调提示词，考完就跟没考一样。
 */
export function feedsTuning(exam) {
  return exam?.split !== "frozen";
}

export class ExamRejected extends Error {
  constructor(examId, reasons) {
    const list = reasons ?? [String(examId)];
    super(`考卷被拒收（${examId}）：\n${list.map((r) => `  - ${r}`).join("\n")}`);
    this.name = "ExamRejected";
    this.examId = examId;
    this.reasons = list;
  }
}

function unknownKeys(obj, allowed) {
  return Object.keys(obj ?? {}).filter((k) => !allowed.includes(k));
}

function isStrArray(v) {
  return Array.isArray(v) && v.every((x) => typeof x === "string" && x.length > 0);
}

/**
 * 校验一份考卷声明。
 * @param {object} raw 考卷 JSON
 * @param {object} ctx
 * @param {(id:string)=>{family:string, caseIds:string[]}|null} ctx.lookupRecipe 已注册配方的索引；查不到即红线 2
 */
export function validateExam(raw, { lookupRecipe } = {}) {
  const rejections = [];
  const reject = (why) => rejections.push(why);
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return { ok: false, rejections: ["考卷必须是一个对象"] };
  }
  const examId = typeof raw.examId === "string" && raw.examId ? raw.examId : "(缺 examId)";

  if (raw.version !== EXAM_VERSION) reject(`version 必须是 ${EXAM_VERSION}，实为 ${JSON.stringify(raw.version)}`);
  for (const k of unknownKeys(raw, TOP_KEYS)) reject(`表外键 ${k}：考卷只能声明 ${TOP_KEYS.join(" / ")}，多余的一律拒收而不是忽略`);
  if (typeof raw.examId !== "string" || !raw.examId) reject("examId 缺失：账本与绿名单都要靠它定位这一份考卷");
  if (!EXAM_SPLITS.includes(raw.split)) {
    reject(`split 必须是 ${EXAM_SPLITS.join(" / ")} 之一，实为 ${JSON.stringify(raw.split)}：这张考卷要不要拿来调优必须写死，不给默认值`);
  }

  const recipeId = raw.recipe;
  const recipe = typeof recipeId === "string" ? lookupRecipe?.(recipeId) ?? null : null;
  if (!recipe) {
    reject(`配方 ${JSON.stringify(recipeId)} 未注册：判定用的请求序列必须来自 sidecar/recipes/ 里的表（红线 2）`);
  } else {
    if (raw.family !== recipe.family) reject(`family=${JSON.stringify(raw.family)} 与配方 ${recipeId} 的族名 ${recipe.family} 不一致：考卷不许挂到别的族上`);
  }

  // —— 漏洞版 ——
  const vuln = raw.vulnerable ?? {};
  for (const k of unknownKeys(vuln, VULNERABLE_KEYS)) reject(`vulnerable 有表外键 ${k}`);
  if (typeof vuln.fixture !== "string" || !vuln.fixture) reject("vulnerable.fixture 缺失：漏洞版考卷必须有靶子");
  if (!isStrArray(vuln.expect) || vuln.expect.length === 0) {
    reject("vulnerable.expect 必须是非空字符串数组：这一族该打中哪几条用例，写清楚");
  } else if (recipe) {
    const unknown = vuln.expect.filter((id) => !recipe.caseIds.includes(id));
    if (unknown.length) {
      reject(
        `vulnerable.expect 里有配方产不出的用例编号：${unknown.join(", ")}（配方 ${recipeId} 的步骤 id 只有 ${recipe.caseIds.join(", ")}）——` +
          `改了配方就该同时改考卷，否则判卷器会永远判「打不中」`
      );
    }
    const dupes = vuln.expect.filter((id, i) => vuln.expect.indexOf(id) !== i);
    if (dupes.length) reject(`vulnerable.expect 有重复编号：${[...new Set(dupes)].join(", ")}`);
  }

  // —— 加固版：只许从漏洞版派生，不许另指靶子 ——
  const hard = raw.hardened ?? {};
  for (const k of unknownKeys(hard, HARDENED_KEYS)) reject(`hardened 有表外键 ${k}`);
  if ("fixture" in hard) {
    reject("hardened 不许声明 fixture：加固版必须由漏洞版插补丁派生，禁止手写两份（第 7 项）");
  }
  if (hard.derivedFrom !== "vulnerable") reject(`hardened.derivedFrom 必须是 "vulnerable"，实为 ${JSON.stringify(hard.derivedFrom)}`);
  const patches = Array.isArray(hard.patch) ? hard.patch : [hard.patch];
  if (patches.some((p) => p == null)) reject("hardened.patch 缺失：没有补丁就没有加固版，考卷不成立");
  else if (patches.length > MAX_DERIVED_PATCHES) reject(`hardened.patch 只能有 ${MAX_DERIVED_PATCHES} 处，实为 ${patches.length} 处`);
  else {
    for (const [i, p] of patches.entries()) {
      for (const k of unknownKeys(p, PATCH_KEYS)) reject(`hardened.patch[${i}] 有表外键 ${k}`);
      for (const key of PATCH_KEYS) {
        if (typeof p?.[key] !== "string" || !p[key]) reject(`hardened.patch[${i}].${key} 缺失：派生要逐字锚定，不能靠事后人肉对代码`);
      }
    }
  }

  // —— 干净对照：不许声明「这里该打中」 ——
  const clean = raw.clean ?? {};
  for (const k of unknownKeys(clean, CLEAN_KEYS)) reject(`clean 有表外键 ${k}`);
  if (typeof clean.fixture !== "string" || !clean.fixture) reject("clean.fixture 缺失：没有干净对照就测不出「凭空造漏洞」");
  if ("expect" in clean) reject("clean 不许声明 expect：干净对照的期望是「一条都不报」，由判卷器写死，不由考卷给");

  const repeat = raw.repeat ?? REPEAT_MIN;
  if (!Number.isInteger(repeat) || repeat < REPEAT_MIN || repeat > REPEAT_MAX) {
    reject(`repeat 必须是 ${REPEAT_MIN}..${REPEAT_MAX} 的整数（连跑两次才算「结论一致」），实为 ${JSON.stringify(raw.repeat)}`);
  }

  return { ok: rejections.length === 0, rejections, examId, normalized: ok(rejections) ? normalize(raw, repeat) : null };
}

function ok(rejections) {
  return rejections.length === 0;
}

function normalize(raw, repeat) {
  const patches = Array.isArray(raw.hardened.patch) ? raw.hardened.patch : [raw.hardened.patch];
  return {
    version: raw.version,
    examId: raw.examId,
    recipe: raw.recipe,
    family: raw.family,
    split: raw.split,
    vulnerable: { fixture: raw.vulnerable.fixture, expect: [...raw.vulnerable.expect], note: raw.vulnerable.note ?? null },
    hardened: { derivedFrom: "vulnerable", patches, note: raw.hardened.note ?? null },
    clean: { fixture: raw.clean.fixture, note: raw.clean.note ?? null },
    repeat,
    note: raw.note ?? null,
  };
}

/** 从仓库根解析考卷里的相对靶子路径；越出 fixtures/ 一律拒（考卷不许把靶子指到私人项目上） */
export function resolveExamFixture(repoRoot, relative) {
  const abs = path.resolve(repoRoot, String(relative ?? ""));
  const fixturesRoot = path.join(repoRoot, "fixtures");
  const rel = path.relative(fixturesRoot, abs);
  if (!rel || rel.startsWith("..") || path.isAbsolute(rel)) return null;
  return abs;
}

/**
 * 装载整个考卷目录：任一一份不合规矩就整批抛错。
 * 「少一份考卷」不是错误——那是 not_graded，由判卷器如实呈现，不伪装成通过。
 */
export function loadExams({ repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", ".."), dir, lookupRecipe } = {}) {
  // 只接受字符串目录：调用方把「没指定」写成 null 时，绝不能用 null 去 existsSync——那会静默返回空批次，
  // 让「0 张考卷」伪装成一次正常跑完的判卷。没指定就等于用仓库目录。
  const examsDir = typeof dir === "string" ? dir : EXAM_DIR;
  const files = existsSync(examsDir) ? readdirSync(examsDir).filter((f) => f.endsWith(".json")).sort() : [];
  const exams = [];
  const failures = [];
  for (const file of files) {
    const parsed = readJson(path.join(examsDir, file));
    if (!parsed.ok) {
      failures.push({ file, examId: file.replace(/\.json$/, ""), reasons: [parsed.error] });
      continue;
    }
    const v = validateExam(parsed.value, { lookupRecipe });
    if (!v.ok) failures.push({ file, examId: v.examId, reasons: v.rejections });
    else exams.push({ ...v.normalized, file, repoRoot });
  }
  if (failures.length) {
    throw new ExamRejected("考卷批次", failures.flatMap((f) => f.reasons.map((r) => `${f.file} — ${r}`)));
  }
  for (const e of exams) {
    for (const [which, rel] of [
      ["vulnerable.fixture", e.vulnerable.fixture],
      ["clean.fixture", e.clean.fixture],
    ]) {
      const abs = resolveExamFixture(repoRoot, rel);
      if (!abs || !existsSync(abs)) throw new ExamRejected(e.examId, [`${which} 指向的靶子不存在或不在 fixtures/ 下：${rel}`]);
    }
  }
  return exams;
}

function readJson(file) {
  try {
    return { ok: true, value: JSON.parse(readFileSync(file, "utf8")) };
  } catch (e) {
    return { ok: false, error: `JSON 解析失败：${e.message}` };
  }
}

/**
 * 加固版派生（第 7 项）：把漏洞版工作区复制来之后，逐字锚定插一处补丁。
 * 锚点对不上就抛错——那说明考卷本身失效（靶子改了而补丁还写着旧代码），
 * 绝不能悄悄返回「加固版和漏洞版一模一样」，否则 G2 是在拿漏洞版考漏洞版。
 * @returns {{diff: string}} 补丁差异记录（进报告，供复核者看这一份加固版到底改了什么）
 */
export function deriveHardened({ workspace, patches }) {
  const records = [];
  for (const patch of patches ?? []) {
    const file = path.join(workspace, patch.file);
    if (!existsSync(file)) throw new ExamRejected("(派生)", [`补丁目标文件不存在：${patch.file}`]);
    const src = readFileSync(file, "utf8");
    const occurrences = src.split(patch.search).length - 1;
    if (occurrences === 0) {
      throw new ExamRejected("(派生)", [`补丁锚点未匹配（${patch.file}）：考卷写的是 ${JSON.stringify(patch.search).slice(0, 120)}，这份靶子里没有这段代码`]);
    }
    if (occurrences > 1) {
      throw new ExamRejected("(派生)", [`补丁锚点在 ${patch.file} 里出现 ${occurrences} 次：派生必须唯一命中，否则加固版改到哪一处说不清`]);
    }
    writeFileSync(file, src.replace(patch.search, `${patch.search}${patch.insertAfter}`));
    records.push({
      file: patch.file,
      anchor: patch.search,
      inserted: patch.insertAfter,
      beforeChars: src.length,
      afterChars: src.length + patch.insertAfter.length,
    });
  }
  const diff = records
    .map((r) => `--- ${r.file}\n+++ ${r.file} (derived hardened)\n@@ 锚点 ${JSON.stringify(r.anchor)}\n+${r.inserted.replace(/^\n/, "").split("\n").join("\n+")}`)
    .join("\n\n");
  return { diff, records };
}
