/**
 * 配方装载器：把 sidecar/recipes/*.json 读成引擎能执行的结构，**装载即校验**。
 *
 * 这一层是动作表（actiontable）的第一个真实消费方。没有它，表只是一份文档；
 * 有了它，「配方里写了执行器不做的动作」会变成装载失败、用例一条都建不出来，
 * 而不是静悄悄跳过那一步之后报一个漂亮的绿灯。
 *
 * 三条边界（与 docs/agent-attack-loop-plan.md 第六节红线一致）：
 *  1. 配方选**结构**（哪条打法、哪个身份、打哪个槽位、变体沿哪几条轴、按什么顺序、要不要修复前复现）；
 *     怎么发请求、怎么算「打穿」仍在写死的代码里——配方拿到的是名字，不是能力。
 *  2. 配方挑的轴必须在 `VARIANT_AXES` 词表内：轴名合法但没有展开器，等于「表上能做、代码里做不到」，
 *     这里同样拒收（拒收文案直接指向能力请求单）。
 *  3. 配方引用的判据名必须与真正执行它的那段写死代码对上。对不上就拒收——
 *     否则「配方说按交叉证明判、代码按状态码判」又是一块假绿灯。
 *
 * 期望文案（expect）与用例名一律由代码生成，不进配方：
 * 能改写「什么算期望结果」的文本，等于让提议者改判据。
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ACTIONS, RECIPE_VERSION, formatRejections, validateRecipe } from "./actiontable.mjs";
import { VARIANT_AXES } from "./attackvariants.mjs";

const RECIPES_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "recipes");

/**
 * 判卷模式的「配方顶替目录」（#202）：草稿从没注册过，而执行器只认 `sidecar/recipes/` 里的表，
 * 于是「拿考卷考一张草稿」此前根本没有通路——双路的结论因此永远停在「没有成绩」。
 * 这一层只开一个**判卷专用**的入口：目录由 `GUARDBUILD_RECIPES_OVERLAY` 给出，
 * 里面每份文件必须显式声明 `gradingOnly: true` 与它顶替的族名，装载的仍是同一套校验。
 *
 * 三条不许松的地方：
 *  - 环境变量给了但目录不存在 → 当场抛错，绝不静默退回注册配方（那会把「考的是草稿」写成「考的是注册配方」）；
 *  - 顶替文件里没有 `gradingOnly` 或族名与文件名不符 → 整份拒收（手写一张表丢进目录就想冒充注册配方，不行）；
 *  - 本进程用过哪些顶替，`recipeOverlayHits()` 全量留给报告披露——扫描报告不许看不出来自己跑的是草稿。
 *
 * 常量值必须与 `overlayDirOrNull()` 里那处字面读取同名（宿主契约测试只认字面形式）。
 */
export const RECIPES_OVERLAY_ENV = "GUARDBUILD_RECIPES_OVERLAY";

/** 哪些动作接受 path 参数：接受就得填成计划槽位，填成字面路径一律拒收（见 inspectRecipe） */
const ACTION_PARAMS = new Map(ACTIONS.map((a) => [a.name, new Set(a.params ?? [])]));

/** 试点族的判卷实现：配方引用别的判据名即拒收（anchor 由单测回读代码核实） */
export const VERDICT_IMPL = {
  "idor-read": { rule: "attack-repro", anchor: { file: "sidecar/lib/probe.mjs", token: "function verifyAttack" } },
  "idor-read-owner-visible": { rule: "business-regress", anchor: { file: "sidecar/lib/probe.mjs", token: "function verifyBusiness" } },
  "sqli-injection": { rule: "attack-repro", anchor: { file: "sidecar/lib/probe.mjs", token: "export function sqliProof" } },
  "path-traversal": { rule: "attack-repro", anchor: { file: "sidecar/lib/probe.mjs", token: "function traversalLeak" } },
};

/**
 * 载荷集与 canary 是**冻结项的名字**，不是可调参数：配方只能引用执行器真正在用的那一个。
 * 引用别的名字若被放行，报告里写的就是「按 X 载荷打的」，实际发的仍是写死的那套——
 * 这正是本项目要拒的那类字段，所以在这里整族拒收，并锚回真正定义载荷的代码。
 */
export const PAYLOAD_SETS = {
  "sqli-default": { desc: "随机基线 vs 永真/报错载荷", anchor: { file: "sidecar/lib/probe.mjs", token: "const SQLI_PAYLOADS = [" } },
  "traversal-default": { desc: "逐级加深的 ../ 穿越 + URL 编码变体", anchor: { file: "sidecar/lib/probe.mjs", token: "const TRAVERSAL_PAYLOADS = [" } },
};

/** 穿越判据比对的特征字段是按 package.json 写的（PKG_MARKERS），换 canary 得先换判卷代码 */
export const CANARY_FILES = {
  "package.json": { desc: "回读到它的特征字段即确证任意文件读取", anchor: { file: "sidecar/lib/probe.mjs", token: "const PKG_MARKERS = [" } },
};

/**
 * 各族执行器写死的请求形态。配方声明与它冲突的值一律拒收：
 * 「报告里的方法」与「实发的方法」不一致，也是一块假绿灯。
 */
export const FAMILY_SHAPE = {
  "sqli-injection": { methodFromPlan: true },
  "path-traversal": { method: "GET" },
};

/** 配方可引用的计划字段，以及真正读它的那段代码；引用一个没人读的字段等于许了个空承诺 */
export const PLAN_FIELDS = {
  ownerField: { anchor: { file: "sidecar/lib/probe.mjs", token: "function ownerOf" } },
  param: { anchor: { file: "sidecar/lib/probe.mjs", token: "function injectionReq" } },
};
const PLAN_REF_RE = /^\{plan\.([A-Za-z][A-Za-z0-9]*)\}$/;

/** 取 `{plan.x}` 里的字段名；不是合法引用返回 null */
export function planFieldName(ref) {
  const m = PLAN_REF_RE.exec(String(ref ?? "").trim());
  return m ? m[1] : null;
}

/**
 * 按配方声明的引用，从候选的注入声明里取参数名。
 * 取值仍来自计划（配方永远写不出参数名字面量），缺省时交给执行器的默认参数名。
 */
export function resolvePlanField(ref, obj, recipeId, where) {
  const field = planFieldName(ref);
  if (!field) {
    throw new RecipeRejected(recipeId, `${where} 给了 ${JSON.stringify(ref)}：这一项必须是 {plan.字段} 引用，配方不许写死参数名（写死了就是替计划编造字段）`);
  }
  if (!PLAN_FIELDS[field]) {
    throw new RecipeRejected(
      recipeId,
      `${where} 引用了 {plan.${field}}：引擎不会读这个字段（可引用：${Object.keys(PLAN_FIELDS).join("/")}）——换字段属于能力增长，请走能力请求单`
    );
  }
  return obj?.[field];
}

/** 计划槽位 → planner 候选种类（写死的对应关系，配方看不到这一层；探索区按它反查槽位） */
export const SLOT_KIND = {
  readPath: "read",
  cancelPath: "cancel",
  unauthReadPath: "unauthRead",
  sqliPath: "sqli",
  traversalPath: "traversal",
};

/** 身份角色 → targets 里的角色对象；角色是「哪个保险库条目」的抽象，配方永远拿不到凭据值 */
const ROLE_TARGET = { attacker: "attacker", victim: "victim", admin: "admin" };

/** 身份角色 → 该角色名下用于正向断言的对象槽位（"own" 就是字面意思：自己名下的那个） */
const ROLE_OWN_TARGET = { attacker: "ownReadTarget", victim: "victimOwnTarget", admin: "adminOwnTarget" };

/**
 * 主角色缺席时的退回目标。退回谁是引擎的性质（身份成对种入），不是配方的可调项：
 * 配方只声明首选身份，缺席时整族用例不至于静默消失，但报告里写的仍是实际用的那个名字。
 */
const ROLE_FALLBACK = { attacker: "victim", victim: "attacker", admin: null };

export class RecipeRejected extends Error {
  constructor(recipeId, detail) {
    super(`配方被拒收（${recipeId}）：\n${detail}`);
    this.name = "RecipeRejected";
    this.recipeId = recipeId;
  }
}

export function listRecipeIds() {
  try {
    return fs
      .readdirSync(RECIPES_DIR)
      .filter((f) => f.endsWith(".json"))
      .map((f) => f.slice(0, -".json".length))
      .sort();
  } catch {
    return [];
  }
}

const cache = new Map();
/** 本进程用过的顶替记录（recipeId -> {file, overlayOf, dir}），报告拿它披露「这一轮跑的不是注册配方」 */
const overlayHits = new Map();

/** 顶替目录：没设环境变量就是 null（常规扫描不受影响）；设了就必须是一个真实目录 */
function overlayDirOrNull() {
  // 这里必须把环境变量名整个写死（宿主那条 Rust 契约测试只认字面形式，改名成变量下标就等于把这条开关
  // 从契约网里漏出去——漏出去的症状是「草稿顶替静默不生效且不报错」）。
  const raw = process.env.GUARDBUILD_RECIPES_OVERLAY;
  if (typeof raw !== "string" || !raw.trim()) return null;
  const dir = path.resolve(raw.trim());
  if (!fs.existsSync(dir) || !fs.statSync(dir).isDirectory()) {
    throw new RecipeRejected("(overlay)", `${RECIPES_OVERLAY_ENV} 指向的目录不存在或不是目录：${dir}——判卷模式不许静默退回注册配方`);
  }
  return dir;
}

/** 这一轮从顶替目录装载过哪些族（报告与 e2e 读它，不信声明只信装载记录） */
export function recipeOverlayHits() {
  return [...overlayHits.entries()].map(([recipeId, h]) => ({ recipeId, ...h }));
}

/** 单测与逐草稿判卷之间要清掉记录，否则第二张草稿的成绩会带着第一张的披露 */
export function resetRecipeOverlayHits() {
  overlayHits.clear();
  for (const k of [...cache.keys()]) if (k.includes("\0")) cache.delete(k);
}

/**
 * 顶替文件的格式：外层是判卷信封，内层 `recipe` 才是被考的那张表。
 * 信封存在的意义是让「这是草稿」这件事写在文件里，而不是靠目录名或调用方口头保证。
 */
function readOverlayRecipeFile(file, recipeId, dir) {
  let wrapped = null;
  try {
    wrapped = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (e) {
    throw new RecipeRejected(recipeId, `顶替文件 JSON 解析失败（${file}）：${e.message}`);
  }
  if (!wrapped || typeof wrapped !== "object" || wrapped.gradingOnly !== true) {
    throw new RecipeRejected(recipeId, `顶替文件缺 gradingOnly: true（${file}）：只有判卷器写出的草稿允许顶替注册配方，手写一份丢进目录不等于注册（红线 2/8）`);
  }
  if (wrapped.familySlot !== recipeId) {
    throw new RecipeRejected(recipeId, `顶替文件声明的族槽位是 ${JSON.stringify(wrapped.familySlot)}，文件名却是 ${recipeId}：顶替对象必须自己说得清顶的是哪一族`);
  }
  if (!wrapped.recipe || typeof wrapped.recipe !== "object") {
    throw new RecipeRejected(recipeId, `顶替文件缺 recipe 段（${file}）`);
  }
  overlayHits.set(recipeId, { file, overlayOf: String(wrapped.draftKey ?? ""), dir });
  return wrapped.recipe;
}

/**
 * 检查一张已经解析好的配方（装载与单测走同一条路，不给测试开后门）：
 * 动作表校验 → 轴词表校验 → 判据实现校验。任一步不过就抛 RecipeRejected。
 * 顺序是先看「表填得对不对」再看「引擎有没有实现它」：提议者要先知道自家表格的错，
 * 而不是被一句「还没接入」挡回去，改完再撞第二堵墙。
 */
export function inspectRecipe(recipe, recipeId) {
  const validation = validateRecipe(recipe);
  if (!validation.ok) throw new RecipeRejected(recipeId, formatRejections(validation));

  for (const step of variantAxisSteps(recipe)) {
    if (!VARIANT_AXES.includes(step.axis)) {
      throw new RecipeRejected(
        recipeId,
        `轴 ${step.axis} 在动作表里合法，但引擎没有它的展开器（已注册：${VARIANT_AXES.join("/")}）——请走能力请求单注册新轴，不是改配方措辞`
      );
    }
  }

  const shape = FAMILY_SHAPE[recipeId] ?? {};
  for (const step of Array.isArray(recipe.steps) ? recipe.steps : []) {
    const where = `步骤 ${step?.id}`;
    if (ACTION_PARAMS.get(step.action)?.has("path")) {
      if (!slotName(step)) {
        throw new RecipeRejected(
          recipeId,
          `${where} 的目标位置给了 ${JSON.stringify(step.path)}：执行器只按计划槽位里的候选发请求，配方写死一条路径就是「报告里写的地址」与「实发的地址」不一致`
        );
      }
      resolveCandidateKind(step, recipeId);
    }
    if (step.method != null) {
      if (shape.methodFromPlan) {
        throw new RecipeRejected(
          recipeId,
          `${where} 写了 method=${JSON.stringify(step.method)}：本族的方法由计划的注入通道决定（body→POST，query/params→GET），配方写死方法只会让报告与实发不一致`
        );
      }
      if (shape.method && step.method !== shape.method) {
        throw new RecipeRejected(recipeId, `${where} 写了 method=${JSON.stringify(step.method)}：执行器这一族只会发 ${shape.method}（换方法属于能力增长）`);
      }
    }
    if (step.payloadSet != null && !PAYLOAD_SETS[step.payloadSet]) {
      throw new RecipeRejected(
        recipeId,
        `${where} 的载荷集 ${JSON.stringify(step.payloadSet)} 不存在（已注册：${Object.keys(PAYLOAD_SETS).join("/")}）——新增载荷集＝新增攻击能力，要人开发、过考卷后注册（走能力请求单），不是改配方措辞`
      );
    }
    if (step.canary != null && !CANARY_FILES[step.canary]) {
      throw new RecipeRejected(
        recipeId,
        `${where} 的 canary ${JSON.stringify(step.canary)} 不存在（已注册：${Object.keys(CANARY_FILES).join("/")}）——判据的特征字段集是按它写死的，换 canary 得先改判卷代码并重新过考卷`
      );
    }
    for (const [key, value] of Object.entries(step)) {
      if (typeof value !== "string" || !value.startsWith("{plan")) continue;
      resolvePlanField(value, {}, recipeId, `${where}.${key}`);
    }
  }

  const impl = VERDICT_IMPL[recipeId];
  if (!impl) {
    throw new RecipeRejected(recipeId, `试点族还没有写死的判卷实现（已接入：${Object.keys(VERDICT_IMPL).join("/")}）`);
  }
  if (recipe.verdict?.rule !== impl.rule) {
    throw new RecipeRejected(
      recipeId,
      `判据名不符：配方引用 ${recipe.verdict?.rule}，实际执行它的是 ${impl.rule}（${impl.anchor.file}）——改判据请动判卷代码并重新过考卷，不是动配方`
    );
  }
  return recipe;
}

/**
 * 装载一张配方：读文件 → JSON 解析 → inspectRecipe 全套校验。
 * 不过就抛 RecipeRejected，调用方（buildCases）不许回退到写死的结构。
 * 设了顶替目录且该族有顶替文件时，装载的是顶替文件里的表——校验一步不少（判据名、槽位、载荷集照查）。
 */
export function loadRecipe(recipeId) {
  const dir = overlayDirOrNull();
  const cacheKey = dir ? `${dir}\0${recipeId}` : recipeId;
  if (cache.has(cacheKey)) return cache.get(cacheKey);
  const file = path.join(RECIPES_DIR, `${recipeId}.json`);
  const shadow = dir ? path.join(dir, `${recipeId}.json`) : null;
  let recipe = null;
  if (shadow && fs.existsSync(shadow)) {
    recipe = readOverlayRecipeFile(shadow, recipeId, dir);
  } else {
    let raw = null;
    try {
      raw = fs.readFileSync(file, "utf8");
    } catch {
      throw new RecipeRejected(recipeId, `找不到配方文件 ${path.relative(path.join(RECIPES_DIR, "..", ".."), file)}`);
    }
    try {
      recipe = JSON.parse(raw);
    } catch (e) {
      throw new RecipeRejected(recipeId, `JSON 解析失败：${e.message}`);
    }
  }
  inspectRecipe(recipe, recipeId);
  cache.set(cacheKey, recipe);
  return recipe;
}

/** 按动作取族内步骤（顺序即构建顺序）：请求族用 request.as，注入/穿越族用各自的动作 */
export function stepsWithAction(recipe, action) {
  return (Array.isArray(recipe?.steps) ? recipe.steps : []).filter((s) => s?.action === action);
}

/** 请求类步骤（真正发出去的那些），顺序即用例构建顺序 */
export function requestSteps(recipe) {
  return stepsWithAction(recipe, "request.as");
}

/** 变体轴步骤，按配方声明顺序返回（顺序决定同一份候选下的用例编号分配） */
export function variantAxisSteps(recipe) {
  return stepsWithAction(recipe, "request.variant").map((s) => ({
    id: s.id,
    uses: s.uses,
    axis: s.axis,
    label: s.label ?? s.axis,
    requiresPreRepro: s.requiresPreRepro === true,
  }));
}

/** 归属人复读步骤（交叉证明挂在哪一步上） */
export function ownershipReadbacks(recipe) {
  return stepsWithAction(recipe, "readback.ownership");
}

/** 从 `{slot:readPath}` 取出槽位名 */
export function slotName(step) {
  const m = /^\{slot:([a-zA-Z]+)\}$/.exec(String(step?.path ?? "").trim());
  return m ? m[1] : null;
}

/** 槽位 → planCandidates 的候选种类；对不上返回 null（调用方拒收，绝不静默换槽位） */
export function candidateKindFor(step) {
  const slot = slotName(step);
  return slot ? SLOT_KIND[slot] ?? null : null;
}

/** 要一个能用值：配方声明的目标位置必须落在引擎真会取用的计划槽位上 */
export function resolveCandidateKind(step, recipeId) {
  const kind = candidateKindFor(step);
  if (!kind) {
    throw new RecipeRejected(
      recipeId,
      `步骤 ${step?.id} 声明的目标位置 ${step?.path} 对应不上引擎会取用的计划槽位（可用：${Object.keys(SLOT_KIND).join("/")}）——换槽位属于能力增长，请走能力请求单`
    );
  }
  return kind;
}

/**
 * 取一族声明打法的那条基线步骤，并把它声明的槽位换成计划里的候选种类。
 * 槽位对不上候选种类＝配方指向了引擎不会取用的位置，拒收
 * （静默换槽位会让报告里写的地址和实际打的地址不是一回事）。
 */
export function baselineStep(recipeId, action = "request.as") {
  const recipe = loadRecipe(recipeId);
  const step = stepsWithAction(recipe, action)[0];
  if (!step) {
    throw new RecipeRejected(recipeId, `配方里没有 ${action} 步骤：没有这一步，这一族一条用例也建不出来`);
  }
  return { recipe, step, kind: resolveCandidateKind(step, recipeId) };
}

export function identityRole(step) {
  return String(step?.identity ?? "");
}

/**
 * 角色 → 本次扫描选定的身份对象。
 * 主角色缺席时退回另一个已种入的主体：目标身份是成对种入的（攻击者/受害人），
 * 少一个不应导致整族用例消失，但退回哪一个由引擎决定，配方不参与。
 */
export function resolveRolePreferred(targets, role) {
  const primary = resolveRole(targets, role);
  if (primary?.name) return primary;
  const fallback = ROLE_FALLBACK[role];
  const alt = fallback ? targets?.[fallback] : null;
  return alt?.name ? alt : null;
}

/** 角色 → 本次扫描选定的身份对象（含 name 与 user），配方里的名字在这一步才落到具体保险库条目 */
export function resolveRole(targets, role) {
  const key = ROLE_TARGET[role];
  return key ? targets?.[key] ?? null : null;
}

/** 角色 → 该角色名下的对象（正向断言用），没有对应槽位时返回 null */
export function ownTargetFor(targets, role) {
  const key = ROLE_OWN_TARGET[role];
  return key ? targets?.[key] ?? null : null;
}

/** 全部配方的装载结果：单测用它断言「仓库里的每张表都进得了引擎」 */
export function checkAllRecipes() {
  return listRecipeIds().map((id) => {
    try {
      loadRecipe(id);
      return { id, ok: true };
    } catch (e) {
      return { id, ok: false, why: e.message };
    }
  });
}

export const RECIPE_FILE_VERSION = RECIPE_VERSION;
