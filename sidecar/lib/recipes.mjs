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
import { RECIPE_VERSION, formatRejections, validateRecipe } from "./actiontable.mjs";
import { VARIANT_AXES } from "./attackvariants.mjs";

const RECIPES_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "recipes");

/** 试点族的判卷实现：配方引用别的判据名即拒收（anchor 由单测回读代码核实） */
export const VERDICT_IMPL = {
  "idor-read": { rule: "attack-repro", anchor: { file: "sidecar/lib/probe.mjs", token: "function verifyAttack" } },
  "idor-read-owner-visible": { rule: "business-regress", anchor: { file: "sidecar/lib/probe.mjs", token: "function verifyBusiness" } },
};

/** 计划槽位 → planner 候选种类（写死的对应关系，配方看不到这一层） */
const SLOT_KIND = { readPath: "read", cancelPath: "cancel", unauthReadPath: "unauthRead" };

/** 身份角色 → targets 里的角色对象；角色是「哪个保险库条目」的抽象，配方永远拿不到凭据值 */
const ROLE_TARGET = { attacker: "attacker", victim: "victim", admin: "admin" };

/** 身份角色 → 该角色名下用于正向断言的对象槽位（"own" 就是字面意思：自己名下的那个） */
const ROLE_OWN_TARGET = { attacker: "ownReadTarget", victim: "victimOwnTarget", admin: "adminOwnTarget" };

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
 */
export function loadRecipe(recipeId) {
  if (cache.has(recipeId)) return cache.get(recipeId);
  const file = path.join(RECIPES_DIR, `${recipeId}.json`);
  let raw = null;
  try {
    raw = fs.readFileSync(file, "utf8");
  } catch {
    throw new RecipeRejected(recipeId, `找不到配方文件 ${path.relative(path.join(RECIPES_DIR, "..", ".."), file)}`);
  }
  let recipe = null;
  try {
    recipe = JSON.parse(raw);
  } catch (e) {
    throw new RecipeRejected(recipeId, `JSON 解析失败：${e.message}`);
  }
  inspectRecipe(recipe, recipeId);
  cache.set(recipeId, recipe);
  return recipe;
}

/** 单步动作类型筛选 */
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
 * 取一族的第一条 request.as 作为基线打法，并把它声明的槽位换成计划里的候选种类。
 * 槽位对不上候选种类＝配方指向了引擎不会取用的位置，拒收
 * （静默换槽位会让报告里写的地址和实际打的地址不是一回事）。
 */
export function baselineStep(recipeId) {
  const recipe = loadRecipe(recipeId);
  const step = requestSteps(recipe)[0];
  if (!step) {
    throw new RecipeRejected(recipeId, "配方里没有任何 request.as 步骤：没有请求，这一族一条用例也建不出来");
  }
  return { recipe, step, kind: resolveCandidateKind(step, recipeId) };
}

export function identityRole(step) {
  return String(step?.identity ?? "");
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
