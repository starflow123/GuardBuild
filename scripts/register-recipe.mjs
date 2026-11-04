#!/usr/bin/env node
/**
 * 注册工具（人工闸门，方案第 6/9/10 项的落点）：把一张**已过考卷**的探索草稿落成 `sidecar/recipes/` 里的配方。
 *
 * 它存在的意义就一句话：**没有这条成绩，谁也注册不了**；有了这条成绩，注册仍然要人一个字一个字确认。
 * 红线 2/8 说「注册是人工动作」，红线 4 说「结论由代码落笔」——这两条要同时成立，就得有个东西
 * 只认判卷器落下的成绩记录，并且把人将要覆盖掉的能力差集摆在确认之前。
 *
 * 它**不做**的事（都要写出来，免得后来被当成做了）：
 *  - 不判卷：成绩来自 `node scripts/benchmark-grader.mjs --draft=<产物>`，本工具只读不写成绩；
 *  - 不改考卷、不碰失败账本与绿名单：那三样是判卷层与回归层的产物，注册工具没有写权限；
 *  - 不新造族：草稿考的是哪一族，就只能注册成哪一族。动作还没配方化的（如匿名读，M5 第 199 项）
 *    在这里会被告知「缺的是执行器，走能力请求单」，而不是被写进一张没人读的表。
 *
 * 默认是演练：只打印「能不能注册、为什么、会改成什么」。要真落文件必须同时给
 * `--write` 与 `--confirm=REGISTER`；丢掉的每一条既有步骤还要按 id 点名列进 `--drop=`，
 * 少点或多点一条都不写——「顺手覆盖掉三条变体轴」这种事不该由一次回车发生。
 *
 * 用法:
 *   node scripts/register-recipe.mjs --draft=<探索产物 json>
 *   node scripts/register-recipe.mjs --draft=<产物> --preview=/tmp/candidate.json
 *   node scripts/register-recipe.mjs --draft=<产物> --drop=attack-read-foreign-obj,... --write --confirm=REGISTER
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  buildCaseIdMap,
  familySlotForDraft,
  gradeRecordFile,
  normalizeCaseId,
  readGradeRecord,
  recipeSha256,
} from "../sidecar/lib/draftgrade.mjs";
import { RECIPE_VERSION } from "../sidecar/lib/actiontable.mjs";
import { VERDICT_IMPL, inspectRecipe, listRecipeIds, loadRecipe, RECIPES_OVERLAY_ENV, stepsWithAction } from "../sidecar/lib/recipes.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const recipesDir = path.join(repoRoot, "sidecar", "recipes");

function argValue(name) {
  const hit = process.argv.slice(2).find((a) => a.startsWith(`${name}=`));
  return hit ? hit.slice(name.length + 1) : null;
}

const draftFile = argValue("--draft");
const previewFile = argValue("--preview");
const dropList = (argValue("--drop") ?? "").split(",").map((s) => s.trim()).filter(Boolean);
const doWrite = process.argv.includes("--write");
const confirmed = argValue("--confirm") === "REGISTER";

const lines = [];
const say = (s = "") => lines.push(s);

/** 逐条核对，每条都要能单独回答「为什么不行」——拒收清单比一句「不合规」有用得多 */
const gates = [];
const check = (name, ok, whyNot) => {
  gates.push({ name, ok: ok === true, whyNot: ok ? null : whyNot ?? null });
  return ok === true;
};

function die(msg) {
  say(`[REGISTER] ${msg}`);
  console.log(lines.join("\n"));
  process.exit(2);
}

async function main() {
  if (!draftFile) {
    die("必须给 --draft=<探索产物 json>：这张工具只处理「一次真实探索留下的那份草稿」，不接受手抄的表");
  }
  if (String(process.env[RECIPES_OVERLAY_ENV] ?? "").trim()) {
    die(`${RECIPES_OVERLAY_ENV} 已设：顶替模式下读到的「注册配方」是被别的东西顶替过的，本工具在这种状态下不判断能力差集`);
  }
  const abs = path.resolve(draftFile);
  if (!existsSync(abs)) die(`草稿产物不存在：${abs}`);

  say("# 配方注册核对（人工闸门）");
  say("");
  say(`- 产物：\`${path.relative(repoRoot, abs).replace(/\\/g, "/")}\``);

  let art = null;
  try {
    art = JSON.parse(readFileSync(abs, "utf8"));
  } catch (e) {
    die(`产物读不出来：${e.message}`);
  }
  const draftKey = art?.draftKey ?? null;
  const draft = art?.draft ?? null;
  const recipe = draft?.recipe ?? null;
  say(`- 草稿键：\`${draftKey ?? "—"}\` · 自报族名 \`${recipe?.family ?? "—"}\` · 提议者 ${art?.proposal?.id ?? "single"} · 模型 ${art?.model ?? "—"}`);
  check("产物有 draftKey 与 draft.recipe", !!draftKey && !!recipe && Array.isArray(recipe?.steps), "缺 draftKey 或 draft.recipe：这不是探索区落下的产物");
  check("草稿自称未注册", draft?.registered === false, `draft.registered=${JSON.stringify(draft?.registered)}：已注册的东西不需要再注册一次`);
  check("草稿过动作表", draft?.tableOk === true, `被动作表拒收 ${(draft?.rejections ?? []).length} 处：先把表填满`);
  if (!check("四项前置都成立", gates.every((g) => g.ok), "见上面打 ✗ 的那几行")) return report();

  const probeSource = readFileSync(path.join(repoRoot, "sidecar", "lib", "probe.mjs"), "utf8");
  const slot = familySlotForDraft(recipe, { probeSource });
  if (!check("草稿顶替得了某一族", slot.ok, slot.whyNot)) return report();
  say(`- 按动作 \`${slot.action}\` 映射到族槽位 \`${slot.recipeId}\`（不是按模型自报的族名——族名是措辞，动作才是事实）`);

  // —— 成绩：只认判卷器写的那份文件，四项对得上才采信 ——
  const gradeDir = path.join(path.dirname(abs), "grades");
  const known = gradeRecordFile(gradeDir, draftKey);
  check("成绩文件路径合法", !!known, "草稿键不合成绩目录的命名规矩（不落半成品，也不读到别处）");
  const rec = readGradeRecord({ gradeDir, draftKey, recipe });
  if (!check("有可采信的考卷成绩", rec.ok, rec.whyNot)) return report();
  const g = rec.record;
  say(`- 成绩：\`${path.relative(repoRoot, rec.file).replace(/\\/g, "/")}\`（判卷器 ${g.gradeVersion}，实跑标签 \`${g.runLabel ?? "—"}\`，配方哈希 \`${String(g.recipeSha256 ?? "").slice(0, 12)}\` = 手上这张 \`${recipeSha256(recipe).slice(0, 12)}\`）`);
  for (const e of g.exams ?? []) {
    say(`  - ${e.examId}（${e.split === "frozen" ? "冻结集" : "开发集"}，连跑 ${e.repeat ?? "?"} 次）→ ${e.pass ? "过" : "没过"}：${Object.entries(e.gates ?? {}).map(([k, v]) => `${k}=${v}`).join(" ")}`);
  }
  check("成绩显示过卷", g.pass === true, g.whyNot ?? "成绩是红的：没过卷的草稿不能注册");
  check("成绩只跑过开发集", (g.exams ?? []).length > 0 && (g.exams ?? []).every((e) => e.split !== "frozen"), "成绩里出现冻结集：未注册草稿不该读过冻结卷");
  check("成绩未自称已注册", g.registered === false, "成绩记录自称已注册：这条记录被污染，判卷器无权写注册状态");
  if (!check("成绩三项都成立", gates.slice(-3).every((x) => x.ok), "见上面打 ✗ 的那几行")) return report();

  // —— 顶替目标：只能是考过的那一族，且那一族必须已有在执行器里跑的表 ——
  const registered = loadRecipe(slot.recipeId);
  const knownIds = listRecipeIds();
  check("这一族已在配方表里", knownIds.includes(slot.recipeId), `sidecar/recipes/${slot.recipeId}.json 不存在：注册成一张没人读的表等于没注册`);
  check("这一族有写死的判卷实现", !!VERDICT_IMPL[slot.recipeId], `族 ${slot.recipeId} 没有 VERDICT_IMPL 项：判据还没接进执行器`);
  if (!check("顶替目标成立", gates.slice(-2).every((x) => x.ok), "见上面打 ✗ 的那几行")) return report();

  const map = buildCaseIdMap({ registeredRecipe: registered, draftRecipe: recipe, action: slot.action });
  if (!check("用例编号能从考卷认的那个数起", map.ok, map.whyNot)) return report();
  say(`- 编号换算：\`${map.from}\` → \`${map.to}\`（考卷的已知答案按右边的写，草稿自己按左边的编号）`);

  const draftSteps = stepsWithAction(recipe, slot.action);
  if (!check("这一族的执行位只有一条", draftSteps.length === 1, `草稿有 ${draftSteps.length} 条 \`${slot.action}\` 步骤，而执行器只取第一条：注册会悄悄少打一条`)) return report();

  // —— 能力差集：注册是**整表替换**，所以必须说清替换掉什么 ——
  const registeredByAction = new Map();
  for (const s of registered.steps ?? []) {
    const list = registeredByAction.get(s.action) ?? [];
    list.push(s);
    registeredByAction.set(s.action, list);
  }
  const draftByAction = new Map();
  for (const s of recipe.steps ?? []) {
    const list = draftByAction.get(s.action) ?? [];
    list.push(s);
    draftByAction.set(s.action, list);
  }
  const lost = [];
  for (const [action, list] of registeredByAction) {
    const kept = draftByAction.get(action) ?? [];
    for (const s of list.slice(kept.length)) lost.push(s);
  }
  const extra = [];
  for (const [action, list] of draftByAction) {
    const have = registeredByAction.get(action) ?? [];
    for (const s of list.slice(have.length)) extra.push(s);
  }
  say("");
  say(`- 现在的表：${(registered.steps ?? []).length} 步 · 草稿的表：${(recipe.steps ?? []).length} 步 → 注册是整表替换，差集如下`);
  for (const s of lost) say(`  - **会丢掉** \`${s.id}\`（${s.action}${s.axis ? `，轴 ${s.axis}` : ""}）`);
  for (const s of extra) say(`  - 新增 \`${s.id ?? "(无 id)"}\`（${s.action}）`);
  const lostIds = lost.map((s) => s.id);
  const droppedOk = lostIds.length === dropList.length && lostIds.every((id) => dropList.includes(id));
  check("能力差集已被人逐条点名", lostIds.length === 0 || droppedOk,
    lostIds.length ? `这张草稿比现在的表少 ${lostIds.length} 条步骤（${lostIds.join("、")}）。确认要丢掉就把这些 id 原样列进 --drop=${lostIds.join(",")}：注册是整表替换，顺手抹掉这几条既有能力不该由一次回车发生` : "");

  // —— 要写的表：判据沿用这一族写死的那条，编号全部换回考卷认的规范号，出处留在文件里 ——
  // 换算走判卷同一把尺（normalizeCaseId）：`exp-1` → `attack-read-foreign`，
  // 挂在它下面的 `exp-1-enc`、`exp-1-proof` 也跟着换成 `attack-read-foreign-enc`。
  // 只换基线号而留下辅助步的草稿号，注册出来的表就是一半规范一半草稿，考卷与账本都对不上账。
  const fold = (id) => normalizeCaseId(id, map);
  const table = {
    version: RECIPE_VERSION,
    family: registered.family,
    title: `${registered.title ?? registered.family}（由探索草稿注册：${String(draftKey).slice(0, 12)}）`,
    registeredFrom: { draftKey, gradeRecord: path.relative(repoRoot, rec.file).replace(/\\/g, "/"), gradedAt: g.gradedAt ?? null, model: art?.model ?? null, proposal: art?.proposal?.id ?? null, draftFamily: recipe.family ?? null, droppedSteps: lostIds },
    steps: (recipe.steps ?? []).map((s) => ({ ...s, id: fold(s.id), uses: s.uses == null ? s.uses : fold(s.uses) })),
    verdict: { rule: VERDICT_IMPL[slot.recipeId].rule },
  };
  let inspect = { ok: true };
  try {
    inspectRecipe(table, slot.recipeId);
  } catch (e) {
    inspect = { ok: false, why: e?.reasons ? e.reasons.join("；") : e.message };
  }
  check("候选表过装载校验（与真注册同一条路）", inspect.ok, inspect.why);
  if (!check("以上全部成立", gates.every((x) => x.ok), "见上面打 ✗ 的那几行")) return report();

  const target = path.join(recipesDir, `${slot.recipeId}.json`);
  say("");
  say("## 候选表");
  say("");
  say("```json");
  say(JSON.stringify(table, null, 2));
  say("```");
  say("");
  if (previewFile) {
    const p = path.resolve(previewFile);
    mkdirSync(path.dirname(p), { recursive: true });
    writeFileSync(p, `${JSON.stringify(table, null, 2)}\n`, "utf8");
    say(`- 候选表已写到 --preview 指定的位置：${p}（这不是注册，sidecar/recipes/ 未变）`);
  }
  if (!doWrite) {
    say(`- 结论：**可以注册，但本轮没有注册**（未给 --write）。要落文件：--write --confirm=REGISTER${lostIds.length ? ` --drop=${lostIds.join(",")}` : ""}`);
    return report({ eligible: true, wrote: false });
  }
  if (!confirmed) {
    say("- 结论：**未注册**——`--write` 还缺 `--confirm=REGISTER`。这个字要人自己打，不是脚本代填。");
    return report({ eligible: true, wrote: false });
  }
  writeFileSync(target, `${JSON.stringify(table, null, 2)}\n`, "utf8");
  // 回读走「读文件 → 同一套装载校验」，不碰本进程的配方缓存：缓存里还是替换前那张表，拿它回读等于自证
  const reload = (() => {
    try {
      const parsed = JSON.parse(readFileSync(target, "utf8"));
      if (JSON.stringify(parsed) !== JSON.stringify(table)) return { ok: false, why: "落盘的文件与核对过的候选表不一致" };
      inspectRecipe(parsed, slot.recipeId);
      return { ok: true, sha: recipeSha256(parsed) };
    } catch (e) {
      return { ok: false, why: e?.reasons ? e.reasons.join("；") : e.message };
    }
  })();
  check("写入后立刻用装载校验回读", reload.ok, reload.why);
  say(`- 已注册：\`${path.relative(repoRoot, target).replace(/\\/g, "/")}\`${reload.ok ? `（回读校验通过，哈希 ${reload.sha.slice(0, 12)}）` : `（**回读被拒：${reload.why}**——文件已落但引擎不认，立刻 git checkout 回滚并报告）`}`);
  say("- 注册之后必须复核：`npm run bench:grader`（考卷从顶替模式换回注册模式）+ 白盒/黑盒基准。**这一步不由本工具代跑**：判卷的绿得由判卷层自己亮。");
  return report({ eligible: gates.every((x) => x.ok), wrote: true });
}

function report(extra = {}) {
  const failed = gates.filter((g) => !g.ok);
  say("");
  say("## 核对清单");
  say("");
  say("| 检查 | 结果 |");
  say("| --- | --- |");
  for (const g of gates) say(`| ${g.name} | ${g.ok ? "✓" : `**✗** ${g.whyNot ?? ""}`} |`);
  say("");
  say(failed.length ? `- 结论：**不能注册**，首要原因：${failed[0].whyNot ?? failed[0].name}` : `- 结论：${extra.wrote ? "已注册" : "可注册，本轮未注册"}`);
  say("- 本工具不写考卷、不写失败账本、不动绿名单；成绩只由 `benchmark-grader.mjs --draft` 产出，注册只由人确认。");
  console.log(lines.join("\n"));
  return failed.length ? 1 : 0;
}

main()
  .then((code) => process.exit(code))
  .catch((e) => {
    die(`异常：${e?.stack ?? e?.message ?? e}`);
  });
