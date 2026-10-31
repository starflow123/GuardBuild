/**
 * 配方化试点（M1-5）的等价性与拒收测试。
 * 运行：npm run test:sidecar
 *
 * 两件事分别要证：
 *  1. 「纯等价重构」是真的：同一批计划形状下，配方驱动的构建器与重构前逐字段同结论，
 *     连判据闭包的源码文本都要一致（判据是冻结项，重构不许顺手改它）。
 *  2. 表真的有牙齿：表外动作、词表外的变体轴、对不上实现判据名、槽位取不到候选种类，
 *     都在装载这一步就把整族用例卡住，而不是静悄悄少打一步。
 */
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  RecipeRejected,
  VERDICT_IMPL,
  baselineStep,
  checkAllRecipes,
  identityRole,
  inspectRecipe,
  loadRecipe,
  ownershipReadbacks,
  requestSteps,
  resolveCandidateKind,
  resolveRole,
  slotName,
  variantAxisSteps,
} from "../lib/recipes.mjs";
import { VARIANT_AXES } from "../lib/attackvariants.mjs";
import { snapshotIdorRead } from "../../scripts/recipe-snapshot.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const GOLDEN = path.join(here, "..", "..", "benchmarks", "idor-read-golden.json");

test("越权读一族：配方驱动的用例与重构前快照逐字段同结论（6 种计划形状）", () => {
  const golden = JSON.parse(fs.readFileSync(GOLDEN, "utf8"));
  const now = snapshotIdorRead();
  assert.deepEqual(Object.keys(now), Object.keys(golden), "形状集合本身不许悄悄变化");
  for (const shape of Object.keys(golden)) {
    assert.equal(now[shape].length, golden[shape].length, `${shape} 的用例条数变了`);
    // 逐条比对（含 verify/crossProof/contract 闭包源码），失败时点名是哪一条
    for (const [i, before] of golden[shape].entries()) {
      assert.deepEqual(now[shape][i], before, `${shape} 第 ${i + 1} 条（${before.id}）与快照不一致`);
    }
  }
});

test("仓库里的每张配方都进得了引擎（装载即校验，全部通过）", () => {
  const results = checkAllRecipes();
  assert.ok(results.length >= 2, `recipes/ 下应至少有试点的两张表，实际 ${results.length}`);
  const bad = results.filter((r) => !r.ok);
  assert.deepEqual(bad, [], "有配方装载即被拒收");
});

test("配方的结构就是这一族的形状：基线一条、三轴按声明顺序、复读挂在基线上", () => {
  const { recipe, step, kind } = baselineStep("idor-read");
  assert.equal(step.id, "attack-read-foreign", "基线步骤 id 决定用例编号，改名等于改历史报告的键");
  assert.equal(step.action, "request.as");
  assert.equal(identityRole(step), "attacker", "越权语义：发起者是一个普通身份，不是受害人");
  assert.equal(slotName(step), "readPath");
  assert.equal(kind, "read", "槽位必须换成引擎真正取候选的那一类");
  assert.deepEqual(
    variantAxisSteps(recipe).map((v) => v.axis),
    VARIANT_AXES,
    "轴的顺序决定变体用例编号的分配方式"
  );
  assert.ok(
    variantAxisSteps(recipe).every((v) => v.requiresPreRepro === true),
    "变体必须先在修复前复现才计入修复后验收（不认这种写法的入口不能当成被修好的证据）"
  );
  assert.equal(ownershipReadbacks(recipe)[0].uses, step.id, "交叉证明声明在基线打法上，同族变体沿用");
  assert.equal(recipe.verdict.rule, "attack-repro");
});

test("判卷实现的锚点还在代码里（配方引用的判据与实际执行的判卷代码不许脱钩）", () => {
  const root = path.join(here, "..", "..");
  const unresolved = [];
  for (const [recipeId, impl] of Object.entries(VERDICT_IMPL)) {
    let text = "";
    try {
      text = fs.readFileSync(path.join(root, impl.anchor.file), "utf8");
    } catch {
      unresolved.push({ recipeId, why: `${impl.anchor.file} 读不到` });
      continue;
    }
    if (!text.includes(impl.anchor.token)) unresolved.push({ recipeId, why: `${impl.anchor.file} 里已找不到 ${impl.anchor.token}` });
  }
  assert.deepEqual(unresolved, [], "有配方的判据引用指向了已经不存在的判卷代码");
});

function fork(mutate) {
  const base = JSON.parse(fs.readFileSync(path.join(here, "..", "recipes", "idor-read.json"), "utf8"));
  mutate(base);
  return base;
}

test("身份位只认保险库条目名：填成凭据值的配方装载即被拒收", () => {
  const bad = fork((r) => {
    r.steps[0].identity = "bearer eyJhbGciOiJIUzI1NiIs";
  });
  assert.throws(() => inspectRecipe(bad, "idor-read"), /凭据值/);
});

test("表外动作进不了引擎：写了执行器不做的动作，整族用例建不出来", () => {
  const bad = fork((r) => {
    r.steps[0].cookieJar = true; // 会话容器：Host 侧根本没这个参数，忽略它＝「说打了其实没打」
  });
  assert.throws(() => inspectRecipe(bad, "idor-read"), (e) => {
    assert.ok(e instanceof RecipeRejected);
    assert.match(e.message, /cookieJar/);
    assert.match(e.message, /没有 Cookie 容器/);
    return true;
  });
});

test("词表外的变体轴被拒收：轴名合法但没有展开器＝表上写着能做、代码里做不到", () => {
  const bad = fork((r) => {
    r.steps[1].axis = "host-header";
  });
  assert.throws(() => inspectRecipe(bad, "idor-read"), /没有它的展开器.*能力请求单/s);
});

test("判据名与实现不符被拒收：配方说按交叉证明判、代码其实按复现证据判", () => {
  const bad = fork((r) => {
    r.verdict = { rule: "cross-proof" };
  });
  assert.throws(() => inspectRecipe(bad, "idor-read"), /判据名不符/);
});

test("未接入判卷实现的新族文件不会被视为已支持", () => {
  const draft = fork((r) => {
    r.family = "sqli-blind";
  });
  assert.throws(() => inspectRecipe(draft, "sqli-blind"), /还没有写死的判卷实现/);
});

test("槽位取不到候选种类时拒收，不静默换槽位", () => {
  const bad = fork((r) => {
    r.steps[0].path = "{slot:ssrfPath}";
  });
  assert.throws(() => resolveCandidateKind(bad.steps[0], "idor-read"), /对应不上引擎会取用的计划槽位/);
});

test("配方文件缺失也是拒收，不是「这一族没有用例」", () => {
  assert.throws(() => loadRecipe("idor-does-not-exist"), (e) => {
    assert.ok(e instanceof RecipeRejected);
    assert.match(e.message, /找不到配方文件/);
    return true;
  });
});

test("角色在装载器里才落到具体身份：配方永远只见角色名", () => {
  const targets = { attacker: { name: "alice", user: { id: 1 } }, victim: { name: "bob", user: { id: 2 } }, admin: null };
  const step = requestSteps(loadRecipe("idor-read"))[0];
  assert.equal(identityRole(step), "attacker", "配方里存的是角色，不是保险库里的账号名");
  assert.equal(resolveRole(targets, identityRole(step)).name, "alice");
  assert.equal(resolveRole(targets, "nobody"), null, "不认识的角色不给身份");
});
