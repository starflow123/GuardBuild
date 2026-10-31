/**
 * 配方化放量（M1-5b）：SQL 注入族与路径穿越（敏感文件泄露）族的等价性与拒收测试。
 * 运行：npm run test:sidecar
 *
 * 与越权读一族同一套证据标准：
 *  1. 「纯等价重构」是真的——同一批计划形状下，配方驱动的构建器与重构前逐字段同结论，
 *     含 send/verify/crossProof/impact 判据闭包的源码文本。
 *  2. 冻结项的引用有牙齿——载荷集名、canary、方法形态、计划字段引用、判据名，
 *     任一对不上执行器的真实形状就在装载这一步整族拒收。
 */
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  CANARY_FILES,
  PAYLOAD_SETS,
  PLAN_FIELDS,
  RecipeRejected,
  VERDICT_IMPL,
  baselineStep,
  checkAllRecipes,
  identityRole,
  inspectRecipe,
  loadRecipe,
  planFieldName,
  resolvePlanField,
  resolveRolePreferred,
  slotName,
} from "../lib/recipes.mjs";
import {
  snapshotPathTraversal,
  snapshotSqliInjection,
} from "../../scripts/recipe-snapshot.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const recipeFile = (id) => path.join(here, "..", "recipes", `${id}.json`);

function checkEquivalence(goldenName, snapshotFn, label) {
  const golden = JSON.parse(fs.readFileSync(path.join(here, "..", "..", "benchmarks", goldenName), "utf8"));
  const now = snapshotFn();
  assert.deepEqual(Object.keys(now), Object.keys(golden), `${label}：形状集合本身不许悄悄变化`);
  for (const shape of Object.keys(golden)) {
    assert.equal(now[shape].length, golden[shape].length, `${label} · ${shape} 的用例条数变了`);
    for (const [i, before] of golden[shape].entries()) {
      assert.deepEqual(now[shape][i], before, `${label} · ${shape} 第 ${i + 1} 条（${before.id}）与快照不一致`);
    }
  }
}

test("SQL 注入族：配方驱动的用例与重构前快照逐字段同结论（7 种计划形状）", () => {
  checkEquivalence("sqli-injection-golden.json", snapshotSqliInjection, "SQL 注入");
});

test("路径穿越族：配方驱动的用例与重构前快照逐字段同结论（6 种计划形状）", () => {
  checkEquivalence("path-traversal-golden.json", snapshotPathTraversal, "路径穿越");
});

test("仓库里的每张配方都进得了引擎（装载即校验，全部通过）", () => {
  const results = checkAllRecipes();
  assert.ok(results.length >= 4, `recipes/ 下应至少有试点的四张表，实际 ${results.length}`);
  const bad = results.filter((r) => !r.ok);
  assert.deepEqual(bad, [], "有配方装载即被拒收");
});

test("两张新配方声明的结构与执行器一致：槽位、参数引用、判据名", () => {
  const sqli = baselineStep("sqli-injection", "payload.inject");
  assert.equal(sqli.step.id, "attack-sql-injection", "基线步骤 id 决定用例编号，改名等于改历史报告的键");
  assert.equal(sqli.kind, "sqli", "槽位必须换成引擎真正取候选的那一类");
  assert.equal(slotName(sqli.step), "sqliPath");
  assert.equal(identityRole(sqli.step), "attacker");
  assert.equal(sqli.step.payloadSet, "sqli-default");
  assert.equal(sqli.recipe.verdict.rule, "attack-repro");

  const trav = baselineStep("path-traversal", "fs.traverse");
  assert.equal(trav.step.id, "attack-path-traversal");
  assert.equal(trav.kind, "traversal");
  assert.equal(slotName(trav.step), "traversalPath");
  assert.equal(trav.step.canary, "package.json");
  assert.equal(trav.step.method, "GET");
  assert.equal(trav.recipe.verdict.rule, "attack-repro");

  // 引用的名字必须真有人实现：这些表就是「引用即承诺」的那一份清单
  assert.ok(PAYLOAD_SETS[sqli.step.payloadSet], "载荷集名没有对应实现");
  assert.ok(CANARY_FILES[trav.step.canary], "canary 没有对应的判据特征集");
  assert.equal(planFieldName(sqli.step.param), "param");
  assert.ok(PLAN_FIELDS.param, "参数名引用没有对应的取值代码");
});

test("冻结项的锚点还在代码里：载荷集、canary、判卷实现与配方不许脱钩", () => {
  const root = path.join(here, "..", "..");
  const unresolved = [];
  const tables = [
    ["VERDICT_IMPL", VERDICT_IMPL],
    ["PAYLOAD_SETS", PAYLOAD_SETS],
    ["CANARY_FILES", CANARY_FILES],
    ["PLAN_FIELDS", PLAN_FIELDS],
  ];
  for (const [tableName, table] of tables) {
    for (const [name, spec] of Object.entries(table)) {
      const anchor = spec.anchor ?? spec;
      let text = "";
      try {
        text = fs.readFileSync(path.join(root, anchor.file), "utf8");
      } catch {
        unresolved.push({ tableName, name, why: `${anchor.file} 读不到` });
        continue;
      }
      if (!text.includes(anchor.token)) unresolved.push({ tableName, name, why: `${anchor.file} 里已找不到 ${anchor.token}` });
    }
  }
  assert.deepEqual(unresolved, [], "有引用指向了已经不存在的实现");
});

function fork(id, mutate) {
  const base = JSON.parse(fs.readFileSync(recipeFile(id), "utf8"));
  mutate(base);
  return base;
}

test("SQL 注入族不许写死方法：方法由计划的注入通道决定，写死就是报告与实发不一致", () => {
  const bad = fork("sqli-injection", (r) => {
    r.steps[0].method = "POST";
  });
  assert.throws(() => inspectRecipe(bad, "sqli-injection"), (e) => {
    assert.ok(e instanceof RecipeRejected);
    assert.match(e.message, /方法由计划的注入通道决定/);
    return true;
  });
});

test("穿越族的方法写不成别的样子：执行器这一族只发 GET", () => {
  const bad = fork("path-traversal", (r) => {
    r.steps[0].method = "POST";
  });
  assert.throws(() => inspectRecipe(bad, "path-traversal"), /只会发 GET/);
});

test("载荷集是冻结项的名字：不存在的载荷集被拒收，而不是照常发写死的那套", () => {
  const bad = fork("sqli-injection", (r) => {
    r.steps[0].payloadSet = "sqli-timeout-blind";
  });
  assert.throws(() => inspectRecipe(bad, "sqli-injection"), (e) => {
    assert.ok(e instanceof RecipeRejected);
    assert.match(e.message, /载荷集/);
    assert.match(e.message, /能力请求单/);
    return true;
  });
});

test("canary 与判据绑死：换成 /etc/passwd 会被拒收，因为特征字段集是按 package.json 写的", () => {
  const bad = fork("path-traversal", (r) => {
    r.steps[0].canary = "/etc/passwd";
  });
  assert.throws(() => inspectRecipe(bad, "path-traversal"), /canary/);
});

test("参数名只能引用引擎真会读的计划字段，也不许写死字面量", () => {
  const unknownField = fork("sqli-injection", (r) => {
    r.steps[0].param = "{plan.argName}";
  });
  assert.throws(() => inspectRecipe(unknownField, "sqli-injection"), /不会读这个字段/);

  const literal = fork("sqli-injection", (r) => {
    r.steps[0].param = "keyword";
  });
  // 字面量不会崩在这一条上：它落在动作表允许的字符串里，但取值那一步会拒——配方写死参数名＝替计划编造字段
  assert.equal(resolvePlanField("{plan.param}", { param: "kw" }, "sqli-injection", "SQL 注入点"), "kw");
  assert.throws(() => resolvePlanField("keyword", { param: "kw" }, "sqli-injection", "SQL 注入点"), /必须是 \{plan\.字段\}/);
  assert.equal(resolvePlanField("{plan.param}", {}, "sqli-injection", "SQL 注入点"), undefined, "计划没给参数名时交回执行器默认值");
});

test("判据名与实际执行的判卷代码不符：整族拒收", () => {
  const bad = fork("sqli-injection", (r) => {
    r.verdict = { rule: "target-touched" };
  });
  assert.throws(() => inspectRecipe(bad, "sqli-injection"), /判据名不符/);
});

test("槽位写成别的攻击族：取不到候选种类就拒收", () => {
  const bad = fork("sqli-injection", (r) => {
    r.steps[0].path = "{slot:cmdiPath}";
  });
  assert.throws(() => inspectRecipe(bad, "sqli-injection"), /对应不上引擎会取用的计划槽位/);
});

test("主身份缺席时退回另一个种入的主体，配方不参与这个决定", () => {
  const step = loadRecipe("sqli-injection").steps[0];
  const both = { attacker: { name: "alice", user: { id: 1 } }, victim: { name: "bob", user: { id: 2 } } };
  assert.equal(resolveRolePreferred(both, identityRole(step)).name, "alice");
  assert.equal(resolveRolePreferred({ attacker: null, victim: { name: "bob" } }, "attacker").name, "bob", "攻击身份缺席→退回受害人，用例不该整族消失");
  assert.equal(resolveRolePreferred({ attacker: null, victim: null }, "victim"), null);
  assert.equal(resolveRolePreferred(both, "admin"), null, "admin 没有兜底身份：不给一个不存在的名字");
});
