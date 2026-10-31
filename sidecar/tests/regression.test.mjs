import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, existsSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { BASELINE_VERSION, compare, gateAgainstBaseline, readBaseline, targetOfKey } from "../lib/regression.mjs";

// M0-2（#188）：不许回退。核心立场是「红一条整轮否决，不看平均」，
// 以及最容易被偷懒掉的一条：失败不许把自己从必过名单里删掉——否则一次改坏会顺手拆掉自己的回退网。

const file = (dir, name = "green.json") => path.join(dir, name);
const tmp = () => mkdtempSync(path.join(tmpdir(), "gb-regression-"));

test("首次跑没有绿名单：全绿建名单，不算回退", () => {
  const dir = tmp();
  try {
    const g = gateAgainstBaseline({ filePath: file(dir), suite: "whitebox", currentKeys: ["whitebox/a", "whitebox/a#c1"], coveredTargets: new Set(["a"]), allPass: true });
    assert.equal(g.ok, true);
    assert.equal(g.reason, "clean");
    assert.equal(g.baselineKeys, 2);
    assert.equal(g.previousKeys, 0);
    assert.ok(existsSync(file(dir)));
    assert.equal(readBaseline(file(dir)).version, BASELINE_VERSION);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("绿→红即回退，并且这条键留在名单里继续追", () => {
  const dir = tmp();
  try {
    gateAgainstBaseline({ filePath: file(dir), suite: "whitebox", currentKeys: ["whitebox/a", "whitebox/a#c1", "whitebox/b"], coveredTargets: new Set(["a", "b"]), allPass: true });
    const g = gateAgainstBaseline({ filePath: file(dir), suite: "whitebox", currentKeys: ["whitebox/a", "whitebox/a#c1"], coveredTargets: new Set(["a", "b"]), allPass: false });
    assert.deepEqual(g.regressions, ["whitebox/b"]);
    assert.equal(g.ok, false);
    assert.equal(g.reason, "regression");
    assert.ok(readBaseline(file(dir)).suites.whitebox.keys.includes("whitebox/b"), "红掉的键必须留在必过名单里");

    // 同一条继续红：仍是回退，不会被"上一次也红过"洗白
    const again = gateAgainstBaseline({ filePath: file(dir), suite: "whitebox", currentKeys: ["whitebox/a", "whitebox/a#c1"], coveredTargets: new Set(["a", "b"]), allPass: false });
    assert.deepEqual(again.regressions, ["whitebox/b"]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("用例级回退也能抓到：靶场整体过但某一族从命中变成漏", () => {
  const dir = tmp();
  try {
    gateAgainstBaseline({ filePath: file(dir), suite: "blackbox", currentKeys: ["blackbox/s#idor-a", "blackbox/s#sqli-b"], coveredTargets: new Set(["s"]), allPass: true });
    const g = gateAgainstBaseline({ filePath: file(dir), suite: "blackbox", currentKeys: ["blackbox/s", "blackbox/s#idor-a"], coveredTargets: new Set(["s"]), allPass: true });
    assert.deepEqual(g.regressions, ["blackbox/s#sqli-b"], "靶场级键新增不该掩盖用例级丢失");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("--only 局部跑：只比对被覆盖的靶场，不写盘、不把别人算成回退", () => {
  const dir = tmp();
  try {
    gateAgainstBaseline({ filePath: file(dir), suite: "whitebox", currentKeys: ["whitebox/a", "whitebox/b"], coveredTargets: new Set(["a", "b"]), allPass: true });
    const before = readFileSync(file(dir), "utf8");
    const g = gateAgainstBaseline({ filePath: file(dir), suite: "whitebox", currentKeys: ["whitebox/b"], coveredTargets: new Set(["b"]), allPass: true, partial: true });
    assert.equal(g.ok, true, "a 这一轮根本没跑，不该被当成回退");
    assert.equal(g.baselineUpdated, false);
    assert.equal(readFileSync(file(dir), "utf8"), before, "局部跑不许改绿名单");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("--rebaseline 只在全绿轮次允许，否则拒绝并不改名单", () => {
  const dir = tmp();
  try {
    gateAgainstBaseline({ filePath: file(dir), suite: "whitebox", currentKeys: ["whitebox/a", "whitebox/b"], coveredTargets: new Set(["a", "b"]), allPass: true });
    const before = readFileSync(file(dir), "utf8");
    const refused = gateAgainstBaseline({ filePath: file(dir), suite: "whitebox", currentKeys: ["whitebox/a"], coveredTargets: new Set(["a", "b"]), allPass: false, rebaseline: true });
    assert.equal(refused.reason, "refuse_rebaseline");
    assert.equal(refused.ok, false);
    assert.equal(readFileSync(file(dir), "utf8"), before);
    assert.equal(refused.baselineKeys, 2, "拒绝重建时名单长度不变");

    const done = gateAgainstBaseline({ filePath: file(dir), suite: "whitebox", currentKeys: ["whitebox/a"], coveredTargets: new Set(["a"]), allPass: true, rebaseline: true });
    assert.equal(done.ok, true);
    assert.deepEqual(readBaseline(file(dir)).suites.whitebox.keys, ["whitebox/a"], "显式全绿重建可以缩小名单");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("套件之间互不干扰", () => {
  const dir = tmp();
  try {
    gateAgainstBaseline({ filePath: file(dir), suite: "whitebox", currentKeys: ["whitebox/a"], coveredTargets: new Set(["a"]), allPass: true });
    const g = gateAgainstBaseline({ filePath: file(dir), suite: "blackbox", currentKeys: ["blackbox/z"], coveredTargets: new Set(["z"]), allPass: true });
    assert.equal(g.previousKeys, 0);
    const base = readBaseline(file(dir));
    assert.deepEqual(Object.keys(base.suites).sort(), ["blackbox", "whitebox"]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("targetOfKey 与 compare 的纯函数口径", () => {
  assert.equal(targetOfKey("whitebox", "whitebox/a#c1"), "a");
  assert.equal(targetOfKey("whitebox", "whitebox/a"), "a");
  const r = compare({ baseline: { version: BASELINE_VERSION, updatedAt: null, suites: { whitebox: { keys: ["whitebox/a"] } } }, suite: "whitebox", currentKeys: ["whitebox/a"], coveredTargets: new Set(["a"]) });
  assert.equal(r.ok, true);
  assert.equal(r.checked, 1);
  assert.deepEqual(r.improvements, []);
});
