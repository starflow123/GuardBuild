import { test } from "node:test";
import assert from "node:assert/strict";
import { buildAttribution, parseDiffHunks, patchLocality } from "../lib/attribution.mjs";
import { CASE_CATEGORY, VERDICT } from "../../shared/protocol.mjs";

const DIFF = [
  "diff --git a/src/app.js b/src/app.js",
  "index 1111111..2222222 100644",
  "--- a/src/app.js",
  "+++ b/src/app.js",
  "@@ -10,6 +10,9 @@ function handler()",
  "+  if (o.userId !== req.user.id) return res.status(403).end();",
  "@@ -120,3 +123,4 @@ function other()",
  "+  // 注释",
  "diff --git a/src/util.js b/src/util.js",
  "index 3333333..4444444 100644",
  "--- a/src/util.js",
  "+++ /dev/null",
].join("\n");

test("parseDiffHunks：多文件多 hunk 的新侧区间，删除文件不登记", () => {
  const hunks = parseDiffHunks(DIFF);
  assert.deepEqual([...hunks.keys()], ["src/app.js"], "+++ 行取新路径，删除的文件（/dev/null）不入库");
  assert.deepEqual(hunks.get("src/app.js"), [
    { start: 10, end: 18 },
    { start: 123, end: 126 },
  ]);
});

test("patchLocality：同文件给行距，异文件与无源码位置分别标记", () => {
  const hunks = parseDiffHunks(DIFF);
  assert.equal(patchLocality({ file: "src/app.js", startLine: 11 }, hunks).distance, 0, "落在 hunk 区间内距离 0");
  assert.equal(patchLocality({ file: "src/app.js", startLine: 200 }, hunks).distance, 74, "区间外给到最近 hunk 的行距");
  assert.equal(patchLocality({ file: "src/app.js", startLine: 200 }, hunks).inCandidateFile, true);
  assert.equal(patchLocality({ file: "src/other.js", startLine: 3 }, hunks).inCandidateFile, false);
  assert.equal(patchLocality({ file: null, startLine: 3 }, hunks).hasSource, false);
});

function makeCtx({ claimed = [], pre = [], candidates = [], diff = DIFF }) {
  const meta = new Map();
  const verdicts = new Map();
  for (const p of pre) {
    meta.set(p.caseId, { candidateKey: p.candidateKey, category: p.category ?? CASE_CATEGORY.ATTACK, name: p.name ?? p.caseId });
    verdicts.set(p.caseId, p.pre);
  }
  return {
    _claimedCandidates: new Set(claimed),
    _preCaseMeta: meta,
    _preCaseVerdicts: verdicts,
    plan: { candidates },
    view: { patch: { diff } },
  };
}

const post = (rows) => rows.map(([caseId, verdict]) => ({ caseId, verdict, caseCategory: CASE_CATEGORY.ATTACK }));

const READ = "GET /api/orders/:id";
const CANCEL = "POST /api/orders/:id/cancel";

test("归因：补丁点名的候选自己完成「打穿 → 阻断」才算通过", () => {
  const ctx = makeCtx({
    claimed: [READ],
    pre: [
      { caseId: "attack-read-foreign", candidateKey: READ, pre: VERDICT.VULNERABLE },
      { caseId: "attack-read-foreign-obj1", candidateKey: READ, pre: VERDICT.VULNERABLE },
    ],
    candidates: [{ method: "GET", path: "/api/orders/:id", fullPath: "/api/orders/:id", file: "src/app.js", startLine: 11 }],
  });
  const res = buildAttribution(ctx, post([
    ["attack-read-foreign", VERDICT.BLOCKED],
    ["attack-read-foreign-obj1", VERDICT.BLOCKED],
  ]));
  assert.equal(res.pass, true);
  assert.equal(res.blockedCount, 1);
  assert.equal(res.rows[0].locality, "same_file", "补丁 hunk 落在该候选的文件");
  assert.equal(res.rows[0].hunkDistance, 0);
});

test("归因：修复前复现的用例没进修复后阶段 → 归因不成立（总体计数再好看也不算修好）", () => {
  const ctx = makeCtx({
    claimed: [READ],
    pre: [
      { caseId: "attack-read-foreign", candidateKey: READ, pre: VERDICT.VULNERABLE },
      { caseId: "attack-read-foreign-2", candidateKey: READ, pre: VERDICT.VULNERABLE },
    ],
  });
  const res = buildAttribution(ctx, post([["attack-read-foreign", VERDICT.BLOCKED]]));
  assert.equal(res.pass, false);
  assert.equal(res.unverifiedCount, 1);
  assert.match(res.failing[0].reason, /未进入修复后验收/);
});

test("归因：修复后 inconclusive 不算阻断", () => {
  const ctx = makeCtx({
    claimed: [READ],
    pre: [{ caseId: "attack-read-foreign", candidateKey: READ, pre: VERDICT.VULNERABLE }],
  });
  const res = buildAttribution(ctx, post([["attack-read-foreign", VERDICT.INCONCLUSIVE]]));
  assert.equal(res.pass, false);
  assert.match(res.failing[0].reason, /inconclusive/);
});

test("归因：修复后仍可越权 → still_vulnerable", () => {
  const ctx = makeCtx({
    claimed: [READ],
    pre: [{ caseId: "attack-read-foreign", candidateKey: READ, pre: VERDICT.VULNERABLE }],
  });
  const res = buildAttribution(ctx, post([["attack-read-foreign", VERDICT.REGRESSED]]));
  assert.equal(res.pass, false);
  assert.equal(res.stillVulnerableCount, 1);
});

test("归因：点名了但修复前没复现 → 只作说明，不判失败", () => {
  const ctx = makeCtx({
    claimed: [CANCEL],
    pre: [{ caseId: "attack-cancel-foreign", candidateKey: CANCEL, pre: VERDICT.BLOCKED }],
  });
  const res = buildAttribution(ctx, post([["attack-cancel-foreign", VERDICT.BLOCKED]]));
  assert.equal(res.pass, true);
  assert.equal(res.rows[0].status, "not_reproduced");
});

test("归因：点名候选在修复前根本没有攻击用例 → 归因不成立", () => {
  const ctx = makeCtx({ claimed: [CANCEL], pre: [] });
  const res = buildAttribution(ctx, post([]));
  assert.equal(res.pass, false);
  assert.match(res.failing[0].reason, /没有它的攻击用例/);
});

test("归因：未被点名的候选即使翻转也只作背景信息，不影响裁决", () => {
  const ctx = makeCtx({
    claimed: [READ],
    pre: [
      { caseId: "attack-read-foreign", candidateKey: READ, pre: VERDICT.VULNERABLE },
      { caseId: "attack-cancel-foreign", candidateKey: CANCEL, pre: VERDICT.VULNERABLE },
    ],
  });
  const res = buildAttribution(ctx, post([
    ["attack-read-foreign", VERDICT.BLOCKED],
    ["attack-cancel-foreign", VERDICT.BLOCKED],
  ]));
  assert.equal(res.pass, true);
  const other = res.rows.find((r) => r.candidateKey === CANCEL);
  assert.equal(other.claimed, false);
  assert.equal(other.status, "blocked");
});

test("归因：业务用例不参与逐候选翻转判定", () => {
  const ctx = makeCtx({
    claimed: [READ],
    pre: [
      { caseId: "attack-read-foreign", candidateKey: READ, pre: VERDICT.VULNERABLE },
      { caseId: "business-read-own", candidateKey: READ, category: CASE_CATEGORY.BUSINESS, pre: VERDICT.PASSED },
    ],
  });
  const res = buildAttribution(ctx, post([["attack-read-foreign", VERDICT.BLOCKED]]));
  assert.equal(res.pass, true);
  assert.equal(res.rows[0].preReproCases, 1);
});

test("归因：补丁落在别的文件时给出 other_file，但不据此否决", () => {
  const ctx = makeCtx({
    claimed: [READ],
    pre: [{ caseId: "attack-read-foreign", candidateKey: READ, pre: VERDICT.VULNERABLE }],
    candidates: [{ method: "GET", path: "/api/orders/:id", fullPath: "/api/orders/:id", file: "src/db.js", startLine: 5 }],
  });
  const res = buildAttribution(ctx, post([["attack-read-foreign", VERDICT.BLOCKED]]));
  assert.equal(res.pass, true);
  assert.equal(res.rows[0].locality, "other_file");
});

test("归因：缺少上下文（无补丁/无 pre 记录）时退化为通过，不抛错", () => {
  const res = buildAttribution({}, []);
  assert.equal(res.pass, true);
  assert.deepEqual(res.rows, []);
});

test("patchLocality：候选绝对路径（含 Windows 扩展前缀）与 diff 的仓库相对路径对齐", () => {
  const hunks = parseDiffHunks(DIFF);
  const loc = patchLocality(
    { file: "\\\\?\\D:\\AiAgent\\project\\demo\\src\\app.js", startLine: 12 },
    hunks
  );
  assert.equal(loc.inCandidateFile, true, "扩展路径前缀与反斜杠不得妨碍匹配");
  assert.equal(loc.distance, 0, "12 落在 +10,9 的 hunk 区间内");
  assert.equal(loc.relPath, "src/app.js", "报告展示仓库相对路径而非用户绝对路径");
});
