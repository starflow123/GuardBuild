import test from "node:test";
import assert from "node:assert/strict";
import { buildScope } from "../lib/patcher.mjs";
import { buildImportGraph, graphToJSON, reviveGraph } from "../lib/depgraph.mjs";
import { buildReport } from "../lib/report.mjs";

// 风险画像：人工审查先看「改了哪些文件、各自扮演什么角色、共享文件影响面多大」，
// 画像错了就会误导审查者，所以逐字段钉住。

const CAND = "src/routes/orders.js";
const APP = "src/app.js";
const GUARD = "src/routes/ownership.js";

// app.js 引 orders.js 与 ownership.js；orders.js 引 data.js → app.js 入度 2、data.js 入度 1
const graphJSON = () => ({
  nodes: [
    { rel: APP, out: [CAND, GUARD], in: [] },
    { rel: CAND, out: ["src/data.js"], in: [APP] },
    { rel: GUARD, out: ["src/data.js"], in: [APP] },
    { rel: "src/data.js", out: [], in: [CAND, GUARD] },
  ],
  unresolved: [],
});

const nodesOf = () => reviveGraph(graphJSON());

test("单文件补丁：画像只有候选文件，跨文件标记为假", () => {
  const scope = buildScope({
    crossFile: false,
    depNodes: null,
    filePatches: [{ file: CAND, role: "candidate", created: false }],
    changedFiles: [{ path: CAND, insertions: 4, deletions: 1 }],
    rejected: [],
  });
  assert.equal(scope.crossFile, false);
  assert.deepEqual(scope.candidateFiles, [CAND]);
  assert.deepEqual(scope.closureFiles, []);
  assert.deepEqual(scope.newFiles, []);
  assert.equal(scope.files.length, 1);
  assert.deepEqual(
    { role: scope.files[0].role, ins: scope.files[0].insertions, del: scope.files[0].deletions, deg: scope.files[0].inDegree },
    { role: "candidate", ins: 4, del: 1, deg: null }
  );
  assert.deepEqual(scope.sharedFiles, []);
  assert.equal(scope.rejectedCount, 0);
});

test("跨文件补丁：区分候选/闭包/新建，并说明漏洞文件为何未改动", () => {
  const scope = buildScope({
    crossFile: true,
    depNodes: nodesOf(),
    // 候选文件本身没被改动，修法挂在 app.js 并新建守卫文件
    filePatches: [
      { file: CAND, crossFileOnly: true, appliedOps: 0 },
      { file: APP, role: "reverse", created: false, appliedOps: 2, fromCandidate: CAND },
      { file: GUARD, role: "new", created: true, appliedOps: 1, fromCandidate: CAND },
    ],
    changedFiles: [
      { path: APP, insertions: 6, deletions: 1 },
      { path: GUARD, insertions: 20, deletions: 0 },
    ],
    rejected: [{ file: "package.json", reason: "越出写集" }],
  });

  assert.equal(scope.crossFile, true);
  assert.deepEqual(scope.candidateFiles, [CAND]);
  assert.deepEqual(scope.closureFiles, [APP]);
  assert.deepEqual(scope.newFiles, [GUARD]);

  const byFile = new Map(scope.files.map((f) => [f.file, f]));
  assert.equal(byFile.get(CAND).untouched, true, "候选文件未改动要显式标出，否则审查者以为补丁没修到点上");
  assert.equal(byFile.get(CAND).insertions, 0);
  assert.equal(byFile.get(APP).role, "reverse");
  assert.equal(byFile.get(APP).inDegree, 0, "入口文件没人引用它");
  assert.equal(byFile.get(GUARD).role, "new");
  assert.equal(byFile.get(GUARD).created, true);
  assert.equal(byFile.get(GUARD).inDegree, 1, "新建守卫被 app.js 引用");
  assert.deepEqual(scope.sharedFiles, [], "没有依赖节点被标成共享文件");
  assert.equal(scope.rejectedCount, 1);
});

test("入度即影响面：被多处 import 的共享文件要单独列出", () => {
  const scope = buildScope({
    crossFile: true,
    depNodes: nodesOf(),
    filePatches: [
      { file: CAND, role: "candidate" },
      { file: "src/data.js", role: "forward", created: false },
    ],
    changedFiles: [{ path: "src/data.js", insertions: 3, deletions: 0 }],
    rejected: [],
  });
  assert.deepEqual(scope.sharedFiles, [{ file: "src/data.js", inDegree: 2 }]);
  assert.deepEqual(scope.closureFiles, ["src/data.js"]);
});

test("路径归一：反斜杠与 ./ 前缀都折叠成同一仓库相对路径，改动行数不丢", () => {
  const scope = buildScope({
    crossFile: true,
    depNodes: null,
    filePatches: [{ file: "./src\\app.js", role: "reverse" }],
    changedFiles: [{ path: "src//app.js", insertions: 5, deletions: 2 }],
    rejected: [],
  });
  assert.equal(scope.files.length, 1, "同一文件不应出现两条画像");
  assert.equal(scope.files[0].file, APP);
  assert.deepEqual({ ins: scope.files[0].insertions, del: scope.files[0].deletions }, { ins: 5, del: 2 });
});

test("同一文件既是被点名的候选又是依赖角色：以依赖角色为准，created 取或", () => {
  const scope = buildScope({
    crossFile: true,
    depNodes: null,
    filePatches: [
      { file: APP, role: "candidate", created: false },
      { file: APP, role: "reverse", created: true },
    ],
    changedFiles: [],
    rejected: [],
  });
  assert.equal(scope.files.length, 1);
  assert.equal(scope.files[0].role, "reverse");
  assert.equal(scope.files[0].created, true);
});

test("buildImportGraph 产物经 JSON 往返后仍能算出入度", () => {
  const files = [
    { rel: APP, content: `import { handleOrders } from "./routes/orders.js";\nimport { requireOrderOwner } from "./routes/ownership.js";\n` },
    { rel: CAND, content: `import { store } from "../data.js";\n` },
    { rel: GUARD, content: `import { store } from "../data.js";\n` },
    { rel: "src/data.js", content: `export const store = {};\n` },
  ];
  const nodes = reviveGraph(graphToJSON(buildImportGraph(files)));
  const scope = buildScope({
    crossFile: true,
    depNodes: nodes,
    filePatches: [{ file: "src/data.js", role: "forward" }],
    changedFiles: [{ path: "src/data.js", insertions: 1, deletions: 1 }],
    rejected: [],
  });
  assert.deepEqual(scope.sharedFiles, [{ file: "src/data.js", inDegree: 2 }]);
});

/** 会话视图最小骨架：只填 buildReport 会用到的字段 */
function ctxWithPatch(patch) {
  return {
    sessionId: "sess-scope",
    gate: false,
    targetConfig: null,
    view: {
      projectRoot: "D:/tmp/shop",
      projectName: "shop",
      startedAt: 1,
      state: "patch_ready",
      findings: [],
      evidence: [],
      phases: {},
      targets: {},
      patch,
      supabase: null,
      blackbox: null,
      acceptance: null,
      llm: null,
      error: null,
    },
  };
}

test("buildReport: 风险画像同时进 report.json 与 Markdown 的补丁段", () => {
  const scope = buildScope({
    crossFile: true,
    depNodes: nodesOf(),
    filePatches: [
      { file: CAND, crossFileOnly: true },
      { file: APP, role: "reverse", created: false },
      { file: "src/data.js", role: "forward", created: false },
      { file: GUARD, role: "new", created: true },
    ],
    changedFiles: [
      { path: APP, insertions: 6, deletions: 1 },
      { path: "src/data.js", insertions: 2, deletions: 0 },
      { path: GUARD, insertions: 20, deletions: 0 },
    ],
    rejected: [{ file: "package.json", reason: "越出写集" }, { file: CAND, reason: "锚点出现多次" }],
  });
  const { json, markdown } = buildReport(
    ctxWithPatch({
      hash: "abc123def456",
      diff: "diff --git a/src/app.js b/src/app.js\n",
      files: [{ path: APP, insertions: 6, deletions: 1 }],
      worktree: "D:/wt/fix-1",
      status: "pending_review",
      lineCount: 29,
      strategy: "llm",
      autoVerify: true,
      llm: { enabled: true, model: "deepseek-chat", crossFile: true, crossFileFiles: [{ from: CAND, to: APP, role: "reverse", ops: 2 }], createdFiles: [GUARD] },
      scope,
    }),
    { outcome: "vulnerable", exitCode: 0, patchStatus: "pending_review" }
  );

  assert.equal(json.patch.scope.crossFile, true);
  assert.deepEqual(json.patch.scope.newFiles, [GUARD]);
  assert.equal(json.patch.scope.rejectedCount, 2);

  assert.match(markdown, /写入范围/);
  assert.match(markdown, /已开启跨文件补丁/);
  assert.match(markdown, /改动范围：候选文件 1 个/);
  assert.match(markdown, /漏洞文件本身未改动/);
  assert.match(markdown, /共享文件影响面/);
  assert.match(markdown, /另有 2 条补丁意图在校验层被拒/);
});
