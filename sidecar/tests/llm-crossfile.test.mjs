import test from "node:test";
import assert from "node:assert/strict";
import {
  crossFilePatchEnabled,
  patchEnabled,
  requestPatchIntent,
  validatePatchOutput,
} from "../lib/llm-patcher.mjs";
import { buildImportGraph, graphToJSON } from "../lib/depgraph.mjs";
import { createPatch } from "../lib/patcher.mjs";

const REL = "src/routes/orders.js";
const TARGET = `const db = require("../db");
router.get("/orders/:id", async (req, res) => {
  const row = await db.orderById(req.params.id);
  res.json(row);
});
`;
const APP = `const orders = require("./routes/orders");
app.use("/api", orders);
`;
const DB = `module.exports = { orderById: (id) => pool.query("SELECT * FROM orders WHERE id = $1", [id]) };
`;

const ws = (over = {}) => ({
  enabled: true,
  roles: new Map([
    [REL, "candidate"],
    ["src/db.js", "forward"],
    ["src/app.js", "reverse"],
  ]),
  rolesLower: new Map([
    [REL, "candidate"],
    ["src/db.js", "forward"],
    ["src/app.js", "reverse"],
  ]),
  newFileDirs: ["src", "src/routes"],
  ...over,
});

const contents = (over = {}) =>
  new Map([[REL, TARGET], ["src/db.js", DB], ["src/app.js", APP], ...Object.entries(over)]);
const v = (patches, opts = {}) =>
  validatePatchOutput({ patches }, { rel: REL, content: TARGET, candidateKeys: ["GET /orders/:id"], ...opts });

test("S2-full: 反向闭包文件（挂载守卫的启动文件）可接受补丁，并按文件分组落账", () => {
  const r = v(
    [
      {
        file: "src/app.js",
        search: 'app.use("/api", orders);',
        replace: 'app.use("/api", requireAuth, orders);',
        candidate: "GET /orders/:id",
        reason: "把守卫挂到挂载点",
      },
    ],
    { writeSet: ws(), contents: contents() }
  );
  assert.equal(r.rejected.length, 0, JSON.stringify(r.rejected));
  assert.equal(r.ops.length, 0, "候选文件本身没有改动");
  assert.deepEqual(Object.keys(r.byFile), ["src/app.js"]);
  assert.equal(r.byFile["src/app.js"][0].count, 1);
  assert.equal(r.accepted[0].role, "reverse");
});

test("S2-full: 写集之外的文件被拒绝，原因点名依赖闭包", () => {
  const r = v(
    [{ file: "src/other.js", search: "const a = 1;", replace: "const a = 2;", candidate: "GET /orders/:id" }],
    { writeSet: ws(), contents: contents() }
  );
  assert.equal(r.ops.length, 0);
  assert.match(r.rejected[0].reason, /不在本次候选的依赖闭包写集内/);
  assert.match(r.rejected[0].reason, /src\/routes\/orders\.js/, "拒绝原因应给出可写清单");
});

test("S2-full: 写集内但取不到真实字节（读取失败/超限）时拒绝，不猜测锚点", () => {
  const r = v(
    [{ file: "src/db.js", search: "pool.query", replace: "pool.querySafe", candidate: "GET /orders/:id" }],
    { writeSet: ws(), contents: new Map([["src/app.js", APP]]) }
  );
  assert.equal(r.rejected.length, 1);
  assert.match(r.rejected[0].reason, /未取得 src\/db\.js 的真实内容/);
});

test("S2-full: 跨文件锚点用各自文件的真实字节校验，改写原文照样失配", () => {
  const r = v(
    [{ file: "src/app.js", search: 'router.use("/api", orders);', replace: 'router.use("/api", guard, orders);', candidate: "GET /orders/:id" }],
    { writeSet: ws(), contents: contents() }
  );
  assert.match(r.rejected[0].reason, /锚点未在文件真实内容中出现/);
});

test("S2-full: 新建文件必须在已扫描到的源码目录下，且受行数/字符数/危险调用约束", () => {
  const good = {
    file: "src/routes/ownership.js",
    create: true,
    content: 'module.exports = function ownership(req, res, next) {\n  next();\n};\n',
    candidate: "GET /orders/:id",
    reason: "抽出归属校验中间件",
  };
  const ok = v([good], { writeSet: ws(), contents: contents() });
  assert.equal(ok.creations.length, 1, JSON.stringify(ok.rejected));
  assert.equal(ok.accepted[0].role, "new");
  assert.equal(ok.creations[0].file, "src/routes/ownership.js");

  const badDir = v([{ ...good, file: "src/guards/ownership.js" }], { writeSet: ws(), contents: contents() });
  assert.match(badDir.rejected[0].reason, /父目录 src\/guards\/ 没有已扫描到的源码文件/);

  const tooLong = v([{ ...good, content: "a\n".repeat(200) }], { writeSet: ws(), contents: contents() });
  assert.match(tooLong.rejected[0].reason, /超过 120 行上限/);

  const dangerous = v(
    [{ ...good, content: 'const cp = require("child_process");\nmodule.exports = cp;' }],
    { writeSet: ws(), contents: contents() }
  );
  assert.match(dangerous.rejected[0].reason, /危险调用/);

  const masked = v([{ ...good, content: "module.exports = { key: \"***\" };" }], { writeSet: ws(), contents: contents() });
  assert.match(masked.rejected[0].reason, /脱敏掩码/);

  const notCreate = v([{ ...good, content: "" }], { writeSet: ws(), contents: contents() });
  assert.match(notCreate.rejected[0].reason, /create 项必须给出整份文件内容/);
});

test("S2-full: 新建文件与附属文件各有数量上限（3 个新建 / 候选外 4 个改动）", () => {
  const mk = (i) => ({
    file: `src/routes/g${i}.js`,
    create: true,
    content: `module.exports = ${i};`,
    candidate: "GET /orders/:id",
  });
  const four = v([mk(1), mk(2), mk(3), mk(4)], { writeSet: ws(), contents: contents() });
  assert.equal(four.creations.length, 3);
  assert.match(four.rejected[0].reason, /新建文件已达上限 3/);

  const roles = new Map([[REL, "candidate"]]);
  const lower = new Map([[REL, "candidate"]]);
  for (let i = 0; i < 6; i++) {
    roles.set(`src/f${i}.js`, "forward");
    lower.set(`src/f${i}.js`, "forward");
  }
  const c = new Map([[REL, TARGET]]);
  for (let i = 0; i < 6; i++) c.set(`src/f${i}.js`, `const anchor${i} = 0;\n`);
  const many = v(
    Array.from({ length: 6 }, (_, i) => ({
      file: `src/f${i}.js`,
      search: `const anchor${i} = 0;`,
      replace: `const anchor${i} = 1;`,
      candidate: "GET /orders/:id",
    })),
    { writeSet: { enabled: true, roles, rolesLower: lower, newFileDirs: ["src"] }, contents: c }
  );
  assert.equal(Object.keys(many.byFile).length, 4, "只接受候选文件之外的前 4 个文件");
  assert.match(many.rejected[0].reason, /最多改动候选文件之外的 4 个文件/);
});

test("S2-full: 单文件上限按文件分别计数，附属文件不能借候选文件的额度", () => {
  const patches = [];
  for (let i = 0; i < 5; i++) {
    patches.push({
      file: "src/db.js",
      search: `orderById${i}`,
      replace: `orderByIdOwned${i}`,
      candidate: "GET /orders/:id",
    });
  }
  const db = `const orderById0 = 0, orderById1 = 0, orderById2 = 0, orderById3 = 0, orderById4 = 0;\n`;
  const r = v(patches, { writeSet: ws(), contents: contents({ "src/db.js": db }) });
  assert.equal(r.byFile["src/db.js"].length, 4);
  assert.match(r.rejected[0].reason, /超过单文件补丁上限 4/);
});

test("S2-lite 语义保持不变：未开启写集时跨文件与新建一律被拒", () => {
  const cross = v(
    [{ file: "src/app.js", search: 'app.use("/api", orders);', replace: 'app.use("/api", guard, orders);', candidate: "GET /orders/:id" }],
    { contents: contents() }
  );
  assert.match(cross.rejected[0].reason, /越出本次候选文件/);

  const created = v(
    [{ file: "src/routes/g.js", create: true, content: "module.exports = 1;", candidate: "GET /orders/:id" }],
    { writeSet: { enabled: false }, contents: contents() }
  );
  assert.match(created.rejected[0].reason, /未开启跨文件补丁/);
});

// —— requestPatchIntent：只取模型点名的写集文件字节，写集外的路径不落进读盘参数 ——
const makeCtx = () => ({
  llmConfig: { patch: true },
  tokens: { project: "tok_p", worktree: "tok_w" },
  _llmPatchFiles: new Set(),
  rpc: { request: async () => ({ content: TARGET }) },
});

const stubChat = (payload) => async () => ({ content: JSON.stringify(payload), model: "test-model", usage: {} });

test("requestPatchIntent: 跨文件补丁只按需读取写集内的文件，越界路径不被读取", async () => {
  const asked = [];
  const fetchContents = async (rels, writeSet) => {
    asked.push(...rels);
    const out = new Map();
    for (const r of rels) if (writeSet.rolesLower.get(r.toLowerCase())) out.set(r, r === "src/app.js" ? APP : DB);
    return out;
  };
  const res = await requestPatchIntent(makeCtx(), {
    file: "D:/p/src/routes/orders.js",
    rel: REL,
    content: TARGET,
    candidates: [{ method: "GET", path: "/orders/:id", kind: "idor-suspect" }],
    evidence: [],
    getToken: async () => "tok",
    chatImpl: stubChat({
      patches: [
        { file: "src/app.js", search: 'app.use("/api", orders);', replace: 'app.use("/api", guard, orders);', candidate: "GET /orders/:id" },
        { file: "../outside.js", search: "const a = 1;", replace: "const a = 2;" },
      ],
    }),
    writeSet: ws(),
    fetchContents,
  });
  assert.deepEqual(asked, ["src/app.js"], "越界/绝对路径不进入读盘清单");
  assert.equal(Object.keys(res.byFile).join(), "src/app.js");
  assert.equal(res.failure, null);
  assert.match(res.rejected[0].reason, /越出本次候选文件|缺少 file|不在本次候选的依赖闭包写集内/, "越界项留下拒绝原因");
});

test("requestPatchIntent: 提示词带出写集与可新建目录，模型才能声明跨文件目标", async () => {
  let seenSystem = "", seenUser = "";
  await requestPatchIntent(makeCtx(), {
    file: "D:/p/src/routes/orders.js",
    rel: REL,
    content: TARGET,
    candidates: [{ method: "GET", path: "/orders/:id", kind: "idor-suspect" }],
    evidence: [],
    getToken: async () => "tok",
    chatImpl: async (_ctx, { systemPrompt, userPrompt }) => {
      seenSystem = systemPrompt;
      seenUser = userPrompt;
      return { content: '{"patches":[]}', model: "m", usage: {} };
    },
    writeSet: ws(),
    fetchContents: async () => new Map(),
  });
  assert.match(seenSystem, /本次运行已开启跨文件补丁/);
  assert.match(seenSystem, /第 4、5、6 条/);
  const user = JSON.parse(seenUser);
  assert.deepEqual(user.writable_files.map((f) => f.role), ["candidate", "forward", "reverse"]);
  assert.deepEqual(user.writable_dirs, ["src", "src/routes"]);
});

test("requestPatchIntent: 未开启写集时提示词保持 S2-lite 的单文件约束", async () => {
  let seenSystem = "";
  await requestPatchIntent(makeCtx(), {
    file: "D:/p/src/routes/orders.js",
    rel: REL,
    content: TARGET,
    candidates: [{ method: "GET", path: "/orders/:id", kind: "idor-suspect" }],
    evidence: [],
    getToken: async () => "tok",
    chatImpl: async (_ctx, { systemPrompt }) => {
      seenSystem = systemPrompt;
      return { content: '{"patches":[]}', model: "m", usage: {} };
    },
  });
  assert.doesNotMatch(seenSystem, /本次运行已开启跨文件补丁/);
});

test("crossFilePatchEnabled: 契约显式开启或环境变量强制，gate 模式结构性禁用", () => {
  const prevKey = process.env.DEEPSEEK_API_KEY;
  const prevEnv = process.env.GUARDBUILD_LLM_PATCH;
  const prevCross = process.env.GUARDBUILD_LLM_CROSSFILE;
  process.env.DEEPSEEK_API_KEY = "test-key";
  try {
    process.env.GUARDBUILD_LLM_PATCH = "1";
    delete process.env.GUARDBUILD_LLM_CROSSFILE;
    const base = { llmConfig: { patch: true } };
    assert.equal(crossFilePatchEnabled(base), false, "默认关闭");
    assert.equal(crossFilePatchEnabled({ ...base, gate: true, llmConfig: { patch: true, patchCrossFile: true } }), false, "gate 永不启用");
    assert.equal(crossFilePatchEnabled({ ...base, llmConfig: { patch: true, patchCrossFile: true } }), true);
    process.env.GUARDBUILD_LLM_CROSSFILE = "1";
    assert.equal(crossFilePatchEnabled({ ...base, llmConfig: { patch: true } }), true, "环境变量可强制开启");
    assert.equal(crossFilePatchEnabled({ ...base, llmConfig: { patch: true, patchCrossFile: false } }), false, "契约显式 false 覆盖环境变量");
    delete process.env.GUARDBUILD_LLM_PATCH;
    assert.equal(patchEnabled({ llmConfig: { patch: false } }), false, "契约显式 patch:false 时编码代理关闭");
    assert.equal(
      crossFilePatchEnabled({ llmConfig: { patch: false, patchCrossFile: true } }),
      false,
      "编码代理关闭时跨文件写权限不生效"
    );
    assert.equal(patchEnabled({ llmConfig: { patch: true } }), true, "有 key 且契约开启时编码代理启用");
  } finally {
    if (prevKey === undefined) delete process.env.DEEPSEEK_API_KEY;
    else process.env.DEEPSEEK_API_KEY = prevKey;
    if (prevEnv === undefined) delete process.env.GUARDBUILD_LLM_PATCH;
    else process.env.GUARDBUILD_LLM_PATCH = prevEnv;
    if (prevCross === undefined) delete process.env.GUARDBUILD_LLM_CROSSFILE;
    else process.env.GUARDBUILD_LLM_CROSSFILE = prevCross;
  }
});

// —— createPatch 集成：跨文件落盘必须逐令牌区分，新建只走 allow_create 通道 ——
const CAND_REL = "src/routes/reports.js";
const CAND_SRC = `const db = require("../db");
router.get("/report/:id", async (req, res) => {
  res.json(await db.query("SELECT * FROM reports WHERE id = " + req.params.id));
});
`;
const APP_SRC = `const router = require("./routes/reports");
app.use("/api", router);
`;
const WT = "D:/wt/fix-1";

const OWNERSHIP = {
  file: "src/routes/ownership.js",
  create: true,
  content: "module.exports = function ownership(req, res, next) {\n  next();\n};\n",
  candidate: "GET /report/:id",
  reason: "抽出归属校验中间件",
};
const MOUNT_GUARD = {
  file: "src/app.js",
  search: 'app.use("/api", router);',
  replace: 'app.use("/api", requireAuth, router);',
  candidate: "GET /report/:id",
  reason: "在挂载点加认证守卫",
};

/** 用内存文件表模拟 Host 的 fs/git RPC，记录每一次写入与读取的令牌归属 */
function patchHarness({ patches, tokens, existing = [] }) {
  const files = new Map([
    [CAND_REL, CAND_SRC],
    ["src/app.js", APP_SRC],
    ["src/db.js", "exports.query = (sql) => pool.query(sql);\n"],
  ]);
  for (const f of existing) files.set(f, "module.exports = 1;\n");
  const writes = [];
  const reads = [];
  const diffs = [];
  const ctx = {
    projectRoot: "D:/p",
    sessionId: "s1",
    tokens: { worktree: "tok_wt", project: "tok_p", worktreeCreate: "tok_wtc", ...tokens },
    llmConfig: { patch: true, patchCrossFile: true },
    llmGetToken: async () => "tok_net",
    view: { evidence: [] },
    analysis: {
      candidates: [{ kind: "sqli-suspect", file: `D:/p/${CAND_REL}`, method: "GET", path: "/report/:id" }],
      depGraph: graphToJSON(
        buildImportGraph([
          { rel: CAND_REL, content: CAND_SRC },
          { rel: "src/app.js", content: APP_SRC },
          { rel: "src/db.js", content: "x" },
        ])
      ),
    },
    emit: () => {},
    db: { insertPatch: () => {} },
    rpc: {
      request: async (method, params) => {
        const relUnderWt = (p) => (String(p).startsWith(`${WT}/`) ? String(p).slice(WT.length + 1) : null);
        if (method === "git.status") return { isRepo: true, entries: [] };
        if (method === "git.worktreeAdd") return { path: `${WT}/` };
        if (method === "fs.list") return { entries: [] };
        if (method === "fs.linkDir") return {};
        if (method === "fs.stat") {
          const rel = relUnderWt(params.path);
          if (rel && files.has(rel)) return { size: files.get(rel).length };
          throw new Error("not found");
        }
        if (method === "fs.read") {
          const rel = params.path === `D:/p/${CAND_REL}` ? CAND_REL : relUnderWt(params.path);
          reads.push({ rel, path: params.path, token: params.token });
          if (rel && files.has(rel)) return { content: files.get(rel), size: 1, redacted: false };
          throw new Error(`未知读取目标 ${params.path}`);
        }
        if (method === "fs.write") {
          writes.push(params);
          const rel = relUnderWt(params.path);
          // Host 独立判定「是否新建」：只有带 content 且目标不存在时 created 才为 true
          const creating = params.content !== undefined && !files.has(rel);
          files.set(rel, params.content ?? files.get(rel));
          return { appliedOps: params.ops?.length ?? 1, beforeSha256: "b", sha256: "s", created: creating };
        }
        if (method === "http.request") {
          return {
            status: 200,
            body: JSON.stringify({
              choices: [{ message: { content: JSON.stringify({ patches }) } }],
              usage: { total_tokens: 10 },
            }),
          };
        }
        if (method === "git.diff") {
          diffs.push(params);
          const diff = "--- a/src/app.js\n+++ b/src/app.js\n+app.use\n--- /dev/null\n+++ b/src/routes/ownership.js\n+module.exports\n";
          return {
            diff,
            // Host 的 git.diff 逐文件回 {path,insertions,deletions}（来自 git diff --numstat），
            // 桩件按 diff 头生成同样形状，别拿计数冒充——风险画像吃的就是这个数组
            files: [...diff.matchAll(/^\+\+\+ b\/(.+)$/gm)]
              .map((m) => m[1])
              .filter((p) => p !== "/dev/null")
              .map((p) => ({ path: p, insertions: 1, deletions: 0, status: p.endsWith("ownership.js") ? "A" : "M" })),
            patchHash: "hash1",
            registeredNewFiles: params.intentAdd ?? [],
          };
        }
        throw new Error(`不应调用 ${method}`);
      },
    },
  };
  return { ctx, writes, reads, diffs, files };
}

async function withKey(fn) {
  const prev = process.env.DEEPSEEK_API_KEY;
  process.env.DEEPSEEK_API_KEY = "test-key";
  try {
    return await fn();
  } finally {
    if (prev === undefined) delete process.env.DEEPSEEK_API_KEY;
    else process.env.DEEPSEEK_API_KEY = prev;
  }
}

test("S2-full：createPatch 落盘三类写入各用对应令牌，新文件登记进 diff", async () => {
  await withKey(async () => {
    const h = patchHarness({
      patches: [
        MOUNT_GUARD,
        OWNERSHIP,
        // 写集外的路径：既不读盘也不落盘
        { file: "../outside.js", search: "const a = 1;", replace: "const a = 2;" },
        { file: "src/secrets.js", search: "const k = 1;", replace: "const k = 2;" },
      ],
    });
    const res = await createPatch(h.ctx);
    assert.deepEqual(
      h.writes.map((w) => ({ token: w.token, file: w.path.slice(WT.length + 1), mode: w.ops ? "ops" : "create" })),
      [
        { token: "tok_wt", file: "src/app.js", mode: "ops" },
        { token: "tok_wtc", file: "src/routes/ownership.js", mode: "create" },
      ],
      "附属文件走 worktree 令牌的锚点替换，新建文件走 allow_create 令牌的整文件写入"
    );
    assert.ok(
      !h.reads.some((r) => /outside|secrets/.test(String(r.path)) || r.rel === null),
      `读盘清单只含写集文件：${JSON.stringify(h.reads)}`
    );
    assert.deepEqual(h.diffs[0].intentAdd, ["src/routes/ownership.js"], "新建文件要登记 intent-to-add 才会进补丁");
    assert.deepEqual(res.createdFiles, ["src/routes/ownership.js"]);
    const byFile = Object.fromEntries(res.filePatches.map((f) => [f.file, f]));
    assert.equal(byFile[CAND_REL].crossFileOnly, true, "候选文件本身没动，但归因要保留");
    assert.equal(byFile[CAND_REL].fixes[0].role, "reverse");
    assert.equal(byFile["src/routes/ownership.js"].role, "new");
    assert.equal(res.claimedKeys.length, 1, "跨文件修复仍算作该候选被修复");
    assert.equal(res.llm.crossFile, true);
    assert.deepEqual(res.llm.crossFileFiles, [{ from: CAND_REL, to: "src/app.js", role: "reverse", ops: 1 }]);
  });
});

test("S2-full：未签发 allow_create 令牌时新建被丢弃，但同批跨文件补丁照常写入", async () => {
  await withKey(async () => {
    const h = patchHarness({ patches: [MOUNT_GUARD, OWNERSHIP], tokens: { worktreeCreate: undefined } });
    const res = await createPatch(h.ctx);
    assert.deepEqual(
      h.writes.map((w) => w.path.slice(WT.length + 1)),
      ["src/app.js"],
      "没有 allow_create 令牌就一次新建写入都不发"
    );
    assert.deepEqual(res.createdFiles, []);
    assert.equal(h.diffs[0].intentAdd, undefined, "没有新文件时不该带 intentAdd 参数");
    assert.ok(
      res.llm.rejected.some((r) => r.reason.includes("未签发 allow_create 作用域")),
      JSON.stringify(res.llm.rejected)
    );
    assert.equal(res.llm.appliedOps, 1, "附属文件的补丁仍然落账");
  });
});

test("S2-full：新建目标在隔离副本中已存在时拒绝整文件覆盖", async () => {
  await withKey(async () => {
    const h = patchHarness({ patches: [MOUNT_GUARD, OWNERSHIP], existing: ["src/routes/ownership.js"] });
    const before = h.files.get("src/routes/ownership.js");
    const res = await createPatch(h.ctx);
    assert.equal(h.files.get("src/routes/ownership.js"), before, "已存在的文件内容不得被覆盖");
    assert.ok(
      res.llm.rejected.some((r) => r.reason.includes("拒绝整文件覆盖")),
      JSON.stringify(res.llm.rejected)
    );
    assert.deepEqual(res.createdFiles, []);
  });
});

