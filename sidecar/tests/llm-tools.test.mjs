/**
 * 只读工具循环（S2-lite）：编码代理可以在产出补丁前，请求 Sidecar 代它读隔离 worktree 里的源码。
 * 这里断言的重点不是「模型更聪明了」，而是边界没变——
 * 读的范围由路径守卫决定、写入范围一个字没多、超预算时诚实失败而不是编造补丁。
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  requestPatchIntent,
  parseToolRequests,
  toolPathAllowed,
  makeReadTools,
} from "../lib/llm-patcher.mjs";
import { normalizeLlm } from "../lib/targetconfig.mjs";
import { RPC_TO_HOST } from "../../shared/protocol.mjs";

const REL = "src/routes/orders.js";
const TOOL_FILE = "src/store.js";
const ANCHOR = "  const order = await store.findById(req.params.id);";
const CONTENT = [
  "const store = require('../store');",
  "",
  "app.get('/api/orders/:id', async (req, res) => {",
  ANCHOR,
  "  if (!order) return res.status(404).json({ error: 'not found' });",
  "  res.json(order);",
  "});",
  "",
].join("\n");
const TOOL_TEXT = "module.exports = { findById: (id) => db.raw('select * from orders where id=' + id) };";

const CANDIDATES = [
  { method: "GET", path: "/api/orders/:id", fullPath: "/api/orders/:id", kind: "idor-suspect", startLine: 3 },
];

function patch() {
  return {
    file: REL,
    search: ANCHOR,
    replace: `${ANCHOR}\n  if (order && order.userId !== req.user.id) {\n    return res.status(403).json({ error: 'forbidden' });\n  }`,
    candidate: "GET /api/orders/:id",
    reason: "补齐归属校验",
  };
}

function fakeCtx() {
  return {
    tokens: { project: "tp", worktree: "tw" },
    view: { evidence: [] },
    rpc: {
      request: async () => {
        throw new Error("测试内不应发起 Host RPC");
      },
    },
  };
}

function args(extra = {}) {
  return {
    file: `D:\\p\\${REL}`,
    rel: REL,
    content: CONTENT,
    candidates: CANDIDATES,
    evidence: [],
    readRedacted: async () => CONTENT,
    getToken: async () => "tok",
    ...extra,
  };
}

test("只读自查：模型先要上下文，Sidecar 代读后回喂结果，再收到补丁", async () => {
  const ctx = fakeCtx();
  const prompts = [];
  const reads = [];
  const res = await requestPatchIntent(
    ctx,
    args({
      tools: {
        read: async (p) => {
          reads.push(p);
          return TOOL_TEXT;
        },
        list: async (p) => [{ path: `${p}/store.js`, kind: "file" }],
      },
      chatImpl: async (_c, { userPrompt }) => {
        prompts.push(userPrompt);
        if (prompts.length === 1) {
          return { content: JSON.stringify({ requests: [{ tool: "read", path: TOOL_FILE }, { tool: "list", path: "src" }] }) };
        }
        return { content: JSON.stringify({ patches: [patch()] }) };
      },
    })
  );
  assert.equal(prompts.length, 2, "一轮自查后二次请求");
  assert.deepEqual(reads, [TOOL_FILE], "只有 read 请求会读文件");
  assert.ok(prompts[1].includes(TOOL_TEXT), "第二轮提示词带回读取内容");
  assert.ok(prompts[1].includes("tool_history"), "自查结果成段呈现，不依赖多轮会话状态");
  assert.equal(res.toolRounds, 1);
  assert.deepEqual(res.toolCalls.map((t) => `${t.tool}:${t.ok}`), ["read:true", "list:true"]);
  assert.equal(res.ops.length, 1, "自查不改变补丁校验与采纳");
  assert.equal(res.failure, null);
});

test("只读自查：越界与敏感路径不执行，拒绝理由原样回喂模型", async () => {
  const ctx = fakeCtx();
  const prompts = [];
  let executed = 0;
  const bump = async () => {
    executed += 1;
    return "x";
  };
  const res = await requestPatchIntent(
    ctx,
    args({
      tools: { read: bump, list: async () => [] },
      chatImpl: async (_c, { userPrompt }) => {
        prompts.push(userPrompt);
        if (prompts.length === 1) {
          return {
            content: JSON.stringify({
              requests: [
                { tool: "read", path: "../outside.js" },
                { tool: "read", path: "guardbuild.json" },
                { tool: "read", path: "node_modules/express/index.js" },
                { tool: "read", path: TOOL_FILE },
              ],
            }),
          };
        }
        return { content: JSON.stringify({ patches: [patch()] }) };
      },
    })
  );
  assert.equal(executed, 1, "只执行白名单内的那一个请求");
  assert.ok(prompts[1].includes("路径越出隔离 worktree"), prompts[1].slice(0, 300));
  assert.ok(prompts[1].includes("依赖清单"));
  assert.equal(res.toolCalls.filter((t) => !t.ok).length, 3);
  assert.equal(res.ops.length, 1);
});

test("只读自查：轮次用尽仍未产出补丁时诚实失败，不无限往返", async () => {
  const ctx = fakeCtx();
  let calls = 0;
  const res = await requestPatchIntent(
    ctx,
    args({
      tools: { read: async () => "x", list: async () => [] },
      maxToolRounds: 1,
      chatImpl: async () => {
        calls += 1;
        return { content: JSON.stringify({ requests: [{ tool: "read", path: TOOL_FILE }] }) };
      },
    })
  );
  assert.equal(calls, 2, "1 轮自查 + 1 次超限判定");
  assert.equal(res.ops.length, 0);
  assert.equal(res.toolRounds, 1);
  assert.match(res.failure, /轮次已达上限/);
});

test("只读自查：同轮给出 patches 时以补丁为准，忽略自查请求", async () => {
  const ctx = fakeCtx();
  let executed = 0;
  const res = await requestPatchIntent(
    ctx,
    args({
      tools: {
        read: async () => {
          executed += 1;
          return "x";
        },
        list: async () => [],
      },
      chatImpl: async () => ({
        content: JSON.stringify({ patches: [patch()], requests: [{ tool: "read", path: TOOL_FILE }] }),
      }),
    })
  );
  assert.equal(executed, 0, "写范围不因工具而扩大，读也不替补丁背书");
  assert.equal(res.ops.length, 1);
  assert.equal(res.toolRounds, 0);
  assert.match(res.toolCalls[0].reason, /忽略自查请求/);
});

test("只读自查：未启用只读工具时不猜内容，直接诚实失败", async () => {
  const ctx = fakeCtx();
  let calls = 0;
  const res = await requestPatchIntent(
    ctx,
    args({
      chatImpl: async () => {
        calls += 1;
        return { content: JSON.stringify({ requests: [{ tool: "read", path: TOOL_FILE }] }) };
      },
    })
  );
  assert.equal(calls, 1);
  assert.equal(res.ops.length, 0);
  assert.match(res.failure, /没有可用的只读工具/);
});

test("只读自查：重复请求沿用上一轮结果，不重复读盘", async () => {
  const ctx = fakeCtx();
  let calls = 0;
  let reads = 0;
  const res = await requestPatchIntent(
    ctx,
    args({
      tools: {
        read: async () => {
          reads += 1;
          return TOOL_TEXT;
        },
        list: async () => [],
      },
      chatImpl: async () => {
        calls += 1;
        if (calls <= 2) return { content: JSON.stringify({ requests: [{ tool: "read", path: TOOL_FILE }] }) };
        return { content: JSON.stringify({ patches: [patch()] }) };
      },
    })
  );
  assert.equal(calls, 3);
  assert.equal(reads, 1, "第二轮同路径命中缓存");
  assert.equal(res.toolRounds, 2);
  assert.ok(res.toolCalls.some((t) => t.reused === true));
});

test("只读自查：读取失败也回喂，模型知道这条路走不通", async () => {
  const ctx = fakeCtx();
  const prompts = [];
  const res = await requestPatchIntent(
    ctx,
    args({
      tools: {
        read: async () => {
          throw new Error("宿主拒绝：文件不在 worktree 中");
        },
        list: async () => [],
      },
      chatImpl: async (_c, { userPrompt }) => {
        prompts.push(userPrompt);
        if (prompts.length === 1) return { content: JSON.stringify({ requests: [{ tool: "read", path: "src/gone.js" }] }) };
        return { content: JSON.stringify({ patches: [] }) };
      },
    })
  );
  assert.ok(prompts[1].includes("宿主拒绝"), prompts[1].slice(0, 300));
  assert.equal(res.toolCalls[0].ok, false);
  assert.equal(res.ops.length, 0);
});

test("parseToolRequests：只认 read/list，单轮上限 4 次", () => {
  assert.equal(parseToolRequests({ patches: [] }).asked, false);
  const notArray = parseToolRequests({ requests: "src/store.js" });
  assert.equal(notArray.asked, true);
  assert.match(notArray.rejected[0].reason, /必须是数组/);
  const many = parseToolRequests({
    requests: Array.from({ length: 6 }, (_v, i) => ({ tool: "read", path: `src/f${i}.js` })),
  });
  assert.equal(many.requests.length, 4);
  assert.equal(many.rejected.length, 2);
  assert.match(many.rejected[0].reason, /单轮最多/);
  const badTool = parseToolRequests({ requests: [{ tool: "exec", path: "src/a.js" }] });
  assert.equal(badTool.requests.length, 0);
  assert.match(badTool.rejected[0].reason, /只支持 read/);
});

test("工具路径守卫：list 可列目录，read 只放源码文件", () => {
  assert.equal(toolPathAllowed("src", { forList: true }).ok, true);
  assert.equal(toolPathAllowed(".", { forList: true }).ok, true);
  assert.equal(toolPathAllowed("src").ok, false, "read 必须指向源码文件");
  assert.equal(toolPathAllowed("src/store.js").ok, true);
  assert.equal(toolPathAllowed("D:/abs/a.js").ok, false);
  assert.equal(toolPathAllowed("config/db.yaml").ok, false);
});

test("makeReadTools：调用只落在隔离 worktree 令牌上，列表折成相对路径", async () => {
  const calls = [];
  const ctx = {
    tokens: { worktree: "tw" },
    rpc: {
      async request(method, params) {
        calls.push({ method, path: params.path, token: params.token, redact: params.redact });
        if (method === RPC_TO_HOST.FS_READ) return { content: "// 脱敏内容 ***" };
        return {
          entries: [
            { path: "C:\\wt\\src\\store.js", kind: "file" },
            { path: "C:\\wt\\node_modules\\express", kind: "dir" },
            { path: "C:\\wt\\src", kind: "dir" },
          ],
        };
      },
    },
  };
  const tools = makeReadTools(ctx, "C:\\wt\\");
  assert.equal(await tools.read("src/store.js"), "// 脱敏内容 ***");
  const entries = await tools.list("src");
  assert.deepEqual(
    entries.map((e) => e.path),
    ["src/store.js", "src"],
    "绝对路径折成 worktree 相对路径，依赖目录不进了列表"
  );
  assert.deepEqual(
    calls.map((c) => c.path),
    ["C:\\wt/src/store.js", "C:\\wt/src"],
    "读取路径始终拼在 worktree 根下"
  );
  assert.ok(
    calls.every((c) => c.token === "tw"),
    "只用 worktree 令牌，读不到原工作区"
  );
  assert.equal(calls[0].redact, undefined, "默认走 Host 脱敏，不请求原始字节");
});

test("契约 llm 字段：patchToolRounds 默认 2，可关但不可放宽", () => {
  assert.equal(normalizeLlm({ enabled: true }).patchToolRounds, 2);
  assert.equal(normalizeLlm({ enabled: true, patchToolRounds: 0 }).patchToolRounds, 0);
  assert.equal(normalizeLlm({ enabled: true, patchToolRounds: 9 }).patchToolRounds, 2);
});
