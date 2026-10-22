import { test } from "node:test";
import assert from "node:assert/strict";
import {
  patchTargetAllowed,
  validatePatchOutput,
  buildPatchPrompt,
  patchEnabled,
  requestPatchIntent,
} from "../lib/llm-patcher.mjs";
import { normalizeLlm } from "../lib/targetconfig.mjs";

const REL = "src/routes/orders.js";
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
const KEYS = ["GET /api/orders/:id"];

function patch(over = {}) {
  return {
    file: REL,
    search: ANCHOR,
    replace: `${ANCHOR}\n  if (order && order.userId !== req.user.id) {\n    return res.status(403).json({ error: 'forbidden' });\n  }`,
    candidate: "GET /api/orders/:id",
    reason: "补齐归属校验",
    ...over,
  };
}

function run(patches, opts = {}) {
  return validatePatchOutput({ patches }, { rel: REL, content: CONTENT, candidateKeys: KEYS, ...opts });
}

test("补丁目标只允许源码文件，拒绝依赖清单/配置/环境/产物/测试", () => {
  assert.equal(patchTargetAllowed("src/a.js").ok, true);
  assert.equal(patchTargetAllowed("src/a.ts").ok, true);
  for (const bad of [
    "package.json",
    "package-lock.json",
    "guardbuild.json",
    ".env",
    "src/.env.production",
    "config/db.yaml",
    "dist/bundle.js",
    "node_modules/express/index.js",
    "tests/orders.test.js",
    "src/orders.spec.ts",
    "certs/key.pem",
    "../outside.js",
    "/abs/path.js",
  ]) {
    const r = patchTargetAllowed(bad);
    assert.equal(r.ok, false, `${bad} 应被拒绝`);
    assert.ok(r.reason, `${bad} 应给出原因`);
  }
});

test("合法补丁意图转成 count=1 的定向替换", () => {
  const r = run([patch()]);
  assert.equal(r.rejected.length, 0);
  assert.equal(r.ops.length, 1);
  assert.deepEqual(Object.keys(r.ops[0]).sort(), ["count", "find", "replace"]);
  assert.equal(r.ops[0].count, 1);
  assert.equal(r.ops[0].find, ANCHOR);
  assert.equal(r.accepted[0].candidate, "GET /api/orders/:id");
  assert.equal(r.accepted[0].reason, "补齐归属校验");
  assert.ok(CONTENT.includes(r.ops[0].find));
});

test("越界文件、危险新增与锚点异常一律拒绝并说明原因", () => {
  const cases = [
    [patch({ file: "src/other.js" }), /越出本次候选文件/],
    [patch({ file: "package.json" }), /越出本次候选文件/],
    [patch({ search: "const" }), /锚点过短|出现多次/],
    [patch({ search: "  res.json(nope);" }), /未.*出现/],
    [patch({ replace: "  const { exec } = require('child_process');" }), /危险调用/],
    [patch({ search: `${ANCHOR}\n${ANCHOR}` }), /未.*出现/],
    [patch({ search: "***REDACTED***" }), /脱敏掩码/],
    [patch({ candidate: "DELETE /api/unknown" }), /不在本次待修复清单/],
    [patch({ replace: ANCHOR }), /空操作/],
  ];
  for (const [p, re] of cases) {
    const r = run([p]);
    assert.equal(r.ops.length, 0, JSON.stringify(p));
    assert.match(r.rejected[0].reason, re, `${JSON.stringify(p)} → ${r.rejected[0].reason}`);
  }
  // 目标本身就是禁改文件时（即使 file 字段与候选一致）也要拒绝
  const forbidden = validatePatchOutput({ patches: [patch({ file: "package.json" })] }, { rel: "package.json", content: CONTENT, candidateKeys: KEYS });
  assert.match(forbidden.rejected[0].reason, /不允许修改该文件/);
});

test("锚点出现多次时不猜测位置", () => {
  const dup = `${CONTENT}\n${ANCHOR}\n`;
  const r = validatePatchOutput({ patches: [patch()] }, { rel: REL, content: dup, candidateKeys: KEYS });
  assert.equal(r.ops.length, 0);
  assert.match(r.rejected[0].reason, /出现多次/);
});

test("改动规模受限：过大补丁被拒绝", () => {
  const big = `${ANCHOR}\n  // pad\n`.repeat(1) + "  // pad\n".repeat(30);
  const r = run([patch({ replace: big })]);
  assert.equal(r.ops.length, 0);
  assert.match(r.rejected[0].reason, /超过/);
});

test("重复或重叠锚点只保留第一条", () => {
  const p = patch();
  const r = run([p, { ...p, replace: `${p.replace}\n  // 再次` }]);
  assert.equal(r.ops.length, 1);
  assert.match(r.rejected[0].reason, /重复|重叠/);
});

test("CRLF 文件上的锚点自动对齐换行风格", () => {
  const crlf = CONTENT.replace(/\n/g, "\r\n");
  const r = validatePatchOutput({ patches: [patch()] }, { rel: REL, content: crlf, candidateKeys: KEYS });
  assert.equal(r.ops.length, 1, JSON.stringify(r.rejected));
  assert.ok(!r.ops[0].find.includes("\n"));
  assert.ok(r.ops[0].replace.includes("\r\n"));
  assert.ok(crlf.includes(r.ops[0].find));
});

test("patches 为空数组表示模型判定无法安全修复", () => {
  const r = run([]);
  assert.equal(r.ops.length, 0);
  assert.match(r.rejected[0].reason, /无法安全自动修复/);
});

test("缺少 patches 数组的非法输出被整体拒绝", () => {
  const r = validatePatchOutput({ note: "x" }, { rel: REL, content: CONTENT });
  assert.equal(r.ops.length, 0);
  assert.match(r.rejected[0].reason, /patches/);
});

test("提示词包含候选与命中的证据，不含无关端点", () => {
  const prompt = buildPatchPrompt({
    rel: REL,
    candidates: [
      { method: "GET", path: "/api/orders/:id", fullPath: "/api/orders/:id", kind: "idor-suspect", startLine: 3, hasAuth: true, hasOwnerGuard: false, style: "express" },
    ],
    evidence: [
      { phase: "pre", method: "GET", endpoint: "/api/orders/7", name: "跨用户读取", verdict: "vulnerable", actual: "200 + 他人数据", response: { status: 200 } },
      { phase: "pre", method: "GET", endpoint: "/api/unrelated", name: "无关用例", verdict: "passed", response: { status: 200 } },
    ],
    snippet: CONTENT,
  });
  assert.ok(prompt.includes("src/routes/orders.js"));
  assert.ok(prompt.includes("GET /api/orders/:id"));
  assert.ok(prompt.includes("跨用户读取"));
  assert.ok(!prompt.includes("无关用例"));
  assert.ok(prompt.includes("store.findById"));
});

test("提示词携带上一轮失败反馈（修复循环自纠错）", () => {
  const prompt = buildPatchPrompt({
    rel: REL,
    candidates: [{ method: "GET", path: "/api/orders/:id", fullPath: "/api/orders/:id", kind: "idor-suspect" }],
    evidence: [],
    snippet: CONTENT,
    feedback: {
      round: 1,
      reason: "上一轮补丁未通过双重验收",
      attack_regressed: 1,
      business_regressed: 0,
      failed_cases: [{ case: "跨用户读取", verdict: "regressed", actual: "200 + 他人数据", status: 200 }],
      instruction: "重新生成最小补丁",
    },
  });
  const obj = JSON.parse(prompt);
  assert.equal(obj.previous_attempt.round, 1);
  assert.equal(obj.previous_attempt.failed_cases[0].case, "跨用户读取");
  assert.match(obj.note, /上一轮补丁未通过双重验收/);
});

test("开关：需要 API 密钥，契约 patch 与环境变量可分别控制", () => {
  const savedKey = process.env.DEEPSEEK_API_KEY;
  const savedEnv = process.env.GUARDBUILD_LLM_PATCH;
  delete process.env.DEEPSEEK_API_KEY;
  assert.equal(patchEnabled({ llmConfig: { patch: true } }), false, "无密钥不得启用");
  process.env.DEEPSEEK_API_KEY = "sk-test";
  assert.equal(patchEnabled({ llmConfig: { patch: true } }), true);
  assert.equal(patchEnabled({ llmConfig: { patch: false } }), false);
  assert.equal(patchEnabled({ llmConfig: null }), false);
  process.env.GUARDBUILD_LLM_PATCH = "1";
  assert.equal(patchEnabled({ llmConfig: null }), true);
  assert.equal(patchEnabled({ llmConfig: { patch: false } }), false, "显式关闭优先于环境变量");
  if (savedEnv === undefined) delete process.env.GUARDBUILD_LLM_PATCH;
  else process.env.GUARDBUILD_LLM_PATCH = savedEnv;
  if (savedKey === undefined) delete process.env.DEEPSEEK_API_KEY;
  else process.env.DEEPSEEK_API_KEY = savedKey;
});

test("契约 llm 字段：patch 跟随 enabled，autoVerify 默认开", () => {
  const on = normalizeLlm({ enabled: true });
  assert.equal(on.enabled, true);
  assert.equal(on.patch, true, "开启 LLM 时编码代理默认启用");
  assert.equal(on.autoVerify, true);
  assert.deepEqual(normalizeLlm({ enabled: true, patch: false, autoVerify: false }).patch, false);
  assert.equal(normalizeLlm({ enabled: true, autoVerify: false }).autoVerify, false);
  assert.equal(normalizeLlm({ enabled: false }).patch, false);
  assert.equal(normalizeLlm({ enabled: true, patchMaxFiles: 99 }).patchMaxFiles, 10);
  assert.equal(normalizeLlm({ enabled: true }).fixRounds, 2, "默认允许两轮自纠错");
  assert.equal(normalizeLlm({ enabled: true, fixRounds: 0 }).fixRounds, 0);
  assert.equal(normalizeLlm({ enabled: true, fixRounds: 99 }).fixRounds, 5, "交互模式上限五轮（gate 始终单轮）");
});

const CANDIDATES = [
  { method: "GET", path: "/api/orders/:id", fullPath: "/api/orders/:id", kind: "idor-suspect", startLine: 3 },
];

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

test("requestPatchIntent：采纳合法意图，丢弃模型给出的其它项", async () => {
  const ctx = fakeCtx();
  let sentPrompt = "";
  const res = await requestPatchIntent(ctx, {
    file: `D:\\p\\${REL}`,
    rel: REL,
    content: CONTENT,
    candidates: CANDIDATES,
    evidence: [],
    readRedacted: async () => CONTENT,
    getToken: async () => "tok",
    chatImpl: async (_c, { userPrompt }) => {
      sentPrompt = userPrompt;
      return {
        content: JSON.stringify({
          patches: [
            patch(),
            { ...patch(), file: "package.json" },
            { ...patch(), replace: ANCHOR },
          ],
        }),
        model: "deepseek-test",
        usage: { total_tokens: 42 },
      };
    },
  });
  assert.equal(res.ops.length, 1);
  assert.equal(res.accepted.length, 1);
  assert.equal(res.rejected.length, 2);
  assert.match(res.rejected[0].reason, /越出本次候选文件/);
  assert.equal(res.model, "deepseek-test");
  assert.equal(res.usage.total_tokens, 42);
  assert.equal(res.failure, null);
  assert.ok(sentPrompt.includes("GET /api/orders/:id"));
});

test("requestPatchIntent：feedback 透传到模型提示词", async () => {
  const ctx = fakeCtx();
  let sentPrompt = "";
  await requestPatchIntent(ctx, {
    file: `D:\\p\\${REL}`,
    rel: REL,
    content: CONTENT,
    candidates: CANDIDATES,
    evidence: [],
    feedback: { round: 1, failed_cases: [{ case: "跨用户读取", verdict: "regressed" }] },
    readRedacted: async () => CONTENT,
    getToken: async () => "tok",
    chatImpl: async (_c, { userPrompt }) => {
      sentPrompt = userPrompt;
      return { content: JSON.stringify({ patches: [patch()] }), model: "m", usage: null };
    },
  });
  const obj = JSON.parse(sentPrompt);
  assert.equal(obj.previous_attempt.round, 1);
  assert.equal(obj.previous_attempt.failed_cases[0].case, "跨用户读取");
});

test("requestPatchIntent：非法规则文件不发起请求", async () => {
  const ctx = fakeCtx();
  const res = await requestPatchIntent(ctx, {
    file: "D:\\p\\package.json",
    rel: "package.json",
    content: CONTENT,
    candidates: CANDIDATES,
    readRedacted: async () => CONTENT,
    getToken: async () => "tok",
    chatImpl: async () => {
      throw new Error("不应调用模型");
    },
  });
  assert.equal(res.ops.length, 0);
  assert.match(res.rejected[0].reason, /不允许修改/);
});

test("requestPatchIntent：模型返回非法 JSON 时诚实失败", async () => {
  const ctx = fakeCtx();
  const res = await requestPatchIntent(ctx, {
    file: `D:\\p\\${REL}`,
    rel: REL,
    content: CONTENT,
    candidates: CANDIDATES,
    readRedacted: async () => CONTENT,
    getToken: async () => "tok",
    chatImpl: async () => ({ content: "我建议加个校验，代码如下…" }),
  });
  assert.equal(res.ops.length, 0);
  assert.match(res.failure, /非法 JSON/);
});

test("requestPatchIntent：单会话文件上限生效", async () => {
  const ctx = fakeCtx();
  let calls = 0;
  const chatImpl = async () => {
    calls++;
    return { content: JSON.stringify({ patches: [] }), model: "m", usage: null };
  };
  const args = (rel) => ({
    file: `D:\\p\\${rel}`,
    rel,
    content: CONTENT,
    candidates: [{ method: "GET", path: "/api/x", fullPath: "/api/x", kind: "sqli-suspect" }],
    readRedacted: async () => CONTENT,
    getToken: async () => "tok",
    chatImpl,
    maxFiles: 2,
  });
  await requestPatchIntent(ctx, args("src/a.js"));
  await requestPatchIntent(ctx, args("src/b.js"));
  const third = await requestPatchIntent(ctx, args("src/c.js"));
  assert.equal(calls, 2);
  assert.match(third.failure, /上限/);
});
