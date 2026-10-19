import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  sanitizeStart,
  sanitizeLogin,
  validateScoutResult,
  runScout,
  applyScoutResult,
  recordScoutVerification,
  clearScoutCache,
} from "../lib/scout.mjs";
import { analyzeProject } from "../lib/analyzer.mjs";
import { buildProbePlan } from "../lib/planner.mjs";
import { RPC_TO_HOST } from "../../shared/protocol.mjs";

const ROOT = "\\\\?\\D:\\scout-target";

function makeRpcCtx({ files }) {
  const calls = { list: 0, read: 0 };
  return {
    calls,
    ctx: {
      projectRoot: ROOT,
      tokens: { project: "tok" },
      rpc: {
        request: async (method, params) => {
          if (method === RPC_TO_HOST.FS_LIST) {
            calls.list++;
            return {
              entries: Object.keys(files).map((rel) => ({
                path: `${ROOT}\\${rel.split("/").join("\\")}`,
                kind: "file",
                size: files[rel].length,
              })),
            };
          }
          if (method === RPC_TO_HOST.FS_READ) {
            calls.read++;
            const rel = String(params.path)
              .replace(/^\\\\\?\\/, "")
              .replace(/\\/g, "/")
              .replace(/^D:\/scout-target\//, "");
            if (files[rel] == null) throw new Error(`ENOENT ${rel}`);
            return { content: files[rel], size: files[rel].length, redacted: true, redactions: [] };
          }
          throw new Error(`不应调用 ${method}`);
        },
      },
    },
  };
}

const FILES = {
  "package.json": JSON.stringify({ name: "mystery-app", main: "boot.mjs" }),
  "server.js": [
    "const app = require('express')();",
    "app.post('/api/login', (req, res) => res.json({ token: 't' }));",
    "app.get('/api/orders/:id', (req, res) => res.json({ id: req.params.id }));",
    "app.get('/api/items', (req, res) => res.json({ items: [] }));",
  ].join("\n"),
};

function tempDataDir() {
  const dir = mkdtempSync(join(tmpdir(), "gb-scout-"));
  const saved = process.env.GUARDBUILD_DATA_DIR;
  process.env.GUARDBUILD_DATA_DIR = dir;
  return {
    dir,
    restore() {
      if (saved == null) delete process.env.GUARDBUILD_DATA_DIR;
      else process.env.GUARDBUILD_DATA_DIR = saved;
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

const LLM_JSON = JSON.stringify({
  start: { cmd: "node", args: ["server.js"], env: { PORT: "${GB_PORT}" }, readyPattern: "listening" },
  login: {
    path: "/api/login",
    bodyTemplate: { email: "{email}", password: "{password}" },
    credentialPath: "token",
  },
  identities: [{ name: "alice", password: "x" }],
  routes: [
    { method: "GET", path: "/api/orders/:id", file: "server.js", line: 3, resource: "order", hasAuth: true },
    { method: "GET", path: "/api/missing/:id", file: "server.js", line: 4 },
    { method: "GET", path: "/api/orders", file: "server.js", line: 3 },
  ],
  notes: ["基于 app.js 推断"],
});

test("sanitizeStart：白名单、shell 元字符、cwd、端口槽位", () => {
  const warnings = [];
  assert.equal(sanitizeStart({ cmd: "bash", args: ["-c", "id"] }, {}, warnings), null);
  assert.ok(warnings.some((w) => w.includes("白名单")));

  assert.equal(sanitizeStart({ cmd: "node", args: ["x; rm -rf /"] }, {}, warnings), null);
  assert.ok(warnings.some((w) => w.includes("shell 元字符")));

  const badCwd = sanitizeStart({ cmd: "node", args: ["s.js"], cwd: "../outside" }, { dirs: new Set(["."]) }, warnings);
  assert.equal(badCwd.cwd, null);
  assert.ok(warnings.some((w) => w.includes("cwd")));

  const ok = sanitizeStart(
    { cmd: "node", args: ["server.js", "--port", "${GB_PORT}"], env: { APP_PORT: "${GB_PORT}", NODE_OPTIONS: "${GB_PORT}" } },
    { dirs: new Set(["."]) },
    []
  );
  assert.equal(ok.cmd, "node");
  assert.deepEqual(ok.args, ["server.js", "--port", "${GB_PORT}"]);
  assert.deepEqual(ok.env, { APP_PORT: "${GB_PORT}" });
});

test("sanitizeLogin：仅 POST、站内路径、字段白名单", () => {
  const warnings = [];
  assert.equal(sanitizeLogin({ path: "/api/login", method: "GET" }, warnings), null);
  assert.equal(sanitizeLogin({ path: "https://evil.example/login" }, warnings), null);
  const ok = sanitizeLogin(
    { path: "/auth/login", bodyTemplate: { email: "{email}", password: "{password}" }, credentialPath: "data.token" },
    warnings
  );
  assert.equal(ok.path, "/auth/login");
  assert.deepEqual(ok.bodyTemplate, { email: "{email}", password: "{password}" });
  assert.equal(ok.credentialPath, "data.token");
});

test("validateScoutResult：丢弃无法定位的路由，保留查询参数路由", async () => {
  const warnings = [];
  const evidence = { dirs: new Set(["."]), files: [{ rel: "server.js", content: FILES["server.js"] }] };
  const raw = {
    login: { path: "/api/login" },
    routes: [
      { method: "GET", path: "/api/orders/{id}", file: "server.js", resource: "order" },
      { method: "GET", path: "/api/orders/:id", file: "server.js", resource: "order" },
      { method: "GET", path: "/api/orders", file: "server.js", query: "status" },
      { method: "GET", path: "/api/items", file: "server.js", list: true, hasOwnerFilter: true },
      { method: "GET", path: "/api/nope/:id", file: "server.js" },
    ],
    identities: [{ name: "alice" }],
  };
  const out = await validateScoutResult(raw, { evidence, readFile: async () => "" }, warnings);
  assert.deepEqual(
    out.routes.map((r) => `${r.method} ${r.path}`),
    ["GET /api/orders/:id", "GET /api/orders", "GET /api/items"]
  );
  // 路径参数化后与已有路由重复（{id} → :id），去重后保留一条
  assert.equal(out.routes[0].line, 3);
  assert.equal(out.routes[1].query, "status");
  assert.equal(out.routes[2].list, true);
  assert.equal(out.routes[2].hasOwnerFilter, true);
  assert.ok(warnings.some((w) => w.includes("identities")));
});

test("runScout：无 key 返回 null；有 chat 注入时校验、缓存且只调用一次", async () => {
  clearScoutCache();
  const temp = tempDataDir();
  const saved = process.env.DEEPSEEK_API_KEY;
  try {
    delete process.env.DEEPSEEK_API_KEY;
    assert.equal(await runScout(makeRpcCtx({ files: FILES }).ctx, { getToken: async () => "t" }), null);

    process.env.DEEPSEEK_API_KEY = "test-key";
    let chatCalls = 0;
    const chatImpl = async () => {
      chatCalls++;
      return { content: LLM_JSON, model: "deepseek-chat", usage: { prompt_tokens: 1 } };
    };
    const first = await runScout(makeRpcCtx({ files: FILES }).ctx, {
      getToken: async () => "t",
      chatImpl,
      model: "deepseek-chat",
    });
    assert.equal(first._source, "llm-scout");
    assert.equal(first._unverified, true);
    assert.equal(first.start.cmd, "node");
    assert.equal(first.login.path, "/api/login");
    assert.deepEqual(first.routes.map((r) => r.path), ["/api/orders/:id"]);
    assert.ok(first.warnings.some((w) => w.includes("/api/missing/:id")));
    assert.equal(first.cached, false);

    const second = await runScout(makeRpcCtx({ files: FILES }).ctx, {
      getToken: async () => "t",
      chatImpl,
      model: "deepseek-chat",
    });
    assert.equal(second.cached, true);
    assert.equal(chatCalls, 1);
  } finally {
    clearScoutCache();
    temp.restore();
    if (saved == null) delete process.env.DEEPSEEK_API_KEY;
    else process.env.DEEPSEEK_API_KEY = saved;
  }
});

test("runScout：侦察结果落盘，无密钥时仍可跨会话复用", async () => {
  clearScoutCache();
  const temp = tempDataDir();
  const saved = process.env.DEEPSEEK_API_KEY;
  try {
    process.env.DEEPSEEK_API_KEY = "test-key";
    let chatCalls = 0;
    const chatImpl = async () => {
      chatCalls++;
      return { content: LLM_JSON, model: "deepseek-chat", usage: { prompt_tokens: 1, total_tokens: 2 } };
    };
    const first = await runScout(makeRpcCtx({ files: FILES }).ctx, {
      getToken: async () => "t",
      chatImpl,
      model: "deepseek-chat",
    });
    assert.equal(first.cached, false);
    assert.ok(first._cacheFile && existsSync(first._cacheFile));
    const cachedJson = readFileSync(first._cacheFile, "utf8");
    assert.ok(!cachedJson.includes("test-key"));
    assert.ok(!cachedJson.includes("alice"));
    const cachedData = JSON.parse(cachedJson);
    assert.equal(cachedData.identities, undefined);
    assert.equal(cachedData.version, "scout-v1");
    assert.equal(cachedData.start.cmd, "node");
    assert.equal(cachedData.login.path, "/api/login");
    assert.equal(cachedData.verified.start, null);
    assert.equal(cachedData.verified.login, null);

    clearScoutCache();
    delete process.env.DEEPSEEK_API_KEY;
    const second = await runScout(makeRpcCtx({ files: FILES }).ctx, {
      getToken: async () => "t",
      chatImpl,
      model: "deepseek-chat",
    });
    assert.equal(second.cached, true);
    assert.equal(second.cacheSource, "disk");
    assert.equal(second.start.cmd, "node");
    assert.equal(second.login.path, "/api/login");
    assert.equal(chatCalls, 1);
  } finally {
    clearScoutCache();
    temp.restore();
    if (saved == null) delete process.env.DEEPSEEK_API_KEY;
    else process.env.DEEPSEEK_API_KEY = saved;
  }
});

test("recordScoutVerification：启动验证失败写回缓存，下次忽略该启动方式", async () => {
  clearScoutCache();
  const temp = tempDataDir();
  const saved = process.env.DEEPSEEK_API_KEY;
  try {
    process.env.DEEPSEEK_API_KEY = "test-key";
    const { ctx } = makeRpcCtx({ files: FILES });
    const first = await runScout(ctx, {
      getToken: async () => "t",
      chatImpl: async () => ({ content: LLM_JSON, model: "deepseek-chat" }),
      model: "deepseek-chat",
    });
    ctx.scoutCacheFile = first._cacheFile;
    assert.equal(recordScoutVerification(ctx, { start: false, login: true }), true);
    const savedData = JSON.parse(readFileSync(first._cacheFile, "utf8"));
    assert.equal(savedData.verified.start, false);
    assert.equal(savedData.verified.login, true);

    clearScoutCache();
    delete process.env.DEEPSEEK_API_KEY;
    const second = await runScout(makeRpcCtx({ files: FILES }).ctx, {
      getToken: async () => "t",
      model: "deepseek-chat",
    });
    assert.equal(second.cached, true);
    assert.equal(second.start, null);
    assert.equal(second.login.path, "/api/login");
    assert.ok(second.warnings.some((w) => w.includes("启动验证") && w.includes("已忽略")));
  } finally {
    clearScoutCache();
    temp.restore();
    if (saved == null) delete process.env.DEEPSEEK_API_KEY;
    else process.env.DEEPSEEK_API_KEY = saved;
  }
});

test("runScout：证据变化使磁盘缓存失效", async () => {
  clearScoutCache();
  const temp = tempDataDir();
  const saved = process.env.DEEPSEEK_API_KEY;
  try {
    process.env.DEEPSEEK_API_KEY = "test-key";
    let chatCalls = 0;
    const chatImpl = async () => {
      chatCalls++;
      return { content: LLM_JSON, model: "deepseek-chat" };
    };
    await runScout(makeRpcCtx({ files: FILES }).ctx, {
      getToken: async () => "t",
      chatImpl,
      model: "deepseek-chat",
    });
    clearScoutCache();
    const changed = { ...FILES, "server.js": `${FILES["server.js"]}\n// changed` };
    const second = await runScout(makeRpcCtx({ files: changed }).ctx, {
      getToken: async () => "t",
      chatImpl,
      model: "deepseek-chat",
    });
    assert.equal(second.cached, false);
    assert.equal(chatCalls, 2);
  } finally {
    clearScoutCache();
    temp.restore();
    if (saved == null) delete process.env.DEEPSEEK_API_KEY;
    else process.env.DEEPSEEK_API_KEY = saved;
  }
});

test("applyScoutResult：显式契约优先，LLM 只补缺", () => {
  const contract = {
    startSource: "contract",
    start: { cmd: "npm", args: ["run", "dev"], env: {}, readyPattern: "ready", readyTimeoutMs: 1000 },
    login: { path: "/login" },
    llmRoutes: null,
  };
  const r1 = applyScoutResult(contract, {
    start: { cmd: "node", args: ["server.js"] },
    login: { path: "/api/login" },
    routes: [{ method: "GET", path: "/orders/:id", file: "server.js" }],
  });
  assert.deepEqual(r1, { start: false, login: false, routes: 1 });
  assert.equal(contract.start.cmd, "npm");
  assert.equal(contract.login.path, "/login");
  assert.equal(contract.llmRoutes.length, 1);

  const fallback = {
    startSource: "default",
    start: { cmd: "node", args: ["server.js"], env: {}, readyPattern: "x", readyTimeoutMs: 1000 },
    login: null,
    llmRoutes: null,
  };
  const r2 = applyScoutResult(fallback, {
    start: { cmd: "node", args: ["boot.mjs"], env: { PORT: "${GB_PORT}" }, readyPattern: "listening" },
    login: { path: "/api/login" },
    routes: [],
  });
  assert.deepEqual(r2, { start: true, login: true, routes: 0 });
  assert.equal(fallback.startSource, "llm-scout");
  assert.equal(fallback.start.args[0], "boot.mjs");
  assert.equal(fallback.loginSource, "llm-scout");
});

test("analyzeProject：LLM 侦察路由并入候选，来源标记 llm-scout", async () => {
  // 裸 http 服务：静态适配器认不出路由，只能依赖 LLM 线索
  const bare = {
    "package.json": JSON.stringify({ name: "mystery-app" }),
    "server.js": [
      "const http = require('http');",
      "// GET /api/invoices/:id -> invoice handler",
      "// GET /api/invoices -> list handler",
      "http.createServer((req, res) => res.end('ok')).listen(3000);",
    ].join("\n"),
  };
  const { ctx } = makeRpcCtx({ files: bare });
  ctx.targetConfig = {
    llmRoutes: [
      { method: "GET", path: "/api/invoices/:id", file: "server.js", line: 2, resource: "invoice", hasAuth: true },
      {
        method: "GET",
        path: "/api/invoices",
        file: "server.js",
        line: 3,
        resource: "invoice",
        hasAuth: true,
        list: true,
        hasOwnerFilter: true,
      },
    ],
  };
  const a = await analyzeProject(ctx);
  const ep = a.endpoints.find((e) => e.fullPath === "/api/invoices/:id");
  assert.ok(ep);
  assert.equal(ep.source, "llm-scout");
  assert.equal(ep.startLine, 2);
  assert.equal(ep.file, "server.js");
  const cand = a.candidates.find((c) => c.fullPath === "/api/invoices/:id");
  assert.equal(cand.kind, "idor-suspect");
  assert.equal(cand.source, "llm-scout");
  const listEp = a.endpoints.find((e) => e.fullPath === "/api/invoices");
  assert.equal(listEp.hasOwnerFilter, true);
  // 列表路由不产生攻击候选，但能被探测计划用作资源发现端点
  assert.equal(a.candidates.some((c) => c.fullPath === "/api/invoices"), false);
  assert.equal(buildProbePlan(a).listEndpoint?.path, "/api/invoices");
  assert.equal(a.diagnostics.endpointsFromLlm, 2);
});
