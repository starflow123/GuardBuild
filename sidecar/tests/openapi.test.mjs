import { test } from "node:test";
import assert from "node:assert/strict";
import { parseOpenapiDoc, MAX_OPENAPI_PATHS } from "../lib/openapi.mjs";
import { analyzeProject } from "../lib/analyzer.mjs";

test("把 {id} 路径参数转成 :id 并产出 endpoint", () => {
  const doc = {
    openapi: "3.0.0",
    servers: [{ url: "http://localhost:3000/api" }],
    paths: {
      "/users/{id}": {
        get: {
          security: [{ bearer: [] }],
          parameters: [{ name: "id", in: "path", required: true }],
        },
      },
      "/orders": { get: { parameters: [{ name: "status", in: "query" }] } },
    },
  };
  const { endpoints, warnings } = parseOpenapiDoc(doc, {});
  assert.equal(endpoints.length, 2);
  const userEp = endpoints.find((e) => e.method === "GET" && e.path === "/users/:id");
  assert.ok(userEp);
  assert.equal(userEp.fullPath, "/api/users/:id");
  assert.equal(userEp.hasAuth, true);
  assert.equal(userEp.authSource, "openapi-declared");
  assert.equal(userEp.source, "openapi");
  assert.equal(userEp.file, null);
  // 无 path param 但有 query → queryParam 线索
  const ordersEp = endpoints.find((e) => e.path === "/orders");
  assert.ok(ordersEp);
  assert.equal(ordersEp.queryParam.param, "status");
  assert.equal(ordersEp.hasAuth, false);
  assert.deepEqual(warnings, []);
});

test("顶层 security 作 fallback，显式空 security 数组表示放行", () => {
  const doc = {
    paths: {
      "/public/{id}": { get: { security: [] } },
      "/private/{id}": { get: {} },
    },
    security: [{ bearer: [] }],
  };
  const { endpoints } = parseOpenapiDoc(doc, {});
  const pub = endpoints.find((e) => e.path === "/public/:id");
  const priv = endpoints.find((e) => e.path === "/private/:id");
  assert.equal(pub.hasAuth, false);
  assert.equal(priv.hasAuth, true);
});

test("basePath 配置覆盖 servers 推导", () => {
  const doc = { paths: { "/x/{id}": { get: {} } } };
  const { endpoints } = parseOpenapiDoc(doc, { basePath: "/v2" });
  assert.equal(endpoints[0].fullPath, "/v2/x/:id");
});

test("超过上限截断并 warning", () => {
  const paths = {};
  for (let i = 0; i < MAX_OPENAPI_PATHS + 10; i++) paths[`/r${i}/{id}`] = { get: {} };
  const { endpoints, warnings } = parseOpenapiDoc({ paths }, {});
  assert.equal(endpoints.length, MAX_OPENAPI_PATHS);
  assert.ok(warnings[0].includes("超过上限"));
});

test("坏输入不崩", () => {
  assert.deepEqual(parseOpenapiDoc(null, {}).endpoints, []);
  assert.deepEqual(parseOpenapiDoc({}, {}).endpoints, []);
  assert.deepEqual(parseOpenapiDoc({ paths: "nope" }, {}).endpoints, []);
});

test("analyzeProject: 从 openapi.json 合并出 idor-suspect 候选（未知框架）", async () => {
  const R = "\\\\?\\D:\\openapi-target";
  // 未知框架的 server.js：裸 http，无 Express 路由装饰，静态适配器认不出
  const serverJs = [
    "const http = require('http');",
    "http.createServer((req, res) => {",
    "  res.end('ok');",
    "}).listen(3000);",
  ].join("\n");
  const openapiJson = JSON.stringify({
    openapi: "3.0.0",
    paths: {
      "/users/{id}": { get: { security: [{ bearer: [] }] } },
      "/orders": { get: { parameters: [{ name: "status", in: "query" }] } },
    },
  });
  const ctx = {
    projectRoot: R,
    tokens: { project: "tok" },
    targetConfig: { openapi: { file: "./openapi.json" } },
    rpc: {
      request: async (method, params) => {
        if (method === "fs.list") {
          return {
            entries: [
              { path: `${R}\\server.js`, kind: "file", size: 100 },
              { path: `${R}\\openapi.json`, kind: "file", size: 200 },
            ],
          };
        }
        if (method === "fs.read") {
          if (String(params.path).endsWith("openapi.json")) return { content: openapiJson, size: 200, redacted: false, redactions: [] };
          return { content: serverJs, size: 100, redacted: false, redactions: [] };
        }
        throw new Error(`不应调用 ${method}`);
      },
    },
  };
  const a = await analyzeProject(ctx);
  // 从 openapi 解析出 2 个端点
  const userEp = a.endpoints.find((e) => e.fullPath === "/users/:id");
  assert.ok(userEp, "应从 openapi 解析出 /users/:id");
  assert.equal(userEp.source, "openapi");
  // 产出 idor-suspect 候选（有 path param + hasAuth）
  const cand = a.candidates.find((c) => c.fullPath === "/users/:id");
  assert.ok(cand, "openapi 端点应产出 idor-suspect 候选");
  assert.equal(cand.kind, "idor-suspect");
  assert.equal(a.diagnostics.endpointsFromOpenapi, 2);
});
