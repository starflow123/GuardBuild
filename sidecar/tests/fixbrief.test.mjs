/**
 * 修复简报单元测试：family 判定 / 复现命令 / 复测命令 / 报告集成。
 * 运行：npm run test:sidecar
 */
import test from "node:test";
import assert from "node:assert/strict";

import { detectFamily, buildFixBrief, buildFixBriefs } from "../lib/fixbrief.mjs";
import { buildReport } from "../lib/report.mjs";

test("detectFamily: 静态 kind 与黑盒用例名都映射到正确家族", () => {
  assert.equal(detectFamily({ kind: "sqli-suspect" }), "sqli");
  assert.equal(detectFamily({ kind: "cmdi-suspect" }), "cmdi");
  assert.equal(detectFamily({ kind: "traversal-suspect" }), "traversal");
  assert.equal(detectFamily({ kind: "ssrf-suspect" }), "ssrf");
  assert.equal(detectFamily({ kind: "idor-suspect" }), "idor");
  assert.equal(detectFamily({ kind: "no-auth-suspect" }), "unauth");
  assert.equal(detectFamily({ kind: "supabase-table" }), "supabase_rls");
  assert.equal(detectFamily({ kind: "supabase-service-role-leak" }), "supabase_key");

  assert.equal(detectFamily({ type: "黑盒·未认证读取 /api/orders" }), "unauth");
  assert.equal(
    detectFamily({ type: "黑盒·未认证读取 /api/orders", detail: "响应包含用户/归属类敏感字段" }),
    "unauth",
    "未认证不应因详情里的「归属」被误判为 IDOR"
  );
  assert.equal(detectFamily({ type: "黑盒·跨用户读取（IDOR）/api/orders/3" }), "idor");
  assert.equal(detectFamily({ type: "黑盒·跨用户修改（IDOR-PUT）/api/orders/3" }), "idor");
  assert.equal(detectFamily({ type: "黑盒·SQL 注入（错误回显）/api/items 参数 id" }), "sqli");
  assert.equal(detectFamily({ type: "黑盒·路径穿越 /download" }), "traversal");
  assert.equal(detectFamily({ type: "黑盒·SSRF /api/preview" }), "ssrf");
  assert.equal(detectFamily({ type: "黑盒·敏感文件暴露 /.env" }), "sensitive_file");
  assert.equal(detectFamily({ type: "黑盒·管理/调试面暴露 /actuator/env" }), "debug_surface");
  assert.equal(detectFamily({ type: "未知问题" }), "generic");
});

test("buildFixBrief: 白盒 IDOR 用真实证据生成 curl 与免 --url 的复测命令", () => {
  const brief = buildFixBrief(
    { kind: "idor-suspect", method: "GET", path: "/api/orders/:id", file: "src/orders.js", startLine: 42 },
    {
      mode: "whitebox",
      baseUrl: "http://127.0.0.1:3000",
      projectRoot: "D:/tmp/shop",
      evidence: [
        { verdict: "safe", method: "GET", endpoint: "/api/orders/7", identity: "bob" },
        {
          verdict: "vulnerable",
          method: "GET",
          endpoint: "/api/orders/7",
          identity: "alice",
          request: { body: null },
        },
      ],
    }
  );
  assert.equal(brief.family, "idor");
  assert.match(brief.reproduce, /^curl -X GET -H "Authorization: Bearer <alice_token>" 'http:\/\/127\.0\.0\.1:3000\/api\/orders\/7'$/);
  assert.match(brief.verify, /guardbuild-headless\.exe --project "D:\/tmp\/shop" --gate/);
  assert.doesNotMatch(brief.verify, /--url/);
  assert.ok(brief.inspect.length > 0);
  assert.ok(brief.fix.length > 0);
});

test("buildFixBrief: 查询参数与 :param 形态都能匹配到证据；无证据时回退为具体路径", () => {
  const q = buildFixBrief(
    { kind: "idor-suspect", method: "GET", path: "/api/invoices", routePath: "/api/invoices" },
    {
      mode: "whitebox",
      baseUrl: "http://127.0.0.1:3000",
      projectRoot: "D:/tmp/shop",
      evidence: [
        {
          verdict: "vulnerable",
          method: "GET",
          endpoint: "/api/invoices?invoiceId=9",
          identity: "(anonymous)",
          request: { body: null },
        },
      ],
    }
  );
  assert.match(q.reproduce, /\/api\/invoices\?invoiceId=9/);
  assert.doesNotMatch(q.reproduce, /Bearer/);

  const fb = buildFixBrief(
    { kind: "traversal-suspect", method: "GET", path: "/api/files/:name" },
    { mode: "whitebox", baseUrl: "http://127.0.0.1:3000", projectRoot: "D:/tmp/shop", evidence: [] }
  );
  assert.equal(fb.reproduce, "curl -X GET 'http://127.0.0.1:3000/api/files/1'");
});

test("buildFixBrief: Supabase RLS / service_role 给出专属复现命令", () => {
  const rls = buildFixBrief(
    { kind: "supabase-table", path: "table:profiles", resource: "profiles" },
    { mode: "whitebox", projectRoot: "D:/tmp/shop", supabaseUrl: "https://abc.supabase.co" }
  );
  assert.equal(rls.family, "supabase_rls");
  assert.match(rls.reproduce, /https:\/\/abc\.supabase\.co\/rest\/v1\/profiles\?select=\*/);
  assert.match(rls.reproduce, /<ANON_KEY>/);

  const key = buildFixBrief(
    { kind: "supabase-service-role-leak", path: "env:NEXT_PUBLIC_SERVICE_ROLE" },
    { mode: "whitebox", projectRoot: "D:/tmp/shop" }
  );
  assert.equal(key.family, "supabase_key");
  assert.match(key.reproduce, /grep -rn "service_role/);
  assert.match(key.fix, /轮换/);
});

test("buildFixBriefs: 黑盒报告直接用已记录的 curl，复测命令带 --url", () => {
  const briefs = buildFixBriefs({
    blackbox: {
      url: "http://127.0.0.1:4000",
      findings: [
        {
          type: "黑盒·未认证读取 /api/accounts/summary",
          method: "GET",
          path: "/api/accounts/summary?full=1",
          detail: "匿名请求返回管理员邮箱",
          curl: "curl -X GET http://127.0.0.1:4000/api/accounts/summary?full=1",
        },
      ],
    },
    evidence: { blackbox: [] },
    summary: { findings: [] },
    session: { projectRoot: "D:/tmp/shop" },
  });
  assert.equal(briefs.length, 1);
  assert.equal(briefs[0].source, "blackbox");
  assert.equal(briefs[0].family, "unauth");
  assert.equal(briefs[0].reproduce, "curl -X GET http://127.0.0.1:4000/api/accounts/summary?full=1");
  assert.match(briefs[0].verify, /--url "http:\/\/127\.0\.0\.1:4000"/);
});

test("buildVerify: Host 的 \\\\?\\ 前缀与反斜杠规范化为可复制路径", () => {
  const brief = buildFixBrief(
    { kind: "idor-suspect", method: "GET", path: "/api/orders/:id" },
    { mode: "whitebox", projectRoot: "\\\\?\\D:\\shop\\app", evidence: [] }
  );
  assert.match(brief.verify, /--project "D:\/shop\/app"/);
  assert.doesNotMatch(brief.verify, /\\\\\?\\/);
});

test("buildReport: report.json 写入 summary.fixBriefs，markdown 渲染修复简报", () => {
  const ctx = {
    sessionId: "sess-test",
    gate: true,
    targetConfig: null,
    view: {
      projectRoot: "D:/tmp/shop",
      projectName: "shop",
      startedAt: 1,
      state: "evidenced",
      findings: [
        {
          id: "fi1",
          method: "GET",
          path: "/api/orders/:id",
          routePath: "/api/orders/:id",
          file: "src/orders.js",
          startLine: 42,
          resource: "orders",
          kind: "idor-suspect",
          sinkCalls: [],
          reason: "按对象 ID 取资源但未见归属校验（IDOR 静态线索）",
        },
      ],
      evidence: [
        {
          phase: "pre",
          verdict: "vulnerable",
          method: "GET",
          endpoint: "/api/orders/7",
          identity: "alice",
          request: { body: null },
        },
      ],
      phases: {},
      targets: { original: { url: "http://127.0.0.1:3000" } },
      patch: null,
      supabase: null,
      blackbox: null,
      acceptance: null,
      llm: null,
      error: null,
    },
  };
  const { json, markdown } = buildReport(ctx, { outcome: "vulnerable_unfixed", exitCode: 1 });
  assert.equal(json.summary.fixBriefs.length, 1);
  assert.equal(json.summary.fixBriefs[0].family, "idor");
  assert.match(json.summary.fixBriefs[0].reproduce, /\/api\/orders\/7/);
  assert.match(markdown, /## 修复简报（1）/);
  assert.match(markdown, /建议排查的代码形态/);
  assert.match(markdown, /修复后复测/);
});
