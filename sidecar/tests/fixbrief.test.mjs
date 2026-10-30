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
  assert.equal(detectFamily({ kind: "upload-suspect" }), "upload");
  assert.equal(detectFamily({ kind: "jwt-suspect" }), "jwt");
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
  assert.equal(detectFamily({ type: "黑盒·文件上传（主动内容）/api/avatar" }), "upload");
  assert.equal(detectFamily({ type: "黑盒·JWT 令牌伪造 /api/me" }), "jwt");
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
  assert.match(brief.risk, /本轮已用跨身份请求复现/, "有 vulnerable 证据才可以说「已复现」");
});

test("buildFixBrief: 纯静态候选不得声称「本轮已复现」", () => {
  const brief = buildFixBrief(
    { kind: "idor-suspect", method: "GET", path: "/api/orders/:id", file: "src/orders.js", startLine: 42 },
    {
      mode: "whitebox",
      baseUrl: "http://127.0.0.1:3000",
      projectRoot: "D:/tmp/shop",
      evidence: [{ verdict: "safe", method: "GET", endpoint: "/api/orders/7", identity: "bob" }],
    }
  );
  assert.doesNotMatch(brief.risk, /已用跨身份请求复现/, "没有越权证据时不能写出复现字样");
  assert.match(brief.risk, /本轮为静态线索，未经运行期请求复现/);
  assert.match(brief.risk, /按客户端提供的对象 ID 取数但未校验归属/, "静态风险描述本身仍要保留");

  const noEv = buildFixBrief(
    { kind: "idor-suspect", method: "GET", path: "/api/orders/:id" },
    { mode: "whitebox", evidence: [] }
  );
  assert.doesNotMatch(noEv.risk, /已用跨身份请求复现/, "无任何证据记录时同样只给静态结论");

  const bb = buildFixBrief(
    { type: "黑盒·跨用户读取（IDOR）/api/orders/3", path: "/api/orders/3" },
    { mode: "blackbox", evidence: [] }
  );
  assert.match(bb.risk, /本轮已用跨身份请求复现/, "黑盒 finding 本身就是复现产物");
});

test("buildFixBrief: JWT 伪造令牌走 jwt 家族，复现命中已记录的受保护端点", () => {
  const brief = buildFixBrief(
    { kind: "jwt-suspect", method: "GET", path: "/api/me", resource: "token" },
    {
      mode: "whitebox",
      baseUrl: "http://127.0.0.1:3000",
      projectRoot: "D:/tmp/shop",
      evidence: [{ verdict: "vulnerable", method: "GET", endpoint: "/api/me", identity: "(anonymous)" }],
    }
  );
  assert.equal(brief.family, "jwt");
  assert.match(brief.reproduce, /'http:\/\/127\.0\.0\.1:3000\/api\/me'/);
  assert.match(brief.fix, /verify/);
  assert.match(brief.fix, /算法/);
  assert.match(brief.fix, /alg=none/);
});

test("buildFixBrief: 业务逻辑/竞态走 bizlogic 家族，复现命中状态流转端点", () => {
  assert.equal(detectFamily({ kind: "bizlogic-suspect" }), "bizlogic");
  assert.equal(detectFamily({ type: "黑盒·并发双花 /api/orders/1/refund" }), "bizlogic");
  const brief = buildFixBrief(
    { kind: "bizlogic-suspect", method: "POST", path: "/api/orders/:id/ship", resource: "order" },
    {
      mode: "whitebox",
      baseUrl: "http://127.0.0.1:3000",
      projectRoot: "D:/tmp/shop",
      evidence: [{ verdict: "vulnerable", method: "POST", endpoint: "/api/orders/:id/ship", identity: "alice" }],
    }
  );
  assert.equal(brief.family, "bizlogic");
  assert.match(brief.reproduce, /'http:\/\/127\.0\.0\.1:3000\/api\/orders\/:id\/ship'/);
  assert.match(brief.fix, /状态机/);
  assert.match(brief.fix, /幂等/);
  assert.match(brief.risk, /并发|状态/);
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
  assert.match(json.summary.fixBriefs[0].risk, /本轮已用跨身份请求复现/);
});

test("buildReport: 挂载前缀写进复现命令、扩展长度路径不进报告、无证据时不声称复现", () => {
  const ctx = {
    sessionId: "sess-mount",
    gate: true,
    targetConfig: null,
    view: {
      projectRoot: "\\\\?\\D:\\shop\\app",
      projectName: "shop",
      startedAt: 1,
      state: "evidenced",
      findings: [
        {
          id: "fi2",
          method: "POST",
          path: "/auth/:role/register",
          routePath: "/:role/register",
          file: "\\\\?\\D:\\shop\\app\\routes\\auth.js",
          startLine: 182,
          resource: "auth",
          kind: "idor-suspect",
          sinkCalls: [],
          reason: "按对象 ID 取资源但未见归属校验（IDOR 静态线索）",
        },
      ],
      evidence: [],
      phases: {},
      targets: { original: { url: "http://127.0.0.1:59448" } },
      patch: null,
      supabase: null,
      blackbox: null,
      acceptance: null,
      llm: null,
      error: null,
    },
  };
  const { json, markdown } = buildReport(ctx, { outcome: "inconclusive", exitCode: 2 });
  const brief = json.summary.fixBriefs[0];
  assert.equal(brief.reproduce, `curl -X POST 'http://127.0.0.1:59448/auth/1/register'`, "要用挂载后的完整地址");
  assert.doesNotMatch(brief.reproduce, /:\/\/[^/]*\/1\/register/, "不能把路由器内的相对地址当端点");
  assert.match(brief.risk, /本轮为静态线索，未经运行期请求复现/);
  assert.doesNotMatch(markdown, /\\\\\?\\/, "报告里不应出现 Windows 扩展长度路径前缀");
  assert.match(markdown, /D:\/shop\/app|D:\\shop\\app/);
});
