import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { RPC_TO_HOST } from "../../shared/protocol.mjs";
import { analyzeProject } from "../lib/analyzer.mjs";
import { buildProbePlan } from "../lib/planner.mjs";
import { buildCases } from "../lib/probe.mjs";
import { findSsrfSignal } from "../lib/signals.mjs";

function listen(handler) {
  return new Promise((resolve) => {
    const server = createServer(handler);
    server.listen(0, "127.0.0.1", () => {
      const port = server.address().port;
      resolve({ server, url: `http://127.0.0.1:${port}` });
    });
  });
}

function stubCtx() {
  return {
    tokens: { net: "net-token" },
    loginConfig: null,
    rpc: {
      request: async (method, params) => {
        if (method !== RPC_TO_HOST.HTTP_REQUEST) throw new Error(`不应调用 ${method}`);
        const res = await fetch(params.url, { method: params.method, headers: params.headers });
        return {
          status: res.status,
          statusText: res.statusText,
          body: await res.text(),
          headers: Object.fromEntries(res.headers),
        };
      },
    },
  };
}

test("findSsrfSignal: URL 直接来自请求输入（query / 变量 / 拼接 / Python）", () => {
  assert.deepEqual(
    findSsrfSignal('const r = await fetch(req.query.url);'),
    { source: "query", param: "url", sink: "fetch", form: "direct" }
  );
  assert.deepEqual(
    findSsrfSignal('const target = req.body.target;\nconst r = await fetch(target);'),
    { source: "body", param: "target", sink: "fetch", form: "variable" }
  );
  assert.deepEqual(
    findSsrfSignal('const { url } = req.query;\naxios.get(url);'),
    { source: "query", param: "url", sink: "get", form: "variable" }
  );
  assert.deepEqual(
    findSsrfSignal('const u = `http://${req.query.host}/health`;\nawait fetch(u);'),
    { source: "query", param: "host", sink: "fetch", form: "variable" }
  );
  assert.deepEqual(
    findSsrfSignal('requests.get(request.args.get("next"))'),
    { source: "query", param: "next", sink: "get", form: "direct" }
  );
  assert.equal(findSsrfSignal('await fetch("/api/health")'), null, "固定 URL 不应成为 SSRF 候选");
  assert.equal(findSsrfSignal('const u = buildInternalUrl();\nawait fetch(u);'), null, "无请求输入不应命中");
});

test("analyzeProject + buildProbePlan: SSRF 候选进入探测计划", async () => {
  const R = "\\\\?\\D:\\ssrf";
  const source = [
    "export async function handleRequest(req, res) {",
    '  if (method === "GET" && pathname === "/api/preview") {',
    "    if (!auth) return json(res, 401, { error: '未登录' });",
    '    const target = url.searchParams.get("url") ?? "";',
    "    const upstream = await fetch(target);",
    "    return json(res, 200, { preview: await upstream.text() });",
    "  }",
    "}",
  ].join("\n");
  const ctx = {
    projectRoot: R,
    tokens: { project: "tok" },
    rpc: {
      request: async (method, params) => {
        if (method === "fs.list") return { entries: [{ path: `${R}\\server.js`, kind: "file", size: 400 }] };
        if (method === "fs.read") return { content: source, size: 400, redacted: false, redactions: [] };
        throw new Error(`不应调用 ${method}`);
      },
    },
  };
  const a = await analyzeProject(ctx);
  const cand = a.candidates.find((c) => c.kind === "ssrf-suspect");
  assert.ok(cand, "fetch(请求参数) 应产生 ssrf-suspect 候选");
  assert.equal(cand.fullPath, "/api/preview");
  assert.deepEqual(cand.ssrf, { source: "query", param: "url", sink: "fetch", form: "variable" });

  const plan = buildProbePlan(a);
  assert.equal(plan.ssrfCandidate?.fullPath, "/api/preview");
  assert.equal(plan.ssrfCandidates.length, 1);
});

test("buildCases + canary: 目标回连 canary 即判 vulnerable，硬化后判 blocked", async () => {
  let hardened = false;
  const vulnerable = await listen(async (req, res) => {
    const url = new URL(req.url, "http://127.0.0.1");
    if (url.pathname !== "/api/preview") {
      res.writeHead(404).end();
      return;
    }
    const target = url.searchParams.get("url") ?? "";
    if (hardened && !target.startsWith("http://api.example.com/")) {
      res.writeHead(403, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "主机不在白名单" }));
      return;
    }
    try {
      const upstream = await fetch(target);
      const body = await upstream.text();
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ preview: body }));
    } catch (err) {
      res.writeHead(502, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: String(err?.message ?? err) }));
    }
  });

  try {
    const cand = {
      path: "/api/preview",
      fullPath: "/api/preview",
      method: "GET",
      ssrf: { source: "query", param: "url", sink: "fetch", form: "variable" },
      routeKeys: ["preview.get"],
    };
    const cases = buildCases(
      { plan: { ssrfCandidates: [cand] }, targetConfig: null },
      { attacker: { name: "alice", user: { id: 1 } }, victim: { name: "bob", user: { id: 2 } } }
    );
    assert.equal(cases.length, 1);
    const kase = cases[0];
    assert.equal(kase.id, "attack-ssrf");
    assert.equal(kase.unfixable, true);
    assert.equal(kase.identity, "alice");

    const ctx = stubCtx();
    const out = await kase.send(ctx, vulnerable.url);
    assert.equal(out.res._ssrfProof.hit, true, "目标实际回连 canary");
    assert.match(out.res._ssrfProof.canaryUrl, /^http:\/\/127\.0\.0\.1:\d+\/gb-ssrf\//);
    assert.deepEqual(kase.verify(out.res, "pre"), {
      verdict: "vulnerable",
      actual: `HTTP 200，服务端按请求参数发起了请求。证据：服务端回连本机 canary（${out.res._ssrfProof.canaryUrl}，命中 1 次）`,
    });
    assert.ok(kase.crossProof(out.res)?.note.includes("回连本机 canary"), "回连应作为内容级交叉证明");
    assert.ok(kase.impact(out.res).includes("内网"));

    hardened = true;
    let blocked = null;
    try {
      blocked = await kase.send(ctx, vulnerable.url);
    } catch (e) {
      assert.fail(`硬化后探测不应抛出请求失败：${e.message}`);
    }
    assert.equal(blocked.res._ssrfProof.hit, false, "白名单拦截后不应回连");
    assert.equal(kase.verify(blocked.res, "pre").verdict, "blocked");
    assert.equal(kase.crossProof(blocked.res), null);
  } finally {
    await new Promise((r) => vulnerable.server.close(r));
  }
});
