import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { createHmac } from "node:crypto";
import { RPC_TO_HOST } from "../../shared/protocol.mjs";
import { analyzeProject } from "../lib/analyzer.mjs";
import { buildProbePlan } from "../lib/planner.mjs";
import { buildCases } from "../lib/probe.mjs";
import { collectJwtSecrets, findJwtSignal } from "../lib/signals.mjs";

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

test("findJwtSignal / collectJwtSecrets: 只解码、alg=none、未固定算法、硬编码密钥", () => {
  assert.equal(findJwtSignal("const payload = jwt.decode(token);").issue, "decode-only");
  assert.equal(findJwtSignal('const p = jwt.decode(token, options={"verify_signature": False});').issue, "decode-only");
  assert.equal(findJwtSignal('jwt.verify(token, secret, { algorithms: ["none"] });').issue, "none-algorithm");
  assert.equal(findJwtSignal("jwt.verify(token, secret);").issue, "no-algorithm");
  assert.equal(
    findJwtSignal('jwt.verify(token, secret, { algorithms: ["HS256"] });'),
    null,
    "固定算法且使用变量密钥不应命中"
  );
  assert.equal(
    findJwtSignal('jwt.verify(token, secret, { algorithms: ["HS256"] });\nconst exp = jwt.decode(token).exp;'),
    null,
    "先验签后 decode 读 exp 不应误报为只解码"
  );

  const weak = collectJwtSecrets('const JWT_SECRET = "gb-weak-secret";\njwt.sign(payload, "another-literal");');
  assert.deepEqual(weak, ["gb-weak-secret", "another-literal"]);
  assert.deepEqual(collectJwtSecrets("const JWT_SECRET = process.env.JWT_SECRET;"), [], "环境变量不是硬编码密钥");
  assert.equal(
    findJwtSignal('const JWT_SECRET = "gb-weak-secret";\njwt.verify(token, JWT_SECRET, { algorithms: ["HS256"] });').issue,
    "weak-secret",
    "固定算法但密钥硬编码仍是静态线索（动态用源码密钥签发验证）"
  );
  assert.equal(findJwtSignal("const payload = { username: user.name };"), null, "普通业务代码不应命中");
});

test("analyzeProject + buildProbePlan: 共享校验 helper 的验签缺口进入受认证端点", async () => {
  const R = "\\\\?\\D:\\jwt";
  const source = [
    "function authenticate(req) {",
    "  const token = tokenOf(req);",
    "  if (!token) return null;",
    '  const payload = HARDENED ? verifyToken(token) : jwt.decode(token);',
    "  return { id: payload.sub, username: payload.username, role: payload.role };",
    "}",
    "export async function handleRequest(req, res) {",
    "  const auth = authenticate(req);",
    '  if (method === "GET" && pathname === "/api/me") {',
    "    if (!auth) return json(res, 401, { error: '未登录' });",
    "    return json(res, 200, { user: auth });",
    "  }",
    '  if (method === "GET" && pathname === "/api/admin/users") {',
    "    if (!auth) return json(res, 401, { error: '未登录' });",
    "    return json(res, 200, { users: [] });",
    "  }",
    "}",
  ].join("\n");
  const ctx = {
    projectRoot: R,
    tokens: { project: "tok" },
    rpc: {
      request: async (method) => {
        if (method === "fs.list") return { entries: [{ path: `${R}\\server.js`, kind: "file", size: 600 }] };
        if (method === "fs.read") return { content: source, size: 600, redacted: false, redactions: [] };
        throw new Error(`不应调用 ${method}`);
      },
    },
  };
  const a = await analyzeProject(ctx);
  const cands = a.candidates.filter((c) => c.kind === "jwt-suspect");
  assert.deepEqual(
    cands.map((c) => c.fullPath).sort(),
    ["/api/admin/users", "/api/me"],
    "两个受认证端点都应带上文件级验签缺口"
  );
  assert.ok(cands.every((c) => c.jwt?.issue === "decode-only"));

  const plan = buildProbePlan(a);
  assert.equal(plan.jwtCandidates.length, 2);
  assert.ok(plan.jwtCandidate);
});

test("buildCases: 伪造令牌被接受且回显身份即 vulnerable，强密钥验签后判 blocked", async () => {
  const WEAK_SECRET = "gb-weak-secret";
  const STRONG_SECRET = "gb-strong-secret";
  let mode = "decode";
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const sign = (token, secret) =>
    createHmac("sha256", secret).update(token.split(".").slice(0, 2).join(".")).digest("base64url");

  const server = await listen((req, res) => {
    const url = new URL(req.url, "http://127.0.0.1");
    if (url.pathname !== "/api/me") {
      res.writeHead(404).end();
      return;
    }
    const raw = String(req.headers.authorization ?? "");
    if (!raw.startsWith("Bearer ")) {
      res.writeHead(401, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "未登录" }));
      return;
    }
    const token = raw.slice("Bearer ".length);
    const parts = token.split(".");
    let payload = null;
    try {
      payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
    } catch {
      payload = null;
    }
    if (!payload) {
      res.writeHead(401, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "令牌无效" }));
      return;
    }
    if (mode !== "decode") {
      const secret = mode === "weak" ? WEAK_SECRET : STRONG_SECRET;
      const header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
      if (header.alg !== "HS256" || parts[2] !== sign(token, secret)) {
        res.writeHead(401, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "令牌无效" }));
        return;
      }
    }
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ user: { username: payload.username, role: payload.role } }));
  });

  try {
    const cand = {
      path: "/api/me",
      fullPath: "/api/me",
      method: "GET",
      jwt: { issue: "decode-only", label: "只解码不验签", secrets: [WEAK_SECRET] },
      routeKeys: ["me.get"],
    };
    const cases = buildCases(
      { plan: { jwtCandidates: [cand] }, targetConfig: null },
      { attacker: { name: "alice", user: { id: 1 } }, victim: { name: "bob", user: { id: 2 } } }
    );
    assert.equal(cases.length, 1);
    const kase = cases[0];
    assert.equal(kase.id, "attack-jwt-forge");
    assert.equal(kase.unfixable, true);
    assert.equal(kase.identity, null);

    const ctx = stubCtx();
    const decoded = await kase.send(ctx, server.url);
    assert.equal(decoded.res._jwtProof.protected, true, "匿名被拒才进入伪造探测");
    assert.equal(decoded.res._jwtProof.hit, true);
    assert.equal(decoded.res._jwtProof.alg, "alg=none");
    const verdict = kase.verify(decoded.res, "pre");
    assert.equal(verdict.verdict, "vulnerable");
    assert.match(verdict.actual, /伪造令牌通过校验/);
    assert.match(verdict.actual, /gbjwt/);
    assert.ok(kase.crossProof(decoded.res)?.note.includes("签名校验被绕过"));
    assert.ok(kase.impact(decoded.res).includes("身份"));

    mode = "weak";
    const weak = await kase.send(ctx, server.url);
    assert.equal(weak.res._jwtProof.alg, "HS256(源码密钥)", "应由源码密钥签发的令牌命中");
    assert.equal(kase.verify(weak.res, "pre").verdict, "vulnerable");

    mode = "strong";
    const blocked = await kase.send(ctx, server.url);
    assert.equal(blocked.res._jwtProof.hit, false);
    assert.equal(kase.verify(blocked.res, "pre").verdict, "blocked");
    assert.equal(kase.crossProof(blocked.res), null);
  } finally {
    await new Promise((r) => server.server.close(r));
  }
});
