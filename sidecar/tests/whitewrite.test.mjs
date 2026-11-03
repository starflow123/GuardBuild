import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { RPC_TO_HOST } from "../../shared/protocol.mjs";
import { buildProbePlan, planView } from "../lib/planner.mjs";
import { buildCases } from "../lib/probe.mjs";

function listen(handler) {
  return new Promise((resolve) => {
    const server = createServer(handler);
    server.listen(0, "127.0.0.1", () => {
      const port = server.address().port;
      resolve({ server, url: `http://127.0.0.1:${port}` });
    });
  });
}

function makeCtx(targetConfig) {
  return {
    tokens: { net: "net-token" },
    loginConfig: null,
    targetConfig,
    plan: { resource: "order" },
    rpc: {
      request: async (method, params) => {
        if (method !== RPC_TO_HOST.HTTP_REQUEST) throw new Error(`不应调用 ${method}`);
        const headers = { ...(params.headers ?? {}) };
        if (params.identityRef) headers["x-gb-identity"] = params.identityRef;
        const res = await fetch(params.url, {
          method: params.method,
          headers,
          body: params.body == null ? undefined : typeof params.body === "string" ? params.body : JSON.stringify(params.body),
        });
        const text = await res.text();
        let json = null;
        try {
          json = JSON.parse(text);
        } catch {
          /* 非 JSON 响应保留原文 */
        }
        return { status: res.status, statusText: res.statusText, body: text, json, headers: Object.fromEntries(res.headers) };
      },
    },
  };
}

/**
 * 订单店：#7/#8 都归 bob（userId 2）。
 * ignoreWrite=true 时 PATCH/DELETE 返回 200 但不落库（模拟「请求被接受却未被处理」）；
 * enforceOwner=true 时非归属人写/删一律 403（加固版）。
 */
function orderShop({ enforceOwner = false, ignoreWrite = false } = {}) {
  const orders = new Map([
    [7, { id: 7, note: "gift", status: "paid", userId: 2 }],
    [8, { id: 8, note: "misc", status: "new", userId: 2 }],
  ]);
  const uidOf = (identity) => (identity === "alice" ? 1 : identity === "bob" ? 2 : null);
  return listen(async (req, res) => {
    const url = new URL(req.url, "http://127.0.0.1");
    const m = url.pathname.match(/^\/api\/orders\/(\d+)$/);
    const send = (status, obj) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(obj));
    };
    if (!m) return send(404, { error: "not found" });
    const id = Number(m[1]);
    const order = orders.get(id);
    if (req.method === "GET") return order ? send(200, { ...order }) : send(404, { error: "not found" });
    if (!order) return send(404, { error: "not found" });
    const uid = uidOf(req.headers["x-gb-identity"]);
    if (enforceOwner && order.userId !== uid) return send(403, { error: "forbidden" });
    let body = {};
    if (req.method === "PATCH" || req.method === "PUT") {
      const chunks = [];
      for await (const c of req) chunks.push(c);
      try {
        body = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
      } catch {
        return send(400, { error: "bad json" });
      }
      if (ignoreWrite) return send(200, { ok: true });
      for (const [k, v] of Object.entries(body)) order[k] = v;
      return send(200, { ...order });
    }
    if (req.method === "DELETE") {
      if (ignoreWrite) return send(200, { ok: true });
      orders.delete(id);
      return send(200, { deleted: true });
    }
    return send(405, { error: "method not allowed" });
  });
}

const writeCtxBuild = (mutation) =>
  makeCtx(mutation ? { mutation } : null);

function patchCand() {
  return {
    path: "/api/orders/:id",
    fullPath: "/api/orders/:id",
    method: "PATCH",
    resource: "order",
    hasAuth: true,
    routeKeys: ["orders.update"],
    kind: "idor-suspect",
  };
}
function deleteCand() {
  return { ...patchCand(), method: "DELETE", routeKeys: ["orders.remove"] };
}

function buildWriteCases(ctx, extraTargets = {}) {
  return buildCases(
    { ...ctx, plan: { ...ctx.plan, writeCandidates: [patchCand(), deleteCand()] } },
    {
      attacker: { name: "alice", user: { id: 1 }, role: "user" },
      victim: { name: "bob", user: { id: 2 }, role: "user" },
      admin: null,
      readTarget: null,
      attackCancelTarget: null,
      attackWriteTarget: { id: 8, note: "misc", status: "new", userId: 2 },
      ...extraTargets,
    }
  );
}

test("buildProbePlan: PUT/PATCH/DELETE 的越权候选进 writeCandidates 槽位，读/取消槽位不受影响", () => {
  const ep = (method, path, kind) => ({
    file: "src/app.js",
    method,
    path,
    fullPath: path,
    style: "express",
    hasAuth: true,
    routeKeys: [],
    kind,
    resource: "order",
  });
  const analysis = {
    endpoints: [],
    candidates: [
      ep("GET", "/api/orders/:id", "idor-suspect"),
      ep("POST", "/api/orders/:id/cancel", "idor-suspect"),
      ep("PATCH", "/api/orders/:id", "idor-suspect"),
      ep("PUT", "/api/orders/:id", "idor-suspect"),
      ep("DELETE", "/api/orders/:id", "idor-suspect"),
      ep("POST", "/api/orders/:id/refund", "idor-suspect"),
      ep("DELETE", "/api/orders/:id/tag", "no-auth-suspect"),
    ],
  };
  const plan = buildProbePlan(analysis);
  assert.deepEqual(
    plan.writeCandidates.map((c) => c.method),
    ["PATCH", "PUT", "DELETE"],
    "写面槽位收 PUT/PATCH/DELETE（top-K=3），POST refund 留给取消语义判断、no-auth 的 DELETE 不进越权写槽"
  );
  assert.equal(plan.readCandidate.method, "GET");
  assert.equal(plan.cancelCandidate.method, "POST");
  assert.equal(planView(plan).writePath, "/api/orders/:id");
});

test("白盒写面开关：默认一条不打；allowWrite 出 PATCH/PUT 用例，DELETE 还要 allowDelete", () => {
  const base = buildWriteCases(writeCtxBuild(null));
  assert.equal(
    base.filter((c) => c.id.startsWith("attack-write-foreign")).length,
    0,
    "开关默认关闭：写面候选一条都不构造（宁缺不假，披露走 gate 文案）"
  );
  const writeOnly = buildWriteCases(writeCtxBuild({ allowWrite: true }));
  const ids = writeOnly.filter((c) => c.id.startsWith("attack-write-foreign"));
  assert.equal(ids.length, 1, "allowWrite 只放行改（PUT/PATCH），删仍锁着");
  assert.equal(ids[0].method, "PATCH");
  const both = buildWriteCases(writeCtxBuild({ allowWrite: true, allowDelete: true }));
  const idsBoth = both.filter((c) => c.id.startsWith("attack-write-foreign"));
  assert.equal(idsBoth.length, 2);
  assert.deepEqual(idsBoth.map((c) => c.method), ["PATCH", "DELETE"]);
  assert.match(idsBoth[1].name, /越权删除/);
});

test("写面越权（改）：归属人复读见到 canary 才判漏洞，随后恢复原值", async () => {
  const shop = await orderShop();
  try {
    const ctx = writeCtxBuild({ allowWrite: true });
    const kase = buildWriteCases(ctx).find((c) => c.id === "attack-write-foreign");
    assert.ok(kase);
    assert.equal(kase.identity, "alice");
    const out = await kase.send(ctx, shop.url);
    const proof = out.res._writeProof;
    assert.equal(proof.mode, "modify");
    assert.equal(proof.field, "note", "从归属人可见对象里挑非 id/status 的字符串字段");
    assert.equal(proof.canary, "misc_gbw");
    assert.equal(proof.changed, true, "复读通道（victim GET）确实见到攻击写入值");
    assert.equal(proof.restored, true, "改完尽力恢复原值");
    const v = kase.verify(out.res, "pre");
    assert.equal(v.verdict, "vulnerable");
    assert.match(v.actual, /复读见到 note=misc_gbw.*原值已恢复/);
    assert.ok(kase.crossProof(out.res)?.note.includes("归属人复读"));
    assert.ok(kase.impact(out.res).includes("越权修改"));
    assert.equal(kase.verify(out.res, "post").verdict, "regressed", "修复后仍能改成＝补丁无效");
  } finally {
    await new Promise((r) => shop.server.close(r));
  }
});

test("写面越权（删）：归属人复读对象消失才判漏洞；被拒绝记 blocked；接受但未落库只记 inconclusive", async () => {
  const ctxDel = writeCtxBuild({ allowWrite: true, allowDelete: true });
  const vuln = await orderShop();
  const hardened = await orderShop({ enforceOwner: true });
  const ignored = await orderShop({ ignoreWrite: true });
  try {
    const kaseDel = buildWriteCases(ctxDel).find((c) => c.method === "DELETE");
    assert.ok(kaseDel);
    const out = await kaseDel.send(ctxDel, vuln.url);
    assert.equal(out.res._writeProof.gone, true);
    assert.equal(out.res._writeProof.rereadStatus, 404);
    const v = kaseDel.verify(out.res, "pre");
    assert.equal(v.verdict, "vulnerable");
    assert.match(v.actual, /复读 #8 已不存在/);
    assert.ok(kaseDel.impact(out.res).includes("不可恢复"));

    const blocked = await kaseDel.send(ctxDel, hardened.url);
    assert.equal(blocked.res._writeProof.gone, false, "加固版拒绝后复读对象仍在");
    assert.equal(kaseDel.verify(blocked.res, "pre").verdict, "blocked");

    const ignoredOut = await kaseDel.send(ctxDel, ignored.url);
    assert.equal(ignoredOut.res._writeProof.gone, false, "200 但对象未消失");
    assert.equal(kaseDel.verify(ignoredOut.res, "pre").verdict, "inconclusive");
  } finally {
    await Promise.all([vuln, hardened, ignored].map((s) => new Promise((r) => s.server.close(r))));
  }
});
