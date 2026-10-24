import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { RPC_TO_HOST } from "../../shared/protocol.mjs";
import { analyzeProject } from "../lib/analyzer.mjs";
import { buildProbePlan } from "../lib/planner.mjs";
import { buildCases } from "../lib/probe.mjs";
import { findBizLogicSignal } from "../lib/signals.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

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
        const headers = { ...(params.headers ?? {}) };
        if (params.identityRef === "alice") headers.authorization = "Bearer tok-1";
        if (params.identityRef === "bob") headers.authorization = "Bearer tok-2";
        const res = await fetch(params.url, {
          method: params.method,
          headers,
          body: params.body ?? undefined,
        });
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

test("findBizLogicSignal: 状态流转动作与一次性动作，GET 与普通路径不入选", () => {
  assert.deepEqual(findBizLogicSignal("/api/orders/:id/ship", "POST"), {
    action: "ship",
    mode: "state",
    requiredFrom: "paid",
  });
  assert.equal(findBizLogicSignal("/api/orders/:id/approve", "POST").requiredFrom, "pending");
  assert.deepEqual(findBizLogicSignal("/api/tickets/42/refund", "POST"), { action: "refund", mode: "race" });
  assert.equal(findBizLogicSignal("/api/wallet/withdraw", "POST").mode, "race");
  assert.equal(findBizLogicSignal("/api/orders/:id/ship", "GET"), null, "GET 不是状态变更动作");
  assert.equal(findBizLogicSignal("/api/orders/:id", "POST"), null);
  assert.equal(findBizLogicSignal("/api/orders", "GET"), null);
  assert.equal(findBizLogicSignal(null, "POST"), null);
});

test("analyzeProject + buildProbePlan: 靶场的状态跳步与并发双花进入计划", async () => {
  const content = readFileSync(path.join(repoRoot, "fixtures", "bizlogic-shop", "src", "app.js"), "utf8");
  const R = "\\\\?\\D:\\biz-shop";
  const file = `${R}\\src\\app.js`;
  const ctx = {
    projectRoot: R,
    tokens: { project: "tok" },
    rpc: {
      request: async (method) => {
        if (method === "fs.list") return { entries: [{ path: file, kind: "file", size: content.length }] };
        if (method === "fs.read") return { content, size: content.length, redacted: false, redactions: [] };
        throw new Error(`不应调用 ${method}`);
      },
    },
  };
  const a = await analyzeProject(ctx);
  const cands = a.candidates.filter((c) => c.kind === "bizlogic-suspect");
  assert.deepEqual(
    cands.map((c) => `${c.method} ${c.fullPath} ${c.bizlogic.mode}`).sort(),
    ["POST /api/orders/:id/refund race", "POST /api/orders/:id/ship state"]
  );
  assert.ok(
    !a.candidates.some((c) => c.kind === "idor-suspect"),
    "本人归属校验存在时不应把订单接口误判为越权读"
  );

  const plan = buildProbePlan(a);
  assert.equal(plan.bizlogicCandidates.length, 2);
  assert.equal(plan.bizlogicCandidate.bizlogic.mode, "state");
  assert.ok(plan.listEndpoint, "按归属过滤的列表接口应成为状态回读入口");
  assert.equal(plan.listEndpoint.path, "/api/orders");
});

test("buildCases: 状态跳步以回读状态为准；并发双花以不同副作用标识为准", async () => {
  let mode = "vuln";
  const orders = [
    { id: 101, userId: 1, amount: 500, status: "pending" },
    { id: 102, userId: 1, amount: 300, status: "paid" },
    { id: 201, userId: 2, amount: 900, status: "paid" },
  ];
  let seq = 0;
  const send = (res, status, body) => {
    res.writeHead(status, { "content-type": "application/json" });
    res.end(JSON.stringify(body));
  };
  const server = await listen((req, res) => {
    const url = new URL(req.url, "http://127.0.0.1");
    const userId = /^Bearer tok-(\d+)$/.exec(String(req.headers.authorization ?? ""))?.[1];
    if (!userId) return send(res, 401, { error: "未登录" });
    if (req.method === "GET" && url.pathname === "/api/orders") {
      return send(res, 200, { items: orders.filter((o) => o.userId === Number(userId)) });
    }
    const ship = url.pathname.match(/^\/api\/orders\/(\d+)\/ship$/);
    if (req.method === "POST" && ship) {
      const order = orders.find((o) => o.id === Number(ship[1]));
      if (!order) return send(res, 404, {});
      if (mode === "hardened" && order.status !== "paid") return send(res, 409, { error: "前置状态不满足" });
      order.status = "shipped";
      return send(res, 200, { order });
    }
    const refund = url.pathname.match(/^\/api\/orders\/(\d+)\/refund$/);
    if (req.method === "POST" && refund) {
      const order = orders.find((o) => o.id === Number(refund[1]));
      if (!order) return send(res, 404, {});
      if (mode === "hardened") {
        if (order.status === "refunded" || order.refunding) return send(res, 409, { error: "已退款" });
        order.refunding = true;
      } else if (order.status === "refunded") {
        return send(res, 409, { error: "已退款" });
      }
      setTimeout(() => {
        order.status = "refunded";
        order.refunding = false;
        seq += 1;
        if (mode === "no-effect-id") return send(res, 200, { ok: true });
        send(res, 200, { ok: true, refund: { refund_id: `rf_${order.id}_${seq}` } });
      }, 60);
      return;
    }
    send(res, 404, {});
  });

  const shipCand = {
    kind: "bizlogic-suspect",
    method: "POST",
    path: "/api/orders/:id/ship",
    fullPath: "/api/orders/:id/ship",
    routeKeys: ["orders.ship"],
    bizlogic: { action: "ship", mode: "state", requiredFrom: "paid" },
  };
  const refundCand = {
    kind: "bizlogic-suspect",
    method: "POST",
    path: "/api/orders/:id/refund",
    fullPath: "/api/orders/:id/refund",
    routeKeys: ["orders.refund"],
    bizlogic: { action: "refund", mode: "race" },
  };
  const ctx = {
    ...stubCtx(),
    plan: {
      listEndpoint: { path: "/api/orders", method: "GET" },
      bizlogicCandidates: [shipCand, refundCand],
    },
    targetConfig: { responses: { list: "items", entity: "order" } },
  };
  const targets = {
    attacker: { name: "alice", user: { id: 1 } },
    victim: { name: "bob", user: { id: 2 } },
    attackerItems: orders.filter((o) => o.userId === 1),
  };

  try {
    const cases = buildCases(ctx, targets);
    const ids = cases.map((c) => c.id);
    assert.ok(ids.includes("business-list-own"), "正向断言（本人列表可见）应一并构建");
    assert.deepEqual(
      cases.filter((c) => c.category === "attack").map((c) => c.id),
      ["attack-state-skip", "attack-race-2"]
    );
    assert.ok(cases.filter((c) => c.category === "attack").every((c) => c.unfixable === true && c.identity === "alice"));

    const stateCase = cases[0];
    const stateRes = await stateCase.send(ctx, server.url);
    assert.equal(stateRes.res._bizProof.from, "pending");
    assert.equal(stateRes.res._bizProof.to, "shipped");
    const stateVerdict = stateCase.verify(stateRes.res, "pre");
    assert.equal(stateVerdict.verdict, "vulnerable");
    assert.match(stateVerdict.actual, /前置状态校验缺失/);
    assert.match(stateCase.crossProof(stateRes.res).note, /状态机/);
    assert.match(stateCase.impact(stateRes.res), /跳过/);

    const raceCase = cases[1];
    const raceRes = await raceCase.send(ctx, server.url);
    assert.equal(raceRes.res._bizProof.successes, 5);
    assert.ok(raceRes.res._bizProof.effectIds.length >= 2);
    const raceVerdict = raceCase.verify(raceRes.res, "pre");
    assert.equal(raceVerdict.verdict, "vulnerable");
    assert.match(raceVerdict.actual, /不同副作用标识/);
    assert.match(raceCase.crossProof(raceRes.res).note, /重复执行/);

    // 加固后：前置状态被拒 + 一次性动作只剩 1 次成功 → 两类都 blocked
    mode = "hardened";
    orders[0].status = "pending";
    orders[1].status = "paid";
    const blockedState = await stateCase.send(ctx, server.url);
    assert.equal(stateCase.verify(blockedState.res, "pre").verdict, "blocked");
    const blockedRace = await raceCase.send(ctx, server.url);
    assert.equal(blockedRace.res._bizProof.successes, 1);
    assert.equal(raceCase.verify(blockedRace.res, "pre").verdict, "blocked");
    assert.equal(raceCase.crossProof(blockedRace.res), null);

    // 成功但拿不到不同副作用标识 → inconclusive，不能算漏洞
    mode = "no-effect-id";
    orders[1].status = "paid";
    const weak = await raceCase.send(ctx, server.url);
    assert.equal(raceCase.verify(weak.res, "pre").verdict, "inconclusive");
  } finally {
    await new Promise((r) => server.server.close(r));
  }
});
