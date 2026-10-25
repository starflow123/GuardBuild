import { test } from "node:test";
import assert from "node:assert/strict";
import {
  ABSENT_PROBE_PATH,
  MAX_SCOUT_ROUTES,
  classifyAnonymous,
  classifyExistence,
  compareOwnerFilter,
  looksDenied,
  verifyScoutRoutes,
} from "../lib/routeverify.mjs";

/** 按「method+path+身份」编排响应；同时记录全部请求，供断言预算与顺序 */
function mockTransport(routes, { throwOn = null } = {}) {
  const calls = [];
  const request = async ({ method, path, identity }) => {
    calls.push({ method, path, identity });
    if (throwOn && path === throwOn) throw new Error("connection refused");
    const key = `${method} ${path} ${identity ?? "anon"}`;
    const res = routes[key] ?? routes[`${method} ${path}`];
    if (!res) return { status: 404, json: { error: "not found", path }, body: JSON.stringify({ error: "not found" }) };
    return { status: res.status, json: res.json, body: res.body ?? JSON.stringify(res.json ?? ""), headers: res.headers ?? {} };
  };
  return { calls, request };
}

const ORDER_ITEM = { status: 200, json: { id: 7, owner: "alice" } };

test("存在性实测：编造的路由被判 not_found 并丢弃", async () => {
  const { calls, request } = mockTransport({
    [`GET ${ABSENT_PROBE_PATH} alice`]: { status: 404, json: { error: "not found" } },
    "GET /api/orders/7 alice": ORDER_ITEM,
    "GET /api/orders/7": { status: 401, json: { error: "unauthorized" } },
    "GET /api/invoices/7 alice": { status: 404, json: { error: "not found", path: "/api/invoices/7" } },
  });
  const v = await verifyScoutRoutes(
    [
      { key: "GET /api/orders/:id", method: "GET", path: "/api/orders/7", identity: "alice" },
      { key: "GET /api/invoices/:id", method: "GET", path: "/api/invoices/7", identity: "alice" },
    ],
    { request }
  );
  assert.equal(v.kept.length, 1);
  assert.equal(v.kept[0].key, "GET /api/orders/:id");
  assert.deepEqual(v.dropped.map((d) => [d.key, d.reason]), [["GET /api/invoices/:id", "not_found"]]);
  assert.equal(v.kept[0].auth, "protected");
  assert.ok(calls.some((c) => c.path === ABSENT_PROBE_PATH));
});

test("SPA catch-all：与不存在基线同状态同响应体 → 判不存在", async () => {
  const shell = { status: 200, body: "<html><body>index app bundle</body></html>" };
  const { request } = mockTransport({
    [`GET ${ABSENT_PROBE_PATH} alice`]: shell,
    "GET /api/ghost/7 alice": shell,
  });
  const v = await verifyScoutRoutes([{ key: "GET /api/ghost/:id", method: "GET", path: "/api/ghost/7", identity: "alice" }], {
    request,
  });
  assert.equal(v.kept.length, 0);
  assert.deepEqual(v.dropped.map((d) => d.reason), ["not_found"]);
});

test("405 判定为方法不匹配，而非存在", async () => {
  const { request } = mockTransport({
    [`GET ${ABSENT_PROBE_PATH} alice`]: { status: 404, json: {} },
    "DELETE /api/orders/7 alice": { status: 405, json: { error: "method not allowed" } },
  });
  const v = await verifyScoutRoutes([{ key: "DELETE /api/orders/:id", method: "DELETE", path: "/api/orders/7", identity: "alice" }], {
    request,
  });
  assert.deepEqual(v.dropped.map((d) => d.reason), ["method_not_allowed"]);
});

test("缺真实资源 id 的路由不猜测，直接判不可验证", async () => {
  const { calls, request } = mockTransport({});
  const v = await verifyScoutRoutes([{ key: "GET /api/orders/:id", method: "GET", path: null, identity: "alice" }], { request });
  assert.deepEqual(v.dropped.map((d) => d.reason), ["no_probe_id"]);
  assert.equal(calls.length, 0);
});

test("请求失败按 not-verified 丢弃，不当成不存在", async () => {
  const { request } = mockTransport(
    { [`GET ${ABSENT_PROBE_PATH} alice`]: { status: 404, json: {} } },
    { throwOn: "/api/orders/7" }
  );
  const notes = [];
  const v = await verifyScoutRoutes([{ key: "GET /api/orders/:id", method: "GET", path: "/api/orders/7", identity: "alice" }], {
    request,
    note: (m) => notes.push(m),
  });
  assert.deepEqual(v.dropped.map((d) => d.reason), ["request_failed"]);
  assert.equal(notes.length, 1);
});

test("匿名即可取数 → auth=open；匿名 200 带拒绝体 → protected", async () => {
  const { request } = mockTransport({
    [`GET ${ABSENT_PROBE_PATH} alice`]: { status: 404, json: {} },
    "GET /api/public/orders alice": ORDER_ITEM,
    "GET /api/public/orders": { status: 200, json: { items: [{ id: 7 }] } },
    "GET /api/orders/7 alice": ORDER_ITEM,
    "GET /api/orders/7": { status: 200, json: { code: 401, message: "please login" } },
  });
  const v = await verifyScoutRoutes(
    [
      { key: "GET /api/public/orders", method: "GET", path: "/api/public/orders", identity: "alice" },
      { key: "GET /api/orders/:id", method: "GET", path: "/api/orders/7", identity: "alice" },
    ],
    { request }
  );
  assert.deepEqual(v.detail.map((d) => [d.key, d.auth]), [
    ["GET /api/public/orders", "open"],
    ["GET /api/orders/:id", "protected"],
  ]);
});

test("列表路由两身份对拉：集合相同=未过滤，互斥=已过滤，空=未确认", async () => {
  const lists = {
    alice: [{ id: 1 }, { id: 2 }],
    bob: [{ id: 1 }, { id: 2 }],
  };
  const same = await verifyScoutRoutes([{ key: "GET /api/orders", method: "GET", path: "/api/orders", identity: "alice", list: true }], {
    request: async ({ path, identity }) =>
      path === ABSENT_PROBE_PATH
        ? { status: 404, json: {} }
        : { status: 200, json: { items: lists[identity ?? "anon"] ?? lists.alice } },
    fetchList: async (_r, identity) => lists[identity],
    identities: ["alice", "bob"],
  });
  assert.equal(same.kept[0].ownerFilter, false);

  const disjoint = await verifyScoutRoutes([{ key: "GET /api/orders", method: "GET", path: "/api/orders", identity: "alice", list: true }], {
    request: async ({ path }) =>
      path === ABSENT_PROBE_PATH ? { status: 404, json: {} } : { status: 200, json: { items: [{ id: 1 }] } },
    fetchList: async (_r, identity) => (identity === "alice" ? [{ id: 1 }] : [{ id: 9 }]),
    identities: ["alice", "bob"],
  });
  assert.equal(disjoint.kept[0].ownerFilter, true);

  const listCalls = [];
  const single = await verifyScoutRoutes([{ key: "GET /api/orders", method: "GET", path: "/api/orders", identity: "alice", list: true }], {
    request: async ({ path }) =>
      path === ABSENT_PROBE_PATH ? { status: 404, json: {} } : { status: 200, json: { items: [{ id: 1 }] } },
    fetchList: async (_r, identity) => {
      listCalls.push(identity);
      return [{ id: 1 }];
    },
    identities: ["alice"],
  });
  assert.equal(single.kept[0].ownerFilter, null);
  assert.deepEqual(listCalls, [], "只有一个身份时不做归属对拉，不能凭单侧列表下结论");
});

test("预算用尽后剩余路由不再发送请求", async () => {
  const { calls, request } = mockTransport({
    [`GET ${ABSENT_PROBE_PATH} alice`]: { status: 404, json: {} },
    "GET /api/orders/7 alice": ORDER_ITEM,
    "GET /api/orders/7": { status: 401, json: {} },
  });
  const v = await verifyScoutRoutes(
    [
      { key: "GET /api/orders/:id", method: "GET", path: "/api/orders/7", identity: "alice" },
      { key: "GET /api/orders/:id again", method: "GET", path: "/api/orders/7", identity: "alice" },
    ],
    { request, budget: 3 }
  );
  assert.equal(v.kept.length, 1);
  assert.deepEqual(v.dropped.map((d) => d.reason), ["budget"]);
  assert.equal(calls.length, 3);
});

test("超过送检上限的路由不参与实测（不静默全量打）", async () => {
  const routes = Array.from({ length: MAX_SCOUT_ROUTES + 3 }, (_, i) => ({
    key: `GET /api/orders/${i}`,
    method: "GET",
    path: `/api/orders/${i}`,
    identity: "alice",
  }));
  const { calls, request } = mockTransport({
    [`GET ${ABSENT_PROBE_PATH} alice`]: { status: 404, json: {} },
  });
  const v = await verifyScoutRoutes(routes, { request });
  assert.equal(v.kept.length, 0);
  assert.equal(v.dropped.length, MAX_SCOUT_ROUTES, "超出上限的路由既不实测也不出现在结果里");
  assert.equal(calls.length, MAX_SCOUT_ROUTES + 1, "1 次基线 + 每条路由 1 次存在性请求");
});

test("纯判定函数", () => {
  assert.equal(classifyExistence({ status: 404 }, { status: 404, body: "x" }), "absent");
  assert.equal(classifyExistence({ status: 200, body: "data" }, { status: 200, body: "shell" }), "present");
  assert.equal(classifyExistence({ status: 200, body: "same" }, { status: 200, body: "same" }), "absent");
  assert.equal(classifyAnonymous({ status: 302, headers: { location: "/login?next=/api" } }), "protected");
  assert.equal(classifyAnonymous({ status: 302, headers: { location: "/dashboard" } }), "unknown");
  assert.equal(classifyAnonymous({}), "unknown");
  assert.equal(looksDenied({ error: null, data: { id: 1 } }), false);
  assert.equal(looksDenied({ error: "forbidden" }), true);
  assert.equal(looksDenied({ items: [1] }), false);
  assert.deepEqual(compareOwnerFilter([{ id: 1 }], [{ id: 1 }], (o) => o.id), false);
  assert.deepEqual(compareOwnerFilter([{ id: 1 }], [{ id: 2 }], (o) => o.id), true);
  assert.deepEqual(compareOwnerFilter([], [{ id: 2 }], (o) => o.id), null);
  assert.deepEqual(compareOwnerFilter([{ id: 1 }, { id: 2 }], [{ id: 2 }], (o) => o.id), null);
});
