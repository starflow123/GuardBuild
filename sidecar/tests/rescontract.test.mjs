import { test } from "node:test";
import assert from "node:assert/strict";
import {
  MAX_ARRAY_PATHS,
  arrayPaths,
  bindingsFromItem,
  compareIdSets,
  contractFingerprint,
  contractForCache,
  discoverBindings,
  discoverEntityContract,
  discoverListContract,
  getByPath,
  idFieldCandidates,
  objectPaths,
  ownerContrastFields,
  readCommitFromGit,
  validateExtras,
} from "../lib/rescontract.mjs";

function qsOf(query) {
  if (!query || Object.keys(query).length === 0) return "";
  return `?${Object.entries(query)
    .map(([k, v]) => `${k}=${v}`)
    .sort()
    .join("&")}`;
}

/** 按「method path?query identity」编排响应，并记录请求序列（断言预算与「没发请求」用） */
function mockTransport(routes) {
  const calls = [];
  const request = async ({ method = "GET", path, query = null, identity = null }) => {
    const key = `${method} ${path}${qsOf(query)} ${identity ?? "anon"}`;
    calls.push(key);
    const res = routes[key];
    if (!res) return { status: 404, json: { error: "not found" }, body: "{}" };
    return { status: res.status, json: res.json, body: JSON.stringify(res.json ?? {}) };
  };
  return { calls, request };
}

const ALICE_PAGE = {
  status: 200,
  json: { payload: { page: 1, total: 2, rows: [{ order_id: 7001, created_by_uid: 1, org_id: 9 }, { order_id: 7002, created_by_uid: 1, org_id: 10 }] } },
};
const BOB_PAGE = {
  status: 200,
  json: { payload: { page: 1, total: 1, rows: [{ order_id: 7003, created_by_uid: 2, org_id: 9 }] } },
};

test("数组路径枚举：只看一层取不到的嵌套列表也能找到，并记录公共字段", () => {
  const paths = arrayPaths({ data: { page: { items: [{ id: 1 }, { id: 2 }] } }, count: 2 });
  assert.deepEqual(paths.map((p) => p.path), ["data.page.items"]);
  assert.deepEqual(paths[0].keys.sort(), ["id"]);
  assert.deepEqual(arrayPaths({ message: "no array here" }), []);
  assert.deepEqual(arrayPaths([{ id: 1 }], { maxDepth: 1 }).map((p) => p.path), [""]);
  const many = {};
  for (let i = 0; i < MAX_ARRAY_PATHS + 4; i += 1) many[`k${i}`] = [{ id: i }];
  assert.equal(arrayPaths(many).length, MAX_ARRAY_PATHS);
});

test("对象路径枚举：认得出包装字段（供单体契约用）", () => {
  const paths = objectPaths({ meta: { orgId: 9 }, record: { order_id: 7 } });
  assert.deepEqual(paths.map((p) => p.path).sort(), ["meta", "record"]);
});

test("主键候选：只取真实存在的字段，id 优先，最多三个", () => {
  assert.deepEqual(idFieldCandidates(["order_id", "id", "title", "uuid", "line_id", "sku_id"]), ["id", "uuid", "order_id"]);
  assert.deepEqual(idFieldCandidates(["title", "amount"]), []);
});

test("id 集合关系：互斥/相同/部分重叠/取不到值四类", () => {
  const set = (...v) => new Set(v.map(String));
  assert.equal(compareIdSets(set(1, 2), set(3)), "disjoint");
  assert.equal(compareIdSets(set(1, 2), set(2, 1)), "identical");
  assert.equal(compareIdSets(set(1, 2), set(2, 3)), "partial");
  assert.equal(compareIdSets(set(), set(1)), "unusable");
  assert.equal(compareIdSets(null, set(1)), "unusable");
});

test("归属字段：同身份内恒定且两身份不同才算，随主键与变化字段排除", () => {
  const a = [{ order_id: 1, created_by_uid: 7, status: "paid", org_id: 9 }, { order_id: 2, created_by_uid: 7, status: "new", org_id: 9 }];
  const b = [{ order_id: 3, created_by_uid: 8, status: "paid", org_id: 9 }];
  assert.deepEqual(ownerContrastFields(a, b, ["order_id"]), ["created_by_uid"]);
});

test("多段参数绑定：只从对象已有字段取值（含下划线命名），取不到就返回 null", () => {
  assert.deepEqual(
    Object.keys(bindingsFromItem({ org_id: 9, order_id: 7 }, ["orgId", "orderId"])).sort(),
    ["orderId", "orgId"]
  );
  assert.equal(bindingsFromItem({ order_id: 7 }, ["orgId", "orderId"]), null);
  assert.equal(bindingsFromItem({ org_id: null, order_id: 7 }, ["orgId", "orderId"]), null);
});

test("模型契约假设：响应里对不上的路径/字段/分页键一律拒掉", () => {
  const sample = { payload: { rows: [{ order_id: 1, created_by_uid: 2 }] } };
  const ok = validateExtras(
    { arrayPaths: ["payload.rows"], idFields: ["order_id"], pagination: [{ page: 1, limit: 200 }] },
    sample
  );
  assert.deepEqual(ok.extras.arrayPaths, ["payload.rows"]);
  assert.deepEqual(ok.extras.idFields, ["order_id"]);
  assert.deepEqual(ok.extras.pagination, [{ page: "1", limit: "200" }]);
  assert.deepEqual(ok.rejected, []);

  const bad = validateExtras(
    { arrayPath: "data.items", idField: "ghost_id", pagination: [{ customCursor: "abc" }, { limit: 99999 }] },
    sample
  );
  assert.deepEqual(bad.extras.arrayPaths, []);
  assert.deepEqual(bad.extras.idFields, []);
  assert.deepEqual(bad.extras.pagination, []);
  assert.equal(bad.rejected.length, 4);
  assert.match(bad.rejected[0], /取不到对象数组/);
});

test("列表契约实测：嵌套路径 + 必填分页 + 非默认主键/归属字段全部由真实响应确定", async () => {
  const { calls, request } = mockTransport({
    "GET /v2/orders/paged alice": { status: 400, json: { error: "page 与 limit 为必填正整数" } },
    "GET /v2/orders/paged bob": { status: 400, json: { error: "page 与 limit 为必填正整数" } },
    "GET /v2/orders/paged?limit=100&page=1 alice": ALICE_PAGE,
    "GET /v2/orders/paged?limit=100&page=1 bob": BOB_PAGE,
  });
  const out = await discoverListContract({
    request,
    slots: [{ key: "GET /v2/orders/paged", method: "GET", path: "/v2/orders/paged" }],
    identities: ["alice", "bob"],
  });
  assert.equal(out.contract.listPath, "payload.rows");
  assert.deepEqual(out.contract.listQuery, { page: "1", limit: "100" });
  assert.equal(out.contract.idField, "order_id");
  assert.equal(out.contract.ownerField, "created_by_uid");
  assert.equal(out.contract.needsPagination, true);
  assert.deepEqual(out.contract.counts, { a: 2, b: 1 });
  assert.equal(out.requestsUsed, 3);
  // 不带分页被 400 拒过，才试出分页组合
  assert.ok(out.tried.some((t) => t.outcome === "bad_request" && t.query === null));
  assert.deepEqual(calls.slice(0, 2), ["GET /v2/orders/paged alice", "GET /v2/orders/paged?limit=100&page=1 alice"]);
});

test("列表契约实测：两身份拿到同一批 id（没按归属过滤）时不给结论", async () => {
  const same = { json: { items: [{ id: 1 }, { id: 2 }] } };
  const { request } = mockTransport({
    "GET /api/orders alice": { ...same, status: 200 },
    "GET /api/orders bob": { ...same, status: 200 },
  });
  const out = await discoverListContract({ request, slots: [{ path: "/api/orders" }], identities: ["alice", "bob"] });
  assert.equal(out.contract, null);
  assert.ok(out.tried.some((t) => t.outcome === "ids_identical"));
});

test("列表契约实测：第二个身份为空列表时不认定归属过滤生效", async () => {
  const { request } = mockTransport({
    "GET /api/orders alice": { status: 200, json: { rows: [{ id: 1 }, { id: 2 }] } },
    "GET /api/orders bob": { status: 200, json: { rows: [] } },
  });
  const out = await discoverListContract({ request, slots: [{ path: "/api/orders" }], identities: ["alice", "bob"] });
  assert.equal(out.contract, null);
  assert.ok(out.tried.some((t) => t.outcome === "empty_list"));
});

test("列表契约实测：预算用尽就停手，判未验证而不是继续打", async () => {
  const routes = {};
  for (const name of ["alice", "bob"]) {
    routes[`GET /a?page=1&limit=100 ${name}`] = { status: 200, json: { rows: [{ id: 1 }] } };
    routes[`GET /a ${name}`] = { status: 200, json: { rows: [{ id: 1 }] } };
    routes[`GET /b ${name}`] = { status: 200, json: { rows: [{ id: 2 }] } };
  }
  const { calls, request } = mockTransport(routes);
  const out = await discoverListContract({
    request,
    slots: [{ path: "/a" }, { path: "/b" }],
    identities: ["alice", "bob"],
    budget: 3,
  });
  assert.equal(out.contract, null);
  assert.equal(calls.length, 3);
  assert.equal(out.requestsUsed, 3);
  assert.ok(out.tried.some((t) => t.outcome === "budget" || t.outcome === "ids_identical"));
});

test("列表契约实测：404 的槽位不再试第二种分页组合", async () => {
  const { calls, request } = mockTransport({});
  const out = await discoverListContract({ request, slots: [{ path: "/nope" }], identities: ["alice", "bob"] });
  assert.equal(out.contract, null);
  assert.deepEqual(calls, ["GET /nope alice"]);
  assert.ok(out.tried.some((t) => t.outcome === "slot_absent"));
});

test("单体契约实测：{ meta, record } 包装里认实体靠的是主键值对得上", async () => {
  const { request } = mockTransport({
    "GET /v1/orgs/9/orders/7001 alice": { status: 200, json: { meta: { orgId: 9 }, record: { order_id: 7001, created_by_uid: 1 } } },
  });
  const out = await discoverEntityContract({
    request,
    slot: { path: "/v1/orgs/9/orders/7001" },
    identity: "alice",
    idField: "order_id",
    idValue: 7001,
    ownerField: "created_by_uid",
  });
  assert.equal(out.entityPath, "record");
  assert.equal(out.requestsUsed, 1);
});

test("单体契约实测：响应里没有带该主键的对象就判未验证，不硬挑一个字段", async () => {
  const { request } = mockTransport({
    "GET /api/x/1 alice": { status: 200, json: { ok: true, meta: { a: 1 } } },
  });
  const out = await discoverEntityContract({ request, slot: { path: "/api/x/1" }, identity: "alice", idField: "order_id", idValue: 7 });
  assert.equal(out.entityPath, null);
  assert.equal(out.reason, "no_object_carries_id");
});

test("多段参数绑定实测：本人对象回读成功才算可寻址；没有来源字段时一个请求都不发", async () => {
  const routes = {
    "GET /v1/orgs/9/orders/7001 alice": { status: 200, json: { record: { order_id: 7001 } } },
  };
  const { calls, request } = mockTransport(routes);
  const ok = await discoverBindings({
    request,
    slots: [{ key: "GET /v1/orgs/:orgId/orders/:orderId", path: "/v1/orgs/:orgId/orders/:orderId", params: ["orgId", "orderId"], identity: "alice" }],
    itemsByIdentity: { alice: { item: { order_id: 7001, org_id: 9, created_by_uid: 1 } } },
    idField: "order_id",
  });
  assert.equal(ok.results[0].outcome, "verified");
  assert.deepEqual(
    Object.fromEntries(Object.entries(ok.results[0].bindings).map(([k, v]) => [k, v.field])),
    { orgId: "org_id", orderId: "order_id" }
  );
  assert.deepEqual(calls, ["GET /v1/orgs/9/orders/7001 alice"]);

  const missed = await discoverBindings({
    request,
    slots: [{ key: "GET /v1/teams/:teamId/orders/:orderId", path: "/v1/teams/:teamId/orders/:orderId", params: ["teamId", "orderId"], identity: "alice" }],
    itemsByIdentity: { alice: { item: { order_id: 7001, org_id: 9 } } },
    idField: "order_id",
  });
  assert.equal(missed.results[0].outcome, "unbound_param");
  assert.equal(missed.results[0].bindings, null);
  assert.equal(missed.requestsUsed, 0);
  assert.equal(calls.length, 1);
});

test("多段参数绑定实测：200 但没读回同一个对象时不算验证通过", async () => {
  const { request } = mockTransport({
    "GET /v1/orgs/9/orders/7001 alice": { status: 200, json: { record: { order_id: 4242 } } },
  });
  const out = await discoverBindings({
    request,
    slots: [{ path: "/v1/orgs/:orgId/orders/:orderId", params: ["orgId", "orderId"], identity: "alice" }],
    itemsByIdentity: { alice: { item: { order_id: 7001, org_id: 9 } } },
    idField: "order_id",
  });
  assert.equal(out.results[0].outcome, "rejected");
  assert.equal(out.results[0].bindings, null);
});

test("契约缓存键：commit / 槽位 / 身份 / 已声明契约任一变化即失效", () => {
  const base = { commit: "abc", slots: [{ path: "/a" }], identities: ["alice", "bob"], resourceName: "order", declared: {} };
  const k = contractFingerprint(base);
  assert.equal(contractFingerprint(base), k);
  assert.notEqual(contractFingerprint({ ...base, commit: "def" }), k);
  assert.notEqual(contractFingerprint({ ...base, slots: [{ path: "/b" }] }), k);
  assert.notEqual(contractFingerprint({ ...base, identities: ["alice", "carol"] }), k);
  assert.notEqual(contractFingerprint({ ...base, declared: { id: "order_id" } }), k);
  // 槽位顺序不影响键
  const two = { ...base, slots: [{ path: "/a" }, { path: "/b" }] };
  assert.equal(contractFingerprint(two), contractFingerprint({ ...base, slots: [{ path: "/b" }, { path: "/a" }] }));
});

test("契约缓存内容：只留字段位置，响应体与原始列表绝不落盘", () => {
  const cached = contractForCache({
    listPath: "payload.rows",
    idField: "order_id",
    ownerField: "created_by_uid",
    slot: { method: "GET", path: "/v2/orders/paged", extraQuery: { token: "secret" } },
    itemsA: [{ created_by_uid: 1, note: "alice 的真实数据" }],
    itemsB: [{ created_by_uid: 2, note: "bob 的真实数据" }],
  });
  assert.equal(cached.itemsA, undefined);
  assert.equal(cached.itemsB, undefined);
  assert.deepEqual(cached.slot, { method: "GET", path: "/v2/orders/paged" });
  assert.doesNotMatch(JSON.stringify(cached), /真实数据|secret/);
});

test("commit 读取：ref 文件 / packed-refs / detached HEAD 三种形态", async () => {
  assert.equal(
    await readCommitFromGit(async (p) => (p === ".git/HEAD" ? "ref: refs/heads/master\n" : p === ".git/refs/heads/master" ? "0123456789abcdef0123456789abcdef01234567\n" : "")),
    "0123456789abcdef0123456789abcdef01234567"
  );
  assert.equal(
    await readCommitFromGit(async (p) =>
      p === ".git/HEAD"
        ? "ref: refs/heads/main\n"
        : p === ".git/refs/heads/main"
          ? ""
          : "0123456789abcdef0123456789abcdef01234567 refs/heads/main\nabcdef0123456789abcdef0123456789abcdef01 refs/heads/other\n"
    ),
    "0123456789abcdef0123456789abcdef01234567"
  );
  assert.equal(await readCommitFromGit(async (p) => (p === ".git/HEAD" ? "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n" : "")), "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
  assert.equal(await readCommitFromGit(async () => { throw new Error("enoent"); }), null);
});

test("getByPath 对非对象节点安全返回 undefined", () => {
  assert.equal(getByPath("plain", "a.b"), undefined);
  assert.equal(getByPath(null, "a"), undefined);
  assert.equal(getByPath({ a: { b: 3 } }, "a.b"), 3);
});
