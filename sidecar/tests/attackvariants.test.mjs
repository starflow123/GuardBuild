/**
 * 攻击变体库与正向断言单元测试：验收必须对「换对象 / 换 ID 写法 / 换参数通道」同样成立，
 * 且修复不得靠删字段或整端点拒绝来冒充「攻击已阻断」。
 * 运行：npm run test:sidecar
 */
import test from "node:test";
import assert from "node:assert/strict";

import {
  MAX_ID_ENCODINGS,
  MAX_VARIANT_CASES,
  channelVariantFor,
  foreignObjectVariants,
  idEncodingVariants,
  rawTokenRequest,
} from "../lib/attackvariants.mjs";
import { buildCases } from "../lib/probe.mjs";

const readCand = { fullPath: "/api/orders/:id", routeKeys: ["orders.get"], resource: "order" };

function ctxWith(plan) {
  return { plan, targetConfig: null };
}

function baseTargets(extra = {}) {
  return {
    attacker: { name: "alice", user: { id: 1 } },
    victim: { name: "bob", user: { id: 2 } },
    admin: null,
    readTarget: { id: 11 },
    ownReadTarget: { id: 14 },
    attackerOwnIds: new Set(["14"]),
    ...extra,
  };
}

test("idEncodingVariants: 只保留「服务端仍解析为同一对象」的写法", () => {
  const list = idEncodingVariants(7);
  assert.ok(list.length >= 2, "数值 ID 至少给出前导零与空白两类写法");
  assert.ok(list.length <= MAX_ID_ENCODINGS);
  for (const v of list) {
    assert.equal(Number(decodeURIComponent(v.token)), 7, `${v.token} 必须仍指向 #7`);
    assert.notEqual(decodeURIComponent(v.token), "7");
  }
  assert.deepEqual(idEncodingVariants("a1b2c3"), [], "非数值 ID 不做编码变体（无法保证指向同一对象）");
  assert.deepEqual(idEncodingVariants(null), []);
});

test("foreignObjectVariants: 跳过基线对象与 attacker 名下对象，最多两个", () => {
  const items = [{ id: 11 }, { id: 12 }, { id: 14 }, { id: 13 }, { id: 15 }];
  const out = foreignObjectVariants(items, 11, new Set(["14"]));
  assert.deepEqual(out.map((v) => v.item.id), [12, 13], "主键 11 与 attacker 自有 14 都不算他人对象");
  assert.deepEqual(foreignObjectVariants(undefined, 11), []);
});

test("channelVariantFor: 仅在 :param 位于末段的只读 REST 候选上构造查询参数别名", () => {
  assert.deepEqual(channelVariantFor(readCand), { label: "改用查询参数 id", base: "/api/orders", param: "id" });
  assert.equal(channelVariantFor({ ...readCand, method: "POST" }), null, "非只读候选不做通道变体");
  assert.equal(channelVariantFor({ fullPath: "/api/orders/:id/items" }), null, "中间段参数不猜路径形态");
  assert.equal(channelVariantFor({ fullPath: "/api/orders", queryParam: { param: "orderId" } }), null);
  assert.equal(channelVariantFor({ ...readCand, graphql: { op: "query" } }), null, "GraphQL 走文档体，不做 URL 通道变体");
  assert.equal(channelVariantFor({ ...readCand, queryParam: { param: "orderId" } }).param, "orderId");
});

test("rawTokenRequest: 变体 token 原样上线（%20 不得被二次编码）", () => {
  assert.equal(rawTokenRequest(readCand, "%207").path, "/api/orders/%207");
  const qCand = { fullPath: "/app/modifyproduct", queryParam: { param: "id" }, method: "GET" };
  assert.equal(rawTokenRequest(qCand, "07").path, "/app/modifyproduct?id=07");
});

test("buildCases: 首要读候选展开三类同源变体，且都带 requiresPreRepro", () => {
  const cases = buildCases(
    ctxWith({
      resource: "order",
      readCandidate: readCand,
      listEndpoint: { path: "/api/orders", routeKey: "orders.list" },
    }),
    baseTargets({ victimItems: [{ id: 11 }, { id: 12 }, { id: 13 }] })
  );
  const variants = cases.filter((c) => c.variant);
  assert.equal(variants.length, MAX_VARIANT_CASES, "变体总数受配额约束");
  assert.deepEqual(
    variants.map((c) => c.id),
    [
      "attack-read-foreign-obj1",
      "attack-read-foreign-obj2",
      "attack-read-foreign-enc1",
      "attack-read-foreign-enc2",
      "attack-read-foreign-enc3",
      "attack-read-foreign-chan1",
    ]
  );
  assert.deepEqual(
    variants.map((c) => c.path),
    ["/api/orders/12", "/api/orders/13", "/api/orders/011", "/api/orders/%2011", "/api/orders/11%20", "/api/orders?id=11"]
  );
  assert.ok(variants.every((c) => c.requiresPreRepro === true), "变体必须先在修复前复现才计入验收");
  assert.ok(variants.every((c) => c.identity === "alice"), "变体仍由 attacker 身份发起（越权语义不变）");

  // 判定语义与基线一致：修复前拿到他人对象即 vulnerable，修复后仍拿到即 regressed
  const enc = variants.find((c) => c.id === "attack-read-foreign-enc1");
  assert.equal(enc.verify({ status: 200, json: { order: { id: 11, userId: 2, amount: 9 } } }, "pre").verdict, "vulnerable");
  assert.equal(enc.verify({ status: 200, json: { order: { id: 11, userId: 2, amount: 9 } } }, "post").verdict, "regressed");
  assert.equal(enc.verify({ status: 403, json: { error: "无权访问" } }, "post").verdict, "blocked");
  assert.equal(
    enc.verify({ status: 200, json: { order: { id: 14, userId: 1 } } }, "post").verdict,
    "inconclusive",
    "返回的是 attacker 自己的对象时不得算越权"
  );
});

test("buildCases: 无额外材料时只保留 ID 写法与通道变体，配额内不截断基线用例", () => {
  const cases = buildCases(
    ctxWith({ resource: "order", readCandidate: readCand }),
    baseTargets()
  );
  assert.deepEqual(
    cases.map((c) => c.id),
    [
      "attack-read-foreign",
      "attack-read-foreign-enc1",
      "attack-read-foreign-enc2",
      "attack-read-foreign-enc3",
      "attack-read-foreign-chan1",
      "business-read-own",
      "business-unauth-401",
    ]
  );
});

test("buildCases: 非首要读候选不展开变体（成本受控）", () => {
  const cases = buildCases(
    ctxWith({
      resource: "order",
      readCandidates: [readCand, { fullPath: "/api/invoices/:id", routeKeys: ["invoices.get"], resource: "invoice" }],
    }),
    baseTargets({ victimItems: [{ id: 11 }, { id: 12 }] })
  );
  const variantCands = cases.filter((c) => c.variant).map((c) => c.routeKey);
  assert.ok(variantCands.every((k) => k === "orders.get"), "变体只挂在首要读候选上");
  assert.ok(cases.some((c) => c.id === "attack-read-foreign-2"), "第二候选仍按基线用例构建");
});

test("buildCases: 正向断言——受害人本人读取同样必须可见，字段不得比修复前少", () => {
  const ctx = ctxWith({ resource: "order", readCandidate: readCand });
  const cases = buildCases(ctx, baseTargets({ victimOwnTarget: { id: 11 } }));
  const victimCase = cases.find((c) => c.id === "business-read-own-victim");
  assert.ok(victimCase, "victim 名下有对象时应构造其本人可见性用例");
  assert.equal(victimCase.identity, "bob");
  assert.equal(victimCase.path, "/api/orders/11");
  assert.equal(
    victimCase.verify({ status: 403, json: { error: "无权访问" } }).verdict,
    "regressed",
    "整端点拒绝（把本人也挡掉）必须判回归，不能算修好"
  );
  assert.equal(
    victimCase.verify({ status: 200, json: { order: { id: 11, userId: 2 } } }).verdict,
    "passed",
    "无修复前基线时按归属可见即通过"
  );

  // 预置修复前字段基线后：缺字段即「用删字段冒充修复」
  ctx._ownerContract = new Map([["business-read-own-victim", ["id", "userId", "amount", "status"]]]);
  const gutted = victimCase.verify({ status: 200, json: { order: { id: 11, userId: 2 } } });
  assert.equal(gutted.verdict, "regressed");
  assert.match(gutted.actual, /字段契约缺失 amount、status/);
  assert.equal(
    victimCase.verify({ status: 200, json: { order: { id: 11, userId: 2, amount: 3, status: "paid" } } }).verdict,
    "passed",
    "字段齐全（含新增字段）应通过"
  );
  assert.equal(victimCase.contract({ json: { order: { id: 11, userId: 2 } } }).join(","), "id,userId");
});
