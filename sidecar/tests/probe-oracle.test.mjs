import test from "node:test";
import assert from "node:assert/strict";

import { followRedirects } from "../lib/http-follow.mjs";
import { sqliProof } from "../lib/probe.mjs";

function fakeSend(steps) {
  let i = 0;
  return async (url) => {
    const step = steps[Math.min(i, steps.length - 1)];
    i += 1;
    return { status: step.status, headers: step.headers ?? {}, body: step.body ?? "", url };
  };
}

test("followRedirects: 同源 307 尾斜杠跳转后返回最终响应", async () => {
  const send = fakeSend([
    { status: 307, headers: { location: "http://t.local/bank_codes/?code=1" } },
    { status: 200, body: '{"bank":"x"}' },
  ]);
  const out = await followRedirects(send, "http://t.local/bank_codes?code=1");
  assert.equal(out.res.status, 200);
  assert.deepEqual(out.hops, ["307 /bank_codes/?code=1"]);
  assert.equal(out.url, "http://t.local/bank_codes/?code=1");
});

test("followRedirects: 跨源 / 非 GET 302 都不跟随", async () => {
  const cross = await followRedirects(
    fakeSend([{ status: 301, headers: { location: "http://evil.local/x" } }, { status: 200 }]),
    "http://t.local/a"
  );
  assert.equal(cross.res.status, 301);
  assert.deepEqual(cross.hops, []);

  const post = await followRedirects(
    fakeSend([{ status: 302, headers: { location: "/next" } }, { status: 200 }]),
    "http://t.local/a",
    { method: "POST" }
  );
  assert.equal(post.res.status, 302);
  assert.deepEqual(post.hops, []);
});

test("sqliProof: 单对象端点（基线 404、注入后独占对象）判为命中", () => {
  // Host http.request 的响应只有 status/headers/body，没有黑盒的 ok 字段
  const benign = { status: 404, body: '{"detail":"Item not found"}', json: { detail: "Item not found" } };
  const attack = { status: 200, body: '{"bank":"BANKA","code":"1"}', json: { bank: "BANKA", code: "1" } };
  const p = sqliProof(attack, benign, "' OR '1'='1' -- ");
  assert.equal(p.hit, true);
  assert.equal(p.singleLeak, true);
});

test("sqliProof: 基线本就 200 的回声型端点不误报", () => {
  const benign = { status: 200, body: '{"echo":"x"}', json: { echo: "x" } };
  const attack = { status: 200, body: '{"echo":"y"}', json: { echo: "y" } };
  assert.equal(sqliProof(attack, benign, "1 OR 1=1").hit, false);
});

test("sqliProof: 列表端点沿用行数差判据", () => {
  const benign = { status: 200, ok: true, json: { items: [] }, body: '{"items":[]}' };
  const attack = { status: 200, ok: true, json: { items: [{ id: 1 }, { id: 2 }] }, body: '{"items":[{"id":1},{"id":2}]}' };
  const p = sqliProof(attack, benign, "' OR 1=1 -- ");
  assert.equal(p.hit, true);
  assert.equal(p.attackCount, 2);
  assert.equal(p.baseCount, 0);
});
