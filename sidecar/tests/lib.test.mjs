/**
 * Sidecar 决策层单元测试：覆盖路径正则翻译、补丁锚点定位与操作生成。
 * 运行：npm run test:sidecar
 */
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { translatePathRegex } from "../lib/analyzer.mjs";
import { methodStyleOps, findRecordDecisionBlock } from "../lib/planner.mjs";

const fixturePath = fileURLToPath(new URL("../../fixtures/vibeshop/src/app.js", import.meta.url));
const fixture = readFileSync(fixturePath, "utf8");

/** 模拟 Host 的定向替换（find/replace/count） */
function applyOps(content, ops) {
  let out = content;
  for (const op of ops) {
    const idx = out.indexOf(op.find);
    assert.notEqual(idx, -1, `锚点未匹配: ${JSON.stringify(op.find.slice(0, 60))}…`);
    out = out.slice(0, idx) + op.replace + out.slice(idx + op.find.length);
  }
  return out;
}

test("translatePathRegex: 捕获组数字段翻译为 :id", () => {
  assert.equal(translatePathRegex("^\\/api\\/orders\\/(\\d+)$"), "/api/orders/:id");
  assert.equal(translatePathRegex("^\\/api\\/orders\\/(\\d+)\\/cancel$"), "/api/orders/:id/cancel");
  assert.equal(translatePathRegex("^\\/api\\/admin\\/orders\\/(\\d+)\\/cancel$"), "/api/admin/orders/:id/cancel");
});

test("translatePathRegex: 其他占位写法（转义括号 / 字符类 / 非捕获组）", () => {
  assert.equal(translatePathRegex("^\\/users\\/\\(\\d+\\)$"), "/users/:id");
  assert.equal(translatePathRegex("^\\/items\\/([0-9]+)$"), "/items/:id");
  assert.equal(translatePathRegex("^\\/files\\/([^\\/]+)$"), "/files/:id");
  assert.equal(translatePathRegex("^\\/logs\\/(?:[0-9]+)$"), "/logs/:id");
});

test("findRecordDecisionBlock: 定位决策为 no-check 的调用块（而非 401 拒绝块）", () => {
  const found = findRecordDecisionBlock(fixture, "orders.get");
  assert.ok(found, "应找到 orders.get 的 recordDecision 块");
  assert.ok(found.block.includes('decision: "no-check"'), "应为 no-check 决策块");
  assert.ok(found.block.includes("查询订单后直接返回"), "应为资源获取后的那次调用");
  assert.ok(!found.block.includes("未登录，拒绝访问订单详情"), "不应误命中 401 拒绝块");
});

test("methodStyleOps: 生成归属校验补丁且不影响拒绝分支", () => {
  const candGet = {
    matchVars: ["orderDetailMatch"],
    resource: "order",
    path: "/api/orders/:id",
    routeKeys: ["orders.get"],
    file: "fixtures/vibeshop/src/app.js",
  };
  const candCancel = {
    matchVars: ["orderCancelMatch"],
    resource: "order",
    path: "/api/orders/:id/cancel",
    routeKeys: ["orders.cancel"],
    file: "fixtures/vibeshop/src/app.js",
  };

  const patched = applyOps(fixture, [...methodStyleOps(fixture, candGet), ...methodStyleOps(fixture, candCancel)]);

  assert.ok(!patched.includes('decision: "no-check"'), "补丁后不应残留 no-check 决策");
  assert.equal((patched.match(/order\.userId !== auth\.user\.id/g) ?? []).length, 2, "两个端点各注入一处归属守卫");
  assert.equal((patched.match(/"order-owner"/g) ?? []).length, 4, "拒绝与放行两条决策路径各记录一次归属检查");
  assert.ok(patched.includes('note: "未登录，拒绝访问订单详情"'), "401 拒绝块注释保持原样");
  assert.ok(patched.includes('note: "未登录，拒绝取消订单"'), "401 拒绝块注释保持原样");
  assert.ok(patched.includes("order.userId !== auth.user.id"), "注入的守卫基于对象归属比较");
});

test("methodStyleOps: 锚点缺失时诚实抛错", () => {
  assert.throws(
    () => methodStyleOps("const x = 1;\n", { matchVars: ["nopeMatch"], resource: "order", path: "/x", file: "x.js" }),
    /锚点未匹配/
  );
  assert.throws(
    () => methodStyleOps(fixture, { matchVars: [], resource: "order", path: "/x", file: "x.js" }),
    /未找到 Match 变量/
  );
});
