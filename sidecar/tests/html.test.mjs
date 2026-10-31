/**
 * SSR / HTML 资源发现与内容归属取证（lib/html.mjs）的单元测试。
 * 运行：npm run test:sidecar
 */
import test from "node:test";
import assert from "node:assert/strict";

import {
  looksHtml,
  templateMatcher,
  pageLinks,
  extractPageIds,
  pageText,
  distinctiveMarkers,
  markersInText,
} from "../lib/html.mjs";

test("looksHtml: JSON 已解析就不是页面，content-type 与正文形态都能认", () => {
  assert.equal(looksHtml({ json: { id: 1 }, body: '{"id":1}', headers: { "content-type": "application/json" } }), false);
  assert.equal(looksHtml({ json: null, body: "<html><body>hi</body></html>", headers: { "content-type": "text/html; charset=utf-8" } }), true);
  assert.equal(looksHtml({ json: null, body: '<!DOCTYPE html>\n<div><a href="/x/1">x</a></div>', headers: {} }), true, "无 content-type 时按正文形态判定");
  assert.equal(looksHtml({ json: null, body: "", headers: { "content-type": "text/html" } }), false, "空正文不是页面");
  assert.equal(looksHtml({ json: null, body: "PK\x03\x04binary", headers: { "content-type": "application/zip" } }), false, "二进制不是页面");
});

test("templateMatcher: 路由模板转段级匹配，尾段参数是主键", () => {
  const m = templateMatcher("/events/:id");
  assert.ok(m.re.exec("/events/42"));
  assert.equal(m.re.exec("/events/42/edit"), null, "参数只吃一段");
  assert.equal(m.re.exec("/orders/42"), null, "不匹配别的路由");
  assert.deepEqual(m.params, ["id"]);
  const nested = templateMatcher("/orgs/:orgId/members/:memberId");
  const hit = nested.re.exec("/orgs/7/members/9");
  assert.equal(hit[hit.length - 1], "9", "多段路由取末段为主键");
  assert.equal(templateMatcher("/events"), null, "无参数的集合页不是对象路由");
});

test("extractPageIds: 从真实 SSR 页面的链接里抓对象 ID（href / 框架路由 prop 都要覆盖）", () => {
  const html = [
    '<!doctype html><html><body>',
    '<nav><a href="/">首页</a> <a href="/events">活动</a></nav>',
    '<a class="card" href="/events/17">春季游园</a>',
    '<a href="/events/18?from=list">夜场</a>',
    '<Link href="/events/19" />',
    '<a href="/admin/events/17">后台同 id，不该被算成新对象</a>',
    '<button data-href="/events/20">报名</button>',
    "</body></html>",
  ].join("\n");
  const found = extractPageIds(html, ["/events/:id"]);
  assert.deepEqual(found.map((f) => f.id), ["17", "18", "19", "20"], "四个入口形态各抓一次，重复模板不重复计");
  assert.equal(found[0].template, "/events/:id");
  assert.equal(found[0].param, "id");
  assert.equal(extractPageIds(html, []).length, 0, "没有候选模板时不猜资源");
});

test("pageLinks 去重且不误吞查询串以外的段", () => {
  const links = pageLinks('<a href="/x/1">a</a><a href="/x/1">a</a><img src="/logo.png">');
  assert.ok(links.includes("/x/1"));
  assert.equal(links.filter((l) => l === "/x/1").length, 1, "同一链接只出现一次");
});

test("pageText: 结构残留归一化后不该盖住正文差异", () => {
  const t = pageText('<div class="card"><script>var a=1;</script><style>.a{color:red}</style><p>订单&nbsp;A-9527&nbsp;已支付</p></div>');
  assert.equal(t, "订单 A-9527 已支付");
});

test("distinctiveMarkers: 只在本人页面出现的片段才算归属证据，差一两个词不算", () => {
  const victim = pageText('<p>订单 SN-77AA-QQ 收货 西郊仓库 备注 加急</p><span>状态 paid</span>');
  const attackerOwn = pageText('<p>订单 SN-11BB-ZZ 收货 南城驿站 备注 自提</p><span>状态 paid</span>');
  const markers = distinctiveMarkers(victim, [attackerOwn]);
  assert.ok(markers.includes("SN-77AA-QQ"), "本人页面的独有单号要被抓到");
  assert.ok(!markers.includes("paid"), "两页都有的通用词不算归属证据");
  assert.deepEqual(distinctiveMarkers("<p>状态 paid</p>", ["<p>状态 paid</p>"]), [], "无独有片段时返回空");
  assert.deepEqual(distinctiveMarkers("AAAA BBBB", ["CCCC"]), [], "少于 3 个片段不足以定案（宁可不判）");
});

test("distinctiveMarkers: 片段保留原始大小写，比对正文时不会因大小写不同而漏判", () => {
  const victim = "Invoice INV-9F3K-AB customer ACME-STEEL-NL order REF-4471-XZ";
  const control = "Invoice INV-1X1X-CD customer GOTEBORG-AB order REF-9982-QM";
  const markers = distinctiveMarkers(victim, [control]);
  assert.ok(markers.includes("INV-9F3K-AB"), "抓到的片段要能原样在响应正文里搜到");
  assert.equal(markersInText(markers, victim).all, true);
});

test("markersInText: 必须全部命中才算证据成立", () => {
  const body = "订单 SN-77AA-QQ 收货 西郊仓库";
  assert.deepEqual(markersInText(["SN-77AA-QQ", "西郊仓库"], body), { hit: ["SN-77AA-QQ", "西郊仓库"], all: true });
  const partial = markersInText(["SN-77AA-QQ", "西郊仓库", "加急"], body);
  assert.equal(partial.all, false, "只命中一部分说明不是同一对象的内容");
  assert.equal(markersInText([], body).all, false, "零片段不构成证据");
});
