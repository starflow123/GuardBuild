import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  ACTIONS,
  KNOWN_IMPOSSIBLE,
  RECIPE_VERSION,
  SLOTS,
  VERDICT_RULES,
  checkAnchors,
  closestActionName,
  formatRejections,
  validateRecipe,
} from "../lib/actiontable.mjs";

// M1-4（#190）：动作表 + 表外动作拒收。
// 这一层的立场：多余字段不能「忽略就好」——执行器读不到的键被忽略，就是「配方说打了、实际没打」，
// 那是假绿灯的一种。所以表外一律拒收，并说清缺哪个动作（它是能力请求单的输入）。

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const rule = (r, where) => r.rejections.find((x) => x.where === where);

const legalIdor = {
  version: RECIPE_VERSION,
  family: "idor-read",
  steps: [
    { id: "hit", action: "request.as", method: "GET", path: "{slot:readPath}", query: "id=other", identity: "attacker" },
    { id: "confirm", action: "readback.ownership", uses: "hit", field: "ownerName" },
  ],
  verdict: { rule: "cross-proof" },
};

test("合法配方通过：但通过只代表填表合法，不代表打得中", () => {
  const v = validateRecipe(legalIdor);
  assert.equal(v.ok, true, JSON.stringify(v.rejections));
  assert.match(formatRejections(v), /只代表填表合法/);
});

test("表外动作被拒，并说明缺哪个动作、最近的是哪条、该走能力请求单", () => {
  const v = validateRecipe({
    version: RECIPE_VERSION,
    family: "idor-read",
    steps: [{ id: "s1", action: "concurrent.request", method: "GET", path: "/api/x" }],
    verdict: { rule: "attack-repro" },
  });
  assert.equal(v.ok, false);
  const hit = rule(v, "steps[0]#s1.action");
  assert.equal(hit.rule, "action_out_of_table");
  assert.equal(hit.missingAction, "concurrent.request");
  assert.equal(hit.nearest, "request.concurrent");
  assert.equal(hit.needCapabilityRequest, true);
  assert.match(formatRejections(v), /应走能力请求单/);
});

test("动作名对了但偷偷挂上执行器不认的键，同样拒收", () => {
  const v = validateRecipe({
    version: RECIPE_VERSION,
    family: "idor-read",
    steps: [{ id: "s1", action: "request.as", method: "GET", path: "/api/x", identity: "attacker", cookieJar: true }],
    verdict: { rule: "attack-repro" },
  });
  const hit = rule(v, "steps[0]#s1.cookieJar");
  assert.equal(hit.rule, "param_out_of_table");
  assert.equal(hit.missingAction, "request.as.cookieJar");
  assert.match(hit.why, /Cookie 容器/);
  assert.ok(hit.allowed.includes("identity"), "拒收时要列出这条动作能带的键");
});

test("CONNECT/TRACE 与没听说过的写法都不进表", () => {
  const mk = (method) =>
    validateRecipe({
      version: RECIPE_VERSION,
      family: "idor-read",
      steps: [{ id: "s1", action: "request.anonymous", method, path: "/api/x" }],
      verdict: { rule: "attack-repro" },
    });
  assert.equal(rule(mk("CONNECT"), "steps[0]#s1.method").rule, "method_denied");
  assert.equal(rule(mk("TRACE"), "steps[0]#s1.method").rule, "method_denied");
  assert.equal(rule(mk("PROPFIND"), "steps[0]#s1.method").rule, "method_unknown");
  assert.equal(rule(mk("get"), "steps[0]#s1.method"), undefined, "小写方法名归一后放行");
});

test("判据冻结：只能引用名字，内联判定与未知判据都拒收", () => {
  const v = validateRecipe({
    ...legalIdor,
    verdict: { rule: "status-is-200", vulnerableIf: "res.status === 200" },
  });
  assert.equal(rule(v, "verdict.rule").rule, "verdict_unknown");
  assert.equal(rule(v, "verdict.vulnerableIf").rule, "verdict_inline");
  assert.match(rule(v, "verdict.vulnerableIf").why, /结论只能由判卷代码落笔/);
});

test("凭据值不许进配方：身份位只认保险库名字", () => {
  const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.Sup3rSecretValueabcdefg";
  const v = validateRecipe({
    version: RECIPE_VERSION,
    family: "idor-read",
    steps: [{ id: "s1", action: "request.as", method: "GET", path: "/api/x", identity: `Bearer ${token}` }],
    verdict: { rule: "attack-repro" },
  });
  const hit = rule(v, "steps[0]#s1.identity");
  assert.equal(hit.rule, "bad_identity");
  assert.match(hit.why, /凭据值不许进配方/);
  // 拒收文案本身是要进事件流与报告的渠道：回显只留长度，不留值
  const text = JSON.stringify(v.rejections) + formatRejections(v);
  assert.ok(!text.includes(token), "凭据值不得出现在拒收结果里");
  assert.ok(!text.includes("Sup3rSecret"), "凭据片段也不许漏");
  assert.match(text, /已隐去/);
});

test("写/删探测的默认开关是冻结项，配方无权自己翻", () => {
  const v = validateRecipe({ ...legalIdor, allowMutation: true });
  assert.equal(rule(v, "allowMutation").rule, "gate_flip");
  assert.match(rule(v, "allowMutation").why, /guardbuild.json/);
});

test("声明依赖开关是允许的，但开关名必须真存在", () => {
  const ok = validateRecipe({
    version: RECIPE_VERSION,
    family: "idor-write",
    steps: [
      { id: "hit", action: "request.as", method: "DELETE", path: "{slot:cancelPath}", identity: "attacker", gate: "allowDestructive" },
      { id: "gate", action: "gate.mutation", kind: "allowDestructive" },
    ],
    verdict: { rule: "attack-repro" },
  });
  assert.equal(ok.ok, true, JSON.stringify(ok.rejections));
  const bad = validateRecipe({
    version: RECIPE_VERSION,
    family: "idor-write",
    steps: [{ id: "hit", action: "request.as", method: "DELETE", path: "{slot:cancelPath}", identity: "attacker", gate: "alwaysOn" }],
    verdict: { rule: "attack-repro" },
  });
  assert.equal(rule(bad, "steps[0]#hit.gate").rule, "gate_unknown");
  const badKind = validateRecipe({
    version: RECIPE_VERSION,
    family: "idor-write",
    steps: [{ id: "g", action: "gate.mutation", kind: "allowEverything" }],
    verdict: { rule: "attack-repro" },
  });
  assert.equal(rule(badKind, "steps[0]#g.kind").rule, "enum_value");
});

test("目标位置只能引用真实存在的槽位", () => {
  const v = validateRecipe({
    version: RECIPE_VERSION,
    family: "idor-read",
    steps: [{ id: "s1", action: "request.anonymous", method: "GET", path: "{slot:magicPath}" }],
    verdict: { rule: "attack-repro" },
  });
  assert.equal(rule(v, "steps[0]#s1.path").rule, "slot_unknown");
  assert.match(rule(v, "steps[0]#s1.path").why, /readPath/);
});

test("结构类拒收：版本、空步骤、重复 id、前向引用、超过执行器写死的跳数", () => {
  assert.equal(rule(validateRecipe({ ...legalIdor, version: "gb-recipe-0" }), "version").rule, "bad_version");
  assert.equal(rule(validateRecipe({ ...legalIdor, steps: [] }), "steps").rule, "empty_steps");
  const dup = validateRecipe({
    ...legalIdor,
    steps: [
      { id: "hit", action: "request.anonymous", method: "GET", path: "/a" },
      { id: "hit", action: "request.anonymous", method: "GET", path: "/b" },
    ],
  });
  assert.equal(rule(dup, "steps[1]#hit.id").rule, "duplicate_id");
  const forward = validateRecipe({
    ...legalIdor,
    steps: [legalIdor.steps[1], legalIdor.steps[0]],
  });
  assert.equal(rule(forward, "steps[0]#confirm.uses").rule, "bad_reference");
  const hops = validateRecipe({
    version: RECIPE_VERSION,
    family: "idor-read",
    steps: [{ id: "s1", action: "request.follow", max: 5 }],
    verdict: { rule: "attack-repro" },
  });
  assert.equal(rule(hops, "steps[0]#s1.max").rule, "over_limit");
});

test("不是对象的东西不当配方处理", () => {
  for (const bad of [null, undefined, "idor", 42]) {
    const v = validateRecipe(bad);
    assert.equal(v.ok, false);
    assert.equal(v.rejections[0].rule, "not_object");
  }
});

test("锚点自检：表上写着能做的，代码里必须还做得到", () => {
  const a = checkAnchors(repoRoot);
  assert.equal(a.ok, true, `未解析的锚点：${JSON.stringify(a.unresolved)}`);
  assert.ok(a.checked >= ACTIONS.length + VERDICT_RULES.length + 1);
});

test("表本身不许自相矛盾：动作名唯一、必填键在自己带的键里、槽位非空", () => {
  const names = ACTIONS.map((x) => x.name);
  assert.equal(new Set(names).size, names.length, "动作名重复会让引用不确定");
  for (const a of ACTIONS) {
    for (const req of a.required) {
      assert.ok(a.params.includes(req), `${a.name} 的必填键 ${req} 不在自己的参数表里`);
    }
    assert.ok(a.anchor?.file && a.anchor?.token, `${a.name} 必须指向实现它的代码`);
  }
  assert.ok(SLOTS.length > 0);
  assert.ok(Object.keys(KNOWN_IMPOSSIBLE).length > 0);
});

test("最近动作提示：拿参数名当动作名时能指回正道", () => {
  assert.equal(closestActionName("concurrent.request"), "request.concurrent");
  assert.equal(closestActionName("request.graphqlquery"), "request.graphql");
  assert.equal(closestActionName("sqlmap.run"), null, "完全无关的写法不许硬凑一个最近项");
});
