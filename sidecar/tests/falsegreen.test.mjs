import test from "node:test";
import assert from "node:assert/strict";
import { allEvidence, auditWhiteboxRun, doubledSegments } from "../lib/falsegreen.mjs";

// 这一层的价值在于「不看结论方向，只看结论有没有被测量支撑」：
// 2026-10-30 唯一的 exit 0 假绿灯（#174）就是靠 3 条打在 /api/api/* 的 404 被记成「被阻断」拿到的。

const attackCase = (endpoint, status) => ({
  category: "attack",
  endpoint,
  response: { status },
  verdict: status === 404 ? "blocked" : "blocked",
});

function reportFor({ exit = 0, attack = [], findings = 5, identities = null, blackbox = null, error = null, start = true }) {
  return {
    verdict: { exitCode: exit, outcome: "not_reproducible" },
    error,
    blackbox,
    summary: {
      findingCount: findings,
      start: start ? { cmd: "node", args: ["server.js"], readyPattern: "listening" } : null,
      identities,
    },
    evidence: { pre: attack.map((a) => attackCase(a[0], a[1])), post: [], postWriteback: [], blackbox: [] },
  };
}

const rules = (issues) => issues.map((i) => i.rule);

test("doubledSegments：认出连续重复段，忽略参数段与查询串", () => {
  assert.deepEqual(doubledSegments("/api/api/auth/login"), ["api"]);
  assert.deepEqual(doubledSegments("/api/api/api/orders"), ["api"]);
  assert.deepEqual(doubledSegments("/api/bookings?x=1"), []);
  assert.deepEqual(doubledSegments("/v1/v2/orders"), []);
  assert.deepEqual(doubledSegments("/api/:id/:id"), []);
});

test("#174 现场：exit 0 + 攻击全打 /api/api/* 的 404 → R2 与 R3 同时命中", () => {
  const issues = auditWhiteboxRun({
    report: reportFor({
      exit: 0,
      attack: [
        ["/api/api/auth/login", 401],
        ["/api/api/bookings", 404],
        ["/api/api/users", 404],
      ],
    }),
  });
  assert.ok(rules(issues).includes("R2"));
  assert.ok(rules(issues).includes("R3"));
  assert.match(issues.find((i) => i.rule === "R2").text, /api @ \/api\/api\/auth\/login/);
});

test("攻击全部 404/405 即为「未复现来自打错地址」", () => {
  const issues = auditWhiteboxRun({
    report: reportFor({
      exit: 0,
      attack: [
        ["/api/orders/1", 404],
        ["/api/orders/2", 405],
      ],
    }),
  });
  assert.deepEqual(rules(issues), ["R3"]);
  assert.match(issues[0].text, /全部 404/);
});

test("正常绿灯：攻击真实到达目标（401/403）→ 无结构性问题", () => {
  const issues = auditWhiteboxRun({
    report: reportFor({
      exit: 0,
      attack: [
        ["/api/orders/1", 403],
        ["/api/orders/2", 401],
        ["/api/settings", 200],
      ],
      identities: { configured: ["alice", "bob"], loggedIn: [{ name: "alice" }, { name: "bob" }] },
    }),
    contract: { identities: [{ name: "alice" }, { name: "bob" }] },
  });
  assert.deepEqual(issues, []);
});

test("exit 0 但身份没建立：跨用户用例其实是匿名打的", () => {
  const issues = auditWhiteboxRun({
    report: reportFor({
      exit: 0,
      attack: [["/api/orders/1", 403]],
      identities: { configured: ["alice", "bob", "carol"], loggedIn: [{ name: "alice" }] },
    }),
    contract: { identities: [{ name: "alice" }, { name: "bob" }, { name: "carol" }] },
  });
  assert.deepEqual(rules(issues), ["R3"]);
  assert.match(issues[0].text, /只建立 1 个会话/);
});

test("红/黄灯不受 R3 约束（结论已经是「未证明」，不需要再要求绿灯支撑）", () => {
  const issues = auditWhiteboxRun({
    report: reportFor({
      exit: 2,
      attack: [
        ["/api/orders/1", 404],
        ["/api/orders/2", 404],
      ],
    }),
  });
  assert.deepEqual(rules(issues), []);
});

test("R4：git_error（worktree 建不出来，白盒专属）单独立项", () => {
  const issues = auditWhiteboxRun({
    report: reportFor({ exit: 2, error: { code: "git_error", message: "Filename too long" } }),
  });
  assert.deepEqual(rules(issues), ["R4"]);
  assert.match(issues[0].text, /Filename too long/);
});

test("R1：白盒层产出黑盒报告 / 没有启动契约", () => {
  assert.deepEqual(rules(auditWhiteboxRun({ report: reportFor({ exit: 1, blackbox: { url: "http://x" } }) })), ["R1"]);
  assert.deepEqual(rules(auditWhiteboxRun({ report: reportFor({ exit: 1, start: false }) })), ["R1"]);
});

test("R5：静态候选 0 条按漏检处理，而不是「项目干净」", () => {
  const issues = auditWhiteboxRun({ report: reportFor({ exit: 1, findings: 0, start: true }), minFindings: 3 });
  assert.deepEqual(rules(issues), ["R5"]);
  assert.match(issues[0].text, /静态候选 0 条 < 下限 3 条/);
});

test("没有报告时不给「通过」", () => {
  const issues = auditWhiteboxRun({ report: null });
  assert.deepEqual(rules(issues), ["R0"]);
});

test("allEvidence 汇总 pre/post/post_writeback", () => {
  const r = reportFor({ attack: [["/a", 200]] });
  r.evidence.post = [{ category: "business" }];
  r.evidence.postWriteback = [{ category: "attack" }];
  assert.equal(allEvidence(r).length, 3);
});
