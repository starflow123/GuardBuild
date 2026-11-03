import test from "node:test";
import assert from "node:assert/strict";
import { BLACKBOX_ONLY_FAMILIES, WHITEBOX_FAMILIES, whiteboxFamilyName } from "../lib/coverage.mjs";
import { attackSurfaceOf } from "../lib/probe.mjs";
import { buildReport } from "../lib/report.mjs";

/** 会话视图的最小骨架：只填 buildReport 会用到的字段 */
function makeCtx(state, attackSurface) {
  return {
    sessionId: "sess-familydiff",
    gate: false,
    targetConfig: null,
    _attackSurface: attackSurface,
    view: {
      projectRoot: "D:/tmp/shop",
      projectName: "shop",
      startedAt: 1,
      state,
      findings: [{ id: "c1", type: "idor", method: "GET", path: "/api/orders/:id" }],
      evidence: [
        {
          phase: "pre",
          name: "跨用户读取别人的订单",
          category: "attack",
          identity: "alice",
          verdict: "blocked",
          actual: "HTTP 403 且无归属泄露",
        },
      ],
      phases: {},
      targets: {},
      patch: null,
      supabase: null,
      blackbox: null,
      acceptance: null,
      llm: null,
      error: null,
    },
  };
}

test("族表：用例 id 归族，认不出的原样保留而不是静默消失", () => {
  for (const f of WHITEBOX_FAMILIES) {
    assert.equal(whiteboxFamilyName(f.prefix), f.name, `${f.prefix} 应归到自己的族`);
    assert.equal(whiteboxFamilyName(`${f.prefix}-enc`), f.name, "变体用例沿用基名所在族");
  }
  assert.equal(whiteboxFamilyName("business-read-own"), null);
  const s = attackSurfaceOf(["attack-read-foreign", "business-read-own", "attack-mystery"], {});
  assert.deepEqual(s.probed, ["跨用户读取（IDOR）"]);
  assert.deepEqual(s.unknown, ["business-read-own", "attack-mystery"]);
});

test("族差集：开关关掉的写面候选不算「无候选」，黑盒专属族单列", () => {
  const writeName = WHITEBOX_FAMILIES.find((f) => f.prefix === "attack-write-foreign").name;
  const gated = attackSurfaceOf(["attack-read-foreign"], {
    gateSkippedWrite: ["DELETE /api/orders/:id"],
    mutation: { allowWrite: true, allowDelete: false },
  });
  assert.equal(gated.noCandidate.includes(writeName), false, "有候选但被开关关掉 → 不能写成「静态没候选」");
  assert.deepEqual(gated.gateSkippedWrite, ["DELETE /api/orders/:id"]);
  assert.deepEqual(gated.blackboxOnly, BLACKBOX_ONLY_FAMILIES);

  const none = attackSurfaceOf(["attack-read-foreign"], { gateSkippedWrite: [] });
  assert.equal(none.noCandidate.includes(writeName), true, "确实没有写面候选时才计入「无候选」");
  assert.equal(none.noCandidate.includes("跨用户读取（IDOR）"), false);
});

test("报告：白盒摘要按实际用例归族，并点名未打的族", () => {
  const surface = attackSurfaceOf(["attack-read-foreign", "attack-anonymous-read"], {
    gateSkippedWrite: ["PATCH /api/orders/:id"],
    mutation: { allowWrite: false, allowDelete: false },
  });
  const { json, markdown } = buildReport(makeCtx("done", surface), {
    outcome: "not_reproducible",
    exitCode: 0,
    state: "done",
  });
  assert.deepEqual(json.summary.attackSurface.gateSkippedWrite, ["PATCH /api/orders/:id"]);
  assert.match(markdown, /本轮攻击面：跨用户读取（IDOR）、无鉴权读取/);
  assert.match(markdown, /本轮无候选、因此一条没打：.*路径穿越/);
  assert.match(markdown, /有候选但被写面开关关掉：PATCH \/api\/orders\/:id/);
  assert.match(markdown, /白盒模式不探测、只在黑盒链路取证：CORS/);
  // 建议段给出可执行的修法，而不是让读者以为「测过且干净」
  assert.match(markdown, /写面越权候选本轮未探测[\s\S]*mutation\.allowWrite/);
  assert.match(markdown, /一条请求都没发出：.*这些族的状态未知/);
  assert.match(markdown, /已测用例未复现，但这不是「系统安全」的证明/);
});

test("报告：黑盒轮次不套白盒族差集（各按各的攻击面口径）", () => {
  const ctx = makeCtx("done", attackSurfaceOf(["attack-read-foreign"], {}));
  ctx.view.blackbox = {
    url: "http://127.0.0.1:9/",
    routeCount: 1,
    coverage: ["跨用户读取（IDOR）"],
    allowMutation: false,
    allowDestructive: false,
    findings: [],
    routes: [],
    login: null,
  };
  const { markdown } = buildReport(ctx, { outcome: "no_findings", exitCode: 0, state: "done" });
  assert.equal(markdown.includes("本轮无候选、因此一条没打"), false, "白盒族差集不该出现在黑盒报告里");
  assert.match(markdown, /本轮攻击面：跨用户读取（IDOR）/);
});
