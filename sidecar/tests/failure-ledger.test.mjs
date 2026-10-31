import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  CATEGORIES,
  appendLedger,
  classifyRun,
  fingerprint,
  greenKeysOf,
  readLedger,
  redactSecrets,
  summarizeLedger,
} from "../lib/failureledger.mjs";

// M0-1（#187）：失败账本。这一层的立场是「失败要能被别人独立复核」——
// 只留一个红叉的话，下游（人或模型）就会照着可能是错的标注去学，所以每条记录带原始请求响应摘录，
// 并且凭据必须先在写出前摘掉：账本是进 git 的新渠道。

const target = (over = {}) => ({ id: "shop", expectedExit: 1, expectedVulnerableCases: ["attack-read-foreign"], ...over });
const result = (over = {}) => ({ id: "shop", pass: false, durationMs: 100, exit: { actual: 1, expected: 1, ok: true }, outcome: { actual: "vulnerable_unfixed", ok: true }, ...over });
const report = (entries) => ({ verdict: { outcome: "vulnerable_unfixed" }, evidence: { pre: entries } });

test("超时与进程错误归到「超时崩溃」，不再往下拆用例", () => {
  const r = classifyRun({ suite: "whitebox", target: target(), result: result({ exit: { actual: null, expected: 1, ok: false, timedOut: true } }), report: null });
  assert.equal(r.length, 1);
  assert.equal(r[0].category, "broken_run");
  assert.equal(r[0].cause, "timeout");

  const e = classifyRun({ suite: "whitebox", target: target(), result: result({ exit: { actual: null, expected: 1, ok: false, error: "spawn ENOENT" } }) });
  assert.equal(e[0].cause, "process_error");
});

test("目标没起来归「起不来」，与「测不了」不混谈", () => {
  const r = classifyRun({
    suite: "whitebox",
    target: target(),
    result: result({ exit: { actual: 2, expected: 1, ok: false }, outcome: { actual: "failed", ok: false } }),
    report: { error: { code: "target_not_ready" }, verdict: { outcome: "failed" } },
  });
  assert.equal(r.length, 1);
  assert.equal(r[0].category, "not_ready");
  assert.equal(r[0].cause, "target_not_ready");
});

test("引擎自己判「测不了」时归 inconclusive，而不是打不中", () => {
  const r = classifyRun({
    suite: "whitebox",
    target: target(),
    result: result({ exit: { actual: 2, expected: 1, ok: false }, outcome: { actual: "inconclusive", ok: false } }),
    report: { error: { code: "no_list_endpoint" }, verdict: { outcome: "inconclusive" } },
  });
  assert.ok(r.some((x) => x.category === "inconclusive" && x.caseKey === "-"));
});

test("漏报按证据形态分cause：没生成用例 / 被目标拒 / 打了没打中", () => {
  const base = { suite: "whitebox", target: target(), result: result({ dynamic: { missed: ["attack-read-foreign"], matched: [], falsePositives: [] } }) };

  const notGenerated = classifyRun({ ...base, report: report([]) });
  assert.equal(notGenerated[0].cause, "case_not_generated");
  assert.equal(notGenerated[0].category, "missed");

  const blocked = classifyRun({
    ...base,
    report: report([{ caseId: "attack-read-foreign", verdict: "blocked", actual: "HTTP 401", request: { url: "http://127.0.0.1:1/api/orders/9" }, response: { status: 401, body: "{\"error\":\"unauthorized\"}" } }]),
  });
  assert.equal(blocked[0].cause, "blocked_by_target");
  assert.equal(blocked[0].evidence.responseStatus, 401);

  const hit = classifyRun({
    ...base,
    report: report([{ caseId: "attack-read-foreign", verdict: "not_reproducible", actual: "HTTP 404", response: { status: 404, body: "{}" }, request: { url: "u" } }]),
  });
  assert.equal(hit[0].cause, "attempted_not_vulnerable");

  const inconclusive = classifyRun({ ...base, report: report([{ caseId: "attack-read-foreign", verdict: "inconclusive", actual: "无响应体可比", response: { status: 200, body: "" } }]) });
  assert.equal(inconclusive[0].category, "inconclusive");
  assert.equal(inconclusive[0].cause, "case_inconclusive");
});

test("同源变体折叠回基名，不因变体编号重复记账", () => {
  const r = classifyRun({
    suite: "whitebox",
    target: target(),
    result: result({ dynamic: { missed: ["attack-read-foreign"], matched: [], falsePositives: [] } }),
    report: report([{ caseId: "attack-read-foreign-obj2", verdict: "blocked", actual: "401", response: { status: 401, body: "" } }]),
  });
  assert.equal(r[0].cause, "blocked_by_target");
});

test("误报分「明令禁止」与「未标注」两种原因", () => {
  const base = { suite: "blackbox", target: target({ expectedVulnerable: ["blackbox-idor-*"], forbiddenVulnerable: ["blackbox-csrf-*"] }) };
  const r = classifyRun({
    ...base,
    result: result({ cases: { matched: [], missed: [], falsePositives: ["blackbox-csrf-api-orders-1", "blackbox-unknown-x"], forbiddenHits: ["blackbox-csrf-api-orders-1"] } }),
    report: { evidence: { blackbox: [{ caseId: "blackbox-csrf-api-orders-1", verdict: "vulnerable", actual: "复读见 canary", response: { status: 200, body: "{}" }, request: { url: "u" } }] } },
  });
  const causes = r.map((x) => x.cause).sort();
  assert.deepEqual(causes, ["forbidden_rule", "unannotated"]);
});

test("退出码不一致但没别的归因时，按实际终态推断类别", () => {
  const clean = classifyRun({ suite: "whitebox", target: target({ expectedExit: 1 }), result: result({ exit: { actual: 0, expected: 1, ok: false }, outcome: { actual: "not_reproducible", ok: false } }), report: report([]) });
  assert.equal(clean[0].category, "missed");
  assert.equal(clean[0].cause, "exit_mismatch");

  const dirty = classifyRun({ suite: "whitebox", target: target({ expectedExit: 0 }), result: result({ exit: { actual: 1, expected: 0, ok: false }, outcome: { actual: "vulnerable_unfixed", ok: false } }), report: report([]) });
  assert.equal(dirty[0].category, "false_positive");
});

test("凭据值不落账本：password / Bearer / Set-Cookie 都被摘掉，保险库占位符原样保留", () => {
  const redacted = redactSecrets('{"password":"hunter2","email":"a@b.c"} Bearer abcdefghijklmnop1234 Set-Cookie: sid=zzzz; Path=/ Authorization: Bearer ***vault:alice***');
  assert.ok(!redacted.includes("hunter2"), redacted);
  assert.ok(!redacted.includes("abcdefghijklmnop1234"), redacted);
  assert.ok(!redacted.includes("sid=zzzz"), redacted);
  assert.ok(redacted.includes("***vault:alice***"), "保险库占位符本来就不是凭据，不该被吞掉");
  assert.ok(redacted.includes('"password":"***redacted***"'), redacted);
});

test("证据摘录会截断并脱敏，长度受控", () => {
  const r = classifyRun({
    suite: "whitebox",
    target: target(),
    result: result({ dynamic: { missed: ["attack-read-foreign"], matched: [], falsePositives: [] } }),
    report: report([{ caseId: "attack-read-foreign", verdict: "blocked", actual: "x", request: { url: "http://127.0.0.1:1/a" }, response: { status: 200, body: `{"password":"p@ss","rows":"${"y".repeat(3000)}"}` } }]),
  });
  assert.ok(r[0].evidence.responseBody.length < 900, "摘录必须有上限");
  assert.ok(!r[0].evidence.responseBody.includes("p@ss"));
});

test("账本按指纹累积：同一条失败不重复占行，只增次数", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "gb-ledger-"));
  const file = path.join(dir, "ledger.jsonl");
  try {
    const rec = classifyRun({ suite: "whitebox", target: target(), result: result({ dynamic: { missed: ["c1"], matched: [], falsePositives: [] } }), report: report([]) })[0];
    const first = appendLedger({ filePath: file, records: [rec], gitHead: "aaa", now: "2026-10-31T00:00:00Z" });
    assert.equal(first.added, 1);
    const second = appendLedger({ filePath: file, records: [rec], gitHead: "bbb", now: "2026-11-01T00:00:00Z" });
    assert.equal(second.added, 0);
    assert.equal(second.updated, 1);
    const entries = readLedger(file);
    assert.equal(entries.length, 1);
    assert.equal(entries[0].occurrences, 2);
    assert.equal(entries[0].firstSeenIn, "aaa");
    assert.equal(entries[0].lastSeenIn, "bbb");
    assert.equal(entries[0].fingerprint, fingerprint(rec));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("只有全绿的完整轮次才关闭旧条目；--only 局部跑不关闭", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "gb-ledger2-"));
  const file = path.join(dir, "ledger.jsonl");
  try {
    const rec = classifyRun({ suite: "whitebox", target: target(), result: result({ dynamic: { missed: ["c1"], matched: [], falsePositives: [] } }), report: report([]) })[0];
    appendLedger({ filePath: file, records: [rec], gitHead: "aaa" });

    appendLedger({ filePath: file, records: [], gitHead: "bbb", partial: true, cleanRun: true, resolveSuite: "whitebox" });
    assert.equal(readLedger(file)[0].status, "open", "局部跑不能把没覆盖到的条目判成已解决");

    appendLedger({ filePath: file, records: [], gitHead: "ccc", cleanRun: true, resolveSuite: "whitebox" });
    const done = readLedger(file)[0];
    assert.equal(done.status, "resolved");
    assert.equal(done.resolvedIn, "ccc");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("绿键快照：只有通过的靶场进靶场级键，命中的用例单独成键", () => {
  const keys = greenKeysOf({
    suite: "whitebox",
    results: [
      { id: "a", pass: true, dynamic: { matched: ["attack-read-foreign"] } },
      { id: "b", pass: false, cases: { matched: ["blackbox-idor-api-orders-1"] } },
      { id: "c", pass: false, dynamic: { matched: [] } },
    ],
  });
  assert.deepEqual(keys, ["whitebox/a", "whitebox/a#attack-read-foreign", "whitebox/b#blackbox-idor-api-orders-1"]);
});

test("五类类别名与文档口径一致", () => {
  assert.deepEqual(Object.values(CATEGORIES), ["打不中", "误报", "起不来", "测不了", "超时崩溃"]);
  const s = summarizeLedger([{ category: "missed", status: "open", occurrences: 3 }, { category: "missed", status: "resolved", occurrences: 1 }]);
  assert.equal(s.missed.open, 1);
  assert.equal(s.missed.occurrences, 4);
});

test("扫描还没开始就失败（工作区/靶场进程）归「起不来」，不记成引擎跑挂", () => {
  const r = classifyRun({
    suite: "blackbox",
    target: target(),
    result: result({ exit: { actual: null, expected: 1, ok: false, error: "npm install 失败" }, startupFailed: true, reportPath: null }),
    report: null,
  });
  assert.equal(r.length, 1);
  assert.equal(r[0].category, "not_ready");
  assert.equal(r[0].cause, "startup_failed");

  const skipped = classifyRun({
    suite: "realworld",
    target: target(),
    result: { id: "shop", pass: true, skipped: true, skipReason: "目录不存在 D:/x", startupFailed: true, startupCause: "skipped_on_host", exit: { actual: null, expected: 0 }, durationMs: 0 },
  });
  assert.equal(skipped[0].category, "not_ready");
  assert.equal(skipped[0].cause, "skipped_on_host");
  assert.match(skipped[0].detail, /目录不存在/);
});

test("detail 里的凭据值不落账本：目标启动日志尾部也先脱敏再写", () => {
  const r = classifyRun({
    suite: "realworld",
    target: target(),
    result: result({
      startupFailed: true,
      exit: { actual: null, expected: 1, ok: false, error: 'seed done {"password":"Sup3rSecret!","email":"a@b.c"}' },
    }),
  });
  assert.equal(r.length, 1);
  assert.ok(!r[0].detail.includes("Sup3rSecret!"), `detail 仍带明文口令：${r[0].detail}`);
  assert.match(r[0].detail, /"password":"\*\*\*redacted\*\*\*"/);
});
