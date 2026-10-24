#!/usr/bin/env node
/**
 * 业务逻辑 / 竞态端到端演练：以 fixtures/bizlogic-shop（订单发货 + 退款）驱动 guardbuild-headless --gate，
 * 验证两类结局：
 *
 *   ① 未修复 → exit 1（verdict=vulnerable_unfixed，error=no_patchable_candidates）
 *      状态跳步：pending 订单调用发货仍返回 2xx，且回读状态变为 shipped；
 *      并发双花：5 次并发退款全部成功并各自返回不同 refund_id。
 *      两类都没有自动修复模板，按「证据成立但不可自动修复」阻断并给人工修复指引。
 *   ② 已修复（GB_BIZ_HARDENED=1：发货校验前置状态 + 退款同步置位后再落账）
 *      → exit 0（not_reproducible）；静态候选仍在，但状态流转被 409 拒绝、并发只剩 1 次成功。
 *
 * 说明：只为「业务规则被绕过」取证——不发破坏性请求，不改目标数据之外的任何东西。
 *
 * 用法: node scripts/e2e-bizlogic.mjs
 */
import { spawn, spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const demoDir = path.join(repoRoot, ".demo-bizlogic");
const dataDir = path.join(demoDir, "data");
const fixture = path.join(repoRoot, "fixtures", "bizlogic-shop");

function resolveHeadlessBin() {
  if (process.env.GUARDBUILD_HEADLESS_BIN) return process.env.GUARDBUILD_HEADLESS_BIN;
  const name = process.platform === "win32" ? "guardbuild-headless.exe" : "guardbuild-headless";
  const debug = path.join(repoRoot, "src-tauri", "target", "debug", name);
  return existsSync(debug) ? debug : path.join(repoRoot, "src-tauri", "target", "release", name);
}
const exe = resolveHeadlessBin();

const checks = [];
function check(name, cond, detail = "") {
  checks.push({ name, pass: !!cond });
  console.log(`${cond ? "  ✓" : "  ✗"} ${name}${detail ? ` — ${detail}` : ""}`);
  return !!cond;
}

function git(args, cwd) {
  const r = spawnSync("git", args, { cwd, encoding: "utf8" });
  if (r.status !== 0) throw new Error(`git ${args.join(" ")} 失败: ${r.stderr || r.stdout}`);
  return r.stdout;
}

function makeWorkspace(name, mutate = null) {
  const ws = path.join(demoDir, name);
  rmSync(ws, { recursive: true, force: true });
  cpSync(fixture, ws, { recursive: true });
  if (mutate) mutate(ws);
  git(["init", "-q"], ws);
  git(["config", "user.email", "gate@guardbuild.local"], ws);
  git(["config", "user.name", "GuardBuild Gate"], ws);
  git(["add", "-A"], ws);
  git(["commit", "-qm", `${name} 基线`], ws);
  return ws;
}

/** 复刻「已修复」形态：源码静态候选保持原样，运行时补上前置状态校验与并发保护 */
function enableHardened(ws) {
  const p = path.join(ws, "guardbuild.json");
  const cfg = JSON.parse(readFileSync(p, "utf8"));
  cfg.start.env = { ...(cfg.start.env ?? {}), GB_BIZ_HARDENED: "1" };
  writeFileSync(p, `${JSON.stringify(cfg, null, 2)}\n`);
}

function runGate(project, label, timeoutMs = 120_000) {
  return new Promise((resolve, reject) => {
    const child = spawn(exe, ["--gate", "--project", project, "--report", path.join(demoDir, "reports", label)], {
      cwd: repoRoot,
      env: {
        ...process.env,
        GUARDBUILD_DATA_DIR: dataDir,
        GUARDBUILD_SIDECAR: path.join(repoRoot, "sidecar", "main.mjs"),
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (b) => { stdout += b.toString(); });
    child.stderr.on("data", (b) => { stderr += b.toString(); });
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`[bizlogic:${label}] 超时 ${timeoutMs}ms`));
    }, timeoutMs);
    child.on("exit", (code) => {
      clearTimeout(timer);
      const gateLine = stdout.split("\n").filter((l) => l.startsWith("GB_GATE ")).pop();
      let gate = null;
      if (gateLine) {
        try { gate = JSON.parse(gateLine.slice("GB_GATE ".length)); } catch { /* ignore */ }
      }
      resolve({ code, gate, stdout, stderr });
    });
    child.on("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
  });
}

function readReport(round) {
  const p = path.join(demoDir, "reports", round, "report.json");
  if (!existsSync(p)) return null;
  try { return JSON.parse(readFileSync(p, "utf8")); } catch { return null; }
}

async function main() {
  console.log("[BIZ] 0/2 准备演示目录…");
  rmSync(demoDir, { recursive: true, force: true });
  mkdirSync(dataDir, { recursive: true });
  if (!existsSync(exe)) throw new Error(`未找到无头宿主: ${exe}（先 cargo build --no-default-features --bin guardbuild-headless）`);

  // ---------- ① 未修复 → exit 1 ----------
  console.log("\n[BIZ] 1/2 未修复：状态跳步 + 并发重复退款：期望 exit 1（vulnerable_unfixed）…");
  const ws1 = makeWorkspace("b1-vuln");
  const r1 = await runGate(ws1, "b1-vuln");
  const g1 = r1.gate ?? {};
  check("退出码 = 1（漏洞证据成立）", r1.code === 1, `code=${r1.code}${r1.code !== 1 ? ` stderr=${r1.stderr.slice(-400)}` : ""}`);
  check(
    "verdict=vulnerable_unfixed 且 error=no_patchable_candidates",
    g1.verdict === "vulnerable_unfixed" && g1.error?.code === "no_patchable_candidates",
    `verdict=${g1.verdict} code=${g1.error?.code} state=${g1.state}`
  );
  const rep1 = readReport("b1-vuln");
  check(
    "报告结论一致（vulnerable_unfixed/exit 1）",
    rep1?.verdict?.outcome === "vulnerable_unfixed" && rep1?.verdict?.exitCode === 1,
    `outcome=${rep1?.verdict?.outcome}`
  );
  const findings1 = rep1?.summary?.findings ?? [];
  const bizFindings = findings1.filter((f) => f.kind === "bizlogic-suspect");
  check(
    "静态发现含发货与退款两个端点",
    ["/api/orders/:id/ship", "/api/orders/:id/refund"].every((p) =>
      bizFindings.some((f) => f.method === "POST" && f.path === p)
    ),
    `findings=${findings1.map((f) => `${f.kind} ${f.method} ${f.path}`).join("、")}`
  );
  check(
    "发现原因区分状态跳步与并发/幂等",
    bizFindings.some((f) => String(f.reason ?? "").includes("前置状态")) &&
      bizFindings.some((f) => String(f.reason ?? "").includes("并发") || String(f.reason ?? "").includes("幂等")),
    `reasons=${bizFindings.map((f) => f.reason).join(" | ")}`
  );

  const pre1 = rep1?.evidence?.pre ?? [];
  const stateEv = pre1.find((e) => e.caseId === "attack-state-skip");
  const raceEv = pre1.find((e) => e.caseId === "attack-race-2");
  check(
    "pre 证据：pending 订单被直接发货（attack-state-skip → vulnerable）",
    stateEv?.verdict === "vulnerable",
    `verdict=${stateEv?.verdict} actual=${String(stateEv?.actual ?? "").slice(0, 100)}`
  );
  check(
    "pre 证据：并发退款被重复执行（attack-race-2 → vulnerable）",
    raceEv?.verdict === "vulnerable",
    `verdict=${raceEv?.verdict} actual=${String(raceEv?.actual ?? "").slice(0, 110)}`
  );
  check(
    "两类证据均为内容级交叉证明（cross-proven）",
    stateEv?.evidenceGrade === "cross-proven" && raceEv?.evidenceGrade === "cross-proven",
    `grades=${stateEv?.evidenceGrade}/${raceEv?.evidenceGrade}`
  );
  check(
    "状态证据写明前置状态与实际流转",
    /pending/.test(String(stateEv?.actual ?? "")) &&
      /shipped/.test(String(stateEv?.actual ?? "")) &&
      /前置状态校验缺失/.test(String(stateEv?.actual ?? "")),
    `actual=${String(stateEv?.actual ?? "").slice(0, 140)}`
  );
  check(
    "并发证据写明成功次数与不同副作用标识",
    /不同副作用标识/.test(String(raceEv?.actual ?? "")) && /rf_/.test(String(raceEv?.actual ?? "")),
    `actual=${String(raceEv?.actual ?? "").slice(0, 160)}`
  );
  check("状态交叉证明指向状态机", String(stateEv?.crossProof ?? "").includes("状态机"), `crossProof=${String(stateEv?.crossProof ?? "").slice(0, 120)}`);
  check("并发交叉证明指向重复执行", String(raceEv?.crossProof ?? "").includes("重复执行"), `crossProof=${String(raceEv?.crossProof ?? "").slice(0, 120)}`);
  check("影响面写明资金/履约损失", /资金|履约|退款/.test(String(raceEv?.impact ?? "")) && /跳过/.test(String(stateEv?.impact ?? "")), `impact=${String(raceEv?.impact ?? "").slice(0, 90)}`);
  check("未生成补丁（业务逻辑类无自动修复模板）", (rep1?.patch ?? null) === null, `patch=${rep1?.patch ? "有" : "无"}`);
  check("错误指引要求人工修复", String(g1.error?.hint ?? "").includes("人工修复"), "");
  check("拒绝语义未误报：错误码非 failed（exit 2）", g1.error?.code !== "failed" && r1.code !== 2, `code=${r1.code} err=${g1.error?.code}`);
  check(
    "漏洞结论只来自业务逻辑用例（无其它越权/注入误报）",
    pre1.filter((e) => e.verdict === "vulnerable").every((e) => String(e.caseId).startsWith("attack-state-skip") || String(e.caseId).startsWith("attack-race")),
    `vulnerable=${pre1.filter((e) => e.verdict === "vulnerable").map((e) => e.caseId).join("、")}`
  );
  const briefs1 = rep1?.summary?.fixBriefs ?? [];
  const bizBrief = briefs1.find((b) => b.family === "bizlogic");
  check("修复简报归入 bizlogic 家族", !!bizBrief, `families=${briefs1.map((b) => b.family).join("、")}`);
  check(
    "修复方向包含状态机与幂等/锁",
    /状态机/.test(String(bizBrief?.fix ?? "")) && /幂等/.test(String(bizBrief?.fix ?? "")) && /锁|唯一/.test(String(bizBrief?.fix ?? "")),
    `fix=${String(bizBrief?.fix ?? "").slice(0, 100)}`
  );

  // 证据入库抽查
  const db = new DatabaseSync(path.join(dataDir, "guardbuild.db"), { readOnly: true });
  const sid1 = g1.sessionId;
  const preVuln = db.prepare("SELECT COUNT(*) n FROM evidence WHERE session_id = ? AND phase='pre' AND verdict='vulnerable'").get(sid1).n;
  const bizRows = db.prepare(
    "SELECT COUNT(*) n FROM evidence WHERE session_id = ? AND phase='pre' AND (endpoint LIKE '%/ship' OR endpoint LIKE '%/refund') AND cross_proof IS NOT NULL"
  ).get(sid1).n;
  const patch1 = db.prepare("SELECT COUNT(*) n FROM patches WHERE session_id = ?").get(sid1).n;
  db.close();
  check("DB：pre 漏洞证据入库（≥2 条）", preVuln >= 2, `pre vulnerable=${preVuln}`);
  check("DB：两条业务逻辑证据带交叉证明落库", bizRows >= 2, `rows=${bizRows}`);
  check("DB：未写入补丁记录", patch1 === 0, `patches=${patch1}`);

  // ---------- ② 已修复 → exit 0 ----------
  console.log("\n[BIZ] 2/2 已修复（前置状态校验 + 同步置位）：期望 exit 0（not_reproducible）…");
  const ws2 = makeWorkspace("b2-hardened", enableHardened);
  const r2 = await runGate(ws2, "b2-hardened");
  const g2 = r2.gate ?? {};
  check("退出码 = 0（无漏洞证据）", r2.code === 0, `code=${r2.code}${r2.code !== 0 ? ` stderr=${r2.stderr.slice(-400)}` : ""}`);
  check("verdict=not_reproducible", g2.verdict === "not_reproducible", `verdict=${g2.verdict} error=${g2.error?.code}`);
  const rep2 = readReport("b2-hardened");
  check(
    "报告结论一致（not_reproducible/exit 0）",
    rep2?.verdict?.outcome === "not_reproducible" && rep2?.verdict?.exitCode === 0,
    `outcome=${rep2?.verdict?.outcome}`
  );
  check(
    "修复后静态候选仍存在（裁决来自动态复现而非静态缺失）",
    (rep2?.summary?.findings ?? []).filter((f) => f.kind === "bizlogic-suspect").length >= 2,
    `findings=${(rep2?.summary?.findings ?? []).map((f) => f.kind).join("、")}`
  );
  const pre2 = rep2?.evidence?.pre ?? [];
  const blockedState = pre2.find((e) => e.caseId === "attack-state-skip");
  const blockedRace = pre2.find((e) => e.caseId === "attack-race-2");
  check(
    "pre 证据：加固后状态跳步被 409 拒绝",
    blockedState?.verdict === "blocked" && /409/.test(String(blockedState?.actual ?? "")),
    `verdict=${blockedState?.verdict} actual=${String(blockedState?.actual ?? "").slice(0, 110)}`
  );
  check(
    "pre 证据：加固后并发退款只剩 1 次成功",
    blockedRace?.verdict === "blocked",
    `verdict=${blockedRace?.verdict} actual=${String(blockedRace?.actual ?? "").slice(0, 130)}`
  );
  check(
    "正向业务断言仍通过（本人列表可见）",
    pre2.some((e) => e.caseId === "business-list-own" && e.verdict === "passed"),
    `business=${pre2.filter((e) => e.caseId?.startsWith("business-")).map((e) => `${e.caseId}:${e.verdict}`).join("、")}`
  );

  const passed = checks.filter((c) => c.pass).length;
  console.log(`\n[BIZ] 断言: ${passed}/${checks.length} 通过`);
  const failed = checks.filter((c) => !c.pass);
  if (failed.length > 0) {
    console.error(`[BIZ] 未通过: ${failed.map((c) => c.name).join("、")}`);
    process.exit(1);
  }
  console.log("[BIZ] 全部通过 ✅");
}

main().catch((e) => {
  console.error(`\n[BIZ] 失败: ${e.message}`);
  const passed = checks.filter((c) => c.pass).length;
  console.log(`[BIZ] 断言: ${passed}/${checks.length} 通过`);
  process.exit(1);
});
