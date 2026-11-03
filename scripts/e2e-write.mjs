#!/usr/bin/env node
/**
 * 白盒写面越权端到端演练：以 fixtures/write-shop（读取有归属校验、PATCH/DELETE 没有）
 * 驱动 guardbuild-headless --gate，验证「开关决定打不打、判据不松口」这条线：
 *
 *   ① 默认（mutation 开关全关）→ exit 0：一条写请求都没发；静态候选仍在，
 *      报告摘要点名「有候选但被写面开关关掉：PATCH / DELETE」——不静默消失，也不算「该测没测」。
 *   ② GUARDBUILD_MUTATE=1 → exit 1：跨用户改写复现，证据是归属人复读见到 note=misc_gbw
 *      且原值已恢复；DELETE 仍锁着并被点名。
 *   ③ 再加 GUARDBUILD_DELETE=1 → exit 1：跨用户删除复现，证据是归属人复读 #10 返回 404（不可回滚）。
 *   ④ 加固版（GB_WRITE_HARDENED=1，运行期按归属拒绝，两个开关都开）→ exit 0：
 *      写面用例全 blocked，静态候选照旧存在（裁决来自动态复现，不是来自动态没打）。
 *
 * 用法: node scripts/e2e-write.mjs
 */
import { spawn, spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const demoDir = path.join(repoRoot, ".demo-write");
const dataDir = path.join(demoDir, "data");
const fixture = path.join(repoRoot, "fixtures", "write-shop");

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
  git(["-c", "core.longpaths=true", "add", "-A"], ws);
  git(["-c", "core.longpaths=true", "commit", "-qm", `${name} 基线`], ws);
  return ws;
}

/** 加固档：运行期补上归属校验（校验藏在 helper 里，静态层看不出来，候选照旧保留） */
function enableHardened(ws) {
  const p = path.join(ws, "guardbuild.json");
  const cfg = JSON.parse(readFileSync(p, "utf8"));
  cfg.start.env = { ...(cfg.start.env ?? {}), GB_WRITE_HARDENED: "1" };
  writeFileSync(p, `${JSON.stringify(cfg, null, 2)}\n`);
}

function runGate(project, label, extraEnv = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(exe, ["--gate", "--project", project, "--report", path.join(demoDir, "reports", label)], {
      cwd: repoRoot,
      env: {
        ...process.env,
        GUARDBUILD_DATA_DIR: dataDir,
        GUARDBUILD_SIDECAR: path.join(repoRoot, "sidecar", "main.mjs"),
        ...extraEnv,
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (b) => { stdout += b.toString(); });
    child.stderr.on("data", (b) => { stderr += b.toString(); });
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`[write:${label}] 超时 240000ms`));
    }, 240_000);
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

function readReport(round, file = "report.json") {
  const p = path.join(demoDir, "reports", round, file);
  if (!existsSync(p)) return null;
  try {
    return file.endsWith(".json") ? JSON.parse(readFileSync(p, "utf8")) : readFileSync(p, "utf8");
  } catch {
    return null;
  }
}

const writeCases = (rep) => (rep?.evidence?.pre ?? []).filter((e) => String(e.caseId ?? "").startsWith("attack-write"));

async function main() {
  console.log("[WRITE] 0/4 准备演示目录…");
  rmSync(demoDir, { recursive: true, force: true });
  mkdirSync(dataDir, { recursive: true });
  if (!existsSync(exe)) throw new Error(`未找到无头宿主: ${exe}（先 npm run host:headless）`);

  // ---------- ① 默认：写面开关全关 ----------
  console.log("\n[WRITE] 1/4 默认（mutation 全关）：一条写请求都不发，但候选必须点名…");
  const ws1 = makeWorkspace("w1-default");
  const r1 = await runGate(ws1, "w1-default");
  const g1 = r1.gate ?? {};
  check("退出码 = 0（读取族已打且未复现，不因写面候选判「测不了」）", r1.code === 0, `code=${r1.code} error=${g1.error?.code}`);
  const rep1 = readReport("w1-default");
  const md1 = readReport("w1-default", "report.md") ?? "";
  check("静态候选含 PATCH 与 DELETE /api/orders/:id", ["PATCH", "DELETE"].every((m) => (rep1?.summary?.findings ?? []).some((f) => f.method === m && f.path === "/api/orders/:id")),
    `findings=${(rep1?.summary?.findings ?? []).map((f) => `${f.method} ${f.path}`).join("、")}`);
  check("本轮没有发出任何写面用例", writeCases(rep1).length === 0, `write=${writeCases(rep1).map((e) => e.caseId).join("、")}`);
  check("攻击面归族只含已打的读取族", (rep1?.summary?.attackSurface?.probed ?? []).includes("跨用户读取（IDOR）"),
    `probed=${(rep1?.summary?.attackSurface?.probed ?? []).join("、")}`);
  check("报告点名「有候选但被写面开关关掉」两条", /被写面开关关掉[^\n]*PATCH[^\n]*DELETE/.test(md1), "");
  check("报告同时给开法（mutation.allowWrite / allowDelete）", md1.includes("mutation.allowWrite") && md1.includes("mutation.allowDelete"), "");
  check("开关关掉的两条不被算成「无候选」", (rep1?.summary?.attackSurface?.noCandidate ?? []).every((x) => !x.includes("写面")),
    `noCandidate=${(rep1?.summary?.attackSurface?.noCandidate ?? []).join("、")}`);

  // ---------- ② 只开改写 ----------
  console.log("\n[WRITE] 2/4 GUARDBUILD_MUTATE=1：跨用户改写复现，删除仍锁着…");
  const ws2 = makeWorkspace("w2-mutate");
  const r2 = await runGate(ws2, "w2-mutate", { GUARDBUILD_MUTATE: "1" });
  check("退出码 = 1（写面证据成立）", r2.code === 1, `code=${r2.code} verdict=${r2.gate?.verdict}`);
  const rep2 = readReport("w2-mutate");
  const ev2 = writeCases(rep2);
  check("改写用例复现（vulnerable）", ev2.some((e) => e.caseId === "attack-write-foreign" && e.verdict === "vulnerable"),
    `write=${ev2.map((e) => `${e.caseId}:${e.verdict}`).join("、")}`);
  check("证据是归属人复读见到 canary，且原值已恢复",
    ev2.some((e) => e.caseId === "attack-write-foreign" && /misc_gbw/.test(String(e.actual)) && /原值已恢复/.test(String(e.actual))),
    `actual=${String(ev2.find((e) => e.caseId === "attack-write-foreign")?.actual ?? "").slice(0, 120)}`);
  check("删除仍未执行并被点名（不可回滚，需另开 allowDelete）",
    (rep2?.summary?.attackSurface?.gateSkippedWrite ?? []).some((x) => x.includes("DELETE")) &&
      !ev2.some((e) => /删除/.test(String(e.name ?? ""))),
    `gated=${(rep2?.summary?.attackSurface?.gateSkippedWrite ?? []).join("、")}`);
  check("写面族进入「本轮攻击面」", (rep2?.summary?.attackSurface?.probed ?? []).includes("跨用户改写 / 删除（写面越权）"), "");

  // ---------- ③ 改写 + 删除 ----------
  console.log("\n[WRITE] 3/4 再加 GUARDBUILD_DELETE=1：跨用户删除复现（复读 404）…");
  const ws3 = makeWorkspace("w3-both");
  const r3 = await runGate(ws3, "w3-both", { GUARDBUILD_MUTATE: "1", GUARDBUILD_DELETE: "1" });
  check("退出码 = 1", r3.code === 1, `code=${r3.code} verdict=${r3.gate?.verdict}`);
  const rep3 = readReport("w3-both");
  const ev3 = writeCases(rep3);
  check("改写 + 删除两条用例都跑出证据", ev3.length >= 2 && ev3.every((e) => e.verdict === "vulnerable"),
    `write=${ev3.map((e) => `${e.caseId}:${e.verdict}`).join("、")}`);
  check("删除证据是归属人复读真的读不到（404），不是状态码猜的",
    ev3.some((e) => /复读[^\n]*404/.test(String(e.actual)) && /销毁不可回滚/.test(String(e.actual))),
    `actual=${String(ev3.find((e) => /404/.test(String(e.actual ?? "")))?.actual ?? "").slice(0, 120)}`);
  check("开关全开时不再有被关掉的写面候选", (rep3?.summary?.attackSurface?.gateSkippedWrite ?? []).length === 0,
    `gated=${(rep3?.summary?.attackSurface?.gateSkippedWrite ?? []).join("、")}`);

  // ---------- ④ 加固版 ----------
  console.log("\n[WRITE] 4/4 加固版（运行期按归属拒绝）+ 两个开关都开：写面全 blocked…");
  const ws4 = makeWorkspace("w4-hardened", enableHardened);
  const r4 = await runGate(ws4, "w4-hardened", { GUARDBUILD_MUTATE: "1", GUARDBUILD_DELETE: "1" });
  check("退出码 = 0（未复现）", r4.code === 0, `code=${r4.code} verdict=${r4.gate?.verdict} error=${r4.gate?.error?.code}`);
  const rep4 = readReport("w4-hardened");
  const ev4 = writeCases(rep4);
  check("写面用例照旧发出（开关开着），但全部 blocked", ev4.length >= 2 && ev4.every((e) => e.verdict === "blocked"),
    `write=${ev4.map((e) => `${e.caseId}:${e.verdict}`).join("、")}`);
  check("加固版静态候选仍存在（裁决来自动态复现）", (rep4?.summary?.findings ?? []).some((f) => f.method === "DELETE"), "");
  check("加固版没有 vulnerable 结论", (rep4?.evidence?.pre ?? []).every((e) => e.verdict !== "vulnerable"), "");

  const passed = checks.filter((c) => c.pass).length;
  console.log(`\n[WRITE] 断言: ${passed}/${checks.length} 通过`);
  const failed = checks.filter((c) => !c.pass);
  if (failed.length > 0) {
    console.error(`[WRITE] 未通过: ${failed.map((c) => c.name).join("、")}`);
    process.exit(1);
  }
  console.log("[WRITE] 全部通过 ✅");
}

main().catch((e) => {
  console.error(`\n[WRITE] 失败: ${e.message}`);
  const passed = checks.filter((c) => c.pass).length;
  console.log(`[WRITE] 断言: ${passed}/${checks.length} 通过`);
  process.exit(1);
});
