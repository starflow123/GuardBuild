#!/usr/bin/env node
/**
 * SSRF 端到端演练：以 fixtures/ssrf-shop（GET /api/preview?url= 直接 fetch 请求参数）
 * 驱动 guardbuild-headless --gate，验证两类结局：
 *
 *   ① 未修复 → exit 1（verdict=vulnerable_unfixed，error=no_patchable_candidates）
 *      引擎把 URL 参数换成指向本进程 canary 的地址；目标服务真的回连 → 内容级交叉证据成立。
 *      SSRF 无自动修复模板，按「证据成立但不可自动修复」阻断并给出人工修复指引。
 *   ② 已修复（GB_SSRF_HARDENED=1：解析 URL 后校验协议 + 主机白名单） → exit 0（not_reproducible）
 *      静态候选仍在，但 canary 不再收到回连 → 不建立漏洞基线。
 *
 * 说明：canary 只监听 127.0.0.1 的随机端口，只接受一次带随机令牌的路径。
 * Docker/远程目标无法回连宿主回环地址，此类目标会得到 inconclusive（不虚构证据）。
 *
 * 用法: node scripts/e2e-ssrf.mjs
 */
import { spawn } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const demoDir = path.join(repoRoot, ".demo-ssrf");
const dataDir = path.join(demoDir, "data");
const fixture = path.join(repoRoot, "fixtures", "ssrf-shop");

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

/** 复刻「已修复」形态：源码静态候选保持原样，运行时开启主机白名单 */
function enableHardened(ws) {
  const p = path.join(ws, "guardbuild.json");
  const cfg = JSON.parse(readFileSync(p, "utf8"));
  cfg.start.env = { ...(cfg.start.env ?? {}), GB_SSRF_HARDENED: "1" };
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
      reject(new Error(`[ssrf:${label}] 超时 ${timeoutMs}ms`));
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
  console.log("[SSRF] 0/2 准备演示目录…");
  rmSync(demoDir, { recursive: true, force: true });
  mkdirSync(dataDir, { recursive: true });
  if (!existsSync(exe)) throw new Error(`未找到无头宿主: ${exe}（先 cargo build --no-default-features --bin guardbuild-headless）`);

  // ---------- ① 未修复 → exit 1 ----------
  console.log("\n[SSRF] 1/2 未修复：URL 参数被服务端直接 fetch，canary 回连：期望 exit 1（vulnerable_unfixed）…");
  const ws1 = makeWorkspace("s1-vuln");
  const r1 = await runGate(ws1, "s1-vuln");
  const g1 = r1.gate ?? {};
  check("退出码 = 1（漏洞证据成立）", r1.code === 1, `code=${r1.code}${r1.code !== 1 ? ` stderr=${r1.stderr.slice(-400)}` : ""}`);
  check(
    "verdict=vulnerable_unfixed 且 error=no_patchable_candidates",
    g1.verdict === "vulnerable_unfixed" && g1.error?.code === "no_patchable_candidates",
    `verdict=${g1.verdict} code=${g1.error?.code} state=${g1.state}`
  );
  const rep1 = readReport("s1-vuln");
  check(
    "报告结论一致（vulnerable_unfixed/exit 1）",
    rep1?.verdict?.outcome === "vulnerable_unfixed" && rep1?.verdict?.exitCode === 1,
    `outcome=${rep1?.verdict?.outcome}`
  );
  const findings1 = rep1?.summary?.findings ?? [];
  const ssrfFinding = findings1.find((f) => f.kind === "ssrf-suspect" && f.method === "GET" && f.path === "/api/preview");
  check("静态发现含 GET /api/preview（SSRF 静态线索）", !!ssrfFinding, `findings=${findings1.map((f) => `${f.kind} ${f.method} ${f.path}`).join("、")}`);
  check("发现原因为 SSRF 文案", String(ssrfFinding?.reason ?? "").includes("SSRF"), `reason=${ssrfFinding?.reason}`);
  const pre1 = rep1?.evidence?.pre ?? [];
  const ev = pre1.find((e) => e.caseId === "attack-ssrf");
  check("pre 证据：SSRF 攻击被放行（attack-ssrf → vulnerable）", ev?.verdict === "vulnerable", `verdict=${ev?.verdict} actual=${String(ev?.actual ?? "").slice(0, 100)}`);
  check("SSRF 证据为内容级交叉证明（cross-proven）", ev?.evidenceGrade === "cross-proven", `grade=${ev?.evidenceGrade}`);
  check("证据记录了本机 canary 回连", String(ev?.actual ?? "").includes("canary"), `actual=${String(ev?.actual ?? "").slice(0, 120)}`);
  check("交叉证明写明服务端回连", String(ev?.crossProof ?? "").includes("回连"), `crossProof=${ev?.crossProof}`);
  check("影响面指向内网/边界绕过", String(ev?.impact ?? "").includes("内网"), `impact=${ev?.impact}`);
  check("未生成补丁（SSRF 无自动修复模板）", (rep1?.patch ?? null) === null, `patch=${rep1?.patch ? "有" : "无"}`);
  check("错误指引要求人工修复", String(g1.error?.hint ?? "").includes("人工修复"), "");
  check("拒绝语义未误报：错误码非 failed（exit 2）", g1.error?.code !== "failed" && r1.code !== 2, `code=${r1.code} err=${g1.error?.code}`);
  const briefs1 = rep1?.summary?.fixBriefs ?? [];
  const ssrfBrief = briefs1.find((b) => b.family === "ssrf");
  check("修复简报归入 SSRF 家族", !!ssrfBrief, `families=${briefs1.map((b) => b.family).join("、")}`);
  check("修复方向包含 URL 解析与主机白名单", /白名单|解析/.test(String(ssrfBrief?.fix ?? "")), `fix=${String(ssrfBrief?.fix ?? "").slice(0, 80)}`);

  // 证据入库抽查
  const db = new DatabaseSync(path.join(dataDir, "guardbuild.db"), { readOnly: true });
  const sid1 = g1.sessionId;
  const preVuln = db.prepare("SELECT COUNT(*) n FROM evidence WHERE session_id = ? AND phase='pre' AND verdict='vulnerable'").get(sid1).n;
  const ssrfRows = db.prepare("SELECT COUNT(*) n FROM evidence WHERE session_id = ? AND endpoint LIKE '/api/preview%' AND cross_proof IS NOT NULL").get(sid1).n;
  const patch1 = db.prepare("SELECT COUNT(*) n FROM patches WHERE session_id = ?").get(sid1).n;
  db.close();
  check("DB：pre 漏洞证据入库（≥1 条）", preVuln >= 1, `pre vulnerable=${preVuln}`);
  check("DB：SSRF 证据带交叉证明落库", ssrfRows >= 1, `rows=${ssrfRows}`);
  check("DB：未写入补丁记录", patch1 === 0, `patches=${patch1}`);

  // ---------- ② 已修复 → exit 0 ----------
  console.log("\n[SSRF] 2/2 已修复（协议 + 主机白名单）：期望 exit 0（not_reproducible）…");
  const ws2 = makeWorkspace("s2-hardened", enableHardened);
  const r2 = await runGate(ws2, "s2-hardened");
  const g2 = r2.gate ?? {};
  check("退出码 = 0（无漏洞证据）", r2.code === 0, `code=${r2.code}${r2.code !== 0 ? ` stderr=${r2.stderr.slice(-400)}` : ""}`);
  check("verdict=not_reproducible", g2.verdict === "not_reproducible", `verdict=${g2.verdict} error=${g2.error?.code}`);
  const rep2 = readReport("s2-hardened");
  check(
    "报告结论一致（not_reproducible/exit 0）",
    rep2?.verdict?.outcome === "not_reproducible" && rep2?.verdict?.exitCode === 0,
    `outcome=${rep2?.verdict?.outcome}`
  );
  check(
    "修复后静态候选仍存在（裁决来自动态复现而非静态缺失）",
    (rep2?.summary?.findings ?? []).some((f) => f.kind === "ssrf-suspect"),
    `findings=${(rep2?.summary?.findings ?? []).map((f) => f.kind).join("、")}`
  );
  const blockedEv = (rep2?.evidence?.pre ?? []).find((e) => e.caseId === "attack-ssrf");
  check("pre 证据：硬化后 URL 被拦截（blocked）", blockedEv?.verdict === "blocked", `verdict=${blockedEv?.verdict} actual=${String(blockedEv?.actual ?? "").slice(0, 100)}`);

  const passed = checks.filter((c) => c.pass).length;
  console.log(`\n[SSRF] 断言: ${passed}/${checks.length} 通过`);
  const failed = checks.filter((c) => !c.pass);
  if (failed.length > 0) {
    console.error(`[SSRF] 未通过: ${failed.map((c) => c.name).join("、")}`);
    process.exit(1);
  }
  console.log("[SSRF] 全部通过 ✅");
}

main().catch((e) => {
  console.error(`\n[SSRF] 失败: ${e.message}`);
  const passed = checks.filter((c) => c.pass).length;
  console.log(`[SSRF] 断言: ${passed}/${checks.length} 通过`);
  process.exit(1);
});
