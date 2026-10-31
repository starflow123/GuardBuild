#!/usr/bin/env node
/**
 * SSR / HTML 页面越权端到端演练：以 fixtures/ssr-shop（全站只有页面的笔记本）驱动
 * guardbuild-headless --gate，验证 #178 补齐的「页面链接发现 + 正文归属取证」在真实链路上成立。
 *
 *   ① 未修复        → exit 1：没有 JSON 列表接口也能从登录后的页面链接里发现对象，
 *                     越权证据是「受害人本人页面独有的正文片段全部出现在攻击响应里」（cross-proven）
 *   ② 运行期加固    → exit 0（not_reproducible）：归属校验写在 src/access.js 里，
 *                     静态候选仍在（路由块内看不见那次比较），结论由实测给出；本人页面照常可读
 *   ③ 源码内联加固  → exit 0（no_candidates）：把 note.userId !== auth.id 写进路由块后，
 *                     静态即识别为「已加归属校验」，该端点不再作为越权候选
 *
 * 用法: node scripts/e2e-ssr.mjs
 */
import { spawn, spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const demoDir = path.join(repoRoot, ".demo-ssr");
const dataDir = path.join(demoDir, "data");
const fixture = path.join(repoRoot, "fixtures", "ssr-shop");

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
  const r = spawnSync("git", ["-c", "core.longpaths=true", ...args], { cwd, encoding: "utf8" });
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

/** ② 运行期加固：源码一字不动，只改启动环境变量 */
function enableHardened(ws) {
  const p = path.join(ws, "guardbuild.json");
  const cfg = JSON.parse(readFileSync(p, "utf8"));
  cfg.start.env = { ...(cfg.start.env ?? {}), GB_SSR_HARDENED: "1" };
  writeFileSync(p, `${JSON.stringify(cfg, null, 2)}\n`);
}

/** ③ 源码内联加固：把归属校验写进路由块（静态可见的典型修法） */
function inlineOwnerCheck(ws) {
  const p = path.join(ws, "src", "app.js");
  const src = readFileSync(p, "utf8");
  const anchor = "if (HARDENED && !canReadNote(auth, note))";
  if (!src.includes(anchor)) throw new Error(`靶场源码锚点缺失，无法构造「已修复」形态：${anchor}`);
  writeFileSync(p, src.replace(anchor, "if (note.userId !== auth.id)"));
}

function runGate(project, label, timeoutMs = 180_000) {
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
      reject(new Error(`[ssr:${label}] 超时 ${timeoutMs}ms`));
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

function readMarkdown(round) {
  const p = path.join(demoDir, "reports", round, "report.md");
  return existsSync(p) ? readFileSync(p, "utf8") : "";
}

const idorFindings = (rep) =>
  (rep?.summary?.findings ?? []).filter((f) => f.method === "GET" && String(f.path ?? "").startsWith("/notes/"));

async function main() {
  console.log("[SSR] 0/3 准备演示目录…");
  rmSync(demoDir, { recursive: true, force: true });
  mkdirSync(dataDir, { recursive: true });
  if (!existsSync(exe)) throw new Error(`未找到无头宿主: ${exe}（先 cargo build --no-default-features --bin guardbuild-headless）`);

  // ---------- ① 未修复：页面越权要复现 ----------
  console.log("\n[SSR] 1/3 未修复（全站只有 HTML 页面，无 JSON 列表接口）：期望 exit 1…");
  const ws1 = makeWorkspace("s1-vuln");
  const r1 = await runGate(ws1, "s1-vuln");
  const g1 = r1.gate ?? {};
  const rep1 = readReport("s1-vuln");
  check("退出码 = 1（漏洞证据成立）", r1.code === 1, `code=${r1.code}${r1.code !== 1 ? ` stderr=${r1.stderr.slice(-400)}` : ""}`);
  check("verdict=vulnerable_unfixed（不是「没测到」也不是「跑挂了」）", g1.verdict === "vulnerable_unfixed", `verdict=${g1.verdict} state=${g1.state} error=${g1.error?.code}`);
  check("报告结论一致（vulnerable_unfixed/exit 1）", rep1?.verdict?.outcome === "vulnerable_unfixed" && rep1?.verdict?.exitCode === 1, `outcome=${rep1?.verdict?.outcome}`);
  check("静态候选含 GET /notes/:id", idorFindings(rep1).length >= 1, `findings=${(rep1?.summary?.findings ?? []).map((f) => `${f.kind} ${f.method} ${f.path}`).join("、") || "无"}`);
  check(
    "资源发现走页面链接回退（不是 no_list_endpoint）",
    /HTML 页面回退/.test(r1.stdout) && !/no_list_endpoint/.test(`${r1.stdout}${r1.stderr}`),
    (r1.stdout.match(/资源发现[^\n]*/g) ?? []).slice(0, 2).join(" | ") || `stderr=${r1.stderr.slice(-200)}`
  );
  const pre1 = rep1?.evidence?.pre ?? [];
  const leak = pre1.find((e) => e.caseId === "attack-read-foreign");
  check("pre 证据：跨用户读页面复现（attack-read-foreign → vulnerable）", leak?.verdict === "vulnerable", `verdict=${leak?.verdict} actual=${String(leak?.actual ?? "").slice(0, 120)}`);
  check("攻击请求打在页面路由上（GET /notes/201）", String(leak?.method) === "GET" && String(leak?.endpoint) === "/notes/201", `endpoint=${leak?.method} ${leak?.endpoint}`);
  check(
    "证据是本人页面独有正文片段（B-2087 / 韩雪 / 耳机退货 一族）",
    /独有/.test(String(leak?.actual ?? "")) && /B-2087|韩雪|YT8837462211/.test(String(leak?.actual ?? "")),
    `actual=${String(leak?.actual ?? "").slice(0, 180)}`
  );
  check("响应正文不是 JSON 字段比对，而是页面正文取证", /页面|正文/.test(String(leak?.actual ?? "")) && /可读取他人.*页面正文/.test(String(leak?.impact ?? "")), `impact=${String(leak?.impact ?? "").slice(0, 90)}`);
  check("证据分级为内容归属交叉证明（cross-proven）", leak?.evidenceGrade === "cross-proven", `grade=${leak?.evidenceGrade}`);
  check("交叉证明写明对照来源（本人会话下的页面）", /本人会话|自己会话/.test(String(leak?.crossProof ?? "")), `crossProof=${String(leak?.crossProof ?? "").slice(0, 140)}`);
  const own1 = pre1.find((e) => String(e.caseId ?? "").startsWith("business-read-own"));
  check("正向断言：本人页面照常可读（内容契约未被删减）", own1?.verdict === "passed", `case=${own1?.caseId} verdict=${own1?.verdict} actual=${String(own1?.actual ?? "").slice(0, 110)}`);
  const anon1 = pre1.find((e) => e.caseId === "business-unauth-401");
  check(
    "匿名请求跳回登录页算「拒绝」，不算认证被绕过（页面应用的正常拒绝形态）",
    anon1?.verdict === "passed" && /登录页|401|403/.test(String(anon1?.actual ?? "")),
    `verdict=${anon1?.verdict} actual=${String(anon1?.actual ?? "").slice(0, 110)}`
  );
  check(
    "受害人侧正向断言同样按正文片段成立（不是「缺对照」）",
    (pre1.find((e) => e.caseId === "business-read-own-victim") ?? {})?.verdict === "passed",
    `verdict=${pre1.find((e) => e.caseId === "business-read-own-victim")?.verdict} actual=${String(
      pre1.find((e) => e.caseId === "business-read-own-victim")?.actual ?? ""
    ).slice(0, 110)}`
  );
  check("报告未把「只验登录」写成静态误报形态", !/静态误报/.test(String(leak?.actual ?? "")), `actual=${String(leak?.actual ?? "").slice(0, 80)}`);
  const md1 = readMarkdown("s1-vuln");
  check("报告正文写明了越权读到的具体内容", /B-2087|韩雪|耳机退货/.test(md1), "");

  const db = new DatabaseSync(path.join(dataDir, "guardbuild.db"), { readOnly: true });
  const rows = db
    .prepare("SELECT verdict, evidence_grade, cross_proof, endpoint FROM evidence WHERE session_id = ? AND phase='pre'")
    .all(g1.sessionId);
  db.close();
  check(
    "DB：页面越权证据带交叉证明落库",
    rows.some((x) => x.verdict === "vulnerable" && x.cross_proof && /\/notes\/201/.test(String(x.endpoint))),
    `rows=${rows.map((x) => `${x.endpoint}:${x.verdict}/${x.evidence_grade}`).join("、")}`
  );

  // ---------- ② 运行期加固：helper 里的归属校验 ----------
  console.log("\n[SSR] 2/3 运行期加固（归属校验在 src/access.js，静态块内不可见）：期望 exit 0…");
  const ws2 = makeWorkspace("s2-hardened", enableHardened);
  const r2 = await runGate(ws2, "s2-hardened");
  const g2 = r2.gate ?? {};
  const rep2 = readReport("s2-hardened");
  check("退出码 = 0（已测用例未复现）", r2.code === 0, `code=${r2.code}${r2.code !== 0 ? ` stderr=${r2.stderr.slice(-400)}` : ""}`);
  check("verdict=not_reproducible（结论来自实测，不是静态漏判）", g2.verdict === "not_reproducible", `verdict=${g2.verdict} error=${g2.error?.code}`);
  check("静态候选仍在（跨文件的归属校验静态看不见）", idorFindings(rep2).length >= 1, `findings=${(rep2?.summary?.findings ?? []).map((f) => f.path).join("、") || "无"}`);
  const pre2 = rep2?.evidence?.pre ?? [];
  const blocked = pre2.find((e) => e.caseId === "attack-read-foreign");
  check("pre 证据：跨用户读页面被 403 挡住", blocked?.verdict === "blocked" && /403/.test(String(blocked?.actual ?? "")), `verdict=${blocked?.verdict} actual=${String(blocked?.actual ?? "").slice(0, 120)}`);
  const own2 = pre2.find((e) => String(e.caseId ?? "").startsWith("business-read-own"));
  check("正向断言：加固后本人页面仍可读（没有靠删内容冒充修复）", own2?.verdict === "passed", `case=${own2?.caseId} verdict=${own2?.verdict} actual=${String(own2?.actual ?? "").slice(0, 110)}`);
  check(
    "本轮没有把页面应用的正常拒绝写成假回归（无 regressed 断言）",
    pre2.every((e) => e.verdict !== "regressed"),
    `regressed=${pre2.filter((e) => e.verdict === "regressed").map((e) => `${e.caseId}(${e.endpoint})`).join("、") || "无"}`
  );
  check("报告标题写明「不等于安全」", /不等于安全/.test(String(rep2?.verdict?.headline ?? "")), `headline=${String(rep2?.verdict?.headline ?? "").slice(0, 90)}`);
  check("发现阶段仍走页面链接（未退化为「没有列表接口」）", /HTML 页面回退/.test(r2.stdout) && !/no_list_endpoint/.test(`${r2.stdout}${r2.stderr}`), "");

  // ---------- ③ 源码内联加固：静态即可识别 ----------
  console.log("\n[SSR] 3/3 源码内联归属校验：期望 exit 0（no_candidates，静态识别为已修复）…");
  const ws3 = makeWorkspace("s3-inline", inlineOwnerCheck);
  const r3 = await runGate(ws3, "s3-inline");
  const g3 = r3.gate ?? {};
  const rep3 = readReport("s3-inline");
  check("退出码 = 0（无越权候选）", r3.code === 0, `code=${r3.code}${r3.code !== 0 ? ` stderr=${r3.stderr.slice(-400)}` : ""}`);
  check("verdict=no_candidates", g3.verdict === "no_candidates", `verdict=${g3.verdict} error=${g3.error?.code}`);
  check("路由块内可见归属校验后，/notes/:id 不再作为越权候选", idorFindings(rep3).length === 0, `findings=${(rep3?.summary?.findings ?? []).map((f) => `${f.kind} ${f.path}`).join("、") || "无"}`);

  const passed = checks.filter((c) => c.pass).length;
  console.log(`\n[SSR] 断言: ${passed}/${checks.length} 通过`);
  const failed = checks.filter((c) => !c.pass);
  if (failed.length > 0) {
    console.error(`[SSR] 未通过: ${failed.map((c) => c.name).join("、")}`);
    process.exit(1);
  }
  console.log("[SSR] 全部通过 ✅");
}

main().catch((e) => {
  console.error(`\n[SSR] 失败: ${e.message}`);
  const passed = checks.filter((c) => c.pass).length;
  console.log(`[SSR] 断言: ${passed}/${checks.length} 通过`);
  process.exit(1);
});
