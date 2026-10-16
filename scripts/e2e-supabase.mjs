#!/usr/bin/env node
/**
 * Supabase / PostgREST 适配器端到端演练：以本机回环 HTTP mock PostgREST 驱动
 * guardbuild-headless --gate，验证三类结局（全部无需本地启动目标服务）：
 *
 *   ① RLS 缺失（匿名可读）  → exit 1（verdict=vulnerable_unfixed，error=no_patchable_candidates）
 *      匿名 anon key 直连 /rest/v1/<表> 命中真实数据行 → 取证成立，属数据库策略问题不自动修复。
 *   ② RLS 正常（匿名空集）  → exit 0（verdict=not_reproducible）
 *      各表匿名均返回空数组 → 未建立漏洞基线。
 *   ③ service_role 客户端暴露 → exit 1（verdict=vulnerable_unfixed，error=no_patchable_candidates）
 *      .env 中出现 NEXT_PUBLIC_ 前缀的 service_role 密钥 → 静态即判严重泄露，即便 RLS 正常也须阻断。
 *
 * 安全约束校验：anon key / service_role 的真实值绝不进入报告、事件流与证据（仅掩码/来源）。
 *
 * 用法: node scripts/e2e-supabase.mjs
 */
import { spawn, spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const demoDir = path.join(repoRoot, ".demo-supabase");
const dataDir = path.join(demoDir, "data");
const fixture = path.join(repoRoot, "fixtures", "supa-shop");

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

/** 生成一个可被 jwtRole 识别角色的 JWT（header.payload.sig，base64url） */
function mkJwt(payloadObj, sig = "MOCKSIGNATUREVALUE") {
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
  return `${b64({ alg: "HS256", typ: "JWT" })}.${b64(payloadObj)}.${sig}`;
}
const ANON_JWT = mkJwt({ role: "anon", iss: "supabase" });
const SERVICE_JWT = mkJwt({ role: "service_role", iss: "supabase" });

/**
 * 启动本机回环 mock PostgREST。
 * @param {boolean} leak true=每表返回含 email 的真实行（RLS 缺失）；false=返回空数组（RLS 生效）
 */
function startMock({ leak }) {
  return new Promise((resolve) => {
    const server = createServer((req, res) => {
      const u = new URL(req.url, "http://127.0.0.1");
      const m = u.pathname.match(/^\/rest\/v1\/([A-Za-z0-9_]+)$/);
      res.setHeader("Content-Type", "application/json");
      if (!m) {
        res.statusCode = 404;
        res.end(JSON.stringify({ message: `relation not exposed` }));
        return;
      }
      if (leak) {
        res.statusCode = 200;
        res.end(
          JSON.stringify([
            { id: 1, email: "alice@example.com", full_name: "Alice", phone: "13800000001" },
            { id: 2, email: "bob@example.com", full_name: "Bob", phone: "13800000002" },
          ])
        );
      } else {
        res.statusCode = 200;
        res.end(JSON.stringify([]));
      }
    });
    server.listen(0, "127.0.0.1", () => resolve({ server, port: server.address().port }));
  });
}

function makeWorkspace(name) {
  const ws = path.join(demoDir, name);
  rmSync(ws, { recursive: true, force: true });
  cpSync(fixture, ws, { recursive: true });
  git(["init", "-q"], ws);
  git(["config", "user.email", "gate@guardbuild.local"], ws);
  git(["config", "user.name", "GuardBuild Gate"], ws);
  git(["add", "-A"], ws);
  git(["commit", "-qm", `${name} 基线`], ws);
  return ws;
}

function writeEnv(ws, { port, serviceRoleLeak }) {
  let env =
    `NEXT_PUBLIC_SUPABASE_URL=http://127.0.0.1:${port}\n` +
    `NEXT_PUBLIC_SUPABASE_ANON_KEY=${ANON_JWT}\n`;
  if (serviceRoleLeak) env += `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=${SERVICE_JWT}\n`;
  writeFileSync(path.join(ws, ".env"), env); // 工作树内文件，不提交（fs.read 读磁盘实际内容）
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
      reject(new Error(`[supabase:${label}] 超时 ${timeoutMs}ms`));
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

async function scenario({ label, leak, serviceRoleLeak }) {
  const { server, port } = await startMock({ leak });
  try {
    const ws = makeWorkspace(label);
    writeEnv(ws, { port, serviceRoleLeak });
    return await runGate(ws, label);
  } finally {
    await new Promise((r) => server.close(r));
  }
}

async function main() {
  console.log("[SUPABASE] 0/3 准备演示目录…");
  rmSync(demoDir, { recursive: true, force: true });
  mkdirSync(dataDir, { recursive: true });
  if (!existsSync(exe)) throw new Error(`未找到无头宿主: ${exe}（先 cargo build --no-default-features --bin guardbuild-headless）`);

  // ---------- ① RLS 缺失 → exit 1 ----------
  console.log("\n[SUPABASE] 1/3 RLS 缺失（匿名可读）：期望 exit 1（vulnerable_unfixed）…");
  const r1 = await scenario({ label: "s1-leak", leak: true, serviceRoleLeak: false });
  const g1 = r1.gate ?? {};
  check("退出码 = 1（漏洞证据成立）", r1.code === 1, `code=${r1.code}`);
  check(
    "verdict=vulnerable_unfixed 且 error=no_patchable_candidates",
    g1.verdict === "vulnerable_unfixed" && g1.error?.code === "no_patchable_candidates",
    `verdict=${g1.verdict} code=${g1.error?.code} state=${g1.state}`
  );
  const rep1 = readReport("s1-leak");
  check("报告结论一致（vulnerable_unfixed/exit 1）", rep1?.verdict?.outcome === "vulnerable_unfixed" && rep1?.verdict?.exitCode === 1, `outcome=${rep1?.verdict?.outcome}`);
  check("报告标注 Supabase 泄露表数 ≥ 1", (rep1?.supabase?.leaks ?? 0) >= 1, `leaks=${rep1?.supabase?.leaks} tables=${(rep1?.supabase?.tables ?? []).length}`);
  const vuln1 = (rep1?.evidence?.pre ?? []).filter((e) => e.verdict === "vulnerable");
  check("pre 证据含匿名可读（identity 为 anon-key）", vuln1.length >= 1 && vuln1.every((e) => String(e.identity).includes("anon-key")), `vulnerable=${vuln1.length}`);
  check("敏感列命中升级为内容级证据（cross-proven）", vuln1.some((e) => e.evidenceGrade === "cross-proven"), `grades=${vuln1.map((e) => e.evidenceGrade).join(",")}`);
  check("静态发现含 Supabase 表条目（method=SUPABASE）", (rep1?.summary?.findings ?? []).some((f) => f.kind === "supabase-table"), `findings=${(rep1?.summary?.findings ?? []).length}`);
  check("未生成补丁（数据库策略不自动修复）", (rep1?.patch ?? null) === null, `patch=${rep1?.patch ? "有" : "无"}`);
  check("报告给出 RLS 加固指引", (rep1?.verdict?.headline ?? "").includes("Supabase"), `headline=${(rep1?.verdict?.headline ?? "").slice(0, 20)}…`);

  // 密钥不泄漏
  const leakBlob1 = [JSON.stringify(rep1 ?? {}), existsSync(path.join(demoDir, "reports", "s1-leak", "report.md")) ? readFileSync(path.join(demoDir, "reports", "s1-leak", "report.md"), "utf8") : "", r1.stdout, r1.stderr].join("\n");
  check("anon key 真实值不进入报告/事件/证据", !leakBlob1.includes(ANON_JWT), "");

  // ---------- ② RLS 正常 → exit 0 ----------
  console.log("\n[SUPABASE] 2/3 RLS 正常（匿名空集）：期望 exit 0（not_reproducible）…");
  const r2 = await scenario({ label: "s2-guarded", leak: false, serviceRoleLeak: false });
  const g2 = r2.gate ?? {};
  check("退出码 = 0（无漏洞证据）", r2.code === 0, `code=${r2.code}`);
  check("verdict=not_reproducible", g2.verdict === "not_reproducible", `verdict=${g2.verdict} error=${g2.error?.code}`);
  const rep2 = readReport("s2-guarded");
  check("报告结论一致（not_reproducible/exit 0）", rep2?.verdict?.outcome === "not_reproducible" && rep2?.verdict?.exitCode === 0, `outcome=${rep2?.verdict?.outcome}`);
  check("报告标注 Supabase 泄露表数 = 0", (rep2?.supabase?.leaks ?? -1) === 0, `leaks=${rep2?.supabase?.leaks}`);

  // ---------- ③ service_role 客户端暴露 → exit 1 ----------
  console.log("\n[SUPABASE] 3/3 service_role 客户端暴露：期望 exit 1（即便 RLS 正常也阻断）…");
  const r3 = await scenario({ label: "s3-svcrole", leak: false, serviceRoleLeak: true });
  const g3 = r3.gate ?? {};
  check("退出码 = 1（漏洞证据成立）", r3.code === 1, `code=${r3.code}`);
  check(
    "verdict=vulnerable_unfixed 且 error=no_patchable_candidates",
    g3.verdict === "vulnerable_unfixed" && g3.error?.code === "no_patchable_candidates",
    `verdict=${g3.verdict} code=${g3.error?.code}`
  );
  const rep3 = readReport("s3-svcrole");
  check("报告标注 service_role 暴露", !!rep3?.supabase?.serviceRoleLeak, `source=${rep3?.supabase?.serviceRoleLeak?.source}`);
  check("静态发现含 service_role 泄露条目", (rep3?.summary?.findings ?? []).some((f) => f.kind === "supabase-service-role-leak"), "");
  const leakBlob3 = [JSON.stringify(rep3 ?? {}), r3.stdout, r3.stderr].join("\n");
  check("service_role 真实值不进入报告/事件", !leakBlob3.includes(SERVICE_JWT), "");
  check("anon key 真实值不进入报告/事件", !leakBlob3.includes(ANON_JWT), "");

  // 证据入库抽查（s1）
  const db = new DatabaseSync(path.join(dataDir, "guardbuild.db"), { readOnly: true });
  const sid1 = g1.sessionId;
  const preVuln = db.prepare("SELECT COUNT(*) n FROM evidence WHERE session_id = ? AND phase='pre' AND verdict='vulnerable'").get(sid1).n;
  const patch1 = db.prepare("SELECT COUNT(*) n FROM patches WHERE session_id = ?").get(sid1).n;
  db.close();
  check("DB：pre 匿名泄露证据入库（≥ 2 表）", preVuln >= 2, `pre vulnerable=${preVuln}`);
  check("DB：未写入补丁记录", patch1 === 0, `patches=${patch1}`);

  const passed = checks.filter((c) => c.pass).length;
  console.log(`\n[SUPABASE] 断言: ${passed}/${checks.length} 通过`);
  const failed = checks.filter((c) => !c.pass);
  if (failed.length > 0) {
    console.error(`[SUPABASE] 未通过: ${failed.map((c) => c.name).join("、")}`);
    process.exit(1);
  }
  console.log("[SUPABASE] 全部通过 ✅");
}

main().catch((e) => {
  console.error(`\n[SUPABASE] 失败: ${e.message}`);
  const passed = checks.filter((c) => c.pass).length;
  console.log(`[SUPABASE] 断言: ${passed}/${checks.length} 通过`);
  process.exit(1);
});
