#!/usr/bin/env node
/**
 * 契约扩展端到端演练：fixtures/contract-shop 的路由在运行期分发表里拼装，
 * 静态适配器识别不到（endpoints=0、candidates=0），必须靠 guardbuild.json 的
 * responses / listEndpoint / routes[].params 才能接入动态探测。
 *
 *   ① 无契约线索   → exit 2（inconclusive / no_endpoints）：静态看不见 = 无法证明，不得放行
 *   ② 完整契约     → exit 1（vulnerable_unfixed）：alice 用 bob 的 order_id 读到 bob 的订单
 *                     （字段名 order_id / created_by_uid 与两段路径参数都来自契约）
 *   ③ 去掉 params  → exit 1（vulnerable_unfixed）：参数取值来源改由运行期绑定实测补上
 *                     （用本人列表里的真实对象逐参数对号并真实回读验证），不再只能 plan_incomplete
 *   ④ 运行期归属校验 → exit 0（not_reproducible）：已测用例打不通
 *
 * 用法: node scripts/e2e-contract.mjs
 */
import { spawn, spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const demoDir = path.join(repoRoot, ".demo-contract");
const dataDir = path.join(demoDir, "data");
const fixture = path.join(repoRoot, "fixtures", "contract-shop");

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

function editContract(ws, fn) {
  const p = path.join(ws, "guardbuild.json");
  const cfg = JSON.parse(readFileSync(p, "utf8"));
  fn(cfg);
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
      reject(new Error(`[contract:${label}] 超时 ${timeoutMs}ms`));
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

async function main() {
  console.log("[CONTRACT] 0/4 准备演示目录…");
  rmSync(demoDir, { recursive: true, force: true });
  mkdirSync(dataDir, { recursive: true });
  if (!existsSync(exe)) throw new Error(`未找到无头宿主: ${exe}（先 cargo build --no-default-features --bin guardbuild-headless）`);

  // ---------- ① 无契约线索 → exit 2（无法证明） ----------
  console.log("\n[CONTRACT] 1/4 无契约线索（静态看不见路由）：期望 exit 2（inconclusive / no_endpoints）…");
  const ws1 = makeWorkspace("c1-static", (ws) =>
    editContract(ws, (cfg) => {
      delete cfg.responses;
      delete cfg.listEndpoint;
      delete cfg.routes;
    })
  );
  const r1 = await runGate(ws1, "c1-static");
  const g1 = r1.gate ?? {};
  check("退出码 = 2（无法证明 ≠ 通过）", r1.code === 2, `code=${r1.code}${r1.code !== 2 ? ` stderr=${r1.stderr.slice(-400)}` : ""}`);
  check(
    "verdict=inconclusive 且 error.code=no_endpoints",
    g1.verdict === "inconclusive" && g1.error?.code === "no_endpoints",
    `verdict=${g1.verdict} code=${g1.error?.code} state=${g1.state}`
  );
  const rep1 = readReport("c1-static");
  const md1 = readMarkdown("c1-static");
  check(
    "报告结论一致（inconclusive / exit 2）",
    rep1?.verdict?.outcome === "inconclusive" && rep1?.verdict?.exitCode === 2,
    `outcome=${rep1?.verdict?.outcome} exit=${rep1?.verdict?.exitCode}`
  );
  check("终态标签写明「无法证明」", /无法证明/.test(String(rep1?.session?.stateLabel ?? "")), `label=${rep1?.session?.stateLabel}`);
  check("结论/建议给出接入方式（routes / openapi / listEndpoint）", /routes/.test(md1) && /listEndpoint/.test(md1), "");

  // ---------- ② 完整契约 → exit 1（复现越权） ----------
  console.log("\n[CONTRACT] 2/4 完整契约（responses + listEndpoint + routes[].params）：期望 exit 1…");
  const ws2 = makeWorkspace("c2-contract");
  const r2 = await runGate(ws2, "c2-contract");
  const g2 = r2.gate ?? {};
  check("退出码 = 1（漏洞证据成立）", r2.code === 1, `code=${r2.code}${r2.code !== 1 ? ` stderr=${r2.stderr.slice(-400)}` : ""}`);
  check(
    "verdict=vulnerable_unfixed 且 error=no_patchable_candidates",
    g2.verdict === "vulnerable_unfixed" && g2.error?.code === "no_patchable_candidates",
    `verdict=${g2.verdict} code=${g2.error?.code}`
  );
  const rep2 = readReport("c2-contract");
  const findings2 = rep2?.summary?.findings ?? [];
  check(
    "契约声明的多段路由进入静态候选",
    findings2.some((f) => f.method === "GET" && f.path === "/v1/orgs/:orgId/orders/:orderId"),
    `findings=${findings2.map((f) => `${f.method} ${f.path}`).join("、") || "无"}`
  );
  const pre2 = rep2?.evidence?.pre ?? [];
  const idor = pre2.find((e) => e.caseId === "attack-read-foreign");
  check("pre 证据：跨用户读取复现（attack-read-foreign → vulnerable）", idor?.verdict === "vulnerable", `verdict=${idor?.verdict} actual=${String(idor?.actual ?? "").slice(0, 120)}`);
  check(
    "请求路径由契约参数拼出（/v1/orgs/9/orders/7002）",
    String(idor?.endpoint ?? "") === "/v1/orgs/9/orders/7002",
    `endpoint=${idor?.endpoint}`
  );
  check(
    "判定依据是响应里的 order_id / created_by_uid（非默认字段名）",
    /7002/.test(String(idor?.actual ?? "")) && /归属 2|归属 bob|created_by_uid/.test(String(idor?.actual ?? "")),
    `actual=${String(idor?.actual ?? "").slice(0, 160)}`
  );
  check(
    "契约 listEndpoint 的分页参数生效（服务端要求 page+limit）",
    /资源发现：「alice」名下可见 1 个订单/.test(r2.stdout) && /资源发现：「bob」名下可见 2 个订单/.test(r2.stdout),
    (r2.stdout.match(/资源发现[^\n]*/g) ?? []).slice(0, 3).join(" | ")
  );
  const bizList = pre2.find((e) => e.caseId === "business-list-own");
  const bizAnon = pre2.find((e) => e.caseId === "business-unauth-401");
  check("业务基线：本人列表正常（business-list-own → passed）", bizList?.verdict === "passed", `verdict=${bizList?.verdict} actual=${String(bizList?.actual ?? "").slice(0, 100)}`);
  check("业务基线：匿名读取被拒（business-unauth-401 → passed）", bizAnon?.verdict === "passed", `verdict=${bizAnon?.verdict}`);

  // ---------- ③ 去掉 params → exit 2（无法证明） ----------
  console.log("\n[CONTRACT] 3/4 多段路径缺参数绑定：期望 exit 1（运行期绑定实测补上取值来源，不再只能 plan_incomplete）…");
  const ws3 = makeWorkspace("c3-noparams", (ws) =>
    editContract(ws, (cfg) => {
      delete cfg.routes[0].params;
    })
  );
  const r3 = await runGate(ws3, "c3-noparams");
  const g3 = r3.gate ?? {};
  check("退出码 = 1（运行期绑定实测后复现越权）", r3.code === 1, `code=${r3.code} verdict=${g3.verdict} error=${g3.error?.code}`);
  check("verdict=vulnerable_unfixed（非 inconclusive / 非静默跳过）", g3.verdict === "vulnerable_unfixed", `verdict=${g3.verdict} code=${g3.error?.code}`);
  const rep3 = readReport("c3-noparams");
  const md3 = readMarkdown("c3-noparams");
  const idor3 = (rep3?.evidence?.pre ?? []).find(
    (e) => e.caseId === "attack-read-foreign" && e.verdict === "vulnerable" && /v1\/orgs\/9\/orders\/7002/.test(String(e.endpoint ?? ""))
  );
  check(
    "pre 证据：两段路径参数由真实对象实测填充（/v1/orgs/9/orders/7002）",
    !!idor3,
    `endpoints=${(rep3?.evidence?.pre ?? []).map((e) => e.endpoint).filter((e) => /orgs/.test(String(e))).join("、") || "无"}`
  );
  check("未伪装成「已测未复现」", !/已测用例未复现/.test(md3), "");

  // ---------- ④ 运行期归属校验 → exit 0 ----------
  console.log("\n[CONTRACT] 4/4 服务端补归属校验：期望 exit 0（not_reproducible）…");
  const ws4 = makeWorkspace("c4-hardened", (ws) =>
    editContract(ws, (cfg) => {
      cfg.start.env = { ...(cfg.start.env ?? {}), GB_CONTRACT_HARDENED: "1" };
    })
  );
  const r4 = await runGate(ws4, "c4-hardened");
  const g4 = r4.gate ?? {};
  check("退出码 = 0（已测用例未复现）", r4.code === 0, `code=${r4.code}${r4.code !== 0 ? ` stderr=${r4.stderr.slice(-400)}` : ""}`);
  check("verdict=not_reproducible", g4.verdict === "not_reproducible", `verdict=${g4.verdict} error=${g4.error?.code}`);
  const rep4 = readReport("c4-hardened");
  const blocked = (rep4?.evidence?.pre ?? []).find((e) => e.caseId === "attack-read-foreign");
  check("pre 证据：跨用户读取被阻断（404）", blocked?.verdict === "blocked" && /404/.test(String(blocked?.actual ?? "")), `verdict=${blocked?.verdict} actual=${String(blocked?.actual ?? "").slice(0, 120)}`);
  check("报告标题写明「不等于安全」", /不等于安全/.test(String(rep4?.verdict?.headline ?? "")), `headline=${String(rep4?.verdict?.headline ?? "").slice(0, 100)}`);

  const passed = checks.filter((c) => c.pass).length;
  console.log(`\n[CONTRACT] 断言: ${passed}/${checks.length} 通过`);
  const failed = checks.filter((c) => !c.pass);
  if (failed.length > 0) {
    console.error(`[CONTRACT] 未通过: ${failed.map((c) => c.name).join("、")}`);
    process.exit(1);
  }
  console.log("[CONTRACT] 全部通过 ✅");
}

main().catch((e) => {
  console.error(`\n[CONTRACT] 失败: ${e.message}`);
  const passed = checks.filter((c) => c.pass).length;
  console.log(`[CONTRACT] 断言: ${passed}/${checks.length} 通过`);
  process.exit(1);
});
