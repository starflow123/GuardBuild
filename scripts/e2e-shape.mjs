#!/usr/bin/env node
/**
 * 资源契约自动发现端到端演练：fixtures/shape-shop 的路由静态可见，但响应形状全部偏离
 * 默认启发式（深嵌套列表 + 强制 page/pageSize 分页 + 非默认字段名 batch_id/keeper_id/tenant_code
 * + {meta,record} 包装 + 两段路径路由）。guardbuild.json 故意不写 responses / listEndpoint /
 * routes[].params —— 契约必须由引擎用两个真实身份对拉实测得出（P2）。
 *
 *   ① 默认（无人工契约）        → exit 1（vulnerable_unfixed）：契约实测出来、跨用户读取复现，
 *                                 且两段路径参数经实测绑定后也进了探测
 *   ② 加固版                    → exit 0（not_reproducible）：已测用例打不通
 *   ③ 删掉单参数路由（只留两段） → exit 1：过去这种项目 plan_incomplete（exit 2），
 *                                 现在运行期参数绑定实测通过后照样覆盖（覆盖率增益）
 *   ④ ③ + 列表元素剥掉 tenant_code → exit 2（param_binding_unverified）：真实对象里找不到
 *                                 参数对应的字段，引擎不猜（无法证明 ≠ 已测未复现）
 *
 * 用法: node scripts/e2e-shape.mjs
 */
import { spawn, spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const demoDir = path.join(repoRoot, ".demo-shape");
const dataDir = path.join(demoDir, "data");
const fixture = path.join(repoRoot, "fixtures", "shape-shop");

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

/** 场景③/④：把单参数路由从源码删掉，只留两段路径路由（过去只能 plan_incomplete 的形态） */
function dropSingleRoute(ws) {
  const p = path.join(ws, "src", "app.js");
  const src = readFileSync(p, "utf8");
  const begin = src.indexOf("// GB_SHAPE_SINGLE_BEGIN");
  const end = src.indexOf("// GB_SHAPE_SINGLE_END");
  if (begin < 0 || end < 0) throw new Error("shape-shop 源码缺少 GB_SHAPE_SINGLE 标记块");
  writeFileSync(p, src.slice(0, begin) + src.slice(end + "// GB_SHAPE_SINGLE_END".length));
}

function runGate(project, label, { timeoutMs = 120_000, envExtra = {} } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(exe, ["--gate", "--project", project, "--report", path.join(demoDir, "reports", label)], {
      cwd: repoRoot,
      env: {
        ...process.env,
        GUARDBUILD_DATA_DIR: dataDir,
        GUARDBUILD_SIDECAR: path.join(repoRoot, "sidecar", "main.mjs"),
        ...envExtra,
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (b) => { stdout += b.toString(); });
    child.stderr.on("data", (b) => { stderr += b.toString(); });
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`[shape:${label}] 超时 ${timeoutMs}ms`));
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
  console.log("[SHAPE] 0/4 准备演示目录…");
  rmSync(demoDir, { recursive: true, force: true });
  mkdirSync(dataDir, { recursive: true });
  if (!existsSync(exe)) throw new Error(`未找到无头宿主: ${exe}（先 cargo build --no-default-features --bin guardbuild-headless）`);

  // ---------- ① 无人工契约，全靠实测发现 → exit 1 ----------
  console.log("\n[SHAPE] 1/4 无人工契约（响应形状全部偏离默认）：期望 exit 1（契约实测出来并复现越权）…");
  const ws1 = makeWorkspace("s1-auto");
  const r1 = await runGate(ws1, "s1-auto");
  const g1 = r1.gate ?? {};
  check("退出码 = 1（漏洞证据成立）", r1.code === 1, `code=${r1.code}${r1.code !== 1 ? ` stderr=${r1.stderr.slice(-500)}` : ""}`);
  check(
    "verdict=vulnerable_unfixed",
    g1.verdict === "vulnerable_unfixed",
    `verdict=${g1.verdict} code=${g1.error?.code}`
  );
  check(
    "资源契约自动发现事件（双身份实测：嵌套列表/主键/归属/分页）",
    /资源契约自动发现（双身份实测）/.test(r1.stdout) &&
      /data\.results\.batchList/.test(r1.stdout) &&
      /batch_id/.test(r1.stdout) &&
      /keeper_id/.test(r1.stdout) &&
      /需分页参数/.test(r1.stdout),
    (r1.stdout.match(/资源契约自动发现[^\n]*/g) ?? [])[0] ?? "未找到发现事件"
  );
  const rep1 = readReport("s1-auto");
  const pre1 = rep1?.evidence?.pre ?? [];
  const idor1 = pre1.find((e) => e.caseId === "attack-read-foreign");
  check("pre 证据：跨用户读取复现（attack-read-foreign → vulnerable）", idor1?.verdict === "vulnerable", `verdict=${idor1?.verdict} actual=${String(idor1?.actual ?? "").slice(0, 140)}`);
  check(
    "请求路径由实测契约拼出（/api/warehouse/batches/4001）",
    String(idor1?.endpoint ?? "") === "/api/warehouse/batches/4001",
    `endpoint=${idor1?.endpoint}`
  );
  check(
    "两段路径参数绑定经实测确认，并真实进入探测",
    /多段路径参数绑定经实测确认/.test(r1.stdout) && /tenant_code/.test(r1.stdout),
    (r1.stdout.match(/多段路径参数绑定[^\n]*/g) ?? [])[0] ?? "未找到绑定事件"
  );
  check(
    "报告 findings 包含两段路径路由（自动绑定后进入候选）",
    (rep1?.summary?.findings ?? []).some((f) => String(f.path).includes("/api/tenants/")),
    `findings=${(rep1?.summary?.findings ?? []).map((f) => `${f.method} ${f.path}`).join("、")}`
  );
  check("契约缓存落盘且不含响应数据", existsSync(path.join(dataDir, "rescontract")), "");

  // ---------- ② 加固版 → exit 0 ----------
  console.log("\n[SHAPE] 2/4 服务端加归属校验：期望 exit 0（not_reproducible）…");
  const ws2 = makeWorkspace("s2-hardened", (ws) => {
    const p = path.join(ws, "guardbuild.json");
    const cfg = JSON.parse(readFileSync(p, "utf8"));
    cfg.start.env = { ...(cfg.start.env ?? {}), GB_SHAPE_HARDENED: "1" };
    writeFileSync(p, `${JSON.stringify(cfg, null, 2)}\n`);
  });
  const r2 = await runGate(ws2, "s2-hardened");
  const g2 = r2.gate ?? {};
  check("退出码 = 0（已测用例未复现）", r2.code === 0, `code=${r2.code}`);
  check("verdict=not_reproducible", g2.verdict === "not_reproducible", `verdict=${g2.verdict} error=${g2.error?.code}`);

  // ---------- ③ 只留两段路径路由 → exit 1（覆盖率增益：过去 plan_incomplete） ----------
  console.log("\n[SHAPE] 3/4 只留两段路径路由（过去 plan_incomplete / exit 2）：期望 exit 1…");
  const ws3 = makeWorkspace("s3-nested-only", dropSingleRoute);
  const r3 = await runGate(ws3, "s3-nested-only");
  const g3 = r3.gate ?? {};
  check("退出码 = 1（运行期绑定实测补上了取值来源）", r3.code === 1, `code=${r3.code} verdict=${g3.verdict} code=${g3.error?.code}${r3.code !== 1 ? ` stderr=${r3.stderr.slice(-500)}` : ""}`);
  const rep3 = readReport("s3-nested-only");
  const pre3 = rep3?.evidence?.pre ?? [];
  const idor3 = pre3.find((e) => e.verdict === "vulnerable" && /api\/tenants/.test(String(e.endpoint ?? "")));
  check(
    "pre 证据：两段路径越权读取复现（endpoint 含 /api/tenants/T-B3/batches/4001）",
    !!idor3 && /T-B3/.test(String(idor3.endpoint)),
    `endpoints=${pre3.map((e) => e.endpoint).filter((e) => /tenants/.test(String(e))).join("、") || "无"}`
  );

  // ---------- ④ 两段路径 + 对象里没有对应字段 → exit 2（不猜） ----------
  console.log("\n[SHAPE] 4/4 列表元素剥掉 tenant_code：期望 exit 2（param_binding_unverified，不猜）…");
  const ws4 = makeWorkspace(
    "s4-unbindable",
    (ws) => {
      dropSingleRoute(ws);
      const p = path.join(ws, "guardbuild.json");
      const cfg = JSON.parse(readFileSync(p, "utf8"));
      cfg.start.env = { ...(cfg.start.env ?? {}), GB_SHAPE_NO_TENANT: "1" };
      writeFileSync(p, `${JSON.stringify(cfg, null, 2)}\n`);
    }
  );
  const r4 = await runGate(ws4, "s4-unbindable");
  const g4 = r4.gate ?? {};
  check("退出码 = 2（取值来源测不出时不得猜着打）", r4.code === 2, `code=${r4.code}`);
  check(
    "verdict=inconclusive 且 error.code=param_binding_unverified",
    g4.verdict === "inconclusive" && g4.error?.code === "param_binding_unverified",
    `verdict=${g4.verdict} code=${g4.error?.code}`
  );
  const md4 = readMarkdown("s4-unbindable");
  check("报告结论一致（inconclusive / exit 2）", /无法证明/.test(md4), "");
  check("建议点名 routes[].params", /routes\[\]\.params/.test(md4), "");
  check("未伪装成「已测未复现」", !/已测用例未复现/.test(md4), "");

  const passed = checks.filter((c) => c.pass).length;
  console.log(`\n[SHAPE] 断言: ${passed}/${checks.length} 通过`);
  const failed = checks.filter((c) => !c.pass);
  if (failed.length > 0) {
    console.error(`[SHAPE] 未通过: ${failed.map((c) => c.name).join("、")}`);
    process.exit(1);
  }
  console.log("[SHAPE] 全部通过 ✅");
}

main().catch((e) => {
  console.error(`\n[SHAPE] 失败: ${e.message}`);
  const passed = checks.filter((c) => c.pass).length;
  console.log(`[SHAPE] 断言: ${passed}/${checks.length} 通过`);
  process.exit(1);
});
