#!/usr/bin/env node
/**
 * NestJS 适配器端到端演练：以 fixtures/nest-shop（@Controller/@Get 真实控制器源码 + 等价 HTTP 垫片）
 * 驱动 guardbuild-headless --gate，验证两类结局：
 *
 *   ① 未修复（详情/取消/导出接口缺归属与路径校验） → exit 1（verdict=vulnerable_unfixed，error=no_patchable_candidates）
 *      alice 携带合法会话读取/取消 bob 的订单 #5002、经 export 穿越回读 package.json → 越权证据成立；
 *      NestJS 形态（守卫/管道依赖注入）无自动修复模板，按「证据成立但不可自动修复」阻断并给出人工修复指引。
 *   ② 已修复（运行时补归属校验 + 读取路径包含校验） → exit 0（verdict=not_reproducible）
 *      静态候选仍在，但攻击无法复现 → 不建立漏洞基线。
 *
 * 运行时说明：垫片不是 NestJS 运行时本体；解析器的被测对象是 fixture 中真实的
 * src/**\/*.controller.ts 源码，动态探测层只认 URL+方法契约（与生产行为一致），CI 无需安装 NestJS。
 *
 * 用法: node scripts/e2e-nest.mjs
 */
import { spawn, spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const demoDir = path.join(repoRoot, ".demo-nest");
const dataDir = path.join(demoDir, "data");
const fixture = path.join(repoRoot, "fixtures", "nest-shop");

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

/** 复刻「已修复」运行时：垫片层补归属校验（详情/取消）与读取路径包含校验（导出）；源文件静态形态保持原样 */
function patchServerToFixed(ws) {
  const p = path.join(ws, "server.js");
  let src = readFileSync(p, "utf8").replace(/\r\n/g, "\n");
  const before = src;
  src = src.replace(
    [
      "      const order = findOrderById(Number(m[1]));",
      '      if (!order) return json(res, 404, { error: "订单不存在" });',
      '      return json(res, 200, { order }); // 复刻漏洞：未校验 order.userId 归属',
    ].join("\n"),
    [
      "      const order = findOrderById(Number(m[1]));",
      '      if (!order || order.userId !== auth.user.id) return json(res, 404, { error: "订单不存在" });',
      "      return json(res, 200, { order });",
    ].join("\n")
  );
  src = src.replace(
    [
      "      const order = findOrderById(Number(m[1]));",
      '      if (!order) return json(res, 404, { error: "订单不存在" });',
      '      if (order.status !== "paid")',
    ].join("\n"),
    [
      "      const order = findOrderById(Number(m[1]));",
      '      if (!order || order.userId !== auth.user.id) return json(res, 404, { error: "订单不存在" });',
      '      if (order.status !== "paid")',
    ].join("\n")
  );
  src = src.replace(
    [
      '      const file = url.searchParams.get("file") ?? "";',
      '      const target = path.join(__dirname, "public", file);',
      "      try {",
      "        return res.end(fs.readFileSync(target)); // 复刻漏洞：未校验读取路径是否越出 public 目录",
    ].join("\n"),
    [
      '      const file = url.searchParams.get("file") ?? "";',
      '      const base = path.join(__dirname, "public");',
      "      const target = path.resolve(base, file);",
      '      if (!target.startsWith(base + path.sep)) return json(res, 403, { error: "路径不合法" });',
      "      try {",
      "        return res.end(fs.readFileSync(target));",
    ].join("\n")
  );
  if (src === before) throw new Error("修复补丁未命中 server.js 锚点（fixture 可能已变更）");
  writeFileSync(p, src);
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
      reject(new Error(`[nest:${label}] 超时 ${timeoutMs}ms`));
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
  console.log("[NEST] 0/2 准备演示目录…");
  rmSync(demoDir, { recursive: true, force: true });
  mkdirSync(dataDir, { recursive: true });
  if (!existsSync(exe)) throw new Error(`未找到无头宿主: ${exe}（先 cargo build --no-default-features --bin guardbuild-headless）`);

  // ---------- ① 未修复（控制器缺归属校验）→ exit 1 ----------
  console.log("\n[NEST] 1/2 未修复：alice 越权读/取消 bob 的订单 + 导出接口穿越：期望 exit 1（vulnerable_unfixed）…");
  const ws1 = makeWorkspace("n1-vuln");
  const r1 = await runGate(ws1, "n1-vuln");
  const g1 = r1.gate ?? {};
  check("退出码 = 1（漏洞证据成立）", r1.code === 1, `code=${r1.code}`);
  check(
    "verdict=vulnerable_unfixed 且 error=no_patchable_candidates",
    g1.verdict === "vulnerable_unfixed" && g1.error?.code === "no_patchable_candidates",
    `verdict=${g1.verdict} code=${g1.error?.code} state=${g1.state}`
  );
  const rep1 = readReport("n1-vuln");
  check("报告结论一致（vulnerable_unfixed/exit 1）", rep1?.verdict?.outcome === "vulnerable_unfixed" && rep1?.verdict?.exitCode === 1, `outcome=${rep1?.verdict?.outcome}`);
  const findings1 = rep1?.summary?.findings ?? [];
  check(
    "静态发现含 GET /api/orders/:id（装饰器路由解析）",
    findings1.some((f) => f.kind === "idor-suspect" && f.method === "GET" && f.path === "/api/orders/:id"),
    `findings=${findings1.map((f) => `${f.method} ${f.path}`).join("、")}`
  );
  check(
    "静态发现含 POST /api/orders/:id/cancel",
    findings1.some((f) => f.kind === "idor-suspect" && f.method === "POST" && f.path === "/api/orders/:id/cancel"),
    ""
  );
  check(
    "静态发现含穿越候选 GET /api/orders/export（@Query 输入合流）",
    findings1.some((f) => f.kind === "traversal-suspect" && f.path === "/api/orders/export"),
    ""
  );
  check(
    "发现来源为控制器文件（src/orders/orders.controller.ts）",
    findings1.some((f) => String(f.file ?? "").replace(/\\/g, "/").includes("src/orders/orders.controller.ts")),
    ""
  );
  const pre1 = rep1?.evidence?.pre ?? [];
  const readEv = pre1.find((e) => e.caseId === "attack-read-foreign");
  check(
    "pre 证据：越权读取被放行（attack-read-foreign → vulnerable）",
    readEv?.verdict === "vulnerable",
    `verdict=${readEv?.verdict} actual=${String(readEv?.actual ?? "").slice(0, 60)}`
  );
  check(
    "越权读取证据为内容级交叉证明（cross-proven）",
    readEv?.evidenceGrade === "cross-proven",
    `grade=${readEv?.evidenceGrade}`
  );
  const cancelEv = pre1.find((e) => e.caseId === "attack-cancel-foreign");
  check("pre 证据：越权取消被放行（attack-cancel-foreign → vulnerable）", cancelEv?.verdict === "vulnerable", `verdict=${cancelEv?.verdict}`);
  const travEv = pre1.find((e) => e.caseId === "attack-path-traversal");
  check(
    "pre 证据：导出接口路径穿越回读成功（attack-path-traversal → vulnerable）",
    travEv?.verdict === "vulnerable" && String(travEv?.actual ?? "").includes("package.json"),
    `verdict=${travEv?.verdict} actual=${String(travEv?.actual ?? "").slice(0, 70)}`
  );
  check("未生成补丁（NestJS 形态无自动修复模板）", (rep1?.patch ?? null) === null, `patch=${rep1?.patch ? "有" : "无"}`);
  check("错误指引要求人工修复", String(g1.error?.hint ?? "").includes("人工修复"), "");
  check("拒绝语义未误报：错误码非 failed（exit 2）", g1.error?.code !== "failed" && r1.code !== 2, `code=${r1.code} err=${g1.error?.code}`);

  // 证据入库抽查
  const db = new DatabaseSync(path.join(dataDir, "guardbuild.db"), { readOnly: true });
  const sid1 = g1.sessionId;
  const preVuln = db.prepare("SELECT COUNT(*) n FROM evidence WHERE session_id = ? AND phase='pre' AND verdict='vulnerable'").get(sid1).n;
  const patch1 = db.prepare("SELECT COUNT(*) n FROM patches WHERE session_id = ?").get(sid1).n;
  db.close();
  check("DB：pre 越权/穿越证据入库（读/取消/穿越 ≥ 3 条）", preVuln >= 3, `pre vulnerable=${preVuln}`);
  check("DB：未写入补丁记录", patch1 === 0, `patches=${patch1}`);

  // ---------- ② 已修复 → exit 0 ----------
  console.log("\n[NEST] 2/2 已修复（运行时补归属校验 + 导出路径包含校验）：期望 exit 0（not_reproducible）…");
  const ws2 = makeWorkspace("n2-fixed", patchServerToFixed);
  const r2 = await runGate(ws2, "n2-fixed");
  const g2 = r2.gate ?? {};
  check("退出码 = 0（无漏洞证据）", r2.code === 0, `code=${r2.code}`);
  check("verdict=not_reproducible", g2.verdict === "not_reproducible", `verdict=${g2.verdict} error=${g2.error?.code}`);
  const rep2 = readReport("n2-fixed");
  check("报告结论一致（not_reproducible/exit 0）", rep2?.verdict?.outcome === "not_reproducible" && rep2?.verdict?.exitCode === 0, `outcome=${rep2?.verdict?.outcome}`);
  check(
    "修复后静态候选仍存在（裁决来自动态复现而非静态缺失）",
    (rep2?.summary?.findings ?? []).length >= 3,
    `findings=${(rep2?.summary?.findings ?? []).length}`
  );

  const passed = checks.filter((c) => c.pass).length;
  console.log(`\n[NEST] 断言: ${passed}/${checks.length} 通过`);
  const failed = checks.filter((c) => !c.pass);
  if (failed.length > 0) {
    console.error(`[NEST] 未通过: ${failed.map((c) => c.name).join("、")}`);
    process.exit(1);
  }
  console.log("[NEST] 全部通过 ✅");
}

main().catch((e) => {
  console.error(`\n[NEST] 失败: ${e.message}`);
  const passed = checks.filter((c) => c.pass).length;
  console.log(`[NEST] 断言: ${passed}/${checks.length} 通过`);
  process.exit(1);
});
