#!/usr/bin/env node
/**
 * Python（FastAPI）适配器端到端演练：以 fixtures/python-shop（真实 FastAPI 应用 + FakeDB 取数）
 * 驱动 guardbuild-headless --gate，验证两类结局：
 *
 *   ① 未修复（详情/取消缺归属校验、小票接口无鉴权） → exit 1（vulnerable_unfixed，error=no_patchable_candidates）
 *      alice 携带合法会话读取/取消 bob 的订单 #2；匿名按编号读回 bob 的小票；
 *      bob 访问管理端列表被 403 拒绝（回归防线：合法的角色守卫未被误伤）。
 *   ② 已修复（运行时归属校验 + 小票接口鉴权） → exit 0（verdict=not_reproducible）
 *      修复以 security.py 辅助函数落地：静态分析仍看到 read/cancel 候选，
 *      但攻击在运行时全部被拒绝 → 不建立漏洞基线（裁决来自动态复现，不是静态缺失）。
 *
 * 运行时说明：本演练使用真实 uvicorn + FastAPI（CI 已预装），不是 HTTP 垫片；
 * Python 修复形态（依赖注入/辅助函数）无自动补丁模板，与 NestJS/GraphQL 一致按人工修复处理。
 *
 * 用法: node scripts/e2e-python.mjs
 */
import { spawn, spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const demoDir = path.join(repoRoot, ".demo-python");
const dataDir = path.join(demoDir, "data");
const fixture = path.join(repoRoot, "fixtures", "python-shop");

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

/** 修复只落在运行时路径：辅助函数在 security.py，静态分析看不到归属比较语句 */
function patchPythonToFixed(ws) {
  const p = path.join(ws, "main.py");
  let src = readFileSync(p, "utf8").replace(/\r\n/g, "\n");
  const before = src;
  writeFileSync(
    path.join(ws, "security.py"),
    [
      "from fastapi import HTTPException",
      "",
      "",
      "def require_owner(order, user):",
      '    if order["userId"] != user["id"]:',
      '        raise HTTPException(status_code=403, detail="无权访问该订单")',
      "",
    ].join("\n")
  );
  src = src.replace(
    "from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException",
    "from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException\n\nfrom security import require_owner"
  );
  src = src.replace(
    [
      "    # 复刻漏洞：仅按 id 取单，未校验 order.userId 是否属于当前用户",
      '    return {"order": order}',
    ].join("\n"),
    ["    require_owner(order, user)", '    return {"order": order}'].join("\n")
  );
  src = src.replace(
    [
      "    # 复刻漏洞：未校验归属即可取消他人订单",
      '    order["status"] = "cancelled"',
      '    return {"order": order}',
    ].join("\n"),
    [
      "    require_owner(order, user)",
      '    order["status"] = "cancelled"',
      '    return {"order": order}',
    ].join("\n")
  );
  src = src.replace(
    "def get_receipt(receipt_id: int, db: FakeDB = Depends(get_db)):",
    "def get_receipt(receipt_id: int, user: dict = Depends(get_current_user), db: FakeDB = Depends(get_db)):"
  );
  src = src.replace(
    [
      "    # 复刻漏洞：小票接口未挂鉴权依赖，匿名即可按编号取回地址与金额",
      '    return {"order": receipt}',
    ].join("\n"),
    ["    require_owner(receipt, user)", '    return {"order": receipt}'].join("\n")
  );
  if (src === before) throw new Error("修复补丁未命中 main.py 锚点（fixture 可能已变更）");
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
      reject(new Error(`[python:${label}] 超时 ${timeoutMs}ms`));
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
  console.log("[PYTHON] 0/2 准备演示目录…");
  rmSync(demoDir, { recursive: true, force: true });
  mkdirSync(dataDir, { recursive: true });
  if (!existsSync(exe)) throw new Error(`未找到无头宿主: ${exe}（先 cargo build --no-default-features --bin guardbuild-headless）`);

  // ---------- ① 未修复 → exit 1 ----------
  console.log("\n[PYTHON] 1/2 未修复：alice 越权读/取消 bob 的订单 + 匿名读小票：期望 exit 1（vulnerable_unfixed）…");
  const ws1 = makeWorkspace("p1-vuln");
  const r1 = await runGate(ws1, "p1-vuln");
  const g1 = r1.gate ?? {};
  check("退出码 = 1（漏洞证据成立）", r1.code === 1, `code=${r1.code}`);
  check(
    "verdict=vulnerable_unfixed 且 error=no_patchable_candidates",
    g1.verdict === "vulnerable_unfixed" && g1.error?.code === "no_patchable_candidates",
    `verdict=${g1.verdict} code=${g1.error?.code} state=${g1.state}`
  );
  const rep1 = readReport("p1-vuln");
  check("报告结论一致（vulnerable_unfixed/exit 1）", rep1?.verdict?.outcome === "vulnerable_unfixed" && rep1?.verdict?.exitCode === 1, `outcome=${rep1?.verdict?.outcome}`);
  const findings1 = rep1?.summary?.findings ?? [];
  check(
    "静态发现含 GET /api/orders/:order_id（FastAPI 装饰器 + APIRouter 前缀）",
    findings1.some((f) => f.kind === "idor-suspect" && f.method === "GET" && f.path === "/api/orders/:order_id"),
    `findings=${findings1.map((f) => `${f.method} ${f.path}`).join("、")}`
  );
  check(
    "静态发现含 POST /api/orders/:order_id/cancel",
    findings1.some((f) => f.kind === "idor-suspect" && f.method === "POST" && f.path === "/api/orders/:order_id/cancel"),
    ""
  );
  check(
    "静态发现含无鉴权 GET /api/receipts/:receipt_id",
    findings1.some((f) => f.kind === "no-auth-suspect" && f.method === "GET" && f.path === "/api/receipts/:receipt_id"),
    ""
  );
  check(
    "发现来源为 main.py（Python 适配器）",
    findings1.some((f) => String(f.file ?? "").replace(/\\/g, "/").endsWith("main.py")),
    ""
  );
  const pre1 = rep1?.evidence?.pre ?? [];
  const readEv = pre1.find((e) => e.caseId === "attack-read-foreign");
  check("pre 证据：越权读取被放行（attack-read-foreign → vulnerable）", readEv?.verdict === "vulnerable", `verdict=${readEv?.verdict} actual=${String(readEv?.actual ?? "").slice(0, 60)}`);
  check("越权读取证据为内容级交叉证明（cross-proven）", readEv?.evidenceGrade === "cross-proven", `grade=${readEv?.evidenceGrade}`);
  const cancelEv = pre1.find((e) => e.caseId === "attack-cancel-foreign");
  check("pre 证据：越权取消被放行（attack-cancel-foreign → vulnerable）", cancelEv?.verdict === "vulnerable", `verdict=${cancelEv?.verdict}`);
  const anonEv = pre1.find((e) => e.caseId === "attack-anonymous-read");
  check("pre 证据：匿名读取小票成功（attack-anonymous-read → vulnerable）", anonEv?.verdict === "vulnerable", `verdict=${anonEv?.verdict} actual=${String(anonEv?.actual ?? "").slice(0, 60)}`);
  const adminEv = pre1.find((e) => e.caseId === "attack-vertical-escalation");
  // 修复前被拒绝的用例语义是「未能复现」（inconclusive），不能算漏洞证据
  check("回归防线：普通用户访问管理端未被放行（attack-vertical-escalation ≠ vulnerable）", adminEv?.verdict && adminEv.verdict !== "vulnerable", `verdict=${adminEv?.verdict} status=${adminEv?.status}`);
  check("未生成补丁（Python 形态无自动修复模板）", (rep1?.patch ?? null) === null, `patch=${rep1?.patch ? "有" : "无"}`);
  check("错误指引要求人工修复", String(g1.error?.hint ?? "").includes("人工修复"), "");
  check("拒绝语义未误报：错误码非 failed（exit 2）", g1.error?.code !== "failed" && r1.code !== 2, `code=${r1.code} err=${g1.error?.code}`);

  const db = new DatabaseSync(path.join(dataDir, "guardbuild.db"), { readOnly: true });
  const sid1 = g1.sessionId;
  const preVuln = db.prepare("SELECT COUNT(*) n FROM evidence WHERE session_id = ? AND phase='pre' AND verdict='vulnerable'").get(sid1).n;
  const patch1 = db.prepare("SELECT COUNT(*) n FROM patches WHERE session_id = ?").get(sid1).n;
  db.close();
  check("DB：pre 越权/匿名证据入库（读/取消/匿名 ≥ 3 条）", preVuln >= 3, `pre vulnerable=${preVuln}`);
  check("DB：未写入补丁记录", patch1 === 0, `patches=${patch1}`);

  // ---------- ② 已修复 → exit 0 ----------
  console.log("\n[PYTHON] 2/2 已修复（运行时归属校验 + 小票鉴权）：期望 exit 0（not_reproducible）…");
  const ws2 = makeWorkspace("p2-fixed", patchPythonToFixed);
  const r2 = await runGate(ws2, "p2-fixed");
  const g2 = r2.gate ?? {};
  check("退出码 = 0（无漏洞证据）", r2.code === 0, `code=${r2.code}`);
  check("verdict=not_reproducible", g2.verdict === "not_reproducible", `verdict=${g2.verdict} error=${g2.error?.code}`);
  const rep2 = readReport("p2-fixed");
  check("报告结论一致（not_reproducible/exit 0）", rep2?.verdict?.outcome === "not_reproducible" && rep2?.verdict?.exitCode === 0, `outcome=${rep2?.verdict?.outcome}`);
  const findings2 = rep2?.summary?.findings ?? [];
  check(
    "修复后静态候选仍在（裁决来自动态复现而非静态缺失）",
    findings2.filter((f) => f.kind === "idor-suspect").length >= 2,
    `idor findings=${findings2.filter((f) => f.kind === "idor-suspect").length}`
  );
  const pre2 = rep2?.evidence?.pre ?? [];
  const attack2 = pre2.filter((e) => String(e.caseId).startsWith("attack-"));
  // 无漏洞基线时不存在 post 阶段，攻击用例的「被拒绝」语义是未能复现（inconclusive）
  check("修复后：全部攻击用例均未放行（含小票详情候选）", attack2.length >= 3 && attack2.every((e) => e.verdict !== "vulnerable"), `cases=${attack2.map((e) => `${e.caseId}:${e.verdict}`).join("、")}`);

  const passed = checks.filter((c) => c.pass).length;
  console.log(`\n[PYTHON] 断言: ${passed}/${checks.length} 通过`);
  const failed = checks.filter((c) => !c.pass);
  if (failed.length > 0) {
    console.error(`[PYTHON] 未通过: ${failed.map((c) => c.name).join("、")}`);
    process.exit(1);
  }
  console.log("[PYTHON] 全部通过 ✅");
}

main().catch((e) => {
  console.error(`\n[PYTHON] 失败: ${e.message}`);
  const passed = checks.filter((c) => c.pass).length;
  console.log(`[PYTHON] 断言: ${passed}/${checks.length} 通过`);
  process.exit(1);
});
