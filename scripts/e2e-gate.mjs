#!/usr/bin/env node
/**
 * CI gate 模式演练：以 6 个目标分别驱动 guardbuild-headless --gate，验证
 *   ① 漏洞目标        → exit 1（verdict=vulnerable, patchStatus=verified，附双重验收）
 *   ② 已修复目标      → exit 0（verdict=no_candidates，静态即无候选）
 *   ③ 运行期防护目标  → exit 0（verdict=not_reproducible，静态有候选但攻击不可复现）
 *   ④ 契约凭证错误    → exit 2（verdict=failed，error.code=login_rejected）
 *   ⑤ 真实形状目标    → exit 1（人类可读 ANSI 就绪行 + build/ 产物诱饵 + 源码在 src/，
 *                        email 登录 + 嵌套 token 提取 + npm prepare 步骤）
 *   ⑥ 无鉴权端点目标  → exit 1（verdict=vulnerable_unfixed：攻击已复现但仅有无鉴权
 *                        候选，无可自动修复 IDOR——必须放行为「漏洞证据成立」而非 exit 0）
 *
 * 同时校验 gate 的权限语义：
 *   - 作用域令牌经策略预声明签发（via=policy），全程无 GB_CONSENT 交互
 *   - 原工作区在 gate 中不被修改（禁止写回，含未提交本地改动保留）
 *   - 审批留痕 via=gate-policy（非 user-diff-approval）
 *   - 每轮均产出 report.json / report.md，且结论与 GB_GATE 裁决一致
 *
 * 所有轮次均以空 stdin 运行（模拟 CI），依赖进程自行裁决退出。
 *
 * 用法: node scripts/e2e-gate.mjs
 */
import { spawn, spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const demoDir = path.join(repoRoot, ".demo-gate");
const dataDir = path.join(demoDir, "data");
const fixture = path.join(repoRoot, "fixtures", "vibeshop");

/** 无头宿主可执行文件：GUARDBUILD_HEADLESS_BIN > target/debug > target/release（跨平台） */
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

function makeWorkspace(name, { mutate, fixtureDir = fixture } = {}) {
  const ws = path.join(demoDir, name);
  cpSync(fixtureDir, ws, { recursive: true });
  if (mutate) mutate(ws);
  git(["init", "-q"], ws);
  git(["config", "user.email", "gate@guardbuild.local"], ws);
  git(["config", "user.name", "GuardBuild Gate"], ws);
  git(["config", "core.autocrlf", "false"], ws);
  git(["add", "-A"], ws);
  git(["commit", "-qm", `${name} 基线`], ws);
  return ws;
}

/** 运行一轮 gate：空 stdin、收集 stdout/stderr、返回 { code, gate, stdout, stderr } */
function runGate(project, label, timeoutMs = 300_000) {
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
      reject(new Error(`[gate:${label}] 超时 ${timeoutMs}ms`));
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

function lastStates(stdout) {
  return stdout.split("\n").filter((l) => l.startsWith("GB_STATE ")).map((l) => {
    try { return JSON.parse(l.slice("GB_STATE ".length)); } catch { return null; }
  }).filter(Boolean);
}

function readReport(round) {
  const p = path.join(demoDir, "reports", round, "report.json");
  if (!existsSync(p)) return null;
  try { return JSON.parse(readFileSync(p, "utf8")); } catch { return null; }
}

async function main() {
  console.log("[GATE] 0/6 准备演示目录…");
  rmSync(demoDir, { recursive: true, force: true });
  const seed = spawnSync(process.execPath, [path.join(repoRoot, "scripts", "seed-demo.mjs"), demoDir], { encoding: "utf8" });
  if (seed.status !== 0) throw new Error(`seed-demo 失败: ${seed.stderr || seed.stdout}`);
  if (!existsSync(exe)) throw new Error(`未找到无头宿主: ${exe}（先 cargo build --no-default-features --bin guardbuild-headless）`);

  // ---------- ① 漏洞目标 → exit 1 ----------
  console.log("\n[GATE] 1/6 漏洞目标：期望 exit 1（漏洞证据成立 + 已验证补丁）…");
  const vulnWs = path.join(demoDir, "vibeshop");
  const r1 = await runGate(vulnWs, "r1");
  const g1 = r1.gate ?? {};
  check("退出码 = 1（漏洞证据成立）", r1.code === 1, `code=${r1.code}`);
  check("verdict=vulnerable 且补丁已验证", g1.verdict === "vulnerable" && g1.patchStatus === "verified", `verdict=${g1.verdict} patchStatus=${g1.patchStatus}`);
  check("补丁哈希为 sha256", typeof g1.patchHash === "string" && /^[0-9a-f]{64}$/.test(g1.patchHash), `hash=${g1.patchHash?.slice(0, 12)}…`);
  check("双重验收通过（攻击全阻断 + 业务全保持）",
    g1.acceptance?.pass === true &&
      g1.acceptance.attackBlocked === g1.acceptance.attackTotal &&
      g1.acceptance.businessPassed === g1.acceptance.businessTotal,
    `attack ${g1.acceptance?.attackBlocked}/${g1.acceptance?.attackTotal}，business ${g1.acceptance?.businessPassed}/${g1.acceptance?.businessTotal}`);
  check("静态候选 ≥ 2", (g1.findings ?? 0) >= 2, `findings=${g1.findings}`);

  check("gate 无任何授权交互（无 GB_CONSENT）", !r1.stdout.includes("GB_CONSENT"), "");
  const states = lastStates(r1.stdout);
  const lastView = states[states.length - 1] ?? {};
  const policyTokens = (lastView.tokens ?? []).filter((t) => t.via === "policy");
  check("作用域令牌经策略签发（via=policy ≥ 3）", policyTokens.length >= 3,
    (lastView.tokens ?? []).map((t) => `${(t.kinds ?? [])[0]}:${t.via}`).join(" | "));
  check("预声明作用域日志正确", r1.stderr.includes("预声明作用域: project.read, worktree.write, proc.spawn, net.probe"), "");

  const wsAppJs = path.join(vulnWs, "src", "app.js");
  const wsAfter = readFileSync(wsAppJs, "utf8");
  check("gate 未修改原工作区（禁止写回）", wsAfter.includes('decision: "no-check"') && wsAfter.includes("本地未提交改动"), "");
  check("会话未进入 applied（无写回状态）", g1.state === "writeback_pending", `state=${g1.state}`);

  const dbPath = path.join(dataDir, "guardbuild.db");
  const db = new DatabaseSync(dbPath, { readOnly: true });
  const sid = g1.sessionId;
  const approval = db.prepare("SELECT via FROM approvals WHERE session_id = ? AND action = 'patch.approve'").get(sid);
  const preN = db.prepare("SELECT COUNT(*) n FROM evidence WHERE session_id = ? AND phase='pre'").get(sid).n;
  const postN = db.prepare("SELECT COUNT(*) n FROM evidence WHERE session_id = ? AND phase='post'").get(sid).n;
  const patchRow = db.prepare("SELECT patch_hash FROM patches WHERE session_id = ?").get(sid);
  db.close();
  check("审批留痕 via=gate-policy", approval?.via === "gate-policy", `via=${approval?.via}`);
  check("证据双阶段入库（pre/post）", preN > 0 && postN > 0, `pre=${preN} post=${postN}`);
  check("补丁记录与 GB_GATE 哈希一致", patchRow?.patch_hash === g1.patchHash, "");

  // 报告产物（r1）
  const rep1 = readReport("r1");
  const md1Path = path.join(demoDir, "reports", "r1", "report.md");
  check("报告产物已生成（report.json + report.md）", !!rep1 && existsSync(md1Path), path.join(demoDir, "reports", "r1"));
  check("报告结论与 GB_GATE 一致（vulnerable/exit 1）",
    rep1?.verdict?.outcome === g1.verdict && rep1?.verdict?.exitCode === g1.exitCode && rep1?.verdict?.patchStatus === "verified",
    `outcome=${rep1?.verdict?.outcome} exitCode=${rep1?.verdict?.exitCode}`);
  check("报告绑定会话与补丁哈希", rep1?.session?.id === g1.sessionId && rep1?.patch?.hash === g1.patchHash, "");
  const md1 = existsSync(md1Path) ? readFileSync(md1Path, "utf8") : "";
  check("报告 markdown 含结论文案与验收摘要", md1.includes("## 结论与建议") && md1.includes("双重验收") && md1.includes(g1.patchHash.slice(0, 12)), "");

  // 收集管线产出的修复版 app.js（供第 2 轮使用）
  const worktreesRoot = path.join(dataDir, "worktrees");
  let fixedAppJs = null;
  for (const s of readdirSync(worktreesRoot)) {
    const sRoot = path.join(worktreesRoot, s);
    if (!statSync(sRoot).isDirectory()) continue;
    for (const fix of readdirSync(sRoot)) {
      const p = path.join(sRoot, fix, "src", "app.js");
      if (existsSync(p)) fixedAppJs = readFileSync(p, "utf8");
    }
  }
  check("已获取管线修复产物（隔离 worktree）", !!fixedAppJs && !fixedAppJs.includes('decision: "no-check"'), "");

  // ---------- ② 已修复目标 → exit 0 ----------
  console.log("\n[GATE] 2/6 已修复目标：期望 exit 0（静态无候选）…");
  const fixedWs = makeWorkspace("fixed-shop", {
    mutate: (ws) => writeFileSync(path.join(ws, "src", "app.js"), fixedAppJs ?? ""),
  });
  const r2 = await runGate(fixedWs, "r2");
  check("退出码 = 0（无漏洞证据）", r2.code === 0, `code=${r2.code}`);
  check("verdict=no_candidates", r2.gate?.verdict === "no_candidates", `verdict=${r2.gate?.verdict} state=${r2.gate?.state}`);
  const rep2 = readReport("r2");
  check("报告一致（no_candidates/exit 0）", rep2?.verdict?.outcome === "no_candidates" && rep2?.verdict?.exitCode === 0, `outcome=${rep2?.verdict?.outcome}`);

  // ---------- ③ 运行期防护目标 → exit 0 ----------
  console.log("\n[GATE] 3/6 运行期防护目标：期望 exit 0（攻击不可复现）…");
  const guardedWs = makeWorkspace("guarded-shop", {
    mutate: (ws) => {
      const server = path.join(ws, "server.js");
      const base = readFileSync(server, "utf8");
      const guard = `import { authenticate } from "./src/auth.js";\nimport { findOrderById } from "./src/data.js";\n\n` +
        `// 归属防护中间件：/api/orders/:id 与 /api/orders/:id/cancel 统一校验资源归属\n` +
        `function ownershipGuard(req) {\n` +
        `  const m = (req.url || "").match(/^\\/api\\/orders\\/(\\d+)(?:\\/cancel)?(?:\\?|$)/);\n` +
        `  if (!m) return false;\n` +
        `  const auth = authenticate(req);\n` +
        `  if (!auth) return false;\n` +
        `  const order = findOrderById(Number(m[1]));\n` +
        `  return !!(order && order.userId !== auth.user.id);\n` +
        `}\n\n`;
      writeFileSync(server, guard + base.replace(
        "const server = http.createServer((req, res) => {",
        `const server = http.createServer((req, res) => {\n  if (ownershipGuard(req)) {\n    res.writeHead(404, { "Content-Type": "application/json" });\n    res.end(JSON.stringify({ error: "订单不存在" }));\n    return;\n  }`
      ));
    },
  });
  const r3 = await runGate(guardedWs, "r3");
  check("退出码 = 0（无漏洞证据）", r3.code === 0, `code=${r3.code}`);
  check("verdict=not_reproducible（静态有候选、攻击不可复现）", r3.gate?.verdict === "not_reproducible",
    `verdict=${r3.gate?.verdict} findings=${r3.gate?.findings} error=${r3.gate?.error?.code}`);
  const rep3 = readReport("r3");
  check("报告一致（not_reproducible/exit 0）", rep3?.verdict?.outcome === "not_reproducible" && rep3?.verdict?.exitCode === 0, `outcome=${rep3?.verdict?.outcome}`);

  // ---------- ④ 契约凭证错误 → exit 2 ----------
  console.log("\n[GATE] 4/6 契约凭证错误：期望 exit 2（执行失败）…");
  const badWs = makeWorkspace("badlogin-shop", {
    mutate: (ws) => writeFileSync(path.join(ws, "guardbuild.json"), JSON.stringify({
      identities: [
        { username: "alice", password: "wrong-pass-1" },
        { username: "bob", password: "wrong-pass-2" },
      ],
    }, null, 2)),
  });
  const r4 = await runGate(badWs, "r4");
  check("退出码 = 2（执行失败）", r4.code === 2, `code=${r4.code}`);
  check("verdict=failed 且 error.code=login_rejected", r4.gate?.verdict === "failed" && r4.gate?.error?.code === "login_rejected",
    `verdict=${r4.gate?.verdict} code=${r4.gate?.error?.code}`);
  const rep4 = readReport("r4");
  check("报告一致（failed/exit 2 + login_rejected）", rep4?.verdict?.outcome === "failed" && rep4?.verdict?.exitCode === 2 && rep4?.error?.code === "login_rejected",
    `outcome=${rep4?.verdict?.outcome} error=${rep4?.error?.code}`);

  // ---------- ⑤ 真实形状目标（ANSI 就绪行 + 产物诱饵）→ exit 1 ----------
  console.log("\n[GATE] 5/6 真实形状目标：期望 exit 1（人类可读 ANSI 就绪行 + 源码优先选择）…");
  const legacyWs = makeWorkspace("legacy-shop", { fixtureDir: path.join(repoRoot, "fixtures", "legacy-shop") });
  const r5 = await runGate(legacyWs, "r5");
  const g5 = r5.gate ?? {};
  check("退出码 = 1（漏洞证据成立）", r5.code === 1, `code=${r5.code}`);
  check("verdict=vulnerable 且补丁已验证", g5.verdict === "vulnerable" && g5.patchStatus === "verified",
    `verdict=${g5.verdict} patchStatus=${g5.patchStatus}`);
  check("ANSI 就绪行端口解析成功（目标已就绪）", (r5.stdout ?? "").includes("已就绪: http://127.0.0.1:"), "");
  const r5log = `${r5.stdout}\n${r5.stderr}`;
  check("email 登录 + 嵌套 token 提取成功（登录成功）", r5log.includes("登录成功"), "");
  check("npm prepare 步骤已执行（原始工作区与 worktree 各一次）",
    (r5log.match(/准备步骤完成/g) ?? []).length >= 2, `执行次数=${(r5log.match(/准备步骤完成/g) ?? []).length}`);
  const rep5 = readReport("r5");
  check("证据级别已注入（pre 摘要含三档计数）",
    !!rep5?.summary?.phases?.pre?.grades && typeof rep5.summary.phases.pre.grades["http-only"] === "number",
    JSON.stringify(rep5?.summary?.phases?.pre?.grades ?? null));
  const f5 = rep5?.summary?.findings ?? [];
  check("静态候选全部来自 src/ 源码（未被 build/ 诱饵挤占）",
    f5.length >= 2 && f5.every((f) => /[\\/]src[\\/]/.test(f.file)),
    `findings=${f5.length}：[${f5.map((f) => path.basename(f.file)).join(", ")}]`);

  // ---------- ⑥ 无鉴权端点目标 → exit 1（vulnerable_unfixed）----------
  console.log("\n[GATE] 6/6 无鉴权端点目标：期望 exit 1（攻击已复现但无可自动修复候选）…");
  const unauthWs = makeWorkspace("unauth-shop", {
    mutate: (ws) => {
      const appJsPath = path.join(ws, "src", "app.js");
      let src = readFileSync(appJsPath, "utf8");
      const swap = (find, repl) => {
        if (!src.includes(find)) throw new Error(`[unauth-shop] 变异锚点未匹配: ${find.slice(0, 60)}…`);
        src = src.replace(find, repl);
      };
      // 详情与取消路由整体去掉认证：静态层转为 no-auth-suspect，运行期匿名可读
      swap(
        `    if (!auth) {
      recordDecision({
        method, path: pathname, routeKey: "orders.get",
        requesterId: null, requesterRole: null,
        checks: ["authenticated"], decision: "deny",
        note: "未登录，拒绝访问订单详情",
      });
      return json(res, 401, { error: "未登录" });
    }
    const orderId = Number(orderDetailMatch[1]);`,
        `    const orderId = Number(orderDetailMatch[1]);`
      );
      swap(
        `      requesterId: auth.user.id, requesterRole: auth.user.role,
      resourceOwner: order.userId,
      checks: ["authenticated"], decision: "no-check",
      note: "查询订单后直接返回，未校验订单归属",`,
        `      requesterId: null, requesterRole: null,
      resourceOwner: order.userId,
      checks: [], decision: "no-check",
      note: "查询订单后直接返回，未校验订单归属",`
      );
      swap(
        `    if (!auth) {
      recordDecision({
        method, path: pathname, routeKey: "orders.cancel",
        requesterId: null, requesterRole: null,
        checks: ["authenticated"], decision: "deny",
        note: "未登录，拒绝取消订单",
      });
      return json(res, 401, { error: "未登录" });
    }
    const orderId = Number(orderCancelMatch[1]);`,
        `    const orderId = Number(orderCancelMatch[1]);`
      );
      swap(
        `      requesterId: auth.user.id, requesterRole: auth.user.role,
      resourceOwner: order.userId,
      checks: ["authenticated"], decision: "no-check",
      note: "取消订单前未校验订单归属",`,
        `      requesterId: null, requesterRole: null,
      resourceOwner: order.userId,
      checks: [], decision: "no-check",
      note: "取消订单前未校验订单归属",`
      );
      writeFileSync(appJsPath, src);
    },
  });
  const r6 = await runGate(unauthWs, "r6");
  const g6 = r6.gate ?? {};
  check("退出码 = 1（漏洞证据成立）", r6.code === 1, `code=${r6.code}`);
  check(
    "verdict=vulnerable_unfixed（攻击已复现但无可自动修复候选）",
    g6.verdict === "vulnerable_unfixed" && g6.error?.code === "no_patchable_candidates",
    `verdict=${g6.verdict} code=${g6.error?.code} state=${g6.state}`
  );
  check("静态候选含无鉴权线索（findings ≥ 1）", (g6.findings ?? 0) >= 1, `findings=${g6.findings}`);
  const rep6 = readReport("r6");
  check(
    "报告一致（vulnerable_unfixed/exit 1）",
    rep6?.verdict?.outcome === "vulnerable_unfixed" && rep6?.verdict?.exitCode === 1,
    `outcome=${rep6?.verdict?.outcome} exitCode=${rep6?.verdict?.exitCode}`
  );
  const db6 = new DatabaseSync(dbPath, { readOnly: true });
  const sid6 = g6.sessionId;
  const anonVuln = db6
    .prepare(
      "SELECT COUNT(*) n FROM evidence WHERE session_id = ? AND phase='pre' AND verdict='vulnerable' AND identity='(anonymous)'"
    )
    .get(sid6).n;
  const patch6 = db6.prepare("SELECT COUNT(*) n FROM patches WHERE session_id = ?").get(sid6).n;
  db6.close();
  check("pre 存在匿名可利用证据（漏洞基线成立）", anonVuln >= 1, `anonymous vulnerable 证据=${anonVuln}`);
  check("未生成补丁（无可自动修复候选）", patch6 === 0, `patches=${patch6}`);

  // ---------- 汇总 ----------
  const passed = checks.filter((c) => c.pass).length;
  console.log(`\n[GATE] 断言: ${passed}/${checks.length} 通过`);
  const failed = checks.filter((c) => !c.pass);
  if (failed.length > 0) {
    console.error(`[GATE] 未通过: ${failed.map((c) => c.name).join("、")}`);
    process.exit(1);
  }
  console.log("[GATE] 全部通过 ✅");
}

main().catch((e) => {
  console.error(`\n[GATE] 失败: ${e.message}`);
  const passed = checks.filter((c) => c.pass).length;
  console.log(`[GATE] 断言: ${passed}/${checks.length} 通过`);
  process.exit(1);
});
