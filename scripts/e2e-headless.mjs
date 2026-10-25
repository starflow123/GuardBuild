#!/usr/bin/env node
/**
 * 无头端到端验收：驱动 guardbuild-headless 走完整个工作流，并校验
 *   静态发现 → 动态复现（修复前漏洞证据）→ 隔离 worktree 补丁 → Diff 审查
 *   → 双重验收（攻击阻断 + 业务回归）→ 授权写回 → 写回后复核 → 回滚
 *
 * 校验点：
 *  - 状态机按预期流转（patch_review / writeback_pending / applied / rolled_back）
 *  - 修复前存在可利用证据（vulnerable / no-check），修复后攻击被阻断且业务无回归
 *  - 补丁哈希绑定、写回后实际工作区复核通过
 *  - 写回保留未提交本地改动；回滚后恢复原状
 *  - SQLite 证据库留痕完整（events / evidence / patches / approvals / acceptance）
 *
 * 用法: node scripts/e2e-headless.mjs
 */
import { spawn, spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import path from "node:path";
import readline from "node:readline";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const demoDir = path.join(repoRoot, ".demo");
const workspace = path.join(demoDir, "vibeshop");
const dataDir = path.join(demoDir, "data");
const reportDir = path.join(demoDir, "reports");

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
  checks.push({ name, pass: !!cond, detail });
  console.log(`${cond ? "  ✓" : "  ✗"} ${name}${detail ? ` — ${detail}` : ""}`);
  return !!cond;
}

async function fail(msg) {
  console.error(`\n[E2E] 失败: ${msg}`);
  printSummary();
  try {
    // 关闭宿主 stdin：让宿主走 EOF 优雅退出（shutdown 会清理被托管的子进程）
    child.stdin.end();
  } catch {
    /* 宿主尚未启动 */
  }
  await new Promise((r) => setTimeout(r, 2000));
  try {
    child.kill();
  } catch {
    /* ignore */
  }
  process.exit(1);
}

function printSummary() {
  const passed = checks.filter((c) => c.pass).length;
  console.log(`\n[E2E] 断言: ${passed}/${checks.length} 通过`);
}

// ---------- 1. 种子数据 ----------
console.log("[E2E] 1/6 生成演示工作区（含未提交本地改动）…");
rmSync(demoDir, { recursive: true, force: true });
const seed = spawnSync(process.execPath, [path.join(repoRoot, "scripts", "seed-demo.mjs"), demoDir], {
  encoding: "utf8",
});
if (seed.status !== 0) await fail(`seed-demo 失败: ${seed.stderr || seed.stdout}`);
console.log(seed.stdout.trim());

if (!existsSync(exe)) await fail(`未找到无头宿主可执行文件: ${exe}（先执行 cargo build --bin guardbuild-headless）`);

// ---------- 2. 启动无头宿主 ----------
console.log("\n[E2E] 2/6 启动无头宿主与 Sidecar…");
const child = spawn(exe, ["--report", reportDir], {
  cwd: repoRoot,
  env: {
    ...process.env,
    GUARDBUILD_DATA_DIR: dataDir,
    GUARDBUILD_SIDECAR: path.join(repoRoot, "sidecar", "main.mjs"),
    GUARDBUILD_E2E_PROJECT: workspace,
    GUARDBUILD_AUTO_CONSENT: "1",
  },
  stdio: ["pipe", "pipe", "pipe"],
});

let view = null;
let events = [];
const stateWaiters = [];
let exited = false;
child.on("exit", () => {
  exited = true;
});

readline.createInterface({ input: child.stdout }).on("line", (line) => {
  if (line.startsWith("GB_STATE ")) {
    try {
      view = JSON.parse(line.slice("GB_STATE ".length));
      for (const w of [...stateWaiters]) {
        if (view.state === w.state || w.predicate?.(view)) {
          stateWaiters.splice(stateWaiters.indexOf(w), 1);
          clearTimeout(w.timer);
          w.resolve(view);
        }
      }
    } catch { /* ignore */ }
  } else if (line.startsWith("GB_EVENT ")) {
    try {
      const ev = JSON.parse(line.slice("GB_EVENT ".length));
      events.push(ev);
      if (ev.severity === "error" || ev.severity === "warn" || ev.severity === "success") {
        console.log(`[E2E]   · [${ev.severity}] ${ev.message}`);
      }
    } catch { /* ignore */ }
  } else if (line.startsWith("GB_CONSENT ")) {
    // 自动同意模式下不应出现用户级授权请求；出现了就直接批准
    try {
      const c = JSON.parse(line.slice("GB_CONSENT ".length));
      console.log(`[E2E]   · 授权请求: ${c.scope?.kind}（自动批准）`);
      send({ cmd: "consent", id: c.consentId, approve: true });
    } catch { /* ignore */ }
  } else if (line.startsWith("GB_ERROR ")) {
    fail(`宿主启动错误: ${line}`);
  } else if (line.startsWith("GB_RESULT ")) {
    try {
      const r = JSON.parse(line.slice("GB_RESULT ".length));
      if (r.ok === false && r.cmd !== "quit") console.error(`[E2E]   命令 ${r.cmd} 返回错误: ${r.error}`);
    } catch { /* ignore */ }
  }
});
child.stderr.on("data", (b) => {
  const s = b.toString().trim();
  if (s) console.log(`[sidecar] ${s.split("\n").slice(-3).join(" | ")}`);
});

function send(obj) {
  child.stdin.write(`${JSON.stringify(obj)}\n`);
}

function waitFor(viewPredicate, label, timeoutMs = 180_000) {
  if (view && viewPredicate(view)) return Promise.resolve(view);
  return new Promise((resolve, reject) => {
    const w = {
      state: null,
      predicate: viewPredicate,
      resolve,
      timer: setTimeout(() => {
        const idx = stateWaiters.indexOf(w);
        if (idx >= 0) stateWaiters.splice(idx, 1);
        reject(new Error(`等待「${label}」超时（当前状态: ${view?.state ?? "?"}）`));
      }, timeoutMs),
    };
    stateWaiters.push(w);
  });
}
const waitState = (state, timeoutMs) => waitFor((v) => v.state === state, `状态 ${state}`, timeoutMs);

/** 等报告刷新到指定终态：写回后复核/回滚都会重发 report.json，这里按内容判定而不是 mtime */
async function waitReport(predicate, label, timeoutMs = 30_000) {
  const file = path.join(reportDir, "report.json");
  const deadline = Date.now() + timeoutMs;
  let last = null;
  while (Date.now() < deadline) {
    if (existsSync(file)) {
      try {
        last = JSON.parse(readFileSync(file, "utf8"));
      } catch {
        /* 宿主正在写，稍后重试 */
      }
      if (last && predicate(last)) return last;
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error(`等待报告「${label}」超时（当前 patchStatus=${last?.verdict?.patchStatus ?? "未生成"}）`);
}

const workspaceAppJs = path.join(workspace, "src", "app.js");
const LOCAL_MARK = "本地未提交改动";

try {
  await waitFor((v) => v.state === "starting", "会话开始", 60_000);
  console.log("[E2E]   会话已建立，等待静态分析与动态复现…");

  // ---------- 3. 静态发现 + 修复前复现 ----------
  console.log("\n[E2E] 3/6 等待修复前证据与隔离补丁…");
  await waitState("patch_review", 240_000);
  check("发现对象级越权候选", (view.findings ?? []).length >= 2, `findings=${(view.findings ?? []).length}`);
  const preEvidence = (view.evidence ?? []).filter((e) => e.phase === "pre");
  const preVuln = preEvidence.filter((e) => e.verdict === "vulnerable");
  check("修复前复现出可利用漏洞", preVuln.length >= 1, `pre 证据 ${preEvidence.length} 条，其中 vulnerable ${preVuln.length} 条`);
  check(
    "漏洞证据关联服务端权限判断（no-check）",
    preVuln.some((e) => e.decision && e.decision.decision === "no-check"),
    preVuln[0]?.decision ? `routeKey=${preVuln[0].decision.routeKey} checks=${JSON.stringify(preVuln[0].decision.checks)}` : ""
  );
  check("隔离补丁已生成", !!view.patch?.hash && view.patch.diff.includes("+"), `hash=${view.patch?.hash?.slice(0, 12)}… 文件=${view.patch?.files?.length}`);
  check("补丁在独立 worktree 中", !!view.patch?.worktree && !view.patch.worktree.startsWith(workspace), view.patch?.worktree);
  check("原工作区尚未被修改（隔离生效）", readFileSync(workspaceAppJs, "utf8").includes("no-check"));
  check("未提交本地改动仍在（补丁前）", readFileSync(workspaceAppJs, "utf8").includes(LOCAL_MARK));

  // ---------- 4. 批准补丁 → 双重验收 ----------
  console.log("\n[E2E] 4/6 批准 Diff，进入隔离实例双重验收…");
  send({ cmd: "patch_approve" });
  await waitState("writeback_pending", 240_000);
  const acc = view.acceptance ?? {};
  check("双重验收通过", acc.pass === true, `攻击阻断 ${acc.attackBlocked}/${acc.attackTotal}，业务保持 ${acc.businessPassed}/${acc.businessTotal}`);
  check("攻击全部被阻断", acc.attackBlocked === acc.attackTotal && acc.attackTotal >= 2, `attackTotal=${acc.attackTotal}`);
  check("业务用例全部保持", acc.businessPassed === acc.businessTotal && acc.businessTotal >= 6, `businessTotal=${acc.businessTotal}`);
  const postEvidence = (view.evidence ?? []).filter((e) => e.phase === "post");
  check("修复后存在 blocked 证据", postEvidence.some((e) => e.verdict === "blocked"), `post 证据 ${postEvidence.length} 条`);
  check(
    "确定性模板补丁同样逐候选归因：点名的入口全部自行翻转",
    (view.patch?.claimed ?? []).length >= 1 &&
      acc.attribution?.pass === true &&
      acc.attribution.claimedCount >= 1 &&
      acc.attribution.blockedCount === acc.attribution.claimedCount &&
      (acc.attribution.rows ?? []).filter((r) => r.claimed).every((r) => r.locality === "same_file"),
    `claimed=${JSON.stringify(view.patch?.claimed ?? [])} blocked=${acc.attribution?.blockedCount}/${acc.attribution?.claimedCount} locality=${(acc.attribution?.rows ?? []).filter((r) => r.claimed).map((r) => r.locality).join("/")}`
  );
  check("原工作区仍未被修改（写回前）", readFileSync(workspaceAppJs, "utf8").includes("no-check"));

  // ---------- 5. 授权写回 → 写回后复核 ----------
  console.log("\n[E2E] 5/6 授权写回工作区，并等待写回后复核…");
  send({ cmd: "writeback_approve" });
  await waitState("applied", 120_000);
  await waitFor(
    (v) => v.acceptance?.writebackRecheck?.pass !== undefined,
    "写回后复核完成",
    180_000
  );
  const recheck = view.acceptance.writebackRecheck;
  check("写回后复核通过", recheck.pass === true, `攻击阻断 ${recheck.attackBlocked}/${recheck.attackTotal}，业务保持 ${recheck.businessPassed}/${recheck.businessTotal}`);
  check(
    "写回后的真实工作区也过了逐候选归因",
    recheck.attribution?.pass === true && recheck.attribution.claimedCount >= 1 && recheck.attribution.blockedCount === recheck.attribution.claimedCount,
    `claimed=${recheck.attribution?.claimedCount} blocked=${recheck.attribution?.blockedCount}`
  );
  const wsAfter = readFileSync(workspaceAppJs, "utf8");
  check("实际工作区已包含修复", !wsAfter.includes('checks: ["authenticated"], decision: "no-check"'), "");
  check("写回保留了未提交本地改动", wsAfter.includes(LOCAL_MARK));
  check(
    "回滚可用（已备份原文件）",
    view.rollback?.available === true && (view.rollback.files ?? []).length >= 1,
    `backupId=${view.rollback?.backupId} files=${(view.rollback?.files ?? []).join(",")}`
  );
  check("写回授权已绑定补丁哈希", view.writebackAuthorized === true && view.tokens?.some((t) => (t.kinds ?? t.scopes ?? []).includes("workspace.write")));

  // ---------- 报告快照必须跟上写回终态 ----------
  console.log("\n[E2E] 校验 report.json / report.md 写回终态…");
  const wbReport = await waitReport((r) => r.verdict?.patchStatus === "written_back", "写回后报告");
  const wbMarkdown = readFileSync(path.join(reportDir, "report.md"), "utf8");
  check(
    "report.json 跟上写回终态（不再停在等待写回）",
    wbReport.session?.state === "applied" && wbReport.patch?.status === "written_back",
    `state=${wbReport.session?.state} patchStatus=${wbReport.verdict?.patchStatus}`
  );
  check(
    "report.json 含写回后复核结论",
    wbReport.summary?.acceptance?.writebackRecheck?.pass === true,
    `recheck=${JSON.stringify(wbReport.summary?.acceptance?.writebackRecheck?.pass)}`
  );
  check(
    "report.json 含 post_writeback 证据",
    (wbReport.summary?.evidence?.postWriteback ?? 0) > 0,
    `postWriteback=${wbReport.summary?.evidence?.postWriteback}`
  );
  check("report.json 含回滚备份信息", !!wbReport.rollback?.backupId, `backupId=${wbReport.rollback?.backupId}`);
  check(
    "report.md 渲染写回后复核段",
    wbMarkdown.includes("写回后复核（真实工作区）") && wbMarkdown.includes("写回后证据（post_writeback"),
    ""
  );

  // ---------- SQLite 留痕校验（回滚前读取） ----------
  console.log("\n[E2E] 6/6 校验 SQLite 证据库与回滚…");
  const dbPath = path.join(dataDir, "guardbuild.db");
  check("证据库文件存在", existsSync(dbPath), dbPath);
  const db = new DatabaseSync(dbPath, { readOnly: true });
  const count = (sql, ...args) => db.prepare(sql).get(...args)?.n ?? 0;
  const sessionId = view.sessionId;
  const evCount = count("SELECT COUNT(*) n FROM evidence WHERE session_id = ?", sessionId);
  const preCount = count("SELECT COUNT(*) n FROM evidence WHERE session_id = ? AND phase='pre'", sessionId);
  const postCount = count("SELECT COUNT(*) n FROM evidence WHERE session_id = ? AND phase='post'", sessionId);
  const pwCount = count("SELECT COUNT(*) n FROM evidence WHERE session_id = ? AND phase='post_writeback'", sessionId);
  const eventCount = count("SELECT COUNT(*) n FROM events WHERE session_id = ?", sessionId);
  const patchRow = db.prepare("SELECT status, patch_hash FROM patches WHERE session_id = ?").get(sessionId);
  const approvalCount = count("SELECT COUNT(*) n FROM approvals WHERE session_id = ?", sessionId);
  const accRows = db.prepare("SELECT COUNT(*) n, SUM(pass) ok FROM acceptance WHERE session_id = ?").get(sessionId);
  db.close();

  check("evidence 三阶段齐全", preCount > 0 && postCount > 0 && pwCount > 0, `pre=${preCount} post=${postCount} post_writeback=${pwCount}（共 ${evCount}）`);
  check("events 结构化留痕", eventCount >= 10, `events=${eventCount}`);
  check("patches 状态已写回", patchRow?.status === "written_back" && patchRow.patch_hash === view.patch.hash, `status=${patchRow?.status}`);
  check("approvals 记录用户授权", approvalCount >= 2, `approvals=${approvalCount}`);
  check("acceptance 用例全部通过", accRows.n > 0 && accRows.n === accRows.ok, `${accRows.ok}/${accRows.n}`);

  // 回滚
  send({ cmd: "rollback" });
  await waitState("rolled_back", 120_000);
  const wsRolled = readFileSync(workspaceAppJs, "utf8");
  check("回滚后修复已撤销", wsRolled.includes('checks: ["authenticated"], decision: "no-check"'));
  check("回滚后本地改动仍在", wsRolled.includes(LOCAL_MARK));

  const rolledReport = await waitReport((r) => r.verdict?.patchStatus === "rolled_back", "回滚后报告");
  const rolledMarkdown = readFileSync(path.join(reportDir, "report.md"), "utf8");
  check(
    "report.json 跟上回滚终态",
    rolledReport.patch?.status === "rolled_back" && rolledReport.session?.state === "rolled_back",
    `state=${rolledReport.session?.state} patchStatus=${rolledReport.verdict?.patchStatus}`
  );
  check("回滚后报告标题如实说明补丁已撤销", /现已回滚/.test(rolledReport.verdict?.headline ?? ""), rolledReport.verdict?.headline);
  check("report.md 标注已回滚", rolledMarkdown.includes("已回滚（工作区恢复写回前）"), "");

  // ---------- 7/6 回归：终态会话槽位释放（曾因残留会话卡在 starting） ----------
  console.log("\n[E2E] 回归：会话结束后可立即开启新会话…");
  const emptyProj = path.join(demoDir, "empty-proj");
  mkdirSync(emptyProj, { recursive: true });
  send({ cmd: "start", project: emptyProj });
  await waitState("error", 60_000);
  check(
    "空项目如实报「未识别路由 · 无法证明」（exit 2，不再伪装成 exit 0）",
    view.error?.code === "no_endpoints" && view.error?.kind === "inconclusive",
    `code=${view.error?.code} kind=${view.error?.kind}`
  );
  check(
    "未识别路由不得显示为执行失败",
    view.stateLabel === "未识别路由 · 无法证明",
    `stateLabel=${view.stateLabel}`
  );
  const failedSessionId = view.sessionId;
  send({ cmd: "start", project: workspace });
  await waitFor(
    (v) => v.state === "analyzing" && v.sessionId !== failedSessionId,
    "失败终态后新会话启动",
    60_000
  );
  check("失败结束后槽位释放，新会话可启动", view.sessionId !== failedSessionId, `新 sessionId=${view.sessionId}`);
  send({ cmd: "cancel" });
  await waitState("aborted", 120_000);
  check("新会话可中止（cancel 生效）", view.state === "aborted");

  // ---------- 8/6 回归：guardbuild.json 启动契约（自定义启动命令 + 自定义就绪行） ----------
  console.log("\n[E2E] 回归：guardbuild.json 变体目标（node boot.js + 自定义就绪行）…");
  const variantDir = path.join(demoDir, "variant-shop");
  cpSync(path.join(repoRoot, "fixtures", "vibeshop"), variantDir, { recursive: true });
  const variantServerJs = path.join(variantDir, "server.js");
  writeFileSync(variantServerJs, readFileSync(variantServerJs, "utf8").replace(/GB_LISTEN/g, "GB_VARIANT_READY"));
  writeFileSync(path.join(variantDir, "boot.js"), 'import("./server.js");\n');
  writeFileSync(
    path.join(variantDir, "guardbuild.json"),
    `${JSON.stringify(
      {
        start: {
          cmd: "node",
          args: ["boot.js"],
          env: { PORT: "0" },
          readyPattern: "GB_VARIANT_READY",
          readyTimeoutMs: 15000,
        },
      },
      null,
      2
    )}\n`
  );
  for (const args of [
    ["init", "-q"],
    ["config", "user.email", "demo@guardbuild.local"],
    ["config", "user.name", "GuardBuild Demo"],
    ["config", "core.autocrlf", "false"],
    ["add", "-A"],
    ["commit", "-qm", "variant 基线（guardbuild.json 自定义启动契约）"],
  ]) {
    const r = spawnSync("git", args, { cwd: variantDir, encoding: "utf8" });
    if (r.status !== 0) throw new Error(`git ${args.join(" ")} 失败: ${r.stderr || r.stdout}`);
  }

  const prevSessionId = view.sessionId;
  send({ cmd: "start", project: variantDir });
  await waitFor(
    (v) => v.state === "patch_review" && v.sessionId !== prevSessionId,
    "变体目标经 guardbuild.json 启动并完成取证",
    240_000
  );
  const variantPre = (view.evidence ?? []).filter((e) => e.phase === "pre");
  check(
    "guardbuild.json 启动契约生效（node boot.js + 自定义就绪行）",
    variantPre.some((e) => e.verdict === "vulnerable"),
    `pre 证据 ${variantPre.length} 条`
  );
  check("变体目标已生成隔离补丁", !!view.patch?.hash, `hash=${view.patch?.hash?.slice(0, 12)}…`);
  send({ cmd: "cancel" });
  await waitState("aborted", 120_000);
  check("变体会话可正常中止", view.state === "aborted");

  // ---------- 写回预检冲突：批准期间用户又改了补丁覆盖的那几行 ----------
  console.log("\n[E2E] 回归：写回预检冲突（工作区基线变化 → 拒绝写回，原文件不动）…");
  const conflictPrevSession = view.sessionId;
  send({ cmd: "start", project: workspace });
  await waitFor(
    (v) => v.state === "patch_review" && v.sessionId !== conflictPrevSession,
    "写回冲突场景会话完成取证",
    240_000
  );
  send({ cmd: "patch_approve" });
  await waitState("writeback_pending", 240_000);
  const beforeConflict = readFileSync(workspaceAppJs, "utf8");
  const NOTE_LINE = 'note: "查询订单后直接返回，未校验订单归属"';
  if (!beforeConflict.includes(NOTE_LINE)) throw new Error("冲突场景前置条件不成立：补丁覆盖的 note 行不在工作区文件中");
  writeFileSync(workspaceAppJs, beforeConflict.replace(NOTE_LINE, 'note: "用户在审批期间改了这行"'));
  const afterUserEdit = readFileSync(workspaceAppJs, "utf8");
  send({ cmd: "writeback_approve" });
  await waitState("error", 120_000);
  check(
    "写回被 Host 预检拒绝（Host 数字码 1007 已归一为符号码 conflict）",
    view.error?.code === "conflict",
    `code=${view.error?.code} kind=${view.error?.kind}`
  );
  check(
    "写回冲突呈现为「补丁未写回」而不是执行失败",
    view.error?.title === "工作区已变化，补丁未写回" && view.stateLabel === "补丁未写回 · 工作区已变化",
    `title=${view.error?.title} stateLabel=${view.stateLabel}`
  );
  check("冲突建议说明原文件未被修改", String(view.error?.semanticHint ?? "").includes("原文件未被修改"), "");
  check(
    "工作区仍是用户自己的内容（没有半写入）",
    readFileSync(workspaceAppJs, "utf8") === afterUserEdit,
    `字节一致=${readFileSync(workspaceAppJs, "utf8") === afterUserEdit}`
  );
} catch (e) {
  await fail(e.message);
}

send({ cmd: "quit" });
await new Promise((r) => setTimeout(r, 1500));
if (!exited) child.kill();

printSummary();
const failed = checks.filter((c) => !c.pass);
if (failed.length > 0) {
  console.error(`[E2E] 未通过: ${failed.map((c) => c.name).join("、")}`);
  process.exit(1);
}
console.log("[E2E] 全部通过 ✅");
process.exit(0);
