#!/usr/bin/env node
/**
 * 纯黑盒外部模式 E2E：真实 HTTP 目标 + Host 网络/保险库 + gate 退出码。
 *
 * legacy-shop（单一 IDOR）：
 *   ① 漏洞目标 → exit 1，findingCount=1，cross-proven 证据
 *   ② 已修复目标（同一路由加归属校验）→ exit 0，no_findings
 *   ③ Cookie 会话鉴权目标 → exit 1，Cookie 注入生效
 *   ④ 目标不可达 → exit 2，failed（且应在 30s 内短路，不做无意义探测）
 * wide-shop（宽攻击面：管理端点 / 写删 IDOR / 匿名写入 / 数字语境注入 / 二次编码穿越）：
 *   ⑤ 默认探测 → 只应出现无副作用的探测族，写类与匿名写一律不出现
 *   ⑥ allowMutation → 跨用户 PUT/PATCH + 匿名写入出现，DELETE 仍不出现
 *   ⑦ allowMutation + allowDestructive → 跨用户 DELETE 出现
 *   ⑧ 加固版（GB_WIDE_HARDENED=1）+ 两个开关都开 → exit 0，四类攻击全部记 blocked 而非静默或 404
 *
 * 断言按「用例集合」而非裸计数：每条探测族都要在证据里以真实 caseId 出现（或确实不出现），
 * 否则新增探测族时 e2e 无法察觉漏跑。
 *
 * 同时校验：报告落盘且与 GB_GATE 一致；报告中不出现真实令牌；原 fixture 不被修改。
 *
 * 用法: node scripts/e2e-blackbox.mjs
 */
import { spawn, spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const demoDir = path.join(repoRoot, ".demo-blackbox-e2e");
const fixture = path.join(repoRoot, "fixtures", "legacy-shop");
const wideFixture = path.join(repoRoot, "fixtures", "wide-shop");
const reportsDir = path.join(demoDir, "reports");

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

function makeShop(name, { fixed = false, from = fixture } = {}) {
  const dir = path.join(demoDir, name);
  cpSync(from, dir, { recursive: true });
  if (fixed) {
    const appPath = path.join(dir, "src", "app.js");
    const src = readFileSync(appPath, "utf8");
    const anchor = "const order = findOrderById(orderId);";
    if (!src.includes(anchor)) throw new Error("fixed 变体锚点未匹配");
    writeFileSync(
      appPath,
      src.replace(anchor, `${anchor}\n    if (order && order.userId !== auth.user.id) return json(res, 403, { error: "无权访问该订单" });`)
    );
  }
  return dir;
}

function makeCookieShop(name) {
  const dir = makeShop(name);
  const cfgPath = path.join(dir, "guardbuild.json");
  const cfg = JSON.parse(readFileSync(cfgPath, "utf8"));
  cfg.login = {
    path: "/session/login",
    bodyTemplate: { email: "{email}", password: "{password}" },
    cookieAuth: true,
    encoding: "form",
  };
  writeFileSync(cfgPath, `${JSON.stringify(cfg, null, 2)}\n`);
  return dir;
}

function startServer(dir, extraEnv = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn("node", ["server.js"], {
      cwd: dir,
      env: { ...process.env, PORT: "0", ...extraEnv },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let out = "";
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error("目标服务启动超时"));
    }, 20_000);
    const onData = (b) => {
      out += b.toString();
      const m = out.replace(/\x1b\[[0-9;]*m/g, "").match(/listening on port\s+(\d+)/i);
      if (m) {
        clearTimeout(timer);
        child.stdout.off("data", onData);
        resolve({ child, port: Number(m[1]) });
      }
    };
    child.stdout.on("data", onData);
    child.stderr.on("data", (b) => (out += b.toString()));
    child.on("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`目标服务提前退出（code=${code}）：${out.slice(-400)}`));
    });
  });
}

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, "127.0.0.1", () => {
      const port = srv.address().port;
      srv.close(() => resolve(port));
    });
    srv.on("error", reject);
  });
}

function runBlackbox({ url, project, label, timeoutMs = 120_000, extraEnv = {} }) {
  const t0 = Date.now();
  return new Promise((resolve, reject) => {
    const child = spawn(
      exe,
      ["--url", url, "--project", project, "--gate", "--report", path.join(reportsDir, label)],
      {
        cwd: repoRoot,
        env: {
          ...process.env,
          GUARDBUILD_DATA_DIR: path.join(demoDir, "data", label),
          GUARDBUILD_SIDECAR: path.join(repoRoot, "sidecar", "main.mjs"),
          ...extraEnv,
        },
        stdio: ["ignore", "pipe", "pipe"],
      }
    );
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (b) => (stdout += b.toString()));
    child.stderr.on("data", (b) => (stderr += b.toString()));
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`[${label}] 超时 ${timeoutMs}ms`));
    }, timeoutMs);
    child.on("exit", (code) => {
      clearTimeout(timer);
      const line = stdout.split("\n").filter((l) => l.startsWith("GB_GATE ")).pop();
      let gate = null;
      if (line) {
        try {
          gate = JSON.parse(line.slice("GB_GATE ".length));
        } catch {
          /* ignore */
        }
      }
      resolve({ code, gate, durationMs: Date.now() - t0, stdout, stderr });
    });
    child.on("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
  });
}

function readReport(label) {
  const p = path.join(reportsDir, label, "report.json");
  if (!existsSync(p)) return null;
  try {
    return JSON.parse(readFileSync(p, "utf8"));
  } catch {
    return null;
  }
}

/** 证据按结论分桶取 caseId 集合：断言「这一探测族真的打过 / 确实没打」，而不是只看 finding 总数。 */
function caseIdsBy(report, verdict) {
  return new Set((report?.evidence?.blackbox ?? []).filter((e) => e.verdict === verdict).map((e) => e.caseId));
}

function hasPrefix(set, prefix) {
  return [...set].some((id) => String(id ?? "").startsWith(prefix));
}

function checkCaseSet(title, ids, must = [], mustNot = []) {
  const shown = [...ids].sort().join(", ") || "（空）";
  for (const p of must) check(`${title} 含 ${p}*`, hasPrefix(ids, p), `实际：${shown}`);
  for (const p of mustNot) check(`${title} 不含 ${p}*`, !hasPrefix(ids, p), `实际：${shown}`);
}

function checkCoverage(title, coverage, must = [], mustNot = []) {
  const text = (coverage ?? []).join("|");
  for (const p of must) check(`${title} 覆盖「${p}」`, text.includes(p), `实际覆盖：${text}`);
  for (const p of mustNot) check(`${title} 未覆盖「${p}」（本轮不该发这类请求）`, !text.includes(p), `实际覆盖：${text}`);
}

function snapshot(dir) {
  const out = {};
  const walk = (d) => {
    for (const name of readdirSync(d)) {
      const p = path.join(d, name);
      const st = statSync(p);
      if (st.isDirectory()) {
        if (name === "node_modules" || name === ".git") continue;
        walk(p);
      } else {
        out[path.relative(dir, p)] = st.size;
      }
    }
  };
  walk(dir);
  return out;
}

async function main() {
  rmSync(demoDir, { recursive: true, force: true });
  mkdirSync(demoDir, { recursive: true });

  console.log("[BB] 准备目标…");
  const vulnShop = makeShop("shop-vuln");
  const fixedShop = makeShop("shop-fixed", { fixed: true });
  const before = snapshot(vulnShop);

  log("1/8 漏洞目标（legacy-shop 单一 IDOR）");
  const vuln = await startServer(vulnShop);
  try {
    const r = await runBlackbox({
      url: `http://127.0.0.1:${vuln.port}`,
      project: vulnShop,
      label: "vuln",
    });
    check("退出码 = 1", r.code === 1, `code=${r.code}`);
    check("verdict=vulnerable_unfixed", r.gate?.verdict === "vulnerable_unfixed", `verdict=${r.gate?.verdict}`);
    check("findingCount=1", r.gate?.blackbox?.findingCount === 1, `findingCount=${r.gate?.blackbox?.findingCount}`);
    check("Host 登录成功（契约身份 alice/bob）", r.gate?.blackbox?.login?.ok === true, `path=${r.gate?.blackbox?.login?.path}`);
    const report = readReport("vuln");
    check("报告落盘且结论一致", report?.verdict?.outcome === "vulnerable_unfixed" && report?.verdict?.exitCode === 1);
    const ev = report?.evidence?.blackbox ?? [];
    check("证据为 cross-proven（内容归属交叉证明）", ev.some((e) => e.evidenceGrade === "cross-proven" && e.verdict === "vulnerable"));
    checkCaseSet("漏洞目标 vulnerable 用例", caseIdsBy(report, "vulnerable"), ["blackbox-idor-"]);
    const raw = JSON.stringify(report ?? {});
    check("报告不含真实令牌（仅 vault 占位）", !/Bearer\s+(?!\*\*\*|<)[A-Za-z0-9._-]{16,}/.test(raw), raw.match(/Bearer [^"]{0,24}/)?.[0] ?? "");
    check("原 fixture 未被修改（黑盒不改码）", JSON.stringify(snapshot(vulnShop)) === JSON.stringify(before));
  } finally {
    vuln.child.kill();
  }

  log("2/8 已修复目标（同一路由加归属校验）");
  const fixed = await startServer(fixedShop);
  try {
    const r = await runBlackbox({
      url: `http://127.0.0.1:${fixed.port}`,
      project: fixedShop,
      label: "fixed",
    });
    check("退出码 = 0", r.code === 0, `code=${r.code}`);
    check("verdict=no_findings", r.gate?.verdict === "no_findings", `verdict=${r.gate?.verdict}`);
    check("findingCount=0", r.gate?.blackbox?.findingCount === 0);
    const report = readReport("fixed");
    check("报告结论一致且无漏洞", report?.verdict?.outcome === "no_findings" && (report?.blackbox?.findings ?? []).length === 0);
    const blocked = (report?.evidence?.blackbox ?? []).some((e) => e.verdict === "blocked");
    check("归属校验生效时记录 blocked 证据（而非仅 404）", blocked);
    checkCaseSet("已修复目标 blocked 用例", caseIdsBy(report, "blocked"), ["blackbox-idor-"]);
  } finally {
    fixed.child.kill();
  }

  log("3/8 Cookie 会话鉴权目标（form 登录 + 302 Set-Cookie）");
  const cookieShop = makeCookieShop("shop-cookie");
  const cookie = await startServer(cookieShop);
  try {
    const r = await runBlackbox({
      url: `http://127.0.0.1:${cookie.port}`,
      project: cookieShop,
      label: "cookie",
    });
    check("退出码 = 1", r.code === 1, `code=${r.code}`);
    check("Host Cookie 登录成功（alice/bob）", r.gate?.blackbox?.login?.ok === true, `path=${r.gate?.blackbox?.login?.path}`);
    const report = readReport("cookie");
    check("Cookie 会话下仍复现 IDOR（Cookie 注入生效）", (report?.blackbox?.findings ?? []).length === 1);
    const raw = JSON.stringify(report ?? {});
    check("报告不泄露会话 Cookie", !/sid=sess_[A-Za-z0-9]+/.test(raw), raw.match(/sid=[^"]{0,16}/)?.[0] ?? "");
  } finally {
    cookie.child.kill();
  }

  log("4/8 宽攻击面目标 · 默认探测（只发无副作用请求）");
  const wideShop = makeShop("shop-wide", { from: wideFixture });
  const wideBefore = snapshot(wideShop);
  const wide = await startServer(wideShop);
  try {
    const r = await runBlackbox({ url: `http://127.0.0.1:${wide.port}`, project: wideShop, label: "wide" });
    check("退出码 = 1", r.code === 1, `code=${r.code}`);
    const report = readReport("wide");
    const ids = caseIdsBy(report, "vulnerable");
    checkCaseSet("默认探测 vulnerable 用例", ids, [
      "blackbox-vertical-",
      "blackbox-idor-",
      "blackbox-sqli-numeric-",
      "blackbox-traversal-",
    ]);
    checkCaseSet("默认探测 vulnerable 用例", ids, [], [
      "blackbox-idor-put-",
      "blackbox-idor-patch-",
      "blackbox-idor-delete-",
      "blackbox-anon-write-",
    ]);
    checkCoverage("默认探测", report?.blackbox?.coverage, ["垂直越权（管理端点）", "跨用户读取（IDOR）"], [
      "跨用户修改（PUT/PATCH）",
      "未认证写入",
      "跨用户删除（DELETE）",
    ]);
    check("报告标记写探测未开启", report?.blackbox?.allowMutation === false && report?.blackbox?.allowDestructive === false);
    check("垂直越权有管理身份交叉证明", (report?.evidence?.blackbox ?? []).some((e) => e.caseId?.startsWith("blackbox-vertical-") && e.evidenceGrade === "cross-proven"));
    check("原 fixture 未被修改", JSON.stringify(snapshot(wideShop)) === JSON.stringify(wideBefore));
  } finally {
    wide.child.kill();
  }

  log("5/8 宽攻击面目标 · allowMutation（放开写/匿名写，仍不删）");
  const mutShop = makeShop("shop-wide-mutate", { from: wideFixture });
  const mutate = await startServer(mutShop);
  try {
    const r = await runBlackbox({
      url: `http://127.0.0.1:${mutate.port}`,
      project: mutShop,
      label: "mutate",
      extraEnv: { GUARDBUILD_BLACKBOX_MUTATE: "1" },
    });
    check("退出码 = 1", r.code === 1, `code=${r.code}`);
    const report = readReport("mutate");
    const ids = caseIdsBy(report, "vulnerable");
    checkCaseSet("allowMutation vulnerable 用例", ids, [
      "blackbox-idor-put-",
      "blackbox-idor-patch-",
      "blackbox-anon-write-",
    ]);
    checkCaseSet("allowMutation vulnerable 用例", ids, [], ["blackbox-idor-delete-"]);
    checkCoverage("allowMutation", report?.blackbox?.coverage, ["跨用户修改（PUT/PATCH）", "未认证写入"], ["跨用户删除（DELETE）"]);
    check("匿名写入以 canary 落库复核（cross-proven）", (report?.evidence?.blackbox ?? []).some((e) => e.caseId?.startsWith("blackbox-anon-write-") && e.evidenceGrade === "cross-proven"));
    check("跨用户修改后已按归属人恢复原值", !(report?.evidence?.blackbox ?? []).some((e) => /恢复未确认/.test(String(e.actual ?? ""))));
    check("canary 未残留在目标数据面（自清理生效）", !(report?.evidence?.blackbox ?? []).some((e) => /自清理未成功/.test(String(e.actual ?? ""))));
  } finally {
    mutate.child.kill();
  }

  log("6/8 宽攻击面目标 · allowMutation + allowDestructive（DELETE 也上）");
  const delShop = makeShop("shop-wide-delete", { from: wideFixture });
  const destructive = await startServer(delShop);
  try {
    const r = await runBlackbox({
      url: `http://127.0.0.1:${destructive.port}`,
      project: delShop,
      label: "destructive",
      extraEnv: { GUARDBUILD_BLACKBOX_MUTATE: "1", GUARDBUILD_BLACKBOX_DELETE: "1" },
    });
    check("退出码 = 1", r.code === 1, `code=${r.code}`);
    const report = readReport("destructive");
    checkCaseSet(
      "allowDestructive vulnerable 用例",
      caseIdsBy(report, "vulnerable"),
      ["blackbox-idor-delete-"]
    );
    checkCoverage("allowDestructive", report?.blackbox?.coverage, ["跨用户删除（DELETE）"]);
    check("DELETE 结论来自归属人复读（不是状态码）", (report?.evidence?.blackbox ?? []).some((e) => e.caseId?.startsWith("blackbox-idor-delete-") && e.evidenceGrade === "cross-proven"));
  } finally {
    destructive.child.kill();
  }

  log("7/8 宽攻击面目标 · 加固版 + 全部开关（应零 finding，且每类攻击都记 blocked）");
  const hardShop = makeShop("shop-wide-hardened", { from: wideFixture });
  const hardened = await startServer(hardShop, { GB_WIDE_HARDENED: "1" });
  try {
    const r = await runBlackbox({
      url: `http://127.0.0.1:${hardened.port}`,
      project: hardShop,
      label: "hardened",
      extraEnv: { GUARDBUILD_BLACKBOX_MUTATE: "1", GUARDBUILD_BLACKBOX_DELETE: "1" },
    });
    check("退出码 = 0", r.code === 0, `code=${r.code}`);
    check("verdict=no_findings", r.gate?.verdict === "no_findings", `verdict=${r.gate?.verdict}`);
    const report = readReport("hardened");
    check("finding 为空", (report?.blackbox?.findings ?? []).length === 0, `findings=${(report?.blackbox?.findings ?? []).length}`);
    const ids = caseIdsBy(report, "blocked");
    checkCaseSet("加固版 blocked 用例", ids, [
      "blackbox-vertical-",
      "blackbox-idor-",
      "blackbox-idor-put-",
      "blackbox-idor-patch-",
      "blackbox-idor-delete-",
      "blackbox-anon-write-",
    ]);
    check(
      "垂直越权的 blocked 有管理身份交叉证明（拒绝来自角色校验，不是端点不存在）",
      (report?.evidence?.blackbox ?? []).some(
        (e) => e.caseId?.startsWith("blackbox-vertical-") && e.evidenceGrade === "cross-proven"
      )
    );
  } finally {
    hardened.child.kill();
  }

  log("8/8 不可达目标");
  const deadPort = await freePort();
  const r = await runBlackbox({
    url: `http://127.0.0.1:${deadPort}`,
    project: vulnShop,
    label: "unreachable",
    timeoutMs: 30_000,
  });
  check("退出码 = 2", r.code === 2, `code=${r.code}`);
  check("verdict=failed", r.gate?.verdict === "failed", `verdict=${r.gate?.verdict}`);
  check("error.code=blackbox_unreachable", r.gate?.error?.code === "blackbox_unreachable", `code=${r.gate?.error?.code}`);
  check("不可达快速短路（<30s，不做整轮探测）", r.durationMs < 30_000, `${r.durationMs}ms`);
  const report = readReport("unreachable");
  check("报告为黑盒模式且标记失败", report?.verdict?.outcome === "failed" && !!report?.blackbox, report?.blackbox?.url ?? "");

  const passed = checks.filter((c) => c.pass).length;
  console.log(`[BB] 断言: ${passed}/${checks.length} 通过`);
  if (passed !== checks.length) {
    console.error("[BB] 失败清单：");
    for (const c of checks.filter((x) => !x.pass)) console.error(`  - ${c.name}`);
    process.exit(1);
  }
  console.log("[BB] 全部通过 ✅");
  rmSync(demoDir, { recursive: true, force: true });
}

function log(title) {
  console.log(`\n[BB] ${title}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
