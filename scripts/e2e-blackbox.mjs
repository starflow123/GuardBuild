#!/usr/bin/env node
/**
 * 纯黑盒外部模式 E2E：真实 HTTP 目标 + Host 网络/保险库 + gate 退出码。
 *
 *   ① 漏洞目标（legacy-shop IDOR） → exit 1，findingCount=1，cross-proven 证据
 *   ② 已修复目标（同一路由加归属校验） → exit 0，no_findings
 *   ③ 目标不可达 → exit 2，failed（且应在 30s 内短路，不做无意义探测）
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

function makeShop(name, { fixed = false } = {}) {
  const dir = path.join(demoDir, name);
  cpSync(fixture, dir, { recursive: true });
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

function startServer(dir) {
  return new Promise((resolve, reject) => {
    const child = spawn("node", ["server.js"], {
      cwd: dir,
      env: { ...process.env, PORT: "0" },
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

function runBlackbox({ url, project, label, timeoutMs = 120_000 }) {
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

  log("1/3 漏洞目标");
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
    const raw = JSON.stringify(report ?? {});
    check("报告不含真实令牌（仅 vault 占位）", !/Bearer\s+(?!\*\*\*|<)[A-Za-z0-9._-]{16,}/.test(raw), raw.match(/Bearer [^"]{0,24}/)?.[0] ?? "");
    check("原 fixture 未被修改（黑盒不改码）", JSON.stringify(snapshot(vulnShop)) === JSON.stringify(before));
  } finally {
    vuln.child.kill();
  }

  log("2/3 已修复目标");
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
  } finally {
    fixed.child.kill();
  }

  log("3/3 不可达目标");
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
