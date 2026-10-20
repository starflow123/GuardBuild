#!/usr/bin/env node
/**
 * Docker 沙箱 E2E：目标真实跑在容器里，攻击仍只走外部 HTTP。
 *
 *  ① 合法 Docker 契约（node:20-alpine + legacy-shop）→ gate exit 1；报告记录沙箱；
 *     容器全部清理；项目目录未被修改。
 *  ② docker.enabled=true 但缺少 image → exit 2 / docker_config_invalid；
 *     绝不静默回退到宿主机直接启动。
 *
 * 需要本机 Docker（Linux 容器）与 node:20-alpine 镜像；无 Docker 时跳过。
 * 用法: node scripts/e2e-docker.mjs
 */
import { spawn, spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const demoDir = path.join(repoRoot, ".demo-docker-e2e");
const fixture = path.join(repoRoot, "fixtures", "legacy-shop");
const reportsDir = path.join(demoDir, "reports");
const IMAGE = process.env.GUARDBUILD_DOCKER_TEST_IMAGE || "node:20-alpine";

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

function dockerAvailable() {
  const r = spawnSync("docker", ["version", "--format", "{{.Server.Version}}"], { encoding: "utf8" });
  return r.status === 0 ? r.stdout.trim() : null;
}

function dockerContainerNames() {
  const r = spawnSync("docker", ["ps", "-a", "--format", "{{.Names}}", "--filter", "name=guardbuild-"], {
    encoding: "utf8",
  });
  return r.status === 0 ? r.stdout.split(/\r?\n/).filter(Boolean).sort() : [];
}

function snapshot(dir) {
  const out = {};
  const walk = (d) => {
    for (const name of readdirSync(d)) {
      const p = path.join(d, name);
      const st = statSync(p);
      if (st.isDirectory()) {
        if (name === ".git") continue;
        walk(p);
      } else if (name !== "guardbuild.json") {
        out[path.relative(dir, p).replace(/\\/g, "/")] = st.size;
      }
    }
  };
  walk(dir);
  return out;
}

function makeWorkspace(name, { docker = true } = {}) {
  const ws = path.join(demoDir, name);
  cpSync(fixture, ws, { recursive: true });
  const serverPath = path.join(ws, "server.js");
  const src = readFileSync(serverPath, "utf8");
  const anchor = 'server.listen(port, "127.0.0.1", () => {';
  if (!src.includes(anchor)) throw new Error("server.listen 锚点未匹配");
  writeFileSync(
    serverPath,
    src.replace(anchor, 'server.listen(port, process.env.HOST || "127.0.0.1", () => {')
  );
  const cfgPath = path.join(ws, "guardbuild.json");
  const cfg = JSON.parse(readFileSync(cfgPath, "utf8"));
  cfg.start.env = { PORT: "${GB_PORT}", HOST: "0.0.0.0" };
  if (docker) {
    cfg.docker = {
      enabled: true,
      image: IMAGE,
      containerPort: 3000,
      workdir: "/app",
      readyTimeoutMs: 90_000,
    };
  } else {
    cfg.docker = { enabled: true };
  }
  writeFileSync(cfgPath, `${JSON.stringify(cfg, null, 2)}\n`);
  git(["init", "-q"], ws);
  git(["config", "user.email", "docker@guardbuild.local"], ws);
  git(["config", "user.name", "GuardBuild Docker"], ws);
  git(["config", "core.autocrlf", "false"], ws);
  git(["add", "-A"], ws);
  git(["commit", "-qm", `${name} 基线`], ws);
  return ws;
}

function runGate(project, label, timeoutMs = 300_000) {
  return new Promise((resolve, reject) => {
    const child = spawn(
      exe,
      ["--gate", "--project", project, "--report", path.join(reportsDir, label)],
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
      reject(new Error(`[gate:${label}] 超时 ${timeoutMs}ms`));
    }, timeoutMs);
    child.on("exit", (code) => {
      clearTimeout(timer);
      const gateLine = stdout.split("\n").filter((l) => l.startsWith("GB_GATE ")).pop();
      let gate = null;
      if (gateLine) {
        try {
          gate = JSON.parse(gateLine.slice("GB_GATE ".length));
        } catch {
          /* ignore */
        }
      }
      resolve({ code, gate, stdout, stderr });
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

async function main() {
  const version = dockerAvailable();
  if (!version) {
    console.log("[DOCKER] 未检测到可用 Docker，跳过（本用例需要 Linux 容器）");
    process.exit(0);
  }
  if (!existsSync(exe)) throw new Error(`headless 可执行文件不存在: ${exe}（先 cargo build --bin guardbuild-headless）`);
  rmSync(demoDir, { recursive: true, force: true });
  mkdirSync(demoDir, { recursive: true });

  console.log(`[DOCKER] Docker ${version}；镜像 ${IMAGE}`);
  const beforeContainers = dockerContainerNames();

  console.log("\n[DOCKER] 1/2 合法容器契约：完整 gate 流程");
  const ws = makeWorkspace("shop-docker", { docker: true });
  const before = snapshot(ws);
  const r = await runGate(ws, "docker-ok");
  const log = `${r.stdout}\n${r.stderr}`;
  check("退出码 = 1（漏洞证据成立）", r.code === 1, `code=${r.code}`);
  check("verdict=vulnerable 且补丁已验证", r.gate?.verdict === "vulnerable" && r.gate?.patchStatus === "verified",
    `verdict=${r.gate?.verdict} patchStatus=${r.gate?.patchStatus}`);
  check("通过 docker run 启动（非宿主机直接 spawn）", log.includes("[Docker] 启动容器 guardbuild-"), "");
  check("宿主端口 → 容器端口映射就绪", /目标容器「[^」]+」已就绪: http:\/\/127\.0\.0\.1:\d+ → 容器 :3000/.test(log), "");
  check("修复前/后目标均运行在容器（至少 2 个容器）",
    (log.match(/\[Docker\] 启动容器 /g) ?? []).length >= 2,
    `次数=${(log.match(/\[Docker\] 启动容器 /g) ?? []).length}`);
  const report = readReport("docker-ok");
  check("报告记录 Docker 沙箱配置",
    report?.targets?.docker?.enabled === true &&
      report.targets.docker.image === IMAGE &&
      report.targets.docker.containerPort === 3000,
    JSON.stringify(report?.targets?.docker ?? null));
  const md = existsSync(path.join(reportsDir, "docker-ok", "report.md"))
    ? readFileSync(path.join(reportsDir, "docker-ok", "report.md"), "utf8")
    : "";
  check("报告 Markdown 含 Docker 沙箱行", md.includes("Docker 沙箱") && md.includes(IMAGE));
  check("容器全部清理（含前置已有容器保持不变）",
    JSON.stringify(dockerContainerNames()) === JSON.stringify(beforeContainers),
    `before=${beforeContainers.length} after=${dockerContainerNames().length}`);
  check("gate 未修改被测项目（除报告目录外）", JSON.stringify(snapshot(ws)) === JSON.stringify(before));

  console.log("\n[DOCKER] 2/2 非法容器配置：必须显式失败，不得回退宿主机");
  const badWs = makeWorkspace("shop-bad-docker", { docker: false });
  const bad = await runGate(badWs, "docker-bad", 120_000);
  check("退出码 = 2", bad.code === 2, `code=${bad.code}`);
  check("error.code=docker_config_invalid", bad.gate?.error?.code === "docker_config_invalid",
    `code=${bad.gate?.error?.code}`);
  check("未回退到宿主机启动目标", !`${bad.stdout}\n${bad.stderr}`.includes("目标实例"), "");
  check("失败后同样无残留容器",
    JSON.stringify(dockerContainerNames()) === JSON.stringify(beforeContainers), "");

  const passed = checks.filter((c) => c.pass).length;
  console.log(`[DOCKER] 断言: ${passed}/${checks.length} 通过`);
  if (passed !== checks.length) {
    console.error("[DOCKER] 失败清单：");
    for (const c of checks.filter((x) => !x.pass)) console.error(`  - ${c.name}`);
    process.exit(1);
  }
  console.log("[DOCKER] 全部通过 ✅");
  rmSync(demoDir, { recursive: true, force: true });
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
