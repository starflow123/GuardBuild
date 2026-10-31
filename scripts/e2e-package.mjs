#!/usr/bin/env node
/**
 * 分发布局端到端演练：验证「没有系统 node 也能跑」的安装形态。
 *
 * 构造 .demo-package/app：
 *   guardbuild-headless(.exe) / runtime/node(.exe) / sidecar/{main.mjs,lib,recipes} / shared/
 * 目标项目复制 fixtures/bizlogic-shop，并把 start.cmd 改成随包 node 的绝对路径；
 * 子进程 PATH 只保留 git 与系统目录（不含 node）：
 *   ① 正常布局 → exit 1（业务逻辑漏洞复现），报告落盘；
 *   ② 移走 runtime/node → exit 2（Host 无法启动 Sidecar），证明随包运行时真的被使用。
 *
 * 同时校验资源映射与签名接口的纯函数行为（不调用签名工具）。
 *
 * 用法: node scripts/e2e-package.mjs   （需先构建 guardbuild-headless）
 */
import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { prepareRuntime, isSupportedNode, parseNodeVersion } from "./prepare-runtime.mjs";
import { buildDistOverlay, RESOURCE_MAP } from "./app-dist.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const demoDir = path.join(repoRoot, ".demo-package");
const appDir = path.join(demoDir, "app");
const fixture = path.join(repoRoot, "fixtures", "bizlogic-shop");
const nodeName = process.platform === "win32" ? "node.exe" : "node";
const exeName = process.platform === "win32" ? "guardbuild-headless.exe" : "guardbuild-headless";

function resolveHeadlessBin() {
  if (process.env.GUARDBUILD_HEADLESS_BIN) return process.env.GUARDBUILD_HEADLESS_BIN;
  const debug = path.join(repoRoot, "src-tauri", "target", "debug", exeName);
  return existsSync(debug) ? debug : path.join(repoRoot, "src-tauri", "target", "release", exeName);
}
const exe = resolveHeadlessBin();
const packagedExe = path.join(appDir, exeName);

const checks = [];
function check(name, cond, detail = "") {
  checks.push({ name, pass: !!cond });
  console.log(`${cond ? "  ✓" : "  ✗"} ${name}${detail ? ` — ${detail}` : ""}`);
  return !!cond;
}

function git(args, cwd) {
  const r = spawnSync("git", args, { cwd, encoding: "utf8" });
  if (r.status !== 0) throw new Error(`git ${args.join(" ")} 失败: ${r.stderr || r.stdout}`);
  return r.stdout.trim();
}

/** 沿用当前 PATH 但剔除一切含 node 可执行文件的目录，保留 git 与系统目录。 */
function pathWithoutNode() {
  const nodeDirs = [path.dirname(process.execPath)];
  return (process.env.PATH ?? "")
    .split(path.delimiter)
    .filter((p) => p && !nodeDirs.includes(p))
    .filter((p) => !existsSync(path.join(p, "node.exe")) && !existsSync(path.join(p, "node")))
    .join(path.delimiter);
}

/** Windows 上刚退出的子进程可能还压着 node.exe 的文件句柄，立刻 rename 会 EBUSY；等它松开。 */
function renameWhenFree(from, to, attempts = 24) {
  const buf = new Int32Array(new SharedArrayBuffer(4));
  for (let i = 0; i < attempts; i++) {
    try {
      renameSync(from, to);
      return true;
    } catch (e) {
      if (e.code !== "EBUSY" && e.code !== "EPERM") throw e;
      Atomics.wait(buf, 0, 0, 500);
    }
  }
  return false;
}

function runGate(project, label, { withRuntime = true } = {}) {
  const dataDir = path.join(demoDir, "data", label);
  const reportDir = path.join(demoDir, "reports", label);
  rmSync(reportDir, { recursive: true, force: true });
  const r = spawnSync(
    packagedExe,
    ["--gate", "--project", project, "--report", reportDir],
    {
      cwd: appDir,
      encoding: "utf8",
      timeout: 180_000,
      env: {
        PATH: pathWithoutNode(),
        SystemRoot: process.env.SystemRoot,
        TEMP: process.env.TEMP,
        TMP: process.env.TMP,
        USERPROFILE: process.env.USERPROFILE,
        GUARDBUILD_DATA_DIR: dataDir,
        GUARDBUILD_AUTO_CONSENT: "0",
      },
    }
  );
  return { status: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "", reportDir, dataDir };
}

function gateLine(stdout) {
  const line = stdout.split(/\r?\n/).find((l) => l.startsWith("GB_GATE "));
  return line ? JSON.parse(line.slice("GB_GATE ".length)) : null;
}

try {
  rmSync(demoDir, { recursive: true, force: true });
  mkdirSync(appDir, { recursive: true });
  if (!existsSync(exe)) throw new Error(`未找到 ${exe}，请先 npm run host:headless 或 cargo build`);

  // —— 布局：exe 同级 runtime / sidecar / shared ——
  cpSync(exe, packagedExe);
  const runtime = prepareRuntime({ destRoot: appDir });
  // 铺什么照 RESOURCE_MAP 抄，不在这里另写一份清单：这一路要验的就是「安装器会带哪些文件」，
  // 手抄一份会让「真实包缺文件」变成「演练照样通过」。runtime/ 由 prepareRuntime 负责。
  const packagedResources = Object.entries(RESOURCE_MAP).filter(([src]) => src.startsWith("../"));
  for (const [src, dest] of packagedResources) {
    const destPath = path.join(appDir, dest);
    mkdirSync(path.dirname(destPath), { recursive: true });
    cpSync(path.resolve(repoRoot, "src-tauri", src), destPath, { recursive: true });
  }

  check("随包 node 存在", existsSync(path.join(appDir, "runtime", nodeName)));
  check("sidecar 入口存在于 exe 同级", existsSync(path.join(appDir, "sidecar", "main.mjs")));
  check("shared 协议存在于 exe 同级", existsSync(path.join(appDir, "shared", "protocol.mjs")));
  const recipeSrcDir = path.join(repoRoot, "sidecar", "recipes");
  const packedRecipeDir = path.join(appDir, "sidecar", "recipes");
  const srcRecipes = readdirSync(recipeSrcDir).sort().join(",");
  const packedRecipes = existsSync(packedRecipeDir) ? readdirSync(packedRecipeDir).sort().join(",") : "(目录缺失)";
  // 装载器按 sidecar/lib/../recipes 找表，漏拷的后果不是「少一族攻击」而是整条判定链在建用例之前抛错
  check("随包配方目录逐文件对齐", srcRecipes === packedRecipes, `随包=${packedRecipes}`);
  check("Node 版本满足 >= 22.5", isSupportedNode(`v${process.versions.node}`), runtime.version);
  check("版本解析拒绝旧版本", parseNodeVersion("v20.11.1")?.[0] === 20 && !isSupportedNode("v20.11.1"));

  // —— 资源映射 / 签名接口纯函数 ——
  const overlay = buildDistOverlay({});
  check("分发资源映射含 sidecar/lib", overlay.bundle.resources["../sidecar/lib/"] === "sidecar/lib/");
  check("分发资源映射含 sidecar/recipes", overlay.bundle.resources["../sidecar/recipes/"] === "sidecar/recipes/");
  check("分发资源映射含 shared", overlay.bundle.resources["../shared/"] === "shared/");
  check("默认不签名", !overlay.bundle.windows.certificateThumbprint && !overlay.bundle.windows.signCommand);
  const signedOverlay = buildDistOverlay({
    GUARDBUILD_SIGN_CERT_THUMBPRINT: "ABCDEF0123456789",
    GUARDBUILD_SIGN_TIMESTAMP_URL: "http://ts.example.test",
  });
  check("证书指纹进入签名配置", signedOverlay.bundle.windows.certificateThumbprint === "ABCDEF0123456789");
  check("默认摘要 sha256", signedOverlay.bundle.windows.digestAlgorithm === "sha256");
  let rejected = false;
  try {
    buildDistOverlay({ GUARDBUILD_SIGN_COMMAND: "signtool sign" });
  } catch (e) {
    rejected = /%1/.test(e.message);
  }
  check("自定义签名命令缺 %1 被拒", rejected);
  check("运行时不进入资源映射键以外的仓库文件", !Object.keys(RESOURCE_MAP).some((k) => k.includes("tests")));

  // —— 目标项目：start.cmd 指向随包 node（PATH 里没有 node） ——
  const project = path.join(demoDir, "project");
  cpSync(fixture, project, { recursive: true });
  const cfgPath = path.join(project, "guardbuild.json");
  const cfg = JSON.parse(readFileSync(cfgPath, "utf8"));
  cfg.start.cmd = path.join(appDir, "runtime", nodeName);
  writeFileSync(cfgPath, `${JSON.stringify(cfg, null, 2)}\n`);
  git(["init", "-q"], project);
  git(["config", "user.email", "gate@guardbuild.local"], project);
  git(["config", "user.name", "GuardBuild Gate"], project);
  git(["add", "-A"], project);
  git(["commit", "-qm", "package 基线"], project);

  console.log("\n① 完整安装布局（PATH 无 node）");
  const ok = runGate(project, "ok");
  const okGate = gateLine(ok.stdout);
  if (ok.status !== 1) console.error(`[debug] stdout:\n${ok.stdout}\n[debug] stderr:\n${ok.stderr}`);
  check("gate 完成（exit 1）", ok.status === 1, `exit=${ok.status}`);
  check("裁决为 vulnerable_unfixed", okGate?.verdict === "vulnerable_unfixed", okGate?.verdict ?? "(无 GB_GATE)");
  check("报告已落盘", existsSync(path.join(ok.reportDir, "report.json")));
  check("被测工作区未被修改", git(["status", "--porcelain"], project) === "");
  check("负向对照前运行时仍在", existsSync(path.join(appDir, "runtime", nodeName)));

  console.log("\n② 移除随包 node（PATH 无 node）");
  const runtimeNode = path.join(appDir, "runtime", nodeName);
  const hidden = `${runtimeNode}.bak`;
  // 移不走就验不了负向对照；这里如实记一条失败，而不是让整轮以 uncaught EBUSY 收场
  const moved = renameWhenFree(runtimeNode, hidden);
  check("随包 node 能从布局移走", moved);
  const bad = runGate(project, "no-runtime");
  check("缺少运行时时 gate 失败（exit 2）", bad.status === 2, `exit=${bad.status}`);
  check("失败信息指向启动 Sidecar", /Sidecar|sidecar|node/i.test(`${bad.stdout}${bad.stderr}`));
  if (moved) renameWhenFree(hidden, runtimeNode);
} finally {
  if (process.env.GUARDBUILD_KEEP_DEMO === "1") console.log(`[debug] 保留 ${demoDir}`);
  else {
    try {
      rmSync(demoDir, { recursive: true, force: true });
    } catch (e) {
      console.log(`[warn] 演示目录清理未完成（${e.code}），残留 ${demoDir}`);
    }
  }
}

const failed = checks.filter((c) => !c.pass);
console.log(`\n${failed.length ? "✗" : "✓"} 分发布局演练：${checks.length - failed.length}/${checks.length} 断言通过`);
if (failed.length) {
  for (const f of failed) console.error(`  - ${f.name}`);
  process.exit(1);
}
