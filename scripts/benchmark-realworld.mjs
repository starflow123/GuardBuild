#!/usr/bin/env node
/**
 * 第三方真实靶场基准：对上游公开靶场（真代码、真框架）跑真实黑盒扫描。
 *
 * 为什么要单独一层：自建 fixture 的路径、参数名、加固开关都是我们自己挑的，
 * 「召回 100%」只证明引擎在自家框架里自洽。这一层用别人的代码检验同一批判据
 * 在陌生工程里是否还成立，并把「未标注的发现」如实列出来供人工核对。
 *
 * 口径：
 * - 靶场缺失（本机没这份代码）或起不来（依赖没装）→ **跳过**，不判失败；
 * - 用 `--require=<id>` 显式声明「这一轮必须跑到」时，跳过才判失败（CI 供给靶场时用）；
 * - expectedVulnerable 来自上游自己声明的漏洞清单 + 逐行核对源码；
 * - 只有「结构上不可能存在该族端点」才写进 forbiddenVulnerable 当误报判据；
 *   真实靶场的否定断言必须人工核实过全部端点，否则宁可作为未标注项列出。
 *
 * 用法:
 *   node scripts/benchmark-realworld.mjs
 *   node scripts/benchmark-realworld.mjs --only=vulnapi
 *   node scripts/benchmark-realworld.mjs --require=vulnapi
 *   GUARDBUILD_REAL_DIR=D:/AiAgent/dogfood node scripts/benchmark-realworld.mjs
 */
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const benchRoot = path.join(repoRoot, ".benchmark-realworld");
const corpusPath = path.join(repoRoot, "benchmarks", "realworld-corpus.json");

function argValue(name) {
  const hit = process.argv.slice(2).find((a) => a.startsWith(`${name}=`));
  return hit ? hit.slice(name.length + 1) : null;
}
const only = new Set((argValue("--only") ?? "").split(",").map((s) => s.trim()).filter(Boolean));
const mustRun = new Set((argValue("--require") ?? "").split(",").map((s) => s.trim()).filter(Boolean));
const keep = process.argv.includes("--keep");

function resolveHeadlessBin() {
  if (process.env.GUARDBUILD_HEADLESS_BIN) return process.env.GUARDBUILD_HEADLESS_BIN;
  const name = process.platform === "win32" ? "guardbuild-headless.exe" : "guardbuild-headless";
  const debug = path.join(repoRoot, "src-tauri", "target", "debug", name);
  return existsSync(debug) ? debug : path.join(repoRoot, "src-tauri", "target", "release", name);
}
const exe = resolveHeadlessBin();

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const port = srv.address().port;
      srv.close(() => resolve(port));
    });
  });
}

function missingRequires(dir, target) {
  return (target.requires ?? []).filter((rel) => !existsSync(path.join(dir, rel)));
}

function startTarget(dir, target, port) {
  const start = target.start;
  const args = (start.args ?? []).map((a) => String(a).replace("${GB_PORT}", String(port)));
  return new Promise((resolve, reject) => {
    const child = spawn(start.cmd, args, {
      cwd: dir,
      env: { ...process.env, ...(start.env ?? {}) },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let out = "";
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`启动超时（${start.readyTimeoutMs ?? 60_000}ms）：${out.slice(-400)}`));
    }, start.readyTimeoutMs ?? 60_000);
    const readyRe = new RegExp(start.readyPattern ?? "listening on port|Uvicorn running on|GBREADY", "i");
    const onData = (b) => {
      out += b.toString();
      const clean = out.replace(/\x1b\[[0-9;]*m/g, "");
      if (!readyRe.test(clean)) return;
      const m =
        clean.match(/GBREADY\s*\{[^}]*"port"\s*:\s*(\d+)/i) ??
        clean.match(/listening on port\s+(\d+)/i) ??
        clean.match(/https?:\/\/127\.0\.0\.1:(\d+)/i) ??
        clean.match(/(?:port|端口)\s*[:=]?\s*(\d{2,5})/i);
      const realPort = m ? Number(m[1]) : port;
      // 端口 0 是「还没分配」的占位（应用先打印自己的配置行），必须等真实端口出现
      if (!realPort || realPort === 0) return;
      clearTimeout(timer);
      child.stdout.off("data", onData);
      resolve({ child, port: realPort, log: out });
    };
    child.stdout.on("data", onData);
    child.stderr.on("data", onData);
    child.on("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`目标进程提前退出（code=${code}）：${out.slice(-400)}`));
    });
  });
}

function stopTarget(child) {
  return new Promise((resolve) => {
    if (!child || child.exitCode != null) return resolve();
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      resolve();
    }, 5_000);
    child.once("exit", () => {
      clearTimeout(timer);
      resolve();
    });
    child.kill();
  });
}

function runScan(dir, port, target) {
  const dataDir = path.join(benchRoot, "data", target.id);
  const reportDir = path.join(benchRoot, "reports", target.id);
  rmSync(dataDir, { recursive: true, force: true });
  rmSync(reportDir, { recursive: true, force: true });
  mkdirSync(dataDir, { recursive: true });

  return new Promise((resolve) => {
    const startedAt = Date.now();
    const child = spawn(
      exe,
      ["--url", `http://127.0.0.1:${port}`, "--project", dir, "--gate", "--report", reportDir],
      {
        cwd: repoRoot,
        env: {
          ...process.env,
          GUARDBUILD_DATA_DIR: dataDir,
          GUARDBUILD_SIDECAR: path.join(repoRoot, "sidecar", "main.mjs"),
          GUARDBUILD_LLM_SCOUT: "",
          GUARDBUILD_LLM_PATCH: "",
          GUARDBUILD_LLM_ATTACKPLAN: "",
          GUARDBUILD_LLM_CROSSFILE: "",
          GUARDBUILD_LLM_BOOTSTRAP: "",
          DEEPSEEK_API_KEY: "",
          DEEPSEEK_BASE_URL: "",
          GUARDBUILD_BLACKBOX_MUTATE: "",
          GUARDBUILD_BLACKBOX_DELETE: "",
          ...(target.env ?? {}),
        },
        stdio: ["ignore", "pipe", "pipe"],
      }
    );
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (b) => { stdout += b.toString(); });
    child.stderr.on("data", (b) => { stderr += b.toString(); });
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill();
    }, target.timeoutMs ?? 420_000);
    const finish = (error) => {
      clearTimeout(timer);
      let report = null;
      const reportPath = path.join(reportDir, "report.json");
      if (existsSync(reportPath)) {
        try {
          report = JSON.parse(readFileSync(reportPath, "utf8"));
        } catch {
          /* 报告损坏 */
        }
      }
      resolve({ code: child.exitCode, report, timedOut, error: error ?? null, durationMs: Date.now() - startedAt, stderr });
    };
    child.on("error", (e) => finish(e.message));
    child.on("exit", () => finish(null));
  });
}

function ruleMatches(caseId, rule) {
  return rule.endsWith("*") ? caseId.startsWith(rule.slice(0, -1)) : caseId === rule;
}

function evaluate(target, run) {
  const evidence = run.report?.evidence?.blackbox ?? [];
  const vulnerable = [...new Set(evidence.filter((e) => e.verdict === "vulnerable").map((e) => e.caseId))];
  const expected = target.expectedVulnerable ?? [];
  const forbidden = target.forbiddenVulnerable ?? [];
  const matched = expected.filter((rule) => vulnerable.some((id) => ruleMatches(id, rule)));
  const missed = expected.filter((rule) => !matched.includes(rule));
  const forbiddenHits = vulnerable.filter((id) => forbidden.some((rule) => ruleMatches(id, rule)));
  const labeled = new Set(vulnerable.filter((id) => expected.some((rule) => ruleMatches(id, rule))));
  const unlabeled = [...new Set(vulnerable.filter((id) => !labeled.has(id) && !forbiddenHits.some((f) => ruleMatches(id, f))))];

  const exitOk = !run.error && !run.timedOut && run.code === target.expectedExit;
  const actualOutcome = run.report?.verdict?.outcome ?? null;
  const outcomeOk = !target.expectedOutcomes || target.expectedOutcomes.includes(actualOutcome);
  const bb = run.report?.blackbox ?? {};
  const openapiOk = target.expectOpenapiFound === undefined ? true : !!bb.openapiFound === !!target.expectOpenapiFound;
  const pass = exitOk && outcomeOk && openapiOk && missed.length === 0 && forbiddenHits.length === 0;

  return {
    id: target.id,
    name: target.name,
    pass,
    skipped: false,
    expectOpenapiFound: target.expectOpenapiFound,
    durationMs: run.durationMs,
    exit: { actual: run.code ?? null, expected: target.expectedExit, ok: exitOk, timedOut: !!run.timedOut, error: run.error ?? null },
    outcome: { actual: actualOutcome, expected: target.expectedOutcomes ?? null, ok: outcomeOk },
    discovery: {
      routeCount: bb.routeCount ?? 0,
      openapiFound: !!bb.openapiFound,
      openapiRouteCount: bb.openapiRouteCount ?? 0,
      frontendRouteCount: bb.frontendRouteCount ?? 0,
      frontendNextManifest: bb.frontendNextManifest ?? 0,
      seoRouteCount: bb.seoRouteCount ?? 0,
      bySource: (bb.routes ?? []).reduce((acc, r) => {
        acc[r.source ?? "unknown"] = (acc[r.source ?? "unknown"] ?? 0) + 1;
        return acc;
      }, {}),
      openapiOk,
    },
    cases: { expected, matched, missed, forbiddenHits, unlabeled, actual: vulnerable },
    verdicts: {
      blocked: evidence.filter((e) => e.verdict === "blocked").map((e) => e.caseId),
      inconclusive: evidence.filter((e) => e.verdict === "inconclusive").map((e) => e.caseId),
    },
    reportPath: run.report ? path.join(benchRoot, "reports", target.id, "report.json") : null,
    stderrTail: (run.stderr ?? "").slice(-400),
  };
}

function skipResult(target, reason) {
  return {
    id: target.id,
    name: target.name,
    pass: true,
    skipped: true,
    skipReason: reason,
    durationMs: 0,
    exit: { actual: null, expected: target.expectedExit, ok: false },
    outcome: { actual: null, expected: target.expectedOutcomes ?? null, ok: false },
    discovery: { routeCount: 0, openapiFound: false, openapiRouteCount: 0, frontendRouteCount: 0, frontendNextManifest: 0, seoRouteCount: 0, bySource: {}, openapiOk: true },
    cases: { expected: target.expectedVulnerable ?? [], matched: [], missed: [], forbiddenHits: [], unlabeled: [], actual: [] },
    verdicts: { blocked: [], inconclusive: [] },
    reportPath: null,
  };
}

function buildMarkdown(meta, results) {
  const run = results.filter((r) => !r.skipped);
  const skipped = results.filter((r) => r.skipped);
  const tp = run.reduce((n, r) => n + r.cases.matched.length, 0);
  const fn = run.reduce((n, r) => n + r.cases.missed.length, 0);
  const fp = run.reduce((n, r) => n + r.cases.forbiddenHits.length, 0);
  const unlabeled = run.reduce((n, r) => n + r.cases.unlabeled.length, 0);
  const lines = [];
  lines.push("# 第三方真实靶场基准");
  lines.push("");
  lines.push(`- 生成时间：${meta.generatedAt}`);
  lines.push(`- 提交：\`${meta.gitHead ?? "未知"}\` · 语料版本 ${meta.corpusVersion}`);
  lines.push(`- 靶场根目录：\`${meta.realDir}\``);
  lines.push(`- 实跑 ${run.length} 个 / 跳过 ${skipped.length} 个`);
  lines.push(`- 标注召回：${tp}/${tp + fn} · 结构不可能族命中（判误报）：${fp} · 未标注发现（仅列出，人工核对）：${unlabeled}`);
  lines.push("");
  lines.push("## 靶场明细");
  lines.push("");
  lines.push("| 靶场 | 退出码（实际/期望） | 命中/标注 | 漏报 | 禁止族命中 | 未标注 | 路由（openapi/frontend/robots/sitemap/brute） | 用时 | 结论 |");
  lines.push("| --- | --- | --- | --- | --- | --- | --- | --- | --- |");
  for (const r of results) {
    if (r.skipped) {
      lines.push(`| ${r.id} | — | — | — | — | — | — | — | 跳过：${r.skipReason} |`);
      continue;
    }
    const d = r.discovery;
    const src = `${d.bySource.openapi ?? 0}/${d.bySource.frontend ?? 0}/${d.bySource.robots ?? 0}/${d.bySource.sitemap ?? 0}/${d.bySource.brute ?? 0}`;
    lines.push(
      `| ${r.id} | ${r.exit.actual ?? "—"}/${r.exit.expected} | ${r.cases.matched.length}/${r.cases.expected.length} | ${r.cases.missed.length} | ${r.cases.forbiddenHits.length} | ${r.cases.unlabeled.length} | ${d.routeCount}（${src}） | ${(r.durationMs / 1000).toFixed(1)}s | ${r.pass ? "通过" : "失败"} |`
    );
  }
  lines.push("");
  const withUnlabeled = run.filter((r) => r.cases.unlabeled.length);
  if (withUnlabeled.length) {
    lines.push("## 未标注发现（不代表误报，需人工核对上游是否真有该问题）");
    lines.push("");
    for (const r of withUnlabeled) lines.push(`- **${r.id}**：${r.cases.unlabeled.map((x) => `\`${x}\``).join("、")}`);
    lines.push("");
  }
  const failures = run.filter((r) => !r.pass);
  if (failures.length) {
    lines.push("## 失败明细");
    lines.push("");
    for (const r of failures) {
      lines.push(`### ${r.id}`);
      for (const m of r.cases.missed) lines.push(`- 漏报（标注族未命中）：\`${m}\``);
      for (const f of r.cases.forbiddenHits) lines.push(`- 禁止族命中（结构上不该有该端点）：\`${f}\``);
      if (!r.exit.ok) lines.push(`- 退出码 ${r.exit.actual ?? "—"} != ${r.exit.expected}${r.exit.timedOut ? "（超时）" : ""}${r.exit.error ? `（${r.exit.error}）` : ""}`);
      if (!r.outcome.ok) lines.push(`- 终态 ${r.outcome.actual ?? "—"} 不在 ${(r.outcome.expected ?? []).join("/")}`);
      if (!r.discovery.openapiOk) lines.push(`- OpenAPI 期望 ${r.expectOpenapiFound ?? "?"}，实际 ${r.discovery.openapiFound}`);
      if (r.stderrTail) lines.push(`- stderr 尾部：\`\`\`\n${r.stderrTail}\n\`\`\``);
      lines.push("");
    }
  }
  if (skipped.length) {
    lines.push("## 跳过说明");
    lines.push("");
    for (const r of skipped) lines.push(`- ${r.id}：${r.skipReason}`);
    lines.push("");
    lines.push("跳过不计入失败，也不代表能力缺失——只有用 `--require=<id>` 显式要求实跑时才会判红。");
    lines.push("");
  }
  lines.push("## 口径");
  lines.push("");
  lines.push("- 标注来自上游作者声明的漏洞清单与逐行源码核对；未标注发现只列出，不自动算误报。");
  lines.push("- 禁止族只写「路由表里结构上不存在该端点」的类别，避免把未知真实问题读成误报。");
  lines.push("- 零模型调用：清空 LLM 开关与密钥；写/破坏性探测默认关闭。");
  lines.push("");
  return lines.join("\n");
}

async function main() {
  if (!existsSync(exe)) throw new Error(`未找到无头宿主: ${exe}`);
  const corpus = JSON.parse(readFileSync(corpusPath, "utf8"));
  const realDir = process.env[corpus.realDirEnv ?? "GUARDBUILD_REAL_DIR"] ?? corpus.defaultRealDir;
  const targets = corpus.targets.filter((t) => only.size === 0 || only.has(t.id));
  if (targets.length === 0) throw new Error(`--only 未匹配任何靶场: ${[...only].join(",")}`);

  if (!keep) rmSync(benchRoot, { recursive: true, force: true });
  mkdirSync(benchRoot, { recursive: true });

  console.log(`[RW-BENCH] ${targets.length} 个第三方靶场，宿主 ${exe}，靶场根 ${realDir}`);
  const results = [];
  for (let i = 0; i < targets.length; i++) {
    const target = targets[i];
    const dir = path.join(realDir, target.dir);
    process.stdout.write(`[RW-BENCH] ${i + 1}/${targets.length} ${target.id} …`);
    if (!existsSync(dir)) {
      results.push(skipResult(target, `目录不存在 ${dir}`));
      console.log(` ⊘ 目录不存在 ${dir}`);
      continue;
    }
    const missing = missingRequires(dir, target);
    if (missing.length) {
      results.push(skipResult(target, `缺少 ${missing.join("、")}（依赖/构建产物未准备）`));
      console.log(` ⊘ 缺少 ${missing.join("、")}`);
      continue;
    }
    let server = null;
    try {
      const port = await freePort();
      const started = await startTarget(dir, target, port);
      server = started.child;
      const run = await runScan(dir, started.port, target);
      const result = evaluate(target, run);
      results.push(result);
      const c = result.cases;
      console.log(
        ` exit=${result.exit.actual ?? "—"}/${result.exit.expected} 命中=${c.matched.length}/${c.expected.length} 漏报=${c.missed.length} 禁止族=${c.forbiddenHits.length} 未标注=${c.unlabeled.length} 路由=${result.discovery.routeCount} ${(result.durationMs / 1000).toFixed(1)}s ${result.pass ? "✓" : "✗"}`
      );
      for (const m of c.missed) console.log(`        漏报 ${m}`);
      for (const f of c.forbiddenHits) console.log(`        禁止族命中 ${f}`);
      for (const u of c.unlabeled) console.log(`        未标注 ${u}`);
      if (!result.exit.ok) console.log(`        退出码 ${result.exit.actual ?? "—"} != ${result.exit.expected}${result.exit.error ? `（${result.exit.error}）` : ""}`);
      if (!result.outcome.ok) console.log(`        终态 ${result.outcome.actual ?? "—"} 不在 ${(result.outcome.expected ?? []).join("/")}`);
    } catch (e) {
      // 起不来多半是这台机器没装依赖，不是引擎回归 → 跳过，但把原因写清楚
      results.push(skipResult(target, `启动失败：${e.message}`));
      console.log(` ⊘ 启动失败：${e.message}`);
    } finally {
      await stopTarget(server);
    }
  }

  const runResults = results.filter((r) => !r.skipped);
  const skipped = results.filter((r) => r.skipped);
  const tp = runResults.reduce((n, r) => n + r.cases.matched.length, 0);
  const fn = runResults.reduce((n, r) => n + r.cases.missed.length, 0);
  const fp = runResults.reduce((n, r) => n + r.cases.forbiddenHits.length, 0);
  const unlabeled = runResults.reduce((n, r) => n + r.cases.unlabeled.length, 0);
  const exitOk = runResults.filter((r) => r.exit.ok).length;
  const passed = runResults.filter((r) => r.pass).length;
  const requiredSkipped = skipped.filter((r) => mustRun.has(r.id));
  const pass = runResults.every((r) => r.pass) && requiredSkipped.length === 0;

  const gitHead = spawnSync("git", ["rev-parse", "--short", "HEAD"], { cwd: repoRoot, encoding: "utf8" }).stdout?.trim() || null;
  const meta = {
    generatedAt: new Date().toISOString(),
    gitHead,
    corpusVersion: corpus.version,
    realDir,
    pass,
    metrics: { tp, fn, fp, unlabeled, exitOk, targets: runResults.length, passed, skipped: skipped.length },
  };
  writeFileSync(path.join(benchRoot, "benchmark-report.json"), JSON.stringify({ ...meta, results }, null, 2));
  writeFileSync(path.join(benchRoot, "benchmark-report.md"), buildMarkdown(meta, results));

  console.log("");
  console.log(
    `[RW-BENCH] 实跑 ${runResults.length}/${targets.length}（跳过 ${skipped.length}）· 召回 ${tp}/${tp + fn} · 禁止族命中 ${fp} · 未标注 ${unlabeled} · 退出码一致 ${exitOk}/${runResults.length}`
  );
  console.log(`[RW-BENCH] 报告：${path.join(benchRoot, "benchmark-report.md")}`);
  if (requiredSkipped.length) console.log(`[RW-BENCH] 未通过：要求实跑的靶场被跳过 → ${requiredSkipped.map((r) => `${r.id}（${r.skipReason}）`).join("；")}`);
  console.log(pass ? "[RW-BENCH] 实跑靶场全部通过 ✅" : "[RW-BENCH] 存在未通过靶场 ❌");
  return pass;
}

main()
  .then((pass) => {
    process.exitCode = pass ? 0 : 1;
  })
  .catch((e) => {
    console.error(`[RW-BENCH] 执行失败: ${e.message}`);
    process.exitCode = 2;
  });
