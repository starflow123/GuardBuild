#!/usr/bin/env node
/**
 * 黑盒精度基准：对固定标注靶场逐个跑真实黑盒扫描，量化
 * 「漏报 / 误报 / 退出码 / 用例族覆盖 / 路由发现来源」。
 *
 * 语料：benchmarks/blackbox-corpus.json。每条规则支持精确 caseId 或前缀（尾部 *）；
 * forbiddenVulnerable 优先于 expectedVulnerable——否则 blackbox-idor-* 会把
 * 写/删/CSRF 变体一并放过，默认档「写探测不该出现」就失去意义。
 * 靶场可以声明 declarative patches（源码插入）、configPatch/configReplace（guardbuild.json）、
 * serverEnv（目标进程环境）、env（扫描端环境，如 allowMutation）。
 *
 * 口径：黑盒用例没有引擎生成的编号变体，caseId 即真实请求路径，因此本次不折叠变体。
 * 任何漏报、误报、退出码/终态不一致都会让基准非零退出。
 *
 * 闭环两层（benchmarks/ 下进仓库）：failure-ledger.jsonl 五类归档、green-baseline.json
 * 绿名单；相对绿名单回退任意一条即整轮否决。两套套件共享同一份账本，按 suite 隔离。
 *
 * 用法:
 *   node scripts/benchmark-blackbox.mjs                # 全量
 *   node scripts/benchmark-blackbox.mjs --only=spa-shop  # 局部跑：不更新绿名单，也不关账
 *   node scripts/benchmark-blackbox.mjs --keep         # 保留上一轮产物
 *   node scripts/benchmark-blackbox.mjs --rebaseline   # 重建黑盒绿名单（仅整轮全绿时被接受）
 */
import { spawn, spawnSync } from "node:child_process";
import {
  cpSync,
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { appendLedger, classifyRun, greenKeysOf } from "../sidecar/lib/failureledger.mjs";
import { gateAgainstBaseline } from "../sidecar/lib/regression.mjs";
import { consoleLoopLines, loopSection } from "./lib/loopsummary.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const benchRoot = path.join(repoRoot, ".benchmark-blackbox");
const corpusPath = path.join(repoRoot, "benchmarks", "blackbox-corpus.json");
const SUITE = "blackbox";
const ledgerPath = path.join(repoRoot, "benchmarks", "failure-ledger.jsonl");
const baselinePath = path.join(repoRoot, "benchmarks", "green-baseline.json");

function argValue(name) {
  const hit = process.argv.slice(2).find((a) => a.startsWith(`${name}=`));
  return hit ? hit.slice(name.length + 1) : null;
}

const only = new Set((argValue("--only") ?? "").split(",").map((s) => s.trim()).filter(Boolean));
const keep = process.argv.includes("--keep");
const rebaseline = process.argv.includes("--rebaseline");

function resolveHeadlessBin() {
  if (process.env.GUARDBUILD_HEADLESS_BIN) return process.env.GUARDBUILD_HEADLESS_BIN;
  const name = process.platform === "win32" ? "guardbuild-headless.exe" : "guardbuild-headless";
  const debug = path.join(repoRoot, "src-tauri", "target", "debug", name);
  return existsSync(debug) ? debug : path.join(repoRoot, "src-tauri", "target", "release", name);
}
const exe = resolveHeadlessBin();

function deepMerge(base, patch) {
  const out = { ...(base && typeof base === "object" && !Array.isArray(base) ? base : {}) };
  for (const [k, v] of Object.entries(patch ?? {})) out[k] = deepMerge(out[k], v);
  return out;
}

function makeWorkspace(target) {
  const ws = path.join(benchRoot, "workspaces", target.id);
  rmSync(ws, { recursive: true, force: true });
  cpSync(path.join(repoRoot, target.fixture), ws, { recursive: true });

  for (const patch of target.patches ?? []) {
    const file = path.join(ws, patch.file);
    const src = readFileSync(file, "utf8");
    if (!src.includes(patch.search)) throw new Error(`${target.id}: 补丁锚点未匹配（${patch.file}）`);
    writeFileSync(file, src.replace(patch.search, `${patch.search}${patch.insertAfter}`));
  }

  if (target.configPatch || target.configReplace) {
    const cfgPath = path.join(ws, "guardbuild.json");
    let cfg = JSON.parse(readFileSync(cfgPath, "utf8"));
    if (target.configPatch) cfg = deepMerge(cfg, target.configPatch);
    for (const [k, v] of Object.entries(target.configReplace ?? {})) cfg[k] = v;
    writeFileSync(cfgPath, `${JSON.stringify(cfg, null, 2)}\n`);
  }
  return ws;
}

function startTarget(ws, target) {
  const cfg = JSON.parse(readFileSync(path.join(ws, "guardbuild.json"), "utf8"));
  const start = cfg.start;
  if (!start?.cmd) throw new Error(`${target.id}: guardbuild.json 缺少 start.cmd`);
  return new Promise((resolve, reject) => {
    const child = spawn(start.cmd, start.args ?? [], {
      cwd: ws,
      env: { ...process.env, ...(start.env ?? {}), ...(target.serverEnv ?? {}) },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let out = "";
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`${target.id}: 目标服务启动超时（${start.readyTimeoutMs ?? 20_000}ms）：${out.slice(-300)}`));
    }, start.readyTimeoutMs ?? 20_000);
    const onData = (b) => {
      out += b.toString();
      const clean = out.replace(/\x1b\[[0-9;]*m/g, "");
      const m =
        clean.match(/listening on port\s+(\d+)/i) ??
        clean.match(/GB_LISTEN\s*\{[^}]*"port"\s*:\s*(\d+)/i) ??
        clean.match(/https?:\/\/127\.0\.0\.1:(\d+)/i) ??
        clean.match(/(?:port|端口)\s*[:=]?\s*(\d{2,5})/i);
      if (m) {
        clearTimeout(timer);
        child.stdout.off("data", onData);
        resolve({ child, port: Number(m[1]) });
      }
    };
    child.stdout.on("data", onData);
    child.stderr.on("data", onData);
    child.on("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`${target.id}: 目标服务提前退出（code=${code}）：${out.slice(-400)}`));
    });
  });
}

function stopTarget(child) {
  return new Promise((resolve) => {
    if (!child || child.exitCode != null) return resolve();
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      resolve();
    }, 3_000);
    child.once("exit", () => {
      clearTimeout(timer);
      resolve();
    });
    child.kill();
  });
}

function runScan(ws, port, target) {
  const dataDir = path.join(benchRoot, "data", target.id);
  const reportDir = path.join(benchRoot, "reports", target.id);
  rmSync(dataDir, { recursive: true, force: true });
  rmSync(reportDir, { recursive: true, force: true });
  mkdirSync(dataDir, { recursive: true });
  const timeoutMs = target.timeoutMs ?? 180_000;

  return new Promise((resolve) => {
    const startedAt = Date.now();
    const child = spawn(
      exe,
      ["--url", `http://127.0.0.1:${port}`, "--project", ws, "--gate", "--report", reportDir],
      {
        cwd: repoRoot,
        env: {
          ...process.env,
          GUARDBUILD_DATA_DIR: dataDir,
          GUARDBUILD_SIDECAR: path.join(repoRoot, "sidecar", "main.mjs"),
          GUARDBUILD_LLM_SCOUT: "",
          GUARDBUILD_LLM_PATCH: "",
          DEEPSEEK_API_KEY: "",
          DEEPSEEK_BASE_URL: "",
          GUARDBUILD_BLACKBOX_URL: "",
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
    }, timeoutMs);
    const finish = (error) => {
      clearTimeout(timer);
      const gateLine = stdout.split("\n").filter((l) => l.startsWith("GB_GATE ")).pop();
      let gate = null;
      if (gateLine) {
        try { gate = JSON.parse(gateLine.slice("GB_GATE ".length)); } catch { /* ignore */ }
      }
      let report = null;
      const reportPath = path.join(reportDir, "report.json");
      if (existsSync(reportPath)) {
        try { report = JSON.parse(readFileSync(reportPath, "utf8")); } catch { /* ignore */ }
      }
      resolve({ code: child.exitCode, gate, report, reportPath: existsSync(reportPath) ? reportPath : null, timedOut, error: error ?? null, durationMs: Date.now() - startedAt, stdout, stderr });
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
  const missed = expected.filter((rule) => !vulnerable.some((id) => ruleMatches(id, rule)));
  const forbiddenHits = vulnerable.filter((id) => forbidden.some((rule) => ruleMatches(id, rule)));
  const unannotated = vulnerable.filter((id) => !expected.some((rule) => ruleMatches(id, rule)));
  const falsePositives = [...new Set([...forbiddenHits, ...unannotated])];

  const exitOk = !run.error && !run.timedOut && run.code === target.expectedExit;
  const actualOutcome = run.report?.verdict?.outcome ?? null;
  const outcomeOk = !target.expectedOutcomes || target.expectedOutcomes.includes(actualOutcome);
  const pass = exitOk && outcomeOk && missed.length === 0 && falsePositives.length === 0;

  const routes = run.report?.blackbox?.routes ?? [];
  const discovery = {
    routeCount: run.report?.blackbox?.routeCount ?? routes.length,
    bySource: routes.reduce((acc, r) => {
      acc[r.source ?? "unknown"] = (acc[r.source ?? "unknown"] ?? 0) + 1;
      return acc;
    }, {}),
    openapiFound: run.report?.blackbox?.openapiFound ?? false,
    openapiRouteCount: run.report?.blackbox?.openapiRouteCount ?? 0,
    frontendRouteCount: run.report?.blackbox?.frontendRouteCount ?? 0,
    frontendScripts: run.report?.blackbox?.frontendScripts ?? 0,
    frontendNextManifest: run.report?.blackbox?.frontendNextManifest ?? 0,
    seoRouteCount: run.report?.blackbox?.seoRouteCount ?? 0,
  };

  return {
    id: target.id,
    pass,
    durationMs: run.durationMs,
    exit: { actual: run.code ?? null, expected: target.expectedExit, ok: exitOk, timedOut: !!run.timedOut, error: run.error ?? null },
    outcome: { actual: actualOutcome, expected: target.expectedOutcomes ?? null, ok: outcomeOk },
    findingsCount: evidence.filter((e) => e.verdict === "vulnerable").length,
    cases: { expected, actual: vulnerable, matched, missed, falsePositives, forbiddenHits, unannotated },
    verdicts: {
      blocked: evidence.filter((e) => e.verdict === "blocked").map((e) => e.caseId),
      inconclusive: evidence.filter((e) => e.verdict === "inconclusive").map((e) => e.caseId),
    },
    discovery,
    reportPath: run.reportPath,
    stderrTail: run.stderr.slice(-1500),
  };
}

function pct(n, d) {
  return d === 0 ? "—" : `${((n / d) * 100).toFixed(1)}%`;
}

function buildMarkdown(meta, results, metrics) {
  const lines = [];
  lines.push("# GuardBuild 黑盒精度基准报告");
  lines.push("");
  lines.push(`- 生成时间：${meta.generatedAt}`);
  lines.push(`- 代码版本：${meta.gitHead || "unknown"}`);
  lines.push(`- 语料：\`benchmarks/blackbox-corpus.json\`（v${meta.corpusVersion}，${results.length} 个靶场）`);
  lines.push(`- 判定：漏报 0 / 误报 0 / 退出码与终态全部一致 / 绿名单不回退 → ${meta.gateOk ? "通过" : "未通过"}`);
  lines.push("");
  lines.push("## 汇总");
  lines.push("");
  lines.push("| 指标 | 值 |");
  lines.push("| --- | --- |");
  lines.push(`| 漏洞用例召回 | ${metrics.tp}/${metrics.tp + metrics.fn}（${pct(metrics.tp, metrics.tp + metrics.fn)}） |`);
  lines.push(`| 误报（未标注或明令禁止） | ${metrics.fp}/${metrics.tp + metrics.fp}（${pct(metrics.fp, metrics.tp + metrics.fp)}） |`);
  lines.push(`| 退出码一致 | ${metrics.exitOk}/${metrics.targets}（${pct(metrics.exitOk, metrics.targets)}） |`);
  lines.push(`| 终态一致 | ${metrics.outcomeOk}/${metrics.targets}（${pct(metrics.outcomeOk, metrics.targets)}） |`);
  lines.push(`| 靶场通过 | ${metrics.passed}/${metrics.targets} |`);
  lines.push("");
  lines.push("## 靶场明细");
  lines.push("");
  lines.push("| 靶场 | 退出码（实际/期望） | 命中/标注 | 漏报 | 误报 | blocked | 路由（openapi/frontend/robots/sitemap/brute） | 用时 | 结论 |");
  lines.push("| --- | --- | --- | --- | --- | --- | --- | --- | --- |");
  for (const r of results) {
    const d = r.discovery;
    const src = `${d.bySource.openapi ?? 0}/${d.bySource.frontend ?? 0}/${d.bySource.robots ?? 0}/${d.bySource.sitemap ?? 0}/${d.bySource.brute ?? 0}`;
    lines.push(
      `| ${r.id} | ${r.exit.actual ?? "—"}/${r.exit.expected} | ${r.cases.matched.length}/${r.cases.expected.length} | ${r.cases.missed.length} | ${r.cases.falsePositives.length} | ${r.verdicts.blocked.length} | ${d.routeCount}（${src}） | ${(r.durationMs / 1000).toFixed(1)}s | ${r.pass ? "通过" : "失败"} |`
    );
  }
  lines.push("");
  const failures = results.filter((r) => !r.pass);
  if (failures.length) {
    lines.push("## 失败明细");
    lines.push("");
    for (const r of failures) {
      lines.push(`### ${r.id}`);
      if (!r.exit.ok) lines.push(`- 退出码：实际 ${r.exit.actual ?? "—"}，期望 ${r.exit.expected}${r.exit.timedOut ? "（超时）" : ""}${r.exit.error ? `（${r.exit.error}）` : ""}`);
      if (!r.outcome.ok) lines.push(`- 终态：实际 ${r.outcome.actual ?? "—"}，期望 ${(r.outcome.expected ?? []).join(" / ")}`);
      for (const m of r.cases.missed) lines.push(`- 漏报：${m}`);
      for (const f of r.cases.forbiddenHits) lines.push(`- 误报（明令禁止）：${f}`);
      for (const f of r.cases.unannotated) lines.push(`- 误报（未标注）：${f}`);
      lines.push("");
    }
  }
  lines.push(...loopSection({ loop: meta.loop }));
  lines.push("## 说明");
  lines.push("");
  lines.push("- 漏洞用例召回：语料标注的 caseId 规则（支持尾部 * 前缀）在报告证据中判为 vulnerable 的比例。");
  lines.push("- 误报：判为 vulnerable 但未命中任何标注规则，或命中 forbiddenVulnerable 的用例；干净靶场出现任何 vulnerable 都属误报。");
  lines.push("- blocked 列只作诊断：它反映「攻击确实打到了、但被拒绝」，不参与通过判定。");
  lines.push("- 路由列展示发现来源（openapi/frontend/robots/sitemap/brute），用于回归前端 JS 深挖、source map、框架清单（含 Next `_buildManifest.js`）、robots/sitemap 声明与 Swagger UI 内嵌地址等发现能力。");
  lines.push("- 本基准要求零模型调用：运行时清空 LLM 密钥与环境开关，确保结果可复现、无外发。");
  lines.push("");
  return lines.join("\n");
}

async function main() {
  if (!existsSync(exe)) {
    throw new Error(`未找到无头宿主: ${exe}（先 cargo build --no-default-features --bin guardbuild-headless）`);
  }
  const corpus = JSON.parse(readFileSync(corpusPath, "utf8"));
  const targets = corpus.targets.filter((t) => only.size === 0 || only.has(t.id));
  if (targets.length === 0) throw new Error(`--only 未匹配任何靶场: ${[...only].join(",")}`);

  if (!keep) rmSync(benchRoot, { recursive: true, force: true });
  mkdirSync(benchRoot, { recursive: true });

  console.log(`[BB-BENCH] ${targets.length} 个标注靶场，宿主 ${exe}`);
  const results = [];
  const ledgerRecords = [];
  for (let i = 0; i < targets.length; i++) {
    const target = targets[i];
    process.stdout.write(`[BB-BENCH] ${i + 1}/${targets.length} ${target.id} …`);
    let server = null;
    try {
      const ws = makeWorkspace(target);
      const started = await startTarget(ws, target);
      server = started.child;
      const run = await runScan(ws, started.port, target);
      const result = evaluate(target, run);
      results.push(result);
      ledgerRecords.push(...classifyRun({ suite: SUITE, target, result, report: run.report, gate: run.gate }));
      const c = result.cases;
      console.log(
        ` exit=${result.exit.actual ?? "—"}/${result.exit.expected} 命中=${c.matched.length}/${c.expected.length} 漏报=${c.missed.length} 误报=${c.falsePositives.length} 路由=${result.discovery.routeCount} ${(result.durationMs / 1000).toFixed(1)}s ${result.pass ? "✓" : "✗"}`
      );
      if (!result.pass) {
        for (const m of c.missed) console.log(`        漏报 ${m}`);
        for (const f of c.forbiddenHits) console.log(`        误报（明令禁止） ${f}`);
        for (const f of c.unannotated) console.log(`        误报（未标注） ${f}`);
        if (!result.exit.ok) console.log(`        退出码 ${result.exit.actual ?? "—"} != ${result.exit.expected}${result.exit.timedOut ? "（超时）" : ""}${result.exit.error ? `（${result.exit.error}）` : ""}`);
        if (!result.outcome.ok) console.log(`        终态 ${result.outcome.actual ?? "—"} 不在 ${(result.outcome.expected ?? []).join("/")}`);
      }
    } catch (e) {
      const failed = {
        id: target.id,
        pass: false,
        durationMs: 0,
        exit: { actual: null, expected: target.expectedExit, ok: false, timedOut: false, error: e.message },
        outcome: { actual: null, expected: target.expectedOutcomes ?? null, ok: false },
        findingsCount: 0,
        cases: { expected: target.expectedVulnerable ?? [], actual: [], matched: [], missed: [], falsePositives: [], forbiddenHits: [], unannotated: [] },
        verdicts: { blocked: [], inconclusive: [] },
        discovery: { routeCount: 0, bySource: {}, openapiFound: false, openapiRouteCount: 0, frontendRouteCount: 0, frontendScripts: 0, frontendNextManifest: 0, seoRouteCount: 0 },
        reportPath: null,
        stderrTail: "",
        // server 还没起来就在 makeWorkspace/startTarget 抛了 —— 归「起不来」
        startupFailed: !server,
      };
      results.push(failed);
      ledgerRecords.push(...classifyRun({ suite: SUITE, target, result: failed, report: null, gate: null }));
      console.log(` ✗ ${e.message}`);
    } finally {
      await stopTarget(server);
    }
  }

  const tp = results.reduce((n, r) => n + r.cases.matched.length, 0);
  const fn = results.reduce((n, r) => n + r.cases.missed.length, 0);
  const fp = results.reduce((n, r) => n + r.cases.falsePositives.length, 0);
  const exitOk = results.filter((r) => r.exit.ok).length;
  const outcomeOk = results.filter((r) => r.outcome.ok).length;
  const passed = results.filter((r) => r.pass).length;
  const pass = results.length === targets.length && results.every((r) => r.pass);

  const gitHead = spawnSync("git", ["rev-parse", "--short", "HEAD"], { cwd: repoRoot, encoding: "utf8" }).stdout?.trim() || null;

  const ledger = appendLedger({
    filePath: ledgerPath,
    records: ledgerRecords,
    gitHead,
    partial: only.size > 0,
    cleanRun: pass && only.size === 0,
    resolveSuite: SUITE,
  });
  const regression = gateAgainstBaseline({
    filePath: baselinePath,
    suite: SUITE,
    currentKeys: greenKeysOf({ suite: SUITE, results }),
    coveredTargets: new Set(results.map((r) => r.id)),
    corpusVersion: corpus.version,
    gitHead,
    allPass: pass,
    partial: only.size > 0,
    rebaseline,
  });
  const loop = {
    suite: SUITE,
    ledger,
    regression,
    ledgerPath: path.relative(repoRoot, ledgerPath).replace(/\\/g, "/"),
    baselinePath: path.relative(repoRoot, baselinePath).replace(/\\/g, "/"),
  };
  const gateOk = pass && regression.ok;

  const meta = {
    generatedAt: new Date().toISOString(),
    gitHead,
    corpusVersion: corpus.version,
    pass,
    gateOk,
    loop,
    metrics: { tp, fn, fp, exitOk, outcomeOk, targets: results.length, passed },
  };
  const jsonPath = path.join(benchRoot, "benchmark-report.json");
  const mdPath = path.join(benchRoot, "benchmark-report.md");
  writeFileSync(jsonPath, JSON.stringify({ ...meta, results }, null, 2));
  writeFileSync(mdPath, buildMarkdown(meta, results, meta.metrics));

  console.log("");
  console.log(`[BB-BENCH] 召回 ${tp}/${tp + fn}（${pct(tp, tp + fn)}）· 误报 ${fp}/${tp + fp}（${pct(fp, tp + fp)}）· 退出码一致 ${exitOk}/${results.length} · 终态一致 ${outcomeOk}/${results.length}`);
  for (const line of consoleLoopLines(loop)) console.log(line);
  console.log(`[BB-BENCH] 报告：${jsonPath}`);
  console.log(`[BB-BENCH]       ${mdPath}`);
  console.log(gateOk ? "[BB-BENCH] 全部通过 ✅" : `[BB-BENCH] 未通过：${results.filter((r) => !r.pass).map((r) => r.id).join("、") || "回退否决"} ❌`);
  return gateOk;
}

main()
  .then((pass) => {
    process.exitCode = pass ? 0 : 1;
  })
  .catch((e) => {
    console.error(`[BB-BENCH] 执行失败: ${e.message}`);
    process.exitCode = 2;
  });
