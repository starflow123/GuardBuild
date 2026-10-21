#!/usr/bin/env node
/**
 * P3 精度基准：对固定标注靶场逐个跑真实 gate，量化漏报 / 误报 / 退出码一致性。
 *
 * 语料：benchmarks/corpus.json。每个靶场声明：
 *   expectedExit             gate 期望退出码（1=有可复现漏洞，0=无）
 *   expectedVulnerableCases  期望被判为 vulnerable 的攻击用例（漏报 = 未命中）
 *   expectedStatic           期望出现的静态候选（仅统计静态召回）
 *   expectedOutcomes         可选，期望的 report.verdict.outcome
 *
 * 判定：任何漏报、误报（vulnerable 但不在标注集合内）、退出码不一致、执行失败
 * 都会让基准以非零退出，作为新增适配器/探测能力的回归闸门。
 *
 * 用法:
 *   node scripts/benchmark.mjs                # 全量
 *   node scripts/benchmark.mjs --only=next-shop,clean-shop
 *   node scripts/benchmark.mjs --keep         # 保留上一轮 .benchmark 产物
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

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const benchRoot = path.join(repoRoot, ".benchmark");
const corpusPath = path.join(repoRoot, "benchmarks", "corpus.json");

function argValue(name) {
  const hit = process.argv.slice(2).find((a) => a.startsWith(`${name}=`));
  return hit ? hit.slice(name.length + 1) : null;
}

const only = new Set((argValue("--only") ?? "").split(",").map((s) => s.trim()).filter(Boolean));
const keep = process.argv.includes("--keep");

/** 无头宿主可执行文件：GUARDBUILD_HEADLESS_BIN > target/debug > target/release（跨平台） */
function resolveHeadlessBin() {
  if (process.env.GUARDBUILD_HEADLESS_BIN) return process.env.GUARDBUILD_HEADLESS_BIN;
  const name = process.platform === "win32" ? "guardbuild-headless.exe" : "guardbuild-headless";
  const debug = path.join(repoRoot, "src-tauri", "target", "debug", name);
  return existsSync(debug) ? debug : path.join(repoRoot, "src-tauri", "target", "release", name);
}
const exe = resolveHeadlessBin();

function commandAvailable(cmd) {
  const probe = spawnSync(process.platform === "win32" ? "where" : "which", [cmd], { encoding: "utf8" });
  return probe.status === 0;
}

function git(args, cwd) {
  const r = spawnSync("git", args, { cwd, encoding: "utf8" });
  if (r.status !== 0) throw new Error(`git ${args.join(" ")} 失败: ${r.stderr || r.stdout}`);
  return r.stdout;
}

function makeWorkspace(id, fixture) {
  const ws = path.join(benchRoot, "workspaces", id);
  rmSync(ws, { recursive: true, force: true });
  cpSync(path.join(repoRoot, fixture), ws, { recursive: true });
  git(["init", "-q"], ws);
  git(["config", "user.email", "benchmark@guardbuild.local"], ws);
  git(["config", "user.name", "GuardBuild Benchmark"], ws);
  git(["config", "core.autocrlf", "false"], ws);
  git(["add", "-A"], ws);
  git(["commit", "-qm", `${id} 基准基线`], ws);
  return ws;
}

function runGate(target, workspace) {
  const dataDir = path.join(benchRoot, "data", target.id);
  const reportDir = path.join(benchRoot, "reports", target.id);
  rmSync(dataDir, { recursive: true, force: true });
  rmSync(reportDir, { recursive: true, force: true });
  mkdirSync(dataDir, { recursive: true });
  const timeoutMs = target.timeoutMs ?? 240_000;

  return new Promise((resolve) => {
    const startedAt = Date.now();
    const child = spawn(
      exe,
      ["--gate", "--project", workspace, "--report", reportDir],
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
    child.on("error", (e) => {
      clearTimeout(timer);
      resolve({ error: e.message, timedOut, durationMs: Date.now() - startedAt, stdout, stderr });
    });
    child.on("exit", (code) => {
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
      resolve({ code, gate, report, reportPath: existsSync(reportPath) ? reportPath : null, timedOut, durationMs: Date.now() - startedAt, stdout, stderr });
    });
  });
}

function matchStatic(finding, expected) {
  if (finding.kind !== expected.kind) return false;
  if (expected.method && finding.method !== expected.method) return false;
  if (expected.path && finding.path !== expected.path) return false;
  if (expected.routeKeys && !(finding.routeKeys ?? []).some((k) => expected.routeKeys.includes(k))) return false;
  return true;
}

function evaluate(target, run) {
  const expectedExit = target.expectedExit;
  const expectedCases = target.expectedVulnerableCases ?? [];
  const findings = run.report?.summary?.findings ?? [];
  const pre = run.report?.evidence?.pre ?? [];
  const actualVulnerable = pre
    .filter((e) => e.category === "attack" && e.verdict === "vulnerable")
    .map((e) => e.caseId);
  const actualById = new Map(pre.map((e) => [e.caseId, e]));
  const matched = expectedCases.filter((id) => actualVulnerable.includes(id));
  const missed = expectedCases.filter((id) => !actualVulnerable.includes(id));
  const falsePositives = actualVulnerable.filter((id) => !expectedCases.includes(id));

  const used = new Set();
  const staticMatched = [];
  const staticMissed = [];
  for (const expected of target.expectedStatic ?? []) {
    const idx = findings.findIndex((f, i) => !used.has(i) && matchStatic(f, expected));
    if (idx >= 0) {
      used.add(idx);
      staticMatched.push(expected);
    } else {
      staticMissed.push(expected);
    }
  }
  const staticExtra = findings.filter((_, i) => !used.has(i));
  const businessRegressed = pre.filter((e) => e.category === "business" && e.verdict === "regressed");

  const exitOk = !run.error && !run.timedOut && run.code === expectedExit;
  const outcomeOk = !target.expectedOutcomes || target.expectedOutcomes.includes(run.report?.verdict?.outcome);
  const pass = exitOk && outcomeOk && missed.length === 0 && falsePositives.length === 0;

  return {
    id: target.id,
    pass,
    durationMs: run.durationMs,
    exit: { actual: run.code ?? null, expected: expectedExit, ok: exitOk, timedOut: !!run.timedOut, error: run.error ?? null },
    outcome: { actual: run.report?.verdict?.outcome ?? null, expected: target.expectedOutcomes ?? null, ok: outcomeOk },
    findingsCount: findings.length,
    dynamic: {
      expected: expectedCases,
      actual: actualVulnerable,
      matched,
      missed: missed.map((id) => ({ caseId: id, actual: actualById.get(id)?.actual ?? null, verdict: actualById.get(id)?.verdict ?? null })),
      falsePositives: falsePositives.map((id) => ({ caseId: id, actual: actualById.get(id)?.actual ?? null })),
    },
    static: { expected: (target.expectedStatic ?? []).length, matched: staticMatched.length, missed: staticMissed, extra: staticExtra.map((f) => `${f.kind} ${f.method ?? ""} ${f.path ?? (f.routeKeys ?? []).join(",")}`) },
    businessRegressed: businessRegressed.map((e) => ({ caseId: e.caseId, actual: e.actual ?? null })),
    reportPath: run.reportPath,
    stderrTail: run.stderr.slice(-1500),
  };
}

function pct(n, d) {
  return d === 0 ? "—" : `${((n / d) * 100).toFixed(1)}%`;
}

function buildMarkdown(meta, results, metrics) {
  const lines = [];
  lines.push("# GuardBuild 精度基准报告");
  lines.push("");
  lines.push(`- 生成时间：${meta.generatedAt}`);
  lines.push(`- 代码版本：${meta.gitHead || "unknown"}`);
  lines.push(`- 语料：\`benchmarks/corpus.json\`（v${meta.corpusVersion}，${results.length} 个靶场）`);
  lines.push(`- 判定：漏报 0 / 误报 0 / 退出码全部一致 → ${meta.pass ? "通过" : "未通过"}`);
  lines.push("");
  lines.push("## 汇总");
  lines.push("");
  lines.push("| 指标 | 值 |");
  lines.push("| --- | --- |");
  lines.push(`| 动态召回率（攻击用例） | ${metrics.tp}/${metrics.tp + metrics.fn}（${pct(metrics.tp, metrics.tp + metrics.fn)}） |`);
  lines.push(`| 动态误报率（vulnerable 中未标注） | ${metrics.fp}/${metrics.tp + metrics.fp}（${pct(metrics.fp, metrics.tp + metrics.fp)}） |`);
  lines.push(`| 退出码一致率 | ${metrics.exitOk}/${metrics.targets}（${pct(metrics.exitOk, metrics.targets)}） |`);
  lines.push(`| 静态召回率（标注候选） | ${metrics.staticMatched}/${metrics.staticExpected}（${pct(metrics.staticMatched, metrics.staticExpected)}） |`);
  lines.push("");
  lines.push("## 靶场明细");
  lines.push("");
  lines.push("| 靶场 | 退出码（实际/期望） | 复现（命中/标注） | 漏报 | 误报 | 静态（命中/标注） | 用时 | 结论 |");
  lines.push("| --- | --- | --- | --- | --- | --- | --- | --- |");
  for (const r of results) {
    const dyn = r.dynamic;
    lines.push(
      `| ${r.id} | ${r.exit.actual ?? "—"}/${r.exit.expected} | ${dyn.matched.length}/${dyn.expected.length} | ${dyn.missed.length} | ${dyn.falsePositives.length} | ${r.static.matched}/${r.static.expected} | ${(r.durationMs / 1000).toFixed(1)}s | ${r.pass ? "通过" : "失败"} |`
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
      if (!r.outcome.ok) lines.push(`- verdict.outcome：实际 ${r.outcome.actual ?? "—"}，期望 ${(r.outcome.expected ?? []).join(" / ")}`);
      for (const m of r.dynamic.missed) lines.push(`- 漏报：${m.caseId}（verdict=${m.verdict ?? "未生成"}）${m.actual ? ` — ${m.actual}` : ""}`);
      for (const f of r.dynamic.falsePositives) lines.push(`- 误报：${f.caseId}${f.actual ? ` — ${f.actual}` : ""}`);
      for (const s of r.static.missed) lines.push(`- 静态漏报：${s.kind} ${s.method ?? ""} ${s.path ?? (s.routeKeys ?? []).join(",")}`);
      for (const b of r.businessRegressed) lines.push(`- 业务基线回归：${b.caseId}`);
      lines.push("");
    }
  }
  lines.push("## 说明");
  lines.push("");
  lines.push("- 动态漏报：标注为 vulnerable 的攻击用例未出现在 pre 证据中，或未被判为 vulnerable。");
  lines.push("- 动态误报：pre 证据中被判为 vulnerable、但未在语料标注集合内的攻击用例；干净靶场出现任何 vulnerable 都属误报。");
  lines.push("- 静态召回仅作诊断（GuardBuild 以动态复现为裁决依据，静态候选由探测阶段澄清），不参与通过/失败判定。");
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

  console.log(`[BENCH] ${targets.length} 个标注靶场，宿主 ${exe}`);
  const results = [];
  const skipped = [];
  for (let i = 0; i < targets.length; i++) {
    const target = targets[i];
    const missing = (target.requires ?? []).filter((cmd) => !commandAvailable(cmd));
    if (missing.length) {
      skipped.push({ id: target.id, missing });
      console.log(`[BENCH] ${i + 1}/${targets.length} ${target.id} — 跳过（缺少 ${missing.join(", ")}）`);
      continue;
    }
    process.stdout.write(`[BENCH] ${i + 1}/${targets.length} ${target.id} …`);
    try {
      const ws = makeWorkspace(target.id, target.fixture);
      const run = await runGate(target, ws);
      const result = evaluate(target, run);
      results.push(result);
      const dyn = result.dynamic;
      console.log(
        ` exit=${result.exit.actual ?? "—"}/${result.exit.expected} 复现=${dyn.matched.length}/${dyn.expected.length} 漏报=${dyn.missed.length} 误报=${dyn.falsePositives.length} 静态=${result.static.matched}/${result.static.expected} ${(result.durationMs / 1000).toFixed(1)}s ${result.pass ? "✓" : "✗"}`
      );
      if (!result.pass) {
        for (const m of dyn.missed) console.log(`        漏报 ${m.caseId} verdict=${m.verdict ?? "未生成"} ${m.actual ?? ""}`);
        for (const f of dyn.falsePositives) console.log(`        误报 ${f.caseId} ${f.actual ?? ""}`);
        if (!result.exit.ok) console.log(`        退出码 ${result.exit.actual ?? "—"} != ${result.exit.expected}${result.exit.timedOut ? "（超时）" : ""}${result.exit.error ? `（${result.exit.error}）` : ""}`);
      }
    } catch (e) {
      results.push({
        id: target.id,
        pass: false,
        durationMs: 0,
        exit: { actual: null, expected: target.expectedExit, ok: false, timedOut: false, error: e.message },
        outcome: { actual: null, expected: target.expectedOutcomes ?? null, ok: false },
        findingsCount: 0,
        dynamic: { expected: target.expectedVulnerableCases ?? [], actual: [], matched: [], missed: [], falsePositives: [] },
        static: { expected: (target.expectedStatic ?? []).length, matched: 0, missed: target.expectedStatic ?? [], extra: [] },
        businessRegressed: [],
        reportPath: null,
        stderrTail: "",
      });
      console.log(` ✗ ${e.message}`);
    }
  }

  const tp = results.reduce((n, r) => n + r.dynamic.matched.length, 0);
  const fn = results.reduce((n, r) => n + r.dynamic.missed.length, 0);
  const fp = results.reduce((n, r) => n + r.dynamic.falsePositives.length, 0);
  const exitOk = results.filter((r) => r.exit.ok).length;
  const staticMatched = results.reduce((n, r) => n + r.static.matched, 0);
  const staticExpected = results.reduce((n, r) => n + r.static.expected, 0);
  const passed = results.filter((r) => r.pass).length;
  const pass = results.length > 0 && results.every((r) => r.pass);

  const gitHead = spawnSync("git", ["rev-parse", "--short", "HEAD"], { cwd: repoRoot, encoding: "utf8" }).stdout?.trim() || null;
  const meta = {
    generatedAt: new Date().toISOString(),
    gitHead,
    corpusVersion: corpus.version,
    pass,
    skipped,
    metrics: { tp, fn, fp, exitOk, targets: results.length, staticMatched, staticExpected, passed },
  };
  const jsonPath = path.join(benchRoot, "benchmark-report.json");
  const mdPath = path.join(benchRoot, "benchmark-report.md");
  writeFileSync(jsonPath, JSON.stringify({ ...meta, results }, null, 2));
  writeFileSync(mdPath, buildMarkdown(meta, results, meta.metrics));

  console.log("");
  console.log(`[BENCH] 动态召回 ${tp}/${tp + fn}（${pct(tp, tp + fn)}）· 误报 ${fp}/${tp + fp}（${pct(fp, tp + fp)}）· 退出码一致 ${exitOk}/${results.length} · 静态召回 ${staticMatched}/${staticExpected}`);
  if (skipped.length) console.log(`[BENCH] 跳过：${skipped.map((s) => `${s.id}（缺 ${s.missing.join("/")}）`).join("；")}`);
  console.log(`[BENCH] 报告：${jsonPath}`);
  console.log(`[BENCH]       ${mdPath}`);
  console.log(pass ? "[BENCH] 全部通过 ✅" : `[BENCH] 未通过：${results.filter((r) => !r.pass).map((r) => r.id).join("、")} ❌`);
  return pass;
}

main()
  .then((pass) => {
    process.exitCode = pass ? 0 : 1;
  })
  .catch((e) => {
    console.error(`[BENCH] 执行失败: ${e.message}`);
    process.exitCode = 2;
  });
