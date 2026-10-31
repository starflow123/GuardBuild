#!/usr/bin/env node
/**
 * 真实项目基准（强制白盒层 · 只跑公开项目）。
 *
 * 为什么要单独一层：自建 fixture 与自建靶场都是「配好的」——不挂双前缀、路径短、
 * 登录走 JSON、守卫写法单一，所以接入层的缺陷（挂载前缀重复拼接、Windows 长路径、
 * 表单 Cookie 登录、SSR 无 JSON 列表接口）在这一层里天然不可能暴露。更关键的是，
 * 只跑黑盒的基准会漏掉白盒独有的失败：黑盒不建 worktree，长路径 bug 就一路绿灯。
 *
 * 语料里 personal=true 的条目（用户自己的项目）默认不跑：2026-10-30 起先把公开层
 * 跑稳，产品成熟后再回测；临时回测需显式 GUARDBUILD_INDIE_PERSONAL=1。
 *
 * 这一层的判据不是「漏洞有没有复现」（真实项目的结论本来就可能是 exit 0），
 * 而是「这一轮绿灯/红灯是不是由真实测量支撑的」：
 * - R1 必须走白盒链路（不传 --url、报告里不得有 blackbox 段、必须有启动契约）；
 * - R2 攻击请求地址不得出现连续重复路径段（`/api/api/x`，即 #174 的指纹）；
 * - R3 exit 0 只有「攻击用例真的打到了目标（不是全 404/405）+ 契约里的身份真的建立了」才成立；
 * - R4 `git_error`（worktree 建不出来，Windows 长路径 = #176）直接判失败；
 * - R5 静态候选数为 0 视为适配器漏检，而不是「项目干净」。
 *
 * 口径：项目缺失 / 依赖没装 / 没有契约 → **跳过**，不判失败；
 * `--require=<id>` 显式要求实跑时，跳过才判红（CI 自备项目时用）。
 *
 * 用法:
 *   node scripts/benchmark-indie.mjs
 *   node scripts/benchmark-indie.mjs --only=vuln-express
 *   node scripts/benchmark-indie.mjs --require=juice-shop
 *   GUARDBUILD_INDIE_DIR=D:/AiAgent/dogfood node scripts/benchmark-indie.mjs
 *
 * 闭环：失败按规则编号（R0–R5）归档进 benchmarks/failure-ledger.jsonl（suite=indie），
 * 绿名单只收靶场级键（这一层没有逐用例标注）。personal=true 的项目一律不写账本、
 * 不写绿名单——项目名会进公开仓库，隐私边界优先于统计完整性。
 */
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { allEvidence, auditWhiteboxRun } from "../sidecar/lib/falsegreen.mjs";
import { appendLedger, greenKeysOf, redactSecrets } from "../sidecar/lib/failureledger.mjs";
import { gateAgainstBaseline } from "../sidecar/lib/regression.mjs";
import { consoleLoopLines, loopSection } from "./lib/loopsummary.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const benchRoot = path.join(repoRoot, ".benchmark-indie");
const corpusPath = path.join(repoRoot, "benchmarks", "indie-corpus.json");
const SUITE = "indie";
const ledgerPath = path.join(repoRoot, "benchmarks", "failure-ledger.jsonl");
const baselinePath = path.join(repoRoot, "benchmarks", "green-baseline.json");

function argValue(name) {
  const hit = process.argv.slice(2).find((a) => a.startsWith(`${name}=`));
  return hit ? hit.slice(name.length + 1) : null;
}
const only = new Set((argValue("--only") ?? "").split(",").map((s) => s.trim()).filter(Boolean));
const mustRun = new Set((argValue("--require") ?? "").split(",").map((s) => s.trim()).filter(Boolean));
const keep = process.argv.includes("--keep");
const rebaseline = process.argv.includes("--rebaseline");

function resolveHeadlessBin() {
  if (process.env.GUARDBUILD_HEADLESS_BIN) return process.env.GUARDBUILD_HEADLESS_BIN;
  const name = process.platform === "win32" ? "guardbuild-headless.exe" : "guardbuild-headless";
  const debug = path.join(repoRoot, "src-tauri", "target", "debug", name);
  return existsSync(debug) ? debug : path.join(repoRoot, "src-tauri", "target", "release", name);
}
const exe = resolveHeadlessBin();

function readContract(dir) {
  const p = path.join(dir, "guardbuild.json");
  if (!existsSync(p)) return null;
  try {
    return JSON.parse(readFileSync(p, "utf8"));
  } catch {
    return null;
  }
}

function missingRequires(dir, target) {
  return (target.requires ?? []).filter((rel) => !existsSync(path.join(dir, rel)));
}

function auditStructure(report, contract, minFindings) {
  return auditWhiteboxRun({ report, contract, minFindings });
}

function runGate(dir, target) {
  const dataDir = path.join(benchRoot, "data", target.id);
  const reportDir = path.join(benchRoot, "reports", target.id);
  rmSync(dataDir, { recursive: true, force: true });
  rmSync(reportDir, { recursive: true, force: true });
  mkdirSync(dataDir, { recursive: true });

  return new Promise((resolve) => {
    const startedAt = Date.now();
    const child = spawn(exe, ["--gate", "--project", dir, "--report", reportDir], {
      cwd: repoRoot,
      env: {
        ...process.env,
        GUARDBUILD_DATA_DIR: dataDir,
        GUARDBUILD_SIDECAR: path.join(repoRoot, "sidecar", "main.mjs"),
        GUARDBUILD_AUTO_CONSENT: "1",
        GUARDBUILD_LLM_SCOUT: "",
        GUARDBUILD_LLM_PATCH: "",
        GUARDBUILD_LLM_ATTACKPLAN: "",
        GUARDBUILD_LLM_CROSSFILE: "",
        GUARDBUILD_LLM_BOOTSTRAP: "",
        DEEPSEEK_API_KEY: "",
        DEEPSEEK_BASE_URL: "",
        ...(target.env ?? {}),
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (b) => { stdout += b.toString(); });
    child.stderr.on("data", (b) => { stderr += b.toString(); });
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill();
    }, target.timeoutMs ?? 600_000);
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
      resolve({ code: child.exitCode, report, timedOut, error: error ?? null, durationMs: Date.now() - startedAt, stdout, stderr });
    };
    child.on("error", (e) => finish(e.message));
    child.on("exit", () => finish(null));
  });
}

function shapeOf(report) {
  const ev = allEvidence(report);
  const attack = ev.filter((e) => e.category === "attack");
  return {
    findings: report?.summary?.findingCount ?? 0,
    evidence: ev.length,
    attack: attack.length,
    vulnerable: ev.filter((e) => e.verdict === "vulnerable").length,
    inconclusive: ev.filter((e) => e.verdict === "inconclusive").length,
    notFound: attack.filter((e) => e.response?.status === 404 || e.response?.status === 405).length,
    identities: report?.summary?.identities
      ? `${report.summary.identities.loggedIn?.length ?? 0}/${report.summary.identities.configured?.length ?? 0}`
      : "—",
    sessionVerify: report?.summary?.identities?.sessionVerification?.status ?? null,
    errorCode: report?.error?.code ?? null,
    errorMessage: report?.error?.message ?? null,
    endpoints: [...new Set(attack.map((e) => e.endpoint))].slice(0, 6),
  };
}

function evaluate(target, run, contract) {
  const report = run.report;
  const failures = [];
  if (!report) {
    failures.push({ rule: "R0", text: `未产出 report.json（exit=${run.code ?? "—"}${run.timedOut ? " 超时" : ""}${run.error ? ` ${run.error}` : ""}）` });
  } else {
    const exitOk = (target.expectedExits ?? [0, 1, 2]).includes(report.verdict?.exitCode);
    if (!exitOk || run.timedOut || run.error) {
      failures.push({
        rule: "R1",
        text: `退出码 ${report.verdict?.exitCode ?? "—"}（终态 ${report.verdict?.outcome ?? "—"}）不在允许集合 ${(target.expectedExits ?? []).join("/")} 或本轮未跑完${run.timedOut ? "（超时）" : ""}`,
      });
    }
    for (const i of auditStructure(report, contract, target.minFindings ?? 1)) failures.push(i);
  }
  const shape = shapeOf(report);
  return {
    id: target.id,
    name: target.name,
    skipped: false,
    pass: failures.length === 0,
    failures,
    exit: report?.verdict?.exitCode ?? null,
    outcome: report?.verdict?.outcome ?? null,
    expectedExits: target.expectedExits ?? null,
    durationMs: run.durationMs,
    shape,
    reportPath: report ? path.join(benchRoot, "reports", target.id, "report.json") : null,
    stderrTail: (run.stderr ?? "").slice(-300),
  };
}

function skipResult(target, reason) {
  return {
    id: target.id,
    name: target.name,
    skipped: true,
    pass: true,
    skipReason: reason,
    failures: [],
    exit: null,
    outcome: null,
    expectedExits: target.expectedExits ?? null,
    durationMs: 0,
    shape: { findings: 0, evidence: 0, attack: 0, vulnerable: 0, inconclusive: 0, notFound: 0, identities: "—", sessionVerify: null, errorCode: null, endpoints: [] },
    reportPath: null,
  };
}

/** 白盒真实层的结构性规则 → 账本五类。R3/R5 是「没测到 / 没认出」，不是「跑挂了」 */
const RULE_CATEGORY = {
  R0: "broken_run",
  R1: "broken_run",
  R2: "missed",
  R3: "inconclusive",
  R4: "not_ready",
  R5: "missed",
};

/** 这一层没有逐用例标注，失败以规则编号归档；个人项目一律不写（项目名会进公开仓库） */
function ledgerRecordsFor(target, result, rootDir) {
  if (target?.personal) return [];
  // 本机项目根的绝对路径会跟着账本进仓库，统一换成占位
  const hideRoot = (s) => (rootDir ? String(s ?? "").split(String(rootDir)).join("<项目根>") : String(s ?? ""));
  const base = {
    suite: SUITE,
    target: result.id,
    exit: { actual: result.exit ?? null, expected: (result.expectedExits ?? [0, 1, 2]).join("/") },
    outcome: { actual: result.outcome ?? null, expected: result.expectedExits ?? null },
    durationMs: result.durationMs ?? null,
    evidence: null,
    corpus: { expectedExits: result.expectedExits ?? null },
  };
  if (result.skipped) {
    return [{ ...base, caseKey: "-", category: "not_ready", cause: "skipped_on_host", detail: hideRoot(redactSecrets(result.skipReason ?? "项目缺失或依赖未准备")) }];
  }
  return (result.failures ?? []).map((f) => ({
    ...base,
    caseKey: f.rule,
    category: RULE_CATEGORY[f.rule] ?? "broken_run",
    cause: f.rule.toLowerCase(),
    detail: hideRoot(redactSecrets(f.text)),
  }));
}

function buildMarkdown(meta, results) {
  const run = results.filter((r) => !r.skipped);
  const skipped = results.filter((r) => r.skipped);
  const green = run.filter((r) => r.exit === 0);
  const noTraffic = run.filter((r) => (r.shape?.attack ?? 0) === 0);
  const lines = [];
  lines.push("# 真实项目基准（强制白盒层 · 公开项目）");
  lines.push("");
  lines.push(`- 生成时间：${meta.generatedAt}`);
  lines.push(`- 提交：\`${meta.gitHead ?? "未知"}\``);
  lines.push(`- 项目根：\`${meta.indieDir}\``);
  lines.push(
    `- 实跑 ${run.length} 个 / 跳过 ${skipped.length} 个 · 绿灯（exit 0）${green.length} 个 · 未产生攻击流量 ${noTraffic.length} 个（只证明终态诚实，不证明检测能力）`
  );
  lines.push("");
  lines.push("| 项目 | 退出码（实际/允许） | 静态候选 | 攻击用例 | 404/405 | 复现 | 身份会话 | 真实性回读 | 用时 | 结论 |");
  lines.push("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |");
  for (const r of results) {
    if (r.skipped) {
      lines.push(`| ${r.id} | — | — | — | — | — | — | — | — | 跳过：${r.skipReason} |`);
      continue;
    }
    const s = r.shape;
    lines.push(
      `| ${r.id} | ${r.exit ?? "—"}/${(r.expectedExits ?? []).join("/")} | ${s.findings} | ${s.attack} | ${s.notFound}/${s.attack} | ${s.vulnerable} | ${s.identities} | ${s.sessionVerify ?? "—"} | ${(r.durationMs / 1000).toFixed(1)}s | ${!r.pass ? "失败" : s.attack ? "通过" : "通过（全程无攻击流量）"} |`
    );
  }
  lines.push("");
  if (noTraffic.length) {
    lines.push("## 未产生攻击流量的项目（结构性合规，但未测量）");
    lines.push("");
    for (const r of noTraffic) {
      const err = r.shape.errorCode ? ` · 错误 \`${r.shape.errorCode}\`` : "";
      const msg = r.shape.errorMessage ? ` — ${r.shape.errorMessage.slice(0, 200)}` : "";
      lines.push(`- ${r.id}：终态 ${r.outcome ?? "—"}${err}${msg}`);
    }
    lines.push("");
  }
  const failed = run.filter((r) => !r.pass);
  if (failed.length) {
    lines.push("## 失败明细");
    lines.push("");
    for (const r of failed) {
      lines.push(`### ${r.id}（exit ${r.exit ?? "—"}，终态 ${r.outcome ?? "—"}）`);
      for (const f of r.failures) lines.push(`- **${f.rule}**：${f.text}`);
      if (r.shape.endpoints.length) lines.push(`- 攻击地址：${r.shape.endpoints.map((x) => `\`${x}\``).join("、")}`);
      if (r.stderrTail) lines.push(`- stderr 尾部：\`\`\`\n${r.stderrTail}\n\`\`\``);
      lines.push("");
    }
  }
  if (skipped.length) {
    lines.push("## 跳过说明");
    lines.push("");
    for (const r of skipped) lines.push(`- ${r.id}：${r.skipReason}`);
    lines.push("");
    lines.push("跳过不计入失败，也不代表能力缺失——只有 `--require=<id>` 显式要求实跑时才会判红。");
    lines.push("");
  }
  lines.push(...loopSection({ loop: meta.loop }));
  lines.push("## 口径");
  lines.push("");
  lines.push("- 这一层不预测结论方向：真实项目跑成 exit 0 / 1 / 2 都可能，允许集合写在 `benchmarks/indie-corpus.json`。");
  lines.push("- 判据是结构性的：R1 必须真走白盒链路、R2 地址不得双前缀、R3 绿灯必须有真实到达的攻击请求与已建立的身份、R4 worktree 建不出来即失败、R5 零候选视为漏检。");
  lines.push(
    "- 「通过（全程无攻击流量）」不等于检测通过：它只说明这一轮的终态是诚实的（没把没测过的东西报成绿灯），本轮没有任何漏洞被实际打出来。这类行要当成待办看，不是成绩。"
  );
  lines.push("- 零模型调用：清空 LLM 开关与密钥；gate 模式禁止写回被测工作区。");
  lines.push("");
  return lines.join("\n");
}

async function main() {
  if (!existsSync(exe)) throw new Error(`未找到无头宿主: ${exe}`);
  const corpus = JSON.parse(readFileSync(corpusPath, "utf8"));
  const indieDir = process.env[corpus.realDirEnv ?? "GUARDBUILD_INDIE_DIR"] ?? corpus.defaultRealDir;
  const selected = corpus.targets.filter((t) => only.size === 0 || only.has(t.id));
  if (selected.length === 0) throw new Error(`--only 未匹配任何项目: ${[...only].join(",")}`);
  // 个人项目默认不跑：这一层先用公开靶场把白盒链路跑稳，产品成熟后再回测。
  const includePersonal = ["1", "true", "yes"].includes(
    String(process.env.GUARDBUILD_INDIE_PERSONAL ?? "").toLowerCase()
  );
  const deferred = includePersonal ? [] : selected.filter((t) => t.personal);
  const targets = includePersonal ? selected : selected.filter((t) => !t.personal);

  if (!keep) rmSync(benchRoot, { recursive: true, force: true });
  mkdirSync(benchRoot, { recursive: true });

  console.log(
    `[INDIE-BENCH] ${targets.length} 个公开真实项目（白盒层）${deferred.length ? ` · 另有 ${deferred.length} 个个人项目本批默认不测` : ""}，宿主 ${exe}，项目根 ${indieDir}`
  );
  const results = [];
  for (let i = 0; i < targets.length; i++) {
    const target = targets[i];
    const dir = path.join(indieDir, target.dir);
    process.stdout.write(`[INDIE-BENCH] ${i + 1}/${targets.length} ${target.id} …`);
    if (!existsSync(dir)) {
      results.push(skipResult(target, `目录不存在 ${dir}`));
      console.log(` ⊘ 目录不存在`);
      continue;
    }
    const missing = missingRequires(dir, target);
    if (missing.length) {
      results.push(skipResult(target, `缺少 ${missing.join("、")}`));
      console.log(` ⊘ 缺少 ${missing.join("、")}`);
      continue;
    }
    const contract = readContract(dir);
    if (target.needsContract && !contract) {
      results.push(skipResult(target, "guardbuild.json 解析失败"));
      console.log(` ⊘ 契约解析失败`);
      continue;
    }
    const run = await runGate(dir, target);
    const result = evaluate(target, run, contract);
    results.push(result);
    const s = result.shape;
    console.log(
      ` exit=${result.exit ?? "—"}/[${(result.expectedExits ?? []).join("/")}] 候选=${s.findings} 攻击=${s.attack} 404=${s.notFound} 复现=${s.vulnerable} 身份=${s.identities}${s.sessionVerify ? `/${s.sessionVerify}` : ""} ${(result.durationMs / 1000).toFixed(1)}s ${result.pass ? "✓" : "✗"}`
    );
    for (const f of result.failures) console.log(`        ${f.rule} ${f.text}`);
  }
  for (const t of deferred) {
    results.push(skipResult(t, "个人项目本批不测（产品成熟后回测；如需实跑设 GUARDBUILD_INDIE_PERSONAL=1）"));
  }

  const runResults = results.filter((r) => !r.skipped);
  const skipped = results.filter((r) => r.skipped);
  const requiredSkipped = skipped.filter((r) => mustRun.has(r.id));
  const pass = runResults.every((r) => r.pass) && requiredSkipped.length === 0;
  const gitHead = spawnSync("git", ["rev-parse", "--short", "HEAD"], { cwd: repoRoot, encoding: "utf8" }).stdout?.trim() || null;

  const targetById = new Map(corpus.targets.map((t) => [t.id, t]));
  const ledgerRecords = results.flatMap((r) => ledgerRecordsFor(targetById.get(r.id), r, indieDir));
  const ledger = appendLedger({
    filePath: ledgerPath,
    records: ledgerRecords,
    gitHead,
    partial: only.size > 0,
    cleanRun: pass && only.size === 0,
    resolveSuite: SUITE,
  });
  // 绿名单同样只收公开项目；被跳过的本轮没跑，不参与回退比对
  const baselineResults = results.filter((r) => !r.skipped && !targetById.get(r.id)?.personal);
  const regression = gateAgainstBaseline({
    filePath: baselinePath,
    suite: SUITE,
    currentKeys: greenKeysOf({ suite: SUITE, results: baselineResults }),
    coveredTargets: new Set(baselineResults.map((r) => r.id)),
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
    indieDir,
    pass,
    gateOk,
    loop,
    metrics: {
      targets: runResults.length,
      passed: runResults.filter((r) => r.pass).length,
      skipped: skipped.length,
      green: runResults.filter((r) => r.exit === 0).length,
      // 一次攻击请求都没打到目标：终态是诚实的，但这轮没有任何「能力被测量过」的证据
      noTraffic: runResults.filter((r) => (r.shape?.attack ?? 0) === 0).length,
      ruleHits: runResults.reduce((acc, r) => {
        for (const f of r.failures) acc[f.rule] = (acc[f.rule] ?? 0) + 1;
        return acc;
      }, {}),
    },
  };
  writeFileSync(path.join(benchRoot, "benchmark-report.json"), JSON.stringify({ ...meta, results }, null, 2));
  writeFileSync(path.join(benchRoot, "benchmark-report.md"), buildMarkdown(meta, results));

  console.log("");
  console.log(
    `[INDIE-BENCH] 实跑 ${runResults.length}/${targets.length}（跳过 ${skipped.length}）· 通过 ${meta.metrics.passed} · 无攻击流量 ${meta.metrics.noTraffic} · 规则命中 ${JSON.stringify(meta.metrics.ruleHits)}`
  );
  for (const r of runResults) {
    if ((r.shape?.attack ?? 0) === 0) {
      console.log(
        `[INDIE-BENCH]   ${r.id}：本轮没有任何攻击请求打到目标（终态 ${r.outcome ?? "—"}）${r.shape?.errorCode ? ` · ${r.shape.errorCode}` : ""}${r.shape?.errorMessage ? ` — ${String(r.shape.errorMessage).slice(0, 120)}` : ""}`
      );
    }
  }
  for (const line of consoleLoopLines(loop)) console.log(line);
  console.log(`[INDIE-BENCH] 报告：${path.join(benchRoot, "benchmark-report.md")}`);
  if (requiredSkipped.length) console.log(`[INDIE-BENCH] 未通过：要求实跑的项目被跳过 → ${requiredSkipped.map((r) => `${r.id}（${r.skipReason}）`).join("；")}`);
  if (pass && meta.metrics.noTraffic) {
    console.log(`[INDIE-BENCH] 终态全部合规，但 ${meta.metrics.noTraffic} 个项目一个攻击请求都没打到——这一层没有证明检测能力，只证明了不撒谎`);
  }
  console.log(gateOk ? "[INDIE-BENCH] 实跑项目终态全部合规 ✅" : "[INDIE-BENCH] 存在未通过项目或相对绿名单回退 ❌");
  return gateOk;
}

main()
  .then((pass) => {
    process.exitCode = pass ? 0 : 1;
  })
  .catch((e) => {
    console.error(`[INDIE-BENCH] 执行失败: ${e.message}`);
    process.exitCode = 2;
  });
