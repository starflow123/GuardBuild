#!/usr/bin/env node
/**
 * 修复循环（fix agent）端到端演练：非 gate 的本地模式 + mock DeepSeek。
 *
 *   第 1 轮：模型只修复取消端点（越权读仍可复现）→ 双重验收失败；
 *   失败证据（regressed 用例）随 previous_attempt 回传模型；
 *   第 2 轮：模型修全两个端点 → 双重验收通过 → writeback_pending。
 *
 * 同时校验：
 *   - gate 之外才启用循环（本脚本不传 --gate）；
 *   - 每轮补丁都在全新隔离 worktree 中生成，失败轮 worktree 被清理；
 *   - report.json / report.md 记录逐轮 hash、裁决与失败用例；
 *   - 原始被测工作区不被修改；密钥不出现在任何产物。
 *
 * 用法: node scripts/e2e-fix-agent.mjs
 */
import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { cpSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const demoDir = path.join(repoRoot, ".demo-fix-agent");
const dataDir = path.join(demoDir, "data");
const reportsDir = path.join(demoDir, "reports");
const fixture = path.join(repoRoot, "fixtures", "llm-patch-shop");
const MOCK_KEY = `sk-mock-${randomBytes(16).toString("hex")}`;

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

function makeWorkspace(name) {
  const ws = path.join(demoDir, name);
  cpSync(fixture, ws, { recursive: true });
  git(["init", "-q"], ws);
  git(["config", "user.email", "gate@guardbuild.local"], ws);
  git(["config", "user.name", "GuardBuild Gate"], ws);
  git(["config", "core.autocrlf", "false"], ws);
  git(["add", "-A"], ws);
  git(["commit", "-qm", `${name} 基线`], ws);
  return ws;
}

const ID_VAR_BY_CANDIDATE = {
  "GET /api/orders/:id": "orderDetailMatch",
  "POST /api/orders/:id/cancel": "orderCancelMatch",
};

function locateBlock(src, matchVar) {
  const at = src.indexOf(`normalizeId(${matchVar}[1])`);
  if (at < 0) return null;
  const eol = src.includes("\r\n") ? "\r\n" : "\n";
  const lineStart = src.lastIndexOf("\n", at) + 1;
  const lines = src.slice(lineStart).replace(/\r\n/g, "\n").split("\n").slice(0, 3);
  if (lines.length < 3) return null;
  if (!lines[1].includes("findOrderById(orderId)") || !lines[2].includes("订单不存在")) return null;
  const indent = (lines[0].match(/^[ \t]*/) ?? [""])[0];
  const join = (arr) => arr.join(eol);
  return {
    search: join(lines),
    replace: join([
      ...lines,
      `${indent}if (order.userId !== auth.user.id) return json(res, 403, { error: "无权访问该订单" });`,
    ]),
  };
}

/**
 * mock DeepSeek：首轮只修取消端点；拿到 previous_attempt 后修全两个端点。
 * 这模拟「模型首轮漏修 → 看到攻击回归证据后自我纠正」。
 */
function startMockLlm() {
  return new Promise((resolve) => {
    const state = { calls: 0, prompts: [], returned: [] };
    const server = createServer((req, res) => {
      const chunks = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", () => {
        if (req.method !== "POST" || req.url !== "/v1/chat/completions") {
          res.statusCode = 404;
          res.end(JSON.stringify({ error: { message: "not found" } }));
          return;
        }
        state.calls += 1;
        let body = {};
        try {
          body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        } catch {
          /* 空提示词按无法修复处理 */
        }
        const userPrompt = body?.messages?.find((m) => m.role === "user")?.content ?? "";
        state.prompts.push(userPrompt);
        let promptObj = null;
        try {
          promptObj = JSON.parse(userPrompt);
        } catch {
          /* ignore */
        }
        const src = String(promptObj?.source_lines ?? "");
        const file = String(promptObj?.file ?? "src/app.js");
        const candidates = (promptObj?.candidates ?? []).map((c) => c.candidate);
        const retrying = !!promptObj?.previous_attempt;
        const targetCandidates = retrying ? candidates : candidates.filter((c) => /cancel/i.test(c));
        const patches = [];
        for (const cand of targetCandidates) {
          const block = locateBlock(src, ID_VAR_BY_CANDIDATE[cand] ?? "");
          if (!block) continue;
          patches.push({
            file,
            search: block.search,
            replace: block.replace,
            candidate: cand,
            reason: retrying ? "根据失败证据补齐缺失端点的归属校验" : "首轮只修取消端点",
          });
        }
        state.returned.push(patches.length);
        res.statusCode = 200;
        res.setHeader("Content-Type", "application/json");
        res.end(
          JSON.stringify({
            id: `mock-fix-agent-${state.calls}`,
            object: "chat.completion",
            model: body?.model ?? "deepseek-chat",
            choices: [
              {
                index: 0,
                message: {
                  role: "assistant",
                  content: JSON.stringify({
                    patches,
                    note: retrying ? "mock: 已按上一轮失败用例补齐" : "mock: 首轮故意漏修",
                  }),
                },
                finish_reason: "stop",
              },
            ],
            usage: { prompt_tokens: Math.ceil(userPrompt.length / 4), completion_tokens: 160 },
          })
        );
      });
    });
    server.listen(0, "127.0.0.1", () => resolve({ server, port: server.address().port, state }));
  });
}

const TERMINAL = new Set(["writeback_pending", "verify_failed", "completed", "failed", "error", "aborted"]);

/** 非 gate 交互模式：保持 stdin 打开，等到终态后发送 quit */
function runLocal(project, label, env, timeoutMs = 300_000) {
  return new Promise((resolve, reject) => {
    const child = spawn(exe, ["--project", project, "--report", path.join(reportsDir, label)], {
      cwd: repoRoot,
      env: {
        ...process.env,
        GUARDBUILD_DATA_DIR: dataDir,
        GUARDBUILD_SIDECAR: path.join(repoRoot, "sidecar", "main.mjs"),
        GUARDBUILD_LLM_SCOUT: "",
        GUARDBUILD_LLM_PATCH: "",
        ...env,
      },
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    let lastState = null;
    let done = false;
    const finish = (code, error = null) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try { child.stdin.write(JSON.stringify({ cmd: "quit" }) + "\n"); } catch { /* 已退出 */ }
      child.stdin.end();
      const wait = setTimeout(() => {
        try { child.kill(); } catch { /* ignore */ }
        if (error) reject(error);
        else resolve({ code, stdout, stderr, states: collectStates(stdout), lastState });
      }, 10_000);
      child.once("exit", (c) => {
        clearTimeout(wait);
        if (error) reject(error);
        else resolve({ code: c, stdout, stderr, states: collectStates(stdout), lastState });
      });
    };
    const timer = setTimeout(() => {
      try { child.kill(); } catch { /* ignore */ }
      reject(new Error(`[fix-agent:${label}] 超时 ${timeoutMs}ms；最后状态 ${lastState?.state ?? "?"}`));
    }, timeoutMs);

    let buf = "";
    child.stdout.on("data", (b) => {
      stdout += b.toString();
      buf += b.toString();
      const lines = buf.split("\n");
      buf = lines.pop() ?? "";
      for (const line of lines) {
        if (!line.startsWith("GB_STATE ")) continue;
        try {
          const view = JSON.parse(line.slice("GB_STATE ".length));
          lastState = view;
          if (TERMINAL.has(view.state)) finish(0);
        } catch {
          /* ignore */
        }
      }
    });
    child.stderr.on("data", (b) => { stderr += b.toString(); });
    child.on("exit", (code) => finish(code));
    child.on("error", reject);
  });
}

function collectStates(stdout) {
  return stdout
    .split("\n")
    .filter((l) => l.startsWith("GB_STATE "))
    .map((l) => {
      try { return JSON.parse(l.slice("GB_STATE ".length)).state ?? null; } catch { return null; }
    })
    .filter(Boolean);
}

function lastView(stdout) {
  const lines = stdout.split("\n").filter((l) => l.startsWith("GB_STATE "));
  for (let i = lines.length - 1; i >= 0; i--) {
    try { return JSON.parse(lines[i].slice("GB_STATE ".length)); } catch { /* continue */ }
  }
  return null;
}

function readReport(label) {
  const p = path.join(reportsDir, label, "report.json");
  return existsSync(p) ? JSON.parse(readFileSync(p, "utf8")) : null;
}

function readMd(label) {
  const p = path.join(reportsDir, label, "report.md");
  return existsSync(p) ? readFileSync(p, "utf8") : "";
}

function worktreeDirs() {
  const root = path.join(dataDir, "worktrees");
  if (!existsSync(root)) return [];
  return readdirSync(root).flatMap((s) => {
    const sRoot = path.join(root, s);
    return statSync(sRoot).isDirectory() ? readdirSync(sRoot).map((f) => path.join(sRoot, f)) : [];
  });
}

async function main() {
  console.log("[FIX-AGENT] 准备演示目录…");
  rmSync(demoDir, { recursive: true, force: true });
  mkdirSync(dataDir, { recursive: true });
  if (!existsSync(exe)) {
    throw new Error(`未找到无头宿主: ${exe}（先 cargo build --no-default-features --bin guardbuild-headless）`);
  }

  const ws = makeWorkspace("shop");
  const { server, port: mockPort, state } = await startMockLlm();
  let run;
  try {
    console.log("[FIX-AGENT] 运行本地会话（第 1 轮故意漏修，期望第 2 轮自纠错通过）…");
    run = await runLocal(ws, "loop", {
      DEEPSEEK_API_KEY: MOCK_KEY,
      DEEPSEEK_BASE_URL: `http://127.0.0.1:${mockPort}/v1`,
    });
  } finally {
    await new Promise((r) => server.close(r));
  }

  const view = lastView(run.stdout) ?? {};
  const report = readReport("loop");
  const md = readMd("loop");
  const patch = view.patch ?? {};
  const loop = patch.fixLoop ?? {};
  const acceptance = view.acceptance ?? {};

  check("终态 writeback_pending（自纠错后验收通过）", view.state === "writeback_pending", `state=${view.state}`);
  check("验收通过（攻击全部阻断 + 业务零回归）", acceptance.pass === true && acceptance.attackBlocked === acceptance.attackTotal, `attack=${acceptance.attackBlocked}/${acceptance.attackTotal} business=${acceptance.businessPassed}/${acceptance.businessTotal}`);
  check("模型恰好调用 2 次（首轮 + 修正轮）", state.calls === 2, `calls=${state.calls} returned=${JSON.stringify(state.returned)}`);
  check("首轮提示词不含 previous_attempt", !state.prompts[0]?.includes("previous_attempt"), "");
  check(
    "第二轮提示词带回失败证据（round=1 + regressed 用例）",
    (() => {
      try {
        const obj = JSON.parse(state.prompts[1] ?? "{}");
        return obj.previous_attempt?.round === 1 && (obj.previous_attempt.failed_cases ?? []).length >= 1;
      } catch {
        return false;
      }
    })(),
    ""
  );

  check("视图记录修复循环 2 轮、上限 2", loop.attempts === 2 && loop.maxRounds === 2, `attempts=${loop.attempts} maxRounds=${loop.maxRounds}`);
  check("第 1 轮未通过、第 2 轮通过", loop.rounds?.[0]?.pass === false && loop.rounds?.[1]?.pass === true && loop.resolvedRound === 2, JSON.stringify((loop.rounds ?? []).map((r) => `${r.round}:${r.pass}`)));
  check(
    "每轮补丁 hash 不同（失败轮被丢弃、重新生成）",
    loop.rounds?.[0]?.patchHash && loop.rounds?.[1]?.patchHash && loop.rounds[0].patchHash !== loop.rounds[1].patchHash,
    `${String(loop.rounds?.[0]?.patchHash ?? "").slice(0, 10)}… vs ${String(loop.rounds?.[1]?.patchHash ?? "").slice(0, 10)}…`
  );
  check(
    "第 1 轮记录攻击回归与失败用例",
    (loop.rounds?.[0]?.verdict?.attackRegressed ?? 0) >= 1 && (loop.rounds?.[0]?.failed ?? []).length >= 1,
    JSON.stringify(loop.rounds?.[0]?.failed ?? [])
  );
  const diff = report?.patch?.diff ?? "";
  check("最终补丁同时修两个端点（两处 403）", (diff.match(/^\+.*order\.userId !== auth\.user\.id/mg) ?? []).length === 2, `+403=${(diff.match(/^\+.*order\.userId !== auth\.user\.id/mg) ?? []).length}`);
  check(
    "报告 patch.fixLoop 完整记录两轮",
    report?.patch?.fixLoop?.attempts === 2 &&
      report?.patch?.fixLoop?.resolvedRound === 2 &&
      (report?.patch?.fixLoop?.rounds ?? []).length === 2,
    JSON.stringify(report?.patch?.fixLoop ?? null).slice(0, 160)
  );
  check("报告 markdown 含「修复循环」逐轮记录", md.includes("修复循环：共 2 轮") && md.includes("第 1 轮：未通过") && md.includes("第 2 轮：通过"), "");
  check("报告裁决为 verified", report?.verdict?.patchStatus === "verified" && report?.verdict?.outcome === "vulnerable", `patchStatus=${report?.verdict?.patchStatus}`);

  check("失败轮 worktree 已清理（只保留最终轮）", worktreeDirs().length <= 1, worktreeDirs().join(", ") || "none");

  const db = new DatabaseSync(path.join(dataDir, "guardbuild.db"), { readOnly: true });
  const rows = db.prepare("SELECT patch_hash, status FROM patches WHERE session_id = ?").all(view.sessionId);
  db.close();
  check("DB 记录两轮补丁", rows.length === 2, `rows=${rows.length}`);

  check("原始工作区未被修改（未授权写回）", git(["status", "--porcelain"], ws).trim() === "", "");
  const blob = [JSON.stringify(report ?? {}), md, run.stdout, run.stderr].join("\n");
  check("mock 密钥不进入报告/事件流/stderr", !blob.includes(MOCK_KEY), "");

  const passed = checks.filter((c) => c.pass).length;
  console.log(`\n[FIX-AGENT] 断言: ${passed}/${checks.length} 通过`);
  const failed = checks.filter((c) => !c.pass);
  if (failed.length > 0) {
    console.error(`[FIX-AGENT] 未通过: ${failed.map((c) => c.name).join("、")}`);
    process.exit(1);
  }
  console.log("[FIX-AGENT] 全部通过 ✅");
  rmSync(demoDir, { recursive: true, force: true });
}

main().catch((e) => {
  console.error(`\n[FIX-AGENT] 失败: ${e.message}`);
  const passed = checks.filter((c) => c.pass).length;
  console.log(`[FIX-AGENT] 断言: ${passed}/${checks.length} 通过`);
  process.exit(1);
});
