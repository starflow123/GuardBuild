#!/usr/bin/env node
/**
 * LLM 编码代理（coding agent）端到端演练：用本机回环 mock DeepSeek 驱动 guardbuild-headless --gate，
 * 验证「模型只产出补丁意图 → Sidecar 严格校验 → Host 写入隔离 worktree → 自动双重验收」整条链路。
 *
 *   靶场 fixtures/llm-patch-shop 的取数形态（normalizeId + 三行取数块）刻意规避确定性归属校验模板：
 *   确定性策略必然锚点失配，只有编码代理能产出补丁。guardbuild.json 声明 start/login/identities，
 *   并显式开启 llm.patch + llm.autoVerify（llm.enabled=false 以关闭接入侦察，保证只发生一次模型调用）。
 *
 *   r1 守规矩的模型：两个越权端点都被补齐归属校验 → 自动双重验收通过 → exit 1（vulnerable + verified），
 *      全程不进入 patch_review（人工只在验收通过后审查 Diff 与授权写回）。
 *   r2 不守规矩的模型：越界改文件 + 锚点在文件中出现多次 → 校验阶段拒绝，仅落一个端点的补丁；
 *      于是「攻击未全部阻断」被双重验收拦下 → exit 1（verify_failed），补丁不会交给人工放行。
 *   r3 不提供密钥：编码代理关闭，模板又覆盖不到 → exit 1（vulnerable_unfixed / no_patchable_candidates），
 *      既不放行也不假装修复，且全程零模型调用。
 *
 * 同时校验安全边界：
 *   - 出站走 Host http.request（回环地址用 net.probe 作用域令牌），密钥只从环境变量读取；
 *   - 发给模型的证据只含候选文件源码与已复现证据，不含 identities / 密码 / 契约内容 / 密钥；
 *   - 密钥真实值不出现在 report.json / report.md / 事件流 / stderr；
 *   - gate 全程不改动被测工作区，结束后隔离 worktree 已清理。
 *
 * 用法: node scripts/e2e-llm-patch.mjs
 */
import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { cpSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const demoDir = path.join(repoRoot, ".demo-llm-patch");
const dataDir = path.join(demoDir, "data");
const fixture = path.join(repoRoot, "fixtures", "llm-patch-shop");

/** 无头宿主可执行文件：GUARDBUILD_HEADLESS_BIN > target/debug > target/release（跨平台） */
function resolveHeadlessBin() {
  if (process.env.GUARDBUILD_HEADLESS_BIN) return process.env.GUARDBUILD_HEADLESS_BIN;
  const name = process.platform === "win32" ? "guardbuild-headless.exe" : "guardbuild-headless";
  const debug = path.join(repoRoot, "src-tauri", "target", "debug", name);
  return existsSync(debug) ? debug : path.join(repoRoot, "src-tauri", "target", "release", name);
}
const exe = resolveHeadlessBin();

// 一次性假密钥：只经环境变量传给被测进程，断言它不会流入任何产物
const MOCK_KEY = `sk-mock-${randomBytes(16).toString("hex")}`;

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

/** 候选 → 该端点取数块使用的路径参数变量名（模拟模型「读懂了这段代码」） */
const ID_VAR_BY_CANDIDATE = {
  "GET /api/orders/:id": "orderDetailMatch",
  "POST /api/orders/:id/cancel": "orderCancelMatch",
};

/**
 * 在模型看到的源码文本里定位「取 ID → 取数 → 判空」三行块，产出最小补丁意图。
 * 保留原文行尾（CRLF/LF），否则锚点与真实字节失配。
 */
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
    // 去掉首行后这三个端点共用的片段：在文件里出现多次，合格模型不该拿它当锚点
    ambiguous: join(lines.slice(1)),
  };
}

/** mock DeepSeek chat completions：按模式返回补丁意图，并记录请求特征 */
function startMockLlm() {
  return new Promise((resolve) => {
    const state = {
      mode: "good",
      calls: 0,
      authHeaders: [],
      prompts: [],
      responseFormat: null,
      stream: null,
      model: null,
      returned: [],
    };
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
        state.authHeaders.push(req.headers.authorization ?? null);
        let body = {};
        try {
          body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        } catch {
          /* 交给下面的空体响应 */
        }
        state.model = body?.model ?? null;
        state.responseFormat = body?.response_format?.type ?? null;
        state.stream = body?.stream ?? null;
        const userPrompt = body?.messages?.find((m) => m.role === "user")?.content ?? "";
        state.prompts.push(userPrompt);

        let promptObj = null;
        try {
          promptObj = JSON.parse(userPrompt);
        } catch {
          /* 非法提示词：下面按无法修复响应 */
        }
        const src = String(promptObj?.source_lines ?? "");
        const file = String(promptObj?.file ?? "src/app.js");
        const candidates = (promptObj?.candidates ?? []).map((c) => c.candidate);
        const patches = [];
        let note = "mock: 无法定位可安全修复的锚点";

        if (promptObj && state.mode === "good") {
          for (const cand of candidates) {
            const block = locateBlock(src, ID_VAR_BY_CANDIDATE[cand] ?? "");
            if (!block) continue;
            patches.push({
              file,
              search: block.search,
              replace: block.replace,
              candidate: cand,
              reason: "取数后补齐「资源归属 != 当前用户 → 403」校验，保持原响应契约",
            });
          }
          note = patches.length ? "mock: 逐端点注入归属校验" : note;
        } else if (promptObj && state.mode === "sloppy") {
          // 1) 越界：改动不在本次候选范围内的文件（且属于禁止修改的数据文件）
          patches.push({
            file: "src/data.js",
            search: "export function findOrderById(id) {",
            replace: "// export function findOrderById(id) {",
            candidate: candidates[0] ?? "GET /api/orders/:id",
            reason: "mock: 越界改动数据层",
          });
          // 2) 非唯一锚点：三个端点共用的两行片段
          const first = locateBlock(src, ID_VAR_BY_CANDIDATE[candidates[0]] ?? "orderDetailMatch");
          if (first) {
            patches.push({
              file,
              search: first.ambiguous,
              replace: `${first.ambiguous}${src.includes("\r\n") ? "\r\n" : "\n"}    if (!order) return json(res, 404, { error: "x" });`,
              candidate: candidates[0],
              reason: "mock: 使用重复锚点",
            });
          }
          // 3) 唯一合法的一条：只修复取消端点
          const cancel = locateBlock(src, ID_VAR_BY_CANDIDATE["POST /api/orders/:id/cancel"]);
          if (cancel) {
            patches.push({
              file,
              search: cancel.search,
              replace: cancel.replace,
              candidate: "POST /api/orders/:id/cancel",
              reason: "mock: 仅修复取消端点",
            });
          }
          note = "mock: 混入越界与歧义锚点";
        }
        state.returned.push(patches.length);

        res.statusCode = 200;
        res.setHeader("Content-Type", "application/json");
        res.end(
          JSON.stringify({
            id: `mock-patch-${state.calls}`,
            object: "chat.completion",
            model: state.model ?? "deepseek-chat",
            choices: [
              {
                index: 0,
                message: { role: "assistant", content: JSON.stringify({ patches, note }) },
                finish_reason: "stop",
              },
            ],
            usage: {
              prompt_tokens: Math.ceil(userPrompt.length / 4),
              completion_tokens: 180,
              total_tokens: Math.ceil(userPrompt.length / 4) + 180,
            },
          })
        );
      });
    });
    server.listen(0, "127.0.0.1", () => resolve({ server, port: server.address().port, state }));
  });
}

function runGate(project, label, env, timeoutMs = 300_000) {
  return new Promise((resolve, reject) => {
    const child = spawn(
      exe,
      ["--gate", "--project", project, "--report", path.join(demoDir, "reports", label)],
      {
        cwd: repoRoot,
        env: {
          ...process.env,
          GUARDBUILD_DATA_DIR: dataDir,
          GUARDBUILD_SIDECAR: path.join(repoRoot, "sidecar", "main.mjs"),
          GUARDBUILD_LLM_SCOUT: "",
          GUARDBUILD_LLM_PATCH: "",
          ...env,
        },
        stdio: ["ignore", "pipe", "pipe"],
      }
    );
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (b) => { stdout += b.toString(); });
    child.stderr.on("data", (b) => { stderr += b.toString(); });
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`[llm-patch:${label}] 超时 ${timeoutMs}ms`));
    }, timeoutMs);
    child.on("exit", (code) => {
      clearTimeout(timer);
      const gateLine = stdout.split("\n").filter((l) => l.startsWith("GB_GATE ")).pop();
      let gate = null;
      if (gateLine) {
        try { gate = JSON.parse(gateLine.slice("GB_GATE ".length)); } catch { /* ignore */ }
      }
      const states = stdout
        .split("\n")
        .filter((l) => l.startsWith("GB_STATE "))
        .map((l) => {
          try { return JSON.parse(l.slice("GB_STATE ".length)).state ?? null; } catch { return null; }
        })
        .filter(Boolean);
      resolve({ code, gate, states, stdout, stderr });
    });
    child.on("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
  });
}

function lastView(stdout) {
  const lines = stdout.split("\n").filter((l) => l.startsWith("GB_STATE "));
  for (let i = lines.length - 1; i >= 0; i--) {
    try {
      return JSON.parse(lines[i].slice("GB_STATE ".length));
    } catch {
      /* 继续向前找 */
    }
  }
  return null;
}

function readReport(round) {
  const p = path.join(demoDir, "reports", round, "report.json");
  if (!existsSync(p)) return null;
  try { return JSON.parse(readFileSync(p, "utf8")); } catch { return null; }
}

function readMd(round) {
  const p = path.join(demoDir, "reports", round, "report.md");
  return existsSync(p) ? readFileSync(p, "utf8") : "";
}

function worktreeLeftovers() {
  const root = path.join(dataDir, "worktrees");
  if (!existsSync(root)) return [];
  return readdirSync(root).flatMap((s) => {
    const sRoot = path.join(root, s);
    return statSync(sRoot).isDirectory() ? readdirSync(sRoot).map((f) => path.join(sRoot, f)) : [];
  });
}

async function main() {
  console.log("[LLM-PATCH] 0/3 准备演示目录…");
  rmSync(demoDir, { recursive: true, force: true });
  mkdirSync(dataDir, { recursive: true });
  if (!existsSync(exe)) {
    throw new Error(`未找到无头宿主: ${exe}（先 cargo build --no-default-features --bin guardbuild-headless）`);
  }

  const { server, port: mockPort, state } = await startMockLlm();
  const llmEnv = {
    DEEPSEEK_API_KEY: MOCK_KEY,
    DEEPSEEK_BASE_URL: `http://127.0.0.1:${mockPort}/v1`,
  };

  let r1;
  let r2;
  let callsAfterR1 = 0;
  let callsAfterR2 = 0;
  try {
    console.log("\n[LLM-PATCH] 1/3 守规矩的编码代理：期望 exit 1（自动双重验收通过的补丁）…");
    state.mode = "good";
    r1 = await runGate(makeWorkspace("patch-good"), "r1", llmEnv);
    callsAfterR1 = state.calls;

    console.log("\n[LLM-PATCH] 2/3 不守规矩的编码代理：期望被校验拒绝并由双重验收拦下…");
    state.mode = "sloppy";
    r2 = await runGate(makeWorkspace("patch-sloppy"), "r2", llmEnv);
    callsAfterR2 = state.calls;
  } finally {
    await new Promise((r) => server.close(r));
  }

  console.log("\n[LLM-PATCH] 3/3 不提供密钥：期望编码代理关闭且诚实判定漏洞未修复…");
  const r3 = await runGate(makeWorkspace("patch-off"), "r3", {
    DEEPSEEK_API_KEY: "",
    DEEPSEEK_BASE_URL: "",
  });

  // ======================= r1：补丁意图 → 自动验收通过 =======================
  const g1 = r1.gate ?? {};
  const v1 = lastView(r1.stdout) ?? {};
  const p1 = v1.patch ?? {};
  const llm1 = p1.llm ?? {};
  const rep1 = readReport("r1");
  const md1 = readMd("r1");

  check("r1 退出码 = 1（漏洞证据成立 + 补丁已验证）", r1.code === 1, `code=${r1.code}`);
  check(
    "r1 verdict=vulnerable 且 patchStatus=verified",
    g1.verdict === "vulnerable" && g1.patchStatus === "verified",
    `verdict=${g1.verdict} patchStatus=${g1.patchStatus} state=${g1.state}`
  );
  check("r1 全程未进入 patch_review（先自动验收再交人工）", !r1.states.includes("patch_review"), r1.states.join("→"));
  check("r1 事件流说明补丁来自 LLM 编码代理并自动验收", r1.stdout.includes("LLM 编码代理") && r1.stdout.includes("自动执行双重验收"), "");
  check("r1 双重验收通过事件（攻击阻断 + 业务保持）", /双重验收通过：攻击阻断 \d+\/\d+，业务保持 \d+\/\d+/.test(r1.stdout), (r1.stdout.match(/双重验收通过：[^\n]*/) ?? [""])[0]);

  check("r1 mock LLM 恰好 1 次补丁请求（接入侦察已关闭）", callsAfterR1 === 1, `calls=${callsAfterR1}`);
  check(
    "r1 出站经 Host 且带 Bearer 鉴权",
    state.authHeaders[0] === `Bearer ${MOCK_KEY}`,
    state.authHeaders[0] ? "Authorization: Bearer ***" : "无鉴权头"
  );
  check(
    "r1 请求为 JSON 模式（json_object + stream=false + deepseek-chat）",
    state.responseFormat === "json_object" && state.stream === false && state.model === "deepseek-chat",
    `format=${state.responseFormat} stream=${state.stream} model=${state.model}`
  );

  const prompt1 = state.prompts[0] ?? "";
  check(
    "提示词含候选端点与真实源码锚点",
    prompt1.includes("GET /api/orders/:id") &&
      prompt1.includes("POST /api/orders/:id/cancel") &&
      prompt1.includes("normalizeId(orderDetailMatch[1])"),
    `${prompt1.length} 字符`
  );
  check("提示词含已复现的攻击证据（vulnerable）", prompt1.includes("reproduced_evidence") && prompt1.includes("vulnerable"), "");
  check(
    "提示词不含身份密码 / guardbuild.json 契约内容",
    !prompt1.includes("alice123") && !prompt1.includes("bob123") && !prompt1.includes("readyPattern") && !prompt1.includes("identities"),
    ""
  );
  check("提示词不含密钥", !prompt1.includes(MOCK_KEY), "");

  check(
    "视图记录补丁策略为 llm-coding-agent",
    String(p1.strategy ?? "").includes("llm-coding-agent"),
    `strategy=${p1.strategy}`
  );
  check("视图标记该补丁走自动双重验收", p1.autoVerify === true, `autoVerify=${p1.autoVerify}`);
  check(
    "视图记录编码代理统计（1 个文件 / 2 处补丁采纳 / 0 拒绝）",
    llm1.enabled === true &&
      (llm1.requestedFiles ?? []).length === 1 &&
      (llm1.appliedFiles ?? []).length === 1 &&
      llm1.appliedFiles[0].file === "src/app.js" &&
      llm1.appliedFiles[0].ops === 2 &&
      llm1.appliedOps === 2 &&
      (llm1.rejected ?? []).length === 0,
    `appliedOps=${llm1.appliedOps} rejected=${(llm1.rejected ?? []).length} files=${JSON.stringify(llm1.appliedFiles)}`
  );
  check("视图记录模型名与 token 用量", llm1.model === "deepseek-chat" && Number(llm1.usage?.[0]?.total_tokens ?? 0) > 0, `model=${llm1.model} usage=${JSON.stringify(llm1.usage?.[0] ?? {})}`);
  check(
    "补丁 fixes 逐条标注候选与策略",
    (p1.fixes ?? []).some((f) => (f.fixes ?? []).some((x) => x.strategy === "llm-coding-agent" && /GET \/api\/orders\/:id/i.test(x.candidate ?? ""))),
    JSON.stringify((p1.fixes ?? []).map((f) => f.fixes?.map((x) => `${x.candidate}:${x.strategy}`)))
  );

  const acc1 = v1.acceptance ?? {};
  check(
    "r1 验收裁决通过（攻击全部阻断 + 业务零回归）",
    acc1.pass === true && acc1.attackTotal >= 2 && acc1.attackBlocked === acc1.attackTotal && acc1.businessTotal >= 1 && acc1.businessPassed === acc1.businessTotal,
    `attack=${acc1.attackBlocked}/${acc1.attackTotal} business=${acc1.businessPassed}/${acc1.businessTotal}`
  );
  const post1Vuln = (rep1?.evidence?.post ?? []).filter((e) => e.verdict === "vulnerable");
  check("r1 修复后证据：无越权成功", post1Vuln.length === 0, `vulnerable=${post1Vuln.length}`);

  // 逐候选归因：补丁点名的每个入口必须自己完成「打穿 → 阻断」，总体变好不算了数
  const attr1 = acc1.attribution ?? {};
  check(
    "r1 归因：点名的 2 个入口均自行翻转（打穿 → 阻断），无 unverified",
    attr1.pass === true &&
      attr1.claimedCount === 2 &&
      attr1.blockedCount === 2 &&
      attr1.unverifiedCount === 0 &&
      attr1.stillVulnerableCount === 0 &&
      (attr1.failing ?? []).length === 0,
    `claimed=${attr1.claimedCount} blocked=${attr1.blockedCount} unverified=${attr1.unverifiedCount}`
  );
  const claimedRows1 = (attr1.rows ?? []).filter((r) => r.claimed);
  check(
    "r1 归因给出补丁 hunk 与候选源码的同文件定位（行距可算）",
    claimedRows1.length === 2 && claimedRows1.every((r) => r.locality === "same_file" && r.hunksInFile >= 1 && Number.isFinite(r.hunkDistance)),
    JSON.stringify(claimedRows1.map((r) => `${r.candidate}:${r.locality}:${r.file}:${r.hunkDistance}`))
  );
  check(
    "归因表只落仓库相对路径，不含用户绝对路径",
    (attr1.rows ?? []).every((r) => !String(r.file ?? "").includes(".demo-llm-patch") && !/\\\\/.test(String(r.file ?? ""))),
    JSON.stringify((attr1.rows ?? []).map((r) => r.file))
  );
  check(
    "r1 报告 markdown 有「逐候选归因」表（入口 / 结论）",
    readMd("r1").includes("逐候选归因") && readMd("r1").includes("已翻转"),
    ""
  );
  check(
    "r1 修复后证据：越权读与越权取消均被拒绝",
    (rep1?.evidence?.post ?? []).filter((e) => e.category === "attack" && e.verdict === "blocked").length >= 2,
    `blocked=${(rep1?.evidence?.post ?? []).filter((e) => e.verdict === "blocked").length}`
  );
  const diff1 = rep1?.patch?.diff ?? "";
  check(
    "补丁 diff 只加归属校验（两处 403）",
    (diff1.match(/^\+.*order\.userId !== auth\.user\.id/mg) ?? []).length === 2 && diff1.includes("无权访问该订单"),
    `+行=${(diff1.match(/^\+(?!\+\+)/gm) ?? []).length}`
  );
  check(
    "报告写入编码代理字段（策略 / autoVerify / 采纳统计）",
    String(rep1?.patch?.strategy ?? "").includes("llm-coding-agent") &&
      rep1?.patch?.autoVerify === true &&
      rep1?.patch?.llm?.appliedOps === 2 &&
      (rep1?.patch?.llm?.appliedFiles ?? []).length === 1,
    `strategy=${rep1?.patch?.strategy} appliedOps=${rep1?.patch?.llm?.appliedOps}`
  );
  check("报告 markdown 含「LLM 编码代理（补丁意图）」章节", md1.includes("LLM 编码代理（补丁意图）") && md1.includes("双重验收"), "");
  check(
    "报告 patch.fixes 逐候选可审计（候选→策略→文件）",
    (rep1?.patch?.fixes ?? []).some(
      (f) =>
        f.file === "src/app.js" &&
        (f.candidates ?? []).length === 2 &&
        f.candidates.every((c) => c.strategy === "llm-coding-agent")
    ),
    JSON.stringify(rep1?.patch?.fixes ?? null)
  );
  check(
    "报告 patch.llm 记录 token 用量",
    Number(rep1?.patch?.llm?.usage?.[0]?.total_tokens ?? 0) > 0,
    JSON.stringify(rep1?.patch?.llm?.usage ?? null)
  );
  check("报告 markdown 含逐候选补丁行", /逐候选：.*GET \/api\/orders\/:id.*llm-coding-agent/.test(md1), "");

  const db = new DatabaseSync(path.join(dataDir, "guardbuild.db"), { readOnly: true });
  const patchRow1 = db.prepare("SELECT strategy, status FROM patches WHERE session_id = ?").get(g1.sessionId);
  const postBad1 = db
    .prepare("SELECT COUNT(*) n FROM evidence WHERE session_id = ? AND phase='post' AND verdict='vulnerable'")
    .get(g1.sessionId).n;
  check("DB 补丁记录策略含 llm-coding-agent", /llm-coding-agent/.test(patchRow1?.strategy ?? ""), `strategy=${patchRow1?.strategy}`);
  check("DB 修复后证据无 vulnerable 残留", postBad1 === 0, `post vulnerable=${postBad1}`);
  db.close();

  check("r1 被测工作区未被修改（gate 禁止写回）", git(["status", "--porcelain"], path.join(demoDir, "patch-good")).trim() === "", "");
  check("r1 隔离 worktree 已清理", worktreeLeftovers().length === 0, worktreeLeftovers().slice(0, 3).join(", ") || "none");

  // ======================= r2：劣质输出被校验拒绝并由验收拦下 =======================
  const g2 = r2.gate ?? {};
  const v2 = lastView(r2.stdout) ?? {};
  const llm2 = v2.patch?.llm ?? {};
  const rep2 = readReport("r2");
  const md2 = readMd("r2");

  check("r2 退出码 = 1（不放行）", r2.code === 1, `code=${r2.code}`);
  check(
    "r2 终态 verify_failed（补丁未通过双重验收）",
    g2.state === "verify_failed" && g2.patchStatus === "verify_failed" && g2.verdict === "vulnerable",
    `state=${g2.state} patchStatus=${g2.patchStatus} verdict=${g2.verdict}`
  );
  check("r2 仍全程不进入 patch_review", !r2.states.includes("patch_review"), r2.states.join("→"));
  check("r2 mock LLM 追加 1 次调用（累计 2）", callsAfterR2 === 2 && callsAfterR2 - callsAfterR1 === 1, `calls=${callsAfterR2}`);
  check(
    "r2 越界改文件被拒绝",
    (llm2.rejected ?? []).some((r) => String(r.reason).includes("越出本次候选文件") || String(r.reason).includes("不允许修改")),
    JSON.stringify((llm2.rejected ?? []).map((r) => `${r.file}:${r.reason}`))
  );
  check(
    "r2 非唯一锚点被拒绝",
    (llm2.rejected ?? []).some((r) => String(r.reason).includes("出现多次")),
    JSON.stringify((llm2.rejected ?? []).map((r) => r.reason))
  );
  check("r2 仅落地 1 处经校验的补丁", llm2.appliedOps === 1 && (llm2.rejected ?? []).length >= 2, `appliedOps=${llm2.appliedOps} rejected=${(llm2.rejected ?? []).length}`);
  check(
    "r2 双重验收未通过：越权读仍在",
    v2.acceptance?.pass === false && v2.acceptance.attackBlocked < v2.acceptance.attackTotal,
    `attack=${v2.acceptance?.attackBlocked}/${v2.acceptance?.attackTotal} business=${v2.acceptance?.businessPassed}/${v2.acceptance?.businessTotal}`
  );
  // 归因只对「补丁点名却没翻转」的入口行使否决权；未点名的入口仍要如实呈现
  const attr2 = v2.acceptance?.attribution ?? {};
  check(
    "r2 归因：点名的取消入口自证翻转，未点名的越权读记为仍可越权",
    attr2.claimedCount === 1 &&
      attr2.blockedCount === 1 &&
      (attr2.rows ?? []).some((r) => !r.claimed && r.status === "still_vulnerable" && r.preReproCases >= 1),
    `claimed=${attr2.claimedCount} blocked=${attr2.blockedCount} rows=${JSON.stringify((attr2.rows ?? []).map((r) => `${r.candidate}:${r.claimed}:${r.status}`))}`
  );
  check(
    "r2 报告 markdown 的归因表只列点名的取消入口",
    md2.includes("逐候选归因") && /\| `POST \/api\/orders\/:id\/cancel` \| \d+ \| .*已翻转/.test(md2),
    (md2.match(/逐候选归因[\s\S]{0,400}/) ?? [""])[0].replace(/\n/g, " | ").slice(0, 260)
  );
  check("r2 报告记录被拒绝意图章节", md2.includes("被拒绝的补丁意图"), "");
  check(
    "r2 报告 patch.llm 记录采纳 1 处 / 拒绝 ≥ 2 条",
    rep2?.patch?.llm?.appliedOps === 1 && (rep2?.patch?.llm?.rejected ?? []).length >= 2,
    `appliedOps=${rep2?.patch?.llm?.appliedOps} rejected=${(rep2?.patch?.llm?.rejected ?? []).length}`
  );
  check(
    "r2 报告逐候选只标已落地的取消候选，且记下未产出补丁的候选",
    (rep2?.patch?.fixes ?? []).flatMap((f) => f.candidates ?? []).some((c) => /POST \/api\/orders\/:id\/cancel/i.test(c.candidate ?? "")) &&
      (rep2?.patch?.skipped ?? []).length >= 1,
    `fixes=${JSON.stringify(rep2?.patch?.fixes ?? null)} skipped=${(rep2?.patch?.skipped ?? []).length}`
  );
  check(
    "r2 报告裁决为 verify_failed",
    rep2?.verdict?.outcome === "vulnerable" && rep2?.verdict?.patchStatus === "verify_failed" && rep2?.verdict?.exitCode === 1,
    `outcome=${rep2?.verdict?.outcome} patchStatus=${rep2?.verdict?.patchStatus}`
  );
  check("r2 被测工作区未被修改", git(["status", "--porcelain"], path.join(demoDir, "patch-sloppy")).trim() === "", "");
  check("r2 隔离 worktree 已清理", worktreeLeftovers().length === 0, worktreeLeftovers().slice(0, 3).join(", ") || "none");

  // ======================= r3：无密钥 → 诚实降级 =======================
  const g3 = r3.gate ?? {};
  const rep3 = readReport("r3");
  check("r3 退出码 = 1（漏洞证据成立）", r3.code === 1, `code=${r3.code}`);
  check(
    "r3 verdict=vulnerable_unfixed 且 error.code=no_patchable_candidates",
    g3.verdict === "vulnerable_unfixed" && g3.error?.code === "no_patchable_candidates",
    `verdict=${g3.verdict} code=${g3.error?.code}`
  );
  check("r3 裁决提示指向 llm.patch 开关", String(g3.error?.hint ?? "").includes("llm.patch"), `hint=${String(g3.error?.hint ?? "").slice(0, 48)}…`);
  check("r3 零模型调用（未配密钥不外发）", state.calls === callsAfterR2, `calls=${state.calls}`);
  check("r3 未出现编码代理补丁事件", !r3.stdout.includes("LLM 编码代理为"), "");
  check("r3 报告无补丁对象", rep3?.patch === null, `patch=${rep3?.patch ? "有" : "无"}`);
  const vuln3 = (rep3?.evidence?.pre ?? []).filter((e) => e.verdict === "vulnerable");
  check("r3 修复前证据仍复现越权（≥ 2）", vuln3.length >= 2, `vulnerable=${vuln3.length}`);
  check("r3 被测工作区未被修改", git(["status", "--porcelain"], path.join(demoDir, "patch-off")).trim() === "", "");

  // ======================= 密钥不泄漏 =======================
  const blob = [
    JSON.stringify(rep1 ?? {}), md1, r1.stdout, r1.stderr,
    JSON.stringify(rep2 ?? {}), md2, r2.stdout, r2.stderr,
    JSON.stringify(rep3 ?? {}), readMd("r3"), r3.stdout, r3.stderr,
  ].join("\n");
  check("mock 密钥不进入报告/事件流/stderr", !blob.includes(MOCK_KEY), "");

  const passed = checks.filter((c) => c.pass).length;
  console.log(`\n[LLM-PATCH] 断言: ${passed}/${checks.length} 通过`);
  const failed = checks.filter((c) => !c.pass);
  if (failed.length > 0) {
    console.error(`[LLM-PATCH] 未通过: ${failed.map((c) => c.name).join("、")}`);
    process.exit(1);
  }
  console.log("[LLM-PATCH] 全部通过 ✅");
}

main().catch((e) => {
  console.error(`\n[LLM-PATCH] 失败: ${e.message}`);
  const passed = checks.filter((c) => c.pass).length;
  console.log(`[LLM-PATCH] 断言: ${passed}/${checks.length} 通过`);
  process.exit(1);
});
