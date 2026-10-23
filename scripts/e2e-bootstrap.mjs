#!/usr/bin/env node
/**
 * S3-full（有界启动代理）端到端演练：以本机回环 mock DeepSeek 驱动 guardbuild-headless，
 * 验证「目标起不来 → 代理在引擎生成的动作菜单里自主处理接入障碍 → 真实拉起才算数」这条链路，
 * 以及它的两条硬边界：模型只能报编号（命令行由引擎拼装）、gate/CI 结构性禁用。
 *
 *   靶场 fixtures/bootstrap-shop：入口 src/data.js 静态 import 构建产物 build/config.js
 *   （由 npm run build 从 config/orders.seed.json 生成）。仓库里只有种子数据，所以
 *   guardbuild.json 里人类声明的启动契约「node server.js」在接入这一步注定失败
 *   （ERR_MODULE_NOT_FOUND，诊断码 missing_dependency）——只有启动代理能把项目拉起来。
 *
 *   r1 正常协作的模型：read scripts/build.js → exec 编号 2（npm run build）→ start 候选 1。
 *      其中 exec 那一步同时 smuggle 了自带的 cmd/args：引擎必须丢掉这些字段、
 *      只按编号执行自己拼的那条命令，并在审计里留痕。构建产物真的落盘、目标真的就绪、
 *      越权证据照旧复现（接入层自救与漏洞裁决彼此解耦）。
 *   r2 反叛的模型：连续报菜单外编号（99 / 42）并试图塞命令行 → 全部被拒 → giveup。
 *      引擎不执行任何模型给的命令（构建产物不出现），会话诚实失败为 target_not_ready，
 *      不伪造「起好了」。
 *   r3 gate 模式 + GUARDBUILD_LLM_BOOTSTRAP=1（且契约里 bootstrap.enabled=true）：
 *      agentic 能力在 CI 里被结构性禁用——没有任何启动代理动作，工作区零改动，
 *      仍按确定性契约失败（exit 2），报告里 bootstrap 字段为 null。
 *
 * 同时校验安全边界：
 *   - 出站走 Host http.request（回环端点用 net.probe 作用域令牌），密钥只从环境变量读取；
 *   - 发给模型的观察只含目标/菜单编号/失败诊断/预算，不含 identities、密码、契约内容；
 *   - 模型原文不进审计：密钥与「私藏命令行」哨兵不出现在事件流、视图、报告、DB 与日志里；
 *   - 每个动作都写 agent_actions（动作/形状/退出码/用时/剩余预算），可事后回看。
 *
 * 用法: node scripts/e2e-bootstrap.mjs
 */
import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import readline from "node:readline";
import { fileURLToPath } from "node:url";
import { openAuditDb, queryAudit } from "./lib/auditdb.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const demoDir = path.join(repoRoot, ".demo-bootstrap");
const dataDir = path.join(demoDir, "data");
const fixture = path.join(repoRoot, "fixtures", "bootstrap-shop");

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
// 哨兵：模型想自己拼命令行时塞进 cmd/args 的内容，绝不允许出现在任何留痕里
const LEAK = "LEAK-SMUGGLED-CMDLINE-9f2c";
// 契约哨兵：guardbuild.json 的私有内容不该出现在给模型的观察里
const SENTINEL = "SENTINEL_GUARDBUILD_CONTRACT_MUST_NOT_BE_SENT_TO_LLM";

const BUILD_REL = path.join("build", "config.js");

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

/**
 * 复制靶场并提交基线。
 * @param {string} name
 * @param {(ws: string) => void} [mutate] 复制后、提交前的改写（如植入契约哨兵）
 */
function makeWorkspace(name, mutate) {
  const ws = path.join(demoDir, name);
  rmSync(ws, { recursive: true, force: true });
  mkdirSync(demoDir, { recursive: true });
  cpSync(fixture, ws, { recursive: true });
  if (mutate) mutate(ws);
  git(["init", "-q"], ws);
  git(["config", "user.email", "gate@guardbuild.local"], ws);
  git(["config", "user.name", "GuardBuild Gate"], ws);
  git(["config", "core.autocrlf", "false"], ws);
  git(["add", "-A"], ws);
  git(["commit", "-qm", `${name} 基线`], ws);
  return ws;
}

/** 模型的一步选择：只报编号（smuggle=true 时附带引擎不该采纳的命令行字段） */
function execPick(id, { smuggle = false } = {}) {
  const pick = { action: "exec", id, note: "mock: 先补齐接入产物" };
  if (smuggle) {
    pick.cmd = "node";
    pick.args = ["-e", `${LEAK}`];
    pick.shell = `npm publish ${LEAK}`;
  }
  return pick;
}

function startPick(candidate = 1) {
  return { action: "start", candidate, note: "mock: 试拉起引擎登记的入口" };
}

/** mock DeepSeek chat completions：按脚本回放启动代理的选择，并记录请求特征 */
function startMockLlm() {
  return new Promise((resolve) => {
    const state = {
      script: [],
      calls: 0,
      returned: [],
      authHeaders: [],
      models: [],
      prompts: [],
      systems: [],
      responseFormat: null,
      stream: null,
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
          /* 交给下面的空脚本响应 */
        }
        const model = body?.model ?? null;
        state.models.push(model);
        state.responseFormat = body?.response_format?.type ?? null;
        state.stream = body?.stream ?? null;
        state.systems.push(body?.messages?.find((m) => m.role === "system")?.content ?? "");
        const userPrompt = body?.messages?.find((m) => m.role === "user")?.content ?? "";
        state.prompts.push(userPrompt);
        const payload = state.script.length
          ? state.script.shift()
          : { action: "giveup", note: "mock: 脚本已用尽，收手" };
        state.returned.push(`${payload.action ?? "?"}${payload.id !== undefined ? `:${payload.id}` : ""}${payload.candidate !== undefined ? `:${payload.candidate}` : ""}`);
        res.statusCode = 200;
        res.setHeader("Content-Type", "application/json");
        res.end(
          JSON.stringify({
            id: `mock-boot-${state.calls}`,
            object: "chat.completion",
            model: model ?? "deepseek-chat",
            choices: [
              { index: 0, message: { role: "assistant", content: JSON.stringify(payload) }, finish_reason: "stop" },
            ],
            usage: {
              prompt_tokens: Math.ceil(userPrompt.length / 4),
              completion_tokens: 60,
              total_tokens: Math.ceil(userPrompt.length / 4) + 60,
            },
          })
        );
      });
    });
    server.listen(0, "127.0.0.1", () => resolve({ server, port: server.address().port, state }));
  });
}

/** 交互（非 gate）会话：启动代理只在交互模式启用，gate 里由代码层结构性禁用 */
function openSession(label, env = {}, argv = []) {
  return new Promise((resolve, reject) => {
    const child = spawn(exe, argv, {
      cwd: repoRoot,
      env: {
        ...process.env,
        GUARDBUILD_DATA_DIR: dataDir,
        GUARDBUILD_SIDECAR: path.join(repoRoot, "sidecar", "main.mjs"),
        GUARDBUILD_LLM_SCOUT: "",
        GUARDBUILD_LLM_PATCH: "",
        GUARDBUILD_AUTO_CONSENT: "1",
        ...env,
      },
      stdio: ["pipe", "pipe", "pipe"],
    });
    const s = {
      label,
      log: "",
      errText: "",
      view: null,
      views: [],
      events: [],
      states: [],
      exitCode: null,
      waiters: [],
    };
    readline
      .createInterface({ input: child.stdout })
      .on("line", (line) => {
        s.log += `${line}\n`;
        if (line.startsWith("GB_STATE ")) {
          try {
            const v = JSON.parse(line.slice("GB_STATE ".length));
            s.view = v;
            s.views.push(v);
            if (v.state) s.states.push(v.state);
            for (const w of [...s.waiters]) {
              let hit = false;
              try {
                hit = w.pred(v);
              } catch {
                hit = false;
              }
              if (hit) {
                s.waiters.splice(s.waiters.indexOf(w), 1);
                clearTimeout(w.timer);
                w.resolve(v);
              }
            }
          } catch {
            /* 非视图行 */
          }
        } else if (line.startsWith("GB_EVENT ")) {
          try {
            s.events.push(JSON.parse(line.slice("GB_EVENT ".length)));
          } catch {
            /* ignore */
          }
        }
      });
    child.stderr.on("data", (b) => {
      s.errText += b.toString();
    });
    child.on("exit", (code) => {
      s.exitCode = code;
      for (const w of [...s.waiters]) {
        clearTimeout(w.timer);
        s.waiters.splice(s.waiters.indexOf(w), 1);
        w.reject(new Error(`[${label}] 宿主提前退出 code=${code}：${s.errText.slice(-500)}`));
      }
    });
    child.on("error", reject);
    s.send = (obj) => child.stdin.write(`${JSON.stringify(obj)}\n`);
    s.wait = (pred, what, timeoutMs = 300_000) =>
      new Promise((resolve2, reject2) => {
        const okNow = () => {
          if (!s.view) return false;
          try {
            return pred(s.view);
          } catch {
            return false;
          }
        };
        if (okNow()) return resolve2(s.view);
        const w = {
          pred,
          resolve: resolve2,
          timer: setTimeout(() => {
            const i = s.waiters.indexOf(w);
            if (i >= 0) s.waiters.splice(i, 1);
            reject2(new Error(`[${label}] 等待「${what}」超时（state=${s.view?.state ?? "-"}，状态序列：${s.states.join("→")}）`));
          }, timeoutMs),
        };
        s.waiters.push(w);
      });
    s.close = async () => {
      s.send({ cmd: "quit" });
      for (let i = 0; i < 60 && s.exitCode === null; i++) await new Promise((r) => setTimeout(r, 200));
      if (s.exitCode === null) child.kill();
    };
    resolve(s);
  });
}

function runGate(project, label, env, timeoutMs = 300_000) {
  return new Promise((resolve, reject) => {
    const child = spawn(exe, ["--gate", "--project", project, "--report", path.join(demoDir, "reports", label)], {
      cwd: repoRoot,
      env: {
        ...process.env,
        GUARDBUILD_DATA_DIR: dataDir,
        GUARDBUILD_SIDECAR: path.join(repoRoot, "sidecar", "main.mjs"),
        ...env,
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (b) => {
      stdout += b.toString();
    });
    child.stderr.on("data", (b) => {
      stderr += b.toString();
    });
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`[bootstrap:${label}] 超时 ${timeoutMs}ms`));
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

function readReport(round, file = "report.json") {
  const p = path.join(demoDir, "reports", round, file);
  if (!existsSync(p)) return null;
  try {
    return JSON.parse(readFileSync(p, "utf8"));
  } catch {
    return null;
  }
}

function readMarkdown(round) {
  const p = path.join(demoDir, "reports", round, "report.md");
  return existsSync(p) ? readFileSync(p, "utf8") : "";
}

function agentActions(sessionId) {
  return queryAudit(
    path.join(dataDir, "guardbuild.db"),
    "SELECT step, action, subject, ok, exit_code, duration_ms, budget_remaining_ms, note FROM agent_actions WHERE session_id = ? ORDER BY step, created_at",
    [sessionId],
    { label: "agent_actions" }
  );
}

function countVulnerablePre(sessionId) {
  return queryAudit(
    path.join(dataDir, "guardbuild.db"),
    "SELECT COUNT(*) n FROM evidence WHERE session_id = ? AND phase='pre' AND verdict='vulnerable'",
    [sessionId],
    { single: true, label: "pre-vulnerable" }
  ).n;
}

const actionSeq = (rows) => rows.map((r) => r.action).join("→");

async function main() {
  console.log("[BOOT] 0/4 准备演示目录…");
  rmSync(demoDir, { recursive: true, force: true });
  mkdirSync(dataDir, { recursive: true });
  if (!existsSync(exe)) throw new Error(`未找到无头宿主: ${exe}（先 cargo build --no-default-features --bin guardbuild-headless）`);

  // r1 工作区把契约注释换成哨兵：代理真的读清单文件，哨兵若出现在观察里就是泄漏
  const ws1 = makeWorkspace("boot-agent-ok", (dir) => {
    const p = path.join(dir, "guardbuild.json");
    const cfg = JSON.parse(readFileSync(p, "utf8"));
    cfg._note = SENTINEL;
    writeFileSync(p, JSON.stringify(cfg, null, 2));
  });
  const ws2 = makeWorkspace("boot-agent-defiant");
  const gateWs = makeWorkspace("boot-gate-disabled");

  const { server, port: mockPort, state } = await startMockLlm();
  const llmEnv = {
    DEEPSEEK_API_KEY: MOCK_KEY,
    DEEPSEEK_BASE_URL: `http://127.0.0.1:${mockPort}/v1`,
  };

  let s1;
  let s2;
  let r3;
  let callsAfterR1 = 0;
  let callsAfterR2 = 0;
  try {
    // ============ r1：读清单 → 按编号构建 → 真实拉起（自带命令行被丢弃） ============
    console.log("\n[BOOT] 1/4 交互模式：代理自主「读构建脚本 → 执行 npm run build → 启动」…");
    state.script = [
      { action: "read", path: "scripts/build.js", note: "mock: 先确认构建脚本做什么" },
      execPick(2, { smuggle: true }),
      startPick(1),
    ];
    s1 = await openSession("r1", llmEnv, ["--report", path.join(demoDir, "reports", "r1")]);
    s1.send({ cmd: "start", project: ws1 });
    await s1.wait((v) => v.sessionId, "会话建立", 60_000);
    const sid1 = s1.view.sessionId;
    await s1.wait(
      (v) => v.sessionId === sid1 && ["error", "patch_review", "writeback_pending", "applied", "completed"].includes(v.state),
      "启动代理接管后的完整一轮",
      330_000
    );
    callsAfterR1 = state.calls;
    const b1 = s1.view.bootstrap ?? {};
    const acts1 = agentActions(sid1);
    const rep1 = readReport("r1");
    const md1 = readMarkdown("r1");

    check(
      "r1 目标由启动代理真正拉起（outcome=started，非模型自评）",
      b1.outcome === "started" && Number(b1.stepsUsed) >= 3 && !!b1.url,
      `outcome=${b1.outcome} steps=${b1.stepsUsed} url=${b1.url ?? "-"}`
    );
    check(
      "r1 动作序列：只读查看 → 丢弃走私命令行 → 执行构建 → 真实启动",
      actionSeq(acts1) === "read→sanitize→exec→start",
      `序列=${actionSeq(acts1)}（视图 ${actionSeq((b1.actions ?? []).map((a) => ({ action: a.action })))}）`
    );
    check("r1 触发原因是确定性启动契约的真实失败（缺 Node 依赖诊断）", /target_not_ready|missing_dependency|缺少 Node 依赖/.test(String(b1.reason ?? "")), `reason=${String(b1.reason ?? "").slice(0, 80)}`);
    check(
      "r1 只读自查为决策提供了构建脚本内容（回灌进下一轮观察）",
      (b1.actions ?? []).some((a) => a.action === "read" && a.subject === "scripts/build.js" && a.ok) &&
        state.prompts.some((p) => String(p).includes("orders.seed.json")),
      `read=${JSON.stringify((b1.actions ?? []).filter((a) => a.action === "read").map((a) => [a.subject, a.ok]))}`
    );
    check(
      "r1 编号 2 解析到引擎自己拼的 npm run build（不是 install，也不是模型给的命令）",
      (b1.actions ?? []).some((a) => a.action === "exec" && a.subject === "npm run build" && a.ok === true && a.exitCode === 0) &&
        !(b1.actions ?? []).some((a) => a.subject === "npm install"),
      `exec=${JSON.stringify((b1.actions ?? []).filter((a) => a.action === "exec").map((a) => [a.subject, a.ok, a.exitCode]))}`
    );
    check(
      "r1 模型自带的 cmd/args/shell 被丢弃并留痕（动作名+原因，无原文）",
      (b1.actions ?? []).some((a) => a.action === "sanitize" && /cmd/.test(String(a.subject)) && String(a.note ?? "").includes("丢弃")) &&
        !JSON.stringify(s1.view).includes(LEAK) &&
        !acts1.some((a) => String(a.subject ?? "").includes(LEAK) || String(a.note ?? "").includes(LEAK)),
      `sanitize=${JSON.stringify((b1.actions ?? []).filter((a) => a.action === "sanitize").map((a) => [a.subject, a.note]))}`
    );
    check("r1 构建产物真实落盘（build/config.js 由代理执行生成）", existsSync(path.join(ws1, BUILD_REL)), BUILD_REL);
    check(
      "r1 后就绪契约是代理验证过的那条（startSource=bootstrap-agent）",
      b1.start?.cmd === "node" &&
        (b1.start?.args ?? []).includes("server.js") &&
        rep1?.summary?.startSource === "bootstrap-agent",
      `start=${JSON.stringify(b1.start)} startSource=${rep1?.summary?.startSource}`
    );
    check(
      "r1 事件流解释代理接管（不是一次启动失败就放弃）",
      s1.log.includes("启动代理执行「npm run build」") && s1.log.includes("启动代理接管后就绪"),
      ""
    );
    const preVuln1 = countVulnerablePre(sid1);
    check("r1 接入层自救后，越权证据照旧复现（≥ 2 条 vulnerable）", preVuln1 >= 2, `pre vulnerable=${preVuln1}`);
    check(
      "r1 会话终态与接入层解耦：漏洞复现成立，改码仍按契约（不自动补丁 → 无可修补候选）",
      (s1.view.state === "error" && s1.view.error?.code === "no_patchable_candidates") ||
        s1.view.state === "patch_review",
      `state=${s1.view.state} code=${s1.view.error?.code ?? "-"}`
    );
    check(
      "r1 报告写入启动代理字段（结局/步数/动作序列/预算）",
      rep1?.bootstrap?.outcome === "started" &&
        Number(rep1.bootstrap.stepsUsed) >= 3 &&
        (rep1.bootstrap.actions ?? []).some((a) => a.action === "exec" && a.subject === "npm run build") &&
        Number(rep1.bootstrap.remainingMs) >= 0 &&
        !!rep1.bootstrap.budget?.totalBudgetMs,
      `bootstrap=${JSON.stringify({ outcome: rep1?.bootstrap?.outcome, steps: rep1?.bootstrap?.stepsUsed, actions: (rep1?.bootstrap?.actions ?? []).length, budget: rep1?.bootstrap?.budget })}`
    );
    check(
      "报告 Markdown 呈现「有界启动代理」章节与动作表",
      md1.includes("有界启动代理") && md1.includes("npm run build") && md1.includes("bootstrap-agent") && md1.includes("非模型自评"),
      ""
    );
    check(
      "r1 作用域令牌经代理出站使用（回环 LLM 走 net.probe）",
      (s1.view.tokens ?? []).some((t) => (t.kinds ?? t.scopes ?? []).includes("net.probe")),
      `tokens=${JSON.stringify((s1.view.tokens ?? []).map((t) => t.kinds ?? t.scopes))}`
    );
    check("r1 预算未被模型拖爆（剩余为正、用时可查）", Number(b1.remainingMs) > 0 && Number(b1.durationMs) > 0, `remaining=${b1.remainingMs}ms duration=${b1.durationMs}ms`);

    // ============ r2：连续报非法编号 + 塞命令行 → 全拒 → giveup，引擎不照做 ============
    console.log("\n[BOOT] 2/4 交互模式：模型抗命（菜单外编号 + 自带命令行）→ 逐条被拒 → 诚实失败…");
    state.script = [
      { action: "exec", id: 99, cmd: "node", args: ["-e", LEAK], note: "mock: 想直接跑自己的命令" },
      { action: "exec", id: 42, shell: `npm publish --access public ${LEAK}`, note: "mock: 再试一次" },
      { action: "giveup", note: "mock: 菜单内没有可行的接入动作，收手等人" },
    ];
    s2 = await openSession("r2", llmEnv, ["--report", path.join(demoDir, "reports", "r2")]);
    s2.send({ cmd: "start", project: ws2 });
    await s2.wait((v) => v.sessionId, "会话建立", 60_000);
    const sid2 = s2.view.sessionId;
    await s2.wait(
      (v) => v.sessionId === sid2 && ["error", "patch_review", "writeback_pending", "completed"].includes(v.state),
      "抗命代理的终态",
      240_000
    );
    callsAfterR2 = state.calls;
    const b2 = s2.view.bootstrap ?? {};
    const acts2 = agentActions(sid2);
    const rep2 = readReport("r2");

    check(
      "r2 代理主动收手：outcome=gave_up，两步非法选择全部被拒",
      b2.outcome === "gave_up" && Number(b2.rejected) === 2 && String(b2.note ?? "").includes("收手"),
      `outcome=${b2.outcome} rejected=${b2.rejected} steps=${b2.stepsUsed} note=${String(b2.note ?? "").slice(0, 40)}`
    );
    check(
      "r2 被拒原因写的是「编号不在菜单内」，不是模型原文",
      acts2.filter((a) => a.action === "rejected").every((a) => /不在菜单内/.test(String(a.note ?? ""))) &&
        acts2.filter((a) => a.action === "rejected").length === 2,
      `rejected=${JSON.stringify(acts2.filter((a) => a.action === "rejected").map((a) => [a.subject, a.note]))}`
    );
    check("r2 引擎没有执行任何命令（审计里无 exec/start，构建产物不存在）", !acts2.some((a) => a.action === "exec" || a.action === "start") && !existsSync(path.join(ws2, BUILD_REL)), `序列=${actionSeq(acts2)}`);
    check(
      "r2 会话诚实失败为启动未就绪（不因模型「觉得起好了」放行）",
      s2.view.state === "error" && s2.view.error?.code === "target_not_ready",
      `state=${s2.view.state} code=${s2.view.error?.code}`
    );
    check("r2 报告记录被拒计数与收手原因", rep2?.bootstrap?.outcome === "gave_up" && Number(rep2?.bootstrap?.rejected) === 2, `bootstrap=${JSON.stringify({ outcome: rep2?.bootstrap?.outcome, rejected: rep2?.bootstrap?.rejected })}`);
    check("r2 事件流没有「已就绪」假象", !s2.log.includes("启动代理接管后就绪"), "");

    // ============ r3：gate + 环境变量与契约都要求启用 → 结构性禁用 ============
    console.log("\n[BOOT] 3/4 gate 模式：即使契约 bootstrap.enabled=true + GUARDBUILD_LLM_BOOTSTRAP=1 也不启用代理…");
    r3 = await runGate(gateWs, "r3", {
      ...llmEnv,
      GUARDBUILD_LLM_BOOTSTRAP: "1",
    });
    const g3 = r3.gate ?? {};
    const view3 = lastView(r3.stdout) ?? {};
    const rep3 = readReport("r3");

    check(
      "r3 gate 失败但不越界：exit 2 / verdict=failed / error=target_not_ready",
      r3.code === 2 && g3.verdict === "failed" && g3.error?.code === "target_not_ready",
      `code=${r3.code} verdict=${g3.verdict} error=${g3.error?.code}`
    );
    check("r3 视图中没有启动代理活动（bootstrap=null）", view3.bootstrap == null, `bootstrap=${JSON.stringify(view3.bootstrap)}`);
    check(
      "r3 全程不出现代理动作（事件流无「启动代理」）",
      !r3.stdout.includes("启动代理") && !r3.stdout.includes("bootstrap-agent"),
      ""
    );
    check("r3 报告 bootstrap 字段为 null", rep3 && rep3.bootstrap === null, `bootstrap=${JSON.stringify(rep3?.bootstrap)}`);
    check("r3 未调用 LLM（代理被禁用后模型一次都没被问）", state.calls === callsAfterR2, `calls=${state.calls}（r2 后=${callsAfterR2}）`);
    check("r3 被测工作区零改动（无构建产物、git 状态干净）", !existsSync(path.join(gateWs, BUILD_REL)) && git(["status", "--porcelain"], gateWs).trim() === "", `porcelain=${git(["status", "--porcelain"], gateWs).trim().slice(0, 80)}`);

    // ============ 4/4 跨轮安全边界 ============
    console.log("\n[BOOT] 4/4 校验安全边界…");
    check("LLM 调用次数只在交互两轮里发生（r1 3 步 + r2 3 步）", callsAfterR1 === 3 && callsAfterR2 === 6, `r1=${callsAfterR1} r1+r2=${callsAfterR2}`);
    check("每次请求带 Bearer 鉴权（密钥经 Host 传递）", state.authHeaders.length === 6 && state.authHeaders.every((h) => h === `Bearer ${MOCK_KEY}`), `headers=${state.authHeaders.length}`);
    check("请求为 JSON 模式（response_format=json_object, stream=false）", state.responseFormat === "json_object" && state.stream === false, `response_format=${state.responseFormat} stream=${state.stream}`);
    const promptBlob = state.prompts.join("\n");
    check(
      "发给模型的观察只给编号与形状（菜单含 npm run build / node server.js）",
      promptBlob.includes("npm run build") && promptBlob.includes("node server.js") && !promptBlob.includes("npm ci"),
      "package.json 无锁文件 → 提供 npm install 而非 npm ci"
    );
    check("发给模型的观察不含身份与密码", !promptBlob.includes("alice123") && !promptBlob.includes("identities"), "");
    check("发给模型的观察不含契约内容（哨兵未发送）", !promptBlob.includes(SENTINEL));
    check("模型哨兵不进入任何留痕（视图/事件/审计/报告）", ![s1.log, s2.log, JSON.stringify([s1.view, s2.view]), JSON.stringify(acts1), JSON.stringify(acts2), JSON.stringify(rep1), JSON.stringify(rep2), md1, readMarkdown("r2")].some((blob) => blob.includes(LEAK)), "");
    const sysPrompt = state.systems[0] ?? "";
    const db = openAuditDb(path.join(dataDir, "guardbuild.db"), { label: "跨轮安全边界" });
    let leakRows = 0;
    let keyRows = 0;
    let auditRows = 0;
    try {
      leakRows = db
        .prepare("SELECT COUNT(*) n FROM events WHERE data_json LIKE ? OR message LIKE ?")
        .get(`%${LEAK}%`, `%${LEAK}%`).n;
      keyRows = db
        .prepare("SELECT COUNT(*) n FROM events WHERE data_json LIKE ? OR message LIKE ?")
        .get(`%${MOCK_KEY}%`, `%${MOCK_KEY}%`).n;
      auditRows = db.prepare("SELECT COUNT(*) n FROM agent_actions").get().n;
    } finally {
      db.close();
    }
    check("事件库不含模型哨兵与密钥", leakRows === 0 && keyRows === 0, `leak=${leakRows} key=${keyRows}`);
    check("动作审计按步落库（两轮共 ≥ 7 行）", auditRows >= 7, `agent_actions=${auditRows}`);
    check(
      "代理系统提示词把边界写死（只报编号 / 不碰源码 / 无法继续就 giveup）",
      sysPrompt.includes("只能从给定菜单") && sysPrompt.includes("giveup") && sysPrompt.includes("不要自己写命令行"),
      ""
    );
    check(
      "每行审计都带剩余预算（可事后复盘预算消耗）",
      [...acts1, ...acts2].every((a) => Number.isInteger(a.budget_remaining_ms)),
      `样例=${JSON.stringify((acts1[0] ?? {}).budget_remaining_ms)}`
    );
  } finally {
    if (s1) await s1.close();
    if (s2) await s2.close();
    await new Promise((r) => server.close(r));
  }

  const failed = checks.filter((c) => !c.pass);
  console.log(`\n[BOOT] 结果：${checks.length - failed.length}/${checks.length} 通过`);
  if (failed.length) {
    for (const f of failed) console.log(`  ✗ ${f.name}`);
    console.log(`演示目录保留供排查: ${demoDir}`);
    process.exit(1);
  }
  rmSync(demoDir, { recursive: true, force: true });
  console.log("[BOOT] 全部通过，已清理演示目录");
}

main().catch((e) => {
  console.error(`[BOOT] 演练失败：${e?.message ?? e}`);
  console.error(`演示目录保留供排查: ${demoDir}`);
  process.exit(1);
});
