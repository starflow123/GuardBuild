#!/usr/bin/env node
/**
 * S2-full（跨文件 / 新建文件补丁）端到端演练：用本机回环 mock DeepSeek 驱动 guardbuild-headless，
 * 验证「模型只产出跨文件补丁意图 → Sidecar 按依赖闭包写集校验 → Host 在隔离 worktree 落盘（含新建文件）
 * → intent-to-add 进补丁 → 自动双重验收 → 授权写回 → 回滚连新建文件一起撤销」整条链路。
 *
 *   靶场 fixtures/crossfile-shop：越权端点在 src/routes/orders.js，处理器形态（normalizeId + 内存 store）
 *   刻意规避确定性归属校验模板；而「正确修法」需要新建 src/routes/ownership.js 并把它挂在 src/app.js 的
 *   分发处 —— 候选文件本身一行都不用改。单文件补丁（S2-lite）在这里结构上做不到，只有开启跨文件写权限才走得通。
 *
 *   r1 会先只读自查、再跨文件下补丁的模型：读挂载点 src/app.js 与目录 src/routes，据回灌内容产出
 *      「新建守卫 + 挂载点两处补丁」→ 自动双重验收通过 → 授权写回（新文件真的进工作区）→ 回滚（新文件被删、
 *      app.js 逐字节复原）。归因走 other_file：候选文件没动，但点名的两个入口都自己完成了「打穿 → 阻断」。
 *   r2 「只写不挂」的模型：只新建守卫文件、不挂到分发处 → 攻击照旧打穿 → 双重验收拦下（verify_failed），
 *      补丁不会交给人工放行：总体计数好看也不算了数，点名的入口必须自己翻转。
 *   r3 gate 模式 + GUARDBUILD_LLM_CROSSFILE=1：跨文件/新建写权限被结构性禁用（CI 里不放开改码能力），
 *      同类补丁意图在校验层被逐条拒绝（未开启跨文件 / 越出本次候选文件），不落任何新文件，被测工作区零改动。
 *
 * 同时校验安全边界：
 *   - 出站走 Host http.request（回环用 net.probe 作用域令牌），密钥只从环境变量读取，不进任何产物；
 *   - 发给模型的证据只含候选文件源码与已复现证据，不含 identities / 密码 / 契约内容；
 *   - 跨文件写入只发生在依赖闭包写集内：写集外的路径既不读盘也不落盘，新建文件目录必须是已扫描源码目录；
 *   - 新建文件用单独的 allow_create 作用域令牌，普通 worktree 令牌写不进新文件；
 *   - gate 全程不改动被测工作区，结束后隔离 worktree 已清理。
 *
 * 用法: node scripts/e2e-cross-file.mjs
 */
import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import path from "node:path";
import readline from "node:readline";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const demoDir = path.join(repoRoot, ".demo-cross-file");
const dataDir = path.join(demoDir, "data");
const fixture = path.join(repoRoot, "fixtures", "crossfile-shop");

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

// —— 靶场事实 ——
const CAND_REL = "src/routes/orders.js";
const APP_REL = "src/app.js";
const GUARD_REL = "src/routes/ownership.js";
const CAND_KEYS = ["GET /api/orders/:id", "POST /api/orders/:id/cancel"];
const FIXTURE_APP_SRC = readFileSync(path.join(fixture, "src", "app.js"), "utf8");

/** 期望新建的归属守卫模块（模型的「跨文件 + 新文件」产物；挂载点在 app.js） */
const GUARD_SRC = String.raw`import { findOrderById } from "../data.js";
import { normalizeId } from "../http.js";
import { recordDecision } from "../diag.js";

// 订单归属守卫：详情与取消都必须先比对「资源所有者 == 请求者」。
// 挂在分发处而不是处理器内部，这样新增的订单入口默认也受保护。
export function requireOrderOwner(pathname, auth) {
  if (!auth) return null; // 未登录交给处理器返回 401
  const cancel = pathname.match(/^\/api\/orders\/(\d+)\/cancel$/);
  const detail = cancel ? null : pathname.match(/^\/api\/orders\/(\d+)$/);
  const rawId = cancel ? cancel[1] : detail ? detail[1] : null;
  if (rawId === null) return null;
  const order = findOrderById(normalizeId(rawId));
  if (!order || order.userId === auth.user.id) return null;
  recordDecision({
    method: cancel ? "POST" : "GET",
    path: pathname,
    routeKey: cancel ? "orders.cancel" : "orders.get",
    requesterId: auth.user.id,
    requesterRole: auth.user.role,
    resourceOwner: order.userId,
    checks: ["authenticated", "owner-match"],
    decision: "deny",
    note: "归属守卫在挂载处拒绝：请求者不是订单所有者",
  });
  return { status: 403, body: { error: "无权访问该订单" } };
}
`;

/** 在「模型看到的」app.js 文本里定位 import 行与挂载块，产出跨文件补丁意图（锚点逐字取自原文） */
function appPatchOps(appSrc) {
  const lines = String(appSrc).replace(/\r\n/g, "\n").split("\n");
  const importIdx = lines.findIndex((l) => l.startsWith('import { handleOrders } from "./routes/orders.js";'));
  const mountIdx = lines.findIndex((l) => l.includes('if (pathname.startsWith("/api/orders"))'));
  if (importIdx < 0 || mountIdx < 0) return null;
  const block = lines.slice(mountIdx, mountIdx + 3);
  if (block.length < 3 || !block[1].includes("return handleOrders(req, res") || block[2].trim() !== "}") return null;
  return {
    importSearch: lines[importIdx],
    importReplace: `${lines[importIdx]}\nimport { requireOrderOwner } from "./routes/ownership.js";`,
    mountSearch: block.join("\n"),
    mountReplace: [
      block[0],
      "    const violation = requireOrderOwner(pathname, auth);",
      "    if (violation) return json(res, violation.status, violation.body);",
      block[1],
      block[2],
    ].join("\n"),
  };
}

function guardPatch() {
  return {
    file: GUARD_REL,
    create: true,
    content: GUARD_SRC,
    candidate: CAND_KEYS[0],
    reason: "抽出可复用的订单归属守卫（新建模块）",
  };
}

function crossFilePatches(appSrc) {
  const ops = appPatchOps(appSrc);
  if (!ops) return [];
  return [
    {
      file: APP_REL,
      search: ops.importSearch,
      replace: ops.importReplace,
      candidate: CAND_KEYS[0],
      reason: "引入归属守卫模块，供分发处调用",
    },
    {
      file: APP_REL,
      search: ops.mountSearch,
      replace: ops.mountReplace,
      candidate: CAND_KEYS[1],
      reason: "在订单模块分发处先做归属校验，详情与取消两个入口一起收口，保持合法用户 2xx 契约",
    },
    guardPatch(),
  ];
}

/** mock DeepSeek chat completions：按模式返回只读自查请求或跨文件补丁意图，并记录请求特征 */
function startMockLlm() {
  return new Promise((resolve) => {
    const state = {
      mode: "agent",
      calls: 0,
      authHeaders: [],
      systems: [],
      prompts: [],
      returned: [],
      model: null,
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
          /* 交给下面的空体响应 */
        }
        state.model = body?.model ?? null;
        state.responseFormat = body?.response_format?.type ?? null;
        state.stream = body?.stream ?? null;
        state.systems.push(body?.messages?.find((m) => m.role === "system")?.content ?? "");
        const userPrompt = body?.messages?.find((m) => m.role === "user")?.content ?? "";
        state.prompts.push(userPrompt);

        let promptObj = null;
        try {
          promptObj = JSON.parse(userPrompt);
        } catch {
          /* 非法提示词：下面按无法修复响应 */
        }

        const respond = (payload) => {
          res.statusCode = 200;
          res.setHeader("Content-Type", "application/json");
          res.end(
            JSON.stringify({
              id: `mock-xf-${state.calls}`,
              object: "chat.completion",
              model: state.model ?? "deepseek-chat",
              choices: [
                {
                  index: 0,
                  message: { role: "assistant", content: JSON.stringify(payload) },
                  finish_reason: "stop",
                },
              ],
              usage: {
                prompt_tokens: Math.ceil(userPrompt.length / 4),
                completion_tokens: 220,
                total_tokens: Math.ceil(userPrompt.length / 4) + 220,
              },
            })
          );
        };

        // 模型「读到的挂载点内容」：只从 Sidecar 回灌的只读自查结果里取
        const appFromHistory = () => {
          for (const round of promptObj?.tool_history ?? []) {
            for (const r of round?.results ?? []) {
              if (r?.tool === "read" && /(^|\/)app\.js$/.test(String(r.path ?? "")) && typeof r.result === "string") {
                return r.result;
              }
            }
          }
          return null;
        };

        if (state.mode === "agent") {
          if (!Array.isArray(promptObj?.tool_history)) {
            state.returned.push("tool");
            respond({
              requests: [
                { tool: "read", path: APP_REL },
                { tool: "list", path: "src/routes" },
              ],
              note: "mock: 先看挂载点与守卫可放置的目录",
            });
            return;
          }
          const seen = appFromHistory();
          const patches = crossFilePatches(seen ?? FIXTURE_APP_SRC);
          state.returned.push(`patches:${patches.length}${seen ? ":from_history" : ":fallback"}`);
          respond({
            patches,
            note: patches.length ? "mock: 新建守卫并挂到分发处" : "mock: 挂载点锚点失配",
          });
          return;
        }
        if (state.mode === "create_only") {
          state.returned.push("create_only");
          respond({ patches: [guardPatch()], note: "mock: 只写守卫不挂载（只写不挂等于没修）" });
          return;
        }
        if (state.mode === "sneaky") {
          state.returned.push("sneaky");
          respond({ patches: crossFilePatches(FIXTURE_APP_SRC), note: "mock: 在 gate 里照搬跨文件补丁" });
          return;
        }
        state.returned.push("none");
        respond({ patches: [], note: "mock: 无" });
      });
    });
    server.listen(0, "127.0.0.1", () => resolve({ server, port: server.address().port, state }));
  });
}

/** 交互（非 gate）会话：跨文件写权限只在交互模式启用，需要 stdin 命令驱动写回与回滚 */
function openSession(label, env = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(exe, [], {
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
    const s = { label, child, view: null, states: [], events: [], log: "", errText: "", waiters: [], exitCode: null };
    readline
      .createInterface({ input: child.stdout })
      .on("line", (line) => {
        s.log += `${line}\n`;
        if (line.startsWith("GB_STATE ")) {
          try {
            const v = JSON.parse(line.slice("GB_STATE ".length));
            s.view = v;
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

function runGate(project, label, env, timeoutMs = 420_000) {
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
    child.stdout.on("data", (b) => {
      stdout += b.toString();
    });
    child.stderr.on("data", (b) => {
      stderr += b.toString();
    });
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`[cross-file:${label}] 超时 ${timeoutMs}ms`));
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
      const states = stdout
        .split("\n")
        .filter((l) => l.startsWith("GB_STATE "))
        .map((l) => {
          try {
            return JSON.parse(l.slice("GB_STATE ".length)).state ?? null;
          } catch {
            return null;
          }
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

function readReport(round) {
  const p = path.join(demoDir, "reports", round, "report.json");
  if (!existsSync(p)) return null;
  try {
    return JSON.parse(readFileSync(p, "utf8"));
  } catch {
    return null;
  }
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
  console.log("[XF] 0/3 准备演示目录…");
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

  const ws1 = makeWorkspace("xf-agent");
  const ws2 = makeWorkspace("xf-unmounted");
  const ws3 = makeWorkspace("xf-gate");
  const app1 = path.join(ws1, "src", "app.js");
  const guard1 = path.join(ws1, "src", "routes", "ownership.js");
  const baselineApp = readFileSync(app1, "utf8");
  if (!existsSync(path.join(ws3, "src", "app.js"))) throw new Error("工作区准备失败：缺 src/app.js");

  let s1;
  let s2;
  let r3;
  let callsR1 = 0;
  let callsR2 = 0;
  let callsR3 = 0;
  try {
    // ============ r1：跨文件 + 新建文件 → 自动验收 → 写回 → 回滚 ============
    console.log("\n[XF] 1/3 交互模式：模型只读自查后产出「新建守卫 + 挂载点补丁」…");
    state.mode = "agent";
    s1 = await openSession("r1", llmEnv);
    s1.send({ cmd: "start", project: ws1 });
    await s1.wait((v) => v.sessionId, "会话建立", 60_000);
    const sid1 = s1.view.sessionId;
    await s1.wait(
      (v) => v.sessionId === sid1 && ["writeback_pending", "verify_failed", "patch_review", "error"].includes(v.state),
      "跨文件补丁裁决",
      330_000
    );
    callsR1 = state.calls;

    const v1 = s1.view;
    const p1 = v1.patch ?? {};
    const llm1 = p1.llm ?? {};
    check("r1 自动双重验收通过并停在 writeback_pending", v1.state === "writeback_pending", `state=${v1.state} 序列=${s1.states.join("→")}`);
    check("r1 视图标记本次启用了跨文件写集", llm1.crossFile === true, `crossFile=${JSON.stringify(llm1.crossFile)}`);
    check(
      "r1 新建文件走 allow_create 令牌并进入补丁清单",
      (llm1.createdFiles ?? []).includes(GUARD_REL),
      `createdFiles=${JSON.stringify(llm1.createdFiles)}`
    );
    check(
      "r1 候选文件外的已有文件被点名（app.js·reverse）",
      (llm1.crossFileFiles ?? []).some((f) => f.from === CAND_REL && f.to === APP_REL && f.role === "reverse" && f.ops === 2),
      `crossFileFiles=${JSON.stringify(llm1.crossFileFiles)}`
    );
    check("r1 只读自查为跨文件锚点提供了上下文", Number(llm1.toolRounds ?? 0) >= 1 && (llm1.toolCalls ?? []).some((t) => t.tool === "read" && t.path === APP_REL && t.ok), `toolRounds=${llm1.toolRounds} toolCalls=${JSON.stringify((llm1.toolCalls ?? []).map((t) => `${t.tool} ${t.path}${t.ok ? "" : "（被拒）"}`))}`);
    check(
      "候选文件本身未被改动，但归因仍保留（crossFileOnly）",
      (p1.fixes ?? []).some((f) => f.file === CAND_REL && f.crossFileOnly === true && (f.fixes ?? []).length >= 2),
      JSON.stringify((p1.fixes ?? []).map((f) => `${f.file}:${f.crossFileOnly ? "crossFileOnly" : "wrote"}:${(f.fixes ?? []).length}`))
    );
    check(
      "新建文件在补丁里有独立条目（role=new）",
      (p1.fixes ?? []).some((f) => f.file === GUARD_REL && f.role === "new" && f.created === true),
      JSON.stringify((p1.fixes ?? []).map((f) => `${f.file}/${f.role ?? "candidate"}/${f.created === true}`))
    );
    check(
      "补丁 diff 含新文件（intent-to-add 生效）与挂载点改动",
      /new file mode/.test(String(p1.diff ?? "")) &&
        String(p1.diff ?? "").includes(GUARD_REL) &&
        String(p1.diff ?? "").includes("requireOrderOwner"),
      `files=${JSON.stringify((p1.files ?? []).map((f) => f.path))}`
    );
    check(
      "补丁策略仍标注 llm-coding-agent 且走自动验收",
      String(p1.strategy ?? "").includes("llm-coding-agent") && p1.autoVerify === true,
      `strategy=${p1.strategy} autoVerify=${p1.autoVerify}`
    );
    check(
      "r1 点名两个越权入口（跨文件修复照样算作该候选被修复）",
      (p1.claimed ?? []).length === 2 && CAND_KEYS.every((k) => (p1.claimed ?? []).includes(k)),
      `claimed=${JSON.stringify(p1.claimed)}`
    );
    const sc1 = p1.scope ?? {};
    check(
      "r1 风险画像：跨文件已开启，候选 / 依赖闭包 / 新建分三类列清",
      sc1.crossFile === true &&
        (sc1.candidateFiles ?? []).includes(CAND_REL) &&
        (sc1.closureFiles ?? []).includes(APP_REL) &&
        (sc1.newFiles ?? []).includes(GUARD_REL),
      `scope=${JSON.stringify({ crossFile: sc1.crossFile, candidateFiles: sc1.candidateFiles, closureFiles: sc1.closureFiles, newFiles: sc1.newFiles })}`
    );
    check(
      "r1 画像显式标出「漏洞文件本身未改动」（修法在挂载点，不是没修到点上）",
      (sc1.files ?? []).some((f) => f.file === CAND_REL && f.untouched === true),
      JSON.stringify((sc1.files ?? []).map((f) => `${f.file}/${f.role}/untouched=${f.untouched}`))
    );
    check(
      "r1 画像带逐文件行数与依赖入度（审查者能判断影响面）",
      (sc1.files ?? []).some((f) => f.file === APP_REL && (f.insertions ?? 0) > 0) &&
        (sc1.files ?? []).some((f) => f.file === GUARD_REL && f.created === true && typeof f.inDegree === "number"),
      JSON.stringify(sc1.files)
    );
    check(
      "r1 画像的被拒计数与会话留痕一致",
      Number(sc1.rejectedCount ?? -1) === (llm1.rejected ?? []).length,
      `scope=${sc1.rejectedCount} llm=${(llm1.rejected ?? []).length}`
    );
    const acc1 = v1.acceptance ?? {};
    check(
      "r1 双重验收通过：攻击全部阻断 + 业务零回归",
      acc1.pass === true && acc1.attackBlocked === acc1.attackTotal && acc1.attackTotal >= 2 && acc1.businessPassed === acc1.businessTotal && acc1.businessTotal >= 1,
      `attack=${acc1.attackBlocked}/${acc1.attackTotal} business=${acc1.businessPassed}/${acc1.businessTotal}`
    );
    const attr1 = acc1.attribution ?? {};
    check(
      "r1 归因：修法落在别的文件也照样判定翻转（点名的 2 个入口自行打穿→阻断）",
      attr1.pass === true && attr1.claimedCount === 2 && attr1.blockedCount === 2 && attr1.unverifiedCount === 0 && attr1.stillVulnerableCount === 0,
      `claimed=${attr1.claimedCount} blocked=${attr1.blockedCount} unverified=${attr1.unverifiedCount} still=${attr1.stillVulnerableCount}`
    );
    const claimedRows1 = (attr1.rows ?? []).filter((r) => r.claimed);
    check(
      "r1 归因把这 2 个入口标为 other_file（候选文件没动，靠同目录新守卫 + 挂载点）",
      claimedRows1.length === 2 && claimedRows1.every((r) => r.locality === "other_file"),
      JSON.stringify(claimedRows1.map((r) => `${r.candidate}:${r.locality}`))
    );
    check("r1 写回前原工作区一个字节都没动", !existsSync(guard1) && readFileSync(app1, "utf8") === baselineApp, `guardExists=${existsSync(guard1)}`);
    check("r1 模型调用 = 1 次只读自查 + 1 次补丁意图", callsR1 === 2, `calls=${callsR1}`);
    check("r1 出站经 Host 且带 Bearer 鉴权", state.authHeaders[0] === `Bearer ${MOCK_KEY}`, state.authHeaders[0] ? "Authorization: Bearer ***" : "无鉴权头");
    check(
      "r1 开启跨文件时系统提示替换了「只改一个文件」条款",
      String(state.systems[0] ?? "").includes("本次运行已开启跨文件补丁") && String(state.systems[0] ?? "").includes("只写不挂等于没修"),
      ""
    );
    const prompt1b = state.prompts[1] ?? "";
    check(
      "r1 提示词给出依赖闭包写集与可新建目录",
      prompt1b.includes("writable_files") && prompt1b.includes(`"role": "reverse"`) && prompt1b.includes("writable_dirs") && prompt1b.includes("src/routes"),
      `${prompt1b.length} 字符`
    );
    check(
      "r1 只读自查回灌的内容含挂载点原文（锚点据此产出）",
      String(state.returned[1] ?? "").endsWith(":from_history") &&
        prompt1b.includes("tool_history") &&
        prompt1b.includes("return handleOrders(req, res"),
      `returned=${JSON.stringify(state.returned)}`
    );
    check(
      "提示词不含身份密码 / identities / 密钥",
      ![state.prompts[0] ?? "", prompt1b].some((p) => p.includes("alice123") || p.includes("bob123") || p.includes("identities") || p.includes(MOCK_KEY)),
      ""
    );

    console.log("\n[XF] 1/3 · 授权写回真实工作区（新建文件应随之落地）…");
    s1.send({ cmd: "writeback_approve" });
    await s1.wait((v) => v.sessionId === sid1 && ["applied", "error", "verify_failed"].includes(v.state), "写回完成", 240_000);
    check("r1 写回后进入 applied", s1.view.state === "applied", `state=${s1.view.state}`);
    await s1.wait((v) => v.acceptance?.writebackRecheck?.pass !== undefined, "写回后复核", 300_000);
    const re1 = s1.view.acceptance.writebackRecheck;
    check("r1 写回后复核同样通过", re1.pass === true, `attack=${re1.attackBlocked}/${re1.attackTotal} business=${re1.businessPassed}/${re1.businessTotal}`);
    const appAfter = readFileSync(app1, "utf8");
    check("r1 真实工作区已挂上归属守卫", appAfter.includes("requireOrderOwner(pathname, auth)") && appAfter.includes('import { requireOrderOwner } from "./routes/ownership.js";'), "");
    check("r1 真实工作区存在新建的守卫文件", existsSync(guard1));
    check("r1 新建守卫内容与模型意图一致（未被掩码/改写）", readFileSync(guard1, "utf8").replace(/\r\n/g, "\n") === GUARD_SRC, `字节=${existsSync(guard1) ? statSync(guard1).size : 0}`);
    check("r1 回滚备份清单含新建文件", JSON.stringify(s1.view.rollback ?? {}).includes("ownership.js"), JSON.stringify(s1.view.rollback ?? {}).slice(0, 220));

    console.log("\n[XF] 1/3 · 回滚（新建文件必须一起被撤销）…");
    s1.send({ cmd: "rollback" });
    await s1.wait((v) => v.sessionId === sid1 && ["rolled_back", "error"].includes(v.state), "回滚完成", 240_000);
    check("r1 回滚后状态为 rolled_back", s1.view.state === "rolled_back", `state=${s1.view.state}`);
    check("r1 回滚删除了新建文件", !existsSync(guard1), `仍存在=${existsSync(guard1)}`);
    check("r1 回滚后 app.js 逐字节复原", readFileSync(app1, "utf8") === baselineApp, "");
    check("r1 回滚后工作区 git 干净", git(["status", "--porcelain"], ws1).trim() === "", git(["status", "--porcelain"], ws1).trim().slice(0, 200));
    await s1.close();

    // ============ r2：只写不挂 → 双重验收拦下 ============
    console.log("\n[XF] 2/3 交互模式：模型只新建守卫、不挂到分发处（只写不挂）…");
    state.mode = "create_only";
    s2 = await openSession("r2", llmEnv);
    s2.send({ cmd: "start", project: ws2 });
    await s2.wait((v) => v.sessionId, "会话建立", 60_000);
    const sid2 = s2.view.sessionId;
    await s2.wait(
      (v) => v.sessionId === sid2 && ["writeback_pending", "verify_failed", "patch_review", "error"].includes(v.state),
      "只写不挂的验收裁决",
      330_000
    );
    callsR2 = state.calls;
    const v2 = s2.view;
    const p2 = v2.patch ?? {};
    const acc2 = v2.acceptance ?? {};
    check("r2 终态 = 验收未通过（verify_failed）", v2.state === "verify_failed", `state=${v2.state} 序列=${s2.states.join("→")}`);
    check("r2 补丁确实新建了守卫文件并进 diff", (p2.llm?.createdFiles ?? []).includes(GUARD_REL) && String(p2.diff ?? "").includes(GUARD_REL), `createdFiles=${JSON.stringify(p2.llm?.createdFiles)}`);
    check("r2 未交人工放行：全程没有 writeback_pending / patch_review", !s2.states.includes("writeback_pending") && !s2.states.includes("patch_review"), s2.states.join("→"));
    check(
      "r2 修复后攻击仍未被阻断（守卫没挂上就是没修）",
      (v2.evidence ?? []).filter((e) => e.phase === "post" && e.category === "attack" && e.verdict === "regressed").length >= 1 &&
        Number(acc2.attackBlocked ?? 0) < Number(acc2.attackTotal ?? 0),
      `post regressed=${(v2.evidence ?? []).filter((e) => e.phase === "post" && e.verdict === "regressed").length} attack=${acc2.attackBlocked}/${acc2.attackTotal} business=${acc2.businessPassed}/${acc2.businessTotal}`
    );
    const attr2 = v2.acceptance?.attribution ?? {};
    check(
      "r2 归因点名入口仍未翻转，验收不因汇总计数好看而放行",
      attr2.pass === false && (attr2.stillVulnerableCount ?? 0) >= 1,
      `pass=${attr2.pass} claimed=${attr2.claimedCount} stillVulnerable=${attr2.stillVulnerableCount}`
    );
    const sc2 = p2.scope ?? {};
    check(
      "r2 画像直接暴露「只写不挂」：新建了守卫文件，但依赖闭包内没有任何挂载改动",
      (sc2.newFiles ?? []).includes(GUARD_REL) &&
        (sc2.closureFiles ?? []).length === 0 &&
        (sc2.files ?? []).some((f) => f.file === CAND_REL && f.untouched === true),
      `scope=${JSON.stringify({ newFiles: sc2.newFiles, closureFiles: sc2.closureFiles, files: (sc2.files ?? []).map((f) => `${f.file}/${f.role}/untouched=${f.untouched}`) })}`
    );
    check("r2 只发生 1 次模型调用（gate 外的交互模式按契约 fixRounds=0 收尾）", callsR2 - callsR1 === 1, `calls=${callsR2 - callsR1}`);
    check("r2 被测工作区未被修改（补丁只在隔离 worktree）", git(["status", "--porcelain"], ws2).trim() === "" && !existsSync(path.join(ws2, "src", "routes", "ownership.js")), git(["status", "--porcelain"], ws2).trim().slice(0, 200));
    await s2.close();

    // ============ r3：gate 模式结构性禁用跨文件写权限 ============
    console.log("\n[XF] 3/3 gate 模式：即使显式开启，跨文件/新建写权限也被结构性关掉…");
    state.mode = "sneaky";
    r3 = await runGate(ws3, "r3", { ...llmEnv, GUARDBUILD_LLM_CROSSFILE: "1" });
    callsR3 = state.calls;
    const g3 = r3.gate ?? {};
    const rep3 = readReport("r3");
    const llm3 = rep3?.error?.details?.llmPatch ?? {};
    const rej3 = llm3.rejected ?? [];
    check("r3 gate 退出码 = 1（漏洞成立、无可用补丁）", r3.code === 1, `code=${r3.code}`);
    check("r3 verdict = vulnerable_unfixed / no_patchable_candidates", String(g3.verdict ?? "").includes("vulnerable_unfixed") || String(g3.error?.code ?? "") === "no_patchable_candidates", `verdict=${g3.verdict} error=${g3.error?.code}`);
    check("r3 视图判定本次没有跨文件写集", llm3.crossFile === false, `crossFile=${JSON.stringify(llm3.crossFile)}`);
    check("r3 未新建任何文件", (llm3.createdFiles ?? []).length === 0, `createdFiles=${JSON.stringify(llm3.createdFiles)}`);
    check("r3 新建意图被拒（未开启跨文件补丁）", rej3.some((r) => String(r.reason).includes("未开启跨文件补丁")), JSON.stringify(rej3.map((r) => r.reason)).slice(0, 240));
    check("r3 跨文件锚点意图被拒（越出本次候选文件）", rej3.some((r) => String(r.reason).includes("越出本次候选文件")), JSON.stringify(rej3.map((r) => r.file)).slice(0, 200));
    check("r3 未申请 allow_create 作用域", !r3.stdout.includes("跨文件补丁：在隔离 worktree"), "");
    check("r3 事件流未出现「含依赖闭包内其它文件」的落盘", !r3.stdout.includes("含依赖闭包内其它文件"), "");
    check("r3 被测工作区零改动", git(["status", "--porcelain"], ws3).trim() === "" && !existsSync(path.join(ws3, "src", "routes", "ownership.js")), git(["status", "--porcelain"], ws3).trim().slice(0, 200));
    check("r3 报告无补丁对象（没有半成品跨文件补丁交给人工）", rep3?.patch == null, `patch=${rep3?.patch ? "有" : "无"}`);
    check("r3 模型调用 = 1 次", callsR3 - callsR2 === 1, `calls=${callsR3 - callsR2}`);
    check("r3 修复前证据仍复现越权（≥ 2）", (rep3?.evidence?.post ?? []).length === 0 && (rep3?.evidence?.pre ?? []).filter((e) => e.verdict === "vulnerable").length >= 2, `pre vulnerable=${(rep3?.evidence?.pre ?? []).filter((e) => e.verdict === "vulnerable").length}`);
  } finally {
    await new Promise((r) => server.close(r));
  }

  // ============ 全局边界：密钥不外泄、临时 worktree 已清理 ============
  const dbPath = path.join(dataDir, "guardbuild.db");
  const dbText = existsSync(dbPath) ? readFileSync(dbPath) : Buffer.alloc(0);
  const allArtifacts = [
    s1?.log ?? "",
    s1?.errText ?? "",
    s2?.log ?? "",
    s2?.errText ?? "",
    r3?.stdout ?? "",
    r3?.stderr ?? "",
    dbText.toString("latin1"),
    ...state.prompts,
    ...state.systems,
  ].join("\n");
  check("密钥真实值不出现在事件流 / stderr / 提示词 / 证据库", !allArtifacts.includes(MOCK_KEY), `key=${MOCK_KEY.slice(0, 8)}…`);
  check(
    "报告里没有把跨文件写入扩大成工作区改动（三份靶场都干净）",
    [ws1, ws2, ws3].every((ws) => git(["status", "--porcelain"], ws).trim() === "") &&
      !existsSync(path.join(ws2, "src", "routes", "ownership.js")) &&
      !existsSync(path.join(ws3, "src", "routes", "ownership.js")),
    ""
  );
  const leftovers = worktreeLeftovers();
  const normPath = (p) => String(p ?? "").replace(/^\\\\\?\\/, "").replace(/[\\/]+$/, "").toLowerCase();
  const wt1 = String(s1?.view?.patch?.worktree ?? "");
  const wt2 = String(s2?.view?.patch?.worktree ?? "");
  check("r1 写回并回滚后，其隔离 worktree 已被清理", wt1 !== "" && !existsSync(wt1), wt1 || "无 worktree 路径");
  check(
    "r2 验收未通过：补丁留在隔离 worktree 供人工回看，新建文件只存在于沙箱内",
    wt2 !== "" && existsSync(path.join(wt2, GUARD_REL)) && !existsSync(path.join(ws2, "src", "routes", "ownership.js")),
    wt2 || "无 worktree 路径"
  );
  check(
    "演练收尾：沙箱里只剩 r2 那份待回看的 worktree（写回过的与 gate 会话都不留临时副本）",
    leftovers.length === 1 && normPath(leftovers[0]) === normPath(wt2),
    `残留=${JSON.stringify(leftovers)}`
  );

  if (existsSync(dbPath)) {
    const db = new DatabaseSync(dbPath, { readOnly: true });
    const one = (sql, ...args) => db.prepare(sql).get(...args);
    const patchRow1 = one("SELECT status, strategy FROM patches WHERE session_id = ?", s1?.view?.sessionId ?? "");
    const patchRow2 = one("SELECT status FROM patches WHERE session_id = ?", s2?.view?.sessionId ?? "");
    const createdCols = one("SELECT COUNT(*) n FROM evidence WHERE session_id = ? AND phase='post_writeback'", s1?.view?.sessionId ?? "");
    db.close();
    check("r1 补丁留痕：写回后回滚（status=rolled_back）", patchRow1?.status === "rolled_back", `status=${patchRow1?.status} strategy=${patchRow1?.strategy}`);
    check("r1 写回后复核证据入库", (createdCols?.n ?? 0) > 0, `post_writeback=${createdCols?.n}`);
    check("r2 未通过验收的补丁留在待审状态（不写回）", ["pending_review", "verify_failed"].includes(String(patchRow2?.status)), `status=${patchRow2?.status}`);
  }

  const passed = checks.filter((c) => c.pass).length;
  console.log(`\n[XF] 断言：${passed}/${checks.length} 通过`);
  const failed = checks.filter((c) => !c.pass);
  if (failed.length) {
    console.error(`[XF] 未通过：${failed.map((c) => c.name).join("、")}`);
    console.error(`[XF] r3 stdout 尾部：\n${String(r3?.stdout ?? "").split("\n").slice(-25).join("\n")}`);
    process.exit(1);
  }
  console.log("[XF] 全部通过 ✅");
  process.exit(0);
}

main().catch((e) => {
  console.error(`\n[XF] 演练失败: ${e?.message ?? e}`);
  console.error(checks.map((c) => `${c.pass ? "✓" : "✗"} ${c.name}`).join("\n"));
  process.exit(1);
});
