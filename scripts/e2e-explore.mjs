#!/usr/bin/env node
/**
 * 探索区（方案第 13 项）端到端演练：本机回环 mock DeepSeek + 白盒靶场 fixtures/selfboot-shop。
 *
 * 这一路要证明的是「模型想怎么打 → 引擎替它真打 → 落成配方草稿，但草稿不是结论」：
 *   r1 默认关闭（带着可用的模型环境）：0 次 LLM 调用、view/report 无 exploration、
 *      判定链结果与 r2 完全一致（探索区不参与判卷）。
 *   r2 双闸开启 + 一轮自主试打 + 同时走私字段：
 *      第 1 轮「以 victim 身份读带主键的订单端点」、第 2 轮「匿名读同一端点」（这两次是真请求），
 *      模型自带的 path/payload/headers/verdict 一律丢弃并只留字段名；
 *      第 3 轮想打 SQL 注入，但本轮计划没声明注入点 → 引擎拒收、一个请求都不发；
 *      第 4 轮自行收手给出族名 → 草稿过动作表校验、registered=false、只落数据目录。
 *   r3 预算：契约写 maxRequests=1（1 次就停）、maxRounds/totalBudgetMs 写到天大 → 引擎夹紧到硬上限；
 *      超限即停并把「用尽的是哪一项」写进事件与报告。
 *   r4 反叛的模型：连续报菜单外编号与错误槽位 → 全部拒收，0 次实发、0 份草稿（不伪造「打过」）。
 *   r5 gate + 契约启用 + 环境变量启用：结构性禁用（0 次 LLM 调用，报告无 exploration）。
 *   r6 纯黑盒外部目标 + 双闸全开：这一路根本不进入（0 次探索调用）。
 *
 * 同时校验安全边界：发给模型的观察不含身份口令与契约内容；密钥与走私哨兵不出现在
 * 视图/事件/报告/DB/草稿文件里；探索流量不进证据库（pre 阶段证据条数与 r1 相同）；
 * sidecar/recipes/ 一个字节都不变（注册仍是人工闸门）。
 *
 * 报告从哪来：白盒交互轮在有漏洞时会停在「补丁待审查」，那一步不落报告。
 * 因此每轮读完视图后发 cancel——侧车在待审查态走中止收尾，报告（含探索区章节）随之落盘。
 * 探索区跑在修复前取证之后，中止不影响它已经写好的 trace、审计与草稿。
 *
 * 用法: node scripts/e2e-explore.mjs
 */
import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";
import readline from "node:readline";
import { fileURLToPath } from "node:url";
import { openAuditDb, queryAudit } from "./lib/auditdb.mjs";
import { EXPLORATION_HARD_CAPS } from "../sidecar/lib/explorer.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const demoDir = path.join(repoRoot, ".demo-explore");
const dataDir = path.join(demoDir, "data");
const reportsDir = path.join(demoDir, "reports");
const fixture = path.join(repoRoot, "fixtures", "selfboot-shop");

function resolveHeadlessBin() {
  if (process.env.GUARDBUILD_HEADLESS_BIN) return process.env.GUARDBUILD_HEADLESS_BIN;
  const name = process.platform === "win32" ? "guardbuild-headless.exe" : "guardbuild-headless";
  const debug = path.join(repoRoot, "src-tauri", "target", "debug", name);
  return existsSync(debug) ? debug : path.join(repoRoot, "src-tauri", "target", "release", name);
}
const exe = resolveHeadlessBin();

const MOCK_KEY = `sk-mock-${randomBytes(16).toString("hex")}`;
// 模型想自己规定「怎么打」时塞进来的内容：绝不允许出现在任何留痕里
const LEAK = "LEAK-SMUGGLED-EXPLORE-7c41";
// 模型原文哨兵：note 不进视图/事件/审计/报告/DB
const NOTE = "MODEL-NOTE-EXPLORATION-2f88";
// 契约哨兵：guardbuild.json 的私有内容不该出现在发给模型的观察里
const SENTINEL = "SENTINEL_EXPLORE_CONTRACT_MUST_NOT_BE_SENT_TO_LLM";

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

/** 复制靶场并按本轮要验的开关写入探索区契约 */
function makeWorkspace(name, exploration) {
  const ws = path.join(demoDir, name);
  rmSync(ws, { recursive: true, force: true });
  mkdirSync(demoDir, { recursive: true });
  cpSync(fixture, ws, { recursive: true });
  const cfgPath = path.join(ws, "guardbuild.json");
  const cfg = JSON.parse(readFileSync(cfgPath, "utf8"));
  cfg._note = SENTINEL;
  if (exploration) cfg.exploration = exploration;
  writeFileSync(cfgPath, `${JSON.stringify(cfg, null, 2)}\n`);
  git(["init", "-q"], ws);
  git(["config", "user.email", "gate@guardbuild.local"], ws);
  git(["config", "user.name", "GuardBuild Gate"], ws);
  git(["config", "core.autocrlf", "false"], ws);
  git(["add", "-A"], ws);
  git(["commit", "-qm", `${name} 基线`], ws);
  return ws;
}

/** 单独起一份靶场给纯黑盒轮次用（探索区对黑盒模式代码级不进入） */
function startTarget() {
  const dir = path.join(demoDir, "target");
  rmSync(dir, { recursive: true, force: true });
  cpSync(fixture, dir, { recursive: true });
  return new Promise((resolve, reject) => {
    const child = spawn("node", ["server.js"], { cwd: dir, env: { ...process.env, PORT: "0" }, stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error("靶场启动超时"));
    }, 20_000);
    const onData = (b) => {
      out += b.toString();
      // 就绪行走 GB_LISTEN 结构化那行：中文提示里的端口和前缀 127 都是数字，正则容易抓错
      const m = out.replace(/\x1b\[[0-9;]*m/g, "").match(/GB_LISTEN\s*(\{[^\n]*\})/);
      if (m) {
        clearTimeout(timer);
        child.stdout.off("data", onData);
        resolve({ child, port: Number(JSON.parse(m[1]).port), dir });
      }
    };
    child.stdout.on("data", onData);
    child.stderr.on("data", (b) => (out += b.toString()));
    child.on("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`靶场提前退出（code=${code}）：${out.slice(-400)}`));
    });
  });
}

/**
 * mock DeepSeek chat completions：按「本轮观察里的菜单」挑编号，而不是写死编号——
 * 断言的是「模型报的编号真的被引擎解析成它自己那条请求」，而不是一份脆弱的固定脚本。
 * mode：explore（照剧本试打并走私字段）/ greedy（一直挑同一动作，永不收手）/ defiant（全挑菜单外）。
 */
function startMockLlm() {
  return new Promise((resolve) => {
    const state = { mode: "explore", base: 0, calls: 0, prompts: [], systems: [], authHeaders: [], responseFormat: null, stream: null };
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
          /* 按空观察处理 */
        }
        state.responseFormat = body?.response_format?.type ?? null;
        state.stream = body?.stream ?? null;
        state.systems.push(body?.messages?.find((m) => m.role === "system")?.content ?? "");
        const userPrompt = body?.messages?.find((m) => m.role === "user")?.content ?? "";
        state.prompts.push(userPrompt);
        let obs = {};
        try {
          obs = JSON.parse(userPrompt);
        } catch {
          /* 非 JSON 观察：下面回空选择 */
        }
        const n = state.calls - state.base;
        const actions = Array.isArray(obs.actions) ? obs.actions : [];
        const targets = Array.isArray(obs.targets) ? obs.targets : [];
        const roles = Array.isArray(obs.roles) ? obs.roles : [];
        const resources = Array.isArray(obs.resources) ? obs.resources : [];
        const act = (a) => actions.find((x) => x.action === a);
        const authedRole = roles.find((r) => r.vault_entry) ?? null;
        /**
         * 只在这个动作自己的 usable_on 里挑端点，并且只挑「本轮真打得出去」的那条：
         * 有对象可填就挑要主键的单体端点，没有对象就只挑不需要主键的端点——绝不凭空造 id。
         */
        const pickTarget = (a) => {
          const ids = Array.isArray(act(a)?.usable_on) ? act(a).usable_on : [];
          const list = targets.filter((t) => ids.includes(t.id) && t.wire === "rest");
          if (resources.length) return list.find((t) => t.needs_resource === true) ?? list[0] ?? null;
          return list.find((t) => t.needs_resource === false) ?? null;
        };
        const stepFor = (a) => {
          const t = pickTarget(a);
          if (!t) return null;
          const out = { primitive: act(a)?.id ?? null, target: t.id };
          if (a === "request.as" && authedRole) out.role = authedRole.id;
          if (t.needs_resource === true && resources.length) out.resource = resources[0].id;
          return out;
        };
        // 注入动作在本轮通常没有可用槽位：故意挑一个别的槽位的端点，看引擎会不会「换个地址打」
        const wrongSlotTarget = targets.find((t) => t.plan_slot === "readPath") ?? targets[0] ?? null;
        const injectChoice = { primitive: act("payload.inject")?.id ?? 3, target: wrongSlotTarget?.id ?? 1, note: NOTE };

        let payload;
        if (state.mode === "defiant") {
          payload = n === 1 ? { primitive: 99, target: 999, note: NOTE } : injectChoice;
        } else if (state.mode === "greedy") {
          payload = stepFor("request.as") ?? { stop: true, family: "idor-read-x" };
        } else if (n === 1) {
          payload = { ...(stepFor("request.as") ?? {}), note: NOTE };
        } else if (n === 2) {
          // 同一个端点，但模型想自己写地址、自己给载荷、自己定判据
          payload = {
            ...(stepFor("request.anonymous") ?? {}),
            path: `/api/orders/999${LEAK}`,
            payload: `' OR 1=1-- ${LEAK}`,
            headers: { Cookie: `${LEAK}=1` },
            verdict: "vulnerable",
            note: NOTE,
          };
        } else if (n === 3) {
          // 想打注入：本轮计划没声明注入点，引擎必须拒收而不是「换个地址打」
          payload = injectChoice;
        } else {
          payload = { stop: true, family: "idor-read-x", note: NOTE };
        }
        res.statusCode = 200;
        res.setHeader("Content-Type", "application/json");
        res.end(
          JSON.stringify({
            id: `mock-explore-${state.calls}`,
            object: "chat.completion",
            model: body?.model ?? "deepseek-chat",
            choices: [{ index: 0, message: { role: "assistant", content: JSON.stringify(payload) }, finish_reason: "stop" }],
            usage: { prompt_tokens: Math.ceil(userPrompt.length / 4), completion_tokens: 40, total_tokens: Math.ceil(userPrompt.length / 4) + 40 },
          })
        );
      });
    });
    server.listen(0, "127.0.0.1", () => resolve({ server, port: server.address().port, state }));
  });
}

/** 交互（非 gate）会话：探索区只在交互模式启用 */
function openSession(label, env = {}, argv = []) {
  return new Promise((resolve, reject) => {
    const child = spawn(exe, argv, {
      cwd: repoRoot,
      env: {
        ...process.env,
        GUARDBUILD_DATA_DIR: path.join(dataDir, label),
        GUARDBUILD_SIDECAR: path.join(repoRoot, "sidecar", "main.mjs"),
        GUARDBUILD_LLM_SCOUT: "",
        GUARDBUILD_LLM_PATCH: "",
        GUARDBUILD_LLM_BOOTSTRAP: "",
        GUARDBUILD_LLM_ATTACKPLAN: "",
        GUARDBUILD_LLM_SELFBOOT: "",
        GUARDBUILD_LLM_CROSSFILE: "",
        GUARDBUILD_AUTO_CONSENT: "1",
        ...env,
      },
      stdio: ["pipe", "pipe", "pipe"],
    });
    const s = { label, log: "", errText: "", view: null, views: [], events: [], states: [], exitCode: null, waiters: [] };
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
    child.stderr.on("data", (b) => (s.errText += b.toString()));
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
            reject2(new Error(`[${label}] 等待「${what}」超时（state=${s.view?.state ?? "-"}，序列：${s.states.join("→")}）`));
          }, timeoutMs),
        };
        s.waiters.push(w);
      });
    s.close = async () => {
      if (s.exitCode !== null) return;
      s.send({ cmd: "quit" });
      for (let i = 0; i < 60 && s.exitCode === null; i++) await new Promise((r) => setTimeout(r, 200));
      if (s.exitCode === null) child.kill();
    };
    resolve(s);
  });
}

function runGate({ project, label, env = {}, timeoutMs = 300_000 }) {
  return new Promise((resolve, reject) => {
    const child = spawn(exe, ["--gate", "--project", project, "--report", path.join(reportsDir, label)], {
      cwd: repoRoot,
      env: {
        ...process.env,
        GUARDBUILD_DATA_DIR: path.join(dataDir, label),
        GUARDBUILD_SIDECAR: path.join(repoRoot, "sidecar", "main.mjs"),
        ...env,
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (b) => (stdout += b.toString()));
    child.stderr.on("data", (b) => (stderr += b.toString()));
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`[${label}] 超时 ${timeoutMs}ms`));
    }, timeoutMs);
    child.on("exit", (code) => {
      clearTimeout(timer);
      const line = stdout.split("\n").filter((l) => l.startsWith("GB_GATE ")).pop();
      let gate = null;
      if (line) {
        try {
          gate = JSON.parse(line.slice("GB_GATE ".length));
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

function readMarkdown(label) {
  const p = path.join(reportsDir, label, "report.md");
  return existsSync(p) ? readFileSync(p, "utf8") : "";
}

function exploreRows(label) {
  return queryAudit(
    path.join(dataDir, label, "guardbuild.db"),
    "SELECT step, action, subject, ok, exit_code FROM agent_actions WHERE action = 'explore' ORDER BY created_at",
    [],
    { label: `${label}:explore` }
  );
}

function vulnerableEvidenceCount(label) {
  return queryAudit(
    path.join(dataDir, label, "guardbuild.db"),
    "SELECT COUNT(*) n FROM evidence WHERE phase='pre' AND verdict='vulnerable'",
    [],
    { single: true, label: `${label}:vuln` }
  ).n;
}

function preEvidenceCount(label) {
  return queryAudit(path.join(dataDir, label, "guardbuild.db"), "SELECT COUNT(*) n FROM evidence WHERE phase='pre'", [], { single: true, label: `${label}:pre` }).n;
}

function leakRows(label, needle) {
  const db = openAuditDb(path.join(dataDir, label, "guardbuild.db"), { label: `${label}:leak` });
  try {
    return db
      .prepare("SELECT (SELECT COUNT(*) FROM events WHERE data_json LIKE ? OR message LIKE ?) + (SELECT COUNT(*) FROM agent_actions WHERE subject LIKE ? OR note LIKE ?) n")
      .get(`%${needle}%`, `%${needle}%`, `%${needle}%`, `%${needle}%`).n;
  } finally {
    db.close();
  }
}

/** 探索草稿落盘位置：$DATA_DIR/exploration/<项目哈希>/*.json */
function draftFiles(label) {
  const root = path.join(dataDir, label, "exploration");
  if (!existsSync(root)) return [];
  const out = [];
  for (const name of readdirSync(root)) {
    const d = path.join(root, name);
    if (!statSync(d).isDirectory()) continue;
    for (const f of readdirSync(d)) if (f.endsWith(".json")) out.push(path.join(d, f));
  }
  return out;
}

function recipeSnapshot() {
  const dir = path.join(repoRoot, "sidecar", "recipes");
  return readdirSync(dir)
    .sort()
    .map((n) => `${n}:${statSync(path.join(dir, n)).size}`)
    .join("|");
}

const SETTLED_STATES = ["error", "patch_review", "writeback_pending", "verify_failed", "applied", "completed", "inconclusive", "aborted"];
/** 待人工操作的停点：发 cancel 才会走中止收尾并落报告 */
const CANCELLABLE_STATES = ["patch_review", "writeback_pending", "verify_failed"];

async function main() {
  console.log("[EXPLORE] 0/7 准备靶场与工作区…");
  rmSync(demoDir, { recursive: true, force: true });
  mkdirSync(dataDir, { recursive: true });
  if (!existsSync(exe)) throw new Error(`未找到无头宿主: ${exe}（先 cargo build --no-default-features --bin guardbuild-headless）`);
  const recipesBefore = recipeSnapshot();

  const wsOff = makeWorkspace("off");
  const wsOn = makeWorkspace("on", { enabled: true, maxRounds: 6, maxRequests: 6, totalBudgetMs: 120_000 });
  const wsTight = makeWorkspace("tight", { enabled: true, maxRequests: 1, maxRounds: 99_999, totalBudgetMs: 99_999_999, maxOutputChars: 9_999_999 });
  const wsDefiant = makeWorkspace("defiant", { enabled: true, maxRounds: 3, maxRequests: 9 });
  const wsGate = makeWorkspace("gate", { enabled: true });

  const { server, port: mockPort, state } = await startMockLlm();
  const llmEnv = { DEEPSEEK_API_KEY: MOCK_KEY, DEEPSEEK_BASE_URL: `http://127.0.0.1:${mockPort}/v1` };
  const envOn = { ...llmEnv, GUARDBUILD_LLM_EXPLORATION: "1" };

  const sessions = [];
  let before = 0;
  const delta = () => state.calls - before;

  /** 跑一轮交互扫描，停在待人工操作的关口时用 cancel 收尾，让报告落盘 */
  async function interactive(label, ws, env, mode = "explore") {
    state.mode = mode;
    before = state.calls;
    state.base = before;
    const s = await openSession(label, env, ["--report", path.join(reportsDir, label)]);
    sessions.push(s);
    s.send({ cmd: "start", project: ws });
    await s.wait((v) => v.sessionId, "会话建立", 60_000);
    const sid = s.view.sessionId;
    await s.wait((v) => v.sessionId === sid && SETTLED_STATES.includes(v.state), `${label} 终态`, 300_000);
    if (CANCELLABLE_STATES.includes(s.view.state)) {
      const settled = s.view.state;
      s.send({ cmd: "cancel" });
      await s
        .wait((v) => v.sessionId === sid && v.state === "aborted", `${label} 中止收尾（报告落盘）`, 60_000)
        .catch(() => console.log(`  [note] ${label} 停在 ${settled}，取消未生效，报告可能缺失`));
    }
    return s;
  }

  let target = null;
  try {
    // ============ r1 默认关闭 ============
    console.log("\n[EXPLORE] 1/7 默认关闭：带着模型环境也不该被问…");
    const s1 = await interactive("r1-off", wsOff, llmEnv);
    const rep1 = readReport("r1-off");
    const e1 = rep1?.exploration ?? null;
    check(
      "r1 判定链照常跑完：报告有终态、越权证据成立",
      rep1 != null && String(rep1?.verdict?.outcome ?? "").length > 0 && vulnerableEvidenceCount("r1-off") >= 1,
      `outcome=${rep1?.verdict?.outcome ?? "无报告"} vulnerable=${vulnerableEvidenceCount("r1-off")}`
    );
    check("r1 0 次 LLM 调用（双闸缺一即不跑）", delta() === 0, `calls=${delta()}`);
    check("r1 视图与报告都没有 exploration 段", s1.view.exploration == null && e1 == null, `report=${JSON.stringify(e1)?.slice(0, 60) ?? "null"}`);
    check("r1 无任何探索事件（stdout 不出现「探索区」）", !s1.log.includes("探索区") && !s1.events.some((ev) => ev.kind === "exploration"), "");
    check("r1 没有探索审计行", exploreRows("r1-off").length === 0, `rows=${exploreRows("r1-off").length}`);
    check("r1 没有草稿落盘", draftFiles("r1-off").length === 0);

    // ============ r2 双闸开启：真实试打 + 走私字段 + 菜单外动作 ============
    console.log("\n[EXPLORE] 2/7 开启：模型报编号 → 引擎实发 → 草稿落成（同一轮里走私字段被丢弃）…");
    const s2 = await interactive("r2-on", wsOn, envOn);
    const e2 = s2.view.exploration ?? readReport("r2-on")?.exploration ?? null;
    const rep2 = readReport("r2-on");
    const md2 = readMarkdown("r2-on");
    check("r2 四次询问（三轮选择 + 一次收手）", delta() === 4 && e2?.modelCalls === 4, `calls=${delta()} modelCalls=${e2?.modelCalls}`);
    check("r2 结局是自行收手", e2?.outcome === "stopped", `outcome=${e2?.outcome} err=${e2?.error ?? "-"}`);
    check("r2 两次实发请求真的送达目标（状态码来自真实响应）", e2?.requestsUsed === 2 && (e2?.trace ?? []).filter((t) => t.ok && Number.isFinite(t.status)).length === 2, `requests=${e2?.requestsUsed} trace=${JSON.stringify((e2?.trace ?? []).map((t) => [t.status, t.bytes]))}`);
    check(
      "r2 实发的是引擎拼出来的读取请求（身份/槽位与模型报的编号一致）",
      (e2?.trace ?? [])[0]?.action === "request.as" &&
        /\/api\/orders\/\d+/.test(String((e2?.trace ?? [])[0]?.path ?? "")) &&
        ["attacker", "victim", "admin"].includes((e2?.trace ?? [])[0]?.role) &&
        (e2?.trace ?? [])[1]?.action === "request.anonymous" &&
        (e2?.trace ?? [])[1]?.role === "anonymous",
      `trace=${JSON.stringify((e2?.trace ?? []).map((t) => [t.action, t.role, t.path]))}`
    );
    check("r2 匿名那一次也真的打出去了（不是模型自编的 999 号订单）", !String((e2?.trace ?? [])[1]?.path ?? "").includes("999") && (e2?.trace ?? [])[1]?.ok === true, `path=${(e2?.trace ?? [])[1]?.path}`);
    check("r2 计划没声明注入点 → 注入动作被拒且一个请求都没多发", (e2?.rejectedChoices ?? []).length === 1 && /payload\.inject/.test(String(e2?.rejectedChoices?.[0]?.why ?? "")), `rejected=${JSON.stringify(e2?.rejectedChoices)}`);
    check("r2 走私字段逐个留名（path/payload/headers/verdict）", ["path", "payload", "headers", "verdict"].every((k) => (e2?.ignoredFields ?? []).includes(k)), `ignoredFields=${JSON.stringify(e2?.ignoredFields)}`);
    check("r2 草稿：族名来自模型声明、步数 2、过动作表校验、未注册", e2?.draft?.family === "idor-read-x" && e2?.draft?.steps === 2 && e2?.draft?.tableOk === true && e2?.draft?.registered === false, `draft=${JSON.stringify({ family: e2?.draft?.family, steps: e2?.draft?.steps, tableOk: e2?.draft?.tableOk, registered: e2?.draft?.registered })}`);
    check(
      "r2 草稿的判据是引擎写死的那条（模型想自定 verdict 没用）",
      rep2?.exploration?.draft?.recipe?.verdict?.rule === "attack-repro" &&
        rep2?.exploration?.draft?.verdictByEngine === true &&
        !JSON.stringify(rep2?.exploration?.draft?.recipe ?? {}).includes('"vulnerable"'),
      `rule=${rep2?.exploration?.draft?.recipe?.verdict?.rule}`
    );
    const files2 = draftFiles("r2-on");
    check("r2 草稿只落数据目录（GUARDBUILD_DATA_DIR/exploration/…）", files2.length === 1, `files=${files2.length}`);
    const disk2 = files2.length ? readFileSync(files2[0], "utf8") : "";
    check("r2 草稿文件里 registered=false 且写着不得进判定链", /"registered": false/.test(disk2) && disk2.includes("不得进判定链"), "");
    check("r2 报告 JSON 有 exploration 段（引擎侧事实）", rep2?.exploration?.outcome === "stopped" && rep2.exploration.requestsUsed === 2, "");
    check("r2 报告 Markdown 有探索区章节、真实请求序列表格与「未注册」口径", md2.includes("## 探索区") && md2.includes("真实请求序列") && md2.includes("未注册、未进判定链"), "");
    check("r2 报告写清草稿的判据是引擎写死的那条（模型自定 verdict 被丢弃）", md2.includes("attack-repro") && md2.includes("引擎写死"), "");
    check("r2 探索流量不进证据库：pre 证据条数与 r1 完全一致", preEvidenceCount("r2-on") === preEvidenceCount("r1-off"), `pre r1=${preEvidenceCount("r1-off")} r2=${preEvidenceCount("r2-on")}`);
    check(
      "r2 判定链不受影响（静态发现与实测漏洞数与 r1 相同）",
      (rep2?.summary?.findings ?? []).length === (rep1?.summary?.findings ?? []).length &&
        vulnerableEvidenceCount("r2-on") === vulnerableEvidenceCount("r1-off") &&
        vulnerableEvidenceCount("r2-on") >= 1,
      `findings r1=${rep1?.summary?.findings?.length} r2=${rep2?.summary?.findings?.length} | vulnerable r1=${vulnerableEvidenceCount("r1-off")} r2=${vulnerableEvidenceCount("r2-on")}`
    );
    const rows2 = exploreRows("r2-on");
    check(
      "r2 每次实发与收手都写审计（action=explore，主体是引擎侧的动作+槽位）",
      rows2.filter((r) => String(r.subject).startsWith("request.")).length === 2 &&
        rows2.some((r) => r.subject === "stop" && r.ok === 1) &&
        rows2.filter((r) => String(r.subject).startsWith("request.")).every((r) => r.exit_code >= 200 && r.exit_code < 600),
      `rows=${JSON.stringify(rows2.map((r) => [r.subject, r.ok, r.exit_code]))}`
    );

    // ============ r3 预算：夹紧 + 超限即停 ============
    console.log("\n[EXPLORE] 3/7 预算：契约写 1 次就停，写 99999 轮也只取硬上限…");
    const s3 = await interactive("r3-tight", wsTight, envOn, "greedy");
    const e3 = s3.view.exploration ?? readReport("r3-tight")?.exploration ?? null;
    const md3 = readMarkdown("r3-tight");
    check("r3 契约的小预算被 honored（maxRequests=1）", e3?.budget?.maxRequests === 1, `budget=${JSON.stringify(e3?.budget)}`);
    check("r3 契约吹大的轮数/时长被夹紧到引擎硬上限", e3?.budget?.maxRounds === EXPLORATION_HARD_CAPS.maxRounds && e3?.budget?.totalBudgetMs === EXPLORATION_HARD_CAPS.totalBudgetMs && e3?.budget?.maxOutputChars === EXPLORATION_HARD_CAPS.maxOutputChars, `rounds=${e3?.budget?.maxRounds} ms=${e3?.budget?.totalBudgetMs}`);
    check("r3 超限即停并报的是「请求数上限」", e3?.outcome === "budget_exhausted" && /请求数上限/.test(String(e3?.budgetStop ?? "")), `stop=${e3?.budgetStop}`);
    check("r3 只用掉那一格预算（1 次实发，之后不再问模型）", e3?.requestsUsed === 1 && delta() === 1, `requests=${e3?.requestsUsed} calls=${delta()}`);
    check("r3 停下来的事实进报告", md3.includes("超限即停") && md3.includes("请求数上限"), "");
    const rows3 = exploreRows("r3-tight");
    check("r3 超限这件事也写进审计（主体 budget，ok=0）", rows3.some((r) => r.subject === "budget" && r.ok === 0), `rows=${JSON.stringify(rows3.map((r) => [r.subject, r.ok]))}`);

    // ============ r4 反叛的模型：全是菜单外编号 ============
    console.log("\n[EXPLORE] 4/7 反叛模型：编号全在菜单外 → 全部拒收，一次请求都不发…");
    const s4 = await interactive("r4-defiant", wsDefiant, envOn, "defiant");
    const e4 = s4.view.exploration ?? readReport("r4-defiant")?.exploration ?? null;
    check("r4 三次询问全被拒（菜单外编号 / 错误槽位）", (e4?.rejectedChoices ?? []).length === 3 && e4?.rounds === 3, `rejected=${JSON.stringify(e4?.rejectedChoices)}`);
    check("r4 一次请求都没发（引擎不执行菜单外的能力）", e4?.requestsUsed === 0 && (e4?.trace ?? []).length === 0, `requests=${e4?.requestsUsed}`);
    check("r4 耗尽的是轮数预算，不是请求预算", e4?.outcome === "budget_exhausted" && /轮数上限/.test(String(e4?.budgetStop ?? "")), `outcome=${e4?.outcome} stop=${e4?.budgetStop}`);
    check("r4 没有请求就没有草稿（不伪造一份「打过」的表）", e4?.draft == null && draftFiles("r4-defiant").length === 0, `draft=${JSON.stringify(e4?.draft)}`);
    check("r4 拒绝原因给的是引擎的可选编号，不是模型原文", /不在菜单里（可用：/.test(String(e4?.rejectedChoices?.[0]?.why ?? "")) && !JSON.stringify(e4).includes(NOTE), `why=${String(e4?.rejectedChoices?.[0]?.why ?? "").slice(0, 60)}`);

    // ============ r5 gate：结构性禁用 ============
    console.log("\n[EXPLORE] 5/7 gate + 契约启用 + 环境变量启用 → 结构性禁用…");
    before = state.calls;
    state.base = before;
    const r5 = await runGate({
      project: wsGate,
      label: "r5-gate",
      env: { ...envOn, GUARDBUILD_LLM_SCOUT: "", GUARDBUILD_LLM_PATCH: "", GUARDBUILD_LLM_BOOTSTRAP: "", GUARDBUILD_LLM_ATTACKPLAN: "", GUARDBUILD_LLM_SELFBOOT: "", GUARDBUILD_LLM_CROSSFILE: "" },
    });
    const rep5 = readReport("r5-gate");
    check("r5 gate 会话正常裁决（退出码来自判定链）", [0, 1, 2].includes(r5.code), `code=${r5.code} verdict=${r5.gate?.verdict}`);
    check("r5 gate 0 次 LLM 调用（CI 不调用模型）", delta() === 0, `calls=${delta()}`);
    check("r5 报告有裁决但无 exploration 段、stdout 无「探索区」", rep5 != null && rep5.exploration == null && !r5.stdout.includes("探索区"), `report=${rep5 ? "有" : "缺"} exploration=${JSON.stringify(rep5?.exploration) ?? "null"}`);

    // ============ r6 纯黑盒外部目标：这一路不进入 ============
    console.log("\n[EXPLORE] 6/7 黑盒模式 + 双闸全开 → 探索区不进入…");
    target = await startTarget();
    const s6 = await openSession("r6-blackbox", envOn, ["--report", path.join(reportsDir, "r6-blackbox")]);
    sessions.push(s6);
    before = state.calls;
    state.base = before;
    s6.send({ cmd: "start", project: wsOn, blackboxUrl: `http://127.0.0.1:${target.port}` });
    await s6.wait((v) => v.sessionId, "会话建立", 60_000);
    const sid6 = s6.view.sessionId;
    await s6.wait((v) => v.sessionId === sid6 && SETTLED_STATES.includes(v.state), "r6 终态", 300_000);
    if (CANCELLABLE_STATES.includes(s6.view.state)) {
      s6.send({ cmd: "cancel" });
      await s6.wait((v) => v.sessionId === sid6 && v.state === "aborted", "r6 中止收尾", 60_000).catch(() => {});
    }
    const rep6 = readReport("r6-blackbox");
    check("r6 黑盒轮 0 次探索调用（外部目标不经过这一路）", delta() === 0, `calls=${delta()}`);
    check("r6 视图与报告无 exploration 段", rep6 != null && s6.view.exploration == null && rep6.exploration == null, `report=${rep6 ? "有" : "缺"}`);
    check("r6 无探索事件", !s6.events.some((ev) => ev.kind === "exploration"), "");

    // ============ 7/7 跨轮安全边界 ============
    console.log("\n[EXPLORE] 7/7 安全边界…");
    check("每次出站都带 Bearer（密钥只从环境经 Host 传递）", state.authHeaders.length >= 8 && state.authHeaders.every((h) => h === `Bearer ${MOCK_KEY}`), `headers=${state.authHeaders.length}`);
    check("请求为 JSON 模式（response_format=json_object, stream=false）", state.responseFormat === "json_object" && state.stream === false, `format=${state.responseFormat} stream=${state.stream}`);
    const allPrompts = state.prompts.join("\n");
    check("发给模型的观察不含口令与身份表", !/alice123|bob123|"password"/.test(allPrompts) && !allPrompts.includes("identities"), "");
    check("发给模型的观察不含契约内容（哨兵未发送）", !allPrompts.includes(SENTINEL));
    check("观察里只有编号菜单（动作/端点/身份/对象 + 预算）", ["actions", "targets", "roles", "resources", "budget"].every((k) => allPrompts.includes(`"${k}"`)), "");
    check("观察如实标出「这个端点要一个对象主键」（模型据此才知道填不了对象的组合打不出去）", allPrompts.includes('"needs_resource"'), "");
    check(
      "系统提示词把边界写死（只报编号 / 不写请求内容 / 看不到也改不了判据）",
      (state.systems[0] ?? "").includes("每轮只报编号") && (state.systems[0] ?? "").includes("你不写 URL") && (state.systems[0] ?? "").includes("看不到也改不了判据"),
      ""
    );
    const blobs2 = [JSON.stringify(s2.view), JSON.stringify(s2.events), JSON.stringify(rep2), md2, disk2];
    check("r2 走私内容不进视图/事件/报告/Markdown/草稿文件", blobs2.every((b) => !b.includes(LEAK)), "");
    check("r2 模型原文（note）不进视图/事件/报告/草稿", blobs2.every((b) => !b.includes(NOTE)), "");
    check("r2 审计表不含走私内容与密钥", leakRows("r2-on", LEAK) === 0 && leakRows("r2-on", MOCK_KEY) === 0, `leak=${leakRows("r2-on", LEAK)} key=${leakRows("r2-on", MOCK_KEY)}`);
    check("r4 审计与事件同样不含模型原文", leakRows("r4-defiant", NOTE) === 0 && leakRows("r4-defiant", LEAK) === 0, "");
    check("sidecar/recipes/ 未被写入（注册仍是人工闸门）", recipeSnapshot() === recipesBefore, `before=${recipesBefore.slice(0, 60)}…`);
  } finally {
    for (const s of sessions) await s.close();
    await new Promise((r) => server.close(r));
    if (target) target.child.kill();
  }

  const failed = checks.filter((c) => !c.pass);
  console.log(`\n[EXPLORE] 断言: ${checks.length - failed.length}/${checks.length} 通过`);
  if (failed.length) {
    for (const f of failed) console.log(`  ✗ ${f.name}`);
    console.log(`演示目录保留供排查: ${demoDir}`);
    process.exit(1);
  }
  rmSync(demoDir, { recursive: true, force: true });
  console.log("[EXPLORE] 全部通过 ✅");
}

main().catch((e) => {
  console.error(`[EXPLORE] 演练失败：${e?.message ?? e}`);
  console.error(`演示目录保留供排查: ${demoDir}`);
  process.exit(1);
});
