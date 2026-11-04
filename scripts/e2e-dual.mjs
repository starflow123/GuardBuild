#!/usr/bin/env node
/**
 * 提议者 A/B 双路独立提案 + 对比分析（方案第 14、15 项）端到端演练。
 * 本机回环 mock DeepSeek + 白盒靶场 fixtures/selfboot-shop，跑的是真实侧车 + 真实宿主。
 *
 * 单测能证明纯函数对不对，这一轮要证明的是接上真靶场以后那三件事仍然成立：
 *   r1 默认关（契约 enabled 但没点名 proposers，环境变量也没开）：0 次模型调用、无 exploration 段。
 *   r2 只开探索区（第 13 项那条单路）：dual 段必须不存在——双路不是「顺手就开」的。
 *   r3 双路真跑（enabled + proposers:["A","B"] + 环境变量）：
 *      A 按通用形状挑「换身份读」，B 按靶子真实响应挑「匿名读」，两路各发各的真实请求；
 *      两份草稿确有差异（这是第 14 项的验收）、菜单指纹一致、提示词隔离通过；
 *      对比代理这一轮故意只写「建议合并」——引擎照样落「退回」（第 15 项的降级权）；
 *      两份草稿各带 A-/B- 前缀落进数据目录，sidecar/recipes/ 一个字节都不变。
 *   r4 gate + 三闸全开：结构性禁用，0 次模型调用，报告里没有双路章节。
 *   r5 纯黑盒外部目标 + 三闸全开：这一路根本不进入。
 *   r6 判卷层落了成绩之后（第 6/14 项那条通路的**读取侧**）：只给 A 放一条形状一致的样例成绩，
 *      A 的两条成绩事实亮绿、B 仍如实无成绩，结论照样是引擎落的「退回」，且 grades/ 逐字节没被扫描改过。
 *      真判卷那条通路在 scripts/e2e-draft-grade.mjs 里演练，这一轮不假装考过卷。
 *
 * 安全边界与第 13 项同一口径：模型走私的内容、模型原文（note）、契约哨兵、身份口令
 * 都不许进视图/事件/报告/草稿文件/审计库；A 一路连响应正文的键都收不到。
 *
 * 报告从哪来：白盒交互轮在有漏洞时停在「补丁待审查」，那一步不落报告。
 * 因此每轮读完视图后发 cancel——侧车在待审查态走中止收尾，双路章节随之落盘。
 *
 * 用法: node scripts/e2e-dual.mjs
 */
import { spawn, spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";
import readline from "node:readline";
import { fileURLToPath } from "node:url";
import { openAuditDb, queryAudit } from "./lib/auditdb.mjs";
import { PROPOSERS, privateLinesOf, proposerById } from "../sidecar/lib/proposers.mjs";
import { GRADE_VERSION } from "../sidecar/lib/grader.mjs";
import { readGradeRecord, recipeSha256, writeGradeRecord } from "../sidecar/lib/draftgrade.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const demoDir = path.join(repoRoot, ".demo-dual");
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
const LEAK = "LEAK-SMUGGLED-DUAL-3a07";
// 模型原文哨兵：note 不进视图/事件/审计/报告/草稿文件
const NOTE = "MODEL-NOTE-DUAL-9d5b";
// 契约哨兵：guardbuild.json 的私有内容不该出现在发给模型的观察里
const SENTINEL = "SENTINEL_DUAL_CONTRACT_MUST_NOT_BE_SENT_TO_LLM";

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

/** 复制靶场并按本轮要验的开关写入探索区/双路契约 */
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

/** 单独起一份靶场给纯黑盒轮次用（双路对黑盒模式代码级不进入） */
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
 * mock DeepSeek：按「本轮观察里给自己的编号菜单」挑，而不是写死编号——
 * 断言的是「这一路报的编号真的被引擎解析成它自己那条请求」。
 * 三种角色靠观察里的字段区分：探索观察带 actions 数组，且双路时带 proposal.id；
 * 对比分析的观察带 task 文本。
 */
function startMockLlm() {
  return new Promise((resolve) => {
    const state = {
      calls: 0,
      base: 0,
      prompts: [],
      systems: [],
      roles: [],
      authHeaders: [],
      responseFormat: null,
      stream: null,
      comparatorAsked: 0,
      per: {},
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
          /* 非 JSON 观察 */
        }
        const isComparator = typeof obs.task === "string" && obs.task.includes("对比");
        const who = isComparator ? "compare" : obs?.proposal?.id ?? "single";
        state.roles.push(who);
        let payload;
        if (isComparator) {
          state.comparatorAsked += 1;
          // 这一轮故意只说「建议合并」，并夹带表外字段：引擎必须照样落退回
          payload = {
            recommendation: "merge",
            divergences: ["A 换身份读、B 匿名读，两路打的是同一类对象的不同前置条件"],
            b_is_reskin: false,
            why: "两份互补，建议合成一条",
            verdict: "vulnerable",
            registered: true,
            note: NOTE,
          };
        } else {
          const actions = Array.isArray(obs.actions) ? obs.actions : [];
          const targets = Array.isArray(obs.targets) ? obs.targets : [];
          const roles = Array.isArray(obs.roles) ? obs.roles : [];
          const resources = Array.isArray(obs.resources) ? obs.resources : [];
          const act = (a) => actions.find((x) => x.action === a);
          const authedRole = roles.find((r) => r.vault_entry) ?? null;
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
          // 这一路的第几次被问（每一路各自计数）
          state.per[who] = (state.per[who] ?? 0) + 1;
          const n = state.per[who];
          if (n === 1) {
            const action = who === "B" ? "request.anonymous" : "request.as";
            payload = {
              ...(stepFor(action) ?? {}),
              path: `/api/orders/999${LEAK}`,
              payload: `' OR 1=1-- ${LEAK}`,
              headers: { Cookie: `${LEAK}=1` },
              verdict: "vulnerable",
              note: NOTE,
            };
          } else if (who === "single" && n === 2) {
            payload = { ...(stepFor("request.anonymous") ?? {}), note: NOTE };
          } else {
            payload = { stop: true, family: who === "B" ? "anon-read-by-response" : who === "single" ? "single-path-read" : "read-by-generic-shape", note: NOTE };
          }
        }
        res.statusCode = 200;
        res.setHeader("Content-Type", "application/json");
        res.end(
          JSON.stringify({
            id: `mock-dual-${state.calls}`,
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

/** 探索审计行：实发逐步一行（真实状态码进 exit_code）、收手一行（族名只写在 note，不冒充主体） */
function exploreRows(label) {
  return queryAudit(
    path.join(dataDir, label, "guardbuild.db"),
    "SELECT step, action, subject, ok, exit_code, note FROM agent_actions WHERE action = 'explore' ORDER BY created_at",
    [],
    { label: `${label}:explore` }
  );
}

/**
 * 侧车自发的事件只落在 DB 的 events 表：宿主把侧车事件收进环形缓冲但不逐条转印到 stdout
 * （stdout 的 GB_EVENT 只有宿主自己发的非 info 事件），所以事件留痕一律从库里读，不看 stdout。
 */
function explorationEventMessages(label) {
  return queryAudit(
    path.join(dataDir, label, "guardbuild.db"),
    "SELECT message FROM events WHERE kind='exploration' ORDER BY ts",
    [],
    { label: `${label}:events` }
  ).map((r) => String(r.message ?? ""));
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

/** 成绩目录快照：扫描这一侧声称「只读不写成绩」，就用逐文件的字节数+内容哈希比给它看 */
function gradeSnapshot(dir) {
  if (!dir || !existsSync(dir)) return "empty";
  return readdirSync(dir)
    .filter((n) => n.endsWith(".json"))
    .sort()
    .map((n) => {
      const buf = readFileSync(path.join(dir, n));
      return `${n}:${buf.length}:${createHash("sha256").update(buf).digest("hex").slice(0, 12)}`;
    })
    .join("|");
}

function recipeSnapshot() {
  const dir = path.join(repoRoot, "sidecar", "recipes");
  return readdirSync(dir)
    .sort()
    .map((n) => `${n}:${statSync(path.join(dir, n)).size}`)
    .join("|");
}

const SETTLED_STATES = ["error", "patch_review", "writeback_pending", "verify_failed", "applied", "completed", "inconclusive", "aborted"];
const CANCELLABLE_STATES = ["patch_review", "writeback_pending", "verify_failed"];

/** 按角色取那一路的出站提示词（roles 与 prompts 同序写入） */
function promptsFor(state, who) {
  return state.prompts.filter((_, i) => state.roles[i] === who);
}

async function main() {
  console.log("[DUAL] 0/7 准备靶场与工作区…");
  rmSync(demoDir, { recursive: true, force: true });
  mkdirSync(dataDir, { recursive: true });
  if (!existsSync(exe)) throw new Error(`未找到无头宿主: ${exe}（先 cargo build --no-default-features --bin guardbuild-headless）`);
  const recipesBefore = recipeSnapshot();

  const wsOff = makeWorkspace("off");
  const wsSingle = makeWorkspace("single", { enabled: true, maxRounds: 5, maxRequests: 5, totalBudgetMs: 120_000 });
  const wsDual = makeWorkspace("dual", { enabled: true, proposers: ["A", "B"], maxRounds: 5, maxRequests: 3, totalBudgetMs: 120_000 });
  const wsGate = makeWorkspace("gate", { enabled: true, proposers: ["A", "B"] });

  const { server, port: mockPort, state } = await startMockLlm();
  const llmEnv = { DEEPSEEK_API_KEY: MOCK_KEY, DEEPSEEK_BASE_URL: `http://127.0.0.1:${mockPort}/v1` };
  const envOn = { ...llmEnv, GUARDBUILD_LLM_EXPLORATION: "1" };

  const sessions = [];
  let before = 0;
  const delta = () => state.calls - before;

  /** 跑一轮交互扫描；停在待人工操作的关口时用 cancel 收尾，让报告落盘 */
  async function interactive(label, ws, env) {
    before = state.calls;
    state.base = before;
    state.per = {};
    state.comparatorAsked = 0;
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
    console.log("\n[DUAL] 1/7 契约没点名提议者、环境变量也没开 → 一次都不问…");
    const s1 = await interactive("r1-off", wsOff, envOn);
    const rep1 = readReport("r1-off");
    check("r1 判定链照常跑完（有漏洞、有证据）", rep1 != null && vulnerableEvidenceCount("r1-off") >= 1, `outcome=${rep1?.verdict?.outcome ?? "无报告"}`);
    check("r1 0 次模型调用", delta() === 0, `calls=${delta()}`);
    check("r1 视图与报告都没有 exploration/dual 段", s1.view.exploration == null && rep1?.exploration == null, "");
    check("r1 没有草稿落盘", draftFiles("r1-off").length === 0);

    // ============ r2 只开探索区：双路不是顺手就开 ============
    console.log("\n[DUAL] 2/7 只开第 13 项那条单路：dual 段必须不存在…");
    const s2 = await interactive("r2-single", wsSingle, envOn);
    const e2 = s2.view.exploration ?? readReport("r2-single")?.exploration ?? null;
    check("r2 单路真跑：三次询问、两次实发", delta() === 3 && e2?.modelCalls === 3 && e2?.requestsUsed === 2, `calls=${delta()} modelCalls=${e2?.modelCalls} requests=${e2?.requestsUsed}`);
    check("r2 是第 13 项那条单路（没有 dual 段、没有提议者归属）", e2?.dual == null && (e2?.proposal ?? null) == null, `dual=${JSON.stringify(e2?.dual) ?? "null"}`);
    check("r2 一路一份草稿，草稿键不带提议者编号", draftFiles("r2-single").length === 1 && !String(e2?.draftKey ?? "").startsWith("A-"), `draftKey=${e2?.draftKey}`);
    check("r2 单路提示词里没有双路的清单段与响应指引", promptsFor(state, "single").every((p) => !p.includes('"shapes"') && !p.includes('"observe"')), "");

    // ============ r3 双路真跑 ============
    console.log("\n[DUAL] 3/7 双路独立提案：同一菜单各打各的 → 草稿有差异 → 对比只出退回…");
    const s3 = await interactive("r3-dual", wsDual, envOn);
    const rep3 = readReport("r3-dual");
    const md3 = readMarkdown("r3-dual");
    const e3 = s3.view.exploration ?? rep3?.exploration ?? null;
    const d3 = e3?.dual ?? null;
    const cmp3 = d3?.comparison ?? null;
    const propA = d3?.proposals?.find((p) => p.id === "A") ?? null;
    const propB = d3?.proposals?.find((p) => p.id === "B") ?? null;
    check("r3 询问次数 = 两路各两轮（4 次）+ 对比代理一次（不进两路预算）", delta() === 5 && d3?.totals?.modelCalls === 4 && state.comparatorAsked === 1, `出站=${delta()} totals.modelCalls=${d3?.totals?.modelCalls} 对比=${state.comparatorAsked}`);
    check("r3 双路跑起来了（两路都有试打记录）", d3?.outcome === "ran" && propA?.outcome === "stopped" && propB?.outcome === "stopped", `outcome=${d3?.outcome} A=${propA?.outcome} B=${propB?.outcome}`);
    check("r3 每路一份独立预算：各 1 次实发、合计 2 次", d3?.budget?.maxRequests === 3 && propA?.requestsUsed === 1 && propB?.requestsUsed === 1 && d3?.totals?.requestsUsed === 2, `budget=${JSON.stringify(d3?.budget)}`);
    check(
      "r3 两路打的是不同打法（A 换身份读 / B 匿名读），状态码来自真实响应",
      propA?.evidence?.requests?.[0]?.action === "request.as" &&
        propB?.evidence?.requests?.[0]?.action === "request.anonymous" &&
        Number.isFinite(propA?.evidence?.requests?.[0]?.status) &&
        Number.isFinite(propB?.evidence?.requests?.[0]?.status) &&
        propB?.evidence?.requests?.[0]?.role === "anonymous",
      `A=${JSON.stringify(propA?.evidence?.requests?.[0])} B=${JSON.stringify(propB?.evidence?.requests?.[0])}`
    );
    check("r3 两路看到的是同一份菜单（指纹一致，差异才归因到提议者）", d3?.menusIdentical === true && !!propA?.menuFingerprint && propA.menuFingerprint === propB?.menuFingerprint, `fp=${String(propA?.menuFingerprint).slice(0, 12)}`);
    check("r3 提示词隔离通过（真流量逐条对账，不是注释里的承诺）", d3?.isolation?.ok === true && (d3?.isolation?.leaked ?? []).length === 0 && d3?.isolation?.checked > 0, `checked=${d3?.isolation?.checked} leaked=${JSON.stringify(d3?.isolation?.leaked)}`);
    check("r3 同一靶场两份草稿确有差异（第 14 项验收）", d3?.draftsDiffer === true && d3?.diff?.identical === false && (d3?.diff?.onlyA ?? []).length >= 1 && (d3?.diff?.onlyB ?? []).length >= 1, `diff=${JSON.stringify(d3?.diff?.divergences)}`);
    check(
      "r3 两路草稿各自带提议者编号、族名不同、都过动作表且都未注册",
      String(propA?.draftKey ?? "").startsWith("A-") &&
        String(propB?.draftKey ?? "").startsWith("B-") &&
        propA?.draft?.family === "read-by-generic-shape" &&
        propB?.draft?.family === "anon-read-by-response" &&
        propA?.draft?.tableOk === true &&
        propB?.draft?.tableOk === true &&
        propA?.draft?.registered === false &&
        propB?.draft?.registered === false,
      `A=${propA?.draftKey}/${propA?.draft?.family} B=${propB?.draftKey}/${propB?.draft?.family}`
    );
    check("r3 两路各自的判据都是引擎写死的那条（模型自定 verdict 没用）", propA?.draft?.verdictRule === "attack-repro" && propA?.draft?.verdictByEngine === true && propB?.draft?.verdictRule === "attack-repro", `A=${propA?.draft?.verdictRule} B=${propB?.draft?.verdictRule}`);
    check("r3 两路各自丢掉的表外字段都留了名（path/payload/headers/verdict）", ["path", "payload", "headers", "verdict"].every((k) => (propA?.evidence?.ignoredFields ?? []).includes(k) && (propB?.evidence?.ignoredFields ?? []).includes(k)), `A=${JSON.stringify(propA?.evidence?.ignoredFields)} B=${JSON.stringify(propB?.evidence?.ignoredFields)}`);
    check("r3 对比代理被问过且它确实说了「建议合并」", state.comparatorAsked === 1 && cmp3?.model?.ok === true && cmp3?.model?.recommendation === "merge_suggestion", `asked=${state.comparatorAsked} model=${JSON.stringify(cmp3?.model)?.slice(0, 90)}`);
    check(
      "r3 引擎照样落退回（第 15 项：模型只有降级权，合并建议要事实齐备才亮）",
      cmp3?.decision === "return" && cmp3?.downgraded_model_merge === true && cmp3?.decidedBy === "engine" && cmp3?.decisionLabel === "退回",
      `decision=${cmp3?.decision} downgraded=${cmp3?.downgraded_model_merge}`
    );
    check("r3 退回原因写的是「草稿没判过卷」，不是含糊一句不合适", (cmp3?.reasons ?? []).some((r) => /没有自己的考卷成绩/.test(String(r))), `reasons=${JSON.stringify(cmp3?.reasons)}`);
    check("r3 结论里没有放行字段：registered=false 且无「通过」写权限", cmp3?.registered === false && cmp3?.canWritePassField === false, "");
    check("r3 对比代理夹带的表外字段被拒收（verdict/registered/note）", ["verdict", "registered", "note"].every((k) => (cmp3?.model?.ignoredFields ?? []).includes(k)), `ignored=${JSON.stringify(cmp3?.model?.ignoredFields)}`);
    check("r3 前置事实成了一张可对账的表（每条都亮明成立与否）", Array.isArray(cmp3?.facts) && cmp3.facts.length >= 9 && cmp3.facts.some((f) => f.ok === false), `facts=${JSON.stringify((cmp3?.facts ?? []).map((f) => [f.fact, f.ok]))}`);
    const files3 = draftFiles("r3-dual");
    check("r3 两份草稿各自落盘（同一项目目录、互不覆盖）", files3.length === 2, `files=${files3.map((f) => path.basename(f)).join(",")}`);
    const disk3 = files3.map((f) => readFileSync(f, "utf8")).join("\n");
    check("r3 草稿文件里写着未注册、不得进判定链", /"registered": false/.test(disk3) && disk3.includes("不得进判定链"), "");
    check(
      "r3 两份草稿各自记录了归属哪一路（proposal.id 与依据）",
      files3.every((f) => {
        const j = JSON.parse(readFileSync(f, "utf8"));
        return ["A", "B"].includes(j?.proposal?.id) && typeof j?.proposal?.basis === "string" && j.proposal.basis.length > 0;
      }),
      ""
    );
    check("r3 报告 Markdown 有双路章节与隔离/差异/结论三块", md3.includes("## 探索区双路") && md3.includes("提示词隔离") && md3.includes("结构差异（确定性代码算的") && md3.includes("对比结论"), "");
    check("r3 报告把「为什么这一节永远没有通过」写在纸上", md3.includes("为什么这一节永远没有「通过」") && md3.includes("对比代理只有降级权"), "");
    check("r3 报告如实标出模型说了合并但被引擎降回退回", md3.includes("被引擎降回退回"), "");
    check("r3 成绩那一栏如实写着无成绩", md3.includes("无（这条草稿还没有考卷成绩）"), `成绩栏=${JSON.stringify((md3.match(/无（[^）]*）/g) ?? []).slice(0, 4))}`);
    check("r3 报告摘要行把双路事实带进结论段", /探索区双路独立提案：A\/B 两路共 2 次实发/.test(md3), "");
    check("r3 探索流量不进证据库：pre 证据条数与单路轮一致", preEvidenceCount("r3-dual") === preEvidenceCount("r2-single"), `pre r2=${preEvidenceCount("r2-single")} r3=${preEvidenceCount("r3-dual")}`);
    check(
      "r3 判定链不受影响（静态发现与实测漏洞数与关闭轮相同）",
      (rep3?.summary?.findings ?? []).length === (rep1?.summary?.findings ?? []).length &&
        vulnerableEvidenceCount("r3-dual") === vulnerableEvidenceCount("r1-off") &&
        vulnerableEvidenceCount("r3-dual") >= 1,
      `findings r1=${rep1?.summary?.findings?.length} r3=${rep3?.summary?.findings?.length}`
    );
    check("r3 判定终态没被双路改动（结论仍来自判卷代码）", rep3?.verdict?.outcome === rep1?.verdict?.outcome, `r1=${rep1?.verdict?.outcome} r3=${rep3?.verdict?.outcome}`);
    const rows3 = exploreRows("r3-dual");
    const sentRows = rows3.filter((r) => String(r.subject).startsWith("request."));
    check(
      "r3 两路的实发都写进审计（真实状态码），收手行各自记下族名（族名在 note，不冒充主体）",
      sentRows.length === 2 &&
        sentRows.every((r) => r.ok === 1 && r.exit_code >= 200 && r.exit_code < 600) &&
        rows3.filter((r) => r.subject === "stop").length === 2 &&
        ["family=read-by-generic-shape", "family=anon-read-by-response"].every((f) => rows3.some((r) => String(r.note) === f)),
      `rows=${JSON.stringify(rows3.map((r) => [r.subject, r.ok, r.exit_code, r.note]))}`
    );
    const evs3 = explorationEventMessages("r3-dual");
    check(
      "r3 对比这一步落进事件留痕（结论由引擎落，DB 事件里看得见）",
      evs3.some((m) => m.includes("探索区双路收手") && m.includes("对比结论=退回") && m.includes("降级权")) &&
        evs3.some((m) => m.includes("对比代理意见：建议合并")),
      `events=${JSON.stringify(evs3.map((m) => m.slice(0, 32)))}`
    );

    // ============ r4 gate：结构性禁用 ============
    console.log("\n[DUAL] 4/7 gate + 三闸全开 → 结构性禁用…");
    before = state.calls;
    state.base = before;
    state.per = {};
    state.comparatorAsked = 0;
    const r4 = await runGate({
      project: wsGate,
      label: "r4-gate",
      env: {
        ...envOn,
        GUARDBUILD_LLM_SCOUT: "",
        GUARDBUILD_LLM_PATCH: "",
        GUARDBUILD_LLM_BOOTSTRAP: "",
        GUARDBUILD_LLM_ATTACKPLAN: "",
        GUARDBUILD_LLM_SELFBOOT: "",
        GUARDBUILD_LLM_CROSSFILE: "",
      },
    });
    const rep4 = readReport("r4-gate");
    check("r4 gate 正常裁决（退出码来自判定链）", [0, 1, 2].includes(r4.code), `code=${r4.code} verdict=${r4.gate?.verdict}`);
    check("r4 gate 0 次模型调用（CI 不调用模型，双路也不）", delta() === 0 && state.comparatorAsked === 0, `calls=${delta()}`);
    check("r4 报告有裁决但无 exploration/dual，stdout 无「探索区」", rep4 != null && rep4.exploration == null && !r4.stdout.includes("探索区"), `report=${rep4 ? "有" : "缺"}`);
    check("r4 gate 没有草稿落盘", draftFiles("r4-gate").length === 0, `files=${draftFiles("r4-gate").length}`);

    // ============ r5 纯黑盒：这一路不进入 ============
    console.log("\n[DUAL] 5/7 黑盒模式 + 三闸全开 → 双路不进入…");
    target = await startTarget();
    before = state.calls;
    state.base = before;
    state.per = {};
    state.comparatorAsked = 0;
    const s5 = await openSession("r5-blackbox", envOn, ["--report", path.join(reportsDir, "r5-blackbox")]);
    sessions.push(s5);
    s5.send({ cmd: "start", project: wsDual, blackboxUrl: `http://127.0.0.1:${target.port}` });
    await s5.wait((v) => v.sessionId, "会话建立", 60_000);
    const sid5 = s5.view.sessionId;
    await s5.wait((v) => v.sessionId === sid5 && SETTLED_STATES.includes(v.state), "r5 终态", 300_000);
    if (CANCELLABLE_STATES.includes(s5.view.state)) {
      s5.send({ cmd: "cancel" });
      await s5.wait((v) => v.sessionId === sid5 && v.state === "aborted", "r5 中止收尾", 60_000).catch(() => {});
    }
    const rep5 = readReport("r5-blackbox");
    check("r5 黑盒轮 0 次模型调用（外部目标不经过这一路）", delta() === 0, `calls=${delta()}`);
    check("r5 视图与报告无 exploration/dual 段", rep5 != null && s5.view.exploration == null && rep5.exploration == null, "");
    check("r5 无探索事件", !s5.events.some((ev) => ev.kind === "exploration"), "");

    // ============ r6 判卷层落了成绩之后：扫描读得到，但自己写不出成绩 ============
    // 成绩记录由 `benchmark-grader.mjs --draft` 产出（那条真通路在 e2e:draft-grade 里演练）。
    // 这一轮只验**读取侧**：所以这里放的是一份「形状与判卷器产出一致」的样例记录，
    // 并且只给 A 那一路放——B 打的是匿名读（`request.anonymous`），那一族今天根本没有考卷（M5 第 199 项）。
    // 单边有成绩时必须仍然落「退回」，这正是这条通路最该有的假绿灯闸门。
    console.log("\n[DUAL] 6/7 判卷层落了成绩之后：扫描只读得到 A 的成绩，B 仍然没考卷 → 依然退回…");
    // 把 r3 那一批草稿整棵复制到 r6 自己的数据目录（草稿键只由「菜单形状 + 模型 + 提议者 + 提示词摘要」决定，
    // 同一个靶子再跑一次键不变，所以判卷层落下的成绩仍然挂得住）。r6 的审计库/报告各走自己的标签目录。
    const srcExplore = path.join(dataDir, "r3-dual", "exploration");
    const hashDirs = existsSync(srcExplore) ? readdirSync(srcExplore).filter((n) => statSync(path.join(srcExplore, n)).isDirectory()) : [];
    mkdirSync(path.join(dataDir, "r6-graded"), { recursive: true });
    if (hashDirs.length) cpSync(srcExplore, path.join(dataDir, "r6-graded", "exploration"), { recursive: true });
    const gradesDir = hashDirs.length ? path.join(dataDir, "r6-graded", "exploration", hashDirs[0], "grades") : null;
    const draftsOnDisk = draftFiles("r6-graded")
      .map((f) => JSON.parse(readFileSync(f, "utf8")))
      .filter((j) => j?.proposal?.id === "A" || j?.proposal?.id === "B");
    const artA = draftsOnDisk.find((j) => j?.proposal?.id === "A");
    const artB = draftsOnDisk.find((j) => j?.proposal?.id === "B");
    check("r6 前置：r3 那两份草稿还在数据目录里（成绩就落在同一批草稿的隔壁目录）", !!gradesDir && !!artA?.draftKey && !!artB?.draftKey, `grades=${gradesDir ?? "无"}`);
    const recipeA = artA?.draft?.recipe ?? null;
    const seeded = writeGradeRecord({
      gradeDir: gradesDir,
      record: {
        gradeVersion: GRADE_VERSION,
        draftKey: artA.draftKey,
        recipeSha256: recipeSha256(recipeA),
        familySlot: "idor-read",
        draftFamily: recipeA?.family ?? null,
        action: "request.as",
        model: artA.model ?? null,
        proposalId: "A",
        runLabel: `sample-${String(artA.draftKey).slice(0, 12)}`,
        overlayDir: ".grader/draft-overlay（样例记录，指向演练外部）",
        overlayProof: { ok: true, seenIn: "vulnerable#1（样例）", envelope: "idor-read.json" },
        caseIdMap: { from: "exp-1", to: "attack-read-foreign" },
        exams: [{ examId: "idor-read--legacy-shop", split: "dev", repeat: 2, pass: true, gates: { hit: "passed", hardened_zero: "passed", clean_control: "passed", consistent: "passed" }, reasons: [] }],
        pass: true,
        whyNot: null,
        gradedAt: Date.now(),
        durationMs: 0,
        registered: false,
        note: "演练样例记录：形状与 scripts/benchmark-grader.mjs --draft 产出的一致，用来验证扫描侧「只读不写成绩」。真判卷见 scripts/e2e-draft-grade.mjs。",
      },
    });
    check("r6 样例成绩落到 grades/ 且四项自校验通过（读得回来才算数）", seeded.ok === true && readGradeRecord({ gradeDir: gradesDir, draftKey: artA.draftKey, recipe: recipeA }).ok === true, `seeded=${JSON.stringify(seeded)}`);
    const gradesBefore = gradeSnapshot(gradesDir);
    const s6 = await interactive("r6-graded", wsDual, envOn);
    const rep6 = readReport("r6-graded");
    const md6 = readMarkdown("r6-graded");
    const d6 = (s6.view.exploration ?? rep6?.exploration ?? {})?.dual ?? null;
    const cmp6 = d6?.comparison ?? null;
    const factOf = (name) => (cmp6?.facts ?? []).find((f) => f.fact === name)?.ok ?? null;
    check("r6 又跑了双路 + 对比代理（5 次出站）", delta() === 5 && d6?.outcome === "ran", `calls=${delta()}`);
    check("r6 A 那一路读到了成绩且是判卷层那条（不是会话自己造的）", factOf("A 有自己的成绩") === true && factOf("A 的成绩显示过卷") === true, `facts=${JSON.stringify((cmp6?.facts ?? []).map((f) => [f.fact, f.ok]))}`);
    check("r6 读来的成绩带着外部实跑标签（runLabel 不是本轮会话名）", (d6?.proposals ?? []).find((p) => p.id === "A")?.grades?.runLabel === `sample-${String(artA.draftKey).slice(0, 12)}`, JSON.stringify((d6?.proposals ?? []).map((p) => [p.id, p.grades?.present, p.grades?.runLabel])));
    check("r6 B 那一路仍然没有成绩（匿名读一族今天没有考卷，见 M5 第 199 项）", factOf("B 有自己的成绩") === false && (cmp6?.reasons ?? []).some((r) => /B 没有自己的考卷成绩/.test(String(r))), `reasons=${JSON.stringify(cmp6?.reasons)}`);
    check("r6 单边过卷造不出绿灯：结论仍是退回，且是引擎自己退的（模型那句合并建议照样被降级）", cmp6?.decision === "return" && cmp6?.decidedBy === "engine" && cmp6?.downgraded_model_merge === true && cmp6?.registered === false, `decision=${cmp6?.decision} decidedBy=${cmp6?.decidedBy} downgraded=${cmp6?.downgraded_model_merge}`);
    check("r6 报告里 A 那栏写着过卷与外部实跑标签、B 那栏如实写着无成绩", md6.includes("过卷（顶替族 `idor-read`") && md6.includes(`sample-${String(artA.draftKey).slice(0, 12)}`) && md6.includes("无（这条草稿还没有考卷成绩）"), `成绩栏=${JSON.stringify((md6.match(/无（[^）]*）/g) ?? []).slice(0, 4))}`);
    check("r6 事件留痕写出「只读判卷器落下的记录，本会话不写成绩」", explorationEventMessages("r6-graded").some((m) => m.includes("草稿考卷成绩") && m.includes("A=过卷")), JSON.stringify(explorationEventMessages("r6-graded").slice(0, 4)));
    check("r6 扫描这一侧没有改成绩：grades/ 逐字节没动", gradeSnapshot(gradesDir) === gradesBefore, `${gradesBefore} → ${gradeSnapshot(gradesDir)}`);

    // ============ 7/7 跨轮安全边界 ============
    console.log("\n[DUAL] 7/7 安全边界与隔离实况…");
    check("每次出站都带 Bearer（密钥只从环境经 Host 传递）", state.authHeaders.length === 13 && state.authHeaders.every((h) => h === `Bearer ${MOCK_KEY}`), `headers=${state.authHeaders.length}`);
    check("请求为 JSON 模式（response_format=json_object, stream=false）", state.responseFormat === "json_object" && state.stream === false, `format=${state.responseFormat} stream=${state.stream}`);
    const allPrompts = state.prompts.join("\n");
    const promptA = promptsFor(state, "A").join("\n");
    const promptB = promptsFor(state, "B").join("\n");
    check("发给模型的观察不含契约内容与身份口令", !allPrompts.includes(SENTINEL) && !/"password"/.test(allPrompts), "");
    check("响应正文里的凭据值进提示词前已被脱敏", !/"(token|password)"\s*:\s*"(?!\*\*\*)/.test(allPrompts), "");
    check("A 一路连响应正文的键都收不到（只有状态码、字节数与错误类别）", promptA.length > 0 && !promptA.includes('"excerpt"') && !promptA.includes('"observe"') && promptA.includes('"shapes"'), "");
    check("B 一路看得见自己那一轮的真实响应摘录", promptB.includes('"excerpt"') && promptB.includes('"observe"') && !promptB.includes('"shapes"'), "");
    check("A 的独有文本没进 B 的提示词（真流量对账）", privateLinesOf(proposerById("A"), PROPOSERS).every((l) => !promptB.includes(l)), `${privateLinesOf(proposerById("A"), PROPOSERS).length} 条`);
    check("B 的独有文本没进 A 的提示词（真流量对账）", privateLinesOf(proposerById("B"), PROPOSERS).every((l) => !promptA.includes(l)), `${privateLinesOf(proposerById("B"), PROPOSERS).length} 条`);
    check("两路的系统提示词各自写死了依据（通用形状 / 靶子真实响应）", state.systems.some((s) => s.includes("通用打法形状")) && state.systems.some((s) => s.includes("靶子实际返回的形状")), "");
    check("两路都被明确告知别的路与它无关", state.systems.some((s) => s.includes("你只看得见自己这一轮的试打记录")), "");
    check("对比代理的系统提示词里写着「不写任何通过/批准/放行」", state.systems.some((s) => s.includes("不写任何「通过/批准/放行」")), "");
    const blobs3 = [JSON.stringify(s3.view), JSON.stringify(s3.events), JSON.stringify(rep3), md3, disk3];
    check("r3 走私内容不进视图/事件/报告/草稿文件", blobs3.every((b) => !b.includes(LEAK)), "");
    check("r3 模型原文（note）不进视图/事件/报告/草稿", blobs3.every((b) => !b.includes(NOTE)), "");
    check("r3 审计表不含走私内容、模型原文与密钥", leakRows("r3-dual", LEAK) === 0 && leakRows("r3-dual", NOTE) === 0 && leakRows("r3-dual", MOCK_KEY) === 0, "");
    check("sidecar/recipes/ 未被写入（注册仍是人工闸门）", recipeSnapshot() === recipesBefore, `before=${recipesBefore.slice(0, 60)}…`);
  } finally {
    for (const s of sessions) await s.close();
    await new Promise((r) => server.close(r));
    if (target) target.child.kill();
  }

  const failed = checks.filter((c) => !c.pass);
  console.log(`\n[DUAL] 断言: ${checks.length - failed.length}/${checks.length} 通过`);
  if (failed.length) {
    for (const f of failed) console.log(`  ✗ ${f.name}`);
    console.log(`演示目录保留供排查: ${demoDir}`);
    process.exit(1);
  }
  rmSync(demoDir, { recursive: true, force: true });
  console.log("[DUAL] 全部通过 ✅");
}

main().catch((e) => {
  console.error(`[DUAL] 演练失败：${e?.message ?? e}`);
  console.error(`演示目录保留供排查: ${demoDir}`);
  process.exit(1);
});
