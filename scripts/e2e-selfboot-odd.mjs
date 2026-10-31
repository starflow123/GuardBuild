#!/usr/bin/env node
/**
 * 换场景自举验收（#184）：以 fixtures/selfboot-odd-shop 驱动 guardbuild-headless，
 * 证明「词表打不中的项目」靠 #182（注册端点/字段名 agent 兜底）+ #183（种子写入观测兜底）
 * 仍能测，且任一层不成立时仍按「测不了」收场，绝不退化成匿名探测或假绿灯。
 *
 * 靶场故意把两条确定性来源全断掉：
 *   - 建号接口 POST /api/huiyuan/add，字段 mail/pwd/nick —— 注册词表 0 候选，契约也没写 register.path；
 *   - 名下写对象 POST /api/xiadan，字段 mingcheng —— 契约没写 register.seed。
 *   另有两个陷阱：POST /api/feedback 回 201 但什么都不落在名下（只有复读归因能识破），
 *   POST /api/mima/reset 长得像写接口但被引擎策略线禁止发建号体（不进菜单，模型看不见就选不到）。
 *
 *   r1 agent 采纳 + 观测造数：/api/huiyuan/add 建号 2 个、/api/xiadan 复读归因成功
 *      → 越权复现（vulnerable_unfixed）；模型夹带的 payload/method/verdict/headers 全部丢弃。
 *   r2 register.agent:false → identity_bootstrap_unavailable，0 次模型调用，无匿名回退。
 *   r3 开了 agent 但没有 DEEPSEEK_API_KEY → llm_unavailable → 同样 exit 2（测不了），0 次调用。
 *   r4 模型只选 /api/feedback（201 却落不下名下对象）→ 两轮纠偏 → identity_bootstrap_failed。
 *   r5 GB_ODD_LEAKY_LIST=1：写入都成功但列表不按归属过滤 → unattributed → no_list_endpoint，
 *      报错说的是实测事实（两个身份看到同一批对象），引擎宁可按「测不了」，
 *      也不把「对象有归属」这个假前提写进越权用例。
 *   r6 gate 冷跑（无缓存）：CI 结构性禁止调用模型 → 0 次调用 + gate_forbids_model_call → exit 2。
 *   r7 gate 复用 r1 已实测验证的缓存：0 次调用、source=cache、照旧复现 → exit 1。
 *
 * 同时校验安全边界：
 *   - 发给模型的菜单只含方法/路径/定义位置/处理函数片段，不含契约私有内容（SENTINEL）、口令、identities；
 *   - 引擎生成的口令（PWD_SHAPE）不落任何产物：report.md / report.json / stdout / stderr / 审计库 / 缓存文件；
 *   - 模型原文（NOTE）与走私内容（LEAK）不进事件流、审计、报告与缓存，只留键名。
 *
 * 用法: node scripts/e2e-selfboot-odd.mjs
 */
import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import path from "node:path";
import readline from "node:readline";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const demoDir = path.join(repoRoot, ".demo-selfboot-odd");
const dataDir = path.join(demoDir, "data");
const reportsDir = path.join(demoDir, "reports");
const fixture = path.join(repoRoot, "fixtures", "selfboot-odd-shop");

function resolveHeadlessBin() {
  if (process.env.GUARDBUILD_HEADLESS_BIN) return process.env.GUARDBUILD_HEADLESS_BIN;
  const name = process.platform === "win32" ? "guardbuild-headless.exe" : "guardbuild-headless";
  const debug = path.join(repoRoot, "src-tauri", "target", "debug", name);
  return existsSync(debug) ? debug : path.join(repoRoot, "src-tauri", "target", "release", name);
}
const exe = resolveHeadlessBin();

const MOCK_KEY = `sk-mock-${randomBytes(16).toString("hex")}`;
// 模型想自己规定「怎么打」时塞进来的内容：绝不允许出现在任何留痕里
const LEAK = "LEAK-SMUGGLED-REGISTER-4c8a";
// 模型原文哨兵：note 不进事件流/审计/报告/缓存
const NOTE = "MODEL-NOTE-SELFBOOT-7f20";
// 契约哨兵：guardbuild.json 的私有内容不该出现在发给模型的菜单里
const SENTINEL = "SENTINEL_ODD_CONTRACT_MUST_NOT_BE_SENT_TO_LLM";

const ADD = "/api/huiyuan/add";
const XIADAN = "/api/xiadan";
const FEEDBACK = "/api/feedback";
const RESET = "/api/mima/reset";

/** 引擎口令形状：Gb + 14 位字母数字 + 2 位数字（identityboot.generateTestPassword） */
const PWD_SHAPE = /Gb[0-9A-Za-z]{14}[2-9][2-9]/g;

const checks = [];
/** mock 服务在 main() 里起，调用计数按「本轮基线之后」算：每轮开始都重置基线（交互轮与 gate 轮都要） */
let mockState = null;
let callBaseline = 0;
const markCalls = () => {
  if (mockState) callBaseline = mockState.calls;
};
const callsDelta = () => (mockState ? mockState.calls - callBaseline : 0);

function check(name, cond, detail = "") {
  checks.push({ name, pass: !!cond });
  console.log(`${cond ? "  ✓" : "  ✗"} ${name}${detail ? ` — ${detail}` : ""}`);
  return !!cond;
}

function git(args, cwd) {
  const r = spawnSync("git", ["-c", "core.longpaths=true", ...args], { cwd, encoding: "utf8" });
  if (r.status !== 0) throw new Error(`git ${args.join(" ")} 失败: ${r.stderr || r.stdout}`);
  return r.stdout;
}

/** 复制靶场 → 改契约 → 提交基线（env 改动必须在提交前，否则工作区不干净） */
function makeWorkspace(name, mutate = null) {
  const ws = path.join(demoDir, name);
  rmSync(ws, { recursive: true, force: true });
  mkdirSync(demoDir, { recursive: true });
  cpSync(fixture, ws, { recursive: true });
  const p = path.join(ws, "guardbuild.json");
  const cfg = JSON.parse(readFileSync(p, "utf8"));
  cfg._note = SENTINEL;
  writeFileSync(p, `${JSON.stringify(cfg, null, 2)}\n`);
  if (mutate) mutate(ws);
  git(["init", "-q"], ws);
  git(["config", "user.email", "gate@guardbuild.local"], ws);
  git(["config", "user.name", "GuardBuild Gate"], ws);
  git(["config", "core.autocrlf", "false"], ws);
  git(["add", "-A"], ws);
  git(["commit", "-qm", `${name} 基线`], ws);
  return ws;
}

function editContract(ws, fn) {
  const p = path.join(ws, "guardbuild.json");
  const cfg = JSON.parse(readFileSync(p, "utf8"));
  fn(cfg);
  writeFileSync(p, `${JSON.stringify(cfg, null, 2)}\n`);
}

const withStartEnv = (ws, env) => editContract(ws, (cfg) => { cfg.start.env = { ...(cfg.start.env ?? {}), ...env }; });
const withAgentOff = (ws) => editContract(ws, (cfg) => { cfg.register = { ...(cfg.register ?? {}), agent: false }; });

/**
 * mock DeepSeek：按引擎菜单里的编号选端点，字段名从菜单附带的处理函数片段里读
 * ——这考的正是「引擎有没有把字段名的唯一可靠来源交给模型」，而不是写死一份答案。
 */
function startMockLlm() {
  return new Promise((resolve) => {
    const state = { mode: "signup", smuggle: false, calls: 0, prompts: [], systems: [], payloads: [] };
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
          /* 下面按空观察处理 */
        }
        const userPrompt = body?.messages?.find((m) => m.role === "user")?.content ?? "";
        state.prompts.push(userPrompt);
        state.systems.push(body?.messages?.find((m) => m.role === "system")?.content ?? "");
        let obs = {};
        try {
          obs = JSON.parse(userPrompt);
        } catch {
          /* 非 JSON 观察：回空 picks */
        }
        const items = Array.isArray(obs.candidates) ? obs.candidates : [];
        const want = state.mode === "decoy" ? FEEDBACK : state.mode === "decline" ? null : ADD;
        const hit = want ? items.find((i) => i.path === want) : undefined;
        const payload = { picks: hit ? [hit.id] : [], templates: {}, note: NOTE };
        if (hit && state.mode !== "decoy") {
          // 字段名只从引擎给的 handler_source 里取，映射到引擎占位符：模型不给任何常量值
          const src = String(hit.handler_source ?? "");
          const fields = [...new Set([...src.matchAll(/req\.body\.([A-Za-z_]\w*)/g)].map((m) => m[1]))];
          const map = {};
          for (const f of fields) {
            if (/^(?:ma?il|e?mail)$/.test(f)) map[f] = "{email}";
            else if (/pwd|passw/i.test(f)) map[f] = "{password}";
            else if (/^(?:nick|nickname|username|user)$/.test(f)) map[f] = "{username}";
          }
          if (Object.values(map).includes("{password}")) payload.templates[String(hit.id)] = map;
        }
        if (state.smuggle) {
          payload.payload = { evil: LEAK };
          payload.method = "DELETE";
          payload.verdict = "vulnerable";
          payload.identity = "alice";
          payload.headers = { "X-Leak": LEAK };
          payload.url = `http://127.0.0.1:9/${LEAK}`;
        }
        state.payloads.push(payload);
        res.statusCode = 200;
        res.setHeader("Content-Type", "application/json");
        res.end(
          JSON.stringify({
            id: `mock-selfboot-${state.calls}`,
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

/** 交互（非 gate）会话：agent 兜底只可能在交互模式调用模型 */
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
        GUARDBUILD_AUTO_CONSENT: "1",
        ...env,
      },
      stdio: ["pipe", "pipe", "pipe"],
    });
    const s = { label, log: "", errText: "", view: null, states: [], events: [], exitCode: null, waiters: [] };
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

function runGate({ project, label, env = {}, dataKey = null, timeoutMs = 300_000 }) {
  return new Promise((resolve, reject) => {
    markCalls();
    const child = spawn(exe, ["--gate", "--project", project, "--report", path.join(reportsDir, label)], {
      cwd: repoRoot,
      env: {
        ...process.env,
        // 缓存按 dataDir 定位：r7 要复用 r1 那一轮的已验证提案，必须落在同一个目录
        GUARDBUILD_DATA_DIR: path.join(dataDir, dataKey ?? label),
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

const readText = (p) => (existsSync(p) ? readFileSync(p, "utf8") : "");
function readReport(label) {
  const p = path.join(reportsDir, label, "report.json");
  try {
    return JSON.parse(readFileSync(p, "utf8"));
  } catch {
    return null;
  }
}
const readMarkdown = (label) => readText(path.join(reportsDir, label, "report.md"));

/** 报告的「身份基础 · 自举」一节（pre 阶段那一份） */
function bootOf(rep) {
  const phases = rep?.summary?.identities?.bootstrap?.byPhase ?? [];
  return phases[0] ?? null;
}

/** 每轮产物 + 该轮独立 dataDir 下的缓存文件与审计库，一起扫哨兵 */
function artifactTexts(label, run) {
  const dir = path.join(reportsDir, label);
  const texts = [
    { name: "report.json", text: readText(path.join(dir, "report.json")) },
    { name: "report.md", text: readText(path.join(dir, "report.md")) },
    { name: "stdout", text: run?.stdout ?? run?.log ?? "" },
    { name: "stderr", text: run?.stderr ?? run?.errText ?? "" },
  ];
  const cacheDir = path.join(dataDir, label, "selfboot");
  if (existsSync(cacheDir)) {
    for (const proj of readdirSync(cacheDir)) {
      const d = path.join(cacheDir, proj);
      for (const f of readdirSync(d)) texts.push({ name: `cache/${f}`, text: readText(path.join(d, f)) });
    }
  }
  const dbFile = path.join(dataDir, label, "guardbuild.db");
  if (existsSync(dbFile)) {
    try {
      const db = new DatabaseSync(dbFile, { readOnly: true });
      try {
        for (const t of db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map((r) => r.name)) {
          texts.push({ name: `db.${t}`, text: JSON.stringify(db.prepare(`SELECT * FROM "${t}" LIMIT 2000`).all()) });
        }
      } finally {
        db.close();
      }
    } catch {
      /* 审计库正被占用时跳过：产物面已够判定 */
    }
  }
  return texts;
}

function scanLeaks(label, run, { sentinels = [LEAK, NOTE, SENTINEL, MOCK_KEY], pwd = true } = {}) {
  const hits = [];
  for (const a of artifactTexts(label, run)) {
    const t = String(a.text ?? "");
    for (const s of sentinels) if (t.includes(s)) hits.push(`${a.name}~${s}`);
    if (pwd) {
      const m = t.match(PWD_SHAPE);
      if (m) hits.push(`${a.name}~口令(${m[0].slice(0, 6)}…)`);
    }
  }
  return hits;
}

/** 事件流里找某类消息（用于断言「引擎确实实跑过」） */
const eventText = (s) => s.events.map((e) => `${e.message ?? ""} ${JSON.stringify(e.data ?? {})}`).join("\n");

async function main() {
  console.log("[ODD] 0/8 准备演示目录…");
  rmSync(demoDir, { recursive: true, force: true });
  mkdirSync(dataDir, { recursive: true });
  mkdirSync(reportsDir, { recursive: true });
  if (!existsSync(exe)) throw new Error(`未找到无头宿主: ${exe}（先 cargo build --no-default-features --bin guardbuild-headless）`);

  const ws1 = makeWorkspace("o1-agent");
  const ws2 = makeWorkspace("o2-agent-off", withAgentOff);
  const ws3 = makeWorkspace("o3-no-key");
  const ws4 = makeWorkspace("o4-decoy");
  const ws5 = makeWorkspace("o5-leaky-list", (ws) => withStartEnv(ws, { GB_ODD_LEAKY_LIST: "1" }));
  const ws6 = makeWorkspace("o6-gate-cold");

  const { server, port: mockPort, state } = await startMockLlm();
  mockState = state;
  const llmEnv = { DEEPSEEK_API_KEY: MOCK_KEY, DEEPSEEK_BASE_URL: `http://127.0.0.1:${mockPort}/v1` };
  const sessions = [];

  async function interactive(label, ws, env = {}, extra = {}) {
    Object.assign(state, { mode: "signup", smuggle: false }, extra);
    markCalls();
    const s = await openSession(label, { ...llmEnv, ...env }, ["--report", path.join(reportsDir, label)]);
    sessions.push(s);
    s.send({ cmd: "start", project: ws });
    await s.wait((v) => v.sessionId, "会话建立", 60_000);
    const sid = s.view.sessionId;
    await s.wait(
      (v) => v.sessionId === sid && ["completed", "error", "patch_review", "writeback_pending", "verify_failed"].includes(v.state),
      `${label} 终态`,
      300_000
    );
    await s.close();
    return s;
  }

  try {
    // ============ r1：词表全落空的异形项目，靠 agent 找端点 + 靠观测造数据 ============
    console.log("\n[ODD] 1/8 agent 采纳 + 观测造数（模型同时夹带越界字段）…");
    const s1 = await interactive("r1", ws1, {}, { smuggle: true });
    const rep1 = readReport("r1");
    const md1 = readMarkdown("r1");
    const boot1 = bootOf(rep1) ?? {};
    const agent1 = boot1.registerAgent ?? {};
    const calls1 = callsDelta();
    const prompt1 = state.prompts.at(-1) ?? "";
    check("r1 会话走到终态并落盘报告", ["error", "completed", "patch_review"].includes(s1.view.state) && !!rep1, `state=${s1.view.state}`);
    check("r1 结论是漏洞已复现（不是「没测到」）", rep1?.verdict?.outcome === "vulnerable_unfixed" || rep1?.error?.code === "no_patchable_candidates", `outcome=${rep1?.verdict?.outcome} code=${rep1?.error?.code}`);
    check("r1 只调用模型 1 次（一次提议即被实跑采纳）", calls1 === 1, `calls=${calls1}`);
    check("r1 注册端点来源＝agent（契约没写、词表也打不中）", boot1.endpoint === ADD && boot1.endpointSource === "agent", `endpoint=${boot1.endpoint}/${boot1.endpointSource}`);
    check("r1 两个身份都由该端点建号（verdict=created / 口令引擎生成）", (boot1.accounts ?? []).filter((a) => a.verdict === "created" && a.endpoint === ADD && a.passwordSource === "engine-generated").length === 2, `accounts=${(boot1.accounts ?? []).map((a) => `${a.name}:${a.verdict}/${a.endpointSource}`).join("、")}`);
    const seeds1 = boot1.seeds ?? [];
    check("r1 名下对象由观测选定（/api/xiadan，source=observed，2 条 written）", seeds1.filter((s) => s.verdict === "written" && s.source === "observed" && s.endpoint === XIADAN).length === 2, `seeds=${seeds1.map((s) => `${s.identity}:${s.endpoint}/${s.verdict}/${s.source}`).join("、") || "无"}`);
    check("r1 观测兜底确实参与（有列表端点、候选含 feedback 与 xiadan）", boot1.seedObservation?.attempted === true && (boot1.seedObservation?.candidates ?? []).includes(XIADAN) && boot1.seedObservation?.listEndpoint === "/api/orders", `obs=${JSON.stringify(boot1.seedObservation ?? null)}`);
    const fb1 = seeds1.find((s) => s.endpoint === FEEDBACK);
    check("r1 陷阱端点 /api/feedback 被复读判掉（201 但落不下名下对象）", !!fb1 && fb1.verdict !== "written" && fb1.source === "observed", `feedback=${JSON.stringify(fb1 ?? null)}`);
    check("r1 采纳轨迹含 adopted（不是只有失败候选）", (agent1.tried ?? []).some((t) => t.endpoint === ADD && t.verdict === "adopted"), `tried=${JSON.stringify(agent1.tried ?? [])}`);
    check("r1 报告 registerAgent：source=model、缓存已标记为实测通过", agent1.source === "model" && agent1.cacheVerified === true && agent1.used === true, `source=${agent1.source} cacheVerified=${agent1.cacheVerified}`);
    check("r1 越权证据打在观测写入的那条对象上（canary 标题可见）", (rep1?.evidence?.pre ?? []).some((e) => e.caseId === "attack-read-foreign" && e.verdict === "vulnerable" && /gbseed-[0-9a-f]{10}/.test(String(e.actual ?? ""))), `pre=${(rep1?.evidence?.pre ?? []).map((e) => `${e.caseId}/${e.verdict}`).join("、")}`);
    check("r1 会话真实性仍经回读验证（自举不豁免 #175）", rep1?.summary?.identities?.sessionVerification?.status === "verified", `status=${rep1?.summary?.identities?.sessionVerification?.status}`);
    check("r1 报告正文写明「端点由兜底代理提议、数据由观测选定」", /兜底代理|实跑采纳/.test(md1) && /观测|复读/.test(md1), `片段=${md1.split("\n").filter((l) => /自举/.test(l)).join(" ⏎ ").slice(0, 220)}`);

    // 边界：菜单内容与模型越界字段
    const menuPaths = [...prompt1.matchAll(/"path":\s*"([^"]+)"/g)].map((m) => m[1]);
    check("r1 发给模型的菜单含三个可选端点", [ADD, XIADAN, FEEDBACK].every((p) => menuPaths.includes(p)), `menu=${menuPaths.join("、")}`);
    check("r1 找回密码接口根本不在菜单里（策略线在引擎侧）", !menuPaths.includes(RESET) && !prompt1.includes(RESET), `menu=${menuPaths.join("、")}`);
    check("r1 菜单带上了处理函数源码片段（字段名的唯一可靠来源）", /handler_source/.test(prompt1) && /req\.body\.mail/.test(prompt1) && /req\.body\.pwd/.test(prompt1), "");
    check("r1 发给模型的观察里没有契约私有内容/身份口令", !prompt1.includes(SENTINEL) && !prompt1.includes(MOCK_KEY) && !new RegExp(PWD_SHAPE.source).test(prompt1), `len=${prompt1.length}`);
    check("r1 越界键全部被丢弃并留痕（载荷/方法/判定/身份/请求头/URL）", ["payload", "method", "verdict", "identity", "headers", "url"].every((k) => (agent1.ignoredKeys ?? []).includes(k)), `ignored=${JSON.stringify(agent1.ignoredKeys ?? [])}`);
    let leak1 = scanLeaks("r1", s1);
    check("r1 走私内容、模型原文、密钥与引擎口令都不落产物/缓存/审计库", leak1.length === 0, leak1.join("、") || "无残留");

    // ============ r2：关掉 agent 就只能诚实说「找不到」 ============
    console.log("\n[ODD] 2/8 register.agent:false：期望 identity_bootstrap_unavailable，且一次模型都不问…");
    const s2 = await interactive("r2", ws2, {});
    const rep2 = readReport("r2");
    check("r2 终态为 error（测不了，不是跑完没漏洞）", s2.view.state === "error" && rep2?.error?.code === "identity_bootstrap_unavailable", `state=${s2.view.state} code=${rep2?.error?.code}`);
    check("r2 结论归类 inconclusive", rep2?.verdict?.outcome === "inconclusive", `outcome=${rep2?.verdict?.outcome}`);
    check("r2 0 次模型调用（契约关了就不问，哪怕环境里有可用密钥）", callsDelta() === 0, `calls=${callsDelta()}`);
    check("r2 hint 指向可执行修法（开 agent 或声明 register.path）", /register\.agent|register\.path/.test(String(rep2?.error?.hint ?? "")), `hint=${String(rep2?.error?.hint ?? "").slice(0, 160)}`);
    check("r2 没有匿名回退：报告不出现「未复现/未发现漏洞」", !/已测未复现|未发现漏洞|not_reproducible/.test(String(rep2?.verdict?.headline ?? "") + String(rep2?.error?.message ?? "")), `headline=${String(rep2?.verdict?.headline ?? "").slice(0, 90)}`);
    check("r2 无口令/哨兵残留", scanLeaks("r2", s2).length === 0, scanLeaks("r2", s2).join("、"));

    // ============ r3：开了 agent 但没有密钥 ============
    console.log("\n[ODD] 3/8 agent 开启但无 DEEPSEEK_API_KEY：期望同样 inconclusive，0 次外发…");
    const s3 = await interactive("r3", ws3, { DEEPSEEK_API_KEY: "" });
    const rep3 = readReport("r3");
    const boot3 = bootOf(rep3) ?? {};
    check("r3 终态 error + identity_bootstrap_unavailable", s3.view.state === "error" && rep3?.error?.code === "identity_bootstrap_unavailable", `state=${s3.view.state} code=${rep3?.error?.code}`);
    check("r3 兜底层记为 llm_unavailable", boot3.registerAgent?.fallback === "llm_unavailable" && boot3.registerAgent?.enabled === true, `agent=${JSON.stringify(boot3.registerAgent ?? null)}`);
    check("r3 0 次真实出站请求（密钥缺失时连 mock 都不碰）", callsDelta() === 0, `calls=${callsDelta()}`);
    check("r3 hint 说清「没密钥就别指望兜底」并仍给确定性修法", /DEEPSEEK_API_KEY|register\.path/.test(String(rep3?.error?.hint ?? "")), `hint=${String(rep3?.error?.hint ?? "").slice(0, 160)}`);

    // ============ r4：模型只选陷阱端点 ============
    console.log("\n[ODD] 4/8 模型只选 /api/feedback：两轮实跑不中 → identity_bootstrap_failed…");
    const s4 = await interactive("r4", ws4, {}, { mode: "decoy" });
    const rep4 = readReport("r4");
    const boot4 = bootOf(rep4) ?? {};
    check("r4 终态 error + identity_bootstrap_failed（找到了端点但换不来会话）", s4.view.state === "error" && rep4?.error?.code === "identity_bootstrap_failed", `state=${s4.view.state} code=${rep4?.error?.code}`);
    check("r4 两轮都问过模型（纠偏轮带上了上一轮实测结果）", callsDelta() === 2 && (boot4.registerAgent?.rounds ?? 0) === 2, `calls=${callsDelta()} rounds=${boot4.registerAgent?.rounds}`);
    const tried4 = boot4.registerAgent?.tried ?? [];
    check("r4 轨迹记录 /api/feedback 未被采纳", tried4.length > 0 && tried4.every((t) => t.endpoint === FEEDBACK) && !tried4.some((t) => t.verdict === "adopted"), `tried=${JSON.stringify(tried4)}`);
    const prompt4 = state.prompts.at(-1) ?? "";
    check("r4 第 2 轮观察含上一轮实跑证据（prior_attempts）", /prior_attempts/.test(prompt4) && prompt4.includes(FEEDBACK), `len=${prompt4.length}`);
    check("r4 结论仍归 inconclusive，没有冒充「已测未复现」", rep4?.verdict?.outcome === "inconclusive" && !/未复现/.test(String(rep4?.verdict?.headline ?? "")), `outcome=${rep4?.verdict?.outcome}`);

    // ============ r5：列表不按归属过滤 → 观测归因必须判掉，且如实说「实测未按归属过滤」 ============
    console.log("\n[ODD] 5/8 GB_ODD_LEAKY_LIST=1：写入成功但归不了属 → no_list_endpoint（测不了，不是没漏洞）…");
    const s5 = await interactive("r5", ws5, {});
    const rep5 = readReport("r5");
    const boot5 = bootOf(rep5) ?? {};
    check("r5 终态 error + no_list_endpoint（不是 exit 0 的「没漏洞」）", s5.view.state === "error" && rep5?.error?.code === "no_list_endpoint", `state=${s5.view.state} code=${rep5?.error?.code}`);
    check("r5 报错写的是实测事实（同一批对象），不是「静态找不到列表」", /未按归属过滤|同一批对象/.test(String(rep5?.error?.message ?? "")), `message=${String(rep5?.error?.message ?? "").slice(0, 160)}`);
    check("r5 归类 inconclusive", rep5?.verdict?.outcome === "inconclusive", `outcome=${rep5?.verdict?.outcome}`);
    check("r5 端点仍由 agent 采纳（身份建得起来，问题只在数据归属）", boot5.endpoint === ADD && (boot5.accounts ?? []).filter((a) => a.verdict === "created").length === 2, `endpoint=${boot5.endpoint} accounts=${(boot5.accounts ?? []).length}`);
    const seeds5 = boot5.seeds ?? [];
    check("r5 观测写入被判定 unattributed（一条都没算成 written）", seeds5.length > 0 && seeds5.every((s) => s.source === "observed") && !seeds5.some((s) => s.verdict === "written"), `seeds=${seeds5.map((s) => `${s.endpoint}/${s.verdict}`).join("、") || "无"}`);
    check("r5 报告与 hint 写明「归不了属的写入不当作名下对象」", /未通过复读归因|unattributed/.test(readMarkdown("r5")) && /归属|listEndpoint/.test(String(rep5?.error?.hint ?? "")), `hint=${String(rep5?.error?.hint ?? "").slice(0, 200)} ⏎ md片段=${readMarkdown("r5").split("\n").filter((l) => /观测|归属/.test(l)).join(" ⏎ ").slice(0, 200)}`);
    check("r5 没有把越权用例说成通过", !(rep5?.evidence?.pre ?? []).some((e) => String(e.caseId ?? "").startsWith("attack-") && e.verdict === "passed"), `pre=${(rep5?.evidence?.pre ?? []).map((e) => `${e.caseId}/${e.verdict}`).join("、") || "空"}`);

    // ============ r6：gate 冷跑（CI 结构性禁止调用模型） ============
    console.log("\n[ODD] 6/8 gate 冷跑（无缓存）：0 次模型调用 + exit 2…");
    const r6 = await runGate({ project: ws6, label: "r6" });
    const rep6 = readReport("r6");
    const boot6 = bootOf(rep6) ?? {};
    check("r6 退出码 = 2（测不了就是不放行）", r6.code === 2, `code=${r6.code} verdict=${r6.gate?.verdict}`);
    check("r6 verdict=inconclusive + identity_bootstrap_unavailable", r6.gate?.verdict === "inconclusive" && rep6?.error?.code === "identity_bootstrap_unavailable", `verdict=${r6.gate?.verdict} code=${rep6?.error?.code}`);
    check("r6 0 次模型调用（CI 不出站）", callsDelta() === 0, `calls=${callsDelta()}`);
    check("r6 记的是结构性禁止，不是「模型没选好」", boot6.registerAgent?.fallback === "gate_forbids_model_call" && boot6.registerAgent?.used === false, `agent=${JSON.stringify(boot6.registerAgent ?? null)}`);

    // ============ r7：gate 复用 r1 已实测验证的缓存 ============
    console.log("\n[ODD] 7/8 gate 复用已验证缓存（同一工作区）：0 次调用 + 照旧复现 → exit 1…");
    const r7 = await runGate({ project: ws1, label: "r7", dataKey: "r1" });
    const rep7 = readReport("r7");
    const boot7 = bootOf(rep7) ?? {};
    check("r7 退出码 = 1（漏洞证据成立）", r7.code === 1, `code=${r7.code} verdict=${r7.gate?.verdict} err=${r7.gate?.error?.code}`);
    check("r7 verdict=vulnerable_unfixed", r7.gate?.verdict === "vulnerable_unfixed", `verdict=${r7.gate?.verdict}`);
    check("r7 0 次模型调用：注册端点来自磁盘缓存", callsDelta() === 0 && boot7.registerAgent?.source === "cache" && boot7.registerAgent?.cacheHit === true, `calls=${callsDelta()} source=${boot7.registerAgent?.source} hit=${boot7.registerAgent?.cacheHit}`);
    check("r7 复用的仍是实跑验证过的那条提案（端点一致）", boot7.endpoint === ADD && boot7.endpointSource === "agent", `endpoint=${boot7.endpoint}/${boot7.endpointSource}`);
    check("r7 观测兜底在 gate 里照旧生效（2 条 written / source=observed）", (boot7.seeds ?? []).filter((s) => s.verdict === "written" && s.source === "observed").length === 2, `seeds=${(boot7.seeds ?? []).map((s) => `${s.endpoint}/${s.verdict}`).join("、")}`);
    check("r7 越权复现证据齐（攻击打在引擎现造的号 + 观测造的对象上）", (rep7?.evidence?.pre ?? []).some((e) => e.caseId === "attack-read-foreign" && e.verdict === "vulnerable"), `pre=${(rep7?.evidence?.pre ?? []).map((e) => `${e.caseId}/${e.verdict}`).join("、")}`);

    // 全轮哨兵复扫（r3/r4/r5 的产物在各自检查里只看了局部，这里统一收口）
    console.log("\n[ODD] 8/8 全轮产物哨兵复扫…");
    const allLeaks = [
      ...scanLeaks("r3", s3),
      ...scanLeaks("r4", s4),
      ...scanLeaks("r5", s5),
      ...scanLeaks("r6", r6),
      ...scanLeaks("r7", r7),
    ];
    check("每一轮的口令/模型原文/走私内容/契约哨兵都不落产物、缓存与审计库", allLeaks.length === 0, allLeaks.join("、") || "无残留");

    const passed = checks.filter((c) => c.pass).length;
    console.log(`\n[ODD] 断言: ${passed}/${checks.length} 通过`);
    const failed = checks.filter((c) => !c.pass);
    if (failed.length > 0) {
      console.error(`[ODD] 未通过: ${failed.map((c) => c.name).join("、")}`);
      process.exit(1);
    }
    console.log("[ODD] 全部通过 ✅");
  } finally {
    for (const s of sessions) {
      try {
        await s.close();
      } catch {
        /* 已退出 */
      }
    }
    server.close();
  }
}

main().catch((e) => {
  console.error(`\n[ODD] 失败: ${e.message}`);
  const passed = checks.filter((c) => c.pass).length;
  console.log(`[ODD] 断言: ${passed}/${checks.length} 通过`);
  process.exit(1);
});
