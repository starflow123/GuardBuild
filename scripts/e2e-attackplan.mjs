#!/usr/bin/env node
/**
 * M2（证据约束下的攻击规划）端到端演练：本机回环 mock DeepSeek + 靶场 fixtures/queue-shop。
 *
 * 靶场把两条真漏洞排在探测预算之外（每类探测只打前 14 条路由）：
 *   /api/queue-01…18 在前（详情有归属校验，跨用户读取被拒）；
 *   /api/contracts 第 19 条（详情缺归属校验）、/api/audit 第 20 条（q 参数字符串拼接）。
 * 于是「打不打得到」只取决于探测预算有没有被重排——这正是规划代理要证明的事。
 *
 *   r1 默认关闭（即使带着可用的模型环境）：0 次 LLM 调用、attackPlan=null、
 *      contracts/audit 都未被探测 → 0 finding（诚实漏报，不是「目标安全」）。
 *   r2 开启 + 两轮：第 1 轮挑 /api/contracts（读类预算）、第 2 轮按第 1 轮实测证据挑 /api/audit
 *      → 两条 finding 都出现，finding 仍由引擎实测判定。
 *   r3 只开 1 轮：只有 contracts 进预算 → IDOR 出现、SQLi 不出现（轮次归因）。
 *   r4 走私字段：模型自带 payload/method/verdict/identity/headers → 全部丢弃并留痕；
 *      finding 集合与 r2 一致，走私内容不进入视图/事件/审计/报告/DB。
 *   r5 编号全非法：choice_rejected → 回退引擎原序，结果与 r1 一致，审计记 ok=false。
 *   r6 gate + 契约启用 + 环境变量启用：结构性禁用（0 次 LLM 调用，attackPlan=null）。
 *
 * 同时校验：发给模型的观察只含路由自身线索（不含 identities/密码/契约内容/令牌）；
 * 模型原文（note）不进入任何留痕；每个规划轮次写 agent_actions(action=attack_plan)。
 *
 * 用法: node scripts/e2e-attackplan.mjs
 */
import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";
import readline from "node:readline";
import { fileURLToPath } from "node:url";
import { openAuditDb, queryAudit } from "./lib/auditdb.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const demoDir = path.join(repoRoot, ".demo-attackplan");
const dataDir = path.join(demoDir, "data");
const reportsDir = path.join(demoDir, "reports");
const fixture = path.join(repoRoot, "fixtures", "queue-shop");

function resolveHeadlessBin() {
  if (process.env.GUARDBUILD_HEADLESS_BIN) return process.env.GUARDBUILD_HEADLESS_BIN;
  const name = process.platform === "win32" ? "guardbuild-headless.exe" : "guardbuild-headless";
  const debug = path.join(repoRoot, "src-tauri", "target", "debug", name);
  return existsSync(debug) ? debug : path.join(repoRoot, "src-tauri", "target", "release", name);
}
const exe = resolveHeadlessBin();

const MOCK_KEY = `sk-mock-${randomBytes(16).toString("hex")}`;
// 模型想自己规定「怎么打」时塞进去的内容：绝不允许出现在任何留痕里
const LEAK = "LEAK-SMUGGLED-ATTACK-3b7e";
// 模型原文哨兵：note 不进视图/事件/审计/报告/DB
const NOTE = "MODEL-NOTE-ATTACK-PLAN-9d14";
// 契约哨兵：guardbuild.json 的私有内容不该出现在发给模型的观察里
const SENTINEL = "SENTINEL_QUEUE_CONTRACT_MUST_NOT_BE_SENT_TO_LLM";

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

/** 复制靶场到工作区并写入本轮的攻击规划契约（规划开关只影响引擎行为，不改靶场数据） */
function makeWorkspace(name, { attackPlan = null, sentinel = true } = {}) {
  const ws = path.join(demoDir, name);
  rmSync(ws, { recursive: true, force: true });
  cpSync(fixture, ws, { recursive: true });
  const cfgPath = path.join(ws, "guardbuild.json");
  const cfg = JSON.parse(readFileSync(cfgPath, "utf8"));
  if (attackPlan) cfg.blackbox.attackPlan = attackPlan;
  if (sentinel) cfg._note = SENTINEL;
  writeFileSync(cfgPath, `${JSON.stringify(cfg, null, 2)}\n`);
  git(["init", "-q"], ws);
  git(["config", "user.email", "gate@guardbuild.local"], ws);
  git(["config", "user.name", "GuardBuild Gate"], ws);
  git(["config", "core.autocrlf", "false"], ws);
  git(["add", "-A"], ws);
  git(["commit", "-qm", `${name} 基线`], ws);
  return ws;
}

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
      const m = out.replace(/\x1b\[[0-9;]*m/g, "").match(/listening on port\s+(\d+)/);
      if (m) {
        clearTimeout(timer);
        child.stdout.off("data", onData);
        resolve({ child, port: Number(m[1]), dir });
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
 * mock DeepSeek chat completions：按「本轮观察里的菜单」选路由编号，而不是写死编号，
 * 这样断言的是「模型能读懂引擎的菜单」，而不是一份脆弱的固定脚本。
 */
function startMockLlm() {
  return new Promise((resolve) => {
    const state = {
      mode: "auto", // auto | invalid
      smuggle: false,
      calls: 0,
      prompts: [],
      systems: [],
      authHeaders: [],
      responseFormat: null,
      stream: null,
      payloads: [],
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
          /* 下面按空观察处理 */
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
          /* 非 JSON 观察：回空选择 */
        }
        let payload;
        if (state.mode === "invalid") {
          payload = { picks: [999], note: NOTE };
        } else {
          const items = Array.isArray(obs.unprobed_routes) ? obs.unprobed_routes : [];
          const want = obs.round === 1 ? "/api/contracts" : "/api/audit";
          const hit = items.find((i) => i.path === want);
          payload = { picks: hit ? [hit.id] : [], note: NOTE };
        }
        if (state.smuggle) {
          payload.payload = `' OR 1=1-- ${LEAK}`;
          payload.method = "POST";
          payload.verdict = "vulnerable";
          payload.identity = "alice";
          payload.headers = { "X-Leak": LEAK };
          payload.expectation = "mock: 想直接下结论";
        }
        state.payloads.push(payload);
        res.statusCode = 200;
        res.setHeader("Content-Type", "application/json");
        res.end(
          JSON.stringify({
            id: `mock-plan-${state.calls}`,
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

/** 交互（非 gate）会话：规划代理只在交互模式启用 */
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

function runGate({ url, project, label, env = {}, timeoutMs = 300_000 }) {
  return new Promise((resolve, reject) => {
    const child = spawn(exe, ["--url", url, "--project", project, "--gate", "--report", path.join(reportsDir, label)], {
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

function vulnerableIds(report) {
  return new Set((report?.evidence?.blackbox ?? []).filter((e) => e.verdict === "vulnerable").map((e) => e.caseId));
}

function hasPrefix(set, prefix) {
  return [...set].some((id) => String(id ?? "").startsWith(prefix));
}

function agentActions(label) {
  return queryAudit(
    path.join(dataDir, label, "guardbuild.db"),
    "SELECT step, action, subject, ok, note FROM agent_actions WHERE action = 'attack_plan' ORDER BY created_at",
    [],
    { label: `${label}:attack_plan` }
  );
}

function snapshot(dir) {
  const out = {};
  const walk = (d) => {
    for (const name of readdirSync(d)) {
      const p = path.join(d, name);
      const st = statSync(p);
      if (st.isDirectory()) {
        if (name === "node_modules" || name === ".git") continue;
        walk(p);
      } else out[path.relative(dir, p)] = st.size;
    }
  };
  walk(dir);
  return out;
}

const CONTRACTS_PREFIX = "blackbox-idor-api-contracts-";
const AUDIT_PREFIX = "blackbox-sqli-or-api-audit-q";

async function main() {
  console.log("[PLAN] 0/7 准备靶场与工作区…");
  rmSync(demoDir, { recursive: true, force: true });
  mkdirSync(dataDir, { recursive: true });
  if (!existsSync(exe)) throw new Error(`未找到无头宿主: ${exe}（先 cargo build --no-default-features --bin guardbuild-headless）`);

  const target = await startTarget();
  const url = `http://127.0.0.1:${target.port}`;
  const before = snapshot(target.dir);

  const wsOff = makeWorkspace("ws-off");
  const wsTwo = makeWorkspace("ws-two", { attackPlan: { enabled: true, rounds: 2, maxPicks: 4 } });
  const wsOne = makeWorkspace("ws-one", { attackPlan: { enabled: true, rounds: 1 } });
  const wsSmuggle = makeWorkspace("ws-smuggle", { attackPlan: { enabled: true, rounds: 2 } });
  const wsReject = makeWorkspace("ws-reject", { attackPlan: { enabled: true, rounds: 1 } });
  const wsGate = makeWorkspace("ws-gate", { attackPlan: { enabled: true } });

  const { server, port: mockPort, state } = await startMockLlm();
  const llmEnv = { DEEPSEEK_API_KEY: MOCK_KEY, DEEPSEEK_BASE_URL: `http://127.0.0.1:${mockPort}/v1` };

  const sessions = [];
  let callsBefore = 0;
  const callsDelta = () => state.calls - callsBefore;

  async function interactive(label, ws, env, extra = {}) {
    Object.assign(state, { mode: "auto", smuggle: false }, extra);
    callsBefore = state.calls;
    const s = await openSession(label, { ...llmEnv, ...env }, ["--report", path.join(reportsDir, label)]);
    sessions.push(s);
    s.send({ cmd: "start", project: ws, blackboxUrl: url });
    await s.wait((v) => v.sessionId, "会话建立", 60_000);
    const sid = s.view.sessionId;
    await s.wait((v) => v.sessionId === sid && ["completed", "error"].includes(v.state), `${label} 终态`, 300_000);
    return s;
  }

  try {
    // ============ r1：默认关闭 ============
    console.log("\n[PLAN] 1/7 默认关闭（带着可用的模型环境也不该被问）…");
    const s1 = await interactive("r1-off", wsOff, {});
    const rep1 = readReport("r1-off");
    const md1 = readMarkdown("r1-off");
    const b1 = s1.view.blackbox ?? {};
    const ids1 = vulnerableIds(rep1);
    check("r1 会话正常完成（不是执行出错）", s1.view.state === "completed" && b1.outcome === "no_findings", `state=${s1.view.state} outcome=${b1.outcome}`);
    check("r1 0 次 LLM 调用（默认关闭，不因环境里有密钥就外发）", callsDelta() === 0, `calls=${callsDelta()}`);
    check("r1 视图 attackPlan=null", b1.attackPlan === null, `attackPlan=${JSON.stringify(b1.attackPlan)}`);
    check("r1 两条高价值路由「已发现但未被探测」", b1.routeCount >= 20 && (b1.routes ?? []).some((r) => r.path === "/api/contracts") && (b1.routes ?? []).some((r) => r.path === "/api/audit"), `routes=${b1.routeCount} probeCap=${b1.probeCap}`);
    check("r1 未命中 contracts（预算外）", !hasPrefix(ids1, CONTRACTS_PREFIX), `vulnerable=${[...ids1].join(", ") || "（空）"}`);
    check("r1 未命中 audit（预算外）", !hasPrefix(ids1, AUDIT_PREFIX));
    check("r1 报告为 no_findings 且披露预算截断", rep1?.verdict?.outcome === "no_findings" && md1.includes("预算外的路由本轮未被打"), `outcome=${rep1?.verdict?.outcome}`);

    // ============ r2：两轮规划 ============
    console.log("\n[PLAN] 2/7 开启两轮：第 1 轮挑合同、第 2 轮按实测证据挑审计…");
    const s2 = await interactive("r2-two", wsTwo, { GUARDBUILD_LLM_ATTACKPLAN: "1" });
    const rep2 = readReport("r2-two");
    const md2 = readMarkdown("r2-two");
    const b2 = s2.view.blackbox ?? {};
    const plan2 = b2.attackPlan ?? {};
    const ids2 = vulnerableIds(rep2);
    check("r2 两次规划调用（两轮各一次）", plan2.llmCalls === 2 && callsDelta() === 2, `llmCalls=${plan2.llmCalls} calls=${callsDelta()}`);
    check(
      "r2 第 1 轮把 /api/contracts 提进预算、第 2 轮把 /api/audit 提进预算",
      plan2.rounds?.[0]?.picks?.[0]?.path === "/api/contracts" && plan2.rounds?.[1]?.picks?.[0]?.path === "/api/audit",
      `rounds=${JSON.stringify((plan2.rounds ?? []).map((r) => (r.picks ?? []).map((p) => p.path)))}`
    );
    check("r2 复现合同越权（IDOR，实测证据）", hasPrefix(ids2, CONTRACTS_PREFIX), `vulnerable=${[...ids2].sort().join(", ") || "（空）"}`);
    check("r2 复现审计日志注入（SQLi，实测证据）", hasPrefix(ids2, AUDIT_PREFIX));
    check("r2 会话终态为有漏洞（不是模型自评）", s2.view.state === "completed" && b2.outcome === "vulnerable_unfixed" && b2.exitCode === 1, `state=${s2.view.state} outcome=${b2.outcome}`);
    const audit2 = agentActions("r2-two");
    check("r2 两个规划轮次都写审计（action=attack_plan, ok=1）", audit2.length === 2 && audit2.every((r) => r.ok === 1), `rows=${JSON.stringify(audit2.map((r) => [r.step, r.ok]))}`);
    check(
      "r2 审计主体写的是引擎路由路径（不是模型原文）",
      audit2.some((r) => String(r.subject).includes("/api/contracts")) && audit2.some((r) => String(r.subject).includes("/api/audit")) && !JSON.stringify(audit2).includes(NOTE),
      `subjects=${JSON.stringify(audit2.map((r) => r.subject))}`
    );
    check("r2 报告 JSON 记录规划轮次与采纳的路由", rep2?.summary?.blackbox?.attackPlan?.rounds?.length === 2 && (rep2?.summary?.blackbox?.attackPlan?.appliedPicks ?? []).length === 2);
    check(
      "r2 报告 Markdown 呈现规划章节与「非模型自评」口径",
      md2.includes("攻击规划代理") && md2.includes("非模型自评") && md2.includes("/api/contracts") && md2.includes("/api/audit"),
      ""
    );
    check(
      "r2 第 2 轮观察里带上一轮实测证据（不是空白重问）",
      state.prompts.some((p) => p.includes("prior_evidence") && p.includes("blackbox-")),
      ""
    );

    // ============ r3：只开 1 轮 ============
    console.log("\n[PLAN] 3/7 只开 1 轮：合同被提进预算，审计没有（轮次归因）…");
    const s3 = await interactive("r3-one", wsOne, { GUARDBUILD_LLM_ATTACKPLAN: "1" });
    const rep3 = readReport("r3-one");
    const plan3 = s3.view.blackbox?.attackPlan ?? {};
    const ids3 = vulnerableIds(rep3);
    check("r3 只有 1 次规划调用", plan3.llmCalls === 1 && callsDelta() === 1, `llmCalls=${plan3.llmCalls} calls=${callsDelta()}`);
    check("r3 合同越权出现", hasPrefix(ids3, CONTRACTS_PREFIX), `vulnerable=${[...ids3].sort().join(", ") || "（空）"}`);
    check("r3 审计注入未出现（第 2 轮没有机会把 audit 排进预算）", !hasPrefix(ids3, AUDIT_PREFIX));

    // ============ r4：走私字段 ============
    console.log("\n[PLAN] 4/7 模型走私 payload/method/verdict/identity/headers → 全部丢弃并留痕…");
    const s4 = await interactive("r4-smuggle", wsSmuggle, { GUARDBUILD_LLM_ATTACKPLAN: "1" }, { smuggle: true });
    const rep4 = readReport("r4-smuggle");
    const md4 = readMarkdown("r4-smuggle");
    const plan4 = s4.view.blackbox?.attackPlan ?? {};
    const ids4 = vulnerableIds(rep4);
    const sameSet = JSON.stringify([...ids2].sort()) === JSON.stringify([...ids4].sort());
    check(
      "r4 走私字段被丢弃并逐项留痕",
      ["payload", "method", "verdict", "identity", "headers", "expectation"].every((k) => (plan4.ignoredFields ?? []).includes(k)),
      `ignoredFields=${JSON.stringify(plan4.ignoredFields)}`
    );
    check("r4 finding 集合与 r2 完全一致（攻击内容仍由引擎生成）", sameSet, `r2=${[...ids2].sort().join(",")} | r4=${[...ids4].sort().join(",")}`);
    check("r4 走私内容不进入视图/事件/报告/Markdown", [JSON.stringify(s4.view), JSON.stringify(s4.events), JSON.stringify(rep4), md4].every((blob) => !blob.includes(LEAK)), "");
    check("r4 模型原文（note）不进入视图/事件/报告", [JSON.stringify(s4.view), JSON.stringify(s4.events), JSON.stringify(rep4), md4].every((blob) => !blob.includes(NOTE)), "");

    // ============ r5：编号全非法 ============
    console.log("\n[PLAN] 5/7 编号全非法 → choice_rejected + 回退引擎原序…");
    const s5 = await interactive("r5-reject", wsReject, { GUARDBUILD_LLM_ATTACKPLAN: "1" }, { mode: "invalid" });
    const rep5 = readReport("r5-reject");
    const md5 = readMarkdown("r5-reject");
    const plan5 = s5.view.blackbox?.attackPlan ?? {};
    const ids5 = vulnerableIds(rep5);
    check("r5 第 1 轮回退为 choice_rejected", plan5.rounds?.[0]?.fallback === "choice_rejected", `rounds=${JSON.stringify((plan5.rounds ?? []).map((r) => r.fallback))}`);
    check("r5 拒绝原因给的是可选编号（不是模型原文）", /可用编号/.test(String(plan5.rounds?.[0]?.rejected ?? "")) && !JSON.stringify(plan5).includes(NOTE), `rejected=${String(plan5.rounds?.[0]?.rejected ?? "").slice(0, 60)}`);
    check("r5 回退后结果与 r1 一致（两条高价值路由都没被打）", !hasPrefix(ids5, CONTRACTS_PREFIX) && !hasPrefix(ids5, AUDIT_PREFIX), `vulnerable=${[...ids5].sort().join(", ") || "（空）"}`);
    check("r5 报告披露未采纳原因", md5.includes("choice_rejected"), "");
    const audit5 = agentActions("r5-reject");
    check("r5 审计记 ok=0（回退不是成功）", audit5.length === 1 && audit5[0].ok === 0, `rows=${JSON.stringify(audit5.map((r) => [r.step, r.ok]))}`);

    // ============ r6：gate 结构性禁用 ============
    console.log("\n[PLAN] 6/7 gate + 契约启用 + 环境变量启用 → 结构性禁用…");
    callsBefore = state.calls;
    const r6 = await runGate({ url, project: wsGate, label: "r6-gate", env: { ...llmEnv, GUARDBUILD_LLM_ATTACKPLAN: "1" } });
    const rep6 = readReport("r6-gate");
    check("r6 gate 退出码 0（无 finding）", r6.code === 0 && r6.gate?.verdict === "no_findings", `code=${r6.code} verdict=${r6.gate?.verdict}`);
    check("r6 gate 0 次 LLM 调用", callsDelta() === 0, `calls=${callsDelta()}`);
    check("r6 视图/报告 attackPlan=null", rep6?.blackbox === null || rep6?.blackbox?.attackPlan == null, `report.attackPlan=${JSON.stringify(rep6?.blackbox?.attackPlan)}`);
    check(
      "r6 全程没有规划活动（无 attackplan 事件、无规划提示）",
      !r6.stdout.includes("攻击规划") && !/"kind":\s*"attackplan"/.test(r6.stdout),
      ""
    );

    // ============ 7/7 跨轮安全边界 ============
    console.log("\n[PLAN] 7/7 安全边界…");
    check("每次 LLM 请求都带 Bearer 鉴权（密钥经 Host 传递）", state.authHeaders.length >= 6 && state.authHeaders.every((h) => h === `Bearer ${MOCK_KEY}`), `headers=${state.authHeaders.length}`);
    check("请求为 JSON 模式（response_format=json_object, stream=false）", state.responseFormat === "json_object" && state.stream === false, `response_format=${state.responseFormat}`);
    const prompts = state.prompts.join("\n");
    check("发给模型的观察不含身份与密码", !prompts.includes("alice123") && !prompts.includes("bob123") && !prompts.includes("carol123") && !prompts.includes("identities"), "");
    check("发给模型的观察不含契约内容（哨兵未发送）", !prompts.includes(SENTINEL));
    check("系统提示词把边界写死（只报编号 / 不判定漏洞 / 不指定请求内容）", (state.systems[0] ?? "").includes("只能从给出的 unprobed_routes 里挑编号") && (state.systems[0] ?? "").includes("你不判定漏洞") && (state.systems[0] ?? "").includes("载荷"), "");
    const db = openAuditDb(path.join(dataDir, "r4-smuggle", "guardbuild.db"), { label: "attack-plan 边界" });
    let leakRows = 0;
    let keyRows = 0;
    try {
      leakRows = db.prepare("SELECT COUNT(*) n FROM events WHERE data_json LIKE ? OR message LIKE ?").get(`%${LEAK}%`, `%${LEAK}%`).n;
      keyRows = db.prepare("SELECT COUNT(*) n FROM events WHERE data_json LIKE ? OR message LIKE ?").get(`%${MOCK_KEY}%`, `%${MOCK_KEY}%`).n;
    } finally {
      db.close();
    }
    check("事件库不含走私内容与密钥", leakRows === 0 && keyRows === 0, `leak=${leakRows} key=${keyRows}`);
    check("靶场未被修改（黑盒只发请求）", JSON.stringify(snapshot(target.dir)) === JSON.stringify(before));
  } finally {
    for (const s of sessions) await s.close();
    await new Promise((r) => server.close(r));
    target.child.kill();
  }

  const failed = checks.filter((c) => !c.pass);
  console.log(`\n[PLAN] 断言: ${checks.length - failed.length}/${checks.length} 通过`);
  if (failed.length) {
    for (const f of failed) console.log(`  ✗ ${f.name}`);
    console.log(`演示目录保留供排查: ${demoDir}`);
    process.exit(1);
  }
  rmSync(demoDir, { recursive: true, force: true });
  console.log("[PLAN] 全部通过 ✅");
}

main().catch((e) => {
  console.error(`[PLAN] 演练失败：${e?.message ?? e}`);
  console.error(`演示目录保留供排查: ${demoDir}`);
  process.exit(1);
});
