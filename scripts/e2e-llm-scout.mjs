#!/usr/bin/env node
/**
 * LLM 接入侦察端到端演练：以本机回环 mock DeepSeek 驱动 guardbuild-headless --gate，
 * 验证未知框架目标能否被「侦察 → 实际启动/登录验证 → 动态复现 → 人工修复裁决」闭环：
 *
 *   靶场 fixtures/llm-scout-shop 为自定义路由表（静态适配器认不出），guardbuild.json
 *   不含 start / login / routes，只声明 identities 与 llm.enabled=true。
 *
 *   期望结局：exit 1（verdict=vulnerable_unfixed，error=no_patchable_candidates）
 *   —— 攻击（越权读 + 越权取消）已复现，但 LLM 路由线索只用于定位探测目标，
 *      不参与自动改码，必须人工修复。
 *
 * 第二轮 r2 关闭 mock 且不提供密钥：验证侦察契约从磁盘缓存复用，
 * 仍会实际启动/登录验证，报告与视图标记 cacheSource=disk。
 * r1 的 mock 返回两个启动候选（首选 node server.js 是合理但错误的猜测，
 * 靶场里只有 boot.mjs）：引擎按序真实启动，首个候选失败后自动切换第二个；
 * r2 从缓存复用时应把上次实际验证通过的候选提到最前，只尝试一次。
 *
 * 同时校验安全边界：
 *   - 侦察请求经 Host 出站，带 Bearer 鉴权；密钥只从环境变量读取；
 *   - 发送给 LLM 的证据不含 identities / 密码 / 任何密钥；
 *   - 密钥真实值不出现在报告、事件流、stderr 与缓存文件。
 *
 * 用法: node scripts/e2e-llm-scout.mjs
 */
import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const demoDir = path.join(repoRoot, ".demo-llm");
const dataDir = path.join(demoDir, "data");
const fixture = path.join(repoRoot, "fixtures", "llm-scout-shop");

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

function makeWorkspace(name, mutate) {
  const ws = path.join(demoDir, name);
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

/** mock DeepSeek chat completions：记录请求特征，返回固定契约 */
const MOCK_CONTRACT = {
  starts: [
    {
      cmd: "node",
      args: ["server.js"],
      env: { PORT: "${GB_PORT}" },
      cwd: null,
      readyPattern: "listening on port",
      readyTimeoutMs: 8000,
    },
    {
      cmd: "node",
      args: ["boot.mjs"],
      env: { PORT: "${GB_PORT}" },
      cwd: null,
      readyPattern: "listening on port",
      readyTimeoutMs: 30_000,
    },
  ],
  login: {
    path: "/api/login",
    method: "POST",
    bodyTemplate: { email: "{email}", password: "{password}" },
    credentialPath: "authentication.token",
  },
  routes: [
    {
      method: "GET",
      path: "/api/orders",
      file: "lib/app.mjs",
      resource: "order",
      hasAuth: true,
      list: true,
      hasOwnerFilter: true,
    },
    { method: "GET", path: "/api/orders/:id", file: "lib/app.mjs", resource: "order", hasAuth: true },
    {
      method: "POST",
      path: "/api/orders/:id/cancel",
      file: "lib/app.mjs",
      resource: "order",
      hasAuth: true,
    },
  ],
  notes: ["mock LLM contract: custom route table"],
};

/** 所有启动候选都不可用的场景：用于验证「候选全灭 → 回退确定性契约」与失败写回缓存 */
const MOCK_DEAD_CONTRACT = {
  ...MOCK_CONTRACT,
  starts: [
    {
      cmd: "node",
      args: ["server.js"],
      env: { PORT: "${GB_PORT}" },
      readyPattern: "listening on port",
      readyTimeoutMs: 5000,
    },
    {
      cmd: "node",
      args: ["nope.mjs"],
      env: { PORT: "${GB_PORT}" },
      readyPattern: "listening on port",
      readyTimeoutMs: 5000,
    },
  ],
};

function startMockLlm() {
  return new Promise((resolve) => {
    const state = {
      calls: 0,
      authHeaders: [],
      prompts: [],
      models: [],
      responseFormat: null,
      stream: null,
      model: null,
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
        state.models.push(state.model);
        state.responseFormat = body?.response_format?.type ?? null;
        state.stream = body?.stream ?? null;
        const userPrompt = body?.messages?.find((m) => m.role === "user")?.content ?? "";
        state.prompts.push(userPrompt);
        const contract = state.model === "deepseek-dead" ? MOCK_DEAD_CONTRACT : MOCK_CONTRACT;
        res.statusCode = 200;
        res.setHeader("Content-Type", "application/json");
        res.end(
          JSON.stringify({
            id: "mock-chat-1",
            object: "chat.completion",
            model: state.model ?? "deepseek-chat",
            choices: [
              {
                index: 0,
                message: { role: "assistant", content: JSON.stringify(contract) },
                finish_reason: "stop",
              },
            ],
            usage: {
              prompt_tokens: Math.ceil(userPrompt.length / 4),
              completion_tokens: 240,
              total_tokens: Math.ceil(userPrompt.length / 4) + 240,
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
    child.stdout.on("data", (b) => { stdout += b.toString(); });
    child.stderr.on("data", (b) => { stderr += b.toString(); });
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`[llm:${label}] 超时 ${timeoutMs}ms`));
    }, timeoutMs);
    child.on("exit", (code) => {
      clearTimeout(timer);
      const gateLine = stdout.split("\n").filter((l) => l.startsWith("GB_GATE ")).pop();
      let gate = null;
      if (gateLine) {
        try { gate = JSON.parse(gateLine.slice("GB_GATE ".length)); } catch { /* ignore */ }
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

function readReport(round) {
  const p = path.join(demoDir, "reports", round, "report.json");
  if (!existsSync(p)) return null;
  try { return JSON.parse(readFileSync(p, "utf8")); } catch { return null; }
}

function findScoutCacheFiles() {
  const root = path.join(dataDir, "scout");
  if (!existsSync(root)) return [];
  const out = [];
  for (const proj of readdirSync(root)) {
    const dir = path.join(root, proj);
    for (const f of readdirSync(dir)) {
      if (f.endsWith(".json")) out.push(path.join(dir, f));
    }
  }
  return out;
}

async function main() {
  console.log("[LLM] 0/3 准备演示目录…");
  rmSync(demoDir, { recursive: true, force: true });
  mkdirSync(dataDir, { recursive: true });
  if (!existsSync(exe)) throw new Error(`未找到无头宿主: ${exe}（先 cargo build --no-default-features --bin guardbuild-headless）`);

  const ws = makeWorkspace("llm-scout-shop");
  // 同一份靶场、换一个模型名：缓存键不同，且 mock 会返回「所有启动候选都不可用」
  const deadWs = makeWorkspace("llm-scout-dead", (dir) => {
    const p = path.join(dir, "guardbuild.json");
    const cfg = JSON.parse(readFileSync(p, "utf8"));
    cfg.llm = { enabled: true, model: "deepseek-dead" };
    writeFileSync(p, JSON.stringify(cfg, null, 2));
  });
  const { server, port: mockPort, state } = await startMockLlm();
  let r1;
  let r3;
  try {
    console.log("\n[LLM] 1/3 未知框架 + mock DeepSeek：期望 exit 1（漏洞复现但无自动补丁）…");
    r1 = await runGate(ws, "r1", {
      DEEPSEEK_API_KEY: MOCK_KEY,
      DEEPSEEK_BASE_URL: `http://127.0.0.1:${mockPort}/v1`,
    });
    console.log("\n[LLM] 2/3 所有启动候选都不可用：期望回退确定性契约后失败，并写回缓存…");
    r3 = await runGate(deadWs, "r3", {
      DEEPSEEK_API_KEY: MOCK_KEY,
      DEEPSEEK_BASE_URL: `http://127.0.0.1:${mockPort}/v1`,
    });
  } finally {
    await new Promise((r) => server.close(r));
  }

  console.log("\n[LLM] 3/3 关闭 mock 且不提供密钥：期望命中磁盘缓存并仍实际验证…");
  const r2 = await runGate(ws, "r2", {
    DEEPSEEK_API_KEY: "",
    DEEPSEEK_BASE_URL: "",
  });

  const g1 = r1.gate ?? {};
  check("退出码 = 1（漏洞证据成立）", r1.code === 1, `code=${r1.code}`);
  check(
    "verdict=vulnerable_unfixed 且 error=no_patchable_candidates",
    g1.verdict === "vulnerable_unfixed" && g1.error?.code === "no_patchable_candidates",
    `verdict=${g1.verdict} code=${g1.error?.code} state=${g1.state}`
  );
  check(
    "裁决说明 LLM 路由不参与自动改码",
    String(g1.error?.hint ?? "").includes("LLM"),
    `hint=${String(g1.error?.hint ?? "").slice(0, 40)}…`
  );

  // ---------- 侦察请求与证据安全 ----------
  check("mock LLM 收到 2 次侦察请求（两个项目各一次）", state.calls === 2, `calls=${state.calls}`);
  check(
    "请求带 Bearer 鉴权（密钥经 Host 传递）",
    state.authHeaders.length === 2 && state.authHeaders.every((h) => h === `Bearer ${MOCK_KEY}`),
    "Authorization: Bearer ***"
  );
  const prompt = state.prompts[0] ?? "";
  check("证据包含源码片段（lib/app.mjs / boot.mjs）", prompt.includes("lib/app.mjs") && prompt.includes("boot.mjs"), `prompt=${prompt.length} 字符`);
  check(
    "证据不含 guardbuild.json 内容（契约哨兵未发送）",
    !prompt.includes("SENTINEL_GUARDBUILD_CONTRACT_MUST_NOT_BE_SENT_TO_LLM") && !prompt.includes(MOCK_KEY),
    ""
  );
  check(
    "请求为 JSON 模式（response_format=json_object, stream=false）",
    state.responseFormat === "json_object" && state.stream === false,
    `response_format=${state.responseFormat} stream=${state.stream}`
  );
  check(
    "模型名按契约传递（deepseek-chat / deepseek-dead）",
    state.models[0] === "deepseek-chat" && state.models[1] === "deepseek-dead",
    `models=${state.models.join(",")}`
  );

  // ---------- 作用域与验证事件 ----------
  check(
    "gate 按 guardbuild.json 预声明作用域（含 net.egress:api.deepseek.com）",
    r1.stderr.includes(
      "[gate] 预声明作用域: project.read, worktree.write, proc.spawn, net.probe, net.egress:api.deepseek.com"
    ),
    ""
  );
  check("LLM 侦察成功事件", r1.stdout.includes("LLM 接入侦察返回候选契约"), "");
  check("LLM 启动契约经实际启动验证", r1.stdout.includes("LLM 启动契约已验证"), "");
  check("LLM 登录契约经实际登录验证", r1.stdout.includes("LLM 登录契约已验证"), "");

  const view = lastView(r1.stdout) ?? {};
  const llm = view.llm ?? {};
  check(
    "视图记录侦察应用结果（start/login/routes 全部生效）",
    llm.used === true &&
      llm.source === "llm-scout" &&
      llm.applied?.start === true &&
      llm.applied?.login === true &&
      llm.applied?.routes === 3,
    `applied=${JSON.stringify(llm.applied)}`
  );
  check(
    "视图记录实际验证通过（start + login）",
    llm.verified?.start === true && llm.verified?.login === true,
    `verified=${JSON.stringify(llm.verified)}`
  );
  const attempts = llm.startAttempts ?? [];
  check(
    "视图记录逐候选启动：首选失败（缺入口）→ 第二候选就绪",
    attempts.length === 2 &&
      attempts[0].index === 1 &&
      attempts[0].ok === false &&
      attempts[0].code === "target_not_ready" &&
      attempts[0].diagnosisCode === "missing_local_file" &&
      attempts[1].index === 2 &&
      attempts[1].ok === true &&
      attempts[1].cmd === "node" &&
      (attempts[1].args ?? []).includes("boot.mjs"),
    JSON.stringify(attempts.map((a) => `${a.index}:${a.ok}:${a.diagnosisCode}`))
  );
  check(
    "事件流解释候选切换（不是一次失败就放弃）",
    r1.stdout.includes("LLM 启动候选 1/2 未通过实际启动") &&
      r1.stdout.includes("继续尝试启动候选 2/2"),
    ""
  );
  check(
    "视图记录侦察证据文件与模型用量",
    Array.isArray(llm.evidenceFiles) &&
      llm.evidenceFiles.includes("lib/app.mjs") &&
      Number(llm.usage?.total_tokens ?? 0) > 0,
    `files=${llm.evidenceFiles?.length} tokens=${llm.usage?.total_tokens}`
  );
  const policyTokens = (view.tokens ?? []).filter((t) => t.via === "policy");
  check("作用域令牌经策略签发（via=policy）", policyTokens.length >= 1, `count=${policyTokens.length}`);

  // ---------- 报告 / 证据 / 补丁 ----------
  const rep = readReport("r1");
  const mdPath = path.join(demoDir, "reports", "r1", "report.md");
  const md = existsSync(mdPath) ? readFileSync(mdPath, "utf8") : "";
  check("报告产物已生成（report.json + report.md）", !!rep && !!md, path.join(demoDir, "reports", "r1"));
  check(
    "报告结论一致（vulnerable_unfixed/exit 1，无补丁）",
    rep?.verdict?.outcome === "vulnerable_unfixed" && rep?.verdict?.exitCode === 1 && rep?.patch === null,
    `outcome=${rep?.verdict?.outcome} patch=${rep?.patch ? "有" : "无"}`
  );
  check(
    "报告写入 LLM 侦察字段（本次调用、已验证、证据/用量）",
    rep?.llm?.used === true &&
      rep.llm.source === "llm-scout" &&
      rep.llm.cached === false &&
      rep.llm.verified?.start === true &&
      rep.llm.verified?.login === true &&
      (rep.llm.evidenceFiles ?? []).includes("lib/app.mjs") &&
      Number(rep.llm.usage?.total_tokens ?? 0) > 0,
    `used=${rep?.llm?.used} cached=${rep?.llm?.cached} verified=${JSON.stringify(rep?.llm?.verified)}`
  );
  check(
    "报告记录 LLM 推断的启动契约（startSource=llm-scout）",
    rep?.summary?.startSource === "llm-scout" &&
      rep?.summary?.start?.cmd === "node" &&
      (rep?.summary?.start?.args ?? []).includes("boot.mjs"),
    `source=${rep?.summary?.startSource} cmd=${rep?.summary?.start?.cmd}`
  );
  check(
    "报告记录逐候选启动结果（首个失败、第二个就绪）",
    Array.isArray(rep?.llm?.startAttempts) &&
      rep.llm.startAttempts.length === 2 &&
      rep.llm.startAttempts[0].ok === false &&
      rep.llm.startAttempts[0].diagnosisCode === "missing_local_file" &&
      rep.llm.startAttempts[1].ok === true,
    JSON.stringify((rep?.llm?.startAttempts ?? []).map((a) => `${a.index}:${a.ok}`))
  );
  check(
    "报告 Markdown 呈现启动候选表",
    md.includes("启动候选实际验证") && md.includes("missing_local_file") && md.includes("boot.mjs"),
    ""
  );
  const findingPaths = (rep?.summary?.findings ?? []).map((f) => f.path);
  check(
    "静态发现来自侦察路由（详情 + 取消）",
    findingPaths.includes("/api/orders/:id") && findingPaths.includes("/api/orders/:id/cancel"),
    findingPaths.join(" | ")
  );
  check("侦察路由为可定位的源码行（lib/app.mjs）", (rep?.summary?.findings ?? []).every((f) => f.file === "lib/app.mjs"), "");
  const vulnPre = (rep?.evidence?.pre ?? []).filter((e) => e.verdict === "vulnerable");
  check(
    "修复前证据：越权读 + 越权取消均已复现",
    vulnPre.length >= 2 && vulnPre.every((e) => String(e.endpoint ?? "").startsWith("/api/orders")),
    `vulnerable=${vulnPre.length} cases=${vulnPre.map((e) => e.caseId).join(",")}`
  );
  check(
    "报告未标记补丁状态（人工修复场景）",
    rep?.verdict?.patchStatus == null,
    `patchStatus=${rep?.verdict?.patchStatus}`
  );

  const db = new DatabaseSync(path.join(dataDir, "guardbuild.db"), { readOnly: true });
  const sid = g1.sessionId;
  const patchN = db.prepare("SELECT COUNT(*) n FROM patches WHERE session_id = ?").get(sid).n;
  const preVulnN = db.prepare("SELECT COUNT(*) n FROM evidence WHERE session_id = ? AND phase='pre' AND verdict='vulnerable'").get(sid).n;
  db.close();
  check("DB：未写入补丁记录", patchN === 0, `patches=${patchN}`);
  check("DB：pre 攻击证据入库（≥ 2）", preVulnN >= 2, `pre vulnerable=${preVulnN}`);

  // ---------- 全部启动候选失败：回退确定性契约，失败结论写回缓存 ----------
  const g3 = r3.gate ?? {};
  const view3 = lastView(r3.stdout) ?? {};
  const llm3 = view3.llm ?? {};
  const attempts3 = llm3.startAttempts ?? [];
  check(
    "r3 全部候选失败：exit 2 / verdict=failed / error=target_not_ready",
    r3.code === 2 && g3.verdict === "failed" && g3.error?.code === "target_not_ready",
    `code=${r3.code} verdict=${g3.verdict} error=${g3.error?.code}`
  );
  check(
    "r3 逐个尝试所有 LLM 候选后才放弃（2 个候选均缺入口）",
    attempts3.length === 2 &&
      attempts3.every((a) => a.ok === false && a.diagnosisCode === "missing_local_file"),
    JSON.stringify(attempts3.map((a) => `${a.index}:${a.ok}:${a.diagnosisCode}`))
  );
  check(
    "r3 回退到确定性契约并记录被拒绝的首选启动方式",
    r3.stdout.includes("回退到缺省启动契约重试") && (llm3.rejectedStart?.args ?? []).includes("server.js"),
    `rejected=${JSON.stringify(llm3.rejectedStart?.args ?? [])}`
  );
  check(
    "r3 失败结论写回缓存（verified.start=false，且没有 workingStart）",
    findScoutCacheFiles().some((f) => {
      try {
        const d = JSON.parse(readFileSync(f, "utf8"));
        return d.verified?.start === false && !d.workingStart;
      } catch {
        return false;
      }
    }),
    ""
  );

  // ---------- 第二轮：无密钥 / 无 mock 的磁盘缓存复用 ----------
  const g2 = r2.gate ?? {};
  check("r2 无密钥仍 exit 1（缓存契约 + 实际复现）", r2.code === 1, `code=${r2.code}`);
  check(
    "r2 verdict=vulnerable_unfixed",
    g2.verdict === "vulnerable_unfixed" && g2.error?.code === "no_patchable_candidates",
    `verdict=${g2.verdict} code=${g2.error?.code}`
  );
  check("r2 未再调用 LLM（mock 请求数仍为 2）", state.calls === 2, `calls=${state.calls}`);
  check("r2 事件流提示命中磁盘侦察缓存", r2.stdout.includes("命中磁盘侦察缓存"), "");
  const view2 = lastView(r2.stdout) ?? {};
  const llm2 = view2.llm ?? {};
  check(
    "r2 视图标记磁盘缓存与保存时间",
    llm2.used === true && llm2.cached === true && llm2.cacheSource === "disk" && Number(llm2.cachedAt) > 0,
    `cached=${llm2.cached} source=${llm2.cacheSource} at=${llm2.cachedAt}`
  );
  check(
    "r2 缓存契约仍经实际启动+登录验证",
    llm2.verified?.start === true && llm2.verified?.login === true,
    `verified=${JSON.stringify(llm2.verified)}`
  );
  const attempts2 = llm2.startAttempts ?? [];
  check(
    "r2 复用缓存时优先上次验证通过的候选（只启动一次）",
    attempts2.length === 1 && attempts2[0].ok === true && (attempts2[0].args ?? []).includes("boot.mjs"),
    JSON.stringify(attempts2.map((a) => `${a.index}:${a.ok}`))
  );
  check(
    "r2 侦察事件确认实际启动/登录验证",
    r2.stdout.includes("LLM 启动契约已验证") && r2.stdout.includes("LLM 登录契约已验证"),
    ""
  );
  const rep2 = readReport("r2");
  check(
    "r2 报告记录缓存来源与验证结果",
    rep2?.llm?.used === true &&
      rep2.llm.cached === true &&
      rep2.llm.cacheSource === "disk" &&
      Number(rep2.llm.cachedAt) > 0 &&
      rep2.llm.verified?.start === true &&
      rep2.llm.verified?.login === true &&
      rep2.summary?.startSource === "llm-scout",
    `cached=${rep2?.llm?.cached} source=${rep2?.llm?.cacheSource} verified=${JSON.stringify(rep2?.llm?.verified)}`
  );
  const rep2Vuln = (rep2?.evidence?.pre ?? []).filter((e) => e.verdict === "vulnerable");
  check("r2 报告仍复现越权证据（≥ 2）", rep2Vuln.length >= 2, `vulnerable=${rep2Vuln.length}`);

  const cacheFiles = findScoutCacheFiles();
  const cacheBlob = cacheFiles.map((f) => readFileSync(f, "utf8")).join("\n");
  check("侦察缓存落盘到数据目录（非目标项目）", cacheFiles.length >= 1, cacheFiles.join(" | "));
  check(
    "缓存不含密钥/身份凭证",
    !cacheBlob.includes(MOCK_KEY) &&
      !cacheBlob.includes("alice@llm.shop") &&
      !cacheBlob.includes("alice123") &&
      !cacheBlob.includes("bob123"),
    ""
  );
  check(
    "缓存写回实际验证结果（start + login）",
    cacheFiles.some((f) => {
      try {
        const d = JSON.parse(readFileSync(f, "utf8"));
        return d.verified?.start === true && d.verified?.login === true;
      } catch {
        return false;
      }
    }),
    ""
  );
  check(
    "缓存记录可用的启动方式（workingStart=boot.mjs）与完整候选队列",
    cacheFiles.some((f) => {
      try {
        const d = JSON.parse(readFileSync(f, "utf8"));
        return (
          Array.isArray(d.starts) &&
          d.starts.length === 2 &&
          d.workingStart?.cmd === "node" &&
          (d.workingStart?.args ?? []).includes("boot.mjs")
        );
      } catch {
        return false;
      }
    }),
    ""
  );

  // ---------- 密钥不泄漏 ----------
  const blob = [JSON.stringify(rep ?? {}), md, r1.stdout, r1.stderr, JSON.stringify(rep2 ?? {}), r2.stdout, r2.stderr, r3.stdout, r3.stderr].join("\n");
  check("mock 密钥不进入报告/事件流/stderr", !blob.includes(MOCK_KEY), "");

  const passed = checks.filter((c) => c.pass).length;
  console.log(`\n[LLM] 断言: ${passed}/${checks.length} 通过`);
  const failed = checks.filter((c) => !c.pass);
  if (failed.length > 0) {
    console.error(`[LLM] 未通过: ${failed.map((c) => c.name).join("、")}`);
    process.exit(1);
  }
  console.log("[LLM] 全部通过 ✅");
}

main().catch((e) => {
  console.error(`\n[LLM] 失败: ${e.message}`);
  const passed = checks.filter((c) => c.pass).length;
  console.log(`[LLM] 断言: ${passed}/${checks.length} 通过`);
  process.exit(1);
});
