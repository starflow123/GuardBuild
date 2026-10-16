#!/usr/bin/env node
/**
 * tRPC 适配器端到端演练：以 fixtures/trpc-shop（真实的 initTRPC/router/zod 源码 + 等价线上协议垫片）
 * 驱动 guardbuild-headless --gate，验证三类结局：
 *
 *   ① 未修复 + superjson 编码 → exit 1（verdict=vulnerable_unfixed，error=no_patchable_candidates）
 *      alice 通过 orders.byId 读到 bob 的订单 #5002、通过 orders.cancel 取消他人订单 → 证据成立；
 *      tRPC 形态（中间件/上下文写法多元）无自动修复模板，按「证据成立但不可自动修复」阻断。
 *   ② 已修复（过程内补归属校验） → exit 0（verdict=not_reproducible）：静态候选仍在，攻击无法复现。
 *   ③ 未修复 + 无 transformer（TRPC_ENCODING=raw） → 仍 exit 1，且探测层改用裸 JSON input。
 *      ①与 ③ 的请求形态差异即「编码协商」的实测证据：静态分析猜不出服务端是否启用
 *      superjson，探测层据 HTTP 400/BAD_REQUEST 判别后重发。
 *
 * 运行时说明：垫片不是 @trpc/server 本体；解析器的被测对象是 src/server/**\/*.ts 的真实路由源码，
 * 动态层只认「过程 URL + ?input= / 请求体 + 信封」协议契约（与生产一致），CI 无需安装 tRPC 与 zod。
 *
 * 用法: node scripts/e2e-trpc.mjs
 */
import { spawn, spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const demoDir = path.join(repoRoot, ".demo-trpc");
const dataDir = path.join(demoDir, "data");
const fixture = path.join(repoRoot, "fixtures", "trpc-shop");

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

/** 复刻「已修复」运行时：byId/cancel 过程内补归属校验；源文件（.ts）静态形态保持原样 */
function patchServerToFixed(ws) {
  const p = path.join(ws, "server.js");
  const src = readFileSync(p, "utf8").replace(/\r\n/g, "\n");
  let out = src;
  const edits = [
    [
      [
        "    run: ({ input }) => {",
        "      const order = findOrderById(input.id);",
        '      if (!order) throw new TrpcError("NOT_FOUND", "订单不存在");',
        "      return { order }; // 复刻漏洞：未校验 order.userId 归属",
      ].join("\n"),
      [
        "    run: ({ ctx, input }) => {",
        "      const order = findOrderById(input.id);",
        '      if (!order || order.userId !== ctx.user.id) throw new TrpcError("NOT_FOUND", "订单不存在");',
        "      return { order };",
      ].join("\n"),
    ],
    [
      [
        "    run: ({ input }) => {",
        "      const order = findOrderById(input.orderId);",
        '      if (!order) throw new TrpcError("NOT_FOUND", "订单不存在");',
      ].join("\n"),
      [
        "    run: ({ ctx, input }) => {",
        "      const order = findOrderById(input.orderId);",
        '      if (!order || order.userId !== ctx.user.id) throw new TrpcError("NOT_FOUND", "订单不存在");',
      ].join("\n"),
    ],
  ];
  for (const [find, replace] of edits) {
    if (!out.includes(find)) throw new Error("修复补丁未命中 server.js 锚点（fixture 可能已变更）");
    out = out.replace(find, replace);
  }
  writeFileSync(p, out);
}

/** 切换为「未启用 transformer」的服务端形态：input 为裸 JSON，响应 data 亦不包裹 */
function patchContractToRawEncoding(ws) {
  const p = path.join(ws, "guardbuild.json");
  const cfg = JSON.parse(readFileSync(p, "utf8"));
  cfg.start.env = { ...(cfg.start.env ?? {}), TRPC_ENCODING: "raw" };
  writeFileSync(p, JSON.stringify(cfg, null, 2));
}

function makeWorkspace(name, mutate = null) {
  const ws = path.join(demoDir, name);
  rmSync(ws, { recursive: true, force: true });
  cpSync(fixture, ws, { recursive: true });
  if (mutate) mutate(ws);
  git(["init", "-q"], ws);
  git(["config", "user.email", "gate@guardbuild.local"], ws);
  git(["config", "user.name", "GuardBuild Gate"], ws);
  git(["add", "-A"], ws);
  git(["commit", "-qm", `${name} 基线`], ws);
  return ws;
}

function runGate(project, label, timeoutMs = 120_000) {
  return new Promise((resolve, reject) => {
    const child = spawn(exe, ["--gate", "--project", project, "--report", path.join(demoDir, "reports", label)], {
      cwd: repoRoot,
      env: {
        ...process.env,
        GUARDBUILD_DATA_DIR: dataDir,
        GUARDBUILD_SIDECAR: path.join(repoRoot, "sidecar", "main.mjs"),
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (b) => { stdout += b.toString(); });
    child.stderr.on("data", (b) => { stderr += b.toString(); });
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`[trpc:${label}] 超时 ${timeoutMs}ms`));
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

function readReport(round) {
  const p = path.join(demoDir, "reports", round, "report.json");
  if (!existsSync(p)) return null;
  try { return JSON.parse(readFileSync(p, "utf8")); } catch { return null; }
}

/** 证据请求串里的 input 值（解码后原样返回，用于断言实际发送的编码形态） */
function inputOf(endpoint) {
  const raw = String(endpoint ?? "").split("?input=")[1] ?? null;
  return raw === null ? null : decodeURIComponent(raw);
}

function sessionRows(sessionId) {
  const db = new DatabaseSync(path.join(dataDir, "guardbuild.db"), { readOnly: true });
  try {
    return {
      pre: db
        .prepare("SELECT endpoint, verdict, evidence_grade FROM evidence WHERE session_id = ? AND phase='pre'")
        .all(sessionId),
      vulnerable: db
        .prepare("SELECT COUNT(*) n FROM evidence WHERE session_id = ? AND phase='pre' AND verdict='vulnerable'")
        .get(sessionId).n,
      patches: db.prepare("SELECT COUNT(*) n FROM patches WHERE session_id = ?").get(sessionId).n,
      trpcEvents: db
        .prepare(
          "SELECT message FROM events WHERE session_id = ? AND (message LIKE '%编码协商%' OR message LIKE '%形态确认%')"
        )
        .all(sessionId)
        .map((r) => r.message),
    };
  } finally {
    db.close();
  }
}

async function main() {
  console.log("[TRPC] 0/3 准备演示目录…");
  rmSync(demoDir, { recursive: true, force: true });
  mkdirSync(dataDir, { recursive: true });
  if (!existsSync(exe)) throw new Error(`未找到无头宿主: ${exe}（先 cargo build --no-default-features --bin guardbuild-headless）`);

  // ---------- ① 未修复（superjson 服务端）→ exit 1 ----------
  console.log("\n[TRPC] 1/3 未修复 + superjson：alice 越权读/取消 bob 的订单：期望 exit 1（vulnerable_unfixed）…");
  const ws1 = makeWorkspace("t1-vuln");
  const r1 = await runGate(ws1, "t1-vuln");
  const g1 = r1.gate ?? {};
  check("退出码 = 1（漏洞证据成立）", r1.code === 1, `code=${r1.code} err=${g1.error?.code}`);
  check(
    "verdict=vulnerable_unfixed 且 error=no_patchable_candidates",
    g1.verdict === "vulnerable_unfixed" && g1.error?.code === "no_patchable_candidates",
    `verdict=${g1.verdict} code=${g1.error?.code} state=${g1.state}`
  );
  const rep1 = readReport("t1-vuln");
  check("报告结论一致（vulnerable_unfixed/exit 1）", rep1?.verdict?.outcome === "vulnerable_unfixed" && rep1?.verdict?.exitCode === 1, `outcome=${rep1?.verdict?.outcome}`);

  const findings1 = rep1?.summary?.findings ?? [];
  check(
    "静态发现含 GET /api/trpc/orders.byId（点连接过程路径 + 跨文件组装）",
    findings1.some((f) => f.kind === "idor-suspect" && f.method === "GET" && f.path === "/api/trpc/orders.byId"),
    `findings=${findings1.map((f) => `${f.method} ${f.path}`).join("、")}`
  );
  check("静态发现含 POST /api/trpc/orders.cancel", findings1.some((f) => f.kind === "idor-suspect" && f.method === "POST" && f.path === "/api/trpc/orders.cancel"), "");
  check(
    "发现来源为路由文件（src/server/routers/orders.ts）",
    findings1.some((f) => String(f.file ?? "").replace(/\\/g, "/").includes("src/server/routers/orders.ts")),
    ""
  );
  check(
    "登录/列表/管理过程未被误报为候选",
    !findings1.some((f) => /auth\.login|orders\.list|admin\./.test(String(f.path))),
    `findings=${findings1.map((f) => f.path).join("、")}`
  );

  const pre1 = rep1?.evidence?.pre ?? [];
  const readEv = pre1.find((e) => e.caseId === "attack-read-foreign");
  check("pre 证据：越权读取被放行（attack-read-foreign → vulnerable）", readEv?.verdict === "vulnerable", `verdict=${readEv?.verdict} actual=${String(readEv?.actual ?? "").slice(0, 60)}`);
  check("越权读取证据为内容级交叉证明（cross-proven）", readEv?.evidenceGrade === "cross-proven", `grade=${readEv?.evidenceGrade}`);
  const cancelEv = pre1.find((e) => e.caseId === "attack-cancel-foreign");
  check("pre 证据：越权取消被放行（attack-cancel-foreign → vulnerable）", cancelEv?.verdict === "vulnerable", `verdict=${cancelEv?.verdict}`);
  check("superjson 形态：查询 input 为 {\"json\":…} 包裹", inputOf(readEv?.endpoint) === '{"json":{"id":5002}}', `input=${inputOf(readEv?.endpoint)}`);
  check("未生成补丁（tRPC 形态无自动修复模板）", (rep1?.patch ?? null) === null, `patch=${rep1?.patch ? "有" : "无"}`);
  check("错误指引要求人工修复", String(g1.error?.hint ?? "").includes("人工修复"), "");
  check("执行层未失败（exit 2 类错误缺席）", g1.error?.code !== "failed" && r1.code !== 2, `code=${r1.code}`);

  const s1 = sessionRows(g1.sessionId);
  check("DB：pre 越权证据入库（读/取消 ≥ 2 条）", s1.vulnerable >= 2, `pre vulnerable=${s1.vulnerable}`);
  check("DB：未写入补丁记录", s1.patches === 0, `patches=${s1.patches}`);
  check("DB：tRPC 编码协商/登录形态事件已记录", s1.trpcEvents.some((m) => /协商|形态确认/.test(m)), `${s1.trpcEvents[0] ?? ""}`);

  // ---------- ② 已修复 → exit 0 ----------
  console.log("\n[TRPC] 2/3 已修复（过程内补归属校验）：期望 exit 0（not_reproducible）…");
  const ws2 = makeWorkspace("t2-fixed", patchServerToFixed);
  const r2 = await runGate(ws2, "t2-fixed");
  const g2 = r2.gate ?? {};
  check("退出码 = 0（无漏洞证据）", r2.code === 0, `code=${r2.code} err=${g2.error?.code}`);
  check("verdict=not_reproducible", g2.verdict === "not_reproducible", `verdict=${g2.verdict} error=${g2.error?.code}`);
  const rep2 = readReport("t2-fixed");
  check("报告结论一致（not_reproducible/exit 0）", rep2?.verdict?.outcome === "not_reproducible" && rep2?.verdict?.exitCode === 0, `outcome=${rep2?.verdict?.outcome}`);
  check(
    "修复后静态候选仍存在（裁决来自动态复现而非静态缺失）",
    (rep2?.summary?.findings ?? []).length >= 2,
    `findings=${(rep2?.summary?.findings ?? []).length}`
  );

  // ---------- ③ 未修复 + 裸 JSON 服务端（编码协商）→ exit 1 ----------
  console.log("\n[TRPC] 3/3 未修复 + TRPC_ENCODING=raw（无 transformer）：期望探测层协商出裸 JSON input 并同样复现…");
  const ws3 = makeWorkspace("t3-raw", patchContractToRawEncoding);
  const r3 = await runGate(ws3, "t3-raw");
  const g3 = r3.gate ?? {};
  check("退出码 = 1（raw 形态同样复现）", r3.code === 1, `code=${r3.code} err=${g3.error?.code}`);
  check("verdict=vulnerable_unfixed", g3.verdict === "vulnerable_unfixed", `verdict=${g3.verdict} code=${g3.error?.code}`);
  const rep3 = readReport("t3-raw");
  const readEv3 = (rep3?.evidence?.pre ?? []).find((e) => e.caseId === "attack-read-foreign");
  check("pre 证据：越权读取被放行（raw 形态）", readEv3?.verdict === "vulnerable", `verdict=${readEv3?.verdict} actual=${String(readEv3?.actual ?? "").slice(0, 60)}`);
  check("协商结果：查询 input 改为裸 {\"id\":…}（不再包裹 json）", inputOf(readEv3?.endpoint) === '{"id":5002}', `input=${inputOf(readEv3?.endpoint)}`);
  const s3 = sessionRows(g3.sessionId);
  check("DB：raw 会话记录了协商出的形态", s3.trpcEvents.some((m) => /裸 JSON/.test(m)), `${s3.trpcEvents.join(" / ").slice(0, 90)}`);

  const passed = checks.filter((c) => c.pass).length;
  console.log(`\n[TRPC] 断言: ${passed}/${checks.length} 通过`);
  const failed = checks.filter((c) => !c.pass);
  if (failed.length > 0) {
    console.error(`[TRPC] 未通过: ${failed.map((c) => c.name).join("、")}`);
    process.exit(1);
  }
  console.log("[TRPC] 全部通过 ✅");
}

main().catch((e) => {
  console.error(`\n[TRPC] 失败: ${e.message}`);
  const passed = checks.filter((c) => c.pass).length;
  console.log(`[TRPC] 断言: ${passed}/${checks.length} 通过`);
  process.exit(1);
});
