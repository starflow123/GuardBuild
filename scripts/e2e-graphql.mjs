#!/usr/bin/env node
/**
 * GraphQL 适配器端到端演练：以 fixtures/graphql-shop（真实 schema-first 形态：.graphql SDL +
 * resolver 映射表 + 字段指令鉴权 + 等价线上协议垫片）驱动 guardbuild-headless --gate，验证三类结局：
 *
 *   ① 未修复（拒绝语义按 HTTP 状态码映射，内省开启）→ exit 1（verdict=vulnerable_unfixed，
 *      error=no_patchable_candidates）：alice 通过 Query.order 读到 bob 的订单 #7001、通过
 *      Mutation.cancelOrder 取消他人订单、匿名通过公开字段 Query.receipt 取回他人小票 → 证据成立；
 *      GraphQL 的鉴权分散在指令/shield/middleware/resolver 四层，无自动修复模板，按「证据成立但
 *      不可自动修复」阻断。
 *   ② 运行时补归属校验 + 关闭内省（GRAPHQL_INTROSPECTION=off）→ exit 0（not_reproducible）：
 *      静态候选仍在，攻击无法复现；同时验证「服务端不提供 introspection 时，文档完全按源码 SDL 构造」
 *      这条降级路径（探测层记 WARN 而非静默改用运行时 schema）。
 *   ③ 未修复 + Apollo v4 形态（一律 HTTP 200 + errors[].extensions.code）→ 仍 exit 1，且业务侧的
 *      「未登录被拒」「非管理员被拒」「状态保护生效」必须由探测层从 errors 语义识别（否则用例会
 *      被判成业务回归）。②与③ 合起来构成「拒绝语义两种流派都能正确判定」的实测证据。
 *
 * 运行时说明：垫片不是 GraphQL 运行时本体；解析器的被测对象是 schema.graphql 与
 * src/resolvers.mjs 的真实源码，动态层只认「POST 单端点 + {query,variables} + {data}/{errors} 信封」
 * 的协议契约（与生产一致），CI 无需安装 graphql / apollo-server。
 *
 * 用法: node scripts/e2e-graphql.mjs
 */
import { spawn, spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const demoDir = path.join(repoRoot, ".demo-graphql");
const dataDir = path.join(demoDir, "data");
const fixture = path.join(repoRoot, "fixtures", "graphql-shop");

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

/**
 * 复刻「已修复」运行时：order/cancelOrder 补归属校验、receipt 改为需登录且校验归属；
 * 源文件（schema.graphql / src/resolvers.mjs）的静态形态保持原样（候选仍在）。
 */
function patchServerToFixed(ws) {
  const p = path.join(ws, "server.js");
  const src = readFileSync(p, "utf8").replace(/\r\n/g, "\n");
  let out = src;
  const edits = [
    [
      [
        '    resolve: ({ id }) => {',
        "      const order = findOrderById(id);",
        '      if (!order) throw new GqlError("NOT_FOUND", "订单不存在");',
        "      return order; // 复刻漏洞：未校验订单归属",
      ].join("\n"),
      [
        '    resolve: ({ id }, ctx) => {',
        "      const order = findOrderById(id);",
        '      if (!order || order.userId !== ctx.user.id) throw new GqlError("NOT_FOUND", "订单不存在");',
        "      return order;",
      ].join("\n"),
    ],
    [
      [
        "    auth: null,",
        '    args: { id: "Int" },',
        '    resolve: ({ id }) => {',
        "      const receipt = findReceiptByOrderId(id);",
        '      if (!receipt) throw new GqlError("NOT_FOUND", "小票不存在");',
        "      return receipt; // 复刻漏洞：字段本身公开，匿名即可取回他人地址与金额",
      ].join("\n"),
      [
        '    auth: "user",',
        '    args: { id: "Int" },',
        '    resolve: ({ id }, ctx) => {',
        "      const receipt = findReceiptByOrderId(id);",
        '      if (!receipt || receipt.userId !== ctx.user.id) throw new GqlError("NOT_FOUND", "小票不存在");',
        "      return receipt;",
      ].join("\n"),
    ],
    [
      [
        '    resolve: ({ id }) => {',
        "      const order = findOrderById(id);",
        '      if (!order) throw new GqlError("NOT_FOUND", "订单不存在");',
        '      if (order.status !== "paid") throw new GqlError("CONFLICT", "当前订单状态不可取消");',
        "      order.status = \"cancelled\"; // 复刻漏洞：未校验归属即可取消他人订单",
      ].join("\n"),
      [
        '    resolve: ({ id }, ctx) => {',
        "      const order = findOrderById(id);",
        '      if (!order || order.userId !== ctx.user.id) throw new GqlError("NOT_FOUND", "订单不存在");',
        '      if (order.status !== "paid") throw new GqlError("CONFLICT", "当前订单状态不可取消");',
        "      order.status = \"cancelled\";",
      ].join("\n"),
    ],
  ];
  for (const [find, replace] of edits) {
    if (!out.includes(find)) throw new Error("修复补丁未命中 server.js 锚点（fixture 可能已变更）");
    out = out.replace(find, replace);
  }
  writeFileSync(p, out);
}

/** 切换运行时开关：写入 guardbuild.json 的 start.env（不改动被分析的源码形态） */
function patchStartEnv(ws, env) {
  const p = path.join(ws, "guardbuild.json");
  const cfg = JSON.parse(readFileSync(p, "utf8"));
  cfg.start.env = { ...(cfg.start.env ?? {}), ...env };
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

function runGate(project, label, timeoutMs = 150_000) {
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
      reject(new Error(`[graphql:${label}] 超时 ${timeoutMs}ms`));
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
      gqlEvents: db
        .prepare("SELECT message FROM events WHERE session_id = ? AND message LIKE '%GraphQL%'")
        .all(sessionId)
        .map((r) => r.message),
    };
  } finally {
    db.close();
  }
}

async function main() {
  console.log("[GQL] 0/3 准备演示目录…");
  rmSync(demoDir, { recursive: true, force: true });
  mkdirSync(dataDir, { recursive: true });
  if (!existsSync(exe)) throw new Error(`未找到无头宿主: ${exe}（先 cargo build --no-default-features --bin guardbuild-headless）`);

  // ---------- ① 未修复（状态码映射流派）→ exit 1 ----------
  console.log("\n[GQL] 1/3 未修复：alice 越权读/取消 bob 的订单，匿名读他人小票：期望 exit 1（vulnerable_unfixed）…");
  const ws1 = makeWorkspace("g1-vuln");
  const r1 = await runGate(ws1, "g1-vuln");
  const g1 = r1.gate ?? {};
  check("退出码 = 1（漏洞证据成立）", r1.code === 1, `code=${r1.code} err=${g1.error?.code}`);
  check(
    "verdict=vulnerable_unfixed 且 error=no_patchable_candidates",
    g1.verdict === "vulnerable_unfixed" && g1.error?.code === "no_patchable_candidates",
    `verdict=${g1.verdict} code=${g1.error?.code} state=${g1.state}`
  );
  const rep1 = readReport("g1-vuln");
  check("报告结论一致（vulnerable_unfixed/exit 1）", rep1?.verdict?.outcome === "vulnerable_unfixed" && rep1?.verdict?.exitCode === 1, `outcome=${rep1?.verdict?.outcome}`);

  const findings1 = rep1?.summary?.findings ?? [];
  const keys1 = findings1.flatMap((f) => f.routeKeys ?? []);
  check(
    "静态发现 = 3 条字段级候选（Query.order / Mutation.cancelOrder / Query.receipt）",
    ["Query.order", "Mutation.cancelOrder", "Query.receipt"].every((k) => keys1.includes(k)),
    `routeKeys=${keys1.join("、")}`
  );
  check(
    "两条为 idor-suspect、一条为 no-auth-suspect",
    findings1.filter((f) => f.kind === "idor-suspect").length === 2 &&
      findings1.some((f) => f.kind === "no-auth-suspect" && (f.routeKeys ?? []).includes("Query.receipt")),
    `kinds=${findings1.map((f) => `${f.routeKeys}:${f.kind}`).join("、")}`
  );
  check(
    "发现来源为解析器源码文件（src/resolvers.mjs）且带行号",
    findings1.every((f) => String(f.file ?? "").replace(/\\/g, "/").includes("src/resolvers.mjs") && Number(f.startLine) > 0),
    `files=${findings1.map((f) => `${f.file}:${f.startLine}`).join("、")}`
  );
  check(
    "端点统一为 POST /graphql（单端点模型：寻址在文档不在 URL）",
    findings1.length > 0 && findings1.every((f) => f.method === "POST" && String(f.path).endsWith("/graphql")),
    `paths=${[...new Set(findings1.map((f) => `${f.method} ${f.path}`))].join("、")}`
  );
  check(
    "登录/列表/管理字段未被误报为候选",
    !keys1.some((k) => /login|myOrders|admin/i.test(k)),
    `routeKeys=${keys1.join("、")}`
  );

  const pre1 = rep1?.evidence?.pre ?? [];
  const readEv = pre1.find((e) => e.caseId === "attack-read-foreign");
  check("pre 证据：越权读取被放行（attack-read-foreign → vulnerable）", readEv?.verdict === "vulnerable", `verdict=${readEv?.verdict} actual=${String(readEv?.actual ?? "").slice(0, 60)}`);
  check("越权读取证据为内容级交叉证明（cross-proven）", readEv?.evidenceGrade === "cross-proven", `grade=${readEv?.evidenceGrade}`);
  check("取消他人订单被放行（attack-cancel-foreign → vulnerable）", pre1.find((e) => e.caseId === "attack-cancel-foreign")?.verdict === "vulnerable", "");
  check("匿名读取公开字段被放行（attack-anonymous-read → vulnerable）", pre1.find((e) => e.caseId === "attack-anonymous-read")?.verdict === "vulnerable", "");
  check("角色守卫生效：管理端越权未被判为漏洞", pre1.find((e) => e.caseId === "attack-vertical-escalation")?.verdict !== "vulnerable", `verdict=${pre1.find((e) => e.caseId === "attack-vertical-escalation")?.verdict}`);
  const readDoc = String(readEv?.request?.body ?? "");
  check("探测文档按 SDL 构造：query GuardbuildProbe($id: Int!) { order(…)", /\$id:\s*Int!/.test(readDoc) && /order\(\s*id:\s*\$id\s*\)/.test(readDoc), readDoc.slice(0, 90));
  check("文档选取集含 status（枚举字段可被选中，取消状态才可比对）", /selection|status/.test(readDoc) && /\bstatus\b/.test(readDoc), "");
  check("未生成补丁（GraphQL 形态无自动修复模板）", (rep1?.patch ?? null) === null, `patch=${rep1?.patch ? "有" : "无"}`);
  check("错误指引要求人工修复", String(g1.error?.hint ?? "").includes("人工修复"), "");
  check("执行层未失败（exit 2 类错误缺席）", g1.error?.code !== "failed" && r1.code !== 2, `code=${r1.code}`);

  const s1 = sessionRows(g1.sessionId);
  check("DB：pre 越权证据入库（读/取消/匿名 ≥ 3 条）", s1.vulnerable >= 3, `pre vulnerable=${s1.vulnerable}`);
  check("DB：未写入补丁记录", s1.patches === 0, `patches=${s1.patches}`);
  check("DB：GraphQL 端点确认 + 参数形态协商事件已记录", s1.gqlEvents.some((m) => /端点确认/.test(m)) && s1.gqlEvents.some((m) => /参数形态协商/.test(m)), `${s1.gqlEvents.join(" / ").slice(0, 120)}`);

  // ---------- ② 已修复 + 关闭内省 → exit 0 ----------
  console.log("\n[GQL] 2/3 已修复（补归属校验）+ GRAPHQL_INTROSPECTION=off：期望 exit 0（not_reproducible）…");
  const ws2 = makeWorkspace("g2-fixed", (ws) => {
    patchServerToFixed(ws);
    patchStartEnv(ws, { GRAPHQL_INTROSPECTION: "off" });
  });
  const r2 = await runGate(ws2, "g2-fixed");
  const g2 = r2.gate ?? {};
  check("退出码 = 0（无漏洞证据）", r2.code === 0, `code=${r2.code} err=${g2.error?.code}`);
  check("verdict=not_reproducible", g2.verdict === "not_reproducible", `verdict=${g2.verdict} error=${g2.error?.code}`);
  const rep2 = readReport("g2-fixed");
  check("报告结论一致（not_reproducible/exit 0）", rep2?.verdict?.outcome === "not_reproducible" && rep2?.verdict?.exitCode === 0, `outcome=${rep2?.verdict?.outcome}`);
  check(
    "修复后静态候选仍存在（裁决来自动态复现而非静态缺失）",
    (rep2?.summary?.findings ?? []).length >= 3,
    `findings=${(rep2?.summary?.findings ?? []).length}`
  );
  const pre2 = rep2?.evidence?.pre ?? [];
  const readEv2 = pre2.find((e) => e.caseId === "attack-read-foreign");
  check("越权读取不再成立（他人订单按不存在处理）", readEv2 && readEv2.verdict !== "vulnerable", `verdict=${readEv2?.verdict} actual=${String(readEv2?.actual ?? "").slice(0, 50)}`);
  check("匿名读取公开字段被拒（receipt 补登录后不再泄露）", pre2.find((e) => e.caseId === "attack-anonymous-read")?.verdict !== "vulnerable", "");
  check("本人业务保持可用（business-read-own / business-cancel-own / business-admin-cancel 全通过）", ["business-read-own", "business-cancel-own", "business-admin-cancel", "business-list-own", "business-shipped-guard"].every((cid) => pre2.find((e) => e.caseId === cid)?.verdict === "passed"), `verdicts=${pre2.filter((e) => e.caseCategory === "business").map((e) => `${e.caseId}:${e.verdict}`).join("、")}`);
  const s2 = sessionRows(g2.sessionId);
  check("DB：关闭内省时降级为「完全按源码 SDL 构造」告警而非报错", s2.gqlEvents.some((m) => /introspection 不可用/.test(m)), `${s2.gqlEvents[0] ?? ""}`);

  // ---------- ③ 未修复 + Apollo v4（HTTP 200 + errors）→ exit 1 ----------
  console.log("\n[GQL] 3/3 未修复 + GRAPHQL_ERROR_STATUS=inline（一律 200+errors）：期望仍 exit 1，且拒绝语义由 errors 识别…");
  const ws3 = makeWorkspace("g3-inline", (ws) => patchStartEnv(ws, { GRAPHQL_ERROR_STATUS: "inline" }));
  const r3 = await runGate(ws3, "g3-inline");
  const g3 = r3.gate ?? {};
  check("退出码 = 1（200+errors 流派同样复现）", r3.code === 1, `code=${r3.code} err=${g3.error?.code}`);
  check("verdict=vulnerable_unfixed", g3.verdict === "vulnerable_unfixed", `verdict=${g3.verdict} code=${g3.error?.code}`);
  const rep3 = readReport("g3-inline");
  const pre3 = rep3?.evidence?.pre ?? [];
  const readEv3 = pre3.find((e) => e.caseId === "attack-read-foreign");
  check("pre 证据：越权读取被放行（inline 流派）", readEv3?.verdict === "vulnerable", `verdict=${readEv3?.verdict}`);
  check("复现证据仍为 cross-proven（内容比对不依赖 HTTP 状态码）", readEv3?.evidenceGrade === "cross-proven", `grade=${readEv3?.evidenceGrade}`);
  const unauthBiz3 = pre3.find((e) => e.caseId === "business-unauth-401");
  check("未登录访问被识别为语义拒绝（200+UNAUTHENTICATED，业务用例仍通过）", unauthBiz3?.verdict === "passed" && /GraphQL 拒绝|语义拒绝/.test(String(unauthBiz3?.actual ?? "")), `verdict=${unauthBiz3?.verdict} actual=${String(unauthBiz3?.actual ?? "").slice(0, 70)}`);
  const nonadmin3 = pre3.find((e) => e.caseId === "business-nonadmin-denied");
  check("非管理员访问管理端被识别为语义拒绝（200+FORBIDDEN）", nonadmin3?.verdict === "passed" && /语义拒绝/.test(String(nonadmin3?.actual ?? "")), `verdict=${nonadmin3?.verdict} actual=${String(nonadmin3?.actual ?? "").slice(0, 70)}`);
  const shipped3 = pre3.find((e) => e.caseId === "business-shipped-guard");
  check("状态保护生效（200+CONFLICT 视为等价 409）", shipped3?.verdict === "passed", `verdict=${shipped3?.verdict} actual=${String(shipped3?.actual ?? "").slice(0, 70)}`);
  check("inline 流派下无任何业务用例被判回归", pre3.filter((e) => e.caseCategory === "business" && e.verdict === "regressed").length === 0, `regressed=${pre3.filter((e) => e.caseCategory === "business" && e.verdict === "regressed").map((e) => e.caseId).join("、")}`);
  check("200+NOT_FOUND（对象不存在）未被当作越权成功证据", pre3.filter((e) => e.caseCategory === "attack" && e.verdict === "vulnerable").every((e) => /order|cancel|receipt/.test(String(e.caseId))), `attack vulnerable=${pre3.filter((e) => e.caseCategory === "attack" && e.verdict === "vulnerable").map((e) => e.caseId).join("、")}`);

  const passed = checks.filter((c) => c.pass).length;
  console.log(`\n[GQL] 断言: ${passed}/${checks.length} 通过`);
  const failed = checks.filter((c) => !c.pass);
  if (failed.length > 0) {
    console.error(`[GQL] 未通过: ${failed.map((c) => c.name).join("、")}`);
    process.exit(1);
  }
  console.log("[GQL] 全部通过 ✅");
}

main().catch((e) => {
  console.error(`\n[GQL] 失败: ${e.message}`);
  const passed = checks.filter((c) => c.pass).length;
  console.log(`[GQL] 断言: ${passed}/${checks.length} 通过`);
  process.exit(1);
});
