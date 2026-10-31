#!/usr/bin/env node
/**
 * 身份与测试数据自举端到端演练（#179）：以 fixtures/selfboot-shop（空库靶场）驱动
 * guardbuild-headless --gate，验证「引擎在沙箱内用目标自己的注册接口建号、再给每个账号
 * 写入名下对象」这条链路，以及它在任一环节不成立时的诚实失败形态。
 *
 *   靶场的关键设定：src/app.js 里 USERS 初始为空数组，唯一建号入口是 POST /api/register。
 *   guardbuild.json 的 identities 故意省略 password，登录契约按 {email} 取身份 ——
 *   也就是说：不注册就没有身份，注册了但引擎没把派生邮箱记回身份，登录照样登不进去。
 *
 *   ① 未修复            → exit 1：两个账号由引擎现注册（口令随机生成）、各自名下有一条
 *                        seed 写入的订单，跨归属读复现（vulnerable_unfixed）
 *   ② 归属校验加固      → exit 0：自举照常成功，攻击打不通就是打不通（not_reproducible），
 *                        报告仍写明「不等于安全」
 *   ③ 目标关闭注册      → exit 2：省略口令的身份建不了号 → identity_bootstrap_failed，
 *                        绝不退化成匿名探测后报「未发现漏洞」
 *   ④ 写入被 403 拒      → exit 2：号建了、数据写不进 → identity_seed_failed（没归属对象
 *                        就无从构造越权用例，本轮按「测不了」处理）
 *   ⑤ 契约关掉自举      → exit 2：register.enabled=false 且身份省略口令 → identity_bootstrap_unavailable
 *
 * 同时校验安全边界：
 *   - 引擎生成的口令不出现在 report.md / report.json / stdout / stderr / 审计库任何一处；
 *   - 口令不进会话对象与事件流，只经 credential.protect 登记为 Host 侧脱敏词；
 *   - 报告的「身份基础」一节把「谁被注册、造了几条数据、口令来源」写成人能读的一句话。
 *
 * 用法: node scripts/e2e-selfboot.mjs
 */
import { spawn, spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const demoDir = path.join(repoRoot, ".demo-selfboot");
const dataDir = path.join(demoDir, "data");
const fixture = path.join(repoRoot, "fixtures", "selfboot-shop");

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
  const r = spawnSync("git", ["-c", "core.longpaths=true", ...args], { cwd, encoding: "utf8" });
  if (r.status !== 0) throw new Error(`git ${args.join(" ")} 失败: ${r.stderr || r.stdout}`);
  return r.stdout;
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

function withStartEnv(ws, env) {
  const p = path.join(ws, "guardbuild.json");
  const cfg = JSON.parse(readFileSync(p, "utf8"));
  cfg.start.env = { ...(cfg.start.env ?? {}), ...env };
  writeFileSync(p, `${JSON.stringify(cfg, null, 2)}\n`);
}

const disableSelfBoot = (ws) => {
  const p = path.join(ws, "guardbuild.json");
  const cfg = JSON.parse(readFileSync(p, "utf8"));
  cfg.register = { ...(cfg.register ?? {}), enabled: false };
  writeFileSync(p, `${JSON.stringify(cfg, null, 2)}\n`);
};

function runGate(project, label, timeoutMs = 180_000) {
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
      reject(new Error(`[selfboot:${label}] 超时 ${timeoutMs}ms`));
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

function readMarkdown(round) {
  const p = path.join(demoDir, "reports", round, "report.md");
  return existsSync(p) ? readFileSync(p, "utf8") : "";
}

const readText = (p) => (existsSync(p) ? readFileSync(p, "utf8") : "");

/** 引擎口令形状：Gb + 14 位字母数字 + 2 位数字（见 identityboot.generateTestPassword） */
const PWD_SHAPE = /Gb[0-9A-Za-z]{14}[2-9][2-9]/g;

function artifactTexts(round, roundLog) {
  const dir = path.join(demoDir, "reports", round);
  return [
    { name: "report.json", text: readText(path.join(dir, "report.json")) },
    { name: "report.md", text: readText(path.join(dir, "report.md")) },
    { name: "gate stdout", text: roundLog.stdout },
    { name: "gate stderr", text: roundLog.stderr },
  ];
}

async function main() {
  console.log("[SELFB] 0/5 准备演示目录…");
  rmSync(demoDir, { recursive: true, force: true });
  mkdirSync(dataDir, { recursive: true });
  if (!existsSync(exe)) throw new Error(`未找到无头宿主: ${exe}（先 cargo build --no-default-features --bin guardbuild-headless）`);

  // ---------- ① 空库 + 省略口令：引擎建号造数据，漏洞照复现 ----------
  console.log("\n[SELFB] 1/5 未修复（空库，身份由引擎自举）：期望 exit 1…");
  const ws1 = makeWorkspace("b1-vuln");
  const r1 = await runGate(ws1, "b1-vuln");
  const g1 = r1.gate ?? {};
  const rep1 = readReport("b1-vuln");
  check("退出码 = 1（漏洞证据成立）", r1.code === 1, `code=${r1.code}${r1.code !== 1 ? ` stderr=${r1.stderr.slice(-400)}` : ""}`);
  check("verdict=vulnerable_unfixed（不是「没测到」也不是「跑挂了」）", g1.verdict === "vulnerable_unfixed", `verdict=${g1.verdict} state=${g1.state} error=${g1.error?.code}`);
  const idr1 = rep1?.summary?.identities ?? {};
  check("两个身份都由引擎注册建立（2/2 会话）", (idr1.loggedIn ?? []).length === 2, `loggedIn=${(idr1.loggedIn ?? []).map((i) => i.name).join("、") || "无"}`);
  const boot1 = (idr1.bootstrap?.byPhase ?? [])[0] ?? null;
  check("报告身份基础里有自举一节（端点/建号数/造数据数）", !!boot1, `bootstrap=${JSON.stringify(idr1.bootstrap ?? null).slice(0, 120)}`);
  check("注册端点来自契约声明（不是引擎猜的）", boot1?.endpoint === "/api/register" && boot1?.endpointSource === "contract", `endpoint=${boot1?.endpoint}/${boot1?.endpointSource}`);
  check(
    "两个账号都经目标注册接口建成（verdict=created，口令来源 engine-generated）",
    (boot1?.accounts ?? []).length === 2 &&
      boot1.accounts.every((a) => a.verdict === "created" && a.status === 201 && a.passwordSource === "engine-generated"),
    `accounts=${(boot1?.accounts ?? []).map((a) => `${a.name}:${a.verdict}/${a.status}/${a.passwordSource}`).join("、") || "无"}`
  );
  check(
    "每个新建账号名下各有一条 seed 写入的订单（201 written）",
    (boot1?.seeds ?? []).length === 2 && boot1.seeds.every((s) => s.verdict === "written" && s.status === 201),
    `seeds=${(boot1?.seeds ?? []).map((s) => `${s.identity}:${s.endpoint}/${s.verdict}`).join("、") || "无"}`
  );
  check("口令脱敏登记成功（Host protected 保险库回执 ok）", Object.values(boot1?.secretProtection ?? {}).every((v) => v === "ok") && Object.keys(boot1?.secretProtection ?? {}).length === 2, `secretProtection=${JSON.stringify(boot1?.secretProtection ?? {})}`);
  const md1 = readMarkdown("b1-vuln");
  check("报告正文一句话讲清「账号是引擎现注册的、口令只进保险库」", /身份自举：本轮由目标注册接口 `\/api\/register`（contract）建号 2 个/.test(md1) && /口令由引擎随机生成、只进 Host 保险库/.test(md1), "");
  check("会话真实性仍经回读验证（自举不豁免 #175）", idr1.sessionVerification?.status === "verified", `status=${idr1.sessionVerification?.status} probe=${idr1.sessionVerification?.probePath}`);

  const pre1 = rep1?.evidence?.pre ?? [];
  const leak = pre1.find((e) => e.caseId === "attack-read-foreign");
  check("pre 证据：跨归属读他人订单复现（攻击对象是 seed 写进去的那条）", leak?.verdict === "vulnerable", `verdict=${leak?.verdict} endpoint=${leak?.endpoint} actual=${String(leak?.actual ?? "").slice(0, 120)}`);
  check("证据正文能看到引擎写入的 canary 标题（数据确实是本轮造的）", /gbseed-[0-9a-f]{10}/.test(String(leak?.actual ?? "")) || /gbseed-/.test(md1), `actual=${String(leak?.actual ?? "").slice(0, 140)}`);
  const own1 = pre1.find((e) => String(e.caseId ?? "").startsWith("business-read-own"));
  check("正向断言：本人名下订单照常可读（自举没把目标改坏）", own1?.verdict === "passed", `case=${own1?.caseId} verdict=${own1?.verdict}`);

  // 口令泄露面：产物 + 审计库
  let leaked = [];
  for (const a of artifactTexts("b1-vuln", r1)) {
    const m = String(a.text ?? "").match(PWD_SHAPE);
    if (m) leaked.push(`${a.name}:${m[0]}`);
  }
  const db = new DatabaseSync(path.join(dataDir, "guardbuild.db"), { readOnly: true });
  try {
    const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map((r) => r.name);
    for (const t of tables) {
      const rows = db.prepare(`SELECT * FROM "${t}" LIMIT 500`).all();
      const blob = JSON.stringify(rows);
      const m = blob.match(PWD_SHAPE);
      if (m) leaked.push(`db.${t}:${m[0]}`);
    }
    const evCount = db.prepare("SELECT COUNT(*) AS n FROM evidence WHERE session_id = ?").get(g1.sessionId)?.n ?? 0;
    check("审计库确有本轮证据落库（不是只写在报告里）", evCount > 0, `evidence=${evCount} 行`);
  } finally {
    db.close();
  }
  check("引擎生成的口令不出现在任何产物/审计库里", leaked.length === 0, leaked.join("、") || "无残留");

  // ---------- ② 归属校验加固：自举成功，攻击打不通 ----------
  console.log("\n[SELFB] 2/5 归属校验加固（GB_SELFB_HARDENED=1）：期望 exit 0…");
  const ws2 = makeWorkspace("b2-hardened", (ws) => withStartEnv(ws, { GB_SELFB_HARDENED: "1" }));
  const r2 = await runGate(ws2, "b2-hardened");
  const g2 = r2.gate ?? {};
  const rep2 = readReport("b2-hardened");
  check("退出码 = 0（已测用例未复现）", r2.code === 0, `code=${r2.code}${r2.code !== 0 ? ` stderr=${r2.stderr.slice(-400)}` : ""}`);
  check("verdict=not_reproducible（结论来自实测）", g2.verdict === "not_reproducible", `verdict=${g2.verdict} error=${g2.error?.code}`);
  const boot2 = (rep2?.summary?.identities?.bootstrap?.byPhase ?? [])[0] ?? {};
  check("加固轮仍完成自举（2 个账号 + 2 条数据）", (boot2.accounts ?? []).filter((a) => a.verdict === "created").length === 2 && (boot2.seeds ?? []).filter((s) => s.verdict === "written").length === 2, `accounts=${(boot2.accounts ?? []).length} seeds=${(boot2.seeds ?? []).length}`);
  const blocked2 = (rep2?.evidence?.pre ?? []).find((e) => e.caseId === "attack-read-foreign");
  check("pre 证据：跨归属读被 403 挡住", blocked2?.verdict === "blocked" && /403/.test(String(blocked2?.actual ?? "")), `verdict=${blocked2?.verdict} actual=${String(blocked2?.actual ?? "").slice(0, 120)}`);
  check("报告标题仍写明「不等于安全」", /不等于安全|未证明安全/.test(String(rep2?.verdict?.headline ?? "") + readMarkdown("b2-hardened")), `headline=${String(rep2?.verdict?.headline ?? "").slice(0, 80)}`);

  // ---------- ③ 目标关闭注册：建不了号就是测不了 ----------
  console.log("\n[SELFB] 3/5 目标关闭注册（GB_SELFB_BOOT=0）：期望 exit 2…");
  const ws3 = makeWorkspace("b3-no-boot", (ws) => withStartEnv(ws, { GB_SELFB_BOOT: "0" }));
  const r3 = await runGate(ws3, "b3-no-boot");
  const g3 = r3.gate ?? {};
  const rep3 = readReport("b3-no-boot");
  check("退出码 = 2（执行未成立，不是放行）", r3.code === 2, `code=${r3.code}`);
  check("错误码 = identity_bootstrap_failed（注册被目标拒）", g3.error?.code === "identity_bootstrap_failed", `error=${g3.error?.code} verdict=${g3.verdict}`);
  check("终态归为 inconclusive（「测不了」而不是「没漏洞」）", g3.verdict === "inconclusive", `verdict=${g3.verdict}`);
  check("hint 明说不退回匿名探测", /匿名|不会改用/.test(String(g3.error?.hint ?? "")), `hint=${String(g3.error?.hint ?? "").slice(0, 160)}`);
  const regReqs3 = (r3.stdout.match(/\/api\/register/g) ?? []).length;
  check("引擎确实打过注册接口（有真实请求，不是凭空判定）", regReqs3 > 0, `stdout 提及 /api/register ${regReqs3} 次`);
  // 退出码图例（「0=已测未复现 / …」）本来就要解释三种码，不该算成把本轮说成通过；
  // 判据只看结论段与去掉图例那一行后的正文。
  const md3Body = readMarkdown("b3-no-boot")
    .split("\n")
    .filter((l) => !l.includes("退出码"))
    .join("\n");
  check(
    "报告里没有「未复现」这类被当成通过的措辞",
    !/已测未复现|未发现漏洞/.test(md3Body + String(rep3?.verdict?.headline ?? "")) &&
      /无法证明|测不了/.test(md3Body),
    `headline=${String(rep3?.verdict?.headline ?? "").slice(0, 90)}`
  );

  // ---------- ④ 写入被拒：有号没数据也是测不了 ----------
  console.log("\n[SELFB] 4/5 写入被 403 拒（GB_SELFB_SEED_DENIED=1）：期望 exit 2…");
  const ws4 = makeWorkspace("b4-seed-denied", (ws) => withStartEnv(ws, { GB_SELFB_SEED_DENIED: "1" }));
  const r4 = await runGate(ws4, "b4-seed-denied");
  const g4 = r4.gate ?? {};
  check("退出码 = 2", r4.code === 2, `code=${r4.code}`);
  check("错误码 = identity_seed_failed", g4.error?.code === "identity_seed_failed", `error=${g4.error?.code} verdict=${g4.verdict}`);
  check("hint 讲清「没有归属对象就无从构造越权用例」", /归属对象|写入却被拒/.test(String(g4.error?.hint ?? "")), `hint=${String(g4.error?.hint ?? "").slice(0, 160)}`);

  // ---------- ⑤ 契约关掉自举：省略口令却没地方建号 ----------
  console.log("\n[SELFB] 5/5 契约 register.enabled=false：期望 exit 2（identity_bootstrap_unavailable）…");
  const ws5 = makeWorkspace("b5-disabled", disableSelfBoot);
  const r5 = await runGate(ws5, "b5-disabled");
  const g5 = r5.gate ?? {};
  check("退出码 = 2", r5.code === 2, `code=${r5.code}`);
  check("错误码 = identity_bootstrap_unavailable", g5.error?.code === "identity_bootstrap_unavailable", `error=${g5.error?.code} verdict=${g5.verdict}`);
  check("hint 指向可执行的修法（声明 register.path 或提供口令）", /register\.path|已存在的账号口令/.test(String(g5.error?.hint ?? "")), `hint=${String(g5.error?.hint ?? "").slice(0, 160)}`);
  check("本轮没有向目标发出任何注册请求", !/POST \/api\/register|\/api\/register/.test(r5.stdout) || /register\.enabled=false|被契约显式关闭/.test(String(g5.error?.hint ?? "")), `stdout 提及注册=${(r5.stdout.match(/\/api\/register/g) ?? []).length}`);

  const passed = checks.filter((c) => c.pass).length;
  console.log(`\n[SELFB] 断言: ${passed}/${checks.length} 通过`);
  const failed = checks.filter((c) => !c.pass);
  if (failed.length > 0) {
    console.error(`[SELFB] 未通过: ${failed.map((c) => c.name).join("、")}`);
    process.exit(1);
  }
  console.log("[SELFB] 全部通过 ✅");
}

main().catch((e) => {
  console.error(`\n[SELFB] 失败: ${e.message}`);
  const passed = checks.filter((c) => c.pass).length;
  console.log(`[SELFB] 断言: ${passed}/${checks.length} 通过`);
  process.exit(1);
});
