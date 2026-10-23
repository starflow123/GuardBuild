/**
 * 演练脚本读库入口（scripts/lib/auditdb.mjs）的回归测试。
 *
 * 它要守住的事故：S3-full 演练在 Node 24 上撞「database is locked / disk I/O error」——
 * 读库落在写者收尾（小事务、关库检查点、-wal/-shm 拆装）的窗口里，而 node:sqlite 默认
 * busy_timeout=0，SQLite 立刻返回 SQLITE_BUSY，整轮演练被一个「读者」带崩。
 * 所以这里的重点不是查询语义，而是：写者活着、正在写、正在关，读者都必须读到。
 */
import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { openAuditDb, queryAudit } from "../../scripts/lib/auditdb.mjs";

const CHURNER = `
import { DatabaseSync } from "node:sqlite";
const dbPath = process.argv[2];
const cycles = Number(process.argv[3] ?? 120);
const sleep = (ms) => { const a = new Int32Array(new SharedArrayBuffer(4)); Atomics.wait(a, 0, 0, ms); };
for (let c = 0; c < cycles; c++) {
  const db = new DatabaseSync(dbPath);
  db.exec("PRAGMA journal_mode = WAL;");
  const ins = db.prepare("INSERT INTO agent_actions(session_id, step, note) VALUES ('s1', ?, ?)");
  for (let i = 0; i < 10; i++) ins.run(c, "cycle " + c + " row " + i);
  db.close();
  sleep(3);
}
`;

function sleepSync(ms) {
  const shared = new Int32Array(new SharedArrayBuffer(4));
  Atomics.wait(shared, 0, 0, ms);
}

/** Windows 上刚 kill 掉的写者进程会短暂占住目录，删除要重试 */
function rmDirRetry(dir) {
  for (let i = 0; i < 20; i++) {
    try {
      rmSync(dir, { recursive: true, force: true });
      return;
    } catch (e) {
      if (!/EPERM|EBUSY|ENOTEMPTY/.test(String(e?.code ?? e?.message ?? ""))) throw e;
      sleepSync(100);
    }
  }
}

function makeStore(dir) {
  const dbPath = path.join(dir, "guardbuild.db");
  const db = new DatabaseSync(dbPath);
  db.exec("PRAGMA journal_mode = WAL;");
  db.exec("CREATE TABLE agent_actions(id INTEGER PRIMARY KEY, session_id TEXT, step INTEGER, note TEXT)");
  db.exec("INSERT INTO agent_actions(session_id, step, note) VALUES ('s1', 1, 'read'), ('s1', 2, 'exec'), ('s2', 1, 'rejected')");
  db.close();
  return dbPath;
}

test("queryAudit: 健康库上按参数取行，只读语义（不改数据）", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "gb-auditdb-"));
  try {
    const dbPath = makeStore(dir);
    const rows = queryAudit(dbPath, "SELECT step, note FROM agent_actions WHERE session_id = ? ORDER BY step", ["s1"]);
    assert.deepEqual(rows.map((r) => [r.step, r.note]), [[1, "read"], [2, "exec"]]);
    const count = queryAudit(dbPath, "SELECT COUNT(*) n FROM agent_actions", [], { single: true });
    assert.equal(count.n, 3);
    // 只读入口不该改写库内容
    const before = queryAudit(dbPath, "SELECT COUNT(*) n FROM agent_actions", [], { single: true }).n;
    assert.equal(before, 3);
  } finally {
    rmDirRetry(dir);
  }
});

test("queryAudit: 写者边写边关库时读者仍读得到（CI database is locked 的回归位）", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "gb-auditdb-race-"));
  const churnPath = path.join(dir, "churn.mjs");
  writeFileSync(churnPath, CHURNER);
  let child = null;
  try {
    const dbPath = makeStore(dir);
    child = spawn(process.execPath, ["--no-warnings", churnPath, dbPath, "400"], { stdio: ["ignore", "ignore", "pipe"] });
    let errText = "";
    child.stderr.on("data", (b) => (errText += b.toString()));
    child.on("error", (e) => (errText += String(e)));

    let maxRows = 0;
    let grew = false;
    for (let i = 0; i < 120 && !grew; i++) {
      const rows = queryAudit(dbPath, "SELECT step FROM agent_actions WHERE session_id = 's1'", [], {
        attempts: 20,
        label: "race",
      });
      assert.ok(rows.length >= 2, `第 ${i} 次读到 ${rows.length} 行（基线 2 行必须在）${errText ? ` / 写者 stderr: ${errText.slice(0, 200)}` : ""}`);
      if (rows.length > maxRows) maxRows = rows.length;
      grew = maxRows > 2;
      if (!grew) sleepSync(20);
    }
    assert.ok(grew, `写者的提交应逐步对读者可见（最多读到 ${maxRows} 行）${errText ? ` / 写者 stderr: ${errText.slice(0, 200)}` : ""}`);
  } finally {
    if (child) child.kill();
    sleepSync(150);
    rmDirRetry(dir);
  }
});

test("openAuditDb: 库不存在时给出可排查的错误（带上库路径）", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "gb-auditdb-miss-"));
  try {
    const missing = path.join(dir, "nope", "guardbuild.db");
    assert.throws(() => openAuditDb(missing, { attempts: 2, delayMs: 10 }), /证据库不可读.*guardbuild\.db/);
  } finally {
    rmDirRetry(dir);
  }
});

test("queryAudit: 句柄一定归还（读失败也关闭，不留悬挂连接）", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "gb-auditdb-close-"));
  try {
    const dbPath = makeStore(dir);
    assert.throws(() => queryAudit(dbPath, "SELECT * FROM 不存在的手写语句"), /证据库不可读|no such table/);
    // 上一次读失败后，库仍可正常读（说明没有把连接与锁留在原地）
    assert.equal(queryAudit(dbPath, "SELECT COUNT(*) n FROM agent_actions", [], { single: true }).n, 3);
  } finally {
    rmDirRetry(dir);
  }
});
