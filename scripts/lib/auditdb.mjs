/**
 * 演练脚本读取证据库（guardbuild.db）的唯一入口。
 *
 * 事故背景：S3-full 演练在 Node 24 上稳定撞「database is locked」（慢机器三平台全红，
 * 本地偶发）。原因是读库落在写者收尾的窗口里——sidecar 会话到终态后仍在提交、
 * 关库时 SQLite 要做检查点并拆装 -wal/-shm，而 node:sqlite 默认 busy_timeout=0，
 * SQLite 一遇冲突就立刻返回 SQLITE_BUSY。演练脚本是「读者」，不该因为写者还没收尾就整轮失败。
 *
 * 策略（最小权限优先）：
 *   路线 1：只读句柄 + busy_timeout，等写者让开；
 *   路线 2：读写句柄 + PRAGMA query_only=ON —— 它有权初始化/恢复 -shm，
 *           语句层面只能读，落不下任何数据（检查点化是 SQLite 对已提交内容的常规整理）。
 * 两条路线反复失败才报错，错误信息带上库路径与最后一次原始报错，便于事后排查。
 */
import { DatabaseSync } from "node:sqlite";

function sleepSync(ms) {
  const shared = new Int32Array(new SharedArrayBuffer(4));
  Atomics.wait(shared, 0, 0, ms);
}

/** 某些 Node 版本不认 timeout 选项，此时退化为「开库后再设 busy_timeout」 */
function openWith(dbPath, { readOnly, busyMs }) {
  const options = readOnly ? { readOnly: true, timeout: busyMs } : { timeout: busyMs };
  try {
    return new DatabaseSync(dbPath, options);
  } catch (e) {
    if (!/timeout/i.test(String(e?.message ?? ""))) throw e;
    return new DatabaseSync(dbPath, readOnly ? { readOnly: true } : {});
  }
}

/** 打开后立刻设 busy_timeout，并用一次廉价查询确认「读得动」 */
function arm(db, readOnly, busyMs) {
  try {
    if (!readOnly) db.exec("PRAGMA query_only = ON"); // 路线 2：句柄可写，语句只读
    db.exec(`PRAGMA busy_timeout = ${busyMs}`);
    db.prepare("SELECT COUNT(*) FROM sqlite_master").get();
    return db;
  } catch (e) {
    try {
      db.close();
    } catch {
      /* ignore */
    }
    throw e;
  }
}

function openRoute(dbPath, busyMs, readOnly) {
  return arm(openWith(dbPath, { readOnly, busyMs }), readOnly, busyMs);
}

const ROUTES = [
  ["只读", (p, ms) => openRoute(p, ms, true)],
  ["query_only", (p, ms) => openRoute(p, ms, false)],
];

/**
 * 打开证据库供读取，返回的句柄由调用方 close。
 * @param {string} dbPath
 * @param {{attempts?: number, delayMs?: number, busyMs?: number, label?: string}} [opts]
 */
export function openAuditDb(dbPath, opts = {}) {
  const { attempts = 20, delayMs = 150, busyMs = 3000, label = "" } = opts;
  let lastErr = null;
  for (let i = 0; i < attempts; i++) {
    for (const [routeName, route] of ROUTES) {
      try {
        return route(dbPath, busyMs);
      } catch (e) {
        lastErr = e;
        console.log(`  [auditdb] ${label || dbPath}：${routeName} 路线第 ${i + 1} 次被挡 — ${e?.message ?? e}`);
      }
    }
    if (i < attempts - 1) sleepSync(Math.min(delayMs * (i + 1), 1000));
  }
  throw new Error(
    `证据库不可读: ${dbPath}（${attempts} 轮 × 2 路线仍被挡，最后一次：${lastErr?.code ? `${lastErr.code} ` : ""}${lastErr?.message ?? lastErr}）`
  );
}

/**
 * 一次性查询：打开 → prepared 读 → 关闭。
 * @param {string} dbPath
 * @param {string} sql 只读语句
 * @param {Array} [params]
 * @param {{single?: boolean} & object} [opts]
 */
export function queryAudit(dbPath, sql, params = [], opts = {}) {
  const db = openAuditDb(dbPath, opts);
  try {
    const stmt = db.prepare(sql);
    return opts.single ? stmt.get(...params) : stmt.all(...params);
  } finally {
    db.close();
  }
}
