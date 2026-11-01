/*
 * LedgerShop：记账本（第 8 项补齐用的白盒靶子之一）。
 * 路由按 Express 写法组织，运行期由 src/express-lite.js 的微型垫片承载，CI 不装任何依赖。
 *
 * 这一份里埋了两族漏洞，分别由两张考卷各修一处（判卷器只验本族零报，别族照旧是漏洞）：
 *  1) GET /api/search —— 检索词拼进 SQL 文本，没有参数绑定 → SQL 注入（查询参数通道 + 模板插值形态）。
 *  2) GET /api/docs   —— doc 参数直接 join 进读取路径，没有校验是否越出 storage → 敏感文件泄露。
 */
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { authenticate, login } from "./auth.js";
import { createDb } from "./db.js";
import { store } from "./data.js";
import { createRouter } from "./express-lite.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const STORAGE_DIR = path.join(__dirname, "..", "storage");

const db = createDb({ entries: store.entries });

export const router = createRouter();

router.post("/api/login", async (req, res) => {
  const session = login(req.body.email, req.body.password);
  if (!session) return res.status(401).json({ error: "邮箱或密码不正确" });
  return res.json({ token: session.token, user: session.user });
});

router.get("/api/whoami", async (req, res) => {
  const user = authenticate(req);
  if (!user) return res.status(401).json({ error: "请先登录" });
  return res.json({ user: user.user, entryCount: store.entries.filter((e) => e.userId === user.user.id).length });
});

router.get("/api/entries", async (req, res) => {
  const user = authenticate(req);
  if (!user) return res.status(401).json({ error: "请先登录" });
  // 本人账目列表：按归属过滤，正向断言（business-list-own）拿它核对「只看得见自己的」
  return res.json({ entries: store.entries.filter((e) => e.userId === user.user.id) });
});

router.get("/api/search", async (req, res) => {
  const user = authenticate(req);
  if (!user) return res.status(401).json({ error: "请先登录" });
  const { keyword } = req.query;
  try {
    // 复刻漏洞：检索词原样拼进 SQL 文本（真实项目里这行通常是 knex.raw / db.all 的老代码）
    const rows = db.all(`SELECT * FROM entries WHERE memo LIKE '%${keyword ?? ""}%'`);
    return res.json({ entries: rows });
  } catch (err) {
    // 复刻漏洞：排查期把数据库报错原文回写给调用方，报错型注入的证据就从这里出来
    return res.status(500).json({ error: err.message });
  }
});

router.get("/api/docs", async (req, res) => {
  const user = authenticate(req);
  if (!user) return res.status(401).json({ error: "请先登录" });
  const doc = req.query.doc;
  if (!doc) return res.status(400).json({ error: "缺少 doc 参数" });
  const target = path.join(STORAGE_DIR, doc);
  if (!existsSync(target)) return res.status(404).json({ error: "文档不存在" });
  return res.send(readFileSync(target, "utf8"));
});
