#!/usr/bin/env node
/**
 * 攻击规划靶场（fixtures/queue-shop）：验证「每类探测只够打 14 条路由时，把预算重排给真正高价值的路由」。
 *
 * OpenAPI 声明顺序就是引擎的探测顺序（同源同 rank 时稳定排序，见 blackbox.mjs 的 getRoutesForProbing）：
 *   /api/queue-01 … /api/queue-18   18 条列表：要登录、只返回本人条目、详情有归属校验（跨用户读取被防住）
 *   /api/contracts                  第 19 条：列表只返回本人条目，但详情不校验归属 → 可跨用户读取
 *   /api/audit                      第 20 条：声明 q 查询参数，字符串语境拼接 → ' OR 1=1-- 放开结果集
 *
 * 默认预算 14 条时「引擎原序」永远打不到 contracts 与 audit：这两条 finding 出不出现，
 * 只取决于探测预算有没有被重排（这正是攻击规划代理要证明的事）。
 * 所有越权/注入端点都要求登录：匿名可读会把「未认证读取」和目标漏洞混在一起，归因就不唯一了。
 */
import { createServer } from "node:http";

const accounts = {
  "alice@queue.shop": { id: 1, email: "alice@queue.shop", password: "alice123", role: "user" },
  "bob@queue.shop": { id: 2, email: "bob@queue.shop", password: "bob123", role: "user" },
  "carol@queue.shop": { id: 3, email: "carol@queue.shop", password: "carol123", role: "admin" },
};
const tokens = new Map();

// 18 个队列 × 3 个账号：列表按本人过滤，详情按归属校验（IDOR 防住）
const queueItems = [];
for (let n = 1; n <= 18; n += 1) {
  const queue = `queue-${String(n).padStart(2, "0")}`;
  for (const u of Object.values(accounts)) {
    queueItems.push({ id: n * 100 + u.id, queue, userId: u.id, label: `${queue}-owner-${u.id}` });
  }
}

const contracts = [
  { id: 4101, userId: 1, title: "alice-contract" },
  { id: 4102, userId: 2, title: "bob-contract" },
  { id: 4103, userId: 3, title: "carol-contract" },
];

// 注意：这里不能出现 "test"（基线查询字面量），否则基线本身有数据，注入差分就失去归因
const auditRows = [
  { id: 7101, note: "role escalation attempt blocked" },
  { id: 7102, note: "failed login from unknown device" },
  { id: 7103, note: "policy change approved by admin" },
  { id: 7104, note: "token revoked after rotation" },
];

function authUser(req) {
  return tokens.get((req.headers.authorization ?? "").replace(/^Bearer\s+/, "")) ?? null;
}

function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}"));
      } catch {
        resolve({});
      }
    });
  });
}

function openapiPaths() {
  const paths = {};
  for (let n = 1; n <= 18; n += 1) {
    paths[`/api/queue-${String(n).padStart(2, "0")}`] = {
      get: { summary: `队列 ${n} 的条目（仅本人）` },
    };
  }
  paths["/api/contracts"] = { get: { summary: "合同列表（仅本人）" } };
  paths["/api/audit"] = {
    get: {
      summary: "审计日志检索",
      parameters: [{ name: "q", in: "query", required: true, schema: { type: "string" } }],
    },
  };
  paths["/api/login"] = { post: { summary: "登录" } };
  return paths;
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, "http://127.0.0.1");
  const send = (status, body) => {
    res.writeHead(status, { "Content-Type": "application/json" });
    res.end(JSON.stringify(body));
  };
  const user = authUser(req);

  if (req.method === "POST" && url.pathname === "/api/login") {
    const body = await readBody(req);
    const u = accounts[body.email];
    if (!u || u.password !== body.password) return send(401, { error: "bad credentials" });
    const token = `tok-${u.id}-${Math.random().toString(36).slice(2, 8)}`;
    tokens.set(token, u);
    return send(200, { authentication: { token, user: { id: u.id, role: u.role, email: u.email } } });
  }

  if (req.method === "GET" && url.pathname === "/openapi.json") {
    return send(200, {
      openapi: "3.0.0",
      info: { title: "queue-shop", version: "1.0.0" },
      paths: openapiPaths(),
    });
  }

  if (req.method === "GET" && url.pathname === "/") return send(200, { service: "queue-shop" });

  const queueList = url.pathname.match(/^\/api\/queue-(\d{2})$/);
  if (queueList && req.method === "GET") {
    if (!user) return send(401, { error: "unauthorized" });
    const queue = `queue-${queueList[1]}`;
    return send(200, { items: queueItems.filter((i) => i.queue === queue && i.userId === user.id) });
  }
  const queueDetail = url.pathname.match(/^\/api\/queue-(\d{2})\/(\d+)$/);
  if (queueDetail && req.method === "GET") {
    if (!user) return send(401, { error: "unauthorized" });
    const item = queueItems.find(
      (i) => i.queue === `queue-${queueDetail[1]}` && i.id === Number(queueDetail[2])
    );
    if (!item) return send(404, { error: "not found" });
    if (item.userId !== user.id) return send(403, { error: "forbidden" }); // 归属校验：跨用户读取被拒
    return send(200, { ...item });
  }

  if (req.method === "GET" && url.pathname === "/api/contracts") {
    if (!user) return send(401, { error: "unauthorized" });
    return send(200, { items: contracts.filter((c) => c.userId === user.id) });
  }
  const contractDetail = url.pathname.match(/^\/api\/contracts\/(\d+)$/);
  if (contractDetail && req.method === "GET") {
    if (!user) return send(401, { error: "unauthorized" });
    const contract = contracts.find((c) => c.id === Number(contractDetail[1]));
    if (!contract) return send(404, { error: "not found" });
    return send(200, { ...contract }); // 缺归属校验：任何登录身份都能按 ID 读到别人的合同
  }

  if (req.method === "GET" && url.pathname === "/api/audit") {
    if (!user) return send(401, { error: "unauthorized" });
    const raw = url.searchParams.get("q");
    if (raw == null) return send(400, { error: "q required" });
    // 生产里这里是 `WHERE note LIKE '%${raw}%'` 的字符串拼接；这里用等价匹配模拟：
    // 只有真的闭合引号并追加布尔条件才会改变结果集，普通检索字面量按 LIKE 处理
    if (raw.startsWith("' OR 1=1--")) return send(200, { items: auditRows });
    if (raw.startsWith("' OR 1=2--")) return send(200, { items: [] });
    return send(200, { items: auditRows.filter((r) => r.note.includes(raw)) });
  }

  return send(404, { error: "not found" });
});

server.listen(Number(process.env.PORT ?? 0), "127.0.0.1", () => {
  console.log(`[queue-shop] listening on port ${server.address().port}`);
});
