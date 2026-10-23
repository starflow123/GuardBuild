#!/usr/bin/env node
/**
 * 黑盒宽攻击面靶场（fixtures/wide-shop）：只为验证「引擎的探测族能不能打到真实漏洞」而存在。
 *
 * 每一段都对应一类此前覆盖不到的形态，故意做成「看起来像生产代码」的写法：
 *   - /api/admin/users     只校验登录、不校验角色（垂直越权）
 *   - /api/orders/:id      详情/改/删不做归属校验（读写删三类跨用户）
 *   - /api/messages        读要登录、写与删不校验身份（未认证写入 + 匿名删除）
 *   - /api/invoices?year=  数字语境拼 SQL（字符串型 payload 一律 400，只有布尔表达式能进）
 *   - /api/documents?name= 安全过滤器只看第一次解码的结果，应用自己再解一次（二次编码穿越）
 *   - /openapi.json        声明 year/name 两个查询参数（探测按声明参数打，而不是靠猜）
 *
 * 注入/穿越两端都要求登录：匿名可读会让「未认证读取」与「参数注入」两类证据混在一起，
 * 加固轮的「不应有任何 finding」也就无法断言。
 *
 * GB_WIDE_HARDENED=1 时以上每一段都补上正确的授权/归属/参数化校验，用于「不该报」的那一轮。
 */
import { createServer } from "node:http";

const hardened = process.env.GB_WIDE_HARDENED === "1";

const accounts = {
  "alice@wide.shop": { id: 1, email: "alice@wide.shop", password: "alice123", role: "user" },
  "bob@wide.shop": { id: 2, email: "bob@wide.shop", password: "bob123", role: "user" },
  "carol@wide.shop": { id: 3, email: "carol@wide.shop", password: "carol123", role: "admin" },
};
const tokens = new Map();
const orders = [
  { id: 101, userId: 1, note: "alice-note" },
  { id: 102, userId: 2, note: "bob-note" },
];
const messages = [{ id: 900, userId: 1, body: "seed-message" }];
let nextMessageId = 901;
const invoices = [
  { id: 1, year: 2024, total: 100 },
  { id: 2, year: 2024, total: 220 },
  { id: 3, year: 2025, total: 340 },
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
      info: { title: "wide-shop", version: "1.0.0" },
      paths: {
        "/api/invoices": { get: { parameters: [{ name: "year", in: "query" }] } },
        "/api/documents": { get: { parameters: [{ name: "name", in: "query" }] } },
      },
    });
  }

  if (req.method === "GET" && url.pathname === "/") return send(200, { service: "wide-shop", hardened });

  if (req.method === "GET" && url.pathname === "/api/admin/users") {
    if (!user) return send(401, { error: "unauthorized" });
    if (hardened && user.role !== "admin") return send(403, { error: "forbidden" });
    return send(200, { items: Object.values(accounts).map(({ id, email }) => ({ id, email })) });
  }

  if (req.method === "GET" && url.pathname === "/api/orders") {
    if (!user) return send(401, { error: "unauthorized" });
    return send(200, { items: orders.filter((o) => o.userId === user.id) });
  }
  const orderDetail = url.pathname.match(/^\/api\/orders\/(\d+)$/);
  if (orderDetail) {
    if (!user) return send(401, { error: "unauthorized" });
    const order = orders.find((x) => x.id === Number(orderDetail[1]));
    if (!order) return send(404, { error: "not found" });
    if (hardened && order.userId !== user.id) return send(403, { error: "forbidden" });
    if (req.method === "GET") return send(200, { ...order });
    if (req.method === "PATCH" || req.method === "PUT") {
      const body = await readBody(req);
      if (typeof body.note === "string") order.note = body.note;
      return send(200, { ...order });
    }
    if (req.method === "DELETE") {
      orders.splice(orders.indexOf(order), 1);
      return send(200, { deleted: true });
    }
    return send(405, { error: "method not allowed" });
  }

  if (url.pathname === "/api/messages") {
    if (req.method === "GET") {
      if (!user) return send(401, { error: "unauthorized" });
      return send(200, { items: messages });
    }
    if (req.method === "POST") {
      if (hardened) return send(401, { error: "unauthorized" });
      const body = await readBody(req);
      if (typeof body.body !== "string") return send(400, { error: "bad body" });
      const msg = { id: nextMessageId++, userId: null, body: body.body };
      messages.push(msg);
      return send(201, { ...msg });
    }
  }
  const messageDetail = url.pathname.match(/^\/api\/messages\/(\d+)$/);
  if (messageDetail) {
    const msg = messages.find((m) => m.id === Number(messageDetail[1]));
    if (!msg) return send(404, { error: "not found" });
    if (hardened) return send(401, { error: "unauthorized" });
    if (req.method === "DELETE") {
      messages.splice(messages.indexOf(msg), 1);
      return send(200, { deleted: true });
    }
    return send(405, { error: "method not allowed" });
  }

  // 数字语境拼接（这里用等价正则模拟）：非数字一律 400，带引号的字符串 payload 打不进去
  if (url.pathname === "/api/invoices") {
    if (!user) return send(401, { error: "unauthorized" });
    if (req.method !== "GET") return send(404, { error: "not found" });
    const raw = url.searchParams.get("year");
    if (raw == null) return send(200, { items: invoices });
    // 生产里这里是 `WHERE year = ${raw}` 的字符串拼接；这里用等价的正则模拟「数字语境」
    const m = raw.match(/^(\d+)(?:\s+or\s+(\d+)\s*=\s*(\d+))?$/i);
    if (!m || (hardened && m[2] !== undefined)) return send(400, { error: "year must be numeric" });
    const all = m[2] !== undefined && Number(m[2]) === Number(m[3]);
    return send(200, { items: all ? invoices : invoices.filter((i) => i.year === Number(m[1])) });
  }

  if (url.pathname === "/api/documents") {
    if (!user) return send(401, { error: "unauthorized" });
    if (req.method !== "GET") return send(404, { error: "not found" });
    const v = url.searchParams.get("name") ?? "";
    if (v.includes("../") || v.includes("..\\")) return send(400, { error: "bad path" });
    let real = v;
    if (!hardened) {
      try {
        real = decodeURIComponent(v); // 二次解码：过滤器看过的串与真正读文件的串不是同一个
      } catch {
        /* 保留原串 */
      }
    }
    if (real.includes("../") || real.includes("..\\")) {
      return send(200, { content: "root:x:0:0:root:/root:/bin/bash" });
    }
    return send(200, { content: "quarterly report" });
  }

  return send(404, { error: "not found" });
});

server.listen(Number(process.env.PORT ?? 0), "127.0.0.1", () => {
  console.log(`[wide-shop] listening on port ${server.address().port}${hardened ? " (hardened)" : ""}`);
});
