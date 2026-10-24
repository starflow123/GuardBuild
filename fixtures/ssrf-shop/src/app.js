import { randomUUID } from "node:crypto";

/*
 * SSRFShop：复刻「URL 预览」业务的常见漏洞形态。
 * GET /api/preview?url=… 直接把请求参数交给 fetch 发起请求。
 * GB_SSRF_HARDENED=1 时只允许 api.example.com，用于验证修复后的行为（静态候选仍在）。
 */

const HARDENED = process.env.GB_SSRF_HARDENED === "1";
const ALLOWED_HOST = "api.example.com";

const USERS = [
  { id: 1, username: "alice", password: "alice123", role: "user" },
  { id: 2, username: "bob", password: "bob123", role: "user" },
  { id: 3, username: "admin", password: "admin123", role: "admin" },
];
const sessions = new Map();

function json(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(payload),
  });
  res.end(payload);
}

function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      if (!raw) return resolve({});
      try {
        resolve(JSON.parse(raw));
      } catch {
        resolve({});
      }
    });
  });
}

function login(username, password) {
  const user = USERS.find((u) => u.username === username && u.password === password);
  if (!user) return null;
  const token = randomUUID();
  sessions.set(token, user);
  return { token, user: { id: user.id, username: user.username, role: user.role } };
}

function authenticate(req) {
  const header = req.headers.authorization ?? "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  return sessions.get(token) ?? null;
}

/** 修复形态：解析 URL 后做协议与主机白名单校验，拒绝内网/环回地址 */
function assertAllowedTarget(raw) {
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    return { ok: false, status: 400, error: "URL 不合法" };
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return { ok: false, status: 403, error: "仅允许 http/https" };
  }
  if (parsed.hostname !== ALLOWED_HOST) {
    return { ok: false, status: 403, error: "主机不在白名单" };
  }
  return { ok: true };
}

export async function handleRequest(req, res) {
  const url = new URL(req.url, "http://127.0.0.1");
  const pathname = url.pathname;
  const method = req.method.toUpperCase();
  const auth = authenticate(req);

  if (method === "GET" && pathname === "/api/health") {
    return json(res, 200, { ok: true, service: "ssrf-shop" });
  }

  if (method === "POST" && pathname === "/api/login") {
    const body = await readBody(req);
    const result = login(body.username, body.password);
    if (!result) return json(res, 401, { error: "用户名或密码错误" });
    return json(res, 200, { token: result.token, user: result.user });
  }

  if (method === "GET" && pathname === "/api/preview") {
    if (!auth) return json(res, 401, { error: "未登录" });
    const target = url.searchParams.get("url") ?? "";
    if (!target) return json(res, 400, { error: "缺少 url 参数" });
    if (HARDENED) {
      const verdict = assertAllowedTarget(target);
      if (!verdict.ok) return json(res, verdict.status, { error: verdict.error });
    }
    try {
      const upstream = await fetch(target);
      const body = await upstream.text();
      return json(res, 200, { url: target, status: upstream.status, preview: body.slice(0, 300) });
    } catch (err) {
      return json(res, 502, { error: "上游请求失败", detail: String(err?.message ?? err) });
    }
  }

  return json(res, 404, { error: "not found", path: pathname });
}
