import jwt from "./jwtlib.js";
import { signToken, verifyToken } from "./verify.js";

/*
 * JwtShop：复刻「只解码、不验签」的 JWT 认证缺陷。
 * 受认证端点用 jwt.decode 读取载荷就当作身份，任何 alg=none/无效签名令牌都会被接受。
 * GB_JWT_HARDENED=1 时改用 verifyToken（固定 HS256 + 校验签名），用于验证修复后的行为（静态候选仍在）。
 */

const HARDENED = process.env.GB_JWT_HARDENED === "1";

const USERS = [
  { id: 1, username: "alice", password: "alice123", role: "user" },
  { id: 2, username: "bob", password: "bob123", role: "user" },
  { id: 9, username: "root", password: "root123", role: "admin" },
];

function json(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(payload),
  });
  res.end(payload);
}

function readJson(req) {
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

function tokenOf(req) {
  const raw = String(req.headers.authorization ?? "");
  return raw.startsWith("Bearer ") ? raw.slice("Bearer ".length).trim() : null;
}

function authenticate(req) {
  const token = tokenOf(req);
  if (!token) return null;
  try {
    // 修复前：只解载荷，签名与算法都不校验
    const payload = HARDENED ? verifyToken(token) : jwt.decode(token);
    if (!payload) return null;
    return {
      id: payload.sub ?? null,
      username: payload.username ?? payload.name ?? null,
      role: payload.role ?? "user",
    };
  } catch {
    return null;
  }
}

export async function handleRequest(req, res) {
  const url = new URL(req.url, "http://127.0.0.1");
  const pathname = url.pathname;
  const method = req.method.toUpperCase();
  const auth = authenticate(req);

  if (method === "GET" && pathname === "/api/health") {
    return json(res, 200, { ok: true, service: "jwt-shop" });
  }

  if (method === "POST" && pathname === "/api/login") {
    const body = await readJson(req);
    const user = USERS.find((u) => u.username === body.username && u.password === body.password);
    if (!user) return json(res, 401, { error: "用户名或密码错误" });
    return json(res, 200, {
      token: signToken({ sub: String(user.id), username: user.username, role: user.role }),
      user: { id: user.id, username: user.username, role: user.role },
    });
  }

  if (method === "GET" && pathname === "/api/me") {
    if (!auth) return json(res, 401, { error: "未登录" });
    return json(res, 200, { user: auth, scope: "profile" });
  }

  if (method === "GET" && pathname === "/api/admin/users") {
    if (!auth) return json(res, 401, { error: "未登录" });
    if (auth.role !== "admin") return json(res, 403, { error: "需要管理员权限" });
    return json(res, 200, {
      viewer: auth.username,
      users: USERS.map(({ password, ...rest }) => rest),
    });
  }

  return json(res, 404, { error: "not found", path: pathname });
}
