import crypto from "node:crypto";
import { store, findUserById, findUserByEmail, publicUser } from "./data.js";
import { config } from "./config.js";

export function createSession(user) {
  const token = "sess_" + crypto.randomBytes(18).toString("hex");
  store.sessions.set(token, { userId: user.id, createdAt: Date.now() });
  return token;
}

export function login(email, password) {
  const user = findUserByEmail(email);
  if (!user || user.password !== password) return null;
  const token = createSession(user);
  return { token, user: publicUser(user) };
}

function cookieToken(req) {
  const raw = req.headers["cookie"] || "";
  for (const part of raw.split(";")) {
    const [name, ...rest] = part.trim().split("=");
    if (name === "sid") return rest.join("=");
  }
  return "";
}

// 认证中间件：解析 Authorization 或 Cookie 会话，返回当前用户或 null
export function authenticate(req) {
  const header = req.headers["authorization"] || "";
  const bearer = header.startsWith("Bearer ") ? header.slice(7) : "";
  const token = bearer || cookieToken(req);
  if (!token) return null;
  const session = store.sessions.get(token);
  if (!session) return null;
  const user = findUserById(session.userId);
  if (!user) return null;
  return { user, token };
}

export function sessionSecret() {
  return config.sessionSecret;
}
