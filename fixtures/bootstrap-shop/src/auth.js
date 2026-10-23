import crypto from "node:crypto";
import { store, findUserById, findUserByName, publicUser } from "./data.js";

export function createSession(user) {
  const token = "sess_" + crypto.randomBytes(18).toString("hex");
  store.sessions.set(token, { userId: user.id, createdAt: Date.now() });
  return token;
}

export function login(username, password) {
  const user = findUserByName(username);
  if (!user || user.password !== password) return null;
  const token = createSession(user);
  return { token, user: publicUser(user) };
}

// 认证中间件：解析 Authorization 头，返回当前用户或 null
export function authenticate(req) {
  const header = req.headers["authorization"] || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) return null;
  const session = store.sessions.get(token);
  if (!session) return null;
  const user = findUserById(session.userId);
  if (!user) return null;
  return { user, token };
}
