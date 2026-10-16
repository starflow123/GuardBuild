import crypto from "node:crypto";
import { findUserByEmail, publicUser, store } from "./store.mjs";

/** 登录：校验邮箱密码 → 签发会话令牌（与 JwtAuthGuard 的 req.user 注入语义对应） */
export function login(email, password) {
  const user = findUserByEmail(String(email ?? ""));
  if (!user || user.password !== password) return null;
  const token = crypto.randomBytes(24).toString("hex");
  store.sessions.set(token, user.id);
  return { token, user: publicUser(user) };
}

/** 从 Authorization: Bearer <token> 还原当前用户（未登录返回 null） */
export function authenticate(req) {
  const header = String(req.headers.authorization ?? "");
  const m = /^Bearer\s+(.+)$/.exec(header);
  if (!m) return null;
  const userId = store.sessions.get(m[1]);
  if (!userId) return null;
  const user = store.users.find((u) => u.id === userId) ?? null;
  return user ? { user } : null;
}
