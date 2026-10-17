import crypto from "node:crypto";
import { findUserByEmail, publicUser, store } from "./store.mjs";

/** 登录：校验邮箱密码 → 签发会话令牌（对应 Mutation.login 的返回值） */
export function login(email, password) {
  const user = findUserByEmail(String(email ?? ""));
  if (!user || user.password !== password) return null;
  const token = crypto.randomBytes(24).toString("hex");
  store.sessions.set(token, user.id);
  return { token, user: publicUser(user) };
}

/** 从 Authorization: Bearer <token> 还原请求者（无会话返回 null，即匿名上下文） */
export function authenticate(req) {
  const header = String(req.headers?.authorization ?? req.headers?.get?.("authorization") ?? "");
  const m = /^Bearer\s+(.+)$/.exec(header);
  if (!m) return null;
  const userId = store.sessions.get(m[1]);
  if (!userId) return null;
  const user = store.users.find((u) => u.id === userId) ?? null;
  return user ? { user: publicUser(user) } : null;
}
