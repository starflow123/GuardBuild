import crypto from "node:crypto";
import { store, findUserByEmail, publicUser } from "./data.js";

/** 登录：邮箱密码换会话令牌（Bearer 与 Cookie 两种携带方式都支持，与其它靶子的契约一致） */
export function login(email, password) {
  const user = findUserByEmail(email);
  if (!user || user.password !== password) return null;
  const token = crypto.randomBytes(18).toString("hex");
  store.sessions.set(token, user.id);
  return { token, user: publicUser(user) };
}

export function authenticate(req) {
  const header = String(req.headers.authorization ?? "");
  const bearer = header.startsWith("Bearer ") ? header.slice(7) : "";
  const cookieSid = /sid=([^;]+)/.exec(String(req.headers.cookie ?? ""))?.[1] ?? "";
  const token = bearer || cookieSid;
  if (!token) return null;
  const userId = store.sessions.get(token);
  if (!userId) return null;
  const user = store.users.find((u) => u.id === userId) ?? null;
  return user ? { user } : null;
}
