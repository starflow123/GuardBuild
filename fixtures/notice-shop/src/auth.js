import crypto from "node:crypto";
import { findUserByUsername, sessions, users } from "./data.js";

/** 会话只走 Cookie：这套靶子没有令牌接口，登录按 cookieAuth 形态下发 Set-Cookie */
export function login(username, password) {
  const user = findUserByUsername(username);
  if (!user || user.password !== password) return null;
  const sid = crypto.randomBytes(12).toString("hex");
  sessions.set(sid, user.id);
  return { sid, user };
}

export function authenticate(req) {
  const sid = /sid=([^;]+)/.exec(String(req.headers.cookie ?? ""))?.[1];
  if (!sid) return null;
  const userId = sessions.get(sid);
  if (!userId) return null;
  return users.find((u) => u.id === userId) ?? null;
}
