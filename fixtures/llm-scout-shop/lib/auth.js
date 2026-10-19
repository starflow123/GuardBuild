import crypto from "node:crypto";
import { store, findUserById, findUserByEmail, publicUser } from "./data.js";

function createSession(user) {
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
