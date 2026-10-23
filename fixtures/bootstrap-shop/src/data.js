// 内存数据层（演示用，零依赖）。订单来自构建产物 build/config.js，由 npm run build 生成。
import { buildConfig } from "../build/config.js";

export const store = {
  users: [
    { id: "u_1001", username: "alice", password: "alice123", role: "user", displayName: "Alice" },
    { id: "u_1002", username: "bob", password: "bob123", role: "user", displayName: "Bob" },
    { id: "u_9000", username: "admin", password: "admin123", role: "admin", displayName: "管理员" },
  ],
  orders: buildConfig.orders.map((o) => ({ ...o })),
  sessions: new Map(),
};

export function findUserByName(username) {
  return store.users.find((u) => u.username === username) || null;
}

export function findUserById(id) {
  return store.users.find((u) => u.id === id) || null;
}

export function findOrderById(id) {
  return store.orders.find((o) => o.id === id) || null;
}

export function publicUser(user) {
  return { id: user.id, username: user.username, role: user.role, displayName: user.displayName };
}
