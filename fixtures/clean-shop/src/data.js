export const store = {
  users: [
    { id: "u_1001", username: "alice", password: "alice123", role: "user", displayName: "Alice" },
    { id: "u_1002", username: "bob", password: "bob123", role: "user", displayName: "Bob" },
    { id: "u_9000", username: "admin", password: "admin123", role: "admin", displayName: "管理员" },
  ],
  orders: [
    { id: 5001, userId: "u_1001", title: "机械键盘", amount: 699, status: "paid", address: "北京市朝阳区xxx" },
    { id: 5002, userId: "u_1002", title: "人体工学椅", amount: 1899, status: "paid", address: "上海市浦东新区xxx" },
    { id: 5003, userId: "u_1001", title: "显示器支架", amount: 249, status: "shipped", address: "北京市朝阳区xxx" },
    { id: 5004, userId: "u_1001", title: "USB-C 扩展坞", amount: 399, status: "paid", address: "北京市朝阳区xxx" },
    { id: 5005, userId: "u_1002", title: "降噪耳机", amount: 1299, status: "paid", address: "上海市浦东新区xxx" },
    { id: 5006, userId: "u_1002", title: "机械表", amount: 2999, status: "paid", address: "上海市浦东新区xxx" },
  ],
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
