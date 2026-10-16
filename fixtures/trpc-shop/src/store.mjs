// 内存数据层（演示用）。生产环境由 Prisma/Drizzle 提供，这里零依赖便于对照。

export const store = {
  users: [
    { id: "u_1001", email: "alice@trpc.shop", password: "alice123", role: "user", name: "Alice" },
    { id: "u_1002", email: "bob@trpc.shop", password: "bob123", role: "user", name: "Bob" },
    { id: "u_9000", email: "admin@trpc.shop", password: "admin123", role: "admin", name: "管理员" },
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

export function findUserByEmail(email) {
  return store.users.find((u) => u.email === email) || null;
}

export function findOrderById(id) {
  return store.orders.find((o) => o.id === id) || null;
}

export function findOrdersByUser(userId) {
  return store.orders.filter((o) => o.userId === userId);
}

export function publicUser(user) {
  return { id: user.id, email: user.email, name: user.name, role: user.role };
}
