// 内存数据层（演示用）。真实项目由 Prisma/Drizzle 提供，这里零依赖便于对照。

export const store = {
  users: [
    { id: "u_2001", email: "alice@gqlshop.dev", password: "alice123", role: "user", name: "Alice" },
    { id: "u_2002", email: "bob@gqlshop.dev", password: "bob123", role: "user", name: "Bob" },
    { id: "u_9000", email: "admin@gqlshop.dev", password: "admin123", role: "admin", name: "管理员" },
  ],
  orders: [
    { id: 6001, userId: "u_2001", title: "机械键盘", amount: 699, status: "paid", address: "北京市朝阳区xxx" },
    { id: 6002, userId: "u_2001", title: "显示器支架", amount: 249, status: "shipped", address: "北京市朝阳区xxx" },
    { id: 6004, userId: "u_2001", title: "USB-C 扩展坞", amount: 399, status: "paid", address: "北京市朝阳区xxx" },
    { id: 7001, userId: "u_2002", title: "人体工学椅", amount: 1899, status: "paid", address: "上海市浦东新区xxx" },
    { id: 7003, userId: "u_2002", title: "降噪耳机", amount: 1299, status: "shipped", address: "上海市浦东新区xxx" },
    { id: 7005, userId: "u_2002", title: "便携显示器", amount: 1599, status: "paid", address: "上海市浦东新区xxx" },
  ],
  sessions: new Map(),
};

export function findUserByEmail(email) {
  return store.users.find((u) => u.email === email) || null;
}

export function findOrderById(id) {
  const n = Number(id);
  return store.orders.find((o) => o.id === n) || null;
}

export function listOrdersOf(userId) {
  return store.orders.filter((o) => o.userId === userId);
}

/** 小票按订单号索引：订单存在即有小票，取消状态与订单保持一致 */
export function findReceiptByOrderId(id) {
  const order = findOrderById(id);
  if (!order) return null;
  return {
    id: order.id,
    userId: order.userId,
    title: order.title,
    amount: order.amount,
    status: order.status,
    address: order.address,
  };
}

export function publicUser(user) {
  return { id: user.id, email: user.email, name: user.name, role: user.role };
}
