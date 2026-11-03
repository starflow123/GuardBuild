// 内存数据层（演示用）。写面靶场刻意让「读取」有归属校验、「改写 / 删除」没有。
export const store = {
  users: [
    { id: "u_1", email: "alice@write.shop", password: "alice123", role: "user" },
    { id: "u_2", email: "bob@write.shop", password: "bob123", role: "user" },
  ],
  orders: [
    { id: 7, userId: "u_2", note: "gift", status: "new", amount: 120 },
    { id: 8, userId: "u_2", note: "receipt", status: "paid", amount: 240 },
    { id: 10, userId: "u_2", note: "misc", status: "shipped", amount: 360 },
    { id: 9, userId: "u_1", note: "mine", status: "new", amount: 50 },
  ],
  sessions: new Map(),
};

export function findUserByEmail(email) {
  return store.users.find((u) => u.email === email) || null;
}

export function findUserById(id) {
  return store.users.find((u) => u.id === id) || null;
}

export function findOrderById(id) {
  return store.orders.find((o) => o.id === id) || null;
}

export function ordersOf(user) {
  return store.orders.filter((o) => o.userId === user.id);
}

// 归属比对藏在 helper 里：静态层看不出这是「已做归属校验」，运行期却真的挡得住
export function sameOwner(order, user) {
  return order.userId === user.id;
}

export function dropOrder(order) {
  const idx = store.orders.indexOf(order);
  if (idx < 0) return false;
  store.orders.splice(idx, 1);
  return true;
}

export function publicUser(user) {
  return { id: user.id, email: user.email, role: user.role };
}
