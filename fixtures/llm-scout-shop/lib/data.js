export const store = {
  users: [
    { id: "u_1", username: "alice", email: "alice@llm.shop", password: "alice123", role: "user" },
    { id: "u_2", username: "bob", email: "bob@llm.shop", password: "bob123", role: "user" },
  ],
  orders: [
    { id: 101, userId: "u_1", title: "alice 的键盘", amount: 399, status: "paid", address: "北京市海淀区" },
    { id: 102, userId: "u_2", title: "bob 的椅子", amount: 899, status: "paid", address: "上海市徐汇区" },
    { id: 103, userId: "u_1", title: "alice 的显示器", amount: 1299, status: "shipped", address: "北京市海淀区" },
    { id: 104, userId: "u_2", title: "bob 的耳机", amount: 599, status: "paid", address: "上海市徐汇区" },
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

export function publicUser(user) {
  return { id: user.id, username: user.username, email: user.email, role: user.role };
}
