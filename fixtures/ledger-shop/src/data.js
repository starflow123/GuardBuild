export const store = {
  sessions: new Map(),
  users: [
    { id: 1, email: "alice@ledger.shop", password: "alice123", name: "周慕云", role: "user" },
    { id: 2, email: "bob@ledger.shop", password: "bob123", name: "韩雪", role: "user" },
    { id: 3, email: "admin@ledger.shop", password: "admin123", name: "老陈", role: "admin" },
  ],
  entries: [
    { id: 1, userId: 1, title: "云主机月费", memo: "monthly cloud subscription", amount: 268 },
    { id: 2, userId: 1, title: "域名续费", memo: "domain renewal yearly", amount: 55 },
    { id: 3, userId: 1, title: "设计外包", memo: "outsourced banner design", amount: 1800 },
    { id: 4, userId: 2, title: "服务器托管", memo: "colocation rack fee", amount: 990 },
    { id: 5, userId: 2, title: "短信服务", memo: "sms package recharge", amount: 320 },
    { id: 6, userId: 2, title: "办公用品", memo: "office supplies purchase", amount: 145 },
    { id: 7, userId: 3, title: "审计费用", memo: "annual audit service", amount: 6000 },
    { id: 8, userId: 3, title: "备份存储", memo: "offline backup storage", amount: 410 },
    { id: 9, userId: 1, title: "快递到付", memo: "courier fee on delivery", amount: 23 },
    { id: 10, userId: 2, title: "软件订阅", memo: "annual software subscription", amount: 780 },
  ],
};

export function findUserByEmail(email) {
  return store.users.find((u) => u.email === String(email ?? "").toLowerCase()) ?? null;
}

export function publicUser(user) {
  return { id: user.id, email: user.email, name: user.name, role: user.role };
}
