import { store, findOrderById, findUserByEmail } from "../store.mjs";

/**
 * 数据访问层（Prisma/Drizzle 的等价手写形态）：
 * 按 ID 取单条不校验归属，归属过滤由调用方（过程实现）负责——本项目里 byId/cancel 漏了这一步。
 */
export const orderRepo = {
  findAll: () => store.orders,
  findById: (id: number) => findOrderById(id),
  findManyByUser: (userId: string) => store.orders.filter((o: any) => o.userId === userId),
  markCancelled: (id: number) => {
    const order = findOrderById(id);
    if (order) order.status = "cancelled";
    return order;
  },
};

export const sessionRepo = {
  signIn: (email: string, password: string) => {
    const user = findUserByEmail(email);
    if (!user || user.password !== password) return null;
    const token = Math.random().toString(36).slice(2) + Date.now().toString(36);
    store.sessions.set(token, user.id);
    return { token, user };
  },
};
