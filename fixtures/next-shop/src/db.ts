// Prisma 客户端桩：真实项目由 @prisma/client 生成（npx prisma generate）。
// 演示环境用内存数据替代数据库，接口形态与 Prisma 客户端一致。
import { store } from "./store.mjs";

export const db = {
  order: {
    async findMany({ where }: { where?: { userId?: string } } = {}) {
      return store.orders.filter((o) => !where?.userId || o.userId === where.userId);
    },
    async findUnique({ where }: { where: { id: number } }) {
      return store.orders.find((o) => o.id === where.id) ?? null;
    },
  },
};
