import { Injectable } from "@nestjs/common";
import { findOrderById, store } from "./store.mjs";

export interface Order {
  id: number;
  userId: string;
  title: string;
  amount: number;
  status: string;
  address: string;
}

/** 演示用桩：真实项目为 PrismaClient 扩展；此处零依赖便于对照。 */
@Injectable()
export class PrismaService {
  order = {
    findMany: async (args: { where?: { userId?: string } }): Promise<Order[]> =>
      store.orders.filter((o) => !args?.where?.userId || o.userId === args.where.userId),
    findUnique: async (args: { where: { id: number } }): Promise<Order | null> =>
      findOrderById(args?.where?.id) ?? null,
    update: async (args: { where: { id: number }; data: { status: string } }): Promise<Order | null> => {
      const order = findOrderById(args?.where?.id);
      if (order && args?.data?.status) order.status = args.data.status;
      return order ?? null;
    },
  };
}
