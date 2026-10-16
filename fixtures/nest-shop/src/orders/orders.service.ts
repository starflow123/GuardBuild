import { Injectable } from "@nestjs/common";
import { PrismaService } from "../prisma.service";
import type { Order } from "../prisma.service";

@Injectable()
export class OrdersService {
  constructor(private readonly prisma: PrismaService) {}

  findAll(args: { where: { userId: string } }): Promise<Order[]> {
    return this.prisma.order.findMany(args);
  }

  findOne(id: number): Promise<Order | null> {
    return this.prisma.order.findUnique({ where: { id } });
  }

  markCancelled(id: number): Promise<Order | null> {
    return this.prisma.order.update({ where: { id }, data: { status: "cancelled" } });
  }
}
