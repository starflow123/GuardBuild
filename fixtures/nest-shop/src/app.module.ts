import { Module } from "@nestjs/common";
import { AuthController } from "./auth/auth.controller";
import { AuthService } from "./auth/auth.service";
import { OrdersController } from "./orders/orders.controller";
import { OrdersService } from "./orders/orders.service";
import { PrismaService } from "./prisma.service";

@Module({
  controllers: [AuthController, OrdersController],
  providers: [AuthService, OrdersService, PrismaService],
})
export class AppModule {}
