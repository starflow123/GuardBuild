import {
  ConflictException,
  Controller,
  Get,
  NotFoundException,
  Param,
  Post,
  Query,
  Req,
  UseGuards,
} from "@nestjs/common";
import * as fs from "node:fs";
import * as path from "node:path";
import { JwtAuthGuard } from "../auth/jwt-auth.guard";
import { OrdersService } from "./orders.service";

interface AuthedRequest {
  user: { id: string; role: string };
}

@UseGuards(JwtAuthGuard)
@Controller("orders")
export class OrdersController {
  constructor(private readonly ordersService: OrdersService) {}

  @Get()
  list(@Req() req: AuthedRequest) {
    return { orders: this.ordersService.findAll({ where: { userId: req.user.id } }) };
  }

  @Get("export")
  exportOrders(@Query("file") file: string) {
    const target = path.join(__dirname, "..", "..", "public", file);
    return fs.readFileSync(target, "utf8");
  }

  @Get(":id")
  async detail(@Param("id") id: string) {
    const order = await this.ordersService.findOne(Number(id));
    if (!order) throw new NotFoundException("订单不存在");
    return { order };
  }

  @Post(":id/cancel")
  async cancel(@Param("id") id: string) {
    const order = await this.ordersService.findOne(Number(id));
    if (!order) throw new NotFoundException("订单不存在");
    if (order.status !== "paid") throw new ConflictException("当前订单状态不可取消");
    return { ok: true, order: await this.ordersService.markCancelled(order.id) };
  }
}
