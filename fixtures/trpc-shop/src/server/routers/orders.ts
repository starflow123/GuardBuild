import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { router, protectedProcedure } from "../trpc";
import { orderRepo } from "../repo";
import { store } from "../../store.mjs";

/**
 * 订单过程：列表按归属过滤，详情/取消只按 ID 取数——归属校验缺失（本靶场复刻的越权点）。
 */
export const ordersRouter = router({
  list: protectedProcedure.query(async ({ ctx }) => {
    return { orders: store.orders.filter((o: any) => o.userId === ctx.user.id) };
  }),

  byId: protectedProcedure
    .input(z.object({ id: z.number() }))
    .query(async ({ input }) => {
      const order = orderRepo.findById(input.id); // 漏洞：未校验 order.userId 与当前用户
      if (!order) throw new TRPCError({ code: "NOT_FOUND", message: "订单不存在" });
      return { order };
    }),

  cancel: protectedProcedure
    .input(z.object({ orderId: z.number() }))
    .mutation(async ({ input }) => {
      const order = orderRepo.findById(input.orderId); // 漏洞：未校验归属即可取消他人订单
      if (!order) throw new TRPCError({ code: "NOT_FOUND", message: "订单不存在" });
      if (order.status !== "paid") throw new TRPCError({ code: "CONFLICT", message: "当前订单状态不可取消" });
      return { ok: true, order: orderRepo.markCancelled(order.id) };
    }),
});
