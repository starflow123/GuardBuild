import { router, adminProcedure } from "../trpc";
import { orderRepo } from "../repo";

/** 管理端：adminProcedure 守卫（角色校验在中间件），可览全站订单 */
export const adminRouter = router({
  listAll: adminProcedure.query(async () => {
    return { orders: orderRepo.findAll() };
  }),

  stats: adminProcedure.query(async () => {
    return { total: orderRepo.findAll().length };
  }),
});
