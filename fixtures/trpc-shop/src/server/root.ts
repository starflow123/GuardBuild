import { router } from "./trpc";
import { ordersRouter } from "./routers/orders";
import { adminRouter } from "./routers/admin";
import { authRouter } from "./routers/auth";

/** 根路由：跨文件按变量名组装（探测层据此得到 orders.byId / admin.listAll / auth.login 等点路径） */
export const appRouter = router({
  auth: authRouter,
  orders: ordersRouter,
  admin: adminRouter,
});

export type AppRouter = typeof appRouter;
