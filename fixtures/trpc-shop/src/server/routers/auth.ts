import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { router, publicProcedure, protectedProcedure } from "../trpc";
import { sessionRepo } from "../repo";

/** 认证过程：登录为 publicProcedure（无中间件），会话令牌由业务层签发 */
export const authRouter = router({
  login: publicProcedure
    .input(z.object({ email: z.string().email(), password: z.string().min(6) }))
    .mutation(async ({ input }) => {
      const result = sessionRepo.signIn(input.email, input.password);
      if (!result) throw new TRPCError({ code: "UNAUTHORIZED", message: "邮箱或密码错误" });
      return { token: result.token, user: result.user };
    }),

  me: protectedProcedure.query(async ({ ctx }) => {
    return { user: ctx.user };
  }),
});
