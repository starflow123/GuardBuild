import { initTRPC, TRPCError } from "@trpc/server";
import type { CreateExpressContextOptions } from "@trpc/server/adapters/express";
import superjson from "superjson";
import { authenticate } from "../auth.mjs";

/**
 * tRPC 基础装配（v11 写法）：initTRPC + superjson transformer + 三级过程构建器。
 *
 * transformer 决定线上形态：input 必须是 {"json": 原值}，响应 data 亦为 {json, meta?}。
 * 中间件在 input 校验之前执行——因此未登录时返回 401，而不是 400。
 */

export type Context = { user: { id: string; role: string } | null };

export async function createContext({ req }: CreateExpressContextOptions): Context {
  const session = authenticate(req);
  return { user: session?.user ?? null };
}

const t = initTRPC.context<Context>().create({
  transformer: superjson,
  errorFormatter({ shape, error }) {
    return { ...shape, message: error.message };
  },
});

export const router = t.router;

/** 匿名可用（登录/健康检查等） */
export const publicProcedure = t.procedure;

/** 需要登录：无会话直接抛 UNAUTHORIZED */
const isAuthed = t.middleware(({ ctx, next }) => {
  if (!ctx.user) throw new TRPCError({ code: "UNAUTHORIZED", message: "未登录" });
  return next({ ctx: { ...ctx, user: ctx.user } });
});

/** 需要管理员角色 */
const isAdmin = t.middleware(({ ctx, next }) => {
  if (ctx.user?.role !== "admin") throw new TRPCError({ code: "FORBIDDEN", message: "仅管理员可访问" });
  return next();
});

export const protectedProcedure = t.procedure.use(isAuthed);
export const adminProcedure = t.procedure.use(isAuthed).use(isAdmin);
