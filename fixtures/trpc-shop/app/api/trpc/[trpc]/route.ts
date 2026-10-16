import { fetchRequestHandler } from "@trpc/server/adapters/fetch";
import { appRouter } from "../../../../src/server/root";
import { createContext } from "../../../../src/server/trpc";

/**
 * Next.js App Router 的 tRPC 入口（v11 fetch adapter）。
 * endpoint 声明 = 所有过程的公共挂载前缀；过程路径以点连接追加在其后：
 *   GET  /api/trpc/orders.byId?input={"json":{"id":5002}}
 *   POST /api/trpc/orders.cancel  body {"json":{"orderId":5002}}
 */
const handler = (req: Request) =>
  fetchRequestHandler({
    endpoint: "/api/trpc",
    req,
    router: appRouter,
    createContext: () => createContext({ req }),
    onError({ error, path }) {
      console.error(`[trpc] ${path} → ${error.code}: ${error.message}`);
    },
  });

export { handler as GET, handler as POST };
