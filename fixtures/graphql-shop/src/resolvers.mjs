import { GraphQLError } from "graphql";
import { login } from "./auth.mjs";
import { findOrderById, findReceiptByOrderId, store } from "./store.mjs";

/*
 * schema-first 解析器映射表（express-graphql / Apollo Server 的经典结构）。
 * 鉴权线索分两处：SDL 字段指令（@auth / @hasRole / @skipAuth）决定「要不要登录」，
 * 本文件的函数体决定「取数时有没有核对归属」。GuardBuild 的 GraphQL 适配器会合并两层信号，
 * 因此这里刻意保留四种真实写法：
 *   order / cancelOrder —— 只按 id 定位对象（越权）
 *   myOrders            —— 返回体按归属过滤（正确基线）
 *   adminOrders         —— 角色守卫（管理端）
 */

/** 只关心状态是否可取消，与订单属于谁无关 */
function mustBeCancellable(order) {
  if (order.status !== "paid") {
    throw new GraphQLError("当前订单状态不可取消", { extensions: { code: "CONFLICT" } });
  }
}

export const resolvers = {
  Query: {
    order: async (_, { id }) => {
      const order = findOrderById(id);
      if (!order) throw new GraphQLError("订单不存在", { extensions: { code: "NOT_FOUND" } });
      return order; // 复刻漏洞：取数即返回，未核对订单属于请求者
    },
    myOrders: async (_, __, ctx) => store.orders.filter((o) => o.userId === ctx.user.id),
    receipt: async (_, { id }) => {
      const receipt = findReceiptByOrderId(id);
      if (!receipt) throw new GraphQLError("小票不存在", { extensions: { code: "NOT_FOUND" } });
      return receipt; // 复刻漏洞：字段声明为 @skipAuth，无需任何凭证即可取回他人地址与金额
    },
    adminOrders: async (_, __, ctx) => {
      if (ctx.user.role !== "admin") {
        throw new GraphQLError("仅管理员可访问", { extensions: { code: "FORBIDDEN" } });
      }
      return store.orders;
    },
  },

  Mutation: {
    login: async (_, { email, password }) => {
      const session = login(email, password);
      if (!session) throw new GraphQLError("邮箱或密码错误", { extensions: { code: "UNAUTHENTICATED" } });
      return session;
    },
    cancelOrder: async (_, { id }) => {
      const order = findOrderById(id);
      if (!order) throw new GraphQLError("订单不存在", { extensions: { code: "NOT_FOUND" } });
      mustBeCancellable(order);
      order.status = "cancelled"; // 复刻漏洞：任何登录用户都能取消他人订单
      return order;
    },
    adminCancelOrder: async (_, { id }, ctx) => {
      if (ctx.user.role !== "admin") {
        throw new GraphQLError("仅管理员可访问", { extensions: { code: "FORBIDDEN" } });
      }
      const order = findOrderById(id);
      if (!order) throw new GraphQLError("订单不存在", { extensions: { code: "NOT_FOUND" } });
      mustBeCancellable(order);
      order.status = "cancelled";
      return order;
    },
  },
};

export const typeDefs = { kind: "Document", source: "schema.graphql" };
