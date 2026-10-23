/**
 * 构建脚本：把人工维护的种子数据规整成运行期模块 build/config.js。
 * 真实项目里这一步通常是 codegen / 配置编译；本靶场用它制造「不构建就起不来」的接入障碍。
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const seedFile = path.join(root, "config", "orders.seed.json");
const outFile = path.join(root, "build", "config.js");

const seed = JSON.parse(readFileSync(seedFile, "utf8"));
const orders = (seed.orders ?? []).map((o) => ({
  id: Number(o.id),
  userId: String(o.userId),
  title: String(o.title),
  amount: Number(o.amount),
  amountCents: Math.round(Number(o.amount) * 100),
  status: String(o.status),
  address: String(o.address ?? ""),
}));

const text = `// 由 npm run build 生成，请勿手工修改。源数据：config/orders.seed.json
export const buildConfig = {
  currency: ${JSON.stringify(seed.currency ?? "CNY")},
  orderCount: ${orders.length},
  orders: ${JSON.stringify(orders, null, 2)},
};
`;

mkdirSync(path.dirname(outFile), { recursive: true });
writeFileSync(outFile, text);
console.log(`已生成 build/config.js（订单种子 ${orders.length} 条）`);
