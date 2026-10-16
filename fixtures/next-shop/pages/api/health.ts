import type { NextApiRequest, NextApiResponse } from "next";

// Pages Router 形态示例（健康检查，公开端点）：验证 pages/api 解析不产生误报候选
export default function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method === "GET") {
    return res.status(200).json({ ok: true, service: "next-shop" });
  }
  return res.status(405).json({ error: "method not allowed" });
}
