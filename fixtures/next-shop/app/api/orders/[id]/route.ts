import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth";
import { db } from "../../../../src/db";

export async function GET(req: NextRequest, { params }: { params: { id: string } }) {
  const session = await getServerSession();
  if (!session) {
    return NextResponse.json({ error: "未登录" }, { status: 401 });
  }
  const order = await db.order.findUnique({ where: { id: Number(params.id) } });
  if (!order) {
    return NextResponse.json({ error: "订单不存在" }, { status: 404 });
  }
  return NextResponse.json({ order });
}
