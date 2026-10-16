import { NextResponse } from "next/server";
import { getServerSession } from "next-auth";
import { db } from "../../../src/db";

export async function GET() {
  const session = await getServerSession();
  if (!session) {
    return NextResponse.json({ error: "未登录" }, { status: 401 });
  }
  const orders = await db.order.findMany({
    where: { userId: session.user.id },
    orderBy: { id: "desc" },
  });
  return NextResponse.json({ orders });
}
