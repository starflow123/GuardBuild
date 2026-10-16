import { NextRequest, NextResponse } from "next/server";
import { login } from "../../../src/auth.mjs";

export async function POST(req: NextRequest) {
  const { email, password } = await req.json();
  const result = login(email, password);
  if (!result) {
    return NextResponse.json({ error: "邮箱或密码错误" }, { status: 401 });
  }
  return NextResponse.json({ token: result.token, user: result.user });
}
