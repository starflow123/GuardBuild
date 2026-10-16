import { createClient } from "@supabase/supabase-js";

// 客户端初始化：URL 与 anon key 均来自「可公开」的前端环境变量。
// 若数据库表未启用 RLS（行级安全），任何持有该 anon key 的人都能匿名读取全表数据。
export const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL,
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY
);

// 读取个人资料（本应仅本人可见，实际依赖 RLS 策略约束）
export async function getProfiles() {
  const { data, error } = await supabase.from("profiles").select("*");
  if (error) throw error;
  return data;
}

// 读取订单列表（本应仅本人可见）
export async function getOrders() {
  const { data } = await supabase.from("orders").select("*").limit(50);
  return data;
}
