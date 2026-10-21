/**
 * 同源重定向跟随：FastAPI/Starlette 的 redirect_slashes、Express 的尾斜杠跳转都会先回
 * 307/301，攻击用例直接按原状态判定会把「框架跳转」误记为不可复现。
 * 只跟同源、只跟 GET 或 307/308（保方法保体），最多 max 跳。
 */
export function locationOf(res) {
  const headers = res?.headers ?? {};
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === "location" && typeof v === "string" && v) return v;
  }
  return null;
}

export async function followRedirects(send, url, { method = "GET", max = 2 } = {}) {
  let current = url;
  let res = await send(current);
  const hops = [];
  for (let i = 0; i < max; i += 1) {
    const status = res?.status ?? 0;
    if (![301, 302, 303, 307, 308].includes(status)) break;
    if (method !== "GET" && status !== 307 && status !== 308) break;
    const loc = locationOf(res);
    if (!loc) break;
    let next;
    try {
      next = new URL(loc, current);
    } catch {
      break;
    }
    if (next.origin !== new URL(current).origin) break;
    hops.push(`${status} ${next.pathname}${next.search}`);
    current = next.toString();
    res = await send(current);
  }
  return { res, url: current, hops };
}
