import { createHmac, timingSafeEqual } from "node:crypto";

/*
 * 零依赖的最小 JWT 实现，仅覆盖靶场需要的能力：
 *  - sign：HS256
 *  - verify：只接受 HS256，可按 algorithms 固定算法，校验签名与 exp
 *  - decode：只解载荷，不校验签名（有缺陷的调用方会用它当认证）
 */

const b64 = (obj) => Buffer.from(JSON.stringify(obj)).toString("base64url");

function parseJson(part) {
  try {
    return JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
  } catch {
    return null;
  }
}

export function sign(payload, secret) {
  const head = b64({ alg: "HS256", typ: "JWT" });
  const body = b64(payload);
  const sig = createHmac("sha256", secret).update(`${head}.${body}`).digest("base64url");
  return `${head}.${body}.${sig}`;
}

export function verify(token, secret, options = {}) {
  const parts = String(token ?? "").split(".");
  if (parts.length !== 3) throw new Error("invalid token");
  const header = parseJson(parts[0]);
  const payload = parseJson(parts[1]);
  if (!header || !payload) throw new Error("invalid token");
  const allowed = options.algorithms;
  if (Array.isArray(allowed) && !allowed.includes(header.alg)) throw new Error("invalid algorithm");
  if (header.alg !== "HS256") throw new Error("invalid algorithm");
  const expected = createHmac("sha256", secret).update(`${parts[0]}.${parts[1]}`).digest();
  const actual = Buffer.from(parts[2], "base64url");
  if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) {
    throw new Error("invalid signature");
  }
  if (payload.exp && Math.floor(Date.now() / 1000) > payload.exp) throw new Error("jwt expired");
  return payload;
}

export function decode(token, options = {}) {
  const parts = String(token ?? "").split(".");
  if (parts.length < 2) throw new Error("invalid token");
  const payload = parseJson(parts[1]);
  if (!payload) throw new Error("invalid token");
  if (options.complete) return { header: parseJson(parts[0]), payload, signature: parts[2] ?? "" };
  return payload;
}

export default { sign, verify, decode };
