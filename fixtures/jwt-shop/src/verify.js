import jwt from "./jwtlib.js";

const JWT_SECRET = process.env.GB_JWT_SECRET || "gb-jwt-shop-secret";
const TTL_SECONDS = 3600;

export function signToken(payload) {
  const now = Math.floor(Date.now() / 1000);
  return jwt.sign({ ...payload, iat: now, exp: now + TTL_SECONDS }, JWT_SECRET);
}

/** 修复路径：固定算法白名单并校验签名 */
export function verifyToken(token) {
  return jwt.verify(token, JWT_SECRET, { algorithms: ["HS256"] });
}
