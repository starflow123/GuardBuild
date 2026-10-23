/**
 * 攻击变体库（验收加厚）。
 *
 * 单一攻击用例可能「碰巧不通过」：补丁只对那一个对象生效、只对那一种 ID 写法生效、
 * 或只挡住了路径参数那一条通道。本模块把同源漏洞的其它入口展开成变体用例，
 * 让「修好了」必须同时对多个对象、多种 ID 表示、多条参数通道成立。
 *
 * 变体一律由引擎按模板生成（模型不参与编写用例），且只走只读请求：
 * 写/删类变体会在复现阶段就破坏后续用例要读的对象，
 * 造成「自己把证据删掉 → 修复后自然打不通」的假通过，故明确不做。
 *
 * 每条变体都带 requiresPreRepro：修复前没复现的变体（该目标不认这种写法）
 * 不参与修复后的验收，避免把「路由本就 404」记成「补丁把它挡住了」。
 */

/** 同一候选下的变体用例总数上限（三类共享此配额） */
export const MAX_VARIANT_CASES = 6;
/** 额外他人对象数量 */
export const MAX_FOREIGN_OBJECTS = 2;
/** ID 表示变体数量 */
export const MAX_ID_ENCODINGS = 3;

/** 只读 GET 才允许参数通道变体（POST/PUT 形态的读语义由候选自身决定） */
export function channelVariantAllowed(cand) {
  return !!cand && (cand.method ?? "GET") === "GET" && !cand.graphql && !cand.trpc;
}

/**
 * ID 表示变体：保持「服务端解析出的仍是同一个对象」，只改变线上写法。
 * 依据是十进制数值的等价变换（前导零 / 前后空白 / 加号 / 小数点），
 * 命中「拿原始字符串比对的补丁」——这类补丁挡住了 `7`，却放行 `07`。
 * 非数值 ID（UUID、slug）不做编码变体。
 */
export function idEncodingVariants(rawId) {
  const s = String(rawId ?? "").trim();
  if (!/^\d+$/.test(s)) return [];
  const numeric = Number(s);
  if (!Number.isFinite(numeric)) return [];
  const classes = [
    { label: "前导零", token: `0${s}` },
    { label: "前导空格", token: `%20${s}` },
    { label: "尾部空格", token: `${s}%20` },
    { label: "加号前缀", token: `+${s}` },
    { label: "小数点后缀", token: `${s}.0` },
  ];
  const out = [];
  for (const c of classes) {
    const decoded = decodeURIComponent(c.token);
    if (decoded === s) continue;
    // 必须仍解析为同一对象，否则测的不是同一个漏洞
    if (Number(decoded) !== numeric) continue;
    out.push(c);
    if (out.length >= MAX_ID_ENCODINGS) break;
  }
  return out;
}

/**
 * 其它他人对象：同一 handler 下的不同主键。
 * primaryId 已由基线用例覆盖，这里只取归属 victim 的其余对象。
 */
export function foreignObjectVariants(items, primaryId, attackerOwnIds = new Set()) {
  const seen = new Set([String(primaryId ?? "")]);
  const out = [];
  for (const item of items ?? []) {
    const id = item?.id ?? item?._id ?? null;
    if (id == null) continue;
    const key = String(id);
    if (seen.has(key)) continue;
    seen.add(key);
    // attacker 自己名下也有这个 id 时不算他人对象（跨端点 ID 串号防护）
    if (attackerOwnIds.has(key)) continue;
    out.push({ item, label: `他人对象 #${key}` });
    if (out.length >= MAX_FOREIGN_OBJECTS) break;
  }
  return out;
}

/**
 * 参数通道变体：路径参数候选补一条查询参数写法（`/api/orders/7` → `/api/orders?orderId=7`）。
 * 很多实现两条通道都读（`req.params.id ?? req.query.id`），只挡一条就是没修完。
 * 仅在 `:param` 位于末段时构造——中间段的别名要猜路由形状，容易造出不存在的地址。
 */
export function channelVariantFor(cand) {
  if (!channelVariantAllowed(cand)) return null;
  const path = String(cand.fullPath ?? cand.path ?? "");
  const m = path.match(/^(\/.*?)\/:([A-Za-z_]\w*)$/);
  if (!m) return null;
  const param = cand.queryParam?.param || m[2];
  return { label: `改用查询参数 ${param}`, base: m[1], param };
}

/**
 * 按原始 token 构造只读请求路径（不经 encodeURIComponent，变体里的 %20 必须原样上线）。
 * 查询参数形态拼 `?param=token`，路径形态替换唯一的 `:param`。
 */
export function rawTokenRequest(cand, token) {
  const path = cand.fullPath ?? cand.path;
  if (!path) return null;
  const paramSeg = String(path).match(/:[A-Za-z_]\w*/);
  if (cand.queryParam && !paramSeg) {
    const name = cand.queryParam.param || "id";
    const sep = path.includes("?") ? "&" : "?";
    return { method: cand.method ?? "GET", path: `${path}${sep}${name}=${token}`, body: null };
  }
  if (!paramSeg) return null;
  return { method: cand.method ?? "GET", path: path.replace(paramSeg[0], token), body: null };
}

/** 变体用例 id：基名 + 轴 + 序号，便于报告归组与「修复前是否复现」比对 */
export function variantCaseId(baseId, axis, index) {
  return `${baseId}-${axis}${index}`;
}

const VARIANT_AXIS_RE = /-(?:obj|enc|chan)\d+$/;

/** 变体 caseId 还原为语料标注的基名（基准按基名统计召回，变体不另立标注） */
export function variantBaseCaseId(caseId) {
  return String(caseId ?? "").replace(VARIANT_AXIS_RE, "");
}
