/**
 * tRPC 动态探测层的线协议工具（纯函数，无 IO）。
 *
 * 协议对照 @trpc/server v11 非批量 HTTP 形态（与 fixtures/trpc-shop/server.js 等价实现互验）：
 *  - 过程 URL：`<endpoint>/<router>.<proc>`；查询(.query) → GET + `?input=<encodeURIComponent(JSON)>`，
 *    变更(.mutation) → POST + 请求体即 input
 *  - superjson transformer：input 须为 `{"json": 原值}`，响应 data 亦为 `{json, meta?}`；
 *    未用 transformer 时 input 为原值。猜错形态 → zod 校验失败 → HTTP 400 BAD_REQUEST，
 *    探测层据此协商（见 probe.mjs 的 negotiateTrpcInput）。
 *  - 成功信封 `{result:{data:…}}`；错误为 `{error:{…}}` 且映射 HTTP 状态（UNAUTHORIZED 401 等），
 *    因此「攻击被拒绝」判定沿用 DENIED_STATUS，无需 tRPC 专用逻辑。
 *
 * 注意：tRPC 中间件先于 input 校验执行，故未认证请求返回 401 而非 400——
 * 编码协商必须携带身份，否则无法区分「input 形态错误」与「未登录」。
 */

/** input 变体：superjson 包裹优先（vibecoding 模板常见），再裸值；类型猜错时翻转 number/string */
export const INPUT_VARIANTS = [
  { wrap: true, flip: false },
  { wrap: false, flip: false },
  { wrap: true, flip: true },
  { wrap: false, flip: true },
];

export function variantAt(i) {
  return INPUT_VARIANTS[i] ?? INPUT_VARIANTS[0];
}

/** 静态分析是否给出 tRPC 候选 */
export function isTrpcCandidate(cand) {
  return !!(cand && cand.trpc);
}

/** 过程路径形态：末段含点（orders.byId），用于识别契约里写的 tRPC 登录端点 */
export function looksLikeTrpcProcPath(path) {
  const last = String(path ?? "").split("/").pop() ?? "";
  return /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$/.test(last);
}

/** 按声明的 zod 标量类型投放 ID；flip 用于「类型猜错」时翻转 */
function castId(id, kind, flip) {
  let wantNumber = kind === "number";
  if (kind !== "number" && kind !== "string") wantNumber = typeof id === "number";
  if (flip) wantNumber = !wantNumber;
  if (!wantNumber) return String(id);
  const n = Number(id);
  return Number.isFinite(n) ? n : String(id);
}

/** 序列化为 tRPC input 线格式（wrap=true 走 superjson 包裹） */
export function encodeInput(value, wrap) {
  return JSON.stringify(wrap ? { json: value } : value);
}

/** 构造 tRPC input 的 JS 值（裸标量输入 vs 对象字段输入） */
export function trpcInputValue(cand, id, variant = INPUT_VARIANTS[0]) {
  const t = cand?.trpc;
  if (!t) return null;
  const value = castId(id, t.inputKind, variant.flip);
  return t.inputField ? { [t.inputField]: value } : value;
}

/**
 * 按候选 + 对象 ID 生成请求（path/body）。非 tRPC 候选返回 null，由调用方走 REST 形态。
 * method 以候选声明为准（query=GET，mutation=POST）。
 */
export function trpcRequest(cand, id, variant = INPUT_VARIANTS[0]) {
  if (!isTrpcCandidate(cand)) return null;
  const url = cand.fullPath ?? cand.path;
  if (!url) return null;
  const encoded = encodeInput(trpcInputValue(cand, id, variant), variant.wrap);
  if (cand.method === "GET") {
    const sep = url.includes("?") ? "&" : "?";
    return { method: "GET", path: `${url}${sep}input=${encodeURIComponent(encoded)}`, body: null };
  }
  return { method: cand.method ?? "POST", path: url, body: encoded };
}

/** superjson 载荷形态：仅含 json（可选 meta） */
function isSuperjsonPayload(v) {
  if (!v || typeof v !== "object" || Array.isArray(v)) return false;
  const keys = Object.keys(v);
  return keys.includes("json") && keys.every((k) => k === "json" || k === "meta");
}

/** tRPC 成功信封（严格判定：顶层只有 result，且 result 含 data） */
export function isTrpcEnvelope(json) {
  if (!json || typeof json !== "object" || Array.isArray(json)) return false;
  const keys = Object.keys(json);
  if (keys.length !== 1 || keys[0] !== "result") return false;
  const r = json.result;
  return !!r && typeof r === "object" && !Array.isArray(r) && "data" in r;
}

/**
 * 解开响应信封：`{result:{data:…}}` → data（superjson 再剥一层 json）。
 * 非信封响应原样返回，保证 REST 目标行为不变。
 */
export function unwrapTrpcEnvelope(json) {
  if (!isTrpcEnvelope(json)) return json;
  const data = json.result.data;
  return isSuperjsonPayload(data) ? data.json : data;
}

/** input 形态被服务端拒绝（zod 校验失败）：HTTP 400 或错误码 BAD_REQUEST/PARSE_ERROR */
export function inputRejected(res) {
  if (!res) return false;
  if (res.status === 400) return true;
  const body = res.json;
  if (!body || typeof body !== "object") return false;
  const code = body.error?.json?.data?.code ?? body.error?.data?.code ?? body.error?.code ?? null;
  return code === "BAD_REQUEST" || code === "PARSE_ERROR";
}
