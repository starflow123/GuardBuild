/**
 * 路由地址的运行期实测层（agent 兜底的第 3/4 关，也是静态候选的证伪闸门）。
 *
 * 接入侦察只做静态把关（文件真实存在 + 路径能在文件里定位）。这对「模型编了一条
 * 看起来合理但目标根本没实现的路由」无能为力，而这类路由一旦进入候选队列，
 * 就会把模型断言（hasAuth / hasOwnerFilter）当成扫描结论。
 * 同一把尺也用于静态分析拼出的地址：地址是从源码推断出来的，就必须能被实测否证，
 * 否则拼错的前缀会一路走到「未复现 → 放行」。
 *
 * 本模块在目标真正跑起来、身份已登录之后，用真实 HTTP 请求复核每一条 LLM 路由：
 *   1. 存在性 —— 用发现到的真实资源 id 打一次；命中「不存在路由」基线形态即判不存在；
 *   2. 鉴权  —— 匿名再打一次；401/403/拒绝体=确实要登录，2xx 带数据=确实不用登录；
 *   3. 归属过滤 —— 列表路由用两个身份各拉一次；结果集相同=没按归属过滤，互斥=过滤生效。
 *
 * 判定只来自响应，不来自模型：验证不通过的路由会被丢弃（缩小覆盖面），验证通过才回写
 * hasAuth / hasOwnerFilter。传输层由调用方注入（request / fetchList），本模块可单测。
 */

/** 单轮参与实测的 LLM 路由上限 */
export const MAX_SCOUT_ROUTES = 12;
/** 实测总请求预算：存在性 + 匿名 + 基线 + 两身份列表，必须可预期 */
export const MAX_VERIFY_REQUESTS = 48;

/** 「不存在的路径」基线探针：绝对不该命中真实路由 */
export const ABSENT_PROBE_PATH = "/__guardbuild_probe__/absent-route";

const PROTECTED_STATUSES = new Set([401, 403, 407]);
const ABSENT_STATUSES = new Set([404, 410]);

/** 状态码是否属于「路由不存在」形态（供静态候选的实测证伪闸门复用同一把尺） */
export function isAbsentStatus(status) {
  return ABSENT_STATUSES.has(status);
}

const TRUNCATION_MARK = /…（截断，共 \d+ 字节）$/;

/**
 * 本轮全部请求是否都落在「路由不存在」形态上——静态/契约推断地址的实测证伪判据。
 * 与模型路由那道闸共用同一把尺：判定只来自响应，传输由调用方负责。
 *
 * @param {Array<{method?:string,path:string,status?:number,body?:string}>} probes 已发出的请求与响应
 * @param {{status?:number,body?:string}|null} baseline 绝对不存在路径的实测响应；
 *        null＝基线不可用，仅按状态码判（此轮同样没证明触及目标）
 * @returns {{missed: boolean, statuses: number[], attempted: string[]}}
 */
export function allRequestsMissed(probes, baseline) {
  const list = Array.isArray(probes) ? probes : [];
  if (list.length === 0) return { missed: false, statuses: [], attempted: [] };
  const statuses = [...new Set(list.map((p) => p?.status).filter((s) => typeof s === "number"))];
  const attempted = [...new Set(list.map((p) => `${p.method ?? "GET"} ${p.path}`))];
  if (!list.every((p) => isAbsentStatus(p?.status))) return { missed: false, statuses, attempted };
  // 资源级 404（路径存在、对象不存在）与路由级 404 通常不同形：只有同形才算「没打到接口」
  const strip = (s) => String(s ?? "").replace(TRUNCATION_MARK, "").slice(0, 4000);
  const sameShape =
    !baseline || list.every((p) => sameBody({ body: strip(p.body) }, { body: strip(baseline.body) }));
  return { missed: sameShape, statuses, attempted };
}

function normalizeBody(res) {
  const raw = typeof res?.body === "string" ? res.body : res?.body == null ? "" : String(res.body);
  return raw.trim().replace(/\s+/g, " ").slice(0, 4000);
}

/** 粗粒度同体判定：SPA catch-all 会对任意路径回同一份文档，用长度+首尾片段比对 */
export function sameBody(a, b) {
  const x = normalizeBody(a);
  const y = normalizeBody(b);
  if (!x || !y) return x === y;
  if (x.length !== y.length) return false;
  return x.slice(0, 200) === y.slice(0, 200) && x.slice(-200) === y.slice(-200);
}

/** 响应体是否表达「被拒绝」——很多实现用 200 + {error|code≠0} 回未登录 */
export function looksDenied(json) {
  if (!json || typeof json !== "object" || Array.isArray(json)) return false;
  for (const key of Object.keys(json)) {
    if (/^(error|errors|denied|forbidden|unauthorized|message)$/i.test(key)) {
      if (json.data == null && json.result == null && json.items == null) return true;
      // 同时带 data 的（如 {error:null,data:{…}}）不按拒绝处理
      const v = json[key];
      if (v != null && v !== "" && (Array.isArray(v) ? v.length > 0 : true)) return true;
    }
  }
  if (json.code != null && json.code !== 0 && json.data == null && json.result == null) return true;
  return false;
}

/** 响应体是否携带可判读的数据载荷（用于匿名「确实开放」判定） */
function hasPayload(json) {
  if (json == null) return false;
  if (Array.isArray(json)) return json.length > 0;
  if (typeof json !== "object") return String(json).length > 0;
  for (const key of ["data", "result", "items", "rows", "list", "user", "order", "payload"]) {
    const v = json[key];
    if (Array.isArray(v)) return v.length > 0;
    if (v && typeof v === "object") return Object.keys(v).length > 0;
    if (v != null && v !== "") return true;
    if (key === "items" && Array.isArray(json.items)) return json.items.length > 0;
  }
  const keys = Object.keys(json).filter((k) => !/^(code|status|ok|success|meta|message)$/i.test(k));
  return keys.length > 0;
}

/**
 * 存在性判定。baseline 是「不存在路径」的实测响应；catch-all 应用（任意路径回 200 首页）
 * 只能靠响应体比对区分「真路由」与「兜底文档」。
 */
export function classifyExistence(res, baseline) {
  if (res?.status === 405) return "method_mismatch";
  if (ABSENT_STATUSES.has(res?.status)) return "absent";
  if (baseline && res?.status === baseline.status && sameBody(res, baseline)) return "absent";
  return "present";
}

/** 匿名请求判定鉴权形态：protected（确实要登录）/ open（确实不用登录）/ unknown */
export function classifyAnonymous(res) {
  const status = res?.status;
  if (status == null) return "unknown";
  if (PROTECTED_STATUSES.has(status)) return "protected";
  if (status >= 300 && status < 400) {
    const loc = String(res?.headers?.location ?? res?.headers?.Location ?? "").toLowerCase();
    if (/login|signin|sign-in|auth|sso/.test(loc)) return "protected";
    return "unknown";
  }
  if (status >= 200 && status < 300) {
    if (looksDenied(res?.json)) return "protected";
    return hasPayload(res?.json ?? res?.body) ? "open" : "unknown";
  }
  return "unknown";
}

/**
 * 归属过滤判定：两个普通用户各拉一次列表。
 * 两侧都非空且 id 集合相同 → 未按归属过滤（false）；非空且完全互斥 → 过滤生效（true）；
 * 其它（空列表、只有一个身份、部分重叠）→ null（未确认，保留静态/契约结论）。
 */
export function compareOwnerFilter(itemsA, itemsB, idOf) {
  const ids = (arr) =>
    new Set((Array.isArray(arr) ? arr : []).map((o) => idOf(o)).filter((v) => v != null).map(String));
  const a = ids(itemsA);
  const b = ids(itemsB);
  if (a.size === 0 || b.size === 0) return null;
  let overlap = 0;
  for (const v of a) if (b.has(v)) overlap += 1;
  if (overlap === 0) return true;
  if (a.size === b.size && overlap === a.size) return false;
  return null;
}

/**
 * 实测一组 LLM 路由。
 * @param {Array} routes [{ key, method, path, identity, list }]
 *   path 为已填好具体参数值（或查询参数）的完整请求路径；null 表示无法构造 → 直接判不可验证。
 *   identity 为用于「带身份存在性」请求的身份名（可为 null）。
 * @param {object} opts
 * @param {(req:{method:string,path:string,identity:string|null}) => Promise<object>} opts.request
 * @param {(route:object, identity:string) => Promise<Array|null>} [opts.fetchList] 列表路由取数
 * @param {(item:any) => any} [opts.idOf]
 * @param {string[]} [opts.identities] 已登录的普通用户身份名（归属过滤比对需要两个）
 * @param {number} [opts.budget]
 * @param {(msg:string)=>void} [opts.note]
 */
export async function verifyScoutRoutes(routes, opts) {
  const {
    request,
    fetchList = null,
    idOf = (o) => o?.id,
    identities = [],
    budget = MAX_VERIFY_REQUESTS,
    note = () => {},
  } = opts;

  const kept = [];
  const dropped = [];
  const detail = [];
  let used = 0;
  let baseline = null;
  let baselineDone = false;

  const send = async ({ method, path, identity }) => {
    if (used >= budget) return null;
    used += 1;
    try {
      return await request({ method, path, identity });
    } catch (e) {
      return { error: e?.message ?? String(e) };
    }
  };

  for (const route of (Array.isArray(routes) ? routes : []).slice(0, MAX_SCOUT_ROUTES)) {
    if (used >= budget) {
      dropped.push({ key: route.key, reason: "budget", detail: "实测请求预算已用尽，未发送请求" });
      continue;
    }
    if (!route.path) {
      dropped.push({ key: route.key, reason: "no_probe_id", detail: "缺少可用于填充路径参数的真实资源 id" });
      continue;
    }

    if (!baselineDone) {
      baselineDone = true;
      baseline = await send({ method: "GET", path: ABSENT_PROBE_PATH, identity: route.identity ?? null });
      if (baseline?.error) baseline = null;
    }

    const hit = await send({ method: route.method, path: route.path, identity: route.identity ?? null });
    if (!hit) {
      dropped.push({ key: route.key, reason: "budget", detail: "实测请求预算已用尽" });
      continue;
    }
    if (hit.error) {
      dropped.push({ key: route.key, reason: "request_failed", detail: hit.error });
      note(`LLM 路由「${route.key}」实测请求失败：${hit.error}`);
      continue;
    }
    const exists = classifyExistence(hit, baseline);
    if (exists !== "present") {
      dropped.push({
        key: route.key,
        reason: exists === "method_mismatch" ? "method_not_allowed" : "not_found",
        detail: `实测 ${hit.status}（不存在路径基线 ${baseline ? `${baseline.status}${route.identity ? "" : "（匿名）"}` : "不可用"}）`,
      });
      continue;
    }

    // 存在 → 匿名复核鉴权
    let auth = "unknown";
    const anon = await send({ method: route.method, path: route.path, identity: null });
    if (anon && !anon.error) auth = classifyAnonymous(anon);

    // 列表路由 → 两身份对拉复核归属过滤
    let ownerFilter = null;
    if (route.list && typeof fetchList === "function" && identities.length >= 2) {
      const [a, b] = await Promise.all([
        used < budget ? fetchList(route, identities[0]) : Promise.resolve(null),
        used < budget ? fetchList(route, identities[1]) : Promise.resolve(null),
      ]);
      used += 2;
      ownerFilter = compareOwnerFilter(a, b, idOf);
    }

    kept.push({ key: route.key, path: route.path, status: hit.status, auth, ownerFilter });
    detail.push({
      key: route.key,
      method: route.method,
      declaredPath: route.declaredPath ?? route.path,
      exists: true,
      auth,
      ownerFilter,
      status: hit.status,
      anonStatus: anon?.status ?? null,
      baselineStatus: baseline?.status ?? null,
    });
  }

  return { kept, dropped, detail, requestsUsed: used, baselineStatus: baseline?.status ?? null };
}
