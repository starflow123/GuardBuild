/**
 * 动态复现引擎（取证核心）。
 *
 * 以真实 HTTP 请求构造「身份 × 对象归属」矩阵：
 *  - 攻击用例：A 身份访问 B 身份的对象（修复前应可成功，修复后应被拒绝）
 *  - 业务用例：本人资源与合法管理操作（修复前后都必须保持可用）
 *
 * 每个用例同时关联服务端权限判断轨迹（/__diag/decisions），
 * 形成「请求 → 响应 → 服务端决策」三方关联的可核对证据，落库 SQLite。
 *
 * 所有请求经 Host 的 http.request 发出：
 *  - 身份凭证由 Host 保险库注入（Sidecar 只见 identityRef，不见令牌明文）
 *  - 响应体经 Host 脱敏后才返回给 Sidecar（写入证据的仍是掩码形式）
 */
import { RPC_TO_HOST, VERDICT, CASE_CATEGORY, SEVERITY, shortId } from "../../shared/protocol.mjs";

export class ProbeError extends Error {
  constructor(message, { code = "probe_failed", hint = null } = {}) {
    super(message);
    this.code = code;
    this.hint = hint;
  }
}

const DENIED_STATUS = new Set([401, 403, 404]);

function trimBody(text, limit = 4000) {
  if (!text) return "";
  return text.length > limit ? `${text.slice(0, limit)}…（截断，共 ${text.length} 字节）` : text;
}

function getByDotPath(obj, path) {
  let node = obj;
  for (const key of String(path).split(".")) {
    if (node == null || typeof node !== "object") return undefined;
    node = node[key];
  }
  return node;
}

/**
 * 列表响应取数组（形状自适应）：契约点路径 > 顶层数组 > 含 id 对象元素的数组 > 首个对象数组 > 首个数组。
 * 未找到任何数组时返回 null（供断言区分「空列表」与「形状不符」）。
 */
export function extractListItems(json, arrayPath = null) {
  if (arrayPath) {
    const node = getByDotPath(json, arrayPath);
    return Array.isArray(node) ? node : null;
  }
  if (Array.isArray(json)) return json;
  if (json && typeof json === "object") {
    const arrays = Object.values(json).filter(Array.isArray);
    if (arrays.length === 0) return null;
    const withId = arrays.find((a) => a.some((x) => x && typeof x === "object" && "id" in x));
    const withObjects = arrays.find((a) => a.some((x) => x && typeof x === "object"));
    return withId ?? withObjects ?? arrays[0];
  }
  return null;
}

/** 单体响应取实体对象（形状自适应）：契约点路径 > 首个对象值字段 > 响应自身。 */
export function extractEntity(json, entityPath = null) {
  if (!json || typeof json !== "object" || Array.isArray(json)) return null;
  if (entityPath) {
    const node = getByDotPath(json, entityPath);
    return node && typeof node === "object" && !Array.isArray(node) ? node : null;
  }
  for (const v of Object.values(json)) {
    if (v && typeof v === "object" && !Array.isArray(v)) return v;
  }
  return json;
}

/** 资源名标签：order 显示为「订单」，其它资源名原样展示，未知回退「资源」。 */
function resourceLabelOf(r) {
  if (r === "order") return "订单";
  return r && r !== "resource" ? r : "资源";
}

function resourceLabel(ctx) {
  return resourceLabelOf(ctx.plan?.resource);
}

/** 归属字段读取：兼容 userId / user_id / ownerId / owner_id / uid 命名 */
function ownerOf(obj) {
  return obj?.userId ?? obj?.user_id ?? obj?.ownerId ?? obj?.owner_id ?? obj?.uid ?? null;
}

/** 经 Host 发起一次 HTTP 请求（可携带保险库身份） */
async function httpJson(ctx, opts) {
  const {
    baseUrl,
    method,
    path,
    identity = null,
    body = null,
    storeAs = null,
    credentialPath = null,
    credentialPrefix = null,
    credentialHeader = null,
    redact = true,
  } = opts;
  const params = {
    token: ctx.tokens.net,
    method,
    url: `${baseUrl.replace(/\/+$/, "")}${path}`,
    headers: body ? { "Content-Type": "application/json" } : {},
  };
  if (body) params.body = body;
  if (identity) params.identityRef = identity;
  if (storeAs) {
    params.storeCredentialAs = storeAs;
    params.credentialPath = credentialPath;
    params.credentialPrefix = credentialPrefix;
    if (credentialHeader) params.credentialHeader = credentialHeader;
  }
  params.redact = redact;

  let res;
  try {
    res = await ctx.rpc.request(RPC_TO_HOST.HTTP_REQUEST, params, { timeoutMs: 30_000 });
  } catch (e) {
    throw new ProbeError(`请求 ${method} ${path} 失败：${e.message}`, {
      code: "probe_request_failed",
      hint: "请确认目标服务已启动且网络探测令牌有效",
    });
  }
  let json = null;
  try {
    json = JSON.parse(res.body);
  } catch {
    /* 非 JSON 响应 */
  }
  return { ...res, json };
}

/** 拉取自上次以来的服务端权限判断轨迹 */
async function fetchNewDecisions(ctx, baseUrl) {
  const res = await httpJson(ctx, { baseUrl, method: "GET", path: "/__diag/decisions" });
  const entries = res.json?.entries;
  if (!Array.isArray(entries)) return [];
  const fresh = entries.filter((e) => (e.seq ?? 0) > (ctx._lastDecisionSeq ?? 0));
  if (fresh.length > 0) ctx._lastDecisionSeq = Math.max(...fresh.map((e) => e.seq ?? 0));
  return fresh;
}

function matchDecision(entries, kase) {
  for (let i = entries.length - 1; i >= 0; i--) {
    const e = entries[i];
    if ((e.routeKey ?? null) === kase.routeKey && e.method === kase.method && e.path === kase.path) return e;
  }
  return null;
}

/**
 * 构造登录请求体：identity.fields > 契约 login.bodyTemplate > username/email 默认形状。
 * 模板值支持 {name} {username} {email} {password} 占位符（递归替换）。
 */
export function buildLoginBody(identity, loginCfg) {
  const fill = (value) => {
    if (typeof value === "string") {
      return value.replace(/\{(name|username|email|password)\}/g, (_, k) => {
        const v = k === "name" ? identity.name : identity[k];
        return v ?? "";
      });
    }
    if (Array.isArray(value)) return value.map(fill);
    if (value && typeof value === "object") {
      return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, fill(v)]));
    }
    return value;
  };
  const source = identity.fields ?? loginCfg?.bodyTemplate ?? null;
  if (source) return fill(source);
  if (identity.username) return { username: identity.username, password: identity.password };
  return { email: identity.email ?? "", password: identity.password };
}

/** 从登录响应中提取用户对象：契约 userPath > 顶层 user > authentication.user */
function pickUser(json, loginCfg) {
  if (!json || typeof json !== "object") return null;
  const userPath = loginCfg?.userPath;
  if (userPath) {
    const v = userPath
      .split(".")
      .reduce((o, k) => (o && typeof o === "object" ? o[k] : undefined), json);
    if (v && typeof v === "object") return v;
  }
  const direct = json.user ?? json.data?.user ?? json.authentication?.user ?? null;
  return direct && typeof direct === "object" ? direct : null;
}

/** 登录失败归因：按尝试记录给出可行动的 hint */
export function classifyLoginFailure(attempts) {
  const tried = [...new Set(attempts.map((a) => a.path))];
  const statuses = attempts.map((a) => a.status).filter((s) => Number.isFinite(s));
  const anyAuth = statuses.some((s) => s === 401 || s === 403);
  const allMissing = statuses.length > 0 && statuses.every((s) => s === 404 || s === 405);
  const allServerErr = statuses.length > 0 && statuses.every((s) => s >= 500);
  if (allMissing) {
    return {
      code: "login_endpoint_missing",
      hint: `所有候选登录端点均不存在（${tried.join("、")} 返回 404/405）。请在 guardbuild.json 的 login.path 中显式声明正确的登录路径`,
    };
  }
  if (anyAuth) {
    return {
      code: "login_rejected",
      hint: `登录端点已响应但拒绝凭据（HTTP ${statuses.filter((s) => s === 401 || s === 403).join("/")}）。请核对 guardbuild.json 中 identities 的账号/密码，以及 login.bodyTemplate 的字段形状（email 还是 username）`,
    };
  }
  if (allServerErr) {
    return {
      code: "login_server_error",
      hint: `登录请求触发服务端错误（HTTP ${statuses[statuses.length - 1]}）。常见原因：login.bodyTemplate 与端点期望的请求体不匹配，或服务启动不完整；请查看目标进程日志`,
    };
  }
  return {
    code: "login_failed",
    hint: `请确认目标服务正常响应，且登录端点 ${tried[tried.length - 1] ?? ""} 接受契约提供的账号`,
  };
}

/**
 * 所有身份登录（凭证直接存入 Host 保险库，不流经 Sidecar）。
 * 候选端点按序尝试：契约声明 > 静态分析 > /api/login；找到可用端点后固化回 plan。
 */
export async function loginAll(ctx, baseUrl) {
  const cfg = ctx.loginConfig ?? null;
  const candidates =
    Array.isArray(ctx.plan.loginCandidates) && ctx.plan.loginCandidates.length
      ? ctx.plan.loginCandidates
      : [ctx.plan.loginPath];
  const attempts = [];

  for (const path of candidates) {
    const loggedIn = [];
    let failed = false;
    for (const ident of ctx.identities) {
      const res = await httpJson(ctx, {
        baseUrl,
        method: "POST",
        path,
        body: JSON.stringify(buildLoginBody(ident, cfg)),
        storeAs: ident.name,
        credentialPath: cfg?.credentialPath ?? "token",
        credentialPrefix: cfg?.credentialPrefix ?? "Bearer ",
        credentialHeader: cfg?.credentialHeader ?? null,
      });
      if (okStatus(res.status) && res.storedIdentity === ident.name) {
        const user = pickUser(res.json, cfg);
        ctx.emit({
          kind: "identity",
          severity: SEVERITY.INFO,
          message: `身份「${ident.name}」登录成功（${path}），令牌已存入 Host 保险库（响应中的 token 对 Sidecar 显示为 ***）`,
          data: { identity: ident.name, user, stored: true, endpoint: path },
        });
        loggedIn.push({ ...ident, user });
        continue;
      }
      attempts.push({ path, identity: ident.name, status: res.status });
      if (okStatus(res.status) && res.storedIdentity !== ident.name) {
        throw new ProbeError(
          `登录返回 HTTP ${res.status}，但响应中未找到凭据字段「${cfg?.credentialPath ?? "token"}」`,
          {
            code: "credential_path_missing",
            hint: `请检查 guardbuild.json 的 login.credentialPath（当前为 "${cfg?.credentialPath ?? "token"}"）；嵌套令牌应写如 "authentication.token"`,
          }
        );
      }
      failed = true;
      break;
    }
    if (!failed) {
      ctx.plan.loginPath = path;
      ctx.plan.loginCandidates = [path, ...candidates.filter((c) => c !== path)];
      return loggedIn;
    }
  }

  const { code, hint } = classifyLoginFailure(attempts);
  const last = attempts[attempts.length - 1];
  throw new ProbeError(`所有候选登录端点均失败（最后尝试 ${last.path}，HTTP ${last.status}）`, {
    code,
    hint,
  });
}

const ANON_PROBE_MAX_ID = 10;
const ANON_PROBE_MAX_ITEMS = 3;

/** 无列表接口时的回退：用匿名 ID 探测收集可见对象（打匿名越权本就不需要账号发现） */
async function discoverViaAnonymousProbe(ctx, baseUrl, path) {
  const anonymousItems = [];
  for (let id = 1; id <= ANON_PROBE_MAX_ID && anonymousItems.length < ANON_PROBE_MAX_ITEMS; id += 1) {
    const res = await httpJson(ctx, { baseUrl, method: "GET", path: fillParams(path, id), identity: null });
    const o = extractEntity(res.json, ctx.targetConfig?.responses?.entity ?? null);
    if (o && String(o.id) === String(id)) anonymousItems.push(o);
  }
  ctx.emit({
    kind: "discovery",
    severity: anonymousItems.length > 0 ? SEVERITY.INFO : SEVERITY.WARN,
    message:
      anonymousItems.length > 0
        ? `资源发现（匿名探测回退）：无按归属过滤的列表接口，在 ${path} 匿名探测到 ${anonymousItems.length} 个公开可见对象`
        : `资源发现（匿名探测回退）：无列表接口，且 ${path} 匿名 ID 探测未找到可见对象`,
    data: { mode: "anonymous-probe", path, ids: anonymousItems.map((o) => o.id) },
  });
  return anonymousItems;
}

/**
 * 计划槽位读取：多候选数组（planner top-K）优先，回退单槽位（兼容旧计划对象）。
 * kind: "read" | "cancel" | "unauthRead"
 */
function planCandidates(ctx, kind) {
  const arr = ctx.plan?.[`${kind}Candidates`];
  if (Array.isArray(arr) && arr.length > 0) return arr;
  const single = ctx.plan?.[kind === "unauthRead" ? "unauthReadCandidate" : `${kind}Candidate`];
  return single ? [single] : [];
}

function candPath(cand) {
  return cand?.fullPath ?? cand?.path ?? null;
}

/**
 * 发现资源归属。优先各身份的按归属列表接口；
 * 无列表接口时可回退匿名 ID 探测（逐个无鉴权候选路径探测，服务匿名用例）；
 * 两者皆无且计划不依赖对象归属时返回空结果（如仅路径穿越用例）。
 * 返回 { byUser, anonymousItems, anonTargets }。
 */
async function discoverResources(ctx, baseUrl, loggedIn) {
  const listPath = ctx.plan.listEndpoint?.path;
  if (!listPath) {
    const unauthCands = planCandidates(ctx, "unauthRead");
    if (unauthCands.length > 0) {
      const anonTargets = [];
      for (const cand of unauthCands) {
        const p = candPath(cand);
        if (!p) continue;
        const items = await discoverViaAnonymousProbe(ctx, baseUrl, p);
        if (items.length > 0) anonTargets.push({ path: p, item: items[0] });
      }
      return { byUser: {}, anonymousItems: anonTargets.map((t) => t.item), anonTargets };
    }
    if (ctx.plan.traversalCandidate) {
      ctx.emit({
        kind: "discovery",
        severity: SEVERITY.INFO,
        message: "无需资源归属发现：探测计划中的用例不依赖具体对象 ID",
        data: { mode: "not-required" },
      });
      return { byUser: {}, anonymousItems: [], anonTargets: [] };
    }
    throw new ProbeError("静态分析未能定位列表接口，无法发现资源归属", {
      code: "no_list_endpoint",
      hint: "当前策略要求目标项目存在按归属过滤的列表接口（如 GET /api/orders），或至少一个无鉴权单体资源接口（如 GET /api/users/:id，用于匿名探测回退）",
    });
  }
  const byUser = {};
  for (const ident of loggedIn) {
    if (ident.role === "admin") continue;
    const res = await httpJson(ctx, { baseUrl, method: "GET", path: listPath, identity: ident.name });
    const items = extractListItems(res.json, ctx.targetConfig?.responses?.list ?? null) ?? [];
    byUser[ident.name] = items;
    ctx.emit({
      kind: "discovery",
      severity: SEVERITY.INFO,
      message: `资源发现：「${ident.name}」名下可见 ${items.length} 个${resourceLabel(ctx)}`,
      data: { identity: ident.name, count: items.length, ids: items.map((o) => o.id) },
    });
  }
  return { byUser, anonymousItems: [], anonTargets: [] };
}

/**
 * 从发现结果中挑选攻击/业务用例所需的具体对象（loggedIn 携带登录响应中的 user 对象）。
 * 宽容化：缺少身份/对象时返回 null 槽位，由 buildCases 按槽位条件决定哪些用例可构建。
 */
function pickTargets(byUser, loggedIn, anonymousItems = [], anonTargets = []) {
  const users = loggedIn.filter((i) => i.role !== "admin");
  const attacker = users[0] ?? null;
  const victim = users[1] ?? null; // 归属类用例（越权读/操作）需要第二个普通用户，缺则跳过该槽位
  const admin = loggedIn.find((i) => i.role === "admin") ?? null;
  const attackerItems = attacker ? byUser[attacker.name] ?? [] : [];
  const victimItems = victim ? byUser[victim.name] ?? [] : [];
  const victimPaid = victimItems.filter((o) => o.status === "paid");
  const attackerPaid = attackerItems.filter((o) => o.status === "paid");
  return {
    attacker,
    victim,
    admin,
    readTarget: victimItems[0] ?? anonymousItems[0] ?? null,
    attackCancelTarget: victimPaid[0] ?? victimItems[1] ?? victimItems[0] ?? null,
    adminCancelTarget: victimPaid[1] ?? victimPaid[0] ?? victimItems[0] ?? null,
    ownReadTarget: attackerItems[0] ?? null,
    ownCancelTarget: attackerPaid[1] ?? attackerPaid[0] ?? null,
    ownNotCancellable: attackerItems.find((o) => o.status !== "paid") ?? null,
    anonTargets,
  };
}

/** 填充路径参数（任意 :param 形态，不限于 :id） */
function fillParams(path, id) {
  return path.replace(/:[A-Za-z_]\w*/g, String(id));
}

const okStatus = (s) => s >= 200 && s < 300;

/** 攻击用例判定：修复前 = 漏洞可利用；修复后 = 攻击被阻断 */
/**
 * 攻击用例判定。leaked 为「响应中确含越权成功证据」的判定结果：
 * 2xx 但响应无证据（如 200+{"error":"Not Admin"} 语义拒绝）不得当作放行，
 * 否则会产生假复现（修复前误报漏洞）。
 */
function verifyAttack(res, phase, detail, leaked = true) {
  if (phase === "pre") {
    if (okStatus(res.status) && leaked) {
      return { verdict: VERDICT.VULNERABLE, actual: `HTTP ${res.status}，越权请求被放行。${detail ?? ""}` };
    }
    if (okStatus(res.status)) {
      return {
        verdict: VERDICT.INCONCLUSIVE,
        actual: `HTTP ${res.status}，但响应未包含越权成功的证据（可能为语义拒绝，如 200+错误体）`,
      };
    }
    return {
      verdict: VERDICT.INCONCLUSIVE,
      actual: `HTTP ${res.status}，攻击在修复前即无法复现（该端点可能已有防护）`,
    };
  }
  if (DENIED_STATUS.has(res.status)) {
    return { verdict: VERDICT.BLOCKED, actual: `HTTP ${res.status}，越权请求被拒绝。${detail ?? ""}` };
  }
  if (okStatus(res.status) && leaked) {
    return { verdict: VERDICT.REGRESSED, actual: `HTTP ${res.status}，修复后攻击仍可成功，补丁无效。${detail ?? ""}` };
  }
  if (okStatus(res.status)) {
    return {
      verdict: VERDICT.INCONCLUSIVE,
      actual: `HTTP ${res.status}，但响应未包含越权成功的证据（可能为语义拒绝），结果无法判定`,
    };
  }
  return { verdict: VERDICT.INCONCLUSIVE, actual: `HTTP ${res.status}，结果无法判定` };
}

/** 业务用例判定：修复前后都必须保持通过 */
function verifyBusiness(res, expectStatus, detailFn) {
  if (res.status !== expectStatus) {
    return {
      verdict: VERDICT.REGRESSED,
      actual: `HTTP ${res.status}（预期 ${expectStatus}）${detailFn ? `：${detailFn()}` : ""}`,
    };
  }
  const content = detailFn ? detailFn() : null;
  if (content && content.startsWith("FAIL:")) {
    return { verdict: VERDICT.REGRESSED, actual: `HTTP ${res.status}，但内容断言失败：${content.slice(5)}` };
  }
  return { verdict: VERDICT.PASSED, actual: `HTTP ${res.status}${content ? `，${content}` : ""}` };
}

// —— 路径穿越用例辅助 ——

/** package.json 特征字段：≥2 个同时出现即视为回读到目标文件内容 */
const PKG_MARKERS = ['"name"', '"version"', '"dependencies"'];
const TRAVERSAL_PAYLOADS = ["../package.json", "../../package.json", "../../../package.json"];

function traversalLeak(body, localName = null) {
  if (typeof body !== "string" || !body) return false;
  const hits = PKG_MARKERS.filter((m) => body.includes(m)).length;
  if (hits >= 2) return true;
  return !!localName && body.includes(`"${localName}"`);
}

/** 生成一次穿越尝试的请求路径：query 形态追加参数，params 形态替换路径段（编码变体保活） */
function traversalAttemptPath(routePath, trav, payload, encoded) {
  if (trav.source === "params" && trav.param) {
    return routePath.replace(`:${trav.param}`, encoded ? payload.replace(/\//g, "%2F") : payload);
  }
  const param = trav.param ?? "file";
  const value = encoded ? encodeURIComponent(payload) : payload;
  const sep = routePath.includes("?") ? "&" : "?";
  return `${routePath}${sep}${param}=${value}`;
}

/** 构建一个阶段内的全部用例（攻击 + 业务），攻击目标对象由发现阶段确定 */
export function buildCases(ctx, targets) {
  // 每类候选 top-K 逐一构建攻击用例；首个候选保持基名（兼容既有报告/测试/e2e）
  const readCands = planCandidates(ctx, "read");
  const cancelCands = planCandidates(ctx, "cancel");
  const unauthCands = planCandidates(ctx, "unauthRead");
  const readPath = candPath(readCands[0]);
  const cancelPath = candPath(cancelCands[0]);
  const adminListPath = ctx.plan.adminListEndpoint?.path ?? null;
  const adminCancelPath = ctx.plan.adminCancelEndpoint?.path ?? null;
  const listPath = ctx.plan.listEndpoint?.path ?? null;
  const readKey = readCands[0]?.routeKeys?.[0] ?? "orders.get";
  const cancelKey = cancelCands[0]?.routeKeys?.[0] ?? "orders.cancel";
  const { attacker, victim, admin } = targets;
  const label = resourceLabel(ctx);

  const cases = [];

  // —— 攻击用例（仅在计划中存在对应端点且身份/目标齐备时构建，不虚构回退路径）——
  for (const [i, cand] of readCands.entries()) {
    const path = candPath(cand);
    if (!path || !targets.readTarget || !attacker || !victim) continue;
    const readTarget = targets.readTarget;
    const suffix = i === 0 ? "" : `-${i + 1}`;
    const multi = readCands.length > 1 ? `（${path}）` : "";
    const candLabel = resourceLabelOf(cand.resource ?? ctx.plan?.resource);
    cases.push({
      id: `attack-read-foreign${suffix}`,
      category: CASE_CATEGORY.ATTACK,
      name: `${attacker.name} 读取 ${victim.name} 的${candLabel} #${readTarget.id}${multi}`,
      identity: attacker.name,
      method: "GET",
      path: fillParams(path, readTarget.id),
      routeKey: cand.routeKeys?.[0] ?? readKey,
      expect: `越权读取他人${candLabel}应被拒绝（401/403/404）`,
      verify: (res, phase) => {
        const o = extractEntity(res.json, ctx.targetConfig?.responses?.entity ?? null);
        const leaked = o && String(o.id) === String(readTarget.id);
        const detail = leaked
          ? `证据：返回${candLabel} #${o.id}（归属 ${ownerOf(o)}，金额 ${o.amount}，状态 ${o.status}）`
          : "";
        return verifyAttack(res, phase, detail, leaked);
      },
      crossProof: (res) => {
        const o = extractEntity(res.json, ctx.targetConfig?.responses?.entity ?? null);
        if (!o || o.id !== readTarget.id) return null;
        const ownerOk = !victim.user?.id || ownerOf(o) === victim.user.id;
        if (!ownerOk) return null;
        return {
          note: `响应对象 #${o.id} 与请求目标一致，归属 ${ownerOf(o)}${victim.user?.id ? "（与受害人身份一致）" : ""}`,
        };
      },
      impact: (res) => (okStatus(res.status) ? `可读取他人${candLabel}详情及字段（id/userId/amount/address 等）` : null),
    });
  }

  for (const [i, cand] of cancelCands.entries()) {
    const path = candPath(cand);
    if (!path || !targets.attackCancelTarget || !attacker || !victim) continue;
    const cancelTarget = targets.attackCancelTarget;
    const suffix = i === 0 ? "" : `-${i + 1}`;
    const multi = cancelCands.length > 1 ? `（${path}）` : "";
    const candLabel = resourceLabelOf(cand.resource ?? ctx.plan?.resource);
    cases.push({
      id: `attack-cancel-foreign${suffix}`,
      category: CASE_CATEGORY.ATTACK,
      name: `${attacker.name} 取消 ${victim.name} 的${candLabel} #${cancelTarget.id}${multi}`,
      identity: attacker.name,
      method: "POST",
      path: fillParams(path, cancelTarget.id),
      routeKey: cand.routeKeys?.[0] ?? cancelKey,
      expect: `越权取消他人${candLabel}应被拒绝（401/403/404）`,
      verify: (res, phase) => {
        const o = extractEntity(res.json, ctx.targetConfig?.responses?.entity ?? null);
        const changed =
          o && o.status === "cancelled" && (!victim.user?.id || ownerOf(o) === victim.user.id);
        const detail = changed ? `证据：${candLabel} #${o.id}（归属 ${ownerOf(o)}）状态已被改为 cancelled` : "";
        return verifyAttack(res, phase, detail, changed);
      },
      crossProof: (res) => {
        const o = extractEntity(res.json, ctx.targetConfig?.responses?.entity ?? null);
        if (!o || o.id !== cancelTarget.id) return null;
        if (victim.user?.id && ownerOf(o) !== victim.user.id) return null;
        return {
          note: `被操对象 #${o.id} 归属 ${ownerOf(o)}${o.status === "cancelled" ? "，状态已变更为 cancelled" : ""}`,
        };
      },
      impact: (res) => {
        const o = extractEntity(res.json, ctx.targetConfig?.responses?.entity ?? null);
        return o && o.status === "cancelled" ? `可越权取消他人${candLabel}（业务破坏）` : null;
      },
    });
  }

  if (adminListPath && victim) {
    cases.push({
      id: "attack-vertical-escalation",
      category: CASE_CATEGORY.ATTACK,
      name: `${victim.name}（普通用户）访问管理端${label}列表`,
      identity: victim.name,
      method: "GET",
      path: adminListPath,
      routeKey: ctx.plan.adminListEndpoint?.routeKey ?? "admin.orders.list",
      expect: "普通用户访问管理端应被拒绝（401/403/404）",
      verify: (res, phase) => {
        const arr = extractListItems(res.json, ctx.targetConfig?.responses?.list ?? null);
        const leaked = arr && arr.length > 0;
        const detail = leaked
          ? `证据：返回 ${arr.length} 条${label}（归属 ${[...new Set(arr.map((o) => ownerOf(o)))].join(",")}），纵向越权可览全局数据`
          : "";
        return verifyAttack(res, phase, detail, leaked);
      },
      crossProof: (res) => {
        const arr = extractListItems(res.json, ctx.targetConfig?.responses?.list ?? null);
        if (!arr || arr.length === 0) return null;
        const foreign = arr.filter((o) => ownerOf(o) !== victim.user?.id).length;
        if (foreign === 0) return null;
        return { note: `普通用户响应含 ${foreign} 条他人${label}（跨归属全局列表）` };
      },
      impact: (res) => {
        const arr = extractListItems(res.json, ctx.targetConfig?.responses?.list ?? null);
        return arr && arr.length > 0 ? `可越权查看全站${label}（角色校验缺失）` : null;
      },
    });
  }

  for (const [i, cand] of unauthCands.entries()) {
    const path = candPath(cand);
    if (!path) continue;
    // 每个候选优先用该路径匿名探测到的对象；缺失时回退通用读目标
    const anonTarget =
      targets.anonTargets?.find((t) => t.path === path)?.item ?? targets.readTarget ?? null;
    if (!anonTarget) continue;
    const suffix = i === 0 ? "" : `-${i + 1}`;
    const multiText = unauthCands.length > 1 ? ` ${path}` : "";
    const candLabel = resourceLabelOf(cand.resource ?? ctx.plan?.resource);
    cases.push({
      id: `attack-anonymous-read${suffix}`,
      category: CASE_CATEGORY.ATTACK,
      name: `未携带凭证读取${candLabel} #${anonTarget.id}（无鉴权端点${multiText}）`,
      identity: null,
      method: "GET",
      path: fillParams(path, anonTarget.id),
      routeKey: cand.routeKeys?.[0] ?? null,
      expect: `未认证读取${candLabel}应被拒绝（401/403/404）`,
      verify: (res, phase) => {
        const o = extractEntity(res.json, ctx.targetConfig?.responses?.entity ?? null);
        const leaked = o && String(o.id) === String(anonTarget.id);
        const detail = leaked
          ? `证据：匿名请求即返回${candLabel} #${o.id}（归属 ${ownerOf(o)}），无需任何认证`
          : "";
        return verifyAttack(res, phase, detail, leaked);
      },
      crossProof: (res) => {
        const o = extractEntity(res.json, ctx.targetConfig?.responses?.entity ?? null);
        if (!o || o.id !== anonTarget.id) return null;
        return { note: `匿名响应对象 #${o.id} 与请求目标一致，归属 ${ownerOf(o)}` };
      },
      impact: (res) => {
        const o = extractEntity(res.json, ctx.targetConfig?.responses?.entity ?? null);
        return o && o.id === anonTarget.id ? `未认证即可读取任意${candLabel}详情（认证缺失）` : null;
      },
    });
  }

  // —— 路径穿越攻击用例：对逐条 payload 尝试，命中泄露证据即停（无修复策略，仅取证）——
  for (const [i, cand] of planCandidates(ctx, "traversal").entries()) {
    const routePath = candPath(cand);
    if (!routePath) continue;
    const trav = cand.traversal ?? {};
    const suffix = i === 0 ? "" : `-${i + 1}`;
    const travIdentity = victim?.name ?? attacker?.name ?? null;
    const firstAttempt = traversalAttemptPath(routePath, trav, TRAVERSAL_PAYLOADS[0], false);
    cases.push({
      id: `attack-path-traversal${suffix}`,
      category: CASE_CATEGORY.ATTACK,
      name: `路径穿越读取服务器文件（${routePath}${trav.param ? ` · 参数 ${trav.param}` : ""}）`,
      identity: travIdentity,
      method: "GET",
      path: firstAttempt,
      routeKey: cand.routeKeys?.[0] ?? null,
      expect: "路径穿越读取应被拒绝（400/403/404），不得回读目标文件内容",
      send: async (c, baseUrl) => {
        // 本机 package.json 的 name 值用作交叉证据：回读内容须与本机文件一致
        let localName = null;
        try {
          const root = String(c.projectRoot ?? "").replace(/[\\/]+$/, "");
          const rd = await c.rpc.request(RPC_TO_HOST.FS_READ, {
            token: c.tokens.project,
            path: `${root}/package.json`,
            redact: true,
          });
          localName = JSON.parse(rd.content)?.name ?? null;
        } catch {
          /* 无本地文件则仅用通用特征 */
        }
        let last = null;
        let lastPath = firstAttempt;
        let firstErr = null;
        let hit = null;
        let hitPath = null;
        for (const payload of TRAVERSAL_PAYLOADS) {
          for (const encoded of [false, true]) {
            const p = traversalAttemptPath(routePath, trav, payload, encoded);
            try {
              const res = await httpJson(c, { baseUrl, method: "GET", path: p, identity: travIdentity });
              last = res;
              lastPath = p;
              if (traversalLeak(res.body, localName)) {
                hit = res;
                hitPath = p;
                break;
              }
            } catch (e) {
              if (!firstErr) firstErr = e;
            }
          }
          if (hit) break;
        }
        if (!last) throw firstErr ?? new ProbeError(`路径穿越探测请求全部失败（${routePath}）`, { code: "probe_request_failed" });
        const chosen = hit ?? last;
        chosen._traversalProof = { localName, matched: !!hit, attemptPath: hitPath ?? lastPath };
        return { res: chosen, path: hitPath ?? lastPath, method: "GET" };
      },
      verify: (res, phase) => {
        const localName = res._traversalProof?.localName ?? null;
        const leaked = traversalLeak(res.body, localName);
        const detail = leaked
          ? `证据：响应体含 package.json 特征字段${localName ? `（项目名 ${localName} 与本机一致）` : ""}，实际请求 ${res._traversalProof?.attemptPath ?? ""}`
          : "";
        return verifyAttack(res, phase, detail, leaked);
      },
      crossProof: (res) => {
        const proof = res._traversalProof;
        if (!proof?.matched || !proof.localName) return null;
        return { note: `回读内容与本机 package.json 一致（项目名 ${proof.localName}），确证服务器任意文件读取` };
      },
      impact: (res) =>
        traversalLeak(res.body, res._traversalProof?.localName ?? null)
          ? "可通过 ../ 穿越读取服务器任意文件（源码、配置、密钥等敏感信息）"
          : null,
    });
  }

  // —— 业务用例（回归防线）——
  const own = targets.ownReadTarget;
  if (readPath && own && attacker) {
    cases.push({
      id: "business-read-own",
      category: CASE_CATEGORY.BUSINESS,
      name: `${attacker.name} 读取自己的${label} #${own.id}`,
      identity: attacker.name,
      method: "GET",
      path: fillParams(readPath, own.id),
      routeKey: readKey,
      expect: `本人${label}应正常可见（200，且归属本人）`,
      verify: (res) =>
        verifyBusiness(res, 200, () => {
          const o = extractEntity(res.json, ctx.targetConfig?.responses?.entity ?? null);
          if (!o) return `FAIL:响应缺少${label}对象`;
          if (o.id !== own.id) return `FAIL:返回了错误的${label} #${o.id}`;
          if (ownerOf(o) !== attacker.user?.id) return `FAIL:${label}归属异常 ${ownerOf(o)}`;
          return `返回${label} #${o.id}，归属 ${ownerOf(o)}`;
        }),
    });
  }

  if (listPath && attacker) {
    cases.push({
      id: "business-list-own",
      category: CASE_CATEGORY.BUSINESS,
      name: `${attacker.name} 查询${label}列表仅见本人${label}`,
      identity: attacker.name,
      method: "GET",
      path: listPath,
      routeKey: ctx.plan.listEndpoint?.routeKey ?? "orders.list",
      expect: `列表应只包含本人${label}（owner-filter 保持有效）`,
      verify: (res) =>
        verifyBusiness(res, 200, () => {
          const arr = extractListItems(res.json, ctx.targetConfig?.responses?.list ?? null);
          if (!arr) return `FAIL:响应中未找到${label}列表`;
          const foreign = arr.filter((o) => ownerOf(o) !== attacker.user?.id);
          if (foreign.length > 0) return `FAIL:列表泄露他人${label} ${foreign.map((o) => o.id).join(",")}`;
          return `共 ${arr.length} 条，全部归属 ${attacker.user?.id}`;
        }),
    });
  }

  if (cancelPath && targets.ownCancelTarget && attacker) {
    const c = targets.ownCancelTarget;
    cases.push({
      id: "business-cancel-own",
      category: CASE_CATEGORY.BUSINESS,
      name: `${attacker.name} 取消自己的${label} #${c.id}`,
      identity: attacker.name,
      method: "POST",
      path: fillParams(cancelPath, c.id),
      routeKey: cancelKey,
      expect: `本人已支付${label}应可正常取消（200）`,
      verify: (res) =>
        verifyBusiness(res, 200, () => {
          const o = extractEntity(res.json, ctx.targetConfig?.responses?.entity ?? null);
          if (!o) return `FAIL:响应缺少${label}对象`;
          if (o.status !== "cancelled") return `FAIL:状态未变更（${o.status}）`;
          return `${label} #${o.id} 已置为 cancelled`;
        }),
    });
  }

  if (cancelPath && targets.ownNotCancellable && attacker) {
    const s = targets.ownNotCancellable;
    cases.push({
      id: "business-shipped-guard",
      category: CASE_CATEGORY.BUSINESS,
      name: `${attacker.name} 取消已发货${label} #${s.id} 被业务规则拒绝`,
      identity: attacker.name,
      method: "POST",
      path: fillParams(cancelPath, s.id),
      routeKey: cancelKey,
      expect: `状态非 paid 的${label}不可取消（409），业务规则保持有效`,
      verify: (res) =>
        verifyBusiness(res, 409, () => {
          const s2 = res.json?.status;
          return s2 ? `返回当前状态 ${s2}` : `${label}状态保护生效`;
        }),
    });
  }

  if (adminListPath && admin) {
    cases.push({
      id: "business-admin-list",
      category: CASE_CATEGORY.BUSINESS,
      name: `管理员查看全部${label}`,
      identity: admin.name,
      method: "GET",
      path: adminListPath,
      routeKey: ctx.plan.adminListEndpoint?.routeKey ?? "admin.orders.list",
      expect: `管理员应可查看全部${label}（200，跨多个归属）`,
      verify: (res) =>
        verifyBusiness(res, 200, () => {
          const arr = extractListItems(res.json, ctx.targetConfig?.responses?.list ?? null);
          if (!arr) return `FAIL:响应中未找到${label}列表`;
          // 归属读取：列表项无归属字段时（如资源本身即用户），以自身 id 视作独立归属
          const owners = new Set(arr.map((o) => ownerOf(o) ?? o.id));
          if (owners.size < 2) return `FAIL:仅见单一归属（${[...owners].join(",")}）`;
          return `可见 ${arr.length} 条，覆盖 ${owners.size} 个归属`;
        }),
    });
  }

  if (adminCancelPath && admin && targets.adminCancelTarget) {
    const adminTarget = targets.adminCancelTarget;
    cases.push({
      id: "business-admin-cancel",
      category: CASE_CATEGORY.BUSINESS,
      name: `管理员代取消 ${victim.name} 的${label} #${adminTarget.id}`,
      identity: admin.name,
      method: "POST",
      path: fillParams(adminCancelPath, adminTarget.id),
      routeKey: ctx.plan.adminCancelEndpoint?.routeKey ?? "admin.orders.cancel",
      expect: "管理员合法代操作应保持可用（200）",
      verify: (res) =>
        verifyBusiness(res, 200, () => {
          const o = extractEntity(res.json, ctx.targetConfig?.responses?.entity ?? null);
          if (!o) return `FAIL:响应缺少${label}对象`;
          if (o.status !== "cancelled") return `FAIL:状态未变更（${o.status}）`;
          return `${label} #${o.id}（归属 ${ownerOf(o)}）已由管理员取消`;
        }),
    });
  }

  if (adminListPath && victim) {
    cases.push({
      id: "business-nonadmin-denied",
      category: CASE_CATEGORY.BUSINESS,
      name: `${victim.name}（普通用户）访问管理端被拒绝`,
      identity: victim.name,
      method: "GET",
      path: adminListPath,
      routeKey: ctx.plan.adminListEndpoint?.routeKey ?? "admin.orders.list",
      expect: "普通用户访问管理端应被拒绝（403），角色校验保持有效",
      verify: (res) => {
        if (res.status === 403 || res.status === 401) {
          return { verdict: VERDICT.PASSED, actual: `HTTP ${res.status}，角色校验（role:admin）生效` };
        }
        const arr = extractListItems(res.json, ctx.targetConfig?.responses?.list ?? null);
        if (okStatus(res.status) && arr === null) {
          return {
            verdict: VERDICT.PASSED,
            actual: `HTTP ${res.status} + 错误体（语义拒绝），管理端数据未泄露给普通用户`,
          };
        }
        return {
          verdict: VERDICT.REGRESSED,
          actual: `HTTP ${res.status}（预期 403），管理端数据可能被普通用户访问`,
        };
      },
    });
  }

  if (readPath && own) {
    cases.push({
      id: "business-unauth-401",
      category: CASE_CATEGORY.BUSINESS,
      name: `未登录访问${label}详情被拒绝`,
      identity: null,
      method: "GET",
      path: fillParams(readPath, own.id),
      routeKey: readKey,
      expect: "未认证请求应被拒绝（401），认证入口保持有效",
      verify: (res) => {
        if (res.status === 401) return { verdict: VERDICT.PASSED, actual: "HTTP 401，认证拦截生效" };
        if (res.status === 403) return { verdict: VERDICT.PASSED, actual: "HTTP 403，认证拦截生效" };
        return { verdict: VERDICT.REGRESSED, actual: `HTTP ${res.status}（预期 401/403），认证被绕过或异常放行` };
      },
    });
  }

  return cases;
}

/**
 * 执行一个阶段的完整探测（pre：修复前 / post：修复后指向 worktree 实例）。
 * 返回该阶段的证据与统计，证据已落库并推送 UI 事件。
 */
export async function runPhase(ctx, { phase, baseUrl }) {
  ctx._lastDecisionSeq = 0;
  ctx.emit({
    kind: "phase",
    severity: SEVERITY.INFO,
    message: phase === "pre" ? "开始修复前动态复现与取证" : "开始修复后双重验收（指向隔离工作区实例）",
    phase,
    data: { baseUrl },
  });

  const loggedIn = await loginAll(ctx, baseUrl);
  const { byUser, anonymousItems, anonTargets } = await discoverResources(ctx, baseUrl, loggedIn);
  const targets = pickTargets(byUser, loggedIn, anonymousItems, anonTargets);
  const cases = buildCases(ctx, targets);

  const attackSlots = cases.filter((c) => c.category === CASE_CATEGORY.ATTACK);
  if (attackSlots.length === 0) {
    throw new ProbeError("未能构建任何攻击用例（身份或资源发现不足）", {
      code: "no_attack_cases",
      hint: "攻击用例需要：至少一个普通用户身份 + 可填充的对象资源（来自列表接口或匿名探测），请检查 guardbuild.json 的身份配置与目标项目的资源可发现性",
    });
  }
  const plannedSlots = [
    { slot: "readCandidate", prefix: "attack-read-foreign", count: planCandidates(ctx, "read").length },
    { slot: "cancelCandidate", prefix: "attack-cancel-foreign", count: planCandidates(ctx, "cancel").length },
    { slot: "unauthReadCandidate", prefix: "attack-anonymous-read", count: planCandidates(ctx, "unauthRead").length },
    { slot: "traversalCandidate", prefix: "attack-path-traversal", count: planCandidates(ctx, "traversal").length },
  ].filter((s) => s.count > 0);
  const skipped = plannedSlots.filter(
    (s) => !cases.some((c) => c.id === s.prefix || c.id.startsWith(`${s.prefix}-`))
  );
  if (skipped.length > 0) {
    ctx.emit({
      kind: "discovery",
      severity: SEVERITY.WARN,
      message: `计划中有 ${skipped.length} 类攻击用例因身份/资源不足被跳过：${skipped.map((s) => s.slot).join("、")}`,
      data: { skipped },
    });
  }

  const evidence = [];
  for (const kase of cases) {
    let res;
    let sentPath = kase.path;
    let sentMethod = kase.method;
    if (kase.send) {
      // 自定义发送器（如路径穿越的多 payload 尝试），返回实际命中的请求
      const out = await kase.send(ctx, baseUrl);
      res = out.res;
      sentPath = out.path ?? kase.path;
      sentMethod = out.method ?? kase.method;
    } else {
      res = await httpJson(ctx, {
        baseUrl,
        method: kase.method,
        path: kase.path,
        identity: kase.identity,
        body: kase.body ?? null,
      });
    }
    const fresh = await fetchNewDecisions(ctx, baseUrl);
    const decision = matchDecision(fresh, { method: sentMethod, path: sentPath, routeKey: kase.routeKey });
    const { verdict, actual } = kase.verify(res, phase);
    const impact = kase.impact ? kase.impact(res) : null;
    const cross = kase.crossProof ? kase.crossProof(res) : null;
    // 证据分级：strong=有服务端决策轨迹；cross-proven=内容归属交叉证明；http-only=仅 HTTP 状态
    const evidenceGrade = decision ? "strong" : cross ? "cross-proven" : "http-only";

    const record = {
      id: shortId("ev"),
      sessionId: ctx.sessionId,
      phase,
      identity: kase.identity ?? "(anonymous)",
      method: sentMethod,
      endpoint: sentPath,
      request: {
        url: `${baseUrl.replace(/\/+$/, "")}${sentPath}`,
        headers: kase.identity
          ? { Authorization: `Bearer ***vault:${kase.identity}***`, "Content-Type": "application/json" }
          : { "Content-Type": "application/json" },
        body: kase.body ?? null,
      },
      response: {
        status: res.status,
        statusText: res.statusText,
        body: trimBody(res.body),
        redacted: !!res.redacted,
        durationMs: res.durationMs ?? null,
      },
      decision,
      crossProof: cross?.note ?? null,
      evidenceGrade,
      expectation: kase.expect,
      verdict,
      actual,
      impact,
      caseId: kase.id,
      caseCategory: kase.category,
      caseName: kase.name,
      createdAt: Date.now(),
    };
    ctx.db.insertEvidence(record);
    evidence.push(record);

    const severity =
      verdict === VERDICT.VULNERABLE
        ? SEVERITY.ERROR
        : verdict === VERDICT.REGRESSED || verdict === VERDICT.INCONCLUSIVE
          ? SEVERITY.WARN
          : SEVERITY.SUCCESS;
    ctx.emit({
      kind: "evidence",
      severity,
      message: `[${phase === "pre" ? "修复前" : "修复后"}] ${kase.name} → HTTP ${res.status} · ${verdict}${impact ? ` · ${impact}` : ""}`,
      phase,
      data: {
        evidenceId: record.id,
        caseId: kase.id,
        category: kase.category,
        verdict,
        status: res.status,
        evidenceGrade,
        crossProof: cross?.note ?? null,
        decision: decision ? { checks: decision.checks, decision: decision.decision, note: decision.note } : null,
      },
    });
  }

  const counts = { vulnerable: 0, blocked: 0, passed: 0, regressed: 0, inconclusive: 0 };
  for (const e of evidence) counts[e.verdict] = (counts[e.verdict] ?? 0) + 1;

  const grades = { strong: 0, "cross-proven": 0, "http-only": 0 };
  for (const e of evidence) grades[e.evidenceGrade] = (grades[e.evidenceGrade] ?? 0) + 1;

  const attackRecords = evidence.filter((e) => e.caseCategory === CASE_CATEGORY.ATTACK);
  const businessRecords = evidence.filter((e) => e.caseCategory === CASE_CATEGORY.BUSINESS);
  const summary = {
    phase,
    baseUrl,
    counts,
    grades,
    total: evidence.length,
    attackRepro: attackRecords.filter((e) => e.verdict === VERDICT.VULNERABLE).length,
    attackBlocked: attackRecords.filter((e) => e.verdict === VERDICT.BLOCKED).length,
    attackRegressed: attackRecords.filter((e) => e.verdict === VERDICT.REGRESSED).length,
    businessPassed: businessRecords.filter((e) => e.verdict === VERDICT.PASSED).length,
    businessRegressed: businessRecords.filter((e) => e.verdict === VERDICT.REGRESSED).length,
    businessTotal: businessRecords.length,
    targets: {
      attacker: targets.attacker?.name ?? null,
      victim: targets.victim?.name ?? null,
      readTarget: targets.readTarget?.id ?? null,
      cancelTarget: targets.attackCancelTarget?.id ?? null,
    },
  };

  ctx.emit({
    kind: "phase_summary",
    severity: summary.attackRegressed > 0 || summary.businessRegressed > 0 ? SEVERITY.ERROR : SEVERITY.SUCCESS,
    message:
      phase === "pre"
        ? `修复前取证完成：复现漏洞 ${summary.attackRepro}/${attackRecords.length} 条攻击用例，业务基线 ${summary.businessPassed}/${summary.businessTotal} 通过`
        : `修复后验收完成：攻击阻断 ${summary.attackBlocked}/${attackRecords.length}，业务回归 ${summary.businessPassed}/${summary.businessTotal} 通过`,
    phase,
    data: summary,
  });

  return { evidence, summary };
}
