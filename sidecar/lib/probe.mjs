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
import { followRedirects } from "./http-follow.mjs";
import {
  INPUT_VARIANTS,
  encodeInput,
  inputRejected,
  isTrpcCandidate,
  looksLikeTrpcProcPath,
  trpcRequest,
  unwrapTrpcEnvelope,
  variantAt,
} from "./trpcwire.mjs";
import {
  graphqlLoginRequest,
  graphqlPlainRequest,
  graphqlRequest,
  introspectionRequest,
  isGraphqlCandidate,
  looksLikeGraphqlPath,
  parseIntrospection,
  unwrapGraphqlEnvelope,
  isGraphqlDenied,
  graphqlShapeRejected,
} from "./graphqlwire.mjs";
import {
  MAX_VARIANT_CASES,
  channelVariantFor,
  foreignObjectVariants,
  idEncodingVariants,
  rawTokenRequest,
  variantCaseId,
} from "./attackvariants.mjs";
import { candKey } from "./planner.mjs";

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

/** 资源主键读取：兼容 id / userId / user_id / resourceId 命名（响应体字段名不统一） */
function resourceIdOf(obj) {
  return obj?.id ?? obj?.resourceId ?? obj?.userId ?? obj?.user_id ?? null;
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
    storeCookieAs = null,
    credentialPath = null,
    credentialPrefix = null,
    credentialHeader = null,
    extraHeaders = null,
    contentType = null,
    redact = true,
    graphql = false,
  } = opts;
  const headers = { ...(ctx.loginConfig?.extraHeaders ?? {}) };
  if (body) headers["Content-Type"] = contentType ?? "application/json";
  const params = {
    // 黑盒模式把目标主机令牌放在 http 槽位（远程 net.egress）；常规流程仍用 net。
    token: ctx.tokens.http ?? ctx.tokens.net,
    method,
    url: `${baseUrl.replace(/\/+$/, "")}${path}`,
    headers,
  };
  if (body) params.body = body;
  if (identity) params.identityRef = identity;
  if (storeAs) params.storeCredentialAs = storeAs;
  if (storeCookieAs) params.storeCookieAs = storeCookieAs;
  if (credentialPath) params.credentialPath = credentialPath;
  if (credentialPrefix != null) params.credentialPrefix = credentialPrefix;
  if (credentialHeader) params.credentialHeader = credentialHeader;
  // 合并全局额外 header（如 X-Tenant-Id）
  if (extraHeaders && typeof extraHeaders === "object") {
    Object.assign(params.headers, extraHeaders);
  }
  params.redact = redact;

  let res;
  try {
    const url = `${baseUrl.replace(/\/+$/, "")}${path}`;
    const followed = await followRedirects(
      (next) => ctx.rpc.request(RPC_TO_HOST.HTTP_REQUEST, { ...params, url: next }, { timeoutMs: 30_000 }),
      url,
      { method }
    );
    res = followed.res;
    if (followed.hops.length) res = { ...res, redirects: followed.hops };
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
  // tRPC 响应信封（{result:{data:…}} / superjson 再包一层）在此统一解开，
  // 上层 extractEntity/extractListItems 与契约 responses.list/entity 因此无需感知框架形态。
  // 判定严格（顶层仅 result 且含 data），REST 目标响应不受影响。
  if (json !== null) json = unwrapTrpcEnvelope(json);
  // GraphQL 信封（{data, errors}）只在明确声明为 GraphQL 请求时解开：
  // 同时把「HTTP 200 + 拒绝错误」记为 graphqlDenied——GraphQL 的授权拒绝在 HTTP 层常不可见。
  if (graphql && json !== null) {
    res.jsonRaw = json;
    res.graphqlDenied = isGraphqlDenied(json);
    res.graphqlErrored = Array.isArray(json.errors) && json.errors.length > 0;
    json = unwrapGraphqlEnvelope(json);
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

/** 登录请求体编码：JSON（默认）或 form-urlencoded。 */
export function encodeLoginBody(body, form) {
  if (!form) return { body: JSON.stringify(body), contentType: "application/json" };
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(body ?? {})) {
    if (Array.isArray(v)) {
      for (const item of v) params.append(k, item == null ? "" : String(item));
    } else {
      params.append(k, v == null ? "" : String(v));
    }
  }
  return { body: params.toString(), contentType: "application/x-www-form-urlencoded" };
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
    // 登录端点是 tRPC 过程（末段形如 auth.login）时，请求体形态（superjson 包裹与否）未知，
    // 按变体检索到能用第一个身份取回凭据的形态后再为其余身份复用
    const isTrpcProc = looksLikeTrpcProcPath(path);
    // GraphQL 登录：同一 HTTP 端点上的 mutation，文档由静态分析出的登录字段（SDL）构造
    const gqlLogin = ctx.plan.graphql?.login ?? null;
    const isGqlLogin = !!gqlLogin?.field && path === gqlLogin.path && looksLikeGraphqlPath(path);
    const cookieAuth = cfg?.cookieAuth === true;
    const formAuth = cfg?.encoding === "form";
    for (const ident of ctx.identities) {
      const bodyPlain = buildLoginBody(ident, cfg);
      // Cookie 登录允许 3xx：登录接口常用 302 下发 Set-Cookie 并跳转
      const loginOk = (r) =>
        !!r &&
        r.storedIdentity === ident.name &&
        (cookieAuth ? r.status >= 200 && r.status < 400 : okStatus(r.status));
      const gqlReq = isGqlLogin ? graphqlLoginRequest(gqlLogin, bodyPlain) : null;
      if (isGqlLogin && !gqlReq) {
        throw new ProbeError(`GraphQL 登录字段 ${gqlLogin.field} 的请求文档无法构造`, {
          code: "graphql_login_shape",
          hint: `登录 mutation 的入参形态受限于 SDL 声明（当前参数：${(gqlLogin.args ?? []).map((a) => a.name).join("、") || "无"}）；若入参为 input 对象，请在 guardbuild.json 的 login.path 指定 REST 登录端点`,
        });
      }
      const wraps = isTrpcProc ? [true, false] : [false];
      let res = null;
      for (const wrap of wraps) {
        const encoded =
          gqlReq || isTrpcProc ? null : encodeLoginBody(bodyPlain, formAuth);
        res = await httpJson(ctx, {
          baseUrl,
          method: "POST",
          path,
          body: gqlReq
            ? gqlReq.body
            : isTrpcProc
              ? encodeInput(bodyPlain, wrap)
              : encoded.body,
          contentType: encoded?.contentType,
          storeAs: cookieAuth ? null : ident.name,
          storeCookieAs: cookieAuth ? ident.name : null,
          credentialPath: cfg?.credentialPath ?? "token",
          credentialPrefix: cfg?.credentialPrefix ?? "Bearer ",
          credentialHeader: cfg?.credentialHeader ?? null,
          graphql: !!gqlReq,
        });
        if (loginOk(res)) {
          if (isTrpcProc && ctx._trpcWrap == null) {
            ctx._trpcWrap = wrap;
            ctx._trpcVariant = wrap ? 0 : 1;
            ctx.emit({
              kind: "identity",
              severity: SEVERITY.INFO,
              message: `tRPC 登录请求体形态确认：${wrap ? "superjson 包裹" : "裸 JSON"}`,
              data: { wrap, endpoint: path },
            });
          }
          break;
        }
        if (isTrpcProc && inputRejected(res)) continue; // 形态问题，换下一种
        break;
      }
      if (loginOk(res)) {
        const user = pickUser(res.json, cfg);
        ctx.emit({
          kind: "identity",
          severity: SEVERITY.INFO,
          message: cookieAuth
            ? `身份「${ident.name}」登录成功（${path}），会话 Cookie 已存入 Host 保险库（对 Sidecar 不可见）`
            : `身份「${ident.name}」登录成功（${path}），令牌已存入 Host 保险库（响应中的 token 对 Sidecar 显示为 ***）`,
          data: {
            identity: ident.name,
            user,
            stored: true,
            credentialKind: cookieAuth ? "cookie" : "token",
            endpoint: path,
          },
        });
        loggedIn.push({ ...ident, user });
        continue;
      }
      attempts.push({ path, identity: ident.name, status: res.status });
      const statusAccepted = cookieAuth ? res.status >= 200 && res.status < 400 : okStatus(res.status);
      if (statusAccepted && res.storedIdentity !== ident.name) {
        throw new ProbeError(
          cookieAuth
            ? `登录返回 HTTP ${res.status}，但响应未包含 Set-Cookie 会话`
            : `登录返回 HTTP ${res.status}，但响应中未找到凭据字段「${cfg?.credentialPath ?? "token"}」`,
          {
            code: cookieAuth ? "cookie_missing" : "credential_path_missing",
            hint: cookieAuth
              ? "请确认登录接口确实通过 Set-Cookie 下发会话；若实际返回 JSON 令牌，请移除 login.cookieAuth 并检查 login.credentialPath"
              : `请检查 guardbuild.json 的 login.credentialPath（当前为 "${cfg?.credentialPath ?? "token"}"）；嵌套令牌应写如 "authentication.token"`,
          }
        );
      }
      failed = true;
      break;
    }
    if (!failed) {
      ctx.plan.loginPath = path;
      ctx.plan.loginCandidates = [path, ...candidates.filter((c) => c !== path)];
      ctx._loginVerified = true;
      ctx._loginEndpoint = path;
      return loggedIn;
    }
  }

  const { code, hint } = classifyLoginFailure(attempts);
  const last = attempts[attempts.length - 1];
  // 逐个候选端点的实际状态码入消息：单端点框架（GraphQL）的登录失败最易被后一个 404 掩盖
  const tried = attempts.map((a) => `${a.path}→HTTP ${a.status}`).join("，");
  throw new ProbeError(`所有候选登录端点均失败（最后尝试 ${last.path}，HTTP ${last.status}；全部尝试：${tried}）`, {
    code,
    hint,
  });
}

const ANON_PROBE_MAX_ID = 10;
const ANON_PROBE_MAX_ITEMS = 3;

/** 无列表接口时的回退：用匿名 ID 探测收集可见对象（打匿名越权本就不需要账号发现） */
async function discoverViaAnonymousProbe(ctx, baseUrl, cand) {
  const path = candPath(cand);
  const anonymousItems = [];
  for (let id = 1; id <= ANON_PROBE_MAX_ID && anonymousItems.length < ANON_PROBE_MAX_ITEMS; id += 1) {
    const req = candRequest(ctx, cand, id);
    const res = await httpJson(ctx, {
      baseUrl,
      method: req.method ?? "GET",
      path: req.path,
      identity: null,
      body: req.body,
      graphql: req.graphql ?? false,
    });
    const o = extractEntity(res.json, entityPathFor(ctx, cand.graphql));
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
 * 响应取值路径。契约（guardbuild.json 的 responses.entity/list）优先；
 * GraphQL 单次文档只请求一个字段，字段名随候选而变（order / myOrders / adminOrders…），
 * 契约里的固定点路径无法覆盖，故回退为「本次请求的字段名」。
 */
function entityPathFor(ctx, graphql) {
  return ctx.targetConfig?.responses?.entity ?? graphql?.field ?? null;
}
function listPathFor(ctx, graphql) {
  return ctx.targetConfig?.responses?.list ?? graphql?.field ?? null;
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
        const items = await discoverViaAnonymousProbe(ctx, baseUrl, cand);
        if (items.length > 0) anonTargets.push({ path: p, item: items[0] });
      }
      return { byUser: {}, anonymousItems: anonTargets.map((t) => t.item), anonTargets };
    }
    if (
      ctx.plan.traversalCandidate ||
      planCandidates(ctx, "sqli").length > 0 ||
      planCandidates(ctx, "cmdi").length > 0
    ) {
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
  const listReq = slotRequest(ctx.plan.listEndpoint);
  for (const ident of loggedIn) {
    if (ident.role === "admin") continue;
    const res = await httpJson(ctx, {
      baseUrl,
      method: listReq?.method ?? "GET",
      path: listReq?.path ?? listPath,
      identity: ident.name,
      body: listReq?.body ?? null,
      graphql: listReq?.graphql ?? false,
    });
    const items = extractListItems(res.json, listPathFor(ctx, ctx.plan.listEndpoint?.graphql)) ?? [];
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
  // attacker 自己列表里已有的资源 id：这些资源不属于"他人"，请求成功不算越权
  const attackerOwnIds = new Set(attackerItems.map((o) => String(resourceIdOf(o))).filter(Boolean));
  return {
    attacker,
    victim,
    admin,
    attackerOwnIds,
    readTarget: victimItems[0] ?? anonymousItems[0] ?? null,
    // 变体材料：victim 名下全部对象（供「换对象」变体取主键之外的其它归属对象）、
    // victim 自己的对象（正向断言：修复后本人仍能看到完整对象）
    victimItems,
    victimOwnTarget: victimItems[0] ?? null,
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

/** 按候选构造请求路径：查询参数形态（?param=id，idor-suspect/queryParam 候选）或路径参数填充 */
function fillCandPath(cand, id) {
  const path = candPath(cand);
  if (!path) return null;
  if (cand?.queryParam && !/:[A-Za-z_]\w*/.test(path)) {
    const sep = path.includes("?") ? "&" : "?";
    const name = cand.queryParam.param || "id";
    return `${path}${sep}${name}=${encodeURIComponent(String(id))}`;
  }
  return fillParams(path, id);
}

/**
 * 用例请求构造的统一入口：tRPC / GraphQL 候选按各自线上协议生成 URL/body
 *  （tRPC input 放 ?input= 或请求体，编码形态取协商结果 ctx._trpcVariant；
 *   GraphQL 全部走 POST 端点，文档与变量由 SDL 构造，见 graphqlwire），
 * 其余候选保持 REST 形态（method 返回 null，由调用方按用例类型沿用 GET/POST 默认）。
 */
function candRequest(ctx, cand, id) {
  if (isGraphqlCandidate(cand)) {
    const req = graphqlRequest(cand, id, ctx._graphqlCastFlip ?? false);
    if (req) return { path: req.path, body: req.body, method: req.method, graphql: true };
    return { path: fillCandPath(cand, id), body: null, method: null, graphql: null };
  }
  if (!isTrpcCandidate(cand)) return { path: fillCandPath(cand, id), body: null, method: null, graphql: null };
  const req = trpcRequest(cand, id, variantAt(ctx._trpcVariant ?? 0));
  if (!req) return { path: fillCandPath(cand, id), body: null, method: null, graphql: null };
  return { path: req.path, body: req.body, method: req.method, graphql: null };
}

/**
 * 计划端点槽位（listEndpoint / adminListEndpoint / adminCancelEndpoint）的请求构造：
 * GraphQL 用无参数文档（列表/全局视图字段不填 ID），REST 原样返回路径。
 */
function slotRequest(slot) {
  if (!slot?.path) return null;
  if (slot.graphql) {
    const req = graphqlPlainRequest(slot.graphql, slot.path);
    if (req) return { path: req.path, body: req.body, method: req.method, graphql: true };
  }
  return { path: slot.path, body: null, method: slot.method ?? "GET", graphql: null };
}

/** 计划里是否存在需要 input 的 tRPC 候选 */
function planHasTrpc(ctx) {
  const list = ctx.plan?.candidates ?? [];
  return list.some((c) => isTrpcCandidate(c) && c.trpc?.addressable);
}

/**
 * input 变体尝试顺序：已知的 superjson 形态（来自登录协商）优先，其次不翻转 ID 类型。
 * 返回 INPUT_VARIANTS 下标序列，协商与登录共用，保证「试错」次数最少。
 */
function orderedVariants(ctx) {
  const idx = INPUT_VARIANTS.map((_, i) => i);
  const knownWrap = ctx._trpcWrap;
  idx.sort((a, b) => {
    const va = variantAt(a);
    const vb = variantAt(b);
    let d = 0;
    if (knownWrap != null) d += (va.wrap === knownWrap ? 0 : 2) - (vb.wrap === knownWrap ? 0 : 2);
    d += (va.flip ? 1 : 0) - (vb.flip ? 1 : 0);
    return d || a - b;
  });
  return idx;
}

/**
 * tRPC input 编码协商：服务端是否使用 superjson、ID 是 number 还是 string，静态分析无法确证，
 * 发一次只读请求按响应判别（400/BAD_REQUEST = input 形态被 zod 拒绝，其余状态说明 input 已被接受）。
 * 必须携带身份——tRPC 中间件先于 input 校验，未登录时恒返回 401，无法区分两种形态。
 * 仅使用查询（GET）过程，绝不用变更过程做协商，避免产生副作用。
 */
async function negotiateTrpcInput(ctx, baseUrl, loggedIn) {
  if (ctx._trpcNegotiated || !planHasTrpc(ctx)) return;
  ctx._trpcNegotiated = true; // 只协商一次（post 阶段沿用同一形态）；失败也不重复试探
  const ident = loggedIn.find((i) => i.role !== "admin") ?? loggedIn[0] ?? null;
  // 只用查询（GET）过程协商：变更过程有副作用。受保护查询须带身份（中间件先于 input 校验，
  // 无身份恒返回 401 无法判别形态）；无鉴权查询可匿名判别。
  const probes = [];
  for (const c of ctx.plan.readCandidates ?? []) {
    if (isTrpcCandidate(c) && ident) probes.push({ cand: c, identity: ident.name });
  }
  for (const c of ctx.plan.unauthReadCandidates ?? []) {
    if (isTrpcCandidate(c)) probes.push({ cand: c, identity: null });
  }
  const pick = probes[0] ?? null;
  if (!pick) {
    ctx._trpcVariant ??= 0;
    ctx.emit({
      kind: "discovery",
      severity: SEVERITY.WARN,
      message: "tRPC input 编码未协商（无可用作只读试探的查询过程或无可用身份），按默认 superjson 形态探测",
      data: { variant: ctx._trpcVariant, reason: ident ? "no_read_candidate" : "no_identity" },
    });
    return;
  }
  for (const i of orderedVariants(ctx)) {
    const req = trpcRequest(pick.cand, 1, variantAt(i));
    if (!req) break;
    const res = await httpJson(ctx, {
      baseUrl,
      method: req.method,
      path: req.path,
      identity: pick.identity,
      body: req.body,
    });
    if (inputRejected(res)) continue;
    ctx._trpcVariant = i;
    ctx._trpcWrap = variantAt(i).wrap;
    ctx.emit({
      kind: "discovery",
      severity: SEVERITY.INFO,
      message: `tRPC input 编码协商成功：${variantAt(i).wrap ? "superjson 包裹" : "裸 JSON"}${variantAt(i).flip ? "（ID 类型翻转）" : ""}（HTTP ${res.status}）`,
      data: { variant: i, wrap: variantAt(i).wrap, flip: variantAt(i).flip, status: res.status, probe: req.path },
    });
    return;
  }
  ctx._trpcVariant = 0;
  ctx.emit({
    kind: "discovery",
    severity: SEVERITY.WARN,
    message: `tRPC input 编码协商失败：${INPUT_VARIANTS.length} 种形态均被拒绝（HTTP 400），后续探测可能无法复现`,
    data: { variant: 0, probe: candPath(pick.cand) },
  });
}

// —— GraphQL 探测层：端点确认（introspection）+ 参数类型协商 ——

/** 计划里是否存在 GraphQL 候选 */
function planHasGraphql(ctx) {
  return (ctx.plan?.candidates ?? []).some((c) => isGraphqlCandidate(c));
}

const gqlWantsNumber = (t) => t === "Int" || t === "Float";

/**
 * GraphQL 端点确认：向静态分析推出的端点发一次 introspection。
 * 用途严格限定为两件事——① 证实端点确实是 GraphQL 服务；② 用运行时 schema 校正
 * 文档构造所需的参数类型与可选字段。绝不据运行时 schema 生成新候选：
 * 报告里的每一条发现必须能追溯到源码位置，否则无法指认修复点。
 * 服务端关闭内省（生产环境常见）时降级为 WARN，探测继续走 SDL 构造的文档。
 */
async function confirmGraphqlEndpoint(ctx, baseUrl, loggedIn) {
  if (ctx._graphqlConfirmed || !planHasGraphql(ctx)) return;
  ctx._graphqlConfirmed = true;
  const endpoint = ctx.plan.graphql?.endpoint ?? null;
  if (!endpoint) return;
  const identity = (loggedIn.find((i) => i.role !== "admin") ?? loggedIn[0] ?? null)?.name ?? null;
  const req = introspectionRequest(endpoint);
  let res = null;
  try {
    res = await httpJson(ctx, { baseUrl, method: req.method, path: req.path, body: req.body, identity });
  } catch {
    res = null;
  }
  const info = res ? parseIntrospection(res.json ?? res.jsonRaw) : null;
  if (!info) {
    ctx.emit({
      kind: "discovery",
      severity: SEVERITY.WARN,
      message: `GraphQL introspection 不可用（${endpoint} 未返回 schema，可能已关闭内省）：查询文档完全按源码 SDL 构造`,
      data: { endpoint, status: res?.status ?? null },
    });
    return;
  }
  ctx._graphqlSchema = info;
  // 运行时类型 vs SDL 声明类型：不一致记入诊断，并据此决定 ID 投放形态
  const stale = [];
  const wantsNumberByRuntime = new Map();
  for (const c of ctx.plan.candidates ?? []) {
    if (!isGraphqlCandidate(c) || !c.graphql?.addressable || c.graphql.arg?.form !== "scalar") continue;
    const key = `${c.graphql.root}.${c.graphql.field}`;
    const rt = info.fields[key];
    if (!rt) {
      stale.push({ field: key, reason: "运行时 schema 中不存在该字段" });
      continue;
    }
    const rtArg = (rt.args ?? []).find((a) => a.name === c.graphql.arg.name) ?? null;
    if (!rtArg) {
      stale.push({ field: key, reason: `运行时字段无参数 ${c.graphql.arg.name}` });
      continue;
    }
    wantsNumberByRuntime.set(key, gqlWantsNumber(rtArg.typeName));
    if (rtArg.typeName !== c.graphql.arg.typeName) {
      stale.push({ field: key, reason: `参数类型：SDL 声明 ${c.graphql.arg.typeName}，运行时 ${rtArg.typeName}` });
    }
  }
  const consistent = stale.length === 0;
  ctx.emit({
    kind: "discovery",
    severity: consistent ? SEVERITY.INFO : SEVERITY.WARN,
    message: consistent
      ? `GraphQL 端点确认：${endpoint} 可 introspection，运行时 schema 与源码 SDL 一致（根字段 ${Object.keys(info.fields).length} 个）`
      : `GraphQL 端点确认：${endpoint} 可 introspection，但 ${stale.length} 处与源码 SDL 不一致（${stale.map((s) => `${s.field}: ${s.reason}`).join("；")}）`,
    data: { endpoint, fields: Object.keys(info.fields).length, stale },
  });
  if (wantsNumberByRuntime.size > 0) ctx._graphqlArgNumbers = wantsNumberByRuntime;
}

/**
 * GraphQL 参数投放协商：ID 是数值（Int!）还是字符串（ID!/String!）由 schema 决定，
 * SDL 与运行时不一致时文档会被直接拒（HTTP 400 / GRAPHQL_VALIDATION_FAILED）。
 * 优先采用 introspection 给出的运行时类型；否则发一次只读试探，被拒即翻转。
 * 只用查询（op=query）过程试探，绝不用变更过程，避免产生副作用。
 */
async function negotiateGraphqlCast(ctx, baseUrl, loggedIn) {
  if (ctx._graphqlNegotiated || !planHasGraphql(ctx)) return;
  ctx._graphqlNegotiated = true;
  const ident = loggedIn.find((i) => i.role !== "admin") ?? loggedIn[0] ?? null;
  const probes = [];
  for (const c of ctx.plan.readCandidates ?? []) {
    if (isGraphqlCandidate(c) && c.graphql?.addressable && c.graphql.op === "query") {
      probes.push({ cand: c, identity: ident?.name ?? null });
    }
  }
  for (const c of ctx.plan.unauthReadCandidates ?? []) {
    if (isGraphqlCandidate(c) && c.graphql?.addressable) probes.push({ cand: c, identity: null });
  }
  const pick = probes[0] ?? null;
  if (!pick) {
    ctx.emit({
      kind: "discovery",
      severity: SEVERITY.WARN,
      message: "GraphQL 参数形态未协商（无可用作只读试探的查询字段），按 SDL 声明类型探测",
      data: { reason: "no_read_candidate" },
    });
    return;
  }
  // introspection 已知运行时类型：直接判定是否需要翻转，无需试错
  const key = `${pick.cand.graphql.root}.${pick.cand.graphql.field}`;
  const runtime = ctx._graphqlArgNumbers?.get(key);
  if (runtime !== undefined) {
    ctx._graphqlCastFlip = runtime !== gqlWantsNumber(pick.cand.graphql.arg?.typeName);
    if (ctx._graphqlCastFlip) {
      ctx.emit({
        kind: "discovery",
        severity: SEVERITY.INFO,
        message: `GraphQL 参数形态按 introspection 校正：${key} 的 ID 改为 ${runtime ? "数值" : "字符串"}投放`,
        data: { field: key, flip: true, source: "introspection" },
      });
    } else {
      // 一致也要留痕：后面的探测文档为何按 SDL 投放，报告与排障需要这个决策依据
      ctx.emit({
        kind: "discovery",
        severity: SEVERITY.INFO,
        message: `GraphQL 参数形态协商完成：${key} 的运行时参数类型与源码 SDL 一致（${pick.cand.graphql.arg?.typeName}），按声明投放`,
        data: { field: key, flip: false, source: "introspection" },
      });
    }
    return;
  }
  for (const flip of [false, true]) {
    const req = graphqlRequest(pick.cand, 1, flip);
    if (!req) break;
    const res = await httpJson(ctx, {
      baseUrl,
      method: req.method,
      path: req.path,
      identity: pick.identity,
      body: req.body,
      graphql: true,
    });
    if (graphqlShapeRejected(res)) continue;
    ctx._graphqlCastFlip = flip;
    ctx.emit({
      kind: "discovery",
      severity: SEVERITY.INFO,
      message: `GraphQL 参数形态协商成功：${key} 按 SDL 类型${flip ? "（翻转投放）" : "原样投放"}（HTTP ${res.status}）`,
      data: { field: key, flip, status: res.status, probe: req.path },
    });
    return;
  }
  ctx.emit({
    kind: "discovery",
    severity: SEVERITY.WARN,
    message: `GraphQL 参数形态协商失败：${key} 的两种 ID 形态均被拒（HTTP 400/校验错误），后续探测可能无法复现`,
    data: { field: key, probe: candPath(pick.cand) },
  });
}

const okStatus = (s) => s >= 200 && s < 300;

/**
 * 攻击用例判定（修复前 = 漏洞可利用；修复后 = 攻击被阻断）。
 * leaked 为「响应中确含越权成功证据」的判定结果：
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
        actual: `HTTP ${res.status}，但响应未包含越权成功的证据（${
          res.graphqlDenied ? "GraphQL 语义拒绝：HTTP 200 + 拒绝错误" : "可能为语义拒绝，如 200+错误体"
        }）`,
      };
    }
    // pre 阶段：401/403/404 是服务端权限校验生效的硬证据 → 已有防护（静态误报）
    if (DENIED_STATUS.has(res.status)) {
      return {
        verdict: VERDICT.BLOCKED,
        actual: `HTTP ${res.status}，该端点在修复前即已有访问控制（静态分析误报，无需修复）`,
      };
    }
    return {
      verdict: VERDICT.INCONCLUSIVE,
      actual: `HTTP ${res.status}，攻击在修复前即无法复现（非权限类错误，原因待查）`,
    };
  }
  if (DENIED_STATUS.has(res.status) || res.graphqlDenied) {
    return {
      verdict: VERDICT.BLOCKED,
      actual: res.graphqlDenied && !DENIED_STATUS.has(res.status)
        ? `HTTP 200 + GraphQL 错误（语义拒绝），越权请求被拒绝。${detail ?? ""}`
        : `HTTP ${res.status}，越权请求被拒绝。${detail ?? ""}`,
    };
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
    // GraphQL 的拒绝（认证/授权/业务规则）常以 HTTP 200 + errors 形态返回：
    // 期望值为错误状态、且内容断言未失败时，按「语义拒绝」认定该保护仍然生效，而非状态码不符的回归
    if (expectStatus >= 400 && okStatus(res.status) && res.graphqlErrored) {
      const content = detailFn ? detailFn() : null;
      if (!String(content ?? "").startsWith("FAIL:")) {
        return {
          verdict: VERDICT.PASSED,
          actual: `HTTP ${res.status} + GraphQL 错误体（语义拒绝，等价于预期 ${expectStatus}）${content ? `，${content}` : ""}`,
        };
      }
    }
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

// —— 注入类用例辅助 ——

const SQLI_PAYLOADS = ["' OR 1=1 -- ", "' OR '1'='1' -- ", '" OR 1=1 -- ', "1 OR 1=1"];
const SQL_ERROR_RE =
  /(?:SQLITE_ERROR|SQL syntax|syntax error at or near|SQLSTATE\[\w+\]|ER_PARSE_ERROR|You have an error in your SQL syntax|unrecognized token|SequelizeDatabaseError|PrismaClientKnownRequestError|psycopg2\.errors|sqlalchemy\.exc|near\s+["'][^"']*["']:\s*syntax error)/i;

/** 按注入点通道构造请求：body 平铺字段 / query 追加参数 / params 替换路径段 */
function injectionReq(cand, inj, payload) {
  const routePath = candPath(cand);
  if (!routePath) return null;
  const method = cand.method ?? (inj.source === "body" ? "POST" : "GET");
  if (inj.source === "body") {
    return { method, path: routePath, body: JSON.stringify({ [inj.param ?? "input"]: payload }) };
  }
  if (inj.source === "params") {
    const p = inj.param && routePath.includes(`:${inj.param}`)
      ? routePath.replace(`:${inj.param}`, encodeURIComponent(payload))
      : routePath.replace(/:[A-Za-z_]\w*$/, encodeURIComponent(payload));
    return { method, path: p, body: null };
  }
  const param = inj.param ?? "q";
  const sep = routePath.includes("?") ? "&" : "?";
  return {
    method,
    path: `${routePath}${sep}${encodeURIComponent(param)}=${encodeURIComponent(payload)}`,
    body: null,
  };
}

/** 行数/报错双证据：注入后返回更多行，或仅注入请求触发数据库报错特征 */
export function sqliProof(attack, benign, payload) {
  const baseArr = extractListItems(benign?.json, null);
  const attackArr = extractListItems(attack?.json, null);
  const baseCount = baseArr ? baseArr.length : null;
  const attackCount = attackArr ? attackArr.length : null;
  const errorSignature =
    SQL_ERROR_RE.test(attack?.body ?? "") && !SQL_ERROR_RE.test(benign?.body ?? "");
  const rowsLeaked =
    attackCount != null && attackCount > 0 && (baseCount == null || attackCount > baseCount);
  // 单对象端点（fetchone/详情型）没有列表可比：正常值明确查不到（404/400），注入后却拿到对象，
  // 说明 WHERE 条件被放开。要求基线是「确定性未命中」，避免把回声型端点当成注入。
  const okStatus = (r) => r != null && r.status >= 200 && r.status < 300;
  const baseMissed = !!benign && !okStatus(benign) && (benign.status === 404 || benign.status === 400);
  const singleLeak =
    okStatus(attack) &&
    attack?.json != null &&
    typeof attack.json === "object" &&
    !Array.isArray(attack.json) &&
    Object.keys(attack.json).length > 0 &&
    baseMissed;
  return {
    hit: rowsLeaked || singleLeak || errorSignature,
    baseCount,
    attackCount,
    errorSignature,
    singleLeak,
    payload,
  };
}

/** 命令注入回显令牌：由 shell 展开（%OS% / $(id -u)），反射原文不含展开后的值 */
function cmdiAttempts(token) {
  if (process.platform === "win32") {
    return [
      { payload: `127.0.0.1 & echo GB${token}%OS%`, marker: new RegExp(`GB${token}[A-Za-z0-9_.-]+`) },
      { payload: `127.0.0.1 && echo GB${token}%OS%`, marker: new RegExp(`GB${token}[A-Za-z0-9_.-]+`) },
      { payload: `127.0.0.1 & echo GB${token}%USERNAME%`, marker: new RegExp(`GB${token}[A-Za-z0-9_.-]+`) },
    ];
  }
  return [
    { payload: `127.0.0.1; echo GB${token}$(id -u)`, marker: new RegExp(`GB${token}[A-Za-z0-9_-]+`) },
    { payload: `127.0.0.1 && echo GB${token}$(id -u)`, marker: new RegExp(`GB${token}[A-Za-z0-9_-]+`) },
    { payload: `127.0.0.1; echo GB${token}$(whoami)`, marker: new RegExp(`GB${token}[A-Za-z0-9_-]+`) },
  ];
}

/**
 * 外部攻击面扫描：发常见管理路径/敏感文件，记录未授权暴露面。
 * 只做 GET，不破坏数据；发现 200 就记录为暴露端点。
 */
export async function scanAttackSurface(ctx, baseUrl, loggedIn) {
  const paths = [
    "/admin", "/admin/", "/admin/login",
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/heapdump",
    "/debug/pprof", "/metrics",
    "/.env", "/.git/config", "/.git/HEAD",
    "/api/swagger", "/api/docs", "/swagger", "/swagger-ui.html", "/v2/api-docs", "/v3/api-docs",
    "/graphql",
    "/server-status",
    "/wp-admin",
  ];
  const findings = [];
  for (const p of paths) {
    try {
      const res = await httpJson(ctx, { baseUrl, method: "GET", path: p });
      if (okStatus(res.status) && res.json != null) {
        findings.push({ path: p, status: res.status, contentType: res.headers?.["content-type"] ?? "" });
        ctx.emit({
          kind: "evidence",
          severity: SEVERITY.WARN,
          message: `[攻击面] ${p} 返回 HTTP ${res.status}（未授权可访问）`,
          data: { path: p, status: res.status },
        });
      }
    } catch {
      // 忽略单个路径失败
    }
  }
  if (findings.length > 0) {
    ctx.emit({
      kind: "discovery",
      severity: SEVERITY.INFO,
      message: `外部攻击面扫描：发现 ${findings.length} 个未授权可访问路径`,
      data: { findings },
    });
  }
}

/**
 * 速率限制检测：对一个 GET 端点连续发 10 次请求，看是否返回 429。
 */
export async function rateLimitCheck(ctx, baseUrl, loggedIn) {
  const probePath = "/";
  let got429 = false;
  for (let i = 0; i < 10; i++) {
    try {
      const res = await httpJson(ctx, { baseUrl, method: "GET", path: probePath });
      if (res.status === 429) { got429 = true; break; }
    } catch { break; }
  }
  if (!got429) {
    ctx.emit({
      kind: "evidence",
      severity: SEVERITY.WARN,
      message: `[攻击面] ${probePath} 连续 10 次请求无 429，可能缺少速率限制`,
      data: { path: probePath, requests: 10, limited: false },
    });
  }
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
  // 计划槽位的实际请求（GraphQL 需带文档体并以 POST 发送；REST 保持原样）
  const adminListReq = slotRequest(ctx.plan.adminListEndpoint);
  const listReq = slotRequest(ctx.plan.listEndpoint);
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
    const req = candRequest(ctx, cand, readTarget.id);
    cases.push({
      id: `attack-read-foreign${suffix}`,
      candidateKey: candKey(cand),
      category: CASE_CATEGORY.ATTACK,
      name: `${attacker.name} 读取 ${victim.name} 的${candLabel} #${readTarget.id}${multi}`,
      identity: attacker.name,
      method: req.method ?? "GET",
      path: req.path,
      body: req.body,
      graphql: req.graphql ?? null,
      routeKey: cand.routeKeys?.[0] ?? readKey,
      expect: `越权读取他人${candLabel}应被拒绝（401/403/404）`,
      verify: (res, phase) => {
        const o = extractEntity(res.json, entityPathFor(ctx, cand.graphql));
        const leaked = o && String(resourceIdOf(o)) === String(readTarget.id);
        // 跨端点 id 串号防护：如果 attacker 自己列表里就有这个 id，说明是自己的资源，不是越权
        const isOwnResource = leaked && targets.attackerOwnIds?.has(String(readTarget.id));
        const detail = leaked
          ? `证据：返回${candLabel} #${resourceIdOf(o)}（归属 ${ownerOf(o)}，金额 ${o.amount}，状态 ${o.status}）${isOwnResource ? "（但该 id 在 attacker 自己列表中，疑似串号）" : ""}`
          : "";
        if (isOwnResource) {
          // 不算越权：attacker 本来就能访问自己的资源
          return { verdict: "inconclusive", actual: `目标 #${readTarget.id} 在 attacker 自己的资源列表中，疑似跨端点 id 串号，不计为越权` };
        }
        return verifyAttack(res, phase, detail, leaked);
      },
      crossProof: (res) => {
        const o = extractEntity(res.json, entityPathFor(ctx, cand.graphql));
        if (!o || String(resourceIdOf(o)) !== String(readTarget.id)) return null;
        const ownerOk = !victim.user?.id || ownerOf(o) === victim.user.id;
        if (!ownerOk) return null;
        return {
          note: `响应对象 #${resourceIdOf(o)} 与请求目标一致，归属 ${ownerOf(o)}${victim.user?.id ? "（与受害人身份一致）" : ""}`,
        };
      },
      impact: (res) => (okStatus(res.status) ? `可读取他人${candLabel}详情及字段（id/userId/amount/address 等）` : null),
    });
  }

  // —— 同源攻击变体（换对象 / 换 ID 写法 / 换参数通道）——
  // 只对首要读候选展开：基线用例可能「碰巧」因补丁只挡住了那一个对象、那一种写法而通过。
  // 变体带 requiresPreRepro：修复前没复现的（该目标本就不认这种写法）不参与修复后验收。
  const primaryRead = readCands[0];
  if (primaryRead && targets.readTarget && attacker && victim) {
    const candLabel = resourceLabelOf(primaryRead.resource ?? ctx.plan?.resource);
    const targetId = targets.readTarget.id;
    const variants = [];
    for (const v of foreignObjectVariants(
      targets.victimItems,
      targetId,
      targets.attackerOwnIds ?? new Set()
    )) {
      variants.push({
        axis: "obj",
        label: v.label,
        targetId: v.item.id,
        req: candRequest(ctx, primaryRead, v.item.id),
      });
    }
    for (const v of idEncodingVariants(targetId)) {
      const req = rawTokenRequest(primaryRead, v.token) ?? candRequest(ctx, primaryRead, v.token);
      variants.push({ axis: "enc", label: `ID ${v.label}「${v.token}」`, targetId, req });
    }
    const channel = channelVariantFor(primaryRead);
    if (channel) {
      const sep = channel.base.includes("?") ? "&" : "?";
      variants.push({
        axis: "chan",
        label: channel.label,
        targetId,
        req: { method: primaryRead.method ?? "GET", path: `${channel.base}${sep}${channel.param}=${encodeURIComponent(String(targetId))}`, body: null },
      });
    }
    const axisSeq = {};
    for (const v of variants.slice(0, MAX_VARIANT_CASES)) {
      if (!v.req?.path) continue;
      axisSeq[v.axis] = (axisSeq[v.axis] ?? 0) + 1;
      const caseId = variantCaseId("attack-read-foreign", v.axis, axisSeq[v.axis]);
      cases.push({
        id: caseId,
        candidateKey: candKey(primaryRead),
        category: CASE_CATEGORY.ATTACK,
        name: `变体·${v.label}：${attacker.name} 读取 ${victim.name} 的${candLabel}`,
        identity: attacker.name,
        method: v.req.method ?? "GET",
        path: v.req.path,
        body: v.req.body,
        graphql: v.req.graphql ?? null,
        routeKey: primaryRead.routeKeys?.[0] ?? readKey,
        variant: { axis: v.axis, label: v.label },
        requiresPreRepro: true,
        expect: `同一越权入口的变体应被拒绝（401/403/404），补丁不能只挡住基线写法`,
        verify: (res, phase) => {
          const o = extractEntity(res.json, entityPathFor(ctx, primaryRead.graphql));
          const leaked = o && String(resourceIdOf(o)) === String(v.targetId);
          if (leaked && targets.attackerOwnIds?.has(String(v.targetId))) {
            return { verdict: "inconclusive", actual: `目标 #${v.targetId} 在 attacker 自己的资源列表中，疑似跨端点 id 串号，不计为越权` };
          }
          const detail = leaked
            ? `证据：变体写法仍返回${candLabel} #${resourceIdOf(o)}（归属 ${ownerOf(o)}），补丁只挡住了部分入口`
            : "";
          return verifyAttack(res, phase, detail, leaked);
        },
        crossProof: (res) => {
          const o = extractEntity(res.json, entityPathFor(ctx, primaryRead.graphql));
          if (!o || String(resourceIdOf(o)) !== String(v.targetId)) return null;
          if (victim.user?.id && ownerOf(o) !== victim.user.id) return null;
          return { note: `变体「${v.label}」命中的对象 #${resourceIdOf(o)} 归属 ${ownerOf(o)}（与受害人一致）` };
        },
        impact: (res) =>
          okStatus(res.status) ? `换一种写法即可绕过补丁继续越权读取他人${candLabel}` : null,
      });
    }
  }

  for (const [i, cand] of cancelCands.entries()) {
    const path = candPath(cand);
    if (!path || !targets.attackCancelTarget || !attacker || !victim) continue;
    const cancelTarget = targets.attackCancelTarget;
    const suffix = i === 0 ? "" : `-${i + 1}`;
    const multi = cancelCands.length > 1 ? `（${path}）` : "";
    const candLabel = resourceLabelOf(cand.resource ?? ctx.plan?.resource);
    const req = candRequest(ctx, cand, cancelTarget.id);
    cases.push({
      id: `attack-cancel-foreign${suffix}`,
      candidateKey: candKey(cand),
      category: CASE_CATEGORY.ATTACK,
      name: `${attacker.name} 取消 ${victim.name} 的${candLabel} #${cancelTarget.id}${multi}`,
      identity: attacker.name,
      method: req.method ?? cand.method ?? "POST",
      path: req.path,
      body: req.body,
      graphql: req.graphql ?? null,
      routeKey: cand.routeKeys?.[0] ?? cancelKey,
      expect: `越权取消他人${candLabel}应被拒绝（401/403/404）`,
      verify: (res, phase) => {
        const o = extractEntity(res.json, entityPathFor(ctx, cand.graphql));
        const changed =
          o && o.status === "cancelled" && (!victim.user?.id || ownerOf(o) === victim.user.id);
        const detail = changed ? `证据：${candLabel} #${o.id}（归属 ${ownerOf(o)}）状态已被改为 cancelled` : "";
        return verifyAttack(res, phase, detail, changed);
      },
      crossProof: (res) => {
        const o = extractEntity(res.json, entityPathFor(ctx, cand.graphql));
        if (!o || o.id !== cancelTarget.id) return null;
        if (victim.user?.id && ownerOf(o) !== victim.user.id) return null;
        return {
          note: `被操对象 #${o.id} 归属 ${ownerOf(o)}${o.status === "cancelled" ? "，状态已变更为 cancelled" : ""}`,
        };
      },
      impact: (res) => {
        const o = extractEntity(res.json, entityPathFor(ctx, cand.graphql));
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
      method: adminListReq?.method ?? "GET",
      path: adminListReq?.path ?? adminListPath,
      body: adminListReq?.body ?? null,
      graphql: adminListReq?.graphql ?? null,
      routeKey: ctx.plan.adminListEndpoint?.routeKey ?? "admin.orders.list",
      expect: "普通用户访问管理端应被拒绝（401/403/404）",
      verify: (res, phase) => {
        const arr = extractListItems(res.json, listPathFor(ctx, ctx.plan.adminListEndpoint?.graphql));
        const leaked = arr && arr.length > 0;
        const detail = leaked
          ? `证据：返回 ${arr.length} 条${label}（归属 ${[...new Set(arr.map((o) => ownerOf(o)))].join(",")}），纵向越权可览全局数据`
          : "";
        return verifyAttack(res, phase, detail, leaked);
      },
      crossProof: (res) => {
        const arr = extractListItems(res.json, listPathFor(ctx, ctx.plan.adminListEndpoint?.graphql));
        if (!arr || arr.length === 0) return null;
        const foreign = arr.filter((o) => ownerOf(o) !== victim.user?.id).length;
        if (foreign === 0) return null;
        return { note: `普通用户响应含 ${foreign} 条他人${label}（跨归属全局列表）` };
      },
      impact: (res) => {
        const arr = extractListItems(res.json, listPathFor(ctx, ctx.plan.adminListEndpoint?.graphql));
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
    const req = candRequest(ctx, cand, anonTarget.id);
    cases.push({
      id: `attack-anonymous-read${suffix}`,
      candidateKey: candKey(cand),
      category: CASE_CATEGORY.ATTACK,
      name: `未携带凭证读取${candLabel} #${anonTarget.id}（无鉴权端点${multiText}）`,
      identity: null,
      method: req.method ?? "GET",
      path: req.path,
      body: req.body,
      graphql: req.graphql ?? null,
      routeKey: cand.routeKeys?.[0] ?? null,
      expect: `未认证读取${candLabel}应被拒绝（401/403/404）`,
      verify: (res, phase) => {
        const o = extractEntity(res.json, entityPathFor(ctx, cand.graphql));
        const leaked = o && String(o.id) === String(anonTarget.id);
        const detail = leaked
          ? `证据：匿名请求即返回${candLabel} #${o.id}（归属 ${ownerOf(o)}），无需任何认证`
          : "";
        return verifyAttack(res, phase, detail, leaked);
      },
      crossProof: (res) => {
        const o = extractEntity(res.json, entityPathFor(ctx, cand.graphql));
        if (!o || o.id !== anonTarget.id) return null;
        return { note: `匿名响应对象 #${o.id} 与请求目标一致，归属 ${ownerOf(o)}` };
      },
      impact: (res) => {
        const o = extractEntity(res.json, entityPathFor(ctx, cand.graphql));
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
      candidateKey: candKey(cand),
      category: CASE_CATEGORY.ATTACK,
      unfixable: true,
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

  // —— SQL 注入用例：随机基线 vs 布尔/报错载荷（无修复模板，仅取证）——
  for (const [i, cand] of planCandidates(ctx, "sqli").entries()) {
    const injection = cand.sqli;
    const routePath = candPath(cand);
    if (!routePath || !injection) continue;
    const suffix = i === 0 ? "" : `-${i + 1}`;
    const firstReq = injectionReq(cand, injection, SQLI_PAYLOADS[0]);
    if (!firstReq) continue;
    const injIdentity = attacker?.name ?? victim?.name ?? null;
    cases.push({
      id: `attack-sql-injection${suffix}`,
      candidateKey: candKey(cand),
      category: CASE_CATEGORY.ATTACK,
      unfixable: true,
      name: `SQL 注入（${routePath} · 参数 ${injection.param ?? "?"}）`,
      identity: injIdentity,
      method: firstReq.method,
      path: firstReq.path,
      body: firstReq.body,
      routeKey: cand.routeKeys?.[0] ?? null,
      expect: "注入载荷不得改变查询结果或泄露额外数据（应被参数化/校验拦截）",
      send: async (c, baseUrl) => {
        let benign = null;
        try {
          const benignReq = injectionReq(cand, injection, shortId("q"));
          benign = await httpJson(c, { baseUrl, ...benignReq, identity: injIdentity });
        } catch {
          /* 基线失败不阻断：以攻击响应的行数差/报错特征为主 */
        }
        let last = null;
        let lastReq = firstReq;
        let hit = null;
        let hitReq = null;
        let proof = null;
        let firstErr = null;
        for (const payload of SQLI_PAYLOADS) {
          const req = injectionReq(cand, injection, payload);
          try {
            const res = await httpJson(c, { baseUrl, ...req, identity: injIdentity });
            last = res;
            lastReq = req;
            const p = sqliProof(res, benign, payload);
            if (p.hit) {
              hit = res;
              hitReq = req;
              proof = p;
              break;
            }
            proof = proof ?? p;
          } catch (e) {
            if (!firstErr) firstErr = e;
          }
        }
        if (!last) {
          throw firstErr ?? new ProbeError(`SQL 注入探测请求全部失败（${routePath}）`, { code: "probe_request_failed" });
        }
        const chosen = hit ?? last;
        chosen._sqliProof = proof ?? { hit: false, payload: SQLI_PAYLOADS[0] };
        return { res: chosen, path: (hitReq ?? lastReq).path, method: (hitReq ?? lastReq).method };
      },
      verify: (res, phase) => {
        const p = res._sqliProof ?? {};
        const detail = p.hit
          ? `证据：${
              p.errorSignature
                ? "注入请求触发数据库报错特征"
                : p.singleLeak
                  ? "正常值未命中（404/400），注入后独占返回对象"
                  : `注入后返回 ${p.attackCount} 行（正常查询 ${p.baseCount} 行）`
            }，载荷 ${p.payload}`
          : "";
        if (phase === "pre" && p.hit) {
          return { verdict: VERDICT.VULNERABLE, actual: `HTTP ${res.status}，SQL 注入被放行。${detail}` };
        }
        return verifyAttack(res, phase, detail, p.hit);
      },
      crossProof: (res) => {
        const p = res._sqliProof ?? {};
        if (!p.hit) return null;
        return {
          note: p.errorSignature
            ? `注入请求独有数据库报错特征，确认输入进入 SQL 解析（载荷 ${p.payload}）`
            : p.singleLeak
              ? `基线查询该值明确未命中，注入载荷后返回了对象，确认 WHERE 条件被绕过（载荷 ${p.payload}）`
              : `注入后行数由 ${p.baseCount ?? "未知"} 增至 ${p.attackCount}，确认查询条件被绕过`,
        };
      },
      impact: (res) =>
        res._sqliProof?.hit ? "可通过 SQL 注入绕过查询条件读取数据库数据或触发数据库错误" : null,
    });
  }

  // —— 命令注入用例：shell 展开令牌（%OS% / $(id -u)）作证，避免输入反射误报 ——
  for (const [i, cand] of planCandidates(ctx, "cmdi").entries()) {
    const injection = cand.cmdi;
    const routePath = candPath(cand);
    if (!routePath || !injection) continue;
    const suffix = i === 0 ? "" : `-${i + 1}`;
    const token = shortId("c").replace(/_/g, "");
    const attempts = cmdiAttempts(token);
    const firstReq = injectionReq(cand, injection, attempts[0].payload);
    if (!firstReq) continue;
    const injIdentity = attacker?.name ?? victim?.name ?? null;
    cases.push({
      id: `attack-command-injection${suffix}`,
      candidateKey: candKey(cand),
      category: CASE_CATEGORY.ATTACK,
      unfixable: true,
      name: `命令注入（${routePath} · 参数 ${injection.param ?? "?"}）`,
      identity: injIdentity,
      method: firstReq.method,
      path: firstReq.path,
      body: firstReq.body,
      routeKey: cand.routeKeys?.[0] ?? null,
      expect: "命令注入载荷不得被执行（响应不得出现 shell 展开的令牌）",
      send: async (c, baseUrl) => {
        let last = null;
        let lastReq = firstReq;
        let hit = null;
        let hitReq = null;
        let hitPayload = null;
        let firstErr = null;
        for (const attempt of attempts) {
          const req = injectionReq(cand, injection, attempt.payload);
          try {
            const res = await httpJson(c, { baseUrl, ...req, identity: injIdentity });
            last = res;
            lastReq = req;
            if (attempt.marker.test(res.body ?? "")) {
              hit = res;
              hitReq = req;
              hitPayload = attempt.payload;
              break;
            }
          } catch (e) {
            if (!firstErr) firstErr = e;
          }
        }
        if (!last) {
          throw firstErr ?? new ProbeError(`命令注入探测请求全部失败（${routePath}）`, { code: "probe_request_failed" });
        }
        const chosen = hit ?? last;
        chosen._cmdiProof = { hit: !!hit, payload: hitPayload ?? attempts[0].payload };
        return { res: chosen, path: (hitReq ?? lastReq).path, method: (hitReq ?? lastReq).method };
      },
      verify: (res, phase) => {
        const p = res._cmdiProof ?? {};
        const detail = p.hit ? `证据：响应中出现 shell 展开后的令牌（载荷 ${p.payload}）` : "";
        if (phase === "pre" && p.hit) {
          return { verdict: VERDICT.VULNERABLE, actual: `HTTP ${res.status}，命令注入被放行。${detail}` };
        }
        return verifyAttack(res, phase, detail, p.hit);
      },
      crossProof: (res) => {
        const p = res._cmdiProof ?? {};
        if (!p.hit) return null;
        return { note: `注入令牌由 shell 展开（反射原文不含展开值），确认命令被执行：${p.payload}` };
      },
      impact: (res) =>
        res._cmdiProof?.hit ? "可通过命令注入在服务器执行任意系统命令（RCE）" : null,
    });
  }

  // —— 业务用例（回归防线）——
  // 正向断言：修复不得把「本人可见」一并关掉，也不得靠删字段/返回空壳来伪装「攻击已阻断」。
  // 字段契约以修复前的响应为基线（runPhase 在 pre 阶段记录），修复后缺字段即判回归。
  const ownerReadCase = (id, ident, ownTarget) => {
    const req = candRequest(ctx, readCands[0], ownTarget.id);
    const entityOf = (res) => extractEntity(res.json, entityPathFor(ctx, readCands[0]?.graphql));
    return {
      id,
      category: CASE_CATEGORY.BUSINESS,
      name: `${ident.name} 读取自己的${label} #${ownTarget.id}`,
      identity: ident.name,
      method: req.method ?? "GET",
      path: req.path,
      body: req.body,
      graphql: req.graphql ?? null,
      routeKey: readKey,
      expect: `本人${label}应正常可见（200，且归属本人、字段不减少）`,
      contract: (res) => Object.keys(entityOf(res) ?? {}),
      verify: (res) =>
        verifyBusiness(res, 200, () => {
          const o = entityOf(res);
          if (!o) return `FAIL:响应缺少${label}对象`;
          if (String(resourceIdOf(o)) !== String(ownTarget.id)) return `FAIL:返回了错误的${label} #${resourceIdOf(o)}`;
          if (ownerOf(o) !== ident.user?.id) return `FAIL:${label}归属异常 ${ownerOf(o)}`;
          const base = ctx._ownerContract?.get(id) ?? [];
          const missing = base.filter((k) => !(k in o));
          if (missing.length) return `FAIL:字段契约缺失 ${missing.join("、")}（不得删减本人可见内容来冒充修复）`;
          return `返回${label} #${resourceIdOf(o)}，归属 ${ownerOf(o)}，字段 ${Object.keys(o).length} 项`;
        }),
    };
  };

  const own = targets.ownReadTarget;
  if (readPath && own && attacker) {
    cases.push(ownerReadCase("business-read-own", attacker, own));
  }

  // 受害人侧正向断言：补丁常见错误是「只放行 attacker 名下」这类按身份写死的判断
  if (readPath && targets.victimOwnTarget && victim) {
    cases.push(ownerReadCase("business-read-own-victim", victim, targets.victimOwnTarget));
  }

  if (listPath && attacker) {
    cases.push({
      id: "business-list-own",
      category: CASE_CATEGORY.BUSINESS,
      name: `${attacker.name} 查询${label}列表仅见本人${label}`,
      identity: attacker.name,
      method: listReq?.method ?? "GET",
      path: listReq?.path ?? listPath,
      body: listReq?.body ?? null,
      graphql: listReq?.graphql ?? null,
      routeKey: ctx.plan.listEndpoint?.routeKey ?? "orders.list",
      expect: `列表应只包含本人${label}（owner-filter 保持有效）`,
      verify: (res) =>
        verifyBusiness(res, 200, () => {
          const arr = extractListItems(res.json, listPathFor(ctx, ctx.plan.listEndpoint?.graphql));
          if (!arr) return `FAIL:响应中未找到${label}列表`;
          const foreign = arr.filter((o) => ownerOf(o) !== attacker.user?.id);
          if (foreign.length > 0) return `FAIL:列表泄露他人${label} ${foreign.map((o) => o.id).join(",")}`;
          return `共 ${arr.length} 条，全部归属 ${attacker.user?.id}`;
        }),
    });
  }

  if (cancelPath && targets.ownCancelTarget && attacker) {
    const c = targets.ownCancelTarget;
    const ownCancelReq = candRequest(ctx, cancelCands[0], c.id);
    cases.push({
      id: "business-cancel-own",
      category: CASE_CATEGORY.BUSINESS,
      name: `${attacker.name} 取消自己的${label} #${c.id}`,
      identity: attacker.name,
      method: ownCancelReq.method ?? "POST",
      path: ownCancelReq.path,
      body: ownCancelReq.body,
      graphql: ownCancelReq.graphql ?? null,
      routeKey: cancelKey,
      expect: `本人已支付${label}应可正常取消（200）`,
      verify: (res) =>
        verifyBusiness(res, 200, () => {
          const o = extractEntity(res.json, entityPathFor(ctx, cancelCands[0]?.graphql));
          if (!o) return `FAIL:响应缺少${label}对象`;
          if (o.status !== "cancelled") return `FAIL:状态未变更（${o.status}）`;
          return `${label} #${o.id} 已置为 cancelled`;
        }),
    });
  }

  if (cancelPath && targets.ownNotCancellable && attacker) {
    const s = targets.ownNotCancellable;
    const shippedReq = candRequest(ctx, cancelCands[0], s.id);
    cases.push({
      id: "business-shipped-guard",
      category: CASE_CATEGORY.BUSINESS,
      name: `${attacker.name} 取消已发货${label} #${s.id} 被业务规则拒绝`,
      identity: attacker.name,
      method: shippedReq.method ?? "POST",
      path: shippedReq.path,
      body: shippedReq.body,
      graphql: shippedReq.graphql ?? null,
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
      method: adminListReq?.method ?? "GET",
      path: adminListReq?.path ?? adminListPath,
      body: adminListReq?.body ?? null,
      graphql: adminListReq?.graphql ?? null,
      routeKey: ctx.plan.adminListEndpoint?.routeKey ?? "admin.orders.list",
      expect: `管理员应可查看全部${label}（200，跨多个归属）`,
      verify: (res) =>
        verifyBusiness(res, 200, () => {
          const arr = extractListItems(res.json, listPathFor(ctx, ctx.plan.adminListEndpoint?.graphql));
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
    const adminCancelReq = candRequest(ctx, ctx.plan.adminCancelEndpoint, adminTarget.id);
    cases.push({
      id: "business-admin-cancel",
      category: CASE_CATEGORY.BUSINESS,
      name: `管理员代取消 ${victim.name} 的${label} #${adminTarget.id}`,
      identity: admin.name,
      method: adminCancelReq.method ?? "POST",
      path: adminCancelReq.path,
      body: adminCancelReq.body,
      graphql: adminCancelReq.graphql ?? null,
      routeKey: ctx.plan.adminCancelEndpoint?.routeKey ?? "admin.orders.cancel",
      expect: "管理员合法代操作应保持可用（200）",
      verify: (res) =>
        verifyBusiness(res, 200, () => {
          const o = extractEntity(res.json, entityPathFor(ctx, ctx.plan.adminCancelEndpoint?.graphql));
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
      method: adminListReq?.method ?? "GET",
      path: adminListReq?.path ?? adminListPath,
      body: adminListReq?.body ?? null,
      graphql: adminListReq?.graphql ?? null,
      routeKey: ctx.plan.adminListEndpoint?.routeKey ?? "admin.orders.list",
      expect: "普通用户访问管理端应被拒绝（403），角色校验保持有效",
      verify: (res) => {
        if (res.status === 403 || res.status === 401 || res.graphqlDenied) {
          return {
            verdict: VERDICT.PASSED,
            actual: res.graphqlDenied && !DENIED_STATUS.has(res.status)
              ? "HTTP 200 + GraphQL 拒绝（语义拒绝），角色校验（admin）生效"
              : `HTTP ${res.status}，角色校验（role:admin）生效`,
          };
        }
        const arr = extractListItems(res.json, listPathFor(ctx, ctx.plan.adminListEndpoint?.graphql));
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
    const anonReq = candRequest(ctx, readCands[0], own.id);
    cases.push({
      id: "business-unauth-401",
      category: CASE_CATEGORY.BUSINESS,
      name: `未登录访问${label}详情被拒绝`,
      identity: null,
      method: anonReq.method ?? "GET",
      path: anonReq.path,
      body: anonReq.body,
      graphql: anonReq.graphql ?? null,
      routeKey: readKey,
      expect: "未认证请求应被拒绝（401），认证入口保持有效",
      verify: (res) => {
        if (res.status === 401) return { verdict: VERDICT.PASSED, actual: "HTTP 401，认证拦截生效" };
        if (res.status === 403) return { verdict: VERDICT.PASSED, actual: "HTTP 403，认证拦截生效" };
        if (res.graphqlDenied) {
          return { verdict: VERDICT.PASSED, actual: `HTTP ${res.status} + GraphQL 拒绝（语义拒绝），认证拦截生效` };
        }
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
/**
 * 修复后阶段的用例范围（纯函数，便于单测）。
 *  - `unfixable`（无确定性模板）用例：只有补丁点名了它的候选才复跑——否则「本来就没修它」会被算成补丁无效；
 *  - `requiresPreRepro` 变体：只有修复前确实复现过才参与（目标本就不认这种写法时，路由 404 不是补丁的功劳）。
 */
export function postPhaseCases(orderedCases, { claimed = new Set(), preVerdicts = new Map() } = {}) {
  const cases = [];
  let variantSkipped = 0;
  for (const c of orderedCases) {
    if (c.unfixable && !(c.candidateKey && claimed.has(c.candidateKey))) continue;
    if (c.requiresPreRepro && preVerdicts.get(c.id) !== VERDICT.VULNERABLE) {
      variantSkipped += 1;
      continue;
    }
    cases.push(c);
  }
  return { cases, variantSkipped };
}

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
  await negotiateTrpcInput(ctx, baseUrl, loggedIn);
  await confirmGraphqlEndpoint(ctx, baseUrl, loggedIn);
  await negotiateGraphqlCast(ctx, baseUrl, loggedIn);
  const { byUser, anonymousItems, anonTargets } = await discoverResources(ctx, baseUrl, loggedIn);
  const targets = pickTargets(byUser, loggedIn, anonymousItems, anonTargets);
  // 身份交叉校验：attacker 与 victim 必须是两个不同用户，否则"越权读他人"用例退化为"读自己"
  if (targets.attacker && targets.victim) {
    const aId = targets.attacker.user?.id;
    const vId = targets.victim.user?.id;
    if (aId != null && vId != null && String(aId) === String(vId)) {
      ctx.emit({
        kind: "discovery",
        severity: SEVERITY.WARN,
        message: `attacker(${targets.attacker.name}) 与 victim(${targets.victim.name}) 登录后解析出的用户 id 相同（${aId}），越权用例可能退化为"读自己"。请检查 guardbuild.json 的 identities 是否配置了两个真实不同的账号`,
        data: { attackerId: aId, victimId: vId },
      });
    }
    const victimItems = byUser[targets.victim.name] ?? [];
    if (victimItems.length === 0) {
      ctx.emit({
        kind: "discovery",
        severity: SEVERITY.WARN,
        message: `victim(${targets.victim.name}) 名下未发现任何资源（列表接口返回空），越权读用例将依赖匿名探测兜底；若结果全为 inconclusive，请确认 victim 账号下有可访问数据`,
      });
    }
  }
  const allCases = buildCases(ctx, targets);
  // 路径穿越会把不存在的路径打到文件读取接口，个别实现会同步请求外部依赖并阻塞事件循环；
  // 排在最后，避免一条挂起的用例拖掉整轮注入取证（后续请求仍返回 inconclusive）。
  const isTraversal = (c) => c.category === CASE_CATEGORY.ATTACK && c.id.startsWith("attack-path-traversal");
  const orderedCases = [...allCases.filter((c) => !isTraversal(c)), ...allCases.filter(isTraversal)];
  // 外部攻击面扫描：发常见管理路径/敏感文件，记录暴露面（pre 阶段才跑）
  if (phase === "pre") {
    await scanAttackSurface(ctx, baseUrl, loggedIn);
    await rateLimitCheck(ctx, baseUrl, loggedIn);
  }
  // 修复后验收覆盖范围：补丁没点名的注入/穿越/无鉴权候选没有自动修复模板，若与可修复项混在
  // 同一目标中仍按原样复现，会把「本来就没修它」误判成「补丁无效」；但补丁一旦声明修了某个
  // 无模板候选（LLM 编码代理路径），它的用例必须进修复后阶段——否则该候选的「已修复」无从归属。
  const claimed = ctx._claimedCandidates instanceof Set ? ctx._claimedCandidates : new Set();
  let variantSkipped = 0;
  let cases = orderedCases;
  if (phase !== "pre") {
    const scoped = postPhaseCases(orderedCases, { claimed, preVerdicts: ctx._preCaseVerdicts });
    cases = scoped.cases;
    variantSkipped = scoped.variantSkipped;
  }
  const variantPlanned = orderedCases.filter((c) => c.requiresPreRepro).length;
  if (phase !== "pre" && variantSkipped > 0) {
    ctx.emit({
      kind: "phase",
      severity: SEVERITY.INFO,
      message: `修复后验收跳过 ${variantSkipped}/${variantPlanned} 条变体用例（修复前未复现，该目标不认这种写法）`,
      phase,
      data: { variantSkipped, variantPlanned },
    });
  }
  const skippedUnfixable = phase === "pre" ? [] : allCases.filter((c) => c.unfixable);
  if (skippedUnfixable.length > 0) {
    ctx.emit({
      kind: "phase",
      severity: SEVERITY.INFO,
      message: `修复后验收跳过 ${skippedUnfixable.length} 条无自动修复模板的攻击用例（注入/穿越类仅取证）`,
      phase,
      data: { skipped: skippedUnfixable.map((c) => c.id) },
    });
  }

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
    { slot: "sqliCandidate", prefix: "attack-sql-injection", count: planCandidates(ctx, "sqli").length },
    { slot: "cmdiCandidate", prefix: "attack-command-injection", count: planCandidates(ctx, "cmdi").length },
  ].filter((s) => s.count > 0);
  const skipped = plannedSlots.filter(
    (s) => !allCases.some((c) => c.id === s.prefix || c.id.startsWith(`${s.prefix}-`))
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
  let consecutiveSendFailures = 0;
  let skippedSendFailures = 0;
  for (const kase of cases) {
    let res;
    let sentPath = kase.path;
    let sentMethod = kase.method;
    try {
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
          graphql: !!kase.graphql,
        });
      }
    } catch (e) {
      if (e?.code !== "probe_request_failed") throw e;
      // 单条用例的请求失败不足以否定其他候选：跳过并继续，连续两条才判定目标不可用
      consecutiveSendFailures += 1;
      skippedSendFailures += 1;
      ctx.emit({
        kind: "discovery",
        severity: SEVERITY.WARN,
        message: `攻击用例「${kase.name}」请求失败，跳过该用例继续取证：${String(e.message ?? e).slice(0, 240)}`,
        data: { caseId: kase.id, code: e.code },
      });
      if (consecutiveSendFailures >= 2) {
        throw new ProbeError(`连续 ${consecutiveSendFailures} 条攻击用例请求失败，目标可能已不可用：${e.message}`, {
          code: "probe_request_failed",
          hint: "请确认目标服务仍在运行；若探测过程中目标崩溃或阻塞（例如同步请求外部依赖），请修复后重试",
        });
      }
      continue;
    }
    consecutiveSendFailures = 0;
    const fresh = await fetchNewDecisions(ctx, baseUrl);
    const decision = matchDecision(fresh, { method: sentMethod, path: sentPath, routeKey: kase.routeKey });
    const { verdict, actual } = kase.verify(res, phase);
    if (phase === "pre") {
      // 记下修复前结论与「本人可见」的字段基线，供修复后验收判定变体是否参与、字段是否被删减
      (ctx._preCaseVerdicts ??= new Map()).set(kase.id, verdict);
      (ctx._preCaseMeta ??= new Map()).set(kase.id, {
        candidateKey: kase.candidateKey ?? null,
        category: kase.category,
        name: kase.name,
      });
      if (kase.contract) {
        const keys = kase.contract(res);
        if (keys?.length) (ctx._ownerContract ??= new Map()).set(kase.id, keys);
      }
    }
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
      caseCandidate: kase.candidateKey ?? null,
      caseVariant: kase.variant ? { axis: kase.variant.axis, label: kase.variant.label } : null,
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

  // 全轮请求失败不能当成「目标无漏洞」退出：没有证据是网络/可用性问题，不是复现结论
  if (evidence.length === 0 && skippedSendFailures > 0) {
    throw new ProbeError(`全部 ${skippedSendFailures} 条用例请求失败，未能建立任何证据`, {
      code: "probe_request_failed",
      hint: "请确认目标服务仍在运行；若探测过程中目标崩溃或阻塞，请修复后重试",
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
    variantPlanned,
    variantCounted: cases.filter((c) => c.requiresPreRepro).length,
    variantSkipped,
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
        : `修复后验收完成：攻击阻断 ${summary.attackBlocked}/${attackRecords.length}（其中同源变体 ${summary.variantCounted} 条），业务回归 ${summary.businessPassed}/${summary.businessTotal} 通过`,
    phase,
    data: summary,
  });

  return { evidence, summary };
}
