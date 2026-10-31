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
import { createServer } from "node:http";
import { createHmac } from "node:crypto";
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
import { MAX_VARIANT_CASES, channelVariantFor, foreignObjectVariants, idEncodingVariants, rawTokenRequest, variantCaseId } from "./attackvariants.mjs";
import {
  baselineStep,
  identityRole,
  loadRecipe,
  ownTargetFor,
  ownershipReadbacks,
  requestSteps,
  resolvePlanField,
  resolveRole,
  resolveRolePreferred,
  variantAxisSteps,
} from "./recipes.mjs";
import { buildProbePlan, candKey } from "./planner.mjs";
import {
  MAX_SCOUT_ROUTES,
  verifyScoutRoutes,
  allRequestsMissed,
  isAbsentStatus,
  looksDenied,
  sameBody,
  ABSENT_PROBE_PATH,
} from "./routeverify.mjs";
import {
  MAX_CONTRACT_REQUESTS,
  MAX_LIST_SLOTS,
  compareIdSets,
  contractForCache,
  contractFingerprint,
  discoverBindings,
  discoverEntityContract,
  discoverListContract,
  readCommitFromGit,
  readContractCache,
  validateExtras,
  writeContractCache,
} from "./rescontract.mjs";
import {
  distinctiveMarkers,
  extractPageIds,
  looksHtml,
  markersInText,
  pageText,
} from "./html.mjs";
import {
  classifyRegisterResponse,
  classifySeedResponse,
  generateCanary,
  generateTestPassword,
  registerBody,
  resolveRegisterEndpoint,
  seedBody,
  signupCandidates,
} from "./identityboot.mjs";
import { chat as llmChat, isEnabled as llmIsEnabled, parseJson as llmParseJson } from "./llm.mjs";
import {
  askRegisterAgent,
  buildRegisterMenu,
  cacheKeyFor,
  enrichMenuWithHandlers,
  patchAgentCache,
  readAgentCache,
  selfBootAgentEnabled,
  selfBootBudget,
  selfBootModelCallable,
  writeAgentCache,
} from "./selfbootagent.mjs";
import {
  attributeCanary,
  canaryBody,
  extractBodyFields,
  readHandlerSource,
  seedWriteCandidates,
  showsCanary,
} from "./seedobserve.mjs";

export class ProbeError extends Error {
  constructor(message, { code = "probe_failed", hint = null, details = null } = {}) {
    super(message);
    this.code = code;
    this.hint = hint;
    this.details = details;
  }
}

const DENIED_STATUS = new Set([401, 403, 404]);
// 业务规则拒绝：409 冲突 / 422 无法处理，同样说明前置条件或幂等保护生效
const REJECTED_STATUS = (s) => DENIED_STATUS.has(s) || s === 409 || s === 422;

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

/**
 * 响应取值路径的统一读取顺序：人工契约（guardbuild.json）> 运行期实测推断（ctx._derived）> 框架形态。
 * 自动发现只补「人没声明」的空洞，绝不覆盖人工声明；它自己也已经过真实请求验证。
 */
function respPath(ctx, key) {
  const manual = ctx?.targetConfig?.responses?.[key];
  if (manual) return manual;
  return ctx?._derived?.[key] ?? null;
}

/** 归属字段读取：契约 responses.owner（或路由 ownerField）优先，未声明时兼容常见命名 */
const OWNER_FALLBACK_KEYS = ["userId", "user_id", "ownerId", "owner_id", "uid", "created_by_uid", "createdByUid", "created_by"];
export function ownerOf(ctx, obj, override = null) {
  const path = override ?? respPath(ctx, "owner");
  if (path) return getByDotPath(obj, path) ?? null;
  for (const key of OWNER_FALLBACK_KEYS) {
    const v = obj?.[key];
    if (v !== undefined && v !== null) return v;
  }
  return null;
}

/** 资源主键读取：契约 responses.id（或路由 idField）优先，未声明时兼容 id / userId 等命名 */
const ID_FALLBACK_KEYS = ["id", "resourceId", "userId", "user_id"];
export function resourceIdOf(ctx, obj, override = null) {
  const path = override ?? respPath(ctx, "id");
  if (path) return getByDotPath(obj, path) ?? null;
  for (const key of ID_FALLBACK_KEYS) {
    const v = obj?.[key];
    if (v !== undefined && v !== null) return v;
  }
  return null;
}

function contentFieldOf(o) {
  for (const key of ["title", "name", "note", "content", "description"]) {
    const v = o?.[key];
    if (typeof v === "string" && v.trim()) return [key, v.length > 60 ? `${v.slice(0, 60)}…` : v];
  }
  return null;
}

/** 越权读取的证据要点：只列响应里真实存在的字段。
 *  此前硬编码「金额/状态」，目标没有这两个字段时正文写出 undefined，
 *  也看不出这条对象是不是本轮实测写进目标的那一条——内容字段才是能比对归属的证据。 */
function leakEvidenceFields(ctx, o, ownerField) {
  const parts = [`归属 ${ownerOf(ctx, o, ownerField)}`];
  if (o.amount !== undefined && o.amount !== null) parts.push(`金额 ${o.amount}`);
  if (o.status !== undefined && o.status !== null) parts.push(`状态 ${o.status}`);
  const content = contentFieldOf(o);
  if (content) parts.push(`${content[0]} ${content[1]}`);
  return parts.join("，");
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
    // 跳转链要像浏览器一样带上刚存下的会话：Host 在首个响应里就把凭据入库，
    // 若跟随跳转的请求仍不带 Cookie/令牌，302 后的页面看上去永远是匿名形态。
    let attached = identity ?? null;
    const holder = storeCookieAs ?? storeAs;
    const send = async (next) => {
      const r = await ctx.rpc.request(
        RPC_TO_HOST.HTTP_REQUEST,
        attached ? { ...params, url: next, identityRef: attached } : { ...params, url: next },
        { timeoutMs: 30_000 }
      );
      if (!attached && holder && r?.storedIdentity === holder) attached = holder;
      return r;
    };
    const followed = await followRedirects(send, url, { method });
    res = followed.res;
    if (followed.hops.length) res = { ...res, redirects: followed.hops };
    res = { ...res, finalUrl: followed.url };
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
  if (attempts.some((a) => a.shape === "login-form")) {
    return {
      code: "login_form_rerendered",
      hint: `登录端点返回 HTTP ${statuses[statuses.length - 1] ?? "?"}，但响应体仍是登录表单（含密码输入框）——凭据未被接受，会话没有建立（${tried.join("、")}）。GuardBuild 不会把这种响应记成登录成功：拿匿名会话去跑越权用例会全线被拒，最后错报成「未复现」。请核对 guardbuild.json 中 identities 的账号密码（测试账号是否已存在于目标库）与 login.bodyTemplate 字段名；若目标登录后仍返回带表单的页面（靠前端跳转），请改用可判定的 API 登录端点。`,
    };
  }
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

const LOGIN_FORM_WINDOW = 20000;

/**
 * 响应体是否仍是登录表单。真实项目的登录失败通常是 HTTP 200 + 原地重渲染的表单
 * （带密码输入框、并照样下发会话 Cookie），不是 401；只按状态码判定会把匿名会话记成登录成功。
 */
export function rendersLoginForm(res) {
  const body = typeof res?.body === "string" ? res.body : "";
  if (!body) return false;
  const window = body.length > LOGIN_FORM_WINDOW ? body.slice(0, LOGIN_FORM_WINDOW) : body;
  return /<input[^>]+\btype\s*=\s*["']?password/i.test(window);
}

/**
 * 响应是否绕回了登录页本身（原地 200 重渲染，或跳转链上出现登录路径）。
 * 与「含密码输入框」合取才判失败：JSON API 登录成功也停在原路径，但没有表单。
 */
function bouncedToLogin(res, baseUrl, loginPath) {
  const norm = (p) => {
    if (typeof p !== "string" || !p) return null;
    let pathname = p;
    try {
      pathname = new URL(p, baseUrl).pathname;
    } catch {
      /* 已是路径形态 */
    }
    const stripped = pathname.replace(/[?#].*$/, "").replace(/\/+$/, "");
    return stripped || "/";
  };
  const want = norm(loginPath);
  if (!want) return false;
  const hops = (Array.isArray(res?.redirects) ? res.redirects : []).map((h) => norm(String(h).split(" ")[1]));
  if (hops.includes(want)) return true;
  return norm(res?.finalUrl) === want;
}

/** 会话视角下的「被拒绝」：状态码拒绝、JSON 拒绝信封，或响应体又是登录页 */
function deniedForSession(res) {
  if (!res) return false;
  if (res.status === 401 || res.status === 403) return true;
  return rendersLoginForm(res) || looksDenied(res.json);
}

/**
 * 挑一个「已知需要登录、无路径参数、只读、非角色门禁」的 GET 路径，用来回读会话真伪。
 * 排除 hasRoleGuard：角色不足时匿名与登录可能都是拒绝码，会把真实会话误判成无效。
 */
export function pickSessionProbePath(analysis, loginPath) {
  const eps = Array.isArray(analysis?.endpoints) ? analysis.endpoints : [];
  const isPublicish = (p) => /\/(login|signin|logout|register|signup|auth|token|health|ping|metrics)(\/|$)/i.test(p);
  const hit = eps.find(
    (e) =>
      e.hasAuth === true &&
      !e.hasRoleGuard &&
      String(e.method).toUpperCase() === "GET" &&
      typeof e.fullPath === "string" &&
      e.fullPath.startsWith("/") &&
      !e.fullPath.includes(":") &&
      !e.fullPath.includes("*") &&
      e.fullPath !== loginPath &&
      !isPublicish(e.fullPath)
  );
  return hit?.fullPath ?? null;
}

/**
 * 会话真实性回读：同一个受保护 GET，匿名与带会话各打一次。
 * 只有「匿名被拒 + 会话也被拒 + 两者同形」才判定会话没有建立——
 * 匿名不被拒说明该路径本来公开，读不出会话信息，不能据此否定身份。
 */
async function verifySessionAuthenticated(ctx, baseUrl, identity, probePath) {
  let anon = null;
  let sess = null;
  try {
    anon = await httpJson(ctx, { baseUrl, method: "GET", path: probePath, identity: null });
    sess = await httpJson(ctx, { baseUrl, method: "GET", path: probePath, identity });
  } catch {
    return { checked: false, reason: "request_failed" };
  }
  const anonDenied = deniedForSession(anon);
  const sessDenied = deniedForSession(sess);
  return {
    checked: true,
    path: probePath,
    anonStatus: anon?.status ?? null,
    sessStatus: sess?.status ?? null,
    untrusted: anonDenied && sessDenied && anon?.status === sess?.status && sameBody(anon, sess),
  };
}

/**
 * 登录成功后回读会话真伪：拿这个会话打一个静态确认需要登录的只读接口，
 * 与匿名请求比较。「200 + Set-Cookie」不等于身份成立——用未认证会话跑越权，
 * 全线被拒会被记成「已测未复现」放行，所以这里失败就终止本轮。
 */
async function assertSessionsAuthenticated(ctx, baseUrl, loggedIn, loginPath) {
  const probePath = pickSessionProbePath(ctx.analysis, loginPath);
  if (loggedIn.length === 0) return;
  if (!probePath) {
    // 没有可用探针就如实说明，不能既跳过又声称「身份已验证」
    ctx._sessionVerify = {
      status: "skipped",
      probePath: null,
      reason: "静态分析没有「无参数、只读、需登录」的接口可作探针",
      identities: loggedIn.map((i) => i.name),
    };
    ctx.emit({
      kind: "identity",
      severity: SEVERITY.INFO,
      message: "会话真实性回读未执行：静态分析没有「无参数、只读、需登录」的接口可作探针（越权用例仍按实际拒绝形态判定）",
      data: { loginEndpoint: loginPath, probePath: null },
    });
    return;
  }
  const checked = [];
  for (const ident of loggedIn) {
    const v = await verifySessionAuthenticated(ctx, baseUrl, ident.name, probePath);
    if (!v.checked) continue;
    checked.push({ ...v, identity: ident.name });
    if (v.untrusted) {
      throw new ProbeError(
        `身份「${ident.name}」的会话未通过鉴权回读：GET ${probePath} 与匿名请求同形（HTTP ${v.sessStatus}），该会话在目标上并未认证`,
        {
          code: "login_session_unverified",
          hint: `登录接口按状态码看似成功，但用该会话回读一个静态分析确认需要登录的只读接口时，响应与匿名请求完全同形——会话没有真正建立（常见于凭据被拒后目标仍返回 200）。本轮不会带着未认证会话继续跑越权用例（那会把「全线被拒」错报成「未复现」）。请核对 guardbuild.json 的 identities 是否为目标库中已存在且密码正确的账号；若登录响应需按字段判定，请声明 login.credentialPath。`,
          details: {
            identity: ident.name,
            probePath,
            loginEndpoint: loginPath,
            anonStatus: v.anonStatus,
            sessStatus: v.sessStatus,
          },
        }
      );
    }
  }
  if (checked.length > 0) {
    ctx._sessionVerify = {
      status: "verified",
      probePath,
      loginEndpoint: loginPath,
      identities: checked.map((c) => ({
        identity: c.identity,
        anonStatus: c.anonStatus,
        sessStatus: c.sessStatus,
      })),
    };
    ctx.emit({
      kind: "identity",
      severity: SEVERITY.INFO,
      message: `会话真实性已回读验证：GET ${probePath} 匿名被拒（HTTP ${checked[0].anonStatus}），${checked.length} 个身份均读通（HTTP ${checked.map((c) => c.sessStatus).join("/")}）`,
      data: { probePath, verified: checked.map((c) => c.sessStatus), loginEndpoint: loginPath },
    });
  }
}

/**
 * 身份自举（#179）：沙箱目标每次从空库启动，「两个各自名下有数据的账号」只能由引擎造。
 * 这一层只负责**确定性来源**的注册端点：契约 register.path > 静态识别的唯一建号候选；
 * 两者都打不中时不在这里猜——交给 #182 的 agent 编号菜单（见 loginAll 里的候选队列），
 * 兜底也没能实测出一个能建立会话的端点时，仍然显式 inconclusive（exit 2）。
 */
function registerPlan(ctx) {
  // 纯黑盒目标是外部在跑的实例：引擎不向它发注册请求（建号属于对他人系统的写操作，
  // 不在探测授权范围内）。黑盒身份必须是人已经准备好的账号。
  if (ctx.blackboxUrl) return { available: false, reason: "blackbox", candidates: [] };
  const cfg = ctx.registerConfig ?? null;
  if (cfg && cfg.enabled === false) return { available: false, reason: "disabled", candidates: [] };
  const resolved = resolveRegisterEndpoint(cfg, ctx.analysis);
  if (!resolved.path) {
    return { available: false, reason: resolved.source, candidates: resolved.candidates ?? [] };
  }
  return {
    available: true,
    path: resolved.path,
    source: resolved.source,
    method: cfg?.method ?? "POST",
    encoding: cfg?.encoding ?? "json",
    headers: cfg?.headers ?? {},
    bodyTemplate: cfg?.bodyTemplate ?? null,
    seed: cfg?.seed ?? [],
  };
}

/** 注册/种子请求体共用的取值；身份没写 email 时按名字派生一个保留域名邮箱 */
function registerValues(ident) {
  const slug =
    String(ident.username ?? ident.email ?? ident.name ?? "")
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "") || "gbuser";
  return {
    name: ident.name,
    username: ident.username ?? slug,
    email: ident.email ?? `${slug}@guardbuild.test`,
    password: ident.password,
  };
}

/** 注册端点来源的读者口径（报告/事件里要说清「这个端点是谁定的」） */
function sourceLabel(source) {
  return source === "contract"
    ? "契约 register.path"
    : source === "static"
      ? "静态建号形状"
      : source === "agent"
        ? "兜底代理提议、引擎实跑采纳"
        : String(source ?? "未知");
}

/** 候选端点的身份：同一路径配不同字段模板是两次不同的实测，不能互相顶替 */
function candidateKey(cand) {
  if (!cand) return "";
  return `${cand.method} ${cand.path} ${JSON.stringify(cand.bodyTemplate ?? null)}`;
}

/**
 * 留给纠偏轮的目标报错文本：引擎口令一律剔除、截断，且只存在于内存
 * （不进事件流、审计、报告，也不进磁盘缓存）。
 */
function scrubForAgent(text, secret) {
  const raw = typeof text === "string" ? text : text == null ? "" : String(text);
  const masked = secret ? raw.split(String(secret)).join("***") : raw;
  const flat = masked.replace(/\s+/g, " ").trim();
  return flat.length > 240 ? `${flat.slice(0, 240)}…` : flat;
}

/**
 * 把引擎自生成的口令登记进 Host 的 protected 保险库：只用于脱敏，不作为请求头凭证，
 * 也不出现在 credential.list。这样即使目标把凭据回显在响应里，流出 Host 的文本也已被掩码。
 * 失败不阻断本轮（口令仍只存在于内存），但要在报告里如实标注「未被脱敏引擎保护」。
 */
async function protectGeneratedSecret(ctx, identity, value) {
  try {
    await ctx.rpc.request(
      RPC_TO_HOST.CREDENTIAL_PROTECT,
      { token: ctx.tokens.http ?? ctx.tokens.net, label: `password:${identity}`, value },
      { timeoutMs: 10_000 }
    );
    return "ok";
  } catch (e) {
    return `failed：${e.message}`;
  }
}

/** 所有身份登录失败时的归因补充：自举试过但没换来会话，读者要能看到注册这一层的真实结果 */
function bootstrapSuffix(boot, reg, agent = null) {
  const agentNote = agent?.tried?.length
    ? `；注册兜底代理试过 ${agent.tried.map((c) => `${c.endpoint}→${c.verdict}`).join("、")}`
    : agent?.fallback
      ? `；注册兜底代理未给出可用端点（${agent.fallback}）`
      : "";
  if (reg) {
    return `（已尝试 ${boot.method ?? "POST"} ${boot.path ?? reg.endpoint ?? "—"} 自举：${reg.verdict ?? reg.reason}，HTTP ${reg.status ?? "—"}${agentNote}）`;
  }
  if (boot.available) return agentNote ? `（契约/静态端点之外${agentNote}）` : "";
  const why =
    boot.reason === "disabled"
      ? "被契约显式关闭（register.enabled=false）"
      : boot.reason === "blackbox"
        ? "纯黑盒模式不向外部目标发注册请求"
        : boot.reason === "static-ambiguous"
          ? `静态识别到 ${boot.candidates.length} 个建号候选，引擎不猜`
          : "静态未识别到注册路由";
  return `（身份自举未参与：${why}${agentNote}；可在 guardbuild.json 声明 register.path，或开启 register.agent 让模型在编号菜单里提议、由引擎实跑采纳后重跑）`;
}

/**
 * 所有身份登录（凭证直接存入 Host 保险库，不流经 Sidecar）。
 * 每个身份按自己的候选序列取登录端点：identities[].loginPath（多角色应用如
 * 组织者/参与者分别有 /auth/organiser/login 与 /auth/attendee/login）> 全局候选
 * （契约声明 > 静态分析 > /api/login）。身份登录不成即终止本轮——
 * 拿未认证会话继续跑，只会把「全线被拒」写成「已测未复现」。
 *
 * 登录不成时先做一次身份自举（register）：口令省略的身份必须先建号；声明了口令而目标不认，
 * 就用同一份凭据走目标的注册接口再试一次登录。两条路都要「目标真实响应」说话，
 * 任一环节不成立就抛错终止，绝不降级成匿名探测。
 */
export async function loginAll(ctx, baseUrl) {
  const cfg = ctx.loginConfig ?? null;
  const sharedCandidates = (
    Array.isArray(ctx.plan.loginCandidates) && ctx.plan.loginCandidates.length
      ? ctx.plan.loginCandidates
      : [ctx.plan.loginPath]
  ).filter(Boolean);
  const attempts = [];
  const cookieAuth = cfg?.cookieAuth === true;

  /** 单个身份在一个候选端点上的登录尝试 */
  const attemptLogin = async (ident, path) => {
    const isTrpcProc = looksLikeTrpcProcPath(path);
    // GraphQL 登录：同一 HTTP 端点上的 mutation，文档由静态分析出的登录字段（SDL）构造
    const gqlLogin = ctx.plan.graphql?.login ?? null;
    const isGqlLogin = !!gqlLogin?.field && path === gqlLogin.path && looksLikeGraphqlPath(path);
    const formAuth = cfg?.encoding === "form";
    const bodyPlain = buildLoginBody(ident, cfg);
    // Cookie 登录允许 3xx：登录接口常用 302 下发 Set-Cookie 并跳转
    // 「200 + 仍是登录表单」不算成功——真实项目登录失败常渲染表单并照样下发会话 Cookie
    const loginOk = (r) =>
      !!r &&
      r.storedIdentity === ident.name &&
      (cookieAuth ? r.status >= 200 && r.status < 400 : okStatus(r.status)) &&
      !(rendersLoginForm(r) && bouncedToLogin(r, baseUrl, path));
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
      const encoded = gqlReq || isTrpcProc ? null : encodeLoginBody(bodyPlain, formAuth);
      res = await httpJson(ctx, {
        baseUrl,
        method: "POST",
        path,
        body: gqlReq ? gqlReq.body : isTrpcProc ? encodeInput(bodyPlain, wrap) : encoded.body,
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
      // 会话条目不带口令：loggedIn 会流进目标选择、报告与视图，秘密只留在 ctx.identities 与保险库里
      const { password: _drop, ...sessionIdentity } = ident;
      return { ok: true, entry: { ...sessionIdentity, user }, endpoint: path };
    }
    attempts.push({
      path,
      identity: ident.name,
      status: res.status,
      shape: rendersLoginForm(res) && bouncedToLogin(res, baseUrl, path) ? "login-form" : null,
    });
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
    return { ok: false };
  };

  const boot = registerPlan(ctx);
  const bootstrap = {
    phase: ctx._probePhase ?? "pre",
    endpoint: boot.available ? boot.path : null,
    endpointSource: boot.available ? boot.source : null,
    method: boot.available ? boot.method : null,
    unavailableReason: boot.available ? null : boot.reason,
    candidates: boot.available ? [] : boot.candidates,
    accounts: [],
    seeds: [],
    secretProtection: {},
  };
  // 两轮（修复前 / 修复后）各一份：读者要能看出「这个实例也是引擎造的号」，
  // 而不是只在第一轮造过就算数。
  ctx._identityBootstrap = {
    ...(ctx._identityBootstrap ?? {}),
    byPhase: { ...(ctx._identityBootstrap?.byPhase ?? {}), [bootstrap.phase]: bootstrap },
  };

  /**
   * #182 注册端点/字段名的 agent 兜底。状态是**每次 loginAll 一份**（修复前后各一轮）：
   * 菜单惰性构建，只有契约与静态端点都没换来会话时才问模型；模型只报编号与「字段名 → 占位符」，
   * 采纳与否由引擎实跑（注册 2xx/409 → 登录建立会话）决定，会话真实性仍由回读闸门把关。
   */
  const regCfg = ctx.registerConfig ?? {};
  const agentEnabled = selfBootAgentEnabled(ctx);
  // 缓存键里的 model 取契约声明值（与 scout 同一口径）：模型回显的实际型号不参与键，
  // 否则同一份提案在「契约没写 model」的两次运行里会算成两个键，缓存永远命不中。
  const cacheModel = ctx.llmConfig?.model ?? null;
  const agentState = {
    enabled: agentEnabled,
    callable: selfBootModelCallable(ctx),
    budget: selfBootBudget(ctx),
    menu: null,
    exhausted: false,
    queue: [],
    askedRounds: 0,
    cacheLoaded: false,
    cacheKey: null,
    cacheFile: null,
    failedKeys: new Set(),
    failures: [],
    adopted: null,
    meta: {
      enabled: agentEnabled,
      callable: selfBootModelCallable(ctx),
      blackboxForbidden: !!ctx.blackboxUrl,
      rounds: 0,
      asked: false,
      source: null,
      fallback: null,
      menuSize: 0,
      tried: [],
      adoptedEndpoint: null,
      ignored: [],
      droppedFields: [],
      invalid: [],
      cacheHit: false,
      cacheVerified: false,
      model: null,
      rejected: null,
      durationMs: 0,
    },
  };
  bootstrap.agent = agentState.meta;

  /** 身份形状（只给键名，不给值）：模型据此知道引擎能填哪几个占位符 */
  const identityShapeOf = (i) =>
    i.fields && typeof i.fields === "object" && !Array.isArray(i.fields)
      ? Object.keys(i.fields)
      : [i.username ? "username" : null, i.email ? "email" : null, "password"].filter(Boolean);
  const identityShape = (ctx.identities ?? []).map((i) => ({ name: i.name, fields: identityShapeOf(i) }));

  const makeAgentCandidate = (c) => ({
    path: c.path,
    method: c.method ?? regCfg.method ?? "POST",
    encoding: regCfg.encoding ?? "json",
    headers: regCfg.headers ?? {},
    // 模型没给可用模板时回落到契约模板，再由 registerBody 落到引擎默认体——绝不猜字段名
    bodyTemplate: c.bodyTemplate ?? regCfg.bodyTemplate ?? null,
    seed: regCfg.seed ?? [],
    source: "agent",
  });

  async function loadAgentMenu() {
    if (agentState.menu || agentState.exhausted) return agentState.menu;
    const staticHits = signupCandidates(ctx.analysis).map((c) => c.path);
    const menu = buildRegisterMenu(ctx.analysis, {
      maxMenu: agentState.budget.maxMenu,
      staticHits,
    });
    if (!menu.items.length) {
      agentState.exhausted = true;
      agentState.meta.fallback = "no_post_candidates";
      return null;
    }
    await enrichMenuWithHandlers(ctx, menu);
    agentState.menu = menu;
    agentState.meta.menuSize = menu.items.length;
    return menu;
  }

  /** 取下一个待试的 agent 候选：磁盘缓存优先，用完才调模型（最多 budget.rounds 轮，纠偏轮带实测失败） */
  async function nextAgentCandidate() {
    const st = agentState;
    if (!st.enabled || st.exhausted) return null;
    let guard = 0;
    while (!st.queue.length && guard++ < st.budget.rounds + 2) {
      const menu = await loadAgentMenu();
      if (!menu) {
        st.exhausted = true;
        return null;
      }
      if (!st.cacheLoaded) {
        st.cacheLoaded = true;
        st.cacheKey = cacheKeyFor(cacheModel, menu);
        const hit = readAgentCache(ctx, st.cacheKey, menu, { requireVerified: ctx.gate === true });
        if (hit) {
          st.cacheFile = hit.file;
          st.meta.cacheHit = true;
          st.meta.source = "cache";
          st.queue = hit.candidates
            .map(makeAgentCandidate)
            .filter((c) => !st.failedKeys.has(candidateKey(c)));
        }
      }
      if (st.queue.length) break;
      if (!st.callable) {
        if (!st.meta.fallback) st.meta.fallback = ctx.gate === true ? "gate_forbids_model_call" : "agent_not_enabled";
        st.exhausted = true;
        return null;
      }
      if (st.askedRounds >= st.budget.rounds) {
        st.exhausted = true;
        return null;
      }
      const round = st.askedRounds + 1;
      const res = await askRegisterAgent(ctx, {
        menu,
        round,
        priorAttempts: st.failures,
        identityShape,
        getToken: ctx.llm?.getToken,
        model: ctx.llmConfig?.model ?? null,
        budget: st.budget,
        chatImpl: llmChat,
      });
      st.askedRounds = round;
      st.meta.asked = true;
      st.meta.rounds = round;
      st.meta.durationMs += res.meta.durationMs ?? 0;
      st.meta.model = res.meta.model ?? st.meta.model;
      st.meta.ignored = [...st.meta.ignored, ...(res.meta.ignored ?? [])];
      st.meta.droppedFields = [...st.meta.droppedFields, ...(res.meta.droppedFields ?? [])];
      st.meta.invalid = [...st.meta.invalid, ...(res.meta.invalid ?? [])];
      st.meta.rejected = res.meta.rejected ?? st.meta.rejected;
      st.meta.fallback = res.meta.fallback ?? null;
      st.meta.source = res.meta.fallback ? st.meta.source : "model";
      if (!st.cacheKey) st.cacheKey = cacheKeyFor(st.meta.model, menu);
      const fresh = res.candidates
        .map(makeAgentCandidate)
        .filter((c) => !st.failedKeys.has(candidateKey(c)));
      if (!fresh.length) {
        if (!res.meta.fallback) st.meta.fallback = "already_tried";
        continue;
      }
      st.queue = fresh;
      ctx.emit({
        kind: "selfboot",
        severity: SEVERITY.INFO,
        message: `注册兜底代理第 ${round} 轮提议 ${fresh.length} 个候选端点（${fresh.map((c) => c.path).join("、")}）；模型只选端点与字段名，是否采用由引擎实跑注册与登录决定`,
        data: {
          round,
          candidates: fresh.map((c) => ({ endpoint: c.path, fields: c.bodyTemplate ? Object.keys(c.bodyTemplate) : null })),
          menuSize: st.meta.menuSize,
          ignoredKeys: st.meta.ignored,
          droppedFields: st.meta.droppedFields,
        },
      });
    }
    return st.queue.shift() ?? null;
  }

  /** 采纳后把提案落盘并标记为已实测；gate 之后只能复用带这个标记的提案 */
  function markCandidateAdopted(cand, reg) {
    const st = agentState;
    if (cand.source !== "agent") return;
    st.meta.adoptedEndpoint = cand.path;
    // 端点归因即时回写：采纳之后还有第二个身份要建号，那一步失败时报告也得说清「用的是哪个、谁定的」
    bootstrap.endpoint = cand.path;
    bootstrap.endpointSource = cand.source;
    bootstrap.method = cand.method;
    bootstrap.unavailableReason = null;
    // 采纳的那一条也进实跑轨迹：只列失败候选，读者就没法核对「采纳是实测出来的」
    if (!st.meta.tried.some((t) => t.verdict === "adopted" && t.endpoint === cand.path)) {
      st.meta.tried.push({ endpoint: cand.path, verdict: "adopted", status: reg?.status ?? null });
    }
    if (!st.cacheKey) return;
    if (st.cacheFile) {
      if (patchAgentCache(st.cacheFile, { endpoint: true, session: true })) st.meta.cacheVerified = true;
      return;
    }
    const saved = writeAgentCache(
      ctx,
      st.cacheKey,
      [{ path: cand.path, bodyTemplate: cand.bodyTemplate }],
      { model: st.meta.model, rounds: st.askedRounds, verified: { endpoint: true, session: true } }
    );
    if (saved) {
      st.cacheFile = saved.file;
      st.meta.cacheVerified = true;
    }
  }

  /** agent 候选失败要记的三样：不再重试的键、纠偏轮的实测证据、报告里的可审计轨迹 */
  function noteAgentFailure(cand, verdict, status, excerpt) {
    if (cand.source !== "agent") return;
    agentState.failedKeys.add(candidateKey(cand));
    agentState.failures.push({ path: cand.path, method: cand.method, verdict, status: status ?? null, excerpt: excerpt ?? null });
    agentState.meta.tried.push({ endpoint: cand.path, verdict, status: status ?? null });
  }

  /**
   * 一个候选端点上的完整自举：注册被目标接受**且**能建立会话，两步都实测通过才算数。
   * 任一步不中就换下一个候选（含 agent 提案），全不中由调用方回显式 inconclusive。
   */
  const tryCandidate = async (ident, cand, trigger) => {
    const reg = await registerOne(ident, trigger, cand);
    if (reg.verdict !== "created" && reg.verdict !== "exists") {
      noteAgentFailure(cand, reg.verdict ?? reg.reason ?? "failed", reg.status ?? null, reg.excerpt ?? null);
      return { ok: false, accepted: false, reg, cand };
    }
    const entry = await tryLogin(ident);
    if (!entry) {
      // 纠偏轮要看得见「注册被收下、但换不来会话」——只说 login_rejected 模型无从判断这是假建号端点
      const last = attempts.filter((a) => a.identity === ident.name).at(-1);
      noteAgentFailure(
        cand,
        "login_rejected",
        reg.status ?? null,
        `注册返回 HTTP ${reg.status ?? "—"}，但随后 ${last?.path ?? "登录端点"} → HTTP ${last?.status ?? "—"}：该端点没有换来可用会话`
      );
      return { ok: false, accepted: true, reg, cand };
    }
    if (!agentState.adopted) agentState.adopted = cand;
    markCandidateAdopted(cand, reg);
    return { ok: true, entry, reg, cand };
  };

  /**
   * 候选序列：已验证过的端点优先（同一目标只有一个注册接口）> 契约/静态 > agent 提案（惰性）。
   * 返回最后一次失败的信息，调用方据此区分「压根没找到端点」与「找到了但目标不认」。
   */
  const bootstrapIdentity = async (ident, trigger) => {
    const queue = [];
    if (agentState.adopted) queue.push(agentState.adopted);
    if (boot.available && candidateKey(boot) !== candidateKey(agentState.adopted)) queue.push(boot);
    let triedAny = false;
    let last = { accepted: false, reg: null, cand: null };
    for (;;) {
      const cand = queue.shift() ?? (await nextAgentCandidate());
      if (!cand) break;
      triedAny = true;
      const out = await tryCandidate(ident, cand, trigger);
      if (out.ok) return out;
      last = out;
    }
    return { ok: false, triedAny, accepted: last.accepted, reg: last.reg, cand: last.cand };
  };

  /**
   * 用目标自己的注册接口建一个身份（cand 为本轮的一个候选端点）。
   * 口令省略时由引擎随机生成并登记进 Host 保险库；判定只看目标响应
   * （2xx＝已建号，409/「已存在」＝库里有，其余＝这一轮身份不成立）。
   */
  const registerOne = async (ident, trigger, cand) => {
    if (!cand) return { attempted: false, reason: bootstrap.unavailableReason };
    let generated = false;
    if (ident.password == null) {
      ident.password = generateTestPassword();
      generated = true;
      bootstrap.secretProtection[ident.name] = await protectGeneratedSecret(ctx, ident.name, ident.password);
    }
    const values = registerValues(ident);
    const { body, unresolved } = registerBody(ident, cand, values);
    if (unresolved.length) {
      const entry = {
        name: ident.name,
        trigger,
        verdict: "template_unresolved",
        status: null,
        generated,
        fields: unresolved,
        endpoint: cand.path,
        endpointSource: cand.source,
      };
      bootstrap.accounts.push(entry);
      ctx.emit({
        kind: "identity",
        severity: SEVERITY.WARN,
        message: `身份「${ident.name}」未发起注册：${cand.source === "agent" ? "兜底代理给出的字段模板" : "register.bodyTemplate"} 里有引擎填不出的占位符 {${unresolved.join("、")}}`,
        data: { identity: ident.name, endpoint: cand.path, unresolved: unresolved, endpointSource: cand.source },
      });
      return {
        attempted: false,
        reason: "template_unresolved",
        fields: unresolved,
        generated,
        endpoint: cand.path,
        excerpt: `请求体模板里这些占位符引擎填不出来：${unresolved.join("、")}`,
      };
    }
    const encoded = encodeLoginBody(body, cand.encoding === "form");
    let res = null;
    try {
      res = await httpJson(ctx, {
        baseUrl,
        method: cand.method,
        path: cand.path,
        body: encoded.body,
        contentType: encoded.contentType,
        extraHeaders: cand.headers,
      });
    } catch (e) {
      const entry = { name: ident.name, trigger, verdict: "request_failed", status: null, generated, endpoint: cand.path, endpointSource: cand.source };
      bootstrap.accounts.push(entry);
      return {
        attempted: true,
        verdict: "request_failed",
        status: null,
        error: e.message,
        generated,
        endpoint: cand.path,
        excerpt: String(e.message).slice(0, 240),
      };
    }
    const { verdict, status } = classifyRegisterResponse(res);
    // 身份只写了 username 时，注册用的是引擎派生的邮箱；建号成功后把同一个邮箱记回身份，
    // 否则随后按 login.bodyTemplate 的 {email} 登录会发空值，「号建了却登不进去」。
    if ((verdict === "created" || verdict === "exists") && ident.email == null && values.email) {
      ident.email = values.email;
    }
    bootstrap.accounts.push({ name: ident.name, trigger, verdict, status, generated, endpoint: cand.path, endpointSource: cand.source });
    // 只有失败时才把目标的报错文本留给纠偏轮：口令已剔除、截断，且不进事件流/审计/报告
    const excerpt = verdict === "created" || verdict === "exists" ? null : scrubForAgent(res.body, values.password);
    ctx.emit({
      kind: "identity",
      severity: verdict === "created" || verdict === "exists" ? SEVERITY.INFO : SEVERITY.WARN,
      message:
        verdict === "created"
          ? `已用目标自己的注册接口建立身份「${ident.name}」（${cand.method} ${cand.path} → HTTP ${status}；端点来源：${sourceLabel(cand.source)}）${generated ? "；口令由引擎随机生成，只进 Host 保险库（不落配置/报告/证据库）" : ""}`
          : verdict === "exists"
            ? `注册接口报告该账号已存在（HTTP ${status}），直接按声明口令登录`
            : `注册未建立身份「${ident.name}」（${cand.method} ${cand.path} → HTTP ${status}；端点来源：${sourceLabel(cand.source)}）`,
      data: {
        identity: ident.name,
        endpoint: cand.path,
        endpointSource: cand.source,
        status,
        verdict,
        passwordSource: generated ? "engine-generated" : "declared",
      },
    });
    return { attempted: true, verdict, status, generated, endpoint: cand.path, excerpt };
  };

  /** 契约声明的种子写入：只往「该身份自己名下」写对象，状态码不成功就显式失败 */
  const seedFor = async (ident, cand) => {
    const values = registerValues(ident);
    for (const step of cand?.seed ?? []) {
      values.canary = generateCanary();
      const prepared = seedBody(step, values);
      if (!prepared) {
        bootstrap.seeds.push({ identity: ident.name, path: step.path, verdict: "skipped_no_body_template" });
        continue;
      }
      if (prepared.unresolved.length) {
        throw new ProbeError(
          `身份「${ident.name}」的种子数据模板含引擎填不出的占位符 {${prepared.unresolved.join("、")}}（${step.method} ${step.path}）`,
          {
            code: "identity_seed_failed",
            hint: "register.seed 的 bodyTemplate 只支持 {name}/{username}/{email}/{password}/{canary}；其余字段请写成常量。本轮没有造出数据，越权用例没有归属对象可比，引擎不会改用匿名探测蒙过去。",
          }
        );
      }
      const encoded = encodeLoginBody(prepared.body, cand.encoding === "form");
      const res = await httpJson(ctx, {
        baseUrl,
        method: step.method,
        path: step.path,
        identity: ident.name,
        body: encoded.body,
        contentType: encoded.contentType,
        extraHeaders: cand.headers,
      });
      const { verdict, status } = classifySeedResponse(res);
      bootstrap.seeds.push({ identity: ident.name, method: step.method, path: step.path, status, verdict });
      if (verdict !== "written") {
        throw new ProbeError(
          `身份「${ident.name}」的种子数据未能写入：${step.method} ${step.path} → HTTP ${status}`,
          {
            code: "identity_seed_failed",
            hint:
              verdict === "denied"
                ? "登录看似成功、写入却被拒：说明这个会话在目标上并没有真正获得该身份（或该接口另有权限要求）。请核对 identities 的角色与 login.credentialPath；若该身份是引擎刚注册的，多半是目标按角色开放写入，请在 identities 里声明有写入权的账号。"
                : `请核对 register.seed 的端点与字段名（当前 ${step.path}）。没有归属对象，越权用例就无从构造——本轮按「测不了」处理，不按「没问题」处理。`,
          }
        );
      }
      ctx.emit({
        kind: "identity",
        severity: SEVERITY.INFO,
        message: `已为身份「${ident.name}」写入种子数据（${step.method} ${step.path} → HTTP ${status}）`,
        data: { identity: ident.name, endpoint: step.path, status },
      });
    }
  };

  /** 按该身份的候选序列逐个试登录，成功返回会话条目 */
  const tryLogin = async (ident) => {
    const list = ident.loginPath
      ? [ident.loginPath, ...sharedCandidates.filter((p) => p !== ident.loginPath)]
      : sharedCandidates;
    for (const path of list) {
      const r = await attemptLogin(ident, path);
      if (r.ok) return r;
    }
    return null;
  };

  const loggedIn = [];
  const endpoints = [];

  // 报告的「身份基础」一节：谁的会话在哪个端点建立、真实性有没有回读过。
  // 没有这一节，读者只能从「越权全部被拒」反推身份是不是真的成立。
  // 取用即读（getter）：自举/登录中途失败也要留在报告里——「测不了」的那一轮同样得能自证。
  // 明细（注册端点、账号、种子、兜底代理）来自 ctx._identityBootstrap，报告层单独按白名单展开。
  ctx._identityReport = {
    configured: ctx.identities.map((i) => i.name),
    get loggedIn() {
      return loggedIn.map((i) => ({
        name: i.name,
        role: i.role ?? null,
        endpoint: ctx._loginEndpoints?.[i.name] ?? endpoints[0] ?? null,
        credentialKind: ctx.loginConfig?.cookieAuth === true ? "cookie" : "token",
      }));
    },
    get sessionVerification() {
      return ctx._sessionVerify ?? null;
    },
  };

  /** 给「测不了」的提示补上兜底代理这一层的真实状态（开了没中/根本没开），读者才知道下一步做什么 */
  const agentHintNote = () => {
    const m = agentState.meta;
    if (!agentState.enabled) {
      return "　注册兜底代理未开启：在 guardbuild.json 写 register.agent:true（或环境变量 GUARDBUILD_LLM_SELFBOOT=1）后，模型可在引擎给出的 POST 路由编号菜单里提议端点与字段名，是否采用仍由引擎实跑决定。";
    }
    if (m.adoptedEndpoint) return `　注册兜底代理已采纳 ${m.adoptedEndpoint}（来源：${m.source}）。`;
    const bits = [
      m.tried.length ? `实跑过 ${m.tried.map((t) => `${t.endpoint}→${t.verdict}`).join("、")}` : null,
      m.tried.length ? null : m.fallback ? `未给出可用端点（${m.fallback}）` : null,
      // 试过之后模型没再给新候选（纠偏轮出错/拒答）也是事实，不能只留「实跑过」
      m.tried.length && m.fallback && m.fallback !== "already_tried" ? `后续轮次未给出新候选（${m.fallback}）` : null,
      m.ignored.length ? `丢弃的越界键：${m.ignored.join("、")}` : null,
      m.droppedFields.length ? `丢弃的字段映射：${m.droppedFields.join("、")}` : null,
    ].filter(Boolean);
    return bits.length ? `　${bits.join("；")}。` : "";
  };

  for (const ident of ctx.identities) {
    const mustRegister = ident.password == null;
    let reg = null;
    let entry = null;
    let via = null;
    if (mustRegister) {
      if (!boot.available && !agentState.enabled) {
        throw new ProbeError(
          `身份「${ident.name}」省略了 password，但引擎未能确定注册端点，无法自举该身份`,
          {
            code: "identity_bootstrap_unavailable",
            hint:
              bootstrap.unavailableReason === "blackbox"
                ? "纯黑盒模式不会向外部目标发注册请求（建号属于对他人系统的写操作，超出探测授权）。请为该身份提供已存在的测试账号口令，或改用白盒模式让引擎在沙箱内自举。"
                : `省略 identities[].password 意味着「口令由引擎随机生成、走目标自己的注册接口」，因此必须知道那个接口在哪（本轮判定依据：${bootstrap.unavailableReason}${bootstrap.candidates.length ? `，静态候选：${bootstrap.candidates.join("、")}` : ""}）。请在 guardbuild.json 声明 register.path（必要时配 register.bodyTemplate），或改为显式提供已存在的账号口令。${agentHintNote()}`,
            details: { identity: ident.name, reason: bootstrap.unavailableReason, candidates: bootstrap.candidates },
          }
        );
      }
      const out = await bootstrapIdentity(ident, "no-declared-password");
      if (out.ok) {
        reg = out.reg;
        entry = out.entry;
        via = out.cand;
      } else if (out.accepted) {
        // 注册被目标接受、但所有登录候选都不认：归因留在登录层，不改判成「找不到注册接口」
        reg = out.reg;
        via = out.cand;
      } else if (!out.triedAny) {
        throw new ProbeError(
          `身份「${ident.name}」省略了 password，但引擎未能确定注册端点，无法自举该身份`,
          {
            code: "identity_bootstrap_unavailable",
            hint:
              bootstrap.unavailableReason === "blackbox"
                ? "纯黑盒模式不会向外部目标发注册请求（建号属于对他人系统的写操作，超出探测授权）。请为该身份提供已存在的测试账号口令，或改用白盒模式让引擎在沙箱内自举。"
                : `省略 identities[].password 意味着「口令由引擎随机生成、走目标自己的注册接口」，因此必须知道那个接口在哪（本轮判定依据：${bootstrap.unavailableReason}${bootstrap.candidates.length ? `，静态候选：${bootstrap.candidates.join("、")}` : ""}）。请在 guardbuild.json 声明 register.path（必要时配 register.bodyTemplate），或改为显式提供已存在的账号口令。${agentHintNote()}`,
            details: {
              identity: ident.name,
              reason: bootstrap.unavailableReason,
              candidates: bootstrap.candidates,
              agent: { fallback: agentState.meta.fallback, menuSize: agentState.meta.menuSize, asked: agentState.meta.asked },
            },
          }
        );
      } else {
        const last = out.reg ?? {};
        throw new ProbeError(
          `身份「${ident.name}」自举失败：${out.cand?.method ?? "POST"} ${out.cand?.path ?? "—"} → ${last.verdict ?? last.reason ?? "failed"}${last.status ? ` (HTTP ${last.status})` : ""}`,
          {
            code: "identity_bootstrap_failed",
            hint: `口令省略的身份必须先建号才能登录。注册接口没能接受引擎构造的请求体（多为字段名/校验规则不符）：请在 guardbuild.json 声明 register.bodyTemplate（支持 {email}/{username}/{password}/{name}），并确认目标允许公开注册。本轮按「测不了」处理，不会改用匿名探测再报「未发现漏洞」。${agentHintNote()}`,
            details: {
              identity: ident.name,
              endpoint: out.cand?.path ?? null,
              endpointSource: out.cand?.source ?? null,
              verdict: last.verdict ?? last.reason ?? null,
              status: last.status ?? null,
            },
          }
        );
      }
    } else {
      entry = await tryLogin(ident);
      // 声明了口令、目标却不认：很可能是空库沙箱里根本没这个账号。走一次注册再试，
      // 仍不成才报错——中间不做任何「当成已防护」的推断。
      if (!entry && (boot.available || agentState.enabled)) {
        const out = await bootstrapIdentity(ident, "login-rejected");
        if (out.ok) {
          reg = out.reg;
          entry = out.entry;
          via = out.cand;
        } else if (out.reg && (out.reg.verdict === "created" || out.reg.verdict === "exists")) {
          reg = out.reg;
          via = out.cand;
        } else {
          reg = out.reg ?? reg;
        }
      }
    }
    if (!entry) {
      const { code, hint } = classifyLoginFailure(attempts);
      const tried = attempts
        .filter((a) => a.identity === ident.name)
        .map((a) => `${a.path}→HTTP ${a.status}`)
        .join("，");
      throw new ProbeError(
        `身份「${ident.name}」无法在任何候选登录端点上建立会话（尝试：${tried || "无"}）${bootstrapSuffix(boot, reg, agentState.meta)}`,
        {
          code: reg ? "identity_bootstrap_failed" : code,
          hint: `${
            ident.loginPath
              ? `该身份声明的 loginPath 为 ${ident.loginPath}；${hint ?? ""}`
              : `${hint ?? ""}　多角色应用请为每个身份写 identities[].loginPath（如组织者用 /auth/organiser/login），否则角色不匹配的账号会被登录端点拒绝并回渲染登录表单。`
          }${
            reg?.verdict === "exists"
              ? "　注册接口说该账号已存在、但声明的口令登不进去：多半是目标库里的账号来自上一轮/外部种子且口令不同，请改用真实口令或在 prepare 步骤里重置数据库。"
              : ""
          }${agentHintNote()}`,
        }
      );
    }
    loggedIn.push(entry.entry);
    endpoints.push(entry.endpoint);
    // 只给「本轮新建的账号」造数据：库里本来就有对象（或上一轮已写过）就不重复写。
    const seedCand = via ?? (boot.available ? boot : null);
    if (reg?.verdict === "created" && (seedCand?.seed?.length ?? 0) > 0) await seedFor(ident, seedCand);
  }

  const path = endpoints[0];
  ctx.plan.loginPath = path;
  ctx.plan.loginCandidates = [path, ...sharedCandidates.filter((c) => c !== path)];
  ctx._loginVerified = true;
  ctx._loginEndpoint = path;
  ctx._loginEndpoints = Object.fromEntries(ctx.identities.map((i, idx) => [i.name, endpoints[idx] ?? null]));
  await assertSessionsAuthenticated(ctx, baseUrl, loggedIn, path);
  return loggedIn;
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
    if (o && String(resourceIdOf(ctx, o)) === String(id)) anonymousItems.push(o);
  }
  ctx.emit({
    kind: "discovery",
    severity: anonymousItems.length > 0 ? SEVERITY.INFO : SEVERITY.WARN,
    message:
      anonymousItems.length > 0
        ? `资源发现（匿名探测回退）：无按归属过滤的列表接口，在 ${path} 匿名探测到 ${anonymousItems.length} 个公开可见对象`
        : `资源发现（匿名探测回退）：无列表接口，且 ${path} 匿名 ID 探测未找到可见对象`,
    data: { mode: "anonymous-probe", path, ids: anonymousItems.map((o) => resourceIdOf(ctx, o)) },
  });
  return anonymousItems;
}

/* ------------------------ SSR / HTML 页面的资源发现与取证 ------------------------ */

// 页面发现每一步都是真实请求（读入口页 → 抓链接 → 回读本人页面正文），
// 所以预算收紧：拿不到归属对照就判 inconclusive，绝不靠猜 ID 造用例。
const MAX_HTML_IDENTITIES = 2;
const MAX_HTML_ENTRY_PAGES = 4;
const MAX_HTML_IDS_PER_IDENTITY = 3;
const MAX_HTML_BASELINE_PAGES = 6;

/** 候选路由里带路径参数的 REST 模板：页面链接只有填满它们才算资源，不猜 ID 命名 */
function htmlTemplates(ctx) {
  const out = [];
  for (const kind of ["read", "cancel", "unauthRead"]) {
    for (const c of planCandidates(ctx, kind)) {
      if (c?.graphql || c?.trpc) continue;
      const p = candPath(c);
      if (p && /:[A-Za-z_]\w*/.test(p) && !out.includes(p)) out.push(p);
    }
  }
  return out;
}

/** 入口页候选：首页 + 每条模板「参数段之前」的父路径 + 静态已知的无参数 GET 路由 */
export function htmlEntryPages(ctx, templates) {
  const out = [];
  const push = (p) => {
    if (!p || out.includes(p) || out.length >= MAX_HTML_ENTRY_PAGES) return;
    out.push(p);
  };
  push("/");
  for (const t of templates ?? []) {
    const cut = String(t).slice(0, String(t).indexOf(":")).replace(/\/+$/, "");
    push(cut || "/");
  }
  for (const e of ctx?.analysis?.endpoints ?? []) {
    if (e?.graphql || e?.trpc) continue;
    if ((e.method ?? "GET") !== "GET") continue;
    const p = e.fullPath ?? e.path;
    if (!p || /:/.test(p)) continue;
    push(p);
  }
  return out;
}

/** 页面发现的资源对象：主键同时写成契约字段名，让 resourceIdOf 与 JSON 发现走同一条路 */
function htmlResourceItem(ctx, id) {
  const keys = new Set(["id"]);
  const declared = respPath(ctx, "id");
  if (declared && !declared.includes(".")) keys.add(declared);
  return Object.fromEntries([...keys].map((k) => [k, id]));
}

/**
 * 无 JSON 列表接口时的发现回退（传统 SSR 应用：列表是 HTML 页，详情也是 HTML 页）。
 * 登录身份各自读入口页 → 按候选路由模板抓页面链接里的对象 ID → 回读这些对象在
 * 「自己会话」下的正文，作为后续越权取证的归属基线。
 * 返回与 JSON 发现同形的 { byUser, anonymousItems, anonTargets }，并把正文写进
 * ctx._htmlPages（baseline: id → {id,link,owner,text}，byIdentity: 身份 → 同类数组）。
 */
export async function discoverViaHtmlPages(ctx, baseUrl, loggedIn) {
  const templates = htmlTemplates(ctx);
  if (templates.length === 0) return null;
  const users = (loggedIn ?? []).filter((i) => i.role !== "admin").slice(0, MAX_HTML_IDENTITIES);
  if (users.length === 0) return null;
  const entries = htmlEntryPages(ctx, templates);
  let requests = 0;

  const byIdentity = new Map();
  const ownerById = new Map();
  for (const ident of users) {
    const found = [];
    const seen = new Set();
    for (const p of entries) {
      let res = null;
      try {
        res = await httpJson(ctx, { baseUrl, method: "GET", path: p, identity: ident.name });
        requests += 1;
      } catch {
        continue; // 入口页打不开只是少一个来源，不构成结论
      }
      if (!looksHtml(res)) continue;
      for (const item of extractPageIds(res.body, templates)) {
        if (seen.has(String(item.id)) || found.length >= MAX_HTML_IDS_PER_IDENTITY) continue;
        seen.add(String(item.id));
        found.push({ ...item, text: null });
        if (!ownerById.has(String(item.id))) ownerById.set(String(item.id), ident.name);
      }
      if (found.length >= MAX_HTML_IDS_PER_IDENTITY) break;
    }
    byIdentity.set(ident.name, found);
  }

  const total = [...byIdentity.values()].reduce((n, l) => n + l.length, 0);
  if (total === 0) {
    ctx.emit({
      kind: "discovery",
      severity: SEVERITY.WARN,
      message: `HTML 页面资源未发现对象（入口页 ${entries.join("、")} 已试过 ${requests} 次请求，链接里没有能填满候选路由的 ID）`,
      data: { mode: "html-pages", entries, requestsUsed: requests, templates },
    });
    return null;
  }

  // 归属基线：只取「该身份自己会话下」的页面正文，别人的页面正文不能当本人的证据
  const baseline = new Map();
  for (const [name, list] of byIdentity) {
    for (const item of list) {
      if (baseline.size >= MAX_HTML_BASELINE_PAGES) break;
      if (baseline.has(String(item.id))) continue;
      let res = null;
      try {
        res = await httpJson(ctx, { baseUrl, method: "GET", path: item.link, identity: name });
        requests += 1;
      } catch {
        continue;
      }
      if (!okStatus(res.status) || !looksHtml(res)) continue;
      const text = pageText(res.body);
      if (!text) continue;
      item.text = text;
      baseline.set(String(item.id), { ...item, owner: name });
    }
  }
  ctx._htmlPages = { baseline, byIdentity, entries, requestsUsed: requests };

  const byUser = {};
  for (const [name, list] of byIdentity) byUser[name] = list.map((x) => htmlResourceItem(ctx, x.id));
  const noText = users.filter((u) => (byIdentity.get(u.name) ?? []).every((x) => !x.text));
  ctx.emit({
    kind: "discovery",
    severity: baseline.size > 0 ? SEVERITY.INFO : SEVERITY.WARN,
    message:
      baseline.size > 0
        ? `资源发现（HTML 页面回退）：从 ${entries.length} 个入口页的链接里发现 ${total} 个${resourceLabel(ctx)}，已回读 ${baseline.size} 页本人正文作为归属基线（共 ${requests} 次请求）`
        : `资源发现（HTML 页面回退）：发现 ${total} 个${resourceLabel(ctx)}对象，但本人页面正文全部回读失败，越权取证将只能判 inconclusive`,
    data: {
      mode: "html-pages",
      entries,
      requestsUsed: requests,
      counts: Object.fromEntries(byIdentity.entries().map(([n, l]) => [n, l.length])),
      baselines: [...baseline.keys()],
    },
  });
  if (noText.length > 0 && baseline.size > 0) {
    ctx.emit({
      kind: "discovery",
      severity: SEVERITY.WARN,
      message: `身份「${noText.map((u) => u.name).join("、")}」名下页面没有回读到本人正文，其相关越权用例缺少归属对照`,
      data: { identities: noText.map((u) => u.name) },
    });
  }
  return { byUser, anonymousItems: [], anonTargets: [] };
}

/**
 * HTML 越权取证：响应是页面时没有 JSON 字段可比对，证据改为
 * 「受害人本人页面上独有、且原样出现在这次响应正文里的内容片段」。
 * 对照物缺失（攻击者名下没有可比页面）时返回 null —— 没有对照组就没有归属证明，
 * 由上层判 inconclusive，绝不把「页面结构相似」当成越权成功。
 */
function htmlLeakEvidence(ctx, res, targetId) {
  const pages = ctx._htmlPages;
  const base = pages?.baseline?.get(String(targetId));
  if (!base?.text || !looksHtml(res)) return null;
  const controls = [];
  for (const [name, list] of pages.byIdentity) {
    if (name === base.owner) continue; // 本人其它页面同样属于「本人内容」，不能拿来当对照
    for (const p of list) if (String(p.id) !== String(targetId) && p.text) controls.push(p.text);
  }
  if (controls.length === 0) return null;
  const markers = distinctiveMarkers(base.text, controls);
  if (markers.length === 0) {
    return { leaked: false, markers: [], hit: [], link: base.link, reason: "no-unique-content" };
  }
  const { hit, all } = markersInText(markers, pageText(res.body));
  return { leaked: all, markers, hit, link: base.link, owner: base.owner, reason: all ? null : "partial" };
}

/** 越权取证的正向描述：片段清单进 detail，读者能在报告里逐字核对 */
function htmlLeakDetail(e) {
  return `证据：${e.owner} 自己会话下的页面（${e.link}）独有的 ${e.markers.length} 个内容片段，全部出现在这次响应正文里：${e.markers.slice(0, 8).join("、")}`;
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

/** 读语义：REST 走 GET；GraphQL 的 query 过程（传输层仍是 POST），与 planner 的判定保持一致 */
function isReadShaped(c) {
  return (c?.method ?? "GET") === "GET" || c?.graphql?.op === "query";
}

/**
 * 响应取值路径。契约（guardbuild.json 的 responses.entity/list）优先；
 * GraphQL 单次文档只请求一个字段，字段名随候选而变（order / myOrders / adminOrders…），
 * 契约里的固定点路径无法覆盖，故回退为「本次请求的字段名」。
 */
function entityPathFor(ctx, graphql) {
  const manual = ctx.targetConfig?.responses?.entity ?? null;
  if (manual) return manual;
  if (graphql?.field) return graphql.field;
  return ctx._derived?.entity ?? null;
}
function listPathFor(ctx, graphql) {
  const manual = ctx.targetConfig?.responses?.list ?? null;
  if (manual) return manual;
  if (graphql?.field) return graphql.field;
  return ctx._derived?.list ?? null;
}

/**
 * 资源契约自动发现（P2）：列表在哪一层、要不要分页参数、主键与归属字段叫什么、
 * 单体响应里哪个字段才是实体 —— 过去只能人手写进 guardbuild.json，
 * 没写就退化成「找不到列表接口」或者取错对象。这里用两个真实身份的对拉响应来推断：
 * 只有「同一字段在两个身份的列表里互斥」才认定它是主键，只有「同身份内恒定、两身份之间不同」
 * 才认定它是归属字段。推断结果同样要过这一步，模型只能补充候选路径/字段名。
 * 人工契约优先：已声明的字段一律不覆盖。
 */

const COLLECTION_SKIP_RE = /login|logout|session|auth\/|health|metrics|status|swagger|openapi|admin|debug|__diag/i;

function listSlotsForDiscovery(ctx) {
  const slots = [];
  const seen = new Set();
  const declaredPath = ctx.plan?.listEndpoint?.path ?? ctx.targetConfig?.listEndpoint?.path ?? null;
  if (declaredPath) {
    seen.add(`GET ${declaredPath}`);
    slots.push({
      key: `GET ${declaredPath}`,
      method: ctx.plan?.listEndpoint?.method ?? "GET",
      path: declaredPath,
      extraQuery: ctx.plan?.listEndpoint?.query ?? ctx.targetConfig?.listEndpoint?.query ?? null,
    });
  }
  for (const e of ctx.analysis?.endpoints ?? []) {
    if (slots.length >= MAX_LIST_SLOTS) break;
    if (e.graphql || e.trpc) continue; // 这两种线协议各有自己的协商层
    if ((e.method ?? "GET") !== "GET") continue;
    const p = e.fullPath ?? e.path;
    if (!p || /:/.test(p)) continue; // 只谈无路径参数的集合端点
    if (COLLECTION_SKIP_RE.test(p)) continue;
    const key = `GET ${p}`;
    if (seen.has(key)) continue;
    seen.add(key);
    slots.push({ key, method: "GET", path: p });
  }
  return slots;
}

async function readCommitForCache(ctx) {
  const base = String(ctx.projectRoot ?? "").replace(/[\\/]+$/, "");
  const read = async (rel) => {
    try {
      const res = await ctx.rpc.request(
        RPC_TO_HOST.FS_READ,
        { token: ctx.tokens.project, path: `${base}/${rel}`, redact: true },
        { timeoutMs: 10_000 }
      );
      return typeof res?.content === "string" ? res.content : "";
    } catch {
      return "";
    }
  };
  return readCommitFromGit(read);
}

function contractRequest(ctx, baseUrl) {
  return async ({ method, path, query, identity }) => {
    const res = await httpJson(ctx, {
      baseUrl,
      method: method ?? "GET",
      path: appendQuery(path, query ?? null),
      identity,
    });
    return { status: res.status, json: res.json, body: res.body };
  };
}

/** 命中缓存也要重新实测一次：契约缓存是线索，不是结论（目标可能已经改了） */
async function confirmCachedContract(ctx, { baseUrl, cached, users }) {
  const c = cached?.contract;
  if (!c?.listPath || !c?.idField || !c?.slot?.path) return false;
  const request = contractRequest(ctx, baseUrl);
  const sets = [];
  for (const name of users.slice(0, 2)) {
    let res = null;
    try {
      res = await request({ method: c.slot.method, path: c.slot.path, query: c.listQuery, identity: name });
    } catch {
      return false;
    }
    const items = extractListItems(res.json, c.listPath);
    if (!Array.isArray(items) || items.length === 0) return false;
    sets.push(new Set(items.map((o) => String(o?.[c.idField] ?? "")).filter((v) => v !== "")));
  }
  return compareIdSets(sets[0], sets[1]) === "disjoint";
}

function applyDerivedContract(ctx, { contract, entityPath, source, requestsUsed, key }) {
  const declared = ctx.targetConfig?.responses ?? {};
  ctx._derived = { ...(ctx._derived ?? {}) };
  const applied = [];
  if (!declared.list && contract.listPath) {
    ctx._derived.list = contract.listPath;
    applied.push(`列表数组=${contract.listPath}`);
  }
  if (!declared.id && contract.idField) {
    ctx._derived.id = contract.idField;
    applied.push(`主键字段=${contract.idField}`);
  }
  if (!declared.owner && contract.ownerField) {
    ctx._derived.owner = contract.ownerField;
    applied.push(`归属字段=${contract.ownerField}`);
  }
  if (!declared.entity && entityPath) {
    ctx._derived.entity = entityPath;
    applied.push(`实体字段=${entityPath}`);
  }
  ctx.plan.listEndpoint = {
    ...(ctx.plan.listEndpoint ?? {}),
    path: contract.slot.path,
    method: contract.slot.method ?? "GET",
    query: contract.listQuery ?? ctx.plan?.listEndpoint?.query ?? null,
    graphql: null,
    routeKey: contract.slot.routeKey ?? ctx.plan?.listEndpoint?.routeKey ?? null,
  };
  ctx._resourceContract = {
    slotKey: contract.slotKey,
    listPath: contract.listPath,
    listQuery: contract.listQuery ?? null,
    idField: contract.idField,
    ownerField: contract.ownerField ?? null,
    entityPath: entityPath ?? null,
    needsPagination: contract.needsPagination === true,
    counts: contract.counts ?? null,
    applied,
    source,
    requestsUsed,
    fingerprint: key,
  };
  return ctx._resourceContract;
}

/** 人工契约把四类字段都说全了就不再花请求去推断 */
function contractFullyDeclared(ctx) {
  const r = ctx.targetConfig?.responses ?? {};
  const q = ctx.targetConfig?.listEndpoint?.query ?? ctx.plan?.listEndpoint?.query ?? null;
  return !!r.list && !!r.id && !!r.owner && !!r.entity && q != null;
}

/** 用「本人列表里的真实对象」回读单体端点，认出实体字段（{ meta, record } 这类包装） */
async function probeEntityPath(ctx, { baseUrl, contract, users }) {
  const cand = (ctx.plan?.readCandidates ?? [])[0] ?? ctx.plan?.readCandidate ?? null;
  const path = candPath(cand);
  if (!cand || !path) return null;
  const names = (path.match(/:([A-Za-z_]\w*)/g) ?? []).map((s) => s.slice(1));
  if (names.length !== 1) return null; // 多段路径交给绑定实测，这里不猜
  const identity = users[0];
  const res = await httpJson(ctx, {
    baseUrl,
    method: contract.slot.method ?? "GET",
    path: appendQuery(contract.slot.path, contract.listQuery),
    identity,
  });
  const items = extractListItems(res.json, listPathForWith(ctx, contract)) ?? [];
  const own = items.find((o) => o?.[contract.idField] != null);
  if (!own) return null;
  const idValue = own[contract.idField];
  const filled = path.replace(/:([A-Za-z_]\w*)/g, () => encodeURIComponent(String(idValue)));
  const out = await discoverEntityContract({
    request: contractRequest(ctx, baseUrl),
    slot: { method: cand.method ?? "GET", path: filled },
    identity,
    idField: contract.idField,
    idValue,
    ownerField: contract.ownerField ?? null,
  });
  return out.entityPath ?? null;
}

function listPathForWith(ctx, contract) {
  return ctx.targetConfig?.responses?.list ?? contract.listPath ?? null;
}

async function ensureResourceContract(ctx, { baseUrl, loggedIn }) {
  if (contractFullyDeclared(ctx)) return null;
  const users = (loggedIn ?? []).filter((i) => i.role !== "admin").map((i) => i.name);
  if (users.length < 2) return null; // 只有一个身份无法证明「按归属过滤」
  const slots = listSlotsForDiscovery(ctx);
  if (slots.length === 0) return null;

  const declared = ctx.targetConfig?.responses ?? {};
  const commit = await readCommitForCache(ctx);
  const key = contractFingerprint({ commit, slots, identities: users, resourceName: ctx.plan?.resource ?? null, declared });

  const cached = readContractCache(ctx, key);
  if (cached?.contract && (await confirmCachedContract(ctx, { baseUrl, cached, users }))) {
    ctx.emit({
      kind: "discovery",
      severity: SEVERITY.INFO,
      message: `资源契约缓存经两身份实测复核通过（列表=${cached.contract.listPath} · 主键=${cached.contract.idField}）`,
      data: { fingerprint: key, commit, replay: true },
    });
    return applyDerivedContract(ctx, {
      contract: cached.contract,
      entityPath: cached.entityPath ?? null,
      source: "cached-confirmed",
      requestsUsed: 2,
      key,
    });
  }
  if (cached?.contract) {
    ctx.emit({
      kind: "discovery",
      severity: SEVERITY.WARN,
      message: "资源契约缓存与当前响应不符，重新逐条实测推断",
      data: { fingerprint: key },
    });
  }

  const out = await discoverListContract({
    request: contractRequest(ctx, baseUrl),
    slots,
    identities: users,
    budget: MAX_CONTRACT_REQUESTS,
  });
  let contract = out.contract;
  let requestsUsed = out.requestsUsed;
  let source = "live-verified";
  let triedLog = out.tried;
  if (!contract && llmIsEnabled() && typeof ctx.llm?.getToken === "function") {
    const hinted = await llmContractHints(ctx, { baseUrl, slots, users, key });
    if (hinted?.contract) {
      contract = hinted.contract;
      requestsUsed = out.requestsUsed + hinted.requestsUsed;
      source = "llm-hinted-verified";
      triedLog = hinted.tried;
    }
  }
  if (!contract) {
    ctx._resourceContract = {
      attempted: slots.map((s) => s.key),
      tried: out.tried.slice(0, 12),
      requestsUsed: out.requestsUsed,
      applied: [],
      source: "not-verified",
      fingerprint: key,
    };
    ctx.emit({
      kind: "discovery",
      severity: SEVERITY.WARN,
      message: `资源契约自动发现未通过实测（试了 ${slots.length} 个集合端点、发 ${out.requestsUsed} 个请求），仍无法确定列表/主键/归属字段`,
      data: { tried: out.tried.slice(0, 12), requestsUsed: out.requestsUsed },
    });
    return null;
  }

  const entityPath = declared.entity ? null : await probeEntityPath(ctx, { baseUrl, contract, users });
  const summary = applyDerivedContract(ctx, {
    contract,
    entityPath,
    source,
    requestsUsed,
    key,
  });
  writeContractCache(ctx, key, {
    commit,
    contract: contractForCache(contract),
    entityPath,
    verifiedBy: source === "llm-hinted-verified" ? "llm-hint-verified-by-live-requests" : "two-identity-live-requests",
  });
  ctx.emit({
    kind: "discovery",
    severity: SEVERITY.SUCCESS,
    message: `资源契约自动发现（双身份实测）：${summary.applied.join(" · ")}${summary.needsPagination ? " · 该列表需分页参数" : ""}${
      source === "llm-hinted-verified" ? "（列表/字段线索来自模型假设，每条已经真实请求验证）" : ""
    }`,
    data: { ...summary, tried: triedLog.slice(0, 12) },
  });
  return summary;
}

const CONTRACT_HINTS_SYSTEM =
  "你是 API 响应结构分析器。给你一个 HTTP 列表接口的真实响应 JSON 样本。" +
  "任务：指出对象数组所在的键路径、可作为资源主键的字段名、以及这个列表需要的分页查询参数。" +
  "硬性规则：只能引用样本里真实存在的路径与字段，禁止输出数据值，禁止编造；" +
  "不确定就输出空数组。只输出严格 JSON，形如 " +
  '{"arrayPaths":["a.b.list"],"idFields":["batch_id"],"pagination":[{"page":"1","size":"100"}]}，不要任何解释文字。';

/**
 * agent 兜底（受约束）：引擎枚举不到契约时，把一份真实响应样本给模型，只让它提
 * 「路径/字段名/分页键」假设；validateExtras 逐条对照实测响应过滤，剩下的假设再由
 * discoverListContract 用两个身份的真实请求验证。模型不判定任何结论，判定只来自实测。
 */
async function llmContractHints(ctx, { baseUrl, slots, users }) {
  const request = contractRequest(ctx, baseUrl);
  const slot = slots[0];
  let sample = null;
  try {
    sample = await request({ method: slot.method ?? "GET", path: slot.path, query: slot.extraQuery ?? null, identity: users[0] });
  } catch {
    sample = null;
  }
  if (!sample || sample.error || !sample.json || typeof sample.json !== "object") return null;

  const res = await llmChat(ctx, {
    systemPrompt: CONTRACT_HINTS_SYSTEM,
    userPrompt: `响应样本（GET ${slot.path}）：\n${JSON.stringify(sample.json).slice(0, 4000)}\n\n只输出严格 JSON 假设。`,
    getToken: ctx.llm.getToken,
    model: ctx.targetConfig?.llm?.model ?? null,
    timeoutMs: 60_000,
    maxTokens: 400,
    purpose: "提出资源契约补充假设（仅路径/字段名/分页键）",
  });
  const { extras, rejected } = validateExtras(llmParseJson(res.content), sample.json);
  const total =
    extras.arrayPaths.length + extras.idFields.length + extras.pagination.length;
  if (total === 0) {
    ctx.emit({
      kind: "discovery",
      severity: SEVERITY.WARN,
      message: "LLM 契约假设全部被拒（未引用实测响应里真实存在的路径/字段），继续按无契约处理",
      data: { rejected: rejected.slice(0, 6) },
    });
    return null;
  }
  ctx.emit({
    kind: "discovery",
    severity: SEVERITY.INFO,
    message: `LLM 契约补充假设已接受 ${total} 条（列表路径 ${extras.arrayPaths.length} · 主键 ${extras.idFields.length} · 分页 ${extras.pagination.length}），拒掉 ${rejected.length} 条，逐条真实验证中`,
    data: { accepted: extras, rejected: rejected.slice(0, 6) },
  });
  const out2 = await discoverListContract({
    request,
    slots,
    identities: users,
    extras,
    budget: MAX_CONTRACT_REQUESTS,
  });
  if (!out2.contract) {
    ctx.emit({
      kind: "discovery",
      severity: SEVERITY.WARN,
      message: `LLM 契约假设经双身份实测未成立（再发 ${out2.requestsUsed} 个请求仍无法确定列表/主键/归属字段）`,
      data: { tried: out2.tried.slice(0, 12) },
    });
    return null;
  }
  return { contract: out2.contract, requestsUsed: out2.requestsUsed, tried: out2.tried };
}

/**
 * 多段路径参数绑定实测：:orgId/orders/:orderId 这类路由，第二个参数没有真实来源时
 * 过去只能判不可寻址。现在用本人列表里的对象试出字段映射，再真发一次「读自己的对象」请求，
 * 只有目标回读同一个对象才算这条路由可寻址。
 */
async function resolveDerivedBindings(ctx, { baseUrl, byUser, loggedIn, phase }) {
  const users = (loggedIn ?? []).filter((i) => i.role !== "admin").map((i) => i.name);
  if (users.length === 0) return [];
  const idField = respPath(ctx, "id") ?? "id";
  const pending = (ctx.plan?.pendingCandidates ?? []).filter((c) => {
    const names = (candPath(c) ?? "").match(/:([A-Za-z_]\w*)/g) ?? [];
    if (names.length < 2) return false;
    const bindings = c.paramBindings ?? null;
    return !names.every((n) => bindings?.[n.slice(1)]);
  });
  if (pending.length === 0) return [];
  const itemsByIdentity = {};
  for (const name of users) {
    const item = (byUser?.[name] ?? []).find((o) => getByDotPath(o, idField) != null) ?? null;
    if (item) itemsByIdentity[name] = { item };
  }
  const out = await discoverBindings({
    request: contractRequest(ctx, baseUrl),
    slots: pending.map((c) => ({
      key: candKey(c),
      method: c.method ?? "GET",
      path: candPath(c),
      params: (candPath(c).match(/:([A-Za-z_]\w*)/g) ?? []).map((s) => s.slice(1)),
      identity: users[0],
    })),
    itemsByIdentity,
    idField,
  });
  const byKey = new Map(out.results.map((r) => [r.key, r]));
  const resolved = [];
  for (const c of pending) {
    const r = byKey.get(candKey(c));
    if (!r || r.outcome !== "verified" || !r.bindings) {
      ctx.emit({
        kind: "discovery",
        severity: SEVERITY.WARN,
        message: `多段路径「${r?.key ?? candKey(c)}」参数取值未通过实测：${
          r?.outcome === "unbound_param" ? "对象里没有可对应的字段（不猜）" : r?.outcome ?? "unknown"
        }`,
        data: { key: r?.key ?? candKey(c), outcome: r?.outcome ?? "unknown" },
      });
      continue;
    }
    c.paramBindings = { ...(c.paramBindings ?? {}), ...r.bindings };
    const asRead = isReadShaped(c);
    if (asRead && !ctx.plan.readCandidates.includes(c)) {
      ctx.plan.readCandidates = [...(ctx.plan.readCandidates ?? []), c];
      if (!ctx.plan.readCandidate) ctx.plan.readCandidate = c;
    }
    // 单体实体包装路径可能只有这条多段路由能探到（无其它单参数读端点的项目）：
    // 回读 200 已证实响应里哪个位置承载实体，这里补进推导契约
    if (r.entityPath != null && !ctx.targetConfig?.responses?.entity && !ctx._derived?.entity) {
      ctx._derived = { ...(ctx._derived ?? {}), entity: r.entityPath };
      ctx.emit({
        kind: "discovery",
        severity: SEVERITY.INFO,
        message: `实体包装路径经回读实测补推：实体字段=${r.entityPath}（${r.key}）`,
        data: { key: r.key, entityPath: r.entityPath },
      });
    }
    resolved.push({
      key: r.key,
      bindings: Object.fromEntries(Object.entries(r.bindings).map(([k, v]) => [k, v.field])),
      status: r.status,
    });
    ctx.emit({
      kind: "discovery",
      severity: SEVERITY.SUCCESS,
      message: `多段路径参数绑定经实测确认：${r.key} ← ${Object.entries(r.bindings).map(([k, v]) => `${k}=${v.field}`).join("、")}（本人回读 ${r.status}）`,
      data: { key: r.key, bindings: r.bindings },
    });
  }
  // 静态计划只有「多段但无取值来源」这一类候选时，绑定实测就是唯一的放行依据：
  // 全都没绑上则如实报无法构造，而不是带着没填参数的路径去打分。
  if (phase === "pre" && resolved.length === 0 && ctx._planPendingOnly) {
    throw new ProbeError("多段路径参数在真实响应里找不到取值来源，无法构造探测请求", {
      code: "param_binding_unverified",
      hint: `已用本人列表里的真实对象试过这些多段路由（${pending.map((c) => candKey(c)).join("、")}），对象里没有与参数对应的字段，引擎不会猜。请在 guardbuild.json 的 routes[].params 为每个参数声明取值来源（字段名或常量）`,
      details: { pending: pending.map((c) => candKey(c)) },
    });
  }
  return resolved;
}

/* --------------------------------- 资源发现 --------------------------------- */

/**
 * 发现资源归属。优先各身份的按归属列表接口；
 * 无列表接口时可回退匿名 ID 探测（逐个无鉴权候选路径探测，服务匿名用例）；
 * 两者皆无且计划不依赖对象归属时返回空结果（如仅路径穿越用例）。
 * 列表接口/字段名/分页参数没写契约时，先走上面的自动发现（双身份实测）。
 * 返回 { byUser, anonymousItems, anonTargets }。
 */
async function discoverResources(ctx, baseUrl, loggedIn) {
  if (ctx.plan?.listEndpoint || (ctx.analysis?.endpoints ?? []).some((e) => !e.graphql && !e.trpc && (e.method ?? "GET") === "GET" && !/:/.test(e.fullPath ?? e.path ?? ""))) {
    await ensureResourceContract(ctx, { baseUrl, loggedIn });
  }
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
      // 匿名 ID 探测要求响应是 JSON 对象；SSR 应用返回页面时它一无所获，改走页面链接发现
      if (anonTargets.length === 0) {
        const viaHtml = await discoverViaHtmlPages(ctx, baseUrl, loggedIn);
        if (viaHtml) return viaHtml;
      }
      return { byUser: {}, anonymousItems: anonTargets.map((t) => t.item), anonTargets };
    }
    if (
      ctx.plan.traversalCandidate ||
      planCandidates(ctx, "sqli").length > 0 ||
      planCandidates(ctx, "cmdi").length > 0 ||
      planCandidates(ctx, "ssrf").length > 0 ||
      planCandidates(ctx, "upload").length > 0 ||
      planCandidates(ctx, "jwt").length > 0
    ) {
      ctx.emit({
        kind: "discovery",
        severity: SEVERITY.INFO,
        message: "无需资源归属发现：探测计划中的用例不依赖具体对象 ID",
        data: { mode: "not-required" },
      });
      return { byUser: {}, anonymousItems: [], anonTargets: [] };
    }
    // 最后一条回退：SSR/HTML 应用没有 JSON 列表接口，对象 ID 只能从登录后的页面链接里抓
    const viaHtml = await discoverViaHtmlPages(ctx, baseUrl, loggedIn);
    if (viaHtml) return viaHtml;
    // 「找不到列表接口」和「列表找到了但两个身份看到同一批对象」是两件事：
    // 后者是实测出来的事实，报成前者会把读者引去声明一个照样没用的 listEndpoint。
    const notScoped = (ctx._resourceContract?.tried ?? []).filter((t) => /^ids_(?:identical|partial)$/.test(String(t.outcome ?? "")));
    const shared = [...new Set(notScoped.map((t) => t.slot).filter(Boolean))];
    throw new ProbeError(
      notScoped.length
        ? `列表接口未按归属过滤（实测：${shared.join("、")} 在两个身份下返回同一批对象），名下对象无从确定`
        : "静态分析未能定位列表接口，无法发现资源归属",
      {
        code: "no_list_endpoint",
        hint: notScoped.length
          ? "跨归属用例的前提是「这条对象在 A 名下、B 看不见」。实测两个身份的同一路径返回同一批条目时这个前提不成立，引擎按「测不了」收场，不会把人人可见的条目当成某人名下对象。若目标本就按租户/角色共享数据，这种共享语义不在本轮检测范围内；若另有真正按归属过滤的列表，请在 guardbuild.json 用 listEndpoint 指过去。"
          : "当前策略要求目标项目存在按归属过滤的列表接口（如 GET /api/orders），或至少一个无鉴权单体资源接口（如 GET /api/users/:id，用于匿名探测回退）。静态找不到时可在 guardbuild.json 用 listEndpoint 显式声明列表端点（可带分页/过滤查询参数），或在 routes 里补充路由",
      }
    );
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
      data: { identity: ident.name, count: items.length, ids: items.map((o) => resourceIdOf(ctx, o)) },
    });
  }
  // 列表接口存在但按 JSON 取不到任何条目（列表其实渲染成页面）：再用页面链接发现兜一次
  const listed = Object.keys(byUser);
  if (listed.length > 0 && listed.every((name) => (byUser[name] ?? []).length === 0)) {
    const viaHtml = await discoverViaHtmlPages(ctx, baseUrl, loggedIn);
    if (viaHtml) return viaHtml;
  }
  return { byUser, anonymousItems: [], anonTargets: [] };
}

/** 通道未定时最多试几条集合端点做复读（每条都要两身份对拉，成本要封住） */
const MAX_SEED_CHANNELS = 3;

/**
 * #183 种子数据写入端点的观测兜底：契约没写 `register.seed` 时，引擎自己找一个
 * 「会把对象落在当前会话名下」的写接口，让越权用例有真实的受害对象。
 *
 * 为什么这一层不交给模型：「哪个写接口会把对象归属到该身份」是**运行期事实**，
 * 源码里读不出来（中间件注入租户、模型默认 owner、 ORM 作用域都能改变归属）。
 * 采纳的唯一依据是复读：写入方本人的按归属列表里要能看见本次 canary，且其他身份看不见。
 * 所有人都看得见＝列表没按归属过滤，判为 unattributed 并丢弃——宁可有缺口，
 * 也不造出「对象有归属」这个假前提（那会让越权用例的意义整个塌掉）。
 *
 * 这一层跑在资源发现之前：列表契约的实测判定本身要求「两个身份各自名下有对象」，
 * 而对象正是这一层造出来的；先造数据，列表端点/主键再交给双身份对拉实测去定。
 *
 * 边界：只给本轮引擎注册、且名下确实没有对象的账号发写入；纯黑盒目标一律不参与
 * （对他人系统发写请求超出探测授权）；候选来自确定性规则，字段名取自该端点处理函数源码。
 * 失败不抛错：归属对象造不出来时，相关用例会因资源不足记进 `_unverifiedSlots`，
 * 本轮照旧是「测不了」（exit 2），不会被说成「没问题」。
 */
export async function observeSeedWrites(ctx, { baseUrl, byUser, loggedIn }) {
  const out = { byUser, attributed: 0, blocked: null };
  const boot = ctx._identityBootstrap?.byPhase?.[ctx._probePhase ?? "pre"];
  if (!boot || ctx.blackboxUrl) return out;
  const createdNames = new Set((boot.accounts ?? []).filter((a) => a.verdict === "created").map((a) => a.name));
  const seededNames = new Set((boot.seeds ?? []).filter((s) => s.verdict === "written").map((s) => s.identity));
  const nonAdmin = (loggedIn ?? []).filter((i) => i.role !== "admin");
  const need = nonAdmin.filter(
    (i) => createdNames.has(i.name) && !seededNames.has(i.name) && (byUser[i.name] ?? []).length === 0
  );
  if (need.length === 0) return out;
  if (nonAdmin.length < 2) {
    // 只有一个普通身份时，「别人看不见」这条判据无从验证，复读归因不成立：
    // 不发无人能对证的写请求，也不把这条对象当成越权用例的受害对象。
    out.blocked = "single_identity";
    boot.seedObservation = { attempted: false, blocked: out.blocked, identities: need.map((i) => i.name) };
    ctx.emit({
      kind: "identity",
      severity: SEVERITY.WARN,
      message: `种子数据观测兜底未参与：只有 1 个普通身份，无法证明列表按归属过滤（需要两个身份对拉）。跨归属用例本来也 requires 两个不同用户；请声明 register.seed 或补充第二个身份`,
      data: { blocked: out.blocked, identities: need.map((i) => i.name) },
    });
    return out;
  }

  const record = (patch) => {
    boot.seeds.push({ identity: patch.identity, method: patch.method, path: patch.path, ...patch });
  };
  // 复读归因要先有一条「本人看得见、别人看不见」的读取通道。通道还没被定下来时
  // （契约没写 listEndpoint、静态也没定出列表端点）不把这条路直接关掉：用静态枚举出的
  // 集合形态 GET 端点当候选通道，靠本次 canary 是否只出现在调用方列表里选定它——
  // 通道同样由实测证据选定，不是猜出来的。选定并写入后，列表/主键仍交给
  // ensureResourceContract 用双身份对拉实测决定。
  const channels = (ctx.plan?.listEndpoint
    ? [{ method: ctx.plan.listEndpoint.method ?? "GET", path: ctx.plan.listEndpoint.path, query: ctx.plan.listEndpoint.query ?? null }]
    : listSlotsForDiscovery(ctx)
        .slice(0, MAX_SEED_CHANNELS)
        .map((s) => ({ method: s.method ?? "GET", path: s.path, query: s.extraQuery ?? null }))
  ).filter((c) => c.path);
  if (channels.length === 0) {
    // 一条读取通道都没有，复读归因无从做起：这条路诚实关闭，不去发无人能对证的写请求
    out.blocked = "no_list_endpoint";
    boot.seedObservation = { attempted: false, blocked: out.blocked, identities: need.map((i) => i.name) };
    ctx.emit({
      kind: "identity",
      severity: SEVERITY.WARN,
      message: `种子数据观测兜底未参与：本轮没有可用的列表接口（\`${need.length}\` 个新建账号名下没有对象）。越权用例缺少受害对象时会按「测不了」收场，请在 guardbuild.json 声明 listEndpoint 或 register.seed`,
      data: { blocked: out.blocked, identities: need.map((i) => i.name) },
    });
    return out;
  }
  const cands = seedWriteCandidates(ctx.analysis, { listPath: channels[0].path, registerPath: boot.endpoint }).filter(
    (c) => !c.graphql && !c.trpc
  );
  if (cands.length === 0) {
    out.blocked = "no_write_candidates";
    boot.seedObservation = { attempted: false, blocked: out.blocked, listEndpoint: channels[0].path, identities: need.map((i) => i.name) };
    ctx.emit({
      kind: "identity",
      severity: SEVERITY.WARN,
      message: `种子数据观测兜底未参与：静态没有「要求会话、集合形态」的写接口可试（列表 \`${channels[0].path}\`）。新建账号名下没有对象，越权用例将按「测不了」收场；请在 guardbuild.json 的 register.seed 声明写入端点与字段`,
      data: { blocked: out.blocked, listEndpoint: channels[0].path, identities: need.map((i) => i.name) },
    });
    return out;
  }

  const readList = async (name, ch) => {
    const req = slotRequest(ch);
    const r = await httpJson(ctx, {
      baseUrl,
      method: req?.method ?? "GET",
      path: req?.path ?? ch.path,
      identity: name,
      body: req?.body ?? null,
      graphql: req?.graphql ?? false,
    });
    return extractListItems(r.json, listPathFor(ctx, req?.graphql ?? false)) ?? [];
  };

  boot.seedObservation = {
    attempted: true,
    // 单通道时就是它；多通道时等实际读到 canary 的那条被记下来（选定权在复读，不在路径长相）
    listEndpoint: channels.length === 1 ? channels[0].path : null,
    channels: channels.map((c) => c.path),
    candidates: cands.map((c) => c.path),
    identities: need.map((i) => i.name),
  };
  for (const ident of need) {
    for (const cand of cands) {
      const fields = extractBodyFields(await readHandlerSource(ctx, cand));
      if (fields.length === 0) {
        record({ identity: ident.name, method: cand.method, path: cand.path, verdict: "no_body_fields", source: "observed" });
        continue;
      }
      const canary = generateCanary();
      const body = canaryBody(fields, canary);
      const w = await httpJson(ctx, {
        baseUrl,
        method: cand.method,
        path: cand.path,
        identity: ident.name,
        body: JSON.stringify(body),
        contentType: "application/json",
      });
      const cls = classifySeedResponse(w);
      const status = cls.status;
      if (cls.verdict !== "written") {
        record({ identity: ident.name, method: cand.method, path: cand.path, status: cls.status, verdict: cls.verdict, fields, source: "observed" });
        continue;
      }
      // 逐条候选通道复读：只有本次 canary 真实出现在该身份列表里，这条通道才作数
      let att = { verdict: "absent", ownerSeen: false, othersSeen: [] };
      let ownerItems = [];
      let channelUsed = null;
      for (const ch of channels) {
        ownerItems = await readList(ident.name, ch);
        if (!showsCanary(ownerItems, canary)) continue;
        const others = {};
        for (const other of nonAdmin) {
          if (other.name === ident.name) continue;
          others[other.name] = await readList(other.name, ch);
        }
        att = attributeCanary({ ownerItems, otherItemsByOwner: others, canary });
        channelUsed = ch.path;
        break;
      }
      // attributed 才记成 written：报告的「写入 N 条」只数有复读证据的
      record({
        identity: ident.name,
        method: cand.method,
        path: cand.path,
        status,
        verdict: att.verdict === "attributed" ? "written" : att.verdict,
        fields,
        ownerSeen: att.ownerSeen,
        othersSeen: att.othersSeen,
        readBackVia: channelUsed,
        source: "observed",
      });
      if (att.verdict === "attributed") {
        if (boot.seedObservation.listEndpoint !== channelUsed) boot.seedObservation.listEndpoint = channelUsed;
        byUser[ident.name] = ownerItems;
        out.attributed += 1;
        ctx.emit({
          kind: "identity",
          severity: SEVERITY.INFO,
          message: `已为身份「${ident.name}」写入种子数据（${cand.method} ${cand.path} → HTTP ${status}；端点由本轮实跑选定，字段取自该端点处理函数）：本人经 ${channelUsed} 回读到标记 ${canary}，其余 ${nonAdmin.length - 1} 个身份均未见`,
          data: { identity: ident.name, endpoint: cand.path, status, fields, attribution: att.verdict, readBackVia: channelUsed, source: "observed" },
        });
        break;
      }
      ctx.emit({
        kind: "identity",
        severity: SEVERITY.WARN,
        message:
          att.verdict === "unattributed"
            ? `写入成功但无法归属：标记 ${canary} 同时出现在 ${(att.othersSeen.map((n) => `「${n}」`).join("、"))} 的列表里，说明该列表未按归属过滤，本轮不把它当「名下对象」用（${cand.method} ${cand.path}）`
            : `写入返回 HTTP ${status}，但「${ident.name}」本人的列表回读不到标记 ${canary}（${cand.method} ${cand.path}）：该接口没有把对象落在该身份名下`,
        data: { identity: ident.name, endpoint: cand.path, status, fields, attribution: att.verdict, source: "observed" },
      });
    }
  }
  if (out.attributed > 0) {
    out.byUser = { ...byUser };
  }
  return out;
}

/**
 * 建立「资源主键 → 资源对象」索引：多段路径参数（/orgs/:orgId/orders/:orderId）
 * 需要从同一个对象里取出除主键以外的上下文值，索引在发现阶段一次性建立。
 */
function indexResources(ctx, byUser, anonymousItems = []) {
  const map = new Map();
  const add = (o) => {
    const id = resourceIdOf(ctx, o);
    if (id != null && !map.has(String(id))) map.set(String(id), o);
  };
  for (const items of Object.values(byUser ?? {})) for (const o of items ?? []) add(o);
  for (const o of anonymousItems ?? []) add(o);
  return map;
}

/**
 * LLM 侦察路由的运行期实测关（agent 兜底的第 3 关）。
 *
 * 接入侦察只做静态把关（文件存在 + 路径能在文件里定位），hasAuth / hasOwnerFilter
 * 完全是模型断言。这里在目标已启动、身份已登录、资源 id 已发现之后，用真实请求复核：
 * 不存在的路由直接丢弃，鉴权与归属过滤按实测响应回写。验证不通过只会缩小覆盖面，
 * 绝不会凭空造出漏洞结论。
 *
 * 前提：ctx.analysis 中存在 source==="llm-scout" 的候选（其它来源由静态证据支撑，不在此复核）。
 */
export function hasScoutCandidates(ctx) {
  return Array.isArray(ctx?.analysis?.endpoints) && ctx.analysis.endpoints.some((e) => e.source === "llm-scout");
}

function isCollectionCandidate(c) {
  if (c?.list === true) return true;
  const p = candPath(c) ?? "";
  return !/:[A-Za-z_]\w*/.test(p) && !c?.queryParam;
}

function applyScoutVerdict(cand, verdict) {
  cand.liveVerified = true;
  if (verdict.auth === "protected") {
    cand.hasAuth = true;
    cand.authSource = "live-anonymous";
  } else if (verdict.auth === "open") {
    cand.hasAuth = false;
    cand.authSource = "live-anonymous";
    if (cand.kind === "idor-suspect") cand.kind = "no-auth-suspect";
  }
  if (verdict.ownerFilter != null) {
    cand.hasOwnerFilter = verdict.ownerFilter;
    cand.ownerFilterSource = "live-two-identity";
  }
}

async function verifyScoutTargets(ctx, { baseUrl, loggedIn, byUser }) {
  const scoutEps = (ctx.analysis?.endpoints ?? []).filter((e) => e.source === "llm-scout");
  if (scoutEps.length === 0) return null;
  const scoutCands = (ctx.analysis?.candidates ?? []).filter((c) => c.source === "llm-scout");

  const users = (loggedIn ?? []).filter((i) => i.role !== "admin");
  const identities = users.map((u) => u.name);
  const firstIdFor = (name) => {
    const items = byUser?.[name] ?? [];
    for (const o of items) {
      const id = resourceIdOf(ctx, o);
      if (id != null) return id;
    }
    return null;
  };
  // 存在性必须打在真实资源上：假 id 的 404 与「路由不存在」的 404 无法区分。
  let probeId = null;
  let probeIdentity = identities[0] ?? null;
  for (const name of identities) {
    const id = firstIdFor(name);
    if (id != null) {
      probeId = id;
      probeIdentity = name;
      break;
    }
  }

  const routes = scoutEps.slice(0, MAX_SCOUT_ROUTES).map((c) => {
    const collection = isCollectionCandidate(c);
    if (collection) return { key: candKey(c), method: c.method, path: candPath(c), declaredPath: candPath(c), identity: probeIdentity, list: true };
    if (probeId == null) return { key: candKey(c), method: c.method, path: null, declaredPath: candPath(c), identity: null, list: false };
    const req = candRequest(ctx, c, probeId);
    return {
      key: candKey(c),
      method: c.method,
      path: req?.path ?? null,
      declaredPath: candPath(c),
      identity: probeIdentity,
      list: false,
    };
  });

  const result = await verifyScoutRoutes(routes, {
    request: ({ method, path, identity }) => httpJson(ctx, { baseUrl, method, path, identity }),
    fetchList: async (route, identity) => {
      const res = await httpJson(ctx, {
        baseUrl,
        method: route.method ?? "GET",
        path: appendQuery(route.path, ctx.plan?.listEndpoint?.query ?? null),
        identity,
      });
      return extractListItems(res.json, listPathFor(ctx, ctx.plan?.listEndpoint?.graphql)) ?? [];
    },
    idOf: (o) => resourceIdOf(ctx, o),
    identities,
  });

  const droppedKeys = new Map(result.dropped.map((d) => [d.key, d]));
  const keptByKey = new Map(result.kept.map((k) => [k.key, k]));
  const removed = result.dropped.map((d) => ({ key: d.key, reason: d.reason, detail: d.detail ?? null }));
  const droppedCandCount = scoutCands.filter((c) => droppedKeys.has(candKey(c))).length;
  ctx.analysis.candidates = (ctx.analysis.candidates ?? []).filter((c) => {
    return c.source !== "llm-scout" || !droppedKeys.has(candKey(c));
  });
  for (const c of ctx.analysis.candidates ?? []) {
    if (c.source !== "llm-scout") continue;
    const v = keptByKey.get(candKey(c));
    if (v) applyScoutVerdict(c, v);
  }
  ctx.analysis.endpoints = (ctx.analysis.endpoints ?? []).filter((e) => {
    return e.source !== "llm-scout" || !droppedKeys.has(candKey(e));
  });
  for (const e of ctx.analysis.endpoints ?? []) {
    if (e.source !== "llm-scout") continue;
    const v = keptByKey.get(candKey(e));
    if (v) applyScoutVerdict(e, v);
  }

  ctx.scoutRouteVerification = {
    checked: routes.length,
    kept: result.kept.length,
    dropped: removed,
    detail: result.detail,
    requestsUsed: result.requestsUsed,
    baselineStatus: result.baselineStatus,
  };

  if (removed.length > 0) {
    const before = ctx.plan?.listEndpoint?.path ?? null;
    ctx.plan = buildProbePlan(ctx.analysis, {
      loginPathOverride: ctx.loginConfig?.path ?? null,
      contract: ctx.targetConfig ?? null,
    });
    ctx._scoutPlanRebuilt = true;
    ctx._scoutListChanged = (ctx.plan?.listEndpoint?.path ?? null) !== before;
  }
  for (const r of removed) {
    ctx.emit({
      kind: "scout",
      severity: SEVERITY.WARN,
      message: `丢弃 LLM 侦察路由「${r.key}」：实测 ${
        r.reason === "not_found"
          ? "未命中该路由"
          : r.reason === "method_not_allowed"
            ? "方法不被允许"
            : r.reason === "no_probe_id"
              ? "无可填充的真实资源 id，无法验证"
              : r.reason
      }`,
      data: { key: r.key, reason: r.reason, detail: r.detail },
    });
  }
  for (const k of result.kept) {
    const confirmed = [];
    if (k.auth === "open") confirmed.push("匿名即可取到数据（无鉴权确认）");
    if (k.auth === "protected") confirmed.push("匿名被拒绝（需登录确认）");
    if (k.ownerFilter === false) confirmed.push("两身份列表内容一致（未按归属过滤确认）");
    if (k.ownerFilter === true) confirmed.push("两身份列表互斥（归属过滤生效）");
    if (confirmed.length === 0) continue;
    ctx.emit({
      kind: "scout",
      severity: SEVERITY.INFO,
      message: `LLM 侦察路由「${k.key}」实测复核：${confirmed.join("；")}`,
      data: { key: k.key, auth: k.auth, ownerFilter: k.ownerFilter, status: k.status },
    });
  }

  if ((ctx.analysis.candidates ?? []).length === 0 && droppedCandCount > 0) {
    throw new ProbeError(
      `LLM 侦察的 ${droppedCandCount} 条候选路由在运行实例上均未命中，无法证明攻击面`,
      {
        code: "scout_routes_unverified",
        hint: `模型给出的路由实测被目标拒绝（${removed.map((r) => `${r.key}→${r.reason}`).join("；")}）。请在 guardbuild.json 用 routes / openapi.file / listEndpoint 声明真实接口后重跑；本轮没有打到目标，不能据此判定安全`,
        details: { dropped: removed, baselineStatus: result.baselineStatus },
      }
    );
  }
  return ctx.scoutRouteVerification;
}

/**
 * 从发现结果中挑选攻击/业务用例所需的具体对象（loggedIn 携带登录响应中的 user 对象）。
 * 宽容化：缺少身份/对象时返回 null 槽位，由 buildCases 按槽位条件决定哪些用例可构建。
 */
function pickTargets(ctx, byUser, loggedIn, anonymousItems = [], anonTargets = []) {
  const users = loggedIn.filter((i) => i.role !== "admin");
  const attacker = users[0] ?? null;
  const victim = users[1] ?? null; // 归属类用例（越权读/操作）需要第二个普通用户，缺则跳过该槽位
  const admin = loggedIn.find((i) => i.role === "admin") ?? null;
  const attackerItems = attacker ? byUser[attacker.name] ?? [] : [];
  const victimItems = victim ? byUser[victim.name] ?? [] : [];
  const victimPaid = victimItems.filter((o) => o.status === "paid");
  const attackerPaid = attackerItems.filter((o) => o.status === "paid");
  // attacker 自己列表里已有的资源 id：这些资源不属于"他人"，请求成功不算越权
  const attackerOwnIds = new Set(attackerItems.map((o) => String(resourceIdOf(ctx, o))).filter(Boolean));
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
    attackerItems,
    anonTargets,
  };
}

/** 追加固定查询参数（契约 listEndpoint.query，用于分页/过滤）。 */
export function appendQuery(path, query) {
  if (!query || typeof query !== "object") return path;
  const qs = Object.entries(query)
    .filter(([, v]) => v != null)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`)
    .join("&");
  if (!qs) return path;
  return `${path}${path.includes("?") ? "&" : "?"}${qs}`;
}

/**
 * 填充路径参数（任意 :param 形态，不限于 :id）。
 * 契约 params 声明的参数从当前资源对象的字段取值（如 /orgs/:orgId/orders/:orderId 的 orgId），
 * 支持常量；未声明的参数仍按目标对象主键填充（保持单参数路由的既有行为）。
 */
export function fillParams(ctx, cand, path, id) {
  const bindings = cand?.paramBindings ?? null;
  return path.replace(/:([A-Za-z_]\w*)/g, (_m, name) => {
    const b = bindings?.[name];
    if (!b) return String(id);
    if (b.from === "const") return encodeURIComponent(b.value);
    const item = ctx?._resourceById?.get(String(id)) ?? null;
    const v = item ? getByDotPath(item, b.field) : undefined;
    return v === undefined || v === null ? String(id) : encodeURIComponent(String(v));
  });
}

/** 按候选构造请求路径：查询参数形态（?param=id，idor-suspect/queryParam 候选）或路径参数填充 */
function fillCandPath(ctx, cand, id) {
  const path = candPath(cand);
  if (!path) return null;
  if (cand?.queryParam && !/:[A-Za-z_]\w*/.test(path)) {
    const sep = path.includes("?") ? "&" : "?";
    const name = cand.queryParam.param || "id";
    return `${path}${sep}${name}=${encodeURIComponent(String(id))}`;
  }
  return fillParams(ctx, cand, path, id);
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
    return { path: fillCandPath(ctx, cand, id), body: null, method: null, graphql: null };
  }
  if (!isTrpcCandidate(cand)) return { path: fillCandPath(ctx, cand, id), body: null, method: null, graphql: null };
  const req = trpcRequest(cand, id, variantAt(ctx._trpcVariant ?? 0));
  if (!req) return { path: fillCandPath(ctx, cand, id), body: null, method: null, graphql: null };
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
  return { path: appendQuery(slot.path, slot.query), body: null, method: slot.method ?? "GET", graphql: null };
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

// —— SSRF 用例辅助：本地回连 canary ——
// 用例把可被攻击者控制的 URL 指向本进程监听的 127.0.0.1 随机端口；
// 只有目标服务真的发起连接，canary 才会收到带随机令牌的请求。
const SSRF_CANARY_PATH = "/gb-ssrf/";
const SSRF_CANARY_WAIT_MS = 800;

function startSsrfCanary() {
  return new Promise((resolve, reject) => {
    const token = shortId("ssrf");
    const hits = [];
    const server = createServer((req, res) => {
      hits.push({ url: req.url ?? "", at: Date.now() });
      res.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
      res.end(`guardbuild-ssrf-canary:${token}`);
    });
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const port = server.address().port;
      resolve({
        token,
        hits,
        url: `http://127.0.0.1:${port}${SSRF_CANARY_PATH}${token}`,
        close: () => new Promise((r) => server.close(() => r())),
      });
    });
  });
}

async function waitForCanaryHit(canary, timeoutMs = SSRF_CANARY_WAIT_MS) {
  const until = Date.now() + timeoutMs;
  const matched = () => canary.hits.filter((h) => h.url.includes(canary.token)).length;
  while (Date.now() < until) {
    if (matched() > 0) break;
    await new Promise((r) => setTimeout(r, 50));
  }
  return matched();
}

// —— 业务逻辑 / 竞态用例辅助 ——
// 状态跳步：先把对象置于「非前置状态」，再调用流转端点，并以回读状态变化为准；
// 并发双花：同一一次性动作并发提交，只有出现多个不同的副作用标识才算重复执行。
const RACE_CONCURRENCY = 5;
const EFFECT_ID_KEY = /^(?:refund|transaction|txn|transfer|payout|withdrawal|claim|receipt|ledger)_?id$/i;

function firstEffectId(json) {
  const walk = (node, depth) => {
    if (!node || depth > 4) return null;
    if (Array.isArray(node)) {
      for (const v of node) {
        const hit = walk(v, depth + 1);
        if (hit) return hit;
      }
      return null;
    }
    if (typeof node !== "object") return null;
    for (const [k, v] of Object.entries(node)) {
      if (EFFECT_ID_KEY.test(k) && (typeof v === "string" || typeof v === "number") && String(v).length > 0) {
        return String(v);
      }
      const hit = walk(v, depth + 1);
      if (hit) return hit;
    }
    return null;
  };
  return walk(json, 0);
}

// —— JWT 用例辅助 ——
// 伪造令牌只用于本机/授权目标：无签名（alg=none）、无效 HS256 签名、以及源码里明写的密钥签发的 HS256。
// 判定必须内容级：匿名被拒 + 伪造令牌被接受 + 响应回显攻击者指定的身份。

const JWT_FORGE_TTL_S = 3600;

function b64urlJson(obj) {
  return Buffer.from(JSON.stringify(obj)).toString("base64url");
}

function jwtForgeClaims(marker) {
  const now = Math.floor(Date.now() / 1000);
  return {
    sub: marker,
    username: marker,
    name: marker,
    email: `${marker}@gb.local`,
    role: "admin",
    iat: now,
    exp: now + JWT_FORGE_TTL_S,
  };
}

function jwtForgeNone(marker) {
  return `${b64urlJson({ alg: "none", typ: "JWT" })}.${b64urlJson(jwtForgeClaims(marker))}.`;
}

function jwtForgeGarbage(marker) {
  const body = `${b64urlJson({ alg: "HS256", typ: "JWT" })}.${b64urlJson(jwtForgeClaims(marker))}`;
  return `${body}.Z2ItZm9yZ2VkLXNpZ25hdHVyZQ`;
}

function jwtForgeHs256(marker, secret) {
  const body = `${b64urlJson({ alg: "HS256", typ: "JWT" })}.${b64urlJson(jwtForgeClaims(marker))}`;
  const sig = createHmac("sha256", secret).update(body).digest("base64url");
  return `${body}.${sig}`;
}

// —— 文件上传用例辅助 ——

// 主动内容类型：以这些类型同源回读，浏览器会按 HTML/SVG/脚本解析
const UPLOAD_ACTIVE_TYPES = new Set(["text/html", "application/xhtml+xml", "image/svg+xml", "application/javascript", "text/javascript"]);
const UPLOAD_VARIANTS = [
  { ext: "html", type: "text/html", render: (t) => `<div data-gb-upload="${t}">${t}</div>` },
  { ext: "svg", type: "image/svg+xml", render: (t) => `<svg xmlns="http://www.w3.org/2000/svg"><text>${t}</text></svg>` },
];
const UPLOAD_REJECT_RE = /file|upload|type|ext|mime|invalid|unsupported|not\s*allowed|不允许|文件|类型|扩展名/i;

function headerOf(res, name) {
  const want = name.toLowerCase();
  for (const [k, v] of Object.entries(res?.headers ?? {})) {
    if (k.toLowerCase() === want) return v;
  }
  return null;
}

/** 构造 multipart 上传体；字段名来自静态分析，仍做字符白名单避免头注入 */
function multipartUpload(field, filename, contentType, content, token) {
  const safeField = String(field ?? "file").replace(/[^A-Za-z0-9_.-]/g, "") || "file";
  const boundary = `----GuardBuild${token}`;
  const body = [
    `--${boundary}`,
    `Content-Disposition: form-data; name="${safeField}"; filename="${filename}"`,
    `Content-Type: ${contentType}`,
    "",
    content,
    `--${boundary}--`,
    "",
  ].join("\r\n");
  return { body, contentType: `multipart/form-data; boundary=${boundary}`, field: safeField };
}

const UPLOAD_LOCATION_KEYS = ["url", "href", "path", "location", "fileUrl", "file_url", "src"];

/** 从上传响应提取可回读地址（仅同源相对/绝对路径；裸 filename 不算） */
function uploadLocationFrom(res, baseUrl) {
  const direct = headerOf(res, "location") ?? headerOf(res, "x-file-url") ?? headerOf(res, "x-upload-url");
  const candidates = [direct];
  for (const obj of [res?.json, res?.json?.data, res?.json?.file, res?.json?.result, res?.json?.data?.file]) {
    if (!obj || typeof obj !== "object") continue;
    for (const key of UPLOAD_LOCATION_KEYS) {
      if (typeof obj[key] === "string") candidates.push(obj[key]);
    }
  }
  for (const loc of candidates) {
    if (!loc || typeof loc !== "string" || loc.length > 500) continue;
    try {
      const abs = new URL(loc, baseUrl);
      const base = new URL(baseUrl);
      if (abs.host !== base.host) continue;
      return { path: `${abs.pathname}${abs.search}`, raw: loc };
    } catch {
      /* 非法地址忽略 */
    }
  }
  return null;
}

/** 上传成功但未返回地址时，按常见静态目录尝试回读（命中仍须内容与主动类型双重校验） */
function uploadGuessPaths(filename) {
  return ["/uploads", "/files", "/static/uploads", "/upload", "/public/uploads"].map(
    (dir) => `${dir}/${encodeURIComponent(filename)}`
  );
}

/** 回读上传文件：先匿名，拒绝时用上传身份复读 */
async function fetchUploaded(c, baseUrl, path, identity) {
  let res = await httpJson(c, { baseUrl, method: "GET", path });
  if (DENIED_STATUS.has(res.status) && identity) {
    res = await httpJson(c, { baseUrl, method: "GET", path, identity });
  }
  return res;
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

/**
 * 变体轴的展开器：配方挑轴（顺序、要不要修复前复现），这里定「怎么展开」。
 * 轴词表在 attackvariants（用例 id 的还原规则也在那里）——加一条轴＝注册一个展开器，
 * 属于能力增长，走能力请求单；配方写出词表外的轴会在装载时就被拒收。
 * 每轴的内部条数上限（他人对象数、ID 写法数）同样留在代码里：那是执行预算，不是表的格子。
 */
const VARIANT_AXIS_BUILDERS = {
  obj: (ctx, { primaryRead, targets, targetId }) =>
    foreignObjectVariants(targets.victimItems, targetId, targets.attackerOwnIds ?? new Set()).map((v) => ({
      label: v.label,
      targetId: resourceIdOf(ctx, v.item),
      req: candRequest(ctx, primaryRead, resourceIdOf(ctx, v.item)),
    })),
  enc: (ctx, { primaryRead, targetId }) =>
    idEncodingVariants(targetId).map((v) => ({
      label: `ID ${v.label}「${v.token}」`,
      targetId,
      req: rawTokenRequest(primaryRead, v.token) ?? candRequest(ctx, primaryRead, v.token),
    })),
  chan: (ctx, { primaryRead, targetId }) => {
    const channel = channelVariantFor(primaryRead);
    if (!channel) return [];
    const sep = channel.base.includes("?") ? "&" : "?";
    return [
      {
        label: channel.label,
        targetId,
        req: {
          method: primaryRead.method ?? "GET",
          path: `${channel.base}${sep}${channel.param}=${encodeURIComponent(String(targetId))}`,
          body: null,
        },
      },
    ];
  },
};

/** 构建一个阶段内的全部用例（攻击 + 业务），攻击目标对象由发现阶段确定 */
export function buildCases(ctx, targets) {
  // 越权读一族的结构来自配方（sidecar/recipes/idor-read*.json）。装载即过动作表校验：
  // 表外动作、词表外的变体轴、与实际判卷代码不符的判据名都在这里抛出，
  // 不会退回写死的结构冒充「照常跑通」——那正是一块新的假绿灯。
  const readAttack = baselineStep("idor-read");
  const visibleRecipe = loadRecipe("idor-read-owner-visible");
  const readActor = resolveRole(targets, identityRole(readAttack.step));
  // SQL 注入族与路径穿越族的结构也来自配方（M1-5b 放量）：槽位、参数名引用、载荷集名字、
  // canary、判据名任一对不上，装载阶段就整族抛错，不退回去用写死的形状冒充「照常跑通」。
  const sqliAttack = baselineStep("sqli-injection", "payload.inject");
  const travAttack = baselineStep("path-traversal", "fs.traverse");
  const sqliActor = resolveRolePreferred(targets, identityRole(sqliAttack.step));
  const travIdentity = resolveRolePreferred(targets, "victim")?.name ?? null;
  // 交叉证明挂不挂，看配方有没有声明归属人复读（uses 指向基线步骤；
  // 同一入口的其它候选与变体写法沿用同一条声明——它们验的是同一个洞）
  const readCrossProof = ownershipReadbacks(readAttack.recipe).some((s) => s.uses === readAttack.step.id);

  // 每类候选 top-K 逐一构建攻击用例；首个候选保持基名（兼容既有报告/测试/e2e）
  const readCands = planCandidates(ctx, readAttack.kind);
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
    if (!path || !targets.readTarget || !readActor || !victim) continue;
    const readTarget = targets.readTarget;
    const suffix = i === 0 ? "" : `-${i + 1}`;
    const multi = readCands.length > 1 ? `（${path}）` : "";
    const candLabel = resourceLabelOf(cand.resource ?? ctx.plan?.resource);
    const req = candRequest(ctx, cand, resourceIdOf(ctx, readTarget));
    cases.push({
      id: `${readAttack.step.id}${suffix}`,
      candidateKey: candKey(cand),
      category: CASE_CATEGORY.ATTACK,
      name: `${readActor.name} 读取 ${victim.name} 的${candLabel} #${resourceIdOf(ctx, readTarget)}${multi}`,
      identity: readActor.name,
      method: req.method ?? readAttack.step.method ?? "GET",
      path: req.path,
      body: req.body,
      graphql: req.graphql ?? null,
      routeKey: cand.routeKeys?.[0] ?? readKey,
      expect: `越权读取他人${candLabel}应被拒绝（401/403/404）`,
      verify: (res, phase) => {
        const o = extractEntity(res.json, entityPathFor(ctx, cand.graphql));
        const leaked = o && String(resourceIdOf(ctx, o)) === String(resourceIdOf(ctx, readTarget));
        // 跨端点 id 串号防护：如果 attacker 自己列表里就有这个 id，说明是自己的资源，不是越权
        const isOwnResource = leaked && targets.attackerOwnIds?.has(String(resourceIdOf(ctx, readTarget)));
        if (isOwnResource) {
          // 不算越权：attacker 本来就能访问自己的资源
          return { verdict: "inconclusive", actual: `目标 #${resourceIdOf(ctx, readTarget)} 在 attacker 自己的资源列表中，疑似跨端点 id 串号，不计为越权` };
        }
        // JSON 响应比对字段；页面响应没有字段可比，改用正文归属证据
        const html = leaked ? null : htmlLeakEvidence(ctx, res, resourceIdOf(ctx, readTarget));
        const detail = leaked
          ? `证据：返回${candLabel} #${resourceIdOf(ctx, o)}（${leakEvidenceFields(ctx, o, cand.ownerField)}）`
          : html?.leaked
            ? htmlLeakDetail(html)
            : "";
        return verifyAttack(res, phase, detail, leaked || html?.leaked === true);
      },
      crossProof: readCrossProof ? (res) => {
        const o = extractEntity(res.json, entityPathFor(ctx, cand.graphql));
        if (o && String(resourceIdOf(ctx, o)) === String(resourceIdOf(ctx, readTarget))) {
          const ownerOk = !victim.user?.id || ownerOf(ctx, o, cand.ownerField) === victim.user.id;
          if (ownerOk) {
            const content = contentFieldOf(o);
            return {
              note: `响应对象 #${resourceIdOf(ctx, o)} 与请求目标一致，归属 ${ownerOf(ctx, o, cand.ownerField)}${victim.user?.id ? "（与受害人身份一致）" : ""}${content ? `，内容字段 ${content[0]}=${content[1]} 与本人列表中的该对象一致` : ""}`,
            };
          }
        }
        const html = htmlLeakEvidence(ctx, res, resourceIdOf(ctx, readTarget));
        if (!html?.leaked) return null;
        return {
          note: `页面正文交叉证明：攻击响应含 ${victim.name} 本人会话下 ${html.link} 独有的 ${html.markers.length} 个片段（${html.markers.slice(0, 6).join("、")}${html.markers.length > 6 ? "…" : ""}）`,
        };
      } : null,
      impact: (res) =>
        okStatus(res.status)
          ? ctx._htmlPages?.baseline?.has(String(resourceIdOf(ctx, readTarget)))
            ? `可读取他人${candLabel}页面正文（页面渲染的完整内容，无字段级隔离）`
            : `可读取他人${candLabel}详情及字段（id/userId/amount/address 等）`
          : null,
    });
  }

  // —— 同源攻击变体（换对象 / 换 ID 写法 / 换参数通道）——
  // 只对首要读候选展开：基线用例可能「碰巧」因补丁只挡住了那一个对象、那一种写法而通过。
  // 变体带 requiresPreRepro：修复前没复现的（该目标本就不认这种写法）不参与修复后验收。
  const primaryRead = readCands[0];
  if (primaryRead && targets.readTarget && readActor && victim) {
    const candLabel = resourceLabelOf(primaryRead.resource ?? ctx.plan?.resource);
    const targetId = resourceIdOf(ctx, targets.readTarget);
    // 轴的顺序与条数配额：顺序由配方声明（决定用例编号怎么分），
    // 总数上限 MAX_VARIANT_CASES 与每轴内部展开几条留在引擎里（预算，不是表的格子）
    const variants = [];
    for (const spec of variantAxisSteps(readAttack.recipe)) {
      for (const item of VARIANT_AXIS_BUILDERS[spec.axis](ctx, { primaryRead, targets, targetId })) {
        variants.push({ ...item, axis: spec.axis, requiresPreRepro: spec.requiresPreRepro });
      }
    }
    const axisSeq = {};
    for (const v of variants.slice(0, MAX_VARIANT_CASES)) {
      if (!v.req?.path) continue;
      axisSeq[v.axis] = (axisSeq[v.axis] ?? 0) + 1;
      const caseId = variantCaseId(readAttack.step.id, v.axis, axisSeq[v.axis]);
      cases.push({
        id: caseId,
        candidateKey: candKey(primaryRead),
        category: CASE_CATEGORY.ATTACK,
        name: `变体·${v.label}：${readActor.name} 读取 ${victim.name} 的${candLabel}`,
        identity: readActor.name,
        method: v.req.method ?? "GET",
        path: v.req.path,
        body: v.req.body,
        graphql: v.req.graphql ?? null,
        routeKey: primaryRead.routeKeys?.[0] ?? readKey,
        variant: { axis: v.axis, label: v.label },
        requiresPreRepro: v.requiresPreRepro === true,
        expect: `同一越权入口的变体应被拒绝（401/403/404），补丁不能只挡住基线写法`,
        verify: (res, phase) => {
          const o = extractEntity(res.json, entityPathFor(ctx, primaryRead.graphql));
          const leaked = o && String(resourceIdOf(ctx, o)) === String(v.targetId);
          if (leaked && targets.attackerOwnIds?.has(String(v.targetId))) {
            return { verdict: "inconclusive", actual: `目标 #${v.targetId} 在 attacker 自己的资源列表中，疑似跨端点 id 串号，不计为越权` };
          }
          const html = leaked ? null : htmlLeakEvidence(ctx, res, v.targetId);
          const detail = leaked
            ? `证据：变体写法仍返回${candLabel} #${resourceIdOf(ctx, o)}（归属 ${ownerOf(ctx, o, primaryRead.ownerField)}），补丁只挡住了部分入口`
            : html?.leaked
              ? `证据：变体写法仍拿到 ${html.owner} 本人页面（${html.link}）独有的 ${html.markers.length} 个内容片段，补丁只挡住了部分入口`
              : "";
          return verifyAttack(res, phase, detail, leaked || html?.leaked === true);
        },
        crossProof: readCrossProof ? (res) => {
          const o = extractEntity(res.json, entityPathFor(ctx, primaryRead.graphql));
          if (o && String(resourceIdOf(ctx, o)) === String(v.targetId)) {
            if (victim.user?.id && ownerOf(ctx, o, primaryRead.ownerField) !== victim.user.id) return null;
            return { note: `变体「${v.label}」命中的对象 #${resourceIdOf(ctx, o)} 归属 ${ownerOf(ctx, o, primaryRead.ownerField)}（与受害人一致）` };
          }
          const html = htmlLeakEvidence(ctx, res, v.targetId);
          if (!html?.leaked) return null;
          return { note: `变体「${v.label}」同样拿到 ${victim.name} 本人页面的 ${html.markers.length} 个独有片段，补丁只挡住了部分写法` };
        } : null,
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
    const req = candRequest(ctx, cand, resourceIdOf(ctx, cancelTarget));
    cases.push({
      id: `attack-cancel-foreign${suffix}`,
      candidateKey: candKey(cand),
      category: CASE_CATEGORY.ATTACK,
      name: `${attacker.name} 取消 ${victim.name} 的${candLabel} #${resourceIdOf(ctx, cancelTarget)}${multi}`,
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
          o && o.status === "cancelled" && (!victim.user?.id || ownerOf(ctx, o, cand.ownerField) === victim.user.id);
        const detail = changed ? `证据：${candLabel} #${resourceIdOf(ctx, o)}（归属 ${ownerOf(ctx, o, cand.ownerField)}）状态已被改为 cancelled` : "";
        return verifyAttack(res, phase, detail, changed);
      },
      crossProof: (res) => {
        const o = extractEntity(res.json, entityPathFor(ctx, cand.graphql));
        if (!o || String(resourceIdOf(ctx, o)) !== String(resourceIdOf(ctx, cancelTarget))) return null;
        if (victim.user?.id && ownerOf(ctx, o, cand.ownerField) !== victim.user.id) return null;
        return {
          note: `被操对象 #${resourceIdOf(ctx, o)} 归属 ${ownerOf(ctx, o, cand.ownerField)}${o.status === "cancelled" ? "，状态已变更为 cancelled" : ""}`,
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
          ? `证据：返回 ${arr.length} 条${label}（归属 ${[...new Set(arr.map((o) => ownerOf(ctx, o)))].join(",")}），纵向越权可览全局数据`
          : "";
        return verifyAttack(res, phase, detail, leaked);
      },
      crossProof: (res) => {
        const arr = extractListItems(res.json, listPathFor(ctx, ctx.plan.adminListEndpoint?.graphql));
        if (!arr || arr.length === 0) return null;
        const foreign = arr.filter((o) => ownerOf(ctx, o) !== victim.user?.id).length;
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
    const req = candRequest(ctx, cand, resourceIdOf(ctx, anonTarget));
    cases.push({
      id: `attack-anonymous-read${suffix}`,
      candidateKey: candKey(cand),
      category: CASE_CATEGORY.ATTACK,
      name: `未携带凭证读取${candLabel} #${resourceIdOf(ctx, anonTarget)}（无鉴权端点${multiText}）`,
      identity: null,
      method: req.method ?? "GET",
      path: req.path,
      body: req.body,
      graphql: req.graphql ?? null,
      routeKey: cand.routeKeys?.[0] ?? null,
      expect: `未认证读取${candLabel}应被拒绝（401/403/404）`,
      verify: (res, phase) => {
        const o = extractEntity(res.json, entityPathFor(ctx, cand.graphql));
        const leaked = o && String(resourceIdOf(ctx, o)) === String(resourceIdOf(ctx, anonTarget));
        const detail = leaked
          ? `证据：匿名请求即返回${candLabel} #${resourceIdOf(ctx, o)}（归属 ${ownerOf(ctx, o, cand.ownerField)}），无需任何认证`
          : "";
        return verifyAttack(res, phase, detail, leaked);
      },
      crossProof: (res) => {
        const o = extractEntity(res.json, entityPathFor(ctx, cand.graphql));
        if (!o || String(resourceIdOf(ctx, o)) !== String(resourceIdOf(ctx, anonTarget))) return null;
        return { note: `匿名响应对象 #${resourceIdOf(ctx, o)} 与请求目标一致，归属 ${ownerOf(ctx, o, cand.ownerField)}` };
      },
      impact: (res) => {
        const o = extractEntity(res.json, entityPathFor(ctx, cand.graphql));
        return o && String(resourceIdOf(ctx, o)) === String(resourceIdOf(ctx, anonTarget)) ? `未认证即可读取任意${candLabel}详情（认证缺失）` : null;
      },
    });
  }

  // —— 路径穿越攻击用例：对逐条 payload 尝试，命中泄露证据即停（无修复策略，仅取证）——
  for (const [i, cand] of planCandidates(ctx, travAttack.kind).entries()) {
    const routePath = candPath(cand);
    if (!routePath) continue;
    const travRef = cand[travAttack.kind];
    const trav = {
      ...travRef,
      param: resolvePlanField(travAttack.step.param, travRef, "path-traversal", "穿越注入点"),
    };
    const suffix = i === 0 ? "" : `-${i + 1}`;
    const firstAttempt = traversalAttemptPath(routePath, trav, TRAVERSAL_PAYLOADS[0], false);
    cases.push({
      id: `${travAttack.step.id}${suffix}`,
      candidateKey: candKey(cand),
      category: CASE_CATEGORY.ATTACK,
      unfixable: true,
      name: `路径穿越读取服务器文件（${routePath}${trav.param ? ` · 参数 ${trav.param}` : ""}）`,
      identity: travIdentity,
      method: travAttack.step.method ?? "GET",
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

  // —— SSRF 攻击用例：把 HTTP 客户端的 URL 指向本机 canary，命中回连即成立（无修复模板，仅取证）——
  for (const [i, cand] of planCandidates(ctx, "ssrf").entries()) {
    const ssrf = cand.ssrf;
    const routePath = candPath(cand);
    if (!routePath || !ssrf) continue;
    const suffix = i === 0 ? "" : `-${i + 1}`;
    const placeholder = "http://127.0.0.1:1/gb-ssrf/placeholder";
    const firstReq = injectionReq(cand, ssrf, placeholder);
    if (!firstReq) continue;
    const ssrfIdentity = attacker?.name ?? victim?.name ?? null;
    cases.push({
      id: `attack-ssrf${suffix}`,
      candidateKey: candKey(cand),
      category: CASE_CATEGORY.ATTACK,
      unfixable: true,
      name: `SSRF 服务端请求伪造（${routePath}${ssrf.param ? ` · 参数 ${ssrf.param}` : ""}）`,
      identity: ssrfIdentity,
      method: firstReq.method,
      path: firstReq.path,
      body: firstReq.body,
      routeKey: cand.routeKeys?.[0] ?? null,
      expect: "请求中的 URL 不得由服务端直接发起（应校验协议与主机白名单），不得回连内网地址",
      send: async (c, baseUrl) => {
        const canary = await startSsrfCanary();
        try {
          const req = injectionReq(cand, ssrf, canary.url);
          let res = null;
          let err = null;
          try {
            res = await httpJson(c, { baseUrl, ...req, identity: ssrfIdentity });
          } catch (e) {
            err = e;
          }
          const hits = await waitForCanaryHit(canary);
          if (!res && hits === 0) {
            throw err ?? new ProbeError(`SSRF 探测请求失败（${routePath}）`, { code: "probe_request_failed" });
          }
          const chosen = res ?? { status: 0, statusText: "", body: "", json: null };
          chosen._ssrfProof = {
            hit: hits > 0,
            canaryUrl: canary.url,
            requestPath: req.path,
            hits,
            fetchError: res ? null : String(err?.message ?? err ?? "").slice(0, 180),
          };
          return { res: chosen, path: req.path, method: req.method };
        } finally {
          await canary.close();
        }
      },
      verify: (res, phase) => {
        const proof = res._ssrfProof ?? {};
        const detail = proof.hit
          ? `证据：服务端回连本机 canary（${proof.canaryUrl}，命中 ${proof.hits} 次）`
          : "";
        if (phase === "pre") {
          if (proof.hit) {
            return { verdict: VERDICT.VULNERABLE, actual: `HTTP ${res.status}，服务端按请求参数发起了请求。${detail}` };
          }
          if (DENIED_STATUS.has(res.status)) {
            return {
              verdict: VERDICT.BLOCKED,
              actual: `HTTP ${res.status}，请求中的 URL 在修复前即被拦截（静态分析误报，无需修复）`,
            };
          }
          return {
            verdict: VERDICT.INCONCLUSIVE,
            actual: `HTTP ${res.status}，未观测到 canary 回连${
              proof.fetchError ? `（目标侧请求失败：${proof.fetchError}）` : "（可能已有主机/协议白名单）"
            }`,
          };
        }
        if (proof.hit) {
          return { verdict: VERDICT.REGRESSED, actual: `HTTP ${res.status}，修复后仍回连攻击者指定的地址。${detail}` };
        }
        if (DENIED_STATUS.has(res.status)) {
          return { verdict: VERDICT.BLOCKED, actual: `HTTP ${res.status}，请求中的 URL 被拒绝。${detail}` };
        }
        if (res.status === 0) {
          return { verdict: VERDICT.INCONCLUSIVE, actual: "修复后目标未返回响应，且未观测到回连，结果无法判定" };
        }
        return { verdict: VERDICT.BLOCKED, actual: `HTTP ${res.status}，未再观测到 canary 回连（URL 已受限）` };
      },
      crossProof: (res) =>
        res._ssrfProof?.hit
          ? {
              note: `服务端回连本机 canary（${res._ssrfProof.canaryUrl}，命中 ${res._ssrfProof.hits} 次）：请求 URL 由攻击者完全控制`,
            }
          : null,
      impact: (res) =>
        res._ssrfProof?.hit
          ? "可由服务端发起任意内网/外部请求（探测内网服务、访问云元数据、绕过网络边界）"
          : null,
    });
  }

  // —— 文件上传用例：上传仅含随机令牌的主动内容文件，再同源回读（无修复模板，仅取证）——
  for (const [i, cand] of planCandidates(ctx, "upload").entries()) {
    const upload = cand.upload;
    const routePath = candPath(cand);
    if (!routePath || !upload) continue;
    const suffix = i === 0 ? "" : `-${i + 1}`;
    const method = cand.method ?? "POST";
    const uploadIdentity = attacker?.name ?? victim?.name ?? null;
    cases.push({
      id: `attack-upload${suffix}`,
      candidateKey: candKey(cand),
      category: CASE_CATEGORY.ATTACK,
      unfixable: true,
      name: `文件上传（${routePath}${upload.field ? ` · 字段 ${upload.field}` : ""}）`,
      identity: uploadIdentity,
      method,
      path: routePath,
      routeKey: cand.routeKeys?.[0] ?? null,
      expect: "上传接口应校验扩展名/内容类型与文件内容，拒绝 HTML/SVG/脚本等主动内容，且不得以可渲染类型同源回读",
      send: async (c, baseUrl) => {
        const attempts = [];
        let accepted = null;
        let last = null;
        let firstErr = null;
        for (const variant of UPLOAD_VARIANTS) {
          const token = shortId("up").replace(/_/g, "");
          const filename = `gb-${token}.${variant.ext}`;
          const form = multipartUpload(upload.field, filename, variant.type, variant.render(token), token);
          try {
            const res = await httpJson(c, {
              baseUrl,
              method,
              path: routePath,
              identity: uploadIdentity,
              body: form.body,
              contentType: form.contentType,
            });
            last = res;
            attempts.push({ ext: variant.ext, status: res.status, contentType: headerOf(res, "content-type") ?? "" });
            if (okStatus(res.status)) {
              accepted = { res, variant, token, filename };
              break;
            }
          } catch (e) {
            if (!firstErr) firstErr = e;
            attempts.push({ ext: variant.ext, status: 0, error: String(e?.message ?? e).slice(0, 160) });
          }
        }
        if (!accepted) {
          if (!last) {
            throw firstErr ?? new ProbeError(`文件上传探测请求全部失败（${routePath}）`, { code: "probe_request_failed" });
          }
          last._uploadProof = { accepted: false, attempts };
          return { res: last, path: routePath, method };
        }
        const loc = uploadLocationFrom(accepted.res, baseUrl);
        const readPaths = loc ? [loc.path] : uploadGuessPaths(accepted.filename);
        let fetched = null;
        let fetchedPath = null;
        for (const p of readPaths) {
          try {
            const r = await fetchUploaded(c, baseUrl, p, uploadIdentity);
            if (!fetched) {
              fetched = r;
              fetchedPath = p;
            }
            if (okStatus(r.status)) {
              fetched = r;
              fetchedPath = p;
              break;
            }
          } catch {
            /* 单个回读路径失败不影响其余尝试 */
          }
        }
        const ct = (headerOf(fetched, "content-type") ?? "").split(";")[0].trim().toLowerCase();
        const disposition = headerOf(fetched, "content-disposition") ?? "";
        const markerMatched = !!fetched && String(fetched.body ?? "").includes(accepted.token);
        const activeType = UPLOAD_ACTIVE_TYPES.has(ct);
        const attachment = /attachment/i.test(disposition);
        const proof = {
          accepted: true,
          attempts,
          ext: accepted.variant.ext,
          filename: accepted.filename,
          token: accepted.token,
          location: loc?.path ?? null,
          fetchedPath,
          fetchedStatus: fetched?.status ?? null,
          contentType: ct,
          disposition,
          markerMatched,
          activeType,
          attachment,
          exploitable: markerMatched && activeType && !attachment,
        };
        accepted.res._uploadProof = proof;
        return { res: accepted.res, path: routePath, method };
      },
      verify: (res, phase) => {
        const p = res._uploadProof ?? {};
        const attempted = (p.attempts ?? [])
          .map((a) => `${a.ext}:${a.status || "ERR"}`)
          .join("、");
        if (phase === "pre") {
          if (p.exploitable) {
            return {
              verdict: VERDICT.VULNERABLE,
              actual: `HTTP ${res.status}，上传 ${p.filename} 成功；同源 ${p.fetchedPath} 以 ${p.contentType} 回读上传内容（令牌 ${p.token}）`,
            };
          }
          if (!p.accepted) {
            const body = String(res.body ?? "");
            if (res.status === 401 || res.status === 403) {
              return {
                verdict: VERDICT.BLOCKED,
                actual: `HTTP ${res.status}，上传接口在修复前即拒绝该身份（静态分析误报，无需修复）`,
              };
            }
            if ((res.status === 400 || res.status === 415) && UPLOAD_REJECT_RE.test(body)) {
              return {
                verdict: VERDICT.BLOCKED,
                actual: `HTTP ${res.status}，主动内容文件被拒绝（尝试：${attempted}）`,
              };
            }
            return {
              verdict: VERDICT.INCONCLUSIVE,
              actual: `HTTP ${res.status}，上传未成功且无法确认是类型校验（尝试：${attempted}）`,
            };
          }
          if (!p.fetchedStatus) {
            return {
              verdict: VERDICT.INCONCLUSIVE,
              actual: `上传被接受（${p.ext}），但响应未给出可回读地址，无法证明文件可被同源读取`,
            };
          }
          if (!p.markerMatched) {
            return {
              verdict: VERDICT.INCONCLUSIVE,
              actual: `上传被接受，但回读 HTTP ${p.fetchedStatus} 未包含上传令牌（可能重命名/转码或未公开存储）`,
            };
          }
          if (p.attachment || !p.activeType) {
            return {
              verdict: VERDICT.BLOCKED,
              actual: `上传被接受，但回读为 ${
                p.attachment ? "附件下载" : `惰性类型 ${p.contentType || "未知"}`
              }，主动内容不会同源渲染`,
            };
          }
          return { verdict: VERDICT.INCONCLUSIVE, actual: `HTTP ${res.status}，上传结果无法判定` };
        }
        if (p.exploitable) {
          return {
            verdict: VERDICT.REGRESSED,
            actual: `HTTP ${res.status}，修复后仍可上传主动内容并同源回读（令牌 ${p.token}）`,
          };
        }
        if (!p.accepted) {
          if (res.status === 401 || res.status === 403 || res.status === 400 || res.status === 415) {
            return { verdict: VERDICT.BLOCKED, actual: `HTTP ${res.status}，主动内容文件已被拒绝（尝试：${attempted}）` };
          }
          return { verdict: VERDICT.INCONCLUSIVE, actual: `HTTP ${res.status}，上传结果无法判定` };
        }
        if (p.markerMatched && (p.attachment || !p.activeType)) {
          return {
            verdict: VERDICT.BLOCKED,
            actual: `上传仍被接受，但回读为 ${p.attachment ? "附件下载" : `惰性类型 ${p.contentType}`}，主动内容已被中和`,
          };
        }
        return { verdict: VERDICT.INCONCLUSIVE, actual: "修复后上传结果无法作出一致判定" };
      },
      crossProof: (res) =>
        res._uploadProof?.exploitable
          ? {
              note: `上传文件 ${res._uploadProof.filename} 以 ${res._uploadProof.contentType} 同源回读（令牌 ${res._uploadProof.token}）：服务端接受并公开提供攻击者控制的主动内容`,
            }
          : null,
      impact: (res) =>
        res._uploadProof?.exploitable
          ? "可上传任意 HTML/SVG 主动内容并在同源回读，构造存储型 XSS、钓鱼页面或恶意下载；若服务器按扩展名执行脚本，可能进一步导致远程代码执行"
          : null,
    });
  }

  // —— JWT 伪造令牌用例：alg=none / 无效签名 / 源码密钥签发，接受且回显伪造身份即成立 ——
  for (const [i, cand] of planCandidates(ctx, "jwt").entries()) {
    const routePath = candPath(cand);
    if (!routePath || !cand.jwt) continue;
    const suffix = i === 0 ? "" : `-${i + 1}`;
    const method = cand.method ?? "GET";
    cases.push({
      id: `attack-jwt-forge${suffix}`,
      candidateKey: candKey(cand),
      category: CASE_CATEGORY.ATTACK,
      unfixable: true,
      name: `JWT 伪造令牌（${routePath} · ${cand.jwt.label ?? cand.jwt.issue}）`,
      identity: null,
      method,
      path: routePath,
      routeKey: cand.routeKeys?.[0] ?? null,
      expect: "受认证端点必须校验 JWT 签名与算法：alg=none、无效签名或非授权密钥签发的令牌都应被拒绝（401/403）",
      send: async (c, baseUrl) => {
        const marker = `gbjwt${shortId("f").replace(/[^a-z0-9]/gi, "")}`;
        const anon = await httpJson(c, { baseUrl, method, path: routePath });
        const protectedEndpoint = DENIED_STATUS.has(anon.status);
        const attempts = [];
        if (!protectedEndpoint) {
          anon._jwtProof = { marker, baselineStatus: anon.status, protected: false, attempts, hit: false };
          return { res: anon, path: routePath, method };
        }
        const variants = [
          { alg: "alg=none", token: jwtForgeNone(marker) },
          { alg: "HS256(签名无效)", token: jwtForgeGarbage(marker) },
          ...(cand.jwt.secrets ?? []).map((secret) => ({ alg: "HS256(源码密钥)", token: jwtForgeHs256(marker, secret) })),
        ];
        let hit = null;
        let acceptedWithoutEcho = null;
        let lastRes = anon;
        for (const v of variants) {
          let res;
          try {
            res = await httpJson(c, {
              baseUrl,
              method,
              path: routePath,
              extraHeaders: { Authorization: `Bearer ${v.token}` },
            });
          } catch (e) {
            attempts.push({ alg: v.alg, status: 0, error: String(e?.message ?? e).slice(0, 160) });
            continue;
          }
          lastRes = res;
          const markerEcho = String(res.body ?? "").includes(marker);
          attempts.push({ alg: v.alg, status: res.status, markerEcho });
          if (okStatus(res.status) && markerEcho) {
            hit = { res, alg: v.alg };
            break;
          }
          if (okStatus(res.status) && !acceptedWithoutEcho) acceptedWithoutEcho = { res, alg: v.alg };
        }
        const chosen = hit?.res ?? lastRes;
        chosen._jwtProof = {
          marker,
          baselineStatus: anon.status,
          protected: true,
          attempts,
          hit: !!hit,
          alg: hit?.alg ?? null,
          acceptedWithoutEcho: acceptedWithoutEcho?.alg ?? null,
        };
        return { res: chosen, path: routePath, method };
      },
      verify: (res, phase) => {
        const p = res._jwtProof ?? {};
        const tried = (p.attempts ?? []).map((a) => `${a.alg}:${a.status || "ERR"}`).join("、");
        if (!p.protected) {
          return {
            verdict: VERDICT.INCONCLUSIVE,
            actual: `HTTP ${p.baselineStatus}，匿名访问未被拒绝，该端点不经认证，无法构成令牌伪造绕过`,
          };
        }
        if (phase === "pre") {
          if (p.hit) {
            return {
              verdict: VERDICT.VULNERABLE,
              actual: `HTTP ${res.status}，使用 ${p.alg} 伪造令牌通过校验；响应回显伪造身份 ${p.marker}`,
            };
          }
          if (p.acceptedWithoutEcho) {
            return {
              verdict: VERDICT.INCONCLUSIVE,
              actual: `HTTP 200，${p.acceptedWithoutEcho} 伪造令牌被接受但响应未回显伪造身份，无法证明令牌来源`,
            };
          }
          if (DENIED_STATUS.has(res.status) || (p.attempts ?? []).every((a) => DENIED_STATUS.has(a.status))) {
            return {
              verdict: VERDICT.BLOCKED,
              actual: `HTTP ${res.status}，伪造令牌被拒绝（尝试：${tried}）`,
            };
          }
          return {
            verdict: VERDICT.INCONCLUSIVE,
            actual: `HTTP ${res.status}，未取得可判定的令牌接受证据（尝试：${tried}）`,
          };
        }
        if (p.hit) {
          return { verdict: VERDICT.REGRESSED, actual: `HTTP ${res.status}，修复后 ${p.alg} 伪造令牌仍被接受` };
        }
        if (DENIED_STATUS.has(res.status)) {
          return { verdict: VERDICT.BLOCKED, actual: `HTTP ${res.status}，伪造令牌被拒绝（尝试：${tried}）` };
        }
        return {
          verdict: VERDICT.INCONCLUSIVE,
          actual: `HTTP ${res.status}，修复后未取得可判定证据（尝试：${tried}）`,
        };
      },
      crossProof: (res) =>
        res._jwtProof?.hit
          ? {
              note: `使用 ${res._jwtProof.alg} 伪造令牌通过认证，响应回显攻击者指定的身份 ${res._jwtProof.marker}：签名校验被绕过`,
            }
          : null,
      impact: (res) =>
        res._jwtProof?.hit
          ? "可伪造任意用户/管理员身份通过认证，越权访问管理接口或冒用他人身份"
          : null,
    });
  }

  // —— 业务逻辑 / 竞态用例：状态跳步 + 并发双花（无自动修复模板，仅取证）——
  const bizCands = planCandidates(ctx, "bizlogic");
  const ownItems = targets.attackerItems ?? [];
  // 状态跳步的判定依据是回读状态，必须走发现阶段用过的按归属列表接口
  const bizListReq = slotRequest(ctx.plan.listEndpoint);
  for (const [i, cand] of bizCands.entries()) {
    const routePath = candPath(cand);
    if (!routePath || !cand.bizlogic || !attacker) continue;
    const suffix = i === 0 ? "" : `-${i + 1}`;

    if (cand.bizlogic.mode === "state") {
      const requiredFrom = cand.bizlogic.requiredFrom;
      const wrong = ownItems.find(
        (o) => o?.status != null && String(o.status).toLowerCase() !== String(requiredFrom).toLowerCase()
      );
      if (!wrong) continue;
      const req = candRequest(ctx, cand, resourceIdOf(ctx, wrong));
      if (!req?.path) continue;
      const method = req.method ?? cand.method ?? "POST";
      const fromStatus = String(wrong.status);
      cases.push({
        id: `attack-state-skip${suffix}`,
        candidateKey: candKey(cand),
        category: CASE_CATEGORY.ATTACK,
        unfixable: true,
        name: `状态跳步（${routePath} · 要求 ${requiredFrom} · 目标 #${resourceIdOf(ctx, wrong)}）`,
        identity: attacker.name,
        method,
        path: req.path,
        routeKey: cand.routeKeys?.[0] ?? null,
        expect: `处于非前置状态（应要求 ${requiredFrom}）的对象调用 ${cand.bizlogic.action} 必须被拒绝（409/403）`,
        send: async (c, baseUrl) => {
          const transition = await httpJson(c, {
            baseUrl,
            method,
            path: req.path,
            body: req.body ?? null,
            graphql: req.graphql ?? null,
            identity: attacker.name,
          });
          let after = null;
          if (bizListReq?.path) {
            try {
              const readRes = await httpJson(c, {
                baseUrl,
                method: bizListReq.method ?? "GET",
                path: bizListReq.path,
                body: bizListReq.body ?? null,
                graphql: bizListReq.graphql ?? null,
                identity: attacker.name,
              });
              const items = extractListItems(readRes.json, listPathFor(ctx, bizListReq.graphql)) ?? [];
              after = items.find((o) => String(resourceIdOf(ctx, o)) === String(resourceIdOf(ctx, wrong))) ?? null;
            } catch {
              after = null;
            }
          }
          transition._bizProof = {
            kind: "state",
            action: cand.bizlogic.action,
            id: resourceIdOf(ctx, wrong),
            from: fromStatus,
            to: after?.status != null ? String(after.status) : null,
            requiredFrom,
            transitionStatus: transition.status,
          };
          return { res: transition, path: req.path, method };
        },
        verify: (res, phase) => {
          const p = res._bizProof ?? {};
          if (REJECTED_STATUS(p.transitionStatus)) {
            return {
              verdict: VERDICT.BLOCKED,
              actual: `HTTP ${p.transitionStatus}，订单 #${p.id} 处于 ${p.from}（应要求 ${p.requiredFrom}），流转被拒绝`,
            };
          }
          if (okStatus(p.transitionStatus) && p.to && p.to !== p.from) {
            return {
              verdict: VERDICT.VULNERABLE,
              actual: `HTTP ${p.transitionStatus}，订单 #${p.id} 原状态 ${p.from}（应要求 ${p.requiredFrom}）被直接置为 ${p.to}：前置状态校验缺失`,
            };
          }
          if (okStatus(p.transitionStatus)) {
            return {
              verdict: VERDICT.INCONCLUSIVE,
              actual: `HTTP ${p.transitionStatus}，但回读状态为 ${p.to ?? "未知"}（原 ${p.from}），未观察到状态跳步`,
            };
          }
          return { verdict: VERDICT.INCONCLUSIVE, actual: `HTTP ${p.transitionStatus ?? "ERR"}，未取得可判定的状态流转证据` };
        },
        crossProof: (res) => {
          const p = res._bizProof ?? {};
          return p.to && p.to !== p.from
            ? { note: `订单 #${p.id} 在 ${p.from} 状态被直接流转为 ${p.to}（要求前置状态 ${p.requiredFrom}）：状态机前置校验被绕过` }
            : null;
        },
        impact: (res) => {
          const p = res._bizProof ?? {};
          return p.to && p.to !== p.from
            ? `可跳过支付/审批等前置状态直接推进业务（如未付款发货、未审核通过），造成资金或履约损失`
            : null;
        },
      });
      continue;
    }

    // mode === "race"：同一一次性动作并发提交
    const raceTarget = ownItems.find((o) => String(o.status ?? "").toLowerCase() === "paid") ?? ownItems[0];
    if (!raceTarget) continue;
    const raceReq = candRequest(ctx, cand, resourceIdOf(ctx, raceTarget));
    if (!raceReq?.path) continue;
    const method = raceReq.method ?? cand.method ?? "POST";
    cases.push({
      id: `attack-race${suffix}`,
      candidateKey: candKey(cand),
      category: CASE_CATEGORY.ATTACK,
      unfixable: true,
      name: `并发双花（${routePath} · ${cand.bizlogic.action} · 目标 #${resourceIdOf(ctx, raceTarget)}）`,
      identity: attacker.name,
      method: raceReq.method ?? method,
      path: raceReq.path,
      routeKey: cand.routeKeys?.[0] ?? null,
      expect: `${cand.bizlogic.action} 属一次性动作：并发提交必须被幂等/锁保护，只允许一次成功`,
      send: async (c, baseUrl) => {
        const results = await Promise.all(
          Array.from({ length: RACE_CONCURRENCY }, () =>
            httpJson(c, {
              baseUrl,
              method: raceReq.method ?? method,
              path: raceReq.path,
              body: raceReq.body ?? null,
              graphql: raceReq.graphql ?? null,
              identity: attacker.name,
            }).catch((e) => ({ status: 0, json: null, error: String(e?.message ?? e).slice(0, 160) }))
          )
        );
        const attempts = results.map((r) => ({ status: r.status, effectId: firstEffectId(r.json) }));
        const effectIds = [...new Set(attempts.map((a) => a.effectId).filter(Boolean))];
        const successes = attempts.filter((a) => okStatus(a.status)).length;
        const chosen = results.find((r) => okStatus(r.status)) ?? results[results.length - 1] ?? { status: 0, json: null };
        chosen._bizProof = {
          kind: "race",
          action: cand.bizlogic.action,
          id: resourceIdOf(ctx, raceTarget),
          total: RACE_CONCURRENCY,
          successes,
          attempts,
          effectIds,
        };
        return { res: chosen, path: raceReq.path, method: raceReq.method ?? method };
      },
      verify: (res, phase) => {
        const p = res._bizProof ?? {};
        const statuses = (p.attempts ?? []).map((a) => a.status || "ERR").join("/");
        if ((p.successes ?? 0) >= 2 && (p.effectIds ?? []).length >= 2) {
          return {
            verdict: VERDICT.VULNERABLE,
            actual: `并发 ${p.total} 次 ${p.action}，${p.successes} 次成功且产生 ${p.effectIds.length} 个不同副作用标识（${p.effectIds.slice(0, 3).join("、")}）：同一操作被重复执行`,
          };
        }
        if ((p.successes ?? 0) >= 2) {
          return {
            verdict: VERDICT.INCONCLUSIVE,
            actual: `并发 ${p.total} 次 ${p.action}，${p.successes} 次返回成功但未取得不同副作用标识，无法证明重复执行`,
          };
        }
        if ((p.successes ?? 0) === 1) {
          return {
            verdict: VERDICT.BLOCKED,
            actual: `并发 ${p.total} 次 ${p.action} 仅 1 次成功（状态：${statuses}）：一次性动作被串行化或幂等保护`,
          };
        }
        if ((p.attempts ?? []).length > 0 && p.attempts.every((a) => REJECTED_STATUS(a.status))) {
          return { verdict: VERDICT.BLOCKED, actual: `并发 ${p.total} 次 ${p.action} 均被拒绝（状态：${statuses}）` };
        }
        return { verdict: VERDICT.INCONCLUSIVE, actual: `并发 ${p.total} 次 ${p.action} 未取得可判定结果（状态：${statuses}）` };
      },
      crossProof: (res) => {
        const p = res._bizProof ?? {};
        return (p.effectIds ?? []).length >= 2
          ? {
              note: `并发 ${p.total} 次请求返回 ${p.effectIds.length} 个不同副作用标识（${p.effectIds.slice(0, 3).join("、")}），一次${p.action}被重复执行`,
            }
          : null;
      },
      impact: (res) => {
        const p = res._bizProof ?? {};
        return (p.effectIds ?? []).length >= 2
          ? "可并发重复执行退款/领取/转账等一次性操作，造成重复退款、优惠券重复使用或余额双花"
          : null;
      },
    });
  }

  // —— SQL 注入用例：随机基线 vs 布尔/报错载荷（无修复模板，仅取证）——
  for (const [i, cand] of planCandidates(ctx, sqliAttack.kind).entries()) {
    const injectionRef = cand[sqliAttack.kind];
    const routePath = candPath(cand);
    if (!routePath || !injectionRef) continue;
    // 参数名取自配方声明的那个计划字段（配方永远写不出参数名字面量）
    const injection = {
      ...injectionRef,
      param: resolvePlanField(sqliAttack.step.param, injectionRef, "sqli-injection", "SQL 注入点"),
    };
    const suffix = i === 0 ? "" : `-${i + 1}`;
    const firstReq = injectionReq(cand, injection, SQLI_PAYLOADS[0]);
    if (!firstReq) continue;
    const injIdentity = sqliActor?.name ?? null;
    cases.push({
      id: `${sqliAttack.step.id}${suffix}`,
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
  const ownerReadCase = (id, ident, ownTarget, step, withContract) => {
    const ownId = resourceIdOf(ctx, ownTarget);
    const req = candRequest(ctx, readCands[0], ownId);
    const entityOf = (res) => extractEntity(res.json, entityPathFor(ctx, readCands[0]?.graphql));
    return {
      id,
      category: CASE_CATEGORY.BUSINESS,
      name: `${ident.name} 读取自己的${label} #${ownId}`,
      identity: ident.name,
      method: req.method ?? step?.method ?? "GET",
      path: req.path,
      body: req.body,
      graphql: req.graphql ?? null,
      routeKey: readKey,
      expect: `本人${label}应正常可见（200，内容不减少：JSON 比字段、页面比正文独有片段）`,
      // 「修复前本人看到什么」的基线：JSON 用字段名，页面用「只在本人页面出现的正文片段」
      // 挂不挂契约看配方有没有声明归属人复读——没有复读，就没有「修复后不许少内容」的对照物
      contract: withContract ? (res) => {
        if (looksHtml(res)) {
          const e = htmlLeakEvidence(ctx, res, ownId);
          return e ? e.hit : [];
        }
        return Object.keys(entityOf(res) ?? {});
      } : null,
      verify: (res) => {
        if (looksHtml(res)) {
          // 修复前阶段还没有「记录下来的契约」——本人可见内容就从这次响应自己取证
          // （发现阶段已按本人会话回读过页面，独有片段是现成的对照）；
          // 修复后阶段一律以修复前记下的契约为准，缺项即判回归。
          const recorded = ctx._ownerContract?.get(id) ?? [];
          const base = recorded.length > 0 ? recorded : (htmlLeakEvidence(ctx, res, ownId)?.hit ?? []);
          const body = pageText(res.body ?? "");
          if (base.length === 0 && okStatus(res.status)) {
            return {
              verdict: VERDICT.INCONCLUSIVE,
              actual: `HTTP ${res.status}，本人${label}页面可读，但没有可比对的独有内容片段（该页正文未在发现阶段回读到，或没有另一身份的页面作对照），无法证明内容未被删减`,
            };
          }
          return verifyBusiness(res, 200, () => {
            const missing = base.filter((k) => !body.includes(k));
            if (missing.length) return `FAIL:本人页面内容契约缺失 ${missing.slice(0, 6).join("、")}（不得删减本人可见内容来冒充修复）`;
            return `本人页面正文 ${body.length} 字，内容契约 ${base.length} 项全部保留`;
          });
        }
        return verifyBusiness(res, 200, () => {
          const o = entityOf(res);
          if (!o) return `FAIL:响应缺少${label}对象`;
          if (String(resourceIdOf(ctx, o)) !== String(ownId)) return `FAIL:返回了错误的${label} #${resourceIdOf(ctx, o)}`;
          if (ownerOf(ctx, o) !== ident.user?.id) return `FAIL:${label}归属异常 ${ownerOf(ctx, o)}`;
          const base = ctx._ownerContract?.get(id) ?? [];
          const missing = base.filter((k) => !(k in o));
          if (missing.length) return `FAIL:字段契约缺失 ${missing.join("、")}（不得删减本人可见内容来冒充修复）`;
          return `返回${label} #${resourceIdOf(ctx, o)}，归属 ${ownerOf(ctx, o)}，字段 ${Object.keys(o).length} 项`;
        });
      },
    };
  };

  // 本人可见正向断言：哪几个身份各读自己名下的哪个对象，来自配方（idor-read-owner-visible）。
  // 受害人侧那条是补丁「按身份写死放行名单」这类写坏方式的探针。
  const visibleSteps = requestSteps(visibleRecipe);
  const visibleReadback = ownershipReadbacks(visibleRecipe).some((s) => s.uses === visibleSteps[0]?.id);
  for (const step of visibleSteps) {
    const role = identityRole(step);
    const ident = resolveRole(targets, role);
    const ownTarget = ownTargetFor(targets, role);
    if (!readPath || !ident || !ownTarget) continue;
    cases.push(ownerReadCase(step.id, ident, ownTarget, step, visibleReadback));
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
          const foreign = arr.filter((o) => ownerOf(ctx, o) !== attacker.user?.id);
          if (foreign.length > 0) return `FAIL:列表泄露他人${label} ${foreign.map((o) => o.id).join(",")}`;
          return `共 ${arr.length} 条，全部归属 ${attacker.user?.id}`;
        }),
    });
  }

  if (cancelPath && targets.ownCancelTarget && attacker) {
    const c = targets.ownCancelTarget;
    const ownCancelReq = candRequest(ctx, cancelCands[0], resourceIdOf(ctx, c));
    cases.push({
      id: "business-cancel-own",
      category: CASE_CATEGORY.BUSINESS,
      name: `${attacker.name} 取消自己的${label} #${resourceIdOf(ctx, c)}`,
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
    const shippedReq = candRequest(ctx, cancelCands[0], resourceIdOf(ctx, s));
    cases.push({
      id: "business-shipped-guard",
      category: CASE_CATEGORY.BUSINESS,
      name: `${attacker.name} 取消已发货${label} #${resourceIdOf(ctx, s)} 被业务规则拒绝`,
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
          const owners = new Set(arr.map((o) => ownerOf(ctx, o) ?? o.id));
          if (owners.size < 2) return `FAIL:仅见单一归属（${[...owners].join(",")}）`;
          return `可见 ${arr.length} 条，覆盖 ${owners.size} 个归属`;
        }),
    });
  }

  if (adminCancelPath && admin && targets.adminCancelTarget) {
    const adminTarget = targets.adminCancelTarget;
    const adminCancelReq = candRequest(ctx, ctx.plan.adminCancelEndpoint, resourceIdOf(ctx, adminTarget));
    cases.push({
      id: "business-admin-cancel",
      category: CASE_CATEGORY.BUSINESS,
      name: `管理员代取消 ${victim.name} 的${label} #${resourceIdOf(ctx, adminTarget)}`,
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
          return `${label} #${o.id}（归属 ${ownerOf(ctx, o)}）已由管理员取消`;
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

  // 匿名回读本人对象应被 401 拒绝：这一条与配方无关，它验的是认证入口本身
  const own = targets.ownReadTarget;
  if (readPath && own) {
    const anonReq = candRequest(ctx, readCands[0], resourceIdOf(ctx, own));
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
        // 页面应用的「未登录即拒」写成 302 → 登录页：跟随跳转后是 200 的登录表单。
        // 只按状态码判会把这种正常拒绝写成「认证被绕过」的假回归；
        // 但仍要求响应里没有本人页面的独有内容——真有内容就是放行，照旧判回归。
        if (looksHtml(res) && rendersLoginForm(res)) {
          const e = htmlLeakEvidence(ctx, res, resourceIdOf(ctx, own));
          if (!e?.leaked) {
            return {
              verdict: VERDICT.PASSED,
              actual: `HTTP ${res.status} + 登录页（未登录被重定向回登录表单），认证拦截生效，响应内未见详情内容片段`,
            };
          }
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

/**
 * 静态/契约来源地址的实测证伪闸门。LLM 路由一直有「打不通就丢弃」这一关，
 * 从源码推断出的 fullPath 却没有：挂载前缀拼错时整轮请求全落在 404 上，
 * 仍能走到「未复现 → 放行」。这里补齐对称性——本轮发出的每个请求都与
 * 「绝对不存在的路径」同形时，判为未触及目标（inconclusive / exit 2）。
 * 零额外成本：先只看已收集的状态码，全部不存在形态才补发那一次基线请求。
 */
async function assertTargetTouched(ctx, { baseUrl, evidence, phase }) {
  if (phase !== "pre" || evidence.length === 0) return;
  // 先只看已收集的状态码，全部不存在形态才补发那一次基线请求（正常轮次零额外成本）
  if (!evidence.every((e) => isAbsentStatus(e.response?.status))) return;

  let baseline = null;
  try {
    baseline = await httpJson(ctx, { baseUrl, method: "GET", path: ABSENT_PROBE_PATH, identity: null });
  } catch {
    baseline = null;
  }
  const verdict = allRequestsMissed(
    evidence.map((e) => ({ method: e.method, path: e.endpoint, status: e.response?.status, body: e.response?.body })),
    baseline
  );
  if (!verdict.missed) return;

  ctx.routeExistence = {
    touched: false,
    total: evidence.length,
    statuses: verdict.statuses,
    baselineStatus: baseline?.status ?? null,
    attempted: verdict.attempted,
  };
  ctx.emit({
    kind: "discovery",
    severity: SEVERITY.WARN,
    message: `本轮 ${evidence.length} 个请求全部落在「路由不存在」形态（与不存在路径基线 ${ABSENT_PROBE_PATH} 同形），未触及目标接口`,
    phase,
    data: { attempted: verdict.attempted.slice(0, 12), statuses: verdict.statuses, baselineStatus: baseline?.status ?? null },
  });
  throw new ProbeError(
    `全部 ${evidence.length} 条用例打到的地址在目标上都不存在（HTTP ${verdict.statuses.join("/")}，与不存在路径基线同形），无法证明目标安全`,
    {
      code: "static_routes_unverified",
      hint: `静态推断的请求路径与目标实际接口不符是最常见原因（如挂载前缀被重复拼接）。本轮尝试的地址：${verdict.attempted.slice(0, 6).join("；")}。请在 guardbuild.json 用 routes / openapi.file 声明真实接口，或校正路由声明与挂载点的对应关系后重跑；本轮没有打到目标，不能据此判定安全`,
      details: { attempted: verdict.attempted, statuses: verdict.statuses, baselineStatus: baseline?.status ?? null, total: evidence.length },
    }
  );
}

export async function runPhase(ctx, { phase, baseUrl }) {
  ctx._lastDecisionSeq = 0;
  ctx._probePhase = phase;
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
  // #183 契约没写 register.seed 时，观测式兜底先给新建账号造出名下对象：
  // 列表契约的双身份实测要求「各自名下有对象」，这一层补的就是那个前提，
  // 所以它必须跑在资源发现之前，造完再由发现层实测决定列表端点与主键。
  await observeSeedWrites(ctx, { baseUrl, byUser: {}, loggedIn });
  let { byUser, anonymousItems, anonTargets } = await discoverResources(ctx, baseUrl, loggedIn);
  ctx._resourceById = indexResources(ctx, byUser, anonymousItems);
  // LLM 侦察线索只有在真实实例上打通过才算攻击面；丢弃的路由会让计划重建，
  // 列表端点被换掉时必须按新计划重新发现资源，否则后续用例拿的是过期归属数据。
  if (phase === "pre" && hasScoutCandidates(ctx)) {
    await verifyScoutTargets(ctx, { baseUrl, loggedIn, byUser });
    if (ctx._scoutPlanRebuilt && ctx._scoutListChanged) {
      const again = await discoverResources(ctx, baseUrl, loggedIn);
      byUser = again.byUser;
      anonymousItems = again.anonymousItems;
      anonTargets = again.anonTargets;
      ctx._resourceById = indexResources(ctx, byUser, anonymousItems);
    }
  }
  // 多段路径（/orgs/:orgId/orders/:orderId）的取值来源：静态没声明时用本人列表里的真实对象实测绑定，
  // 绑上的候选才进入读候选槽位；绑不上就如实拒掉，绝不猜。
  await resolveDerivedBindings(ctx, { baseUrl, byUser, loggedIn, phase });
  const targets = pickTargets(ctx, byUser, loggedIn, anonymousItems, anonTargets);
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
  // 路径穿越会把不存在的路径打到文件读取接口，SSRF 会让目标主动发起外部请求；
  // 个别实现会同步阻塞事件循环。排在最后，避免一条挂起的用例拖掉整轮注入取证。
  // 注入/穿越两族的用例前缀与候选种类都取自配方声明：改 id 时排序与「计划有候选却没建用例」的
  // 诊断跟着走，不会静默失配（失配的表现是挂起用例排到最前、或整族被当成「没测到」）
  const travBaseline = baselineStep("path-traversal", "fs.traverse");
  const sqliBaseline = baselineStep("sqli-injection", "payload.inject");
  const isSlow = (c) =>
    c.category === CASE_CATEGORY.ATTACK &&
    (c.id.startsWith(travBaseline.step.id) ||
      c.id.startsWith("attack-ssrf") ||
      c.id.startsWith("attack-upload") ||
      c.id.startsWith("attack-jwt-forge") ||
      c.id.startsWith("attack-state-skip") ||
      c.id.startsWith("attack-race"));
  const orderedCases = [...allCases.filter((c) => !isSlow(c)), ...allCases.filter(isSlow)];
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
      message: `修复后验收跳过 ${skippedUnfixable.length} 条无自动修复模板的攻击用例（注入/穿越/SSRF/上传/JWT/业务逻辑类仅取证）`,
      phase,
      data: { skipped: skippedUnfixable.map((c) => c.id) },
    });
  }

  const plannedSlots = [
    { slot: "readCandidate", prefix: "attack-read-foreign", count: planCandidates(ctx, "read").length },
    { slot: "cancelCandidate", prefix: "attack-cancel-foreign", count: planCandidates(ctx, "cancel").length },
    { slot: "unauthReadCandidate", prefix: "attack-anonymous-read", count: planCandidates(ctx, "unauthRead").length },
    { slot: "traversalCandidate", prefix: travBaseline.step.id, count: planCandidates(ctx, travBaseline.kind).length },
    { slot: "sqliCandidate", prefix: sqliBaseline.step.id, count: planCandidates(ctx, sqliBaseline.kind).length },
    { slot: "cmdiCandidate", prefix: "attack-command-injection", count: planCandidates(ctx, "cmdi").length },
    { slot: "ssrfCandidate", prefix: "attack-ssrf", count: planCandidates(ctx, "ssrf").length },
    { slot: "uploadCandidate", prefix: "attack-upload", count: planCandidates(ctx, "upload").length },
    { slot: "jwtCandidate", prefix: "attack-jwt-forge", count: planCandidates(ctx, "jwt").length },
    { slot: "bizlogicCandidate", prefix: "attack-state-skip", count: planCandidates(ctx, "bizlogic").filter((c) => c.bizlogic?.mode === "state").length },
    { slot: "bizlogicCandidate", prefix: "attack-race", count: planCandidates(ctx, "bizlogic").filter((c) => c.bizlogic?.mode === "race").length },
  ].filter((s) => s.count > 0);
  const skipped = plannedSlots.filter(
    (s) => !allCases.some((c) => c.id === s.prefix || c.id.startsWith(`${s.prefix}-`))
  );
  if (skipped.length > 0) {
    // 计划里有候选、却因身份/资源/契约不足一条用例都构不出来：这是「没测到」，
    // 不是「测过没复现」。pre 阶段记下来，由 main 判为 inconclusive（exit 2）。
    if (phase === "pre") ctx._unverifiedSlots = skipped.map((s) => s.slot);
    ctx.emit({
      kind: "discovery",
      severity: SEVERITY.WARN,
      message: `计划中有 ${skipped.length} 类攻击用例因身份/资源不足被跳过：${skipped.map((s) => s.slot).join("、")}`,
      data: { skipped },
    });
  } else if (phase === "pre") {
    ctx._unverifiedSlots = [];
  }

  const attackSlots = cases.filter((c) => c.category === CASE_CATEGORY.ATTACK);
  if (attackSlots.length === 0) {
    // 一个攻击用例都没构造出来＝没有向目标发出越权请求，覆盖未建立（不是「测过没复现」）。
    // 把槽位实测数放进错误详情，报告才能区分「缺数据」与「缺契约」，用户才知道下一步补什么。
    throw new ProbeError(
      `未能构建任何攻击用例（身份或资源发现不足；有候选的槽位：${
        plannedSlots.length ? plannedSlots.map((s) => `${s.slot}×${s.count}`).join("、") : "无"
      }）`,
      {
        code: "no_attack_cases",
        hint: "攻击用例需要：至少一个普通用户身份 + 可填充的对象资源（来自列表接口或匿名探测），请检查 guardbuild.json 的身份配置与目标项目的资源可发现性",
        details: {
          plannedSlots,
          skippedSlots: skipped.map((s) => s.slot),
          casesBuilt: cases.length,
          identities: ctx.identities.map((i) => i.name),
        },
      }
    );
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

  // 全部请求都落在不存在的地址上＝本轮没打到目标，不能进「未复现 → 放行」
  await assertTargetTouched(ctx, { baseUrl, evidence, phase });

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
