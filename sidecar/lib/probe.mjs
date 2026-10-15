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
function resourceLabel(ctx) {
  const r = ctx.plan?.resource;
  if (r === "order") return "订单";
  return r && r !== "resource" ? r : "资源";
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

/** 通过各身份的列表接口发现资源归属（owner → 对象列表） */
async function discoverResources(ctx, baseUrl, loggedIn) {
  const listPath = ctx.plan.listEndpoint?.path;
  if (!listPath) {
    throw new ProbeError("静态分析未能定位列表接口，无法发现资源归属", {
      code: "no_list_endpoint",
      hint: "当前策略要求目标项目存在按归属过滤的列表接口（如 GET /api/orders）",
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
  return byUser;
}

/** 从发现结果中挑选攻击/业务用例所需的具体对象（loggedIn 携带登录响应中的 user 对象） */
function pickTargets(byUser, loggedIn) {
  const users = loggedIn.filter((i) => i.role !== "admin");
  if (users.length < 2) {
    throw new ProbeError("探测计划需要至少两个普通用户身份", { code: "need_two_users" });
  }
  const attacker = users[0];
  const victim = users[1];
  const attackerOrders = byUser[attacker.name] ?? [];
  const victimOrders = byUser[victim.name] ?? [];
  if (victimOrders.length === 0 || attackerOrders.length === 0) {
    throw new ProbeError("资源发现结果不足：至少需要双方各自可见的对象", { code: "insufficient_resources" });
  }
  const victimPaid = victimOrders.filter((o) => o.status === "paid");
  const attackerPaid = attackerOrders.filter((o) => o.status === "paid");
  const attackerNotCancellable = attackerOrders.find((o) => o.status !== "paid") ?? null;
  return {
    attacker,
    victim,
    readTarget: victimOrders[0],
    attackCancelTarget: victimPaid[0] ?? victimOrders[1] ?? victimOrders[0],
    adminCancelTarget: victimPaid[1] ?? victimPaid[0] ?? victimOrders[0],
    ownReadTarget: attackerOrders[0],
    ownCancelTarget: attackerPaid[1] ?? attackerPaid[0] ?? null,
    ownNotCancellable: attackerNotCancellable,
  };
}

/** 填充路径参数（任意 :param 形态，不限于 :id） */
function fillParams(path, id) {
  return path.replace(/:[A-Za-z_]\w*/g, String(id));
}

const okStatus = (s) => s >= 200 && s < 300;

/** 攻击用例判定：修复前 = 漏洞可利用；修复后 = 攻击被阻断 */
function verifyAttack(res, phase, detail) {
  if (phase === "pre") {
    if (okStatus(res.status)) {
      return { verdict: VERDICT.VULNERABLE, actual: `HTTP ${res.status}，越权请求被放行。${detail ?? ""}` };
    }
    return {
      verdict: VERDICT.INCONCLUSIVE,
      actual: `HTTP ${res.status}，攻击在修复前即无法复现（该端点可能已有防护）`,
    };
  }
  if (DENIED_STATUS.has(res.status)) {
    return { verdict: VERDICT.BLOCKED, actual: `HTTP ${res.status}，越权请求被拒绝。${detail ?? ""}` };
  }
  if (okStatus(res.status)) {
    return { verdict: VERDICT.REGRESSED, actual: `HTTP ${res.status}，修复后攻击仍可成功，补丁无效。${detail ?? ""}` };
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

/** 构建一个阶段内的全部用例（攻击 + 业务），攻击目标对象由发现阶段确定 */
export function buildCases(ctx, targets) {
  const readPath = ctx.plan.readCandidate?.fullPath ?? ctx.plan.readCandidate?.path ?? null;
  const cancelPath = ctx.plan.cancelCandidate?.fullPath ?? ctx.plan.cancelCandidate?.path ?? null;
  const adminListPath = ctx.plan.adminListEndpoint?.path ?? null;
  const adminCancelPath = ctx.plan.adminCancelEndpoint?.path ?? null;
  const listPath = ctx.plan.listEndpoint?.path ?? null;
  const readKey = ctx.plan.readCandidate?.routeKeys?.[0] ?? "orders.get";
  const cancelKey = ctx.plan.cancelCandidate?.routeKeys?.[0] ?? "orders.cancel";
  const { attacker, victim } = targets;
  const label = resourceLabel(ctx);

  const cases = [];

  // —— 攻击用例（仅在计划中存在对应端点时构建，不虚构回退路径）——
  if (readPath) {
    const readTarget = targets.readTarget;
    cases.push({
      id: "attack-read-foreign",
      category: CASE_CATEGORY.ATTACK,
      name: `${attacker.name} 读取 ${victim.name} 的${label} #${readTarget.id}`,
      identity: attacker.name,
      method: "GET",
      path: fillParams(readPath, readTarget.id),
      routeKey: readKey,
      expect: `越权读取他人${label}应被拒绝（401/403/404）`,
      verify: (res, phase) => {
        const o = extractEntity(res.json, ctx.targetConfig?.responses?.entity ?? null);
        const leaked = o && o.id === readTarget.id;
        const detail = leaked
          ? `证据：返回${label} #${o.id}（归属 ${ownerOf(o)}，金额 ${o.amount}，状态 ${o.status}）`
          : "";
        return verifyAttack(res, phase, detail);
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
      impact: (res) => (okStatus(res.status) ? `可读取他人${label}详情及字段（id/userId/amount/address 等）` : null),
    });
  }

  if (cancelPath) {
    const cancelTarget = targets.attackCancelTarget;
    cases.push({
      id: "attack-cancel-foreign",
      category: CASE_CATEGORY.ATTACK,
      name: `${attacker.name} 取消 ${victim.name} 的${label} #${cancelTarget.id}`,
      identity: attacker.name,
      method: "POST",
      path: fillParams(cancelPath, cancelTarget.id),
      routeKey: cancelKey,
      expect: `越权取消他人${label}应被拒绝（401/403/404）`,
      verify: (res, phase) => {
        const o = extractEntity(res.json, ctx.targetConfig?.responses?.entity ?? null);
        const changed = o && o.status === "cancelled" && ownerOf(o) === victim.user?.id;
        const detail = changed ? `证据：${label} #${o.id}（归属 ${ownerOf(o)}）状态已被改为 cancelled` : "";
        return verifyAttack(res, phase, detail);
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
        return o && o.status === "cancelled" ? `可越权取消他人${label}（业务破坏）` : null;
      },
    });
  }

  // —— 业务用例（回归防线）——
  const own = targets.ownReadTarget;
  if (readPath) {
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

  if (listPath) {
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

  if (cancelPath && targets.ownCancelTarget) {
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

  if (cancelPath && targets.ownNotCancellable) {
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

  if (adminListPath) {
    cases.push({
      id: "business-admin-list",
      category: CASE_CATEGORY.BUSINESS,
      name: `管理员查看全部${label}`,
      identity: "admin",
      method: "GET",
      path: adminListPath,
      routeKey: ctx.plan.adminListEndpoint?.routeKey ?? "admin.orders.list",
      expect: `管理员应可查看全部${label}（200，跨多个归属）`,
      verify: (res) =>
        verifyBusiness(res, 200, () => {
          const arr = extractListItems(res.json, ctx.targetConfig?.responses?.list ?? null);
          if (!arr) return `FAIL:响应中未找到${label}列表`;
          const owners = new Set(arr.map((o) => ownerOf(o)));
          if (owners.size < 2) return `FAIL:仅见单一归属（${[...owners].join(",")}）`;
          return `可见 ${arr.length} 条，覆盖 ${owners.size} 个归属`;
        }),
    });
  }

  if (adminCancelPath) {
    const adminTarget = targets.adminCancelTarget;
    cases.push({
      id: "business-admin-cancel",
      category: CASE_CATEGORY.BUSINESS,
      name: `管理员代取消 ${victim.name} 的${label} #${adminTarget.id}`,
      identity: "admin",
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

  if (adminListPath) {
    cases.push({
      id: "business-nonadmin-denied",
      category: CASE_CATEGORY.BUSINESS,
      name: `${victim.name}（普通用户）访问管理端被拒绝`,
      identity: victim.name,
      method: "GET",
      path: adminListPath,
      routeKey: ctx.plan.adminListEndpoint?.routeKey ?? "admin.orders.list",
      expect: "普通用户访问管理端应被拒绝（403），角色校验保持有效",
      verify: (res) => verifyBusiness(res, 403, () => "角色校验（role:admin）生效"),
    });
  }

  if (readPath) {
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
  const byUser = await discoverResources(ctx, baseUrl, loggedIn);
  const targets = pickTargets(byUser, loggedIn);
  const cases = buildCases(ctx, targets);

  const evidence = [];
  for (const kase of cases) {
    const res = await httpJson(ctx, {
      baseUrl,
      method: kase.method,
      path: kase.path,
      identity: kase.identity,
      body: kase.body ?? null,
    });
    const fresh = await fetchNewDecisions(ctx, baseUrl);
    const decision = matchDecision(fresh, kase);
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
      method: kase.method,
      endpoint: kase.path,
      request: {
        url: `${baseUrl.replace(/\/+$/, "")}${kase.path}`,
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
      attacker: targets.attacker.name,
      victim: targets.victim.name,
      readTarget: targets.readTarget.id,
      cancelTarget: targets.attackCancelTarget.id,
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
