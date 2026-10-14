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

/** 所有身份登录（凭证直接存入 Host 保险库，不流经 Sidecar） */
export async function loginAll(ctx, baseUrl) {
  const loggedIn = [];
  for (const ident of ctx.identities) {
    const res = await httpJson(ctx, {
      baseUrl,
      method: "POST",
      path: ctx.plan.loginPath,
      body: JSON.stringify({ username: ident.username, password: ident.password }),
      storeAs: ident.name,
      credentialPath: "token",
      credentialPrefix: "Bearer ",
    });
    if (res.status !== 200 || res.storedIdentity !== ident.name) {
      throw new ProbeError(`身份「${ident.name}」登录失败（HTTP ${res.status}）`, {
        code: "login_failed",
        hint: `请确认目标服务在 ${baseUrl} 运行，且登录接口 ${ctx.plan.loginPath} 接受提供的账号`,
      });
    }
    ctx.emit({
      kind: "identity",
      severity: SEVERITY.INFO,
      message: `身份「${ident.name}」登录成功，令牌已存入 Host 保险库（响应中的 token 对 Sidecar 显示为 ***）`,
      data: { identity: ident.name, user: res.json?.user ?? null, stored: true },
    });
    loggedIn.push({ ...ident, user: res.json?.user ?? null });
  }
  return loggedIn;
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
    const items = Array.isArray(res.json?.orders) ? res.json.orders : Array.isArray(res.json) ? res.json : [];
    byUser[ident.name] = items;
    ctx.emit({
      kind: "discovery",
      severity: SEVERITY.INFO,
      message: `资源发现：「${ident.name}」名下可见 ${items.length} 个${ctx.plan.resource === "order" ? "订单" : ctx.plan.resource}`,
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

function fillId(path, id) {
  return path.replace(":id", String(id));
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
function buildCases(ctx, targets) {
  const readPath = ctx.plan.readCandidate?.path ?? "/api/orders/:id";
  const cancelPath = ctx.plan.cancelCandidate?.path ?? "/api/orders/:id/cancel";
  const adminListPath = ctx.plan.adminListEndpoint?.path ?? "/api/admin/orders";
  const adminCancelPath = ctx.plan.adminCancelEndpoint?.path ?? "/api/admin/orders/:id/cancel";
  const readKey = ctx.plan.readCandidate?.routeKeys?.[0] ?? "orders.get";
  const cancelKey = ctx.plan.cancelCandidate?.routeKeys?.[0] ?? "orders.cancel";
  const listPath = ctx.plan.listEndpoint?.path ?? "/api/orders";
  const { attacker, victim } = targets;

  const cases = [];

  // —— 攻击用例 ——
  const readTarget = targets.readTarget;
  cases.push({
    id: "attack-read-foreign",
    category: CASE_CATEGORY.ATTACK,
    name: `${attacker.name} 读取 ${victim.name} 的订单 #${readTarget.id}`,
    identity: attacker.name,
    method: "GET",
    path: fillId(readPath, readTarget.id),
    routeKey: readKey,
    expect: "越权读取他人订单应被拒绝（401/403/404）",
    verify: (res, phase) => {
      const o = res.json?.order;
      const leaked = o && o.id === readTarget.id;
      const detail = leaked
        ? `证据：返回订单 #${o.id}（归属 ${o.userId}，金额 ${o.amount}，状态 ${o.status}）`
        : "";
      return verifyAttack(res, phase, detail);
    },
    impact: (res) => (okStatus(res.status) ? `可读取他人订单详情及字段（id/userId/amount/address 等）` : null),
  });

  const cancelTarget = targets.attackCancelTarget;
  cases.push({
    id: "attack-cancel-foreign",
    category: CASE_CATEGORY.ATTACK,
    name: `${attacker.name} 取消 ${victim.name} 的订单 #${cancelTarget.id}`,
    identity: attacker.name,
    method: "POST",
    path: fillId(cancelPath, cancelTarget.id),
    routeKey: cancelKey,
    expect: "越权取消他人订单应被拒绝（401/403/404）",
    verify: (res, phase) => {
      const o = res.json?.order;
      const changed = o && o.status === "cancelled" && o.userId === victim.user?.id;
      const detail = changed ? `证据：订单 #${o.id}（归属 ${o.userId}）状态已被改为 cancelled` : "";
      return verifyAttack(res, phase, detail);
    },
    impact: (res) => {
      const o = res.json?.order;
      return o && o.status === "cancelled" ? `可越权取消他人订单（业务破坏）` : null;
    },
  });

  // —— 业务用例（回归防线）——
  const own = targets.ownReadTarget;
  cases.push({
    id: "business-read-own",
    category: CASE_CATEGORY.BUSINESS,
    name: `${attacker.name} 读取自己的订单 #${own.id}`,
    identity: attacker.name,
    method: "GET",
    path: fillId(readPath, own.id),
    routeKey: readKey,
    expect: "本人订单应正常可见（200，且归属本人）",
    verify: (res) =>
      verifyBusiness(res, 200, () => {
        const o = res.json?.order;
        if (!o) return "FAIL:响应缺少 order 字段";
        if (o.id !== own.id) return `FAIL:返回了错误的订单 #${o.id}`;
        if (o.userId !== attacker.user?.id) return `FAIL:订单归属异常 ${o.userId}`;
        return `返回订单 #${o.id}，归属 ${o.userId}`;
      }),
  });

  cases.push({
    id: "business-list-own",
    category: CASE_CATEGORY.BUSINESS,
    name: `${attacker.name} 查询订单列表仅见本人订单`,
    identity: attacker.name,
    method: "GET",
    path: listPath,
    routeKey: ctx.plan.listEndpoint?.routeKey ?? "orders.list",
    expect: "列表应只包含本人订单（owner-filter 保持有效）",
    verify: (res) =>
      verifyBusiness(res, 200, () => {
        const arr = Array.isArray(res.json?.orders) ? res.json.orders : null;
        if (!arr) return "FAIL:响应缺少 orders 数组";
        const foreign = arr.filter((o) => o.userId !== attacker.user?.id);
        if (foreign.length > 0) return `FAIL:列表泄露他人订单 ${foreign.map((o) => o.id).join(",")}`;
        return `共 ${arr.length} 条，全部归属 ${attacker.user?.id}`;
      }),
  });

  if (targets.ownCancelTarget) {
    const c = targets.ownCancelTarget;
    cases.push({
      id: "business-cancel-own",
      category: CASE_CATEGORY.BUSINESS,
      name: `${attacker.name} 取消自己的订单 #${c.id}`,
      identity: attacker.name,
      method: "POST",
      path: fillId(cancelPath, c.id),
      routeKey: cancelKey,
      expect: "本人已支付订单应可正常取消（200）",
      verify: (res) =>
        verifyBusiness(res, 200, () => {
          const o = res.json?.order;
          if (!o) return "FAIL:响应缺少 order 字段";
          if (o.status !== "cancelled") return `FAIL:状态未变更（${o.status}）`;
          return `订单 #${o.id} 已置为 cancelled`;
        }),
    });
  }

  if (targets.ownNotCancellable) {
    const s = targets.ownNotCancellable;
    cases.push({
      id: "business-shipped-guard",
      category: CASE_CATEGORY.BUSINESS,
      name: `${attacker.name} 取消已发货订单 #${s.id} 被业务规则拒绝`,
      identity: attacker.name,
      method: "POST",
      path: fillId(cancelPath, s.id),
      routeKey: cancelKey,
      expect: "状态非 paid 的订单不可取消（409），业务规则保持有效",
      verify: (res) =>
        verifyBusiness(res, 409, () => {
          const s2 = res.json?.status;
          return s2 ? `返回当前状态 ${s2}` : "订单状态保护生效";
        }),
    });
  }

  cases.push({
    id: "business-admin-list",
    category: CASE_CATEGORY.BUSINESS,
    name: `管理员查看全部订单`,
    identity: "admin",
    method: "GET",
    path: adminListPath,
    routeKey: ctx.plan.adminListEndpoint?.routeKey ?? "admin.orders.list",
    expect: "管理员应可查看全部订单（200，跨多个归属）",
    verify: (res) =>
      verifyBusiness(res, 200, () => {
        const arr = Array.isArray(res.json?.orders) ? res.json.orders : null;
        if (!arr) return "FAIL:响应缺少 orders 数组";
        const owners = new Set(arr.map((o) => o.userId));
        if (owners.size < 2) return `FAIL:仅见单一归属（${[...owners].join(",")}）`;
        return `可见 ${arr.length} 条，覆盖 ${owners.size} 个归属`;
      }),
  });

  const adminTarget = targets.adminCancelTarget;
  cases.push({
    id: "business-admin-cancel",
    category: CASE_CATEGORY.BUSINESS,
    name: `管理员代取消 ${victim.name} 的订单 #${adminTarget.id}`,
    identity: "admin",
    method: "POST",
    path: fillId(adminCancelPath, adminTarget.id),
    routeKey: ctx.plan.adminCancelEndpoint?.routeKey ?? "admin.orders.cancel",
    expect: "管理员合法代操作应保持可用（200）",
    verify: (res) =>
      verifyBusiness(res, 200, () => {
        const o = res.json?.order;
        if (!o) return "FAIL:响应缺少 order 字段";
        if (o.status !== "cancelled") return `FAIL:状态未变更（${o.status}）`;
        return `订单 #${o.id}（归属 ${o.userId}）已由管理员取消`;
      }),
  });

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

  cases.push({
    id: "business-unauth-401",
    category: CASE_CATEGORY.BUSINESS,
    name: `未登录访问订单详情被拒绝`,
    identity: null,
    method: "GET",
    path: fillId(readPath, own.id),
    routeKey: readKey,
    expect: "未认证请求应被拒绝（401），认证入口保持有效",
    verify: (res) => {
      if (res.status === 401) return { verdict: VERDICT.PASSED, actual: "HTTP 401，认证拦截生效" };
      if (res.status === 403) return { verdict: VERDICT.PASSED, actual: "HTTP 403，认证拦截生效" };
      return { verdict: VERDICT.REGRESSED, actual: `HTTP ${res.status}（预期 401/403），认证被绕过或异常放行` };
    },
  });

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
        decision: decision ? { checks: decision.checks, decision: decision.decision, note: decision.note } : null,
      },
    });
  }

  const counts = { vulnerable: 0, blocked: 0, passed: 0, regressed: 0, inconclusive: 0 };
  for (const e of evidence) counts[e.verdict] = (counts[e.verdict] ?? 0) + 1;

  const attackRecords = evidence.filter((e) => e.caseCategory === CASE_CATEGORY.ATTACK);
  const businessRecords = evidence.filter((e) => e.caseCategory === CASE_CATEGORY.BUSINESS);
  const summary = {
    phase,
    baseUrl,
    counts,
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
