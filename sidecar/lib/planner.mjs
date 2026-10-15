/**
 * 规划器（决策层）：把静态分析产物转化为
 *  1) 探测计划（身份 × 资源矩阵）——动态复现
 *  2) 修复策略（最小权限补丁的生成模板）——隔离修复
 *
 * 该模块是「模型决策」的默认规则实现；接入 LLM 时替换本文件的决策函数即可，
 * 其输出必须仍为同样结构的计划/补丁操作，由执行层（Host）照常校验与执行。
 */
import { SCOPE_KINDS } from "../../shared/protocol.mjs";

export const DEFAULT_IDENTITIES = [
  { name: "alice", username: "alice", password: "alice123", role: "user" },
  { name: "bob", username: "bob", password: "bob123", role: "user" },
  { name: "admin", username: "admin", password: "admin123", role: "admin" },
];

/** 每类候选参与动态探测的上限（top-K，避免候选泛滥时探测膨胀） */
export const PROBE_TOP_K = 3;

export function loadIdentities() {
  const raw = process.env.GUARDBUILD_IDENTITIES;
  if (!raw) return DEFAULT_IDENTITIES;
  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed) && parsed.length >= 2) return parsed;
  } catch {
    /* 使用默认 */
  }
  return DEFAULT_IDENTITIES;
}

/** 端点请求路径：有挂载前缀时用 fullPath（完整 URL），否则退回声明路径 */
function epPath(e) {
  return e.fullPath ?? e.path ?? null;
}

/** 路径中的 :参数 个数（用于识别「按 ID 取单体资源」的路由，不绑定 :id 命名） */
function paramCount(p) {
  return String(p ?? "").match(/:[A-Za-z_]\w*/g)?.length ?? 0;
}

/** 由静态分析结果构建探测计划；loginPathOverride 来自契约（优先级最高） */
export function buildProbePlan(analysis, { loginPathOverride = null } = {}) {
  const eps = analysis.endpoints;
  const candidates = analysis.candidates;

  const analysisLogin = eps.find(
    (e) => e.method === "POST" && (epPath(e) ?? "").toLowerCase().includes("login")
  );
  const loginCandidates = [];
  const pushLogin = (p) => {
    if (typeof p === "string" && p && !loginCandidates.includes(p)) loginCandidates.push(p);
  };
  pushLogin(loginPathOverride);
  if (analysisLogin) pushLogin(epPath(analysisLogin));
  pushLogin("/api/login");

  // 每类取 top-K 候选逐一探测；单槽位（首元素）保留既有语义与消费方兼容
  const topK = (pred, k = PROBE_TOP_K) => {
    const seen = new Set();
    const out = [];
    for (const c of candidates) {
      if (!pred(c)) continue;
      const key = `${c.method} ${epPath(c)}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(c);
      if (out.length >= k) break;
    }
    return out;
  };
  const cancelCandidates = topK(
    (c) => c.kind === "idor-suspect" && c.method === "POST" && (epPath(c) ?? "").endsWith("/cancel")
  );
  const readCandidates = topK(
    (c) => c.kind === "idor-suspect" && c.method === "GET" && paramCount(epPath(c)) === 1
  );
  // 无鉴权候选：匿名读取用例的靶点（与 IDOR 槽位互斥，不做自动修复）
  const unauthReadCandidates = topK(
    (c) => c.kind === "no-auth-suspect" && c.method === "GET" && paramCount(epPath(c)) === 1
  );
  const cancelCandidate = cancelCandidates[0] ?? null;
  const readCandidate = readCandidates[0] ?? null;
  const unauthReadCandidate = unauthReadCandidates[0] ?? null;

  const resource =
    readCandidate?.resource ?? cancelCandidate?.resource ?? unauthReadCandidate?.resource ?? "resource";

  // 列表/管理端点优先选择与资源名匹配的路径（避免把别的资源列表当作探测目标）
  const byResource = (list) =>
    list.find((e) => epPath(e).toLowerCase().includes(resource.toLowerCase())) ?? list[0] ?? null;
  const listFields = eps.filter(
    (e) =>
      e.method === "GET" &&
      epPath(e) &&
      paramCount(epPath(e)) === 0 &&
      e.hasOwnerFilter &&
      !/admin/i.test(epPath(e))
  );
  const list = byResource(listFields);
  const adminFields = eps.filter((e) => e.method === "GET" && /admin/i.test(epPath(e) ?? "") && e.hasRoleGuard);
  const adminCancelFields = eps.filter(
    (e) => e.method === "POST" && /admin/i.test(epPath(e) ?? "") && (epPath(e) ?? "").endsWith("/cancel")
  );
  const adminList = byResource(adminFields);
  const adminCancel = byResource(adminCancelFields);

  return {
    loginPath: loginCandidates[0],
    loginCandidates,
    resource,
    readCandidate,
    cancelCandidate,
    unauthReadCandidate,
    readCandidates,
    cancelCandidates,
    unauthReadCandidates,
    listEndpoint: list ? { path: epPath(list), routeKey: list.routeKeys?.[0] ?? null } : null,
    adminListEndpoint: adminList ? { path: epPath(adminList), routeKey: adminList.routeKeys?.[0] ?? null } : null,
    adminCancelEndpoint: adminCancel ? { path: epPath(adminCancel), routeKey: adminCancel.routeKeys?.[0] ?? null } : null,
    candidates,
  };
}

/** 补丁锚点辅助：定位 recordDecision 调用块（含 routeKey 且决策为 no-check 的那次调用） */
export function findRecordDecisionBlock(content, routeKey) {
  const keyToken = `routeKey: "${routeKey}"`;
  let from = 0;
  while (true) {
    const keyIdx = content.indexOf(keyToken, from);
    if (keyIdx === -1) return null;
    from = keyIdx + keyToken.length;
    const start = content.lastIndexOf("recordDecision({", keyIdx);
    if (start === -1) continue;
    const endMarker = content.indexOf("});", keyIdx);
    if (endMarker === -1) continue;
    const block = content.slice(start, endMarker + 3);
    if (block.includes('decision: "no-check"')) return { block, start, end: endMarker + 3 };
  }
}

function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function resourceLabel(resource) {
  const map = { order: "订单", user: "用户", account: "账户", payment: "支付单", invoice: "发票", file: "文件" };
  return map[resource] ?? resource;
}

function deriveRouteKey(cand) {
  if (cand.routeKeys?.length) return cand.routeKeys[0];
  const seg = (cand.path ?? "").split("/").filter(Boolean);
  const last = seg.pop() ?? "resource";
  const action = last === ":id" ? "get" : last;
  return `${seg[seg.length - 1] ?? "api"}.${action}`;
}

/**
 * 策略 1：在资源获取语句之后注入归属校验（适配手写 if(method===...) 路由）。
 * 返回 [{find, replace, count}]，由 Host 在真实文件字节上执行替换。
 */
export function methodStyleOps(content, cand) {
  const matchVar = cand.matchVars?.[0];
  if (!matchVar) throw new Error(`路由 ${cand.path} 未找到 Match 变量，无法定位锚点`);
  const eol = content.includes("\r\n") ? "\r\n" : "\n";
  const re = new RegExp(
    `(\\r?\\n([ \\t]*)const \\w+ = Number\\(${escapeRe(matchVar)}\\[1\\]\\);[ \\t]*)(\\r?\\n[ \\t]*const (\\w+) = [\\w$]+\\([^)]*\\);[ \\t]*)`
  );
  const m = content.match(re);
  if (!m) throw new Error(`锚点未匹配（${cand.file} · ${cand.routeKey ?? cand.path}）`);
  const indent = m[2];
  const varName = m[4];
  const routeKey = deriveRouteKey(cand);
  const label = resourceLabel(cand.resource);

  const guard = [
    "",
    `${indent}if (${varName} && ${varName}.userId !== auth.user.id) {`,
    `${indent}  recordDecision({`,
    `${indent}    method, path: pathname, routeKey: "${routeKey}",`,
    `${indent}    requesterId: auth.user.id, requesterRole: auth.user.role,`,
    `${indent}    resourceOwner: ${varName}.userId,`,
    `${indent}    checks: ["authenticated", "${cand.resource}-owner"], decision: "deny",`,
    `${indent}    note: "${label}归属校验未通过，拒绝访问",`,
    `${indent}  });`,
    `${indent}  return json(res, 403, { error: "无权访问该${label}" });`,
    `${indent}}`,
  ].join(eol);

  const anchor = m[1] + m[3];
  const ops = [{ find: anchor, replace: anchor + eol + guard, count: 1 }];

  // 更新 allow 分支的决策记录：no-check → owner 校验通过
  const blockInfo = findRecordDecisionBlock(content, routeKey);
  if (blockInfo) {
    const fixed = blockInfo.block
      .replace(
        /checks:\s*\[[^\]]*\]\s*,\s*decision:\s*"no-check"\s*,/,
        `checks: ["authenticated", "${cand.resource}-owner"], decision: "allow",`
      )
      .replace(/note:\s*"[^"]*"/, `note: "${label}归属校验通过"`);
    if (fixed !== blockInfo.block) {
      ops.push({ find: blockInfo.block, replace: fixed, count: 1 });
    }
  }
  return ops;
}

/**
 * 策略 2：Express 风格处理器——findById/findOne 之后注入归属校验。
 */
export function expressStyleOps(content, cand) {
  const eol = content.includes("\r\n") ? "\r\n" : "\n";
  const re =
    /(\r?\n([ \t]*)(?:const|let)\s+(\w+)\s*=\s*(?:await\s+)?[\w$.]+\.(?:findById|findByPk|findOne|findUnique)\([^)]*\);[ \t]*)/;
  const m = content.match(re);
  if (!m) throw new Error(`锚点未匹配（${cand.file} · ${cand.path}）`);
  const indent = m[2];
  const varName = m[3];
  const label = resourceLabel(cand.resource);
  const guard = [
    "",
    `${indent}if (${varName} && ${varName}.userId !== req.user.id) {`,
    `${indent}  return res.status(403).json({ error: "无权访问该${label}" });`,
    `${indent}}`,
  ].join(eol);
  const anchor = m[1];
  return [{ find: anchor, replace: anchor + eol + guard, count: 1 }];
}

export const FIX_STRATEGIES = [
  { name: "owner-guard-after-fetch", styles: ["method"], builder: methodStyleOps, desc: "资源获取后注入归属校验（手写路由）" },
  { name: "express-owner-guard", styles: ["express"], builder: expressStyleOps, desc: "findById 后注入归属校验（Express）" },
];

export function scopeRequestFor(kind) {
  return kind; // 与 shared/protocol.mjs 的 SCOPE_KINDS 对齐
}

export { SCOPE_KINDS };
