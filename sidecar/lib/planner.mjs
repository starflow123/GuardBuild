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

/** 由静态分析结果构建探测计划 */
export function buildProbePlan(analysis) {
  const eps = analysis.endpoints;
  const candidates = analysis.candidates;

  const login =
    eps.find((e) => e.method === "POST" && (e.path ?? "").toLowerCase().includes("login")) ??
    { path: "/api/login", method: "POST" };

  const cancelCandidate = candidates.find((c) => c.method === "POST" && (c.path ?? "").endsWith("/cancel"));
  const readCandidate = candidates.find((c) => c.method === "GET" && (c.path ?? "").includes(":id"));

  const list =
    eps.find(
      (e) => e.method === "GET" && e.path && !e.path.includes(":id") && e.hasOwnerFilter && !/admin/i.test(e.path)
    ) ?? null;

  const adminList = eps.find((e) => e.method === "GET" && /admin/i.test(e.path ?? "") && e.hasRoleGuard) ?? null;
  const adminCancel =
    eps.find((e) => e.method === "POST" && /admin/i.test(e.path ?? "") && (e.path ?? "").endsWith("/cancel")) ?? null;

  const resource = readCandidate?.resource ?? cancelCandidate?.resource ?? "resource";

  return {
    loginPath: login.path,
    resource,
    readCandidate: readCandidate ?? null,
    cancelCandidate: cancelCandidate ?? null,
    listEndpoint: list ? { path: list.path, routeKey: list.routeKeys?.[0] ?? null } : null,
    adminListEndpoint: adminList ? { path: adminList.path, routeKey: adminList.routeKeys?.[0] ?? null } : null,
    adminCancelEndpoint: adminCancel ? { path: adminCancel.path, routeKey: adminCancel.routeKeys?.[0] ?? null } : null,
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
