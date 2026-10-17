/**
 * tRPC 适配器：createTRPCRouter / t.router 路由树静态解析 → 统一「伪区块」（style: "trpc"）。
 *
 * URL 构造（对照 @trpc/server v11 语义）：
 *  - 挂载前缀：fetchRequestHandler/createNextApiHandler 的 endpoint，或 Next.js `[trpc]` 路由文件
 *    位置推断（app/api/trpc/[trpc]/route.ts、pages/api/trpc/[trpc].ts），缺省 /api/trpc
 *  - 过程路径：嵌套 router 以点连接（orders.byId → /api/trpc/orders.byId）
 *  - 查询（.query）→ GET + ?input=<JSON>；变更（.mutation）→ POST + 请求体
 * 认证判定：构建器名（protectedProcedure 等）+ .use(auth 中间件) + 处理体内的 ctx.user/session。
 * 取数寻址：从 .input(z.object({ id: z.string() })) 抽出可填充的标量字段（id/orderId/slug…），
 * 或 .input(z.string()) 的裸标量输入；不可寻址的过程（无输入/复杂对象）不作为越权候选。
 *
 * v1 不提供自动修复策略（tRPC 中间件/上下文写法多元，锚点注入易破坏语义）：
 * 证据成立时按 vulnerable_unfixed 阻断，报告给出人工修复指引。
 * 已知缺口：跨文件以路径别名（~/server/…）组装且变量名冲突的路由、订阅过程、
 * 输入字段藏在 helper schema（.input(OrderIdSchema)）里的形态。
 */
import { braceSpan, callArgsSpan } from "./signals.mjs";

const norm = (p) => String(p).replace(/\\/g, "/");
const lineOf = (content, index) => content.slice(0, index).split("\n").length;

/**
 * 显式 tRPC 标记：仅对含这些线索的文件尝试解析，避免把普通 router({...}) 调用误判为 tRPC 路由。
 * 常见写法有两种（v11 官方示例与 create-t3-app 模板皆然）：
 *  - 路由文件直接 import { createTRPCRouter } from "@trpc/server"
 *  - 路由文件 import { router } from "../trpc"（trpc.ts 里 t.router 的再导出）→ 靠来源模块名识别
 */
export function isTrpcRouterFile(content) {
  return (
    /\bcreateTRPCRouter\b|\binitTRPC\b|@trpc\/server/.test(content) ||
    /(?:import|from)\s+[^\n]*["'][^"']*trpc(?:\/[^"']*)?["']/.test(content)
  );
}

// 路由创建锚点：createTRPCRouter({ / t.router({ / router({
const ROUTER_ANCHOR = /(?:\bcreateTRPCRouter\b|\.router\b|\brouter\b)\s*\(\s*\{/g;
// 声明式导出（供跨文件按变量名组装：export const postRouter = createTRPCRouter({…}）
const ROUTER_DECL = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=\n]{0,120})?=\s*(?:createTRPCRouter\b|\.router\b|\brouter\b)\s*\(\s*\{/g;

const AUTH_BUILDER = /(protected|private|authenticated|authed|authorized|withauth|session|isauthed|requireuser|userprocedure|loggedin|verified)/i;
const PUBLIC_BUILDER = /(public|guest|anon|open|unauthenticated|nosession|baseprocedure)/i;
const ROLE_BUILDER = /(admin|superuser|moderator|role)/i;
const MW_AUTH = /auth|token|guard|login|jwt|permission|session|protected|user/i;

const NON_SCALAR = /^\s*(?:async\s+)?z\s*\.\s*(object|array|union|discriminatedUnion|intersection|tuple|record|prefault|lazy)\b/;
const ZOD_CALL = /^\s*(?:async\s+)?z\s*\./;

// 输入值的线上传递类型：数值族保持 number，其余按 string 发送（boolean 无法承载对象 ID，不作为寻址字段）
const NUMERIC_KIND = /(?:^|[.\s])(?:number|int|int32|int64|float|safeInt|bigint|coerce\s*\.\s*number)\b/;
const BOOLEAN_KIND = /(?:^|[.\s])(?:boolean)\b/;

function scalarKind(valueText) {
  if (BOOLEAN_KIND.test(valueText)) return null;
  return NUMERIC_KIND.test(valueText) ? "number" : "string";
}

function projectRelative(p, projectRoot) {
  if (!projectRoot) return norm(p);
  const root = norm(projectRoot).replace(/\/+$/, "") + "/";
  return norm(p).startsWith(root) ? norm(p).slice(root.length) : norm(p);
}

function normEndpoint(raw) {
  const s = String(raw ?? "").replace(/\\/g, "/").trim();
  if (!s) return null;
  const withSlash = s.startsWith("/") ? s : `/${s}`;
  return withSlash.replace(/\/+$/, "") || "/";
}

/**
 * 挂载前缀：显式 endpoint > [trpc] 文件位置推断 > 缺省 /api/trpc。
 * endpoint 形态：fetchRequestHandler({ endpoint: "/api/trpc" }) 等适配器选项。
 */
export function detectTrpcPrefix(files, projectRoot = null) {
  for (const f of files) {
    const m = /(?:fetchRequestHandler|createNextApiHandler|createHTTPServer|createExpressServer|createFastifyServer)\s*\(\s*\{[\s\S]{0,800}?\bendpoint\s*:\s*["'`]([^"'`]+)["'`]/.exec(
      f.content ?? ""
    );
    if (m) {
      const ep = normEndpoint(m[1]);
      if (ep) return ep;
    }
  }
  for (const f of files) {
    const rel = "/" + projectRelative(f.path, projectRoot).replace(/^\/+/, "");
    // app/api/trpc/[trpc]/route.ts 与 pages/api/trpc/[...trpc].ts：[trpc] 之前的目录段即挂载前缀
    const mp = /(?:^|\/)(?:app|pages)\/([^\[]*)\[(?:\.\.\.)?trpc\](?:\.[A-Za-z]+|\/route\.[A-Za-z]+)$/.exec(rel);
    if (!mp) continue;
    const sub = mp[1].replace(/\/+$/, "");
    if (sub) return `/${sub}`;
  }
  return "/api/trpc";
}

/**
 * 对象字面量正文按顶层逗号切分为条目（跳过字符串/注释/嵌套括号）。
 * 返回 [{ key, valStart, valEnd }]；无键条目（数组元素/计算键/展开）跳过。
 * 导出原因：graphql.mjs 解析 resolver/shield 映射表用的是同一套条目切分。
 */
export function scanEntries(content, from, to) {
  const out = [];
  let depth = 0;
  let quote = null;
  let segStart = from;
  let colonAt = -1;
  let i = from;
  const flush = (end) => {
    const seg = content.slice(segStart, end);
    const keyM = /^\s*(?:(?:get|set)\s+)?["'`]?([A-Za-z_$][\w$]*)["'`]?\s*:/.exec(seg);
    if (keyM && colonAt >= 0) {
      const afterKey = colonAt + 1;
      const lead = /^\s*/.exec(content.slice(afterKey, end))[0];
      const valStart = afterKey + lead.length;
      if (valStart < end) out.push({ key: keyM[1], valStart, valEnd: end });
    }
  };
  while (i < to) {
    const ch = content[i];
    if (quote) {
      if (ch === "\\") { i += 2; continue; }
      if (ch === quote) quote = null;
      i += 1;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") { quote = ch; i += 1; continue; }
    if (ch === "/" && content[i + 1] === "/") {
      const nl = content.indexOf("\n", i);
      if (nl < 0 || nl >= to) break;
      i = nl + 1;
      continue;
    }
    if (ch === "/" && content[i + 1] === "*") {
      const close = content.indexOf("*/", i + 2);
      if (close < 0) break;
      i = close + 2;
      continue;
    }
    if (ch === "{" || ch === "[" || ch === "(") depth += 1;
    else if (ch === "}" || ch === "]" || ch === ")") depth -= 1;
    else if (ch === ":" && depth === 0 && colonAt < 0) colonAt = i;
    else if (ch === "," && depth === 0) {
      flush(i);
      segStart = i + 1;
      colonAt = -1;
    }
    i += 1;
  }
  if (segStart < to) flush(to);
  return out;
}

/** 顶层字段名 + zod 值文本（用于判定可寻址标量） */
function zodObjectFields(zText) {
  const open = /\{\s*/.exec(zText);
  if (!open) return [];
  const braceIdx = open.index;
  const fields = [];
  for (const e of scanEntries(zText, braceIdx + 1, Math.min(zText.length, braceIdx + 1 + 4000))) {
    const valueText = zText.slice(e.valStart, e.valEnd).trim();
    if (NON_SCALAR.test(valueText)) continue;
    if (!ZOD_CALL.test(valueText) && !/^\s*(?:[A-Za-z_$][\w$]*\s*\.\s*)?(?:string|number|boolean|bigint)\b/.test(valueText)) continue;
    const kind = scalarKind(valueText);
    if (!kind) continue;
    fields.push({ name: e.key, scalar: true, kind });
  }
  return fields;
}

/** 从 zod 输入文本抽取可寻址字段：优先 id 命名，其次 *Id/*_id，再次唯一标量字段；裸标量输入记 {scalar:true} */
export function pickInputField(zText) {
  if (!zText) return null;
  const obj = /z\s*\.\s*object\s*\(/.exec(zText);
  if (obj) {
    const openParen = obj.index + obj[0].length - 1;
    const inner = callArgsSpan(zText, openParen, 4000);
    if (inner === null) return null;
    const fields = zodObjectFields(inner);
    if (!fields.length) return null;
    const score = (n) => (/^id$/i.test(n) ? 0 : /Id$/.test(n) ? 1 : /_id$/i.test(n) ? 1 : /(slug|uuid|key|token|code|name)$/i.test(n) ? 2 : 3);
    fields.sort((a, b) => score(a.name) - score(b.name));
    if (score(fields[0].name) <= 2) return { field: fields[0].name, scalar: false, kind: fields[0].kind };
    return fields.length === 1 ? { field: fields[0].name, scalar: false, kind: fields[0].kind } : null;
  }
  // 裸标量输入（.input(z.string()) / z.object({id}).parse 之外的字符串/数字形态）
  const bare = /^\s*(?:async\s+)?z\s*\.\s*(string|number|int|int32|int64|float|bigint|boolean|uuid|cuid|email|date)\b/;
  if (bare.test(zText)) {
    const kind = scalarKind(zText);
    return kind ? { field: null, scalar: true, kind } : null;
  }
  return null;
}

/** 链段鉴权判定：构建器名 + .use(auth 中间件)；public 优先于 protected（publicProcedure 不含认证） */
// 构建器引用只到链上第一个方法调用为止：`protectedProcedure.input(…)` 的构建器是 protectedProcedure，
// `t.procedure.use(isAuthed).input(…)` 的是 t.procedure——把 .input/.use 当成名字一部分会误判鉴权。
const CHAIN_CALL = /\s*\.\s*(?:input|output|meta|use|query|mutation|subscription)\s*\(/;

function chainAuthSignals(valueText, chainText) {
  const head = chainText.split(CHAIN_CALL)[0].trim();
  const rootM = /^[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*/.exec(head);
  const builder = rootM ? rootM[0].replace(/\s*\.\s*/g, ".") : "";
  // 段名两侧都可能带语义：t.protectedProcedure 的根是 t，叶才是 protectedProcedure
  const segs = builder.split(".").filter(Boolean);
  const isPublic = segs.some((s) => PUBLIC_BUILDER.test(s));
  let forcedAuth = !isPublic && segs.some((s) => AUTH_BUILDER.test(s));
  const roleGuard = segs.some((s) => ROLE_BUILDER.test(s));
  for (const m of chainText.matchAll(/\.(?:\$?use)\s*\(/g)) {
    const args = callArgsSpan(chainText, m.index + m[0].length - 1);
    if (args && MW_AUTH.test(args)) forcedAuth = true;
  }
  return { builder, forcedAuth, roleGuard };
}

/** 解析一个路由正文，产出过程条目；跨文件引用（posts: postRouter）交给 onRef 按前缀展开 */
function walkRouterBody(content, braceOpen, prefix, out, onRef) {
  const bodyEnd = braceSpan(content, braceOpen);
  if (bodyEnd < 0) return;
  for (const e of scanEntries(content, braceOpen + 1, bodyEnd)) {
    const procPath = [...prefix, e.key].join(".");
    const valueText = content.slice(e.valStart, e.valEnd);
    // 嵌套路由：createTRPCRouter( / .router( / router(
    const nested = /(?:\bcreateTRPCRouter\b|\.router\b|\brouter\b)\s*\(\s*\{/.exec(valueText);
    if (nested) {
      const open = e.valStart + nested.index + nested[0].length - 1;
      walkRouterBody(content, open, [...prefix, e.key], out, onRef);
      continue;
    }
    // 跨文件组装：值仅是标识符引用（posts: postRouter）
    if (/^\s*[A-Za-z_$][\w$]*\s*$/.test(valueText)) {
      onRef?.(valueText.trim(), [...prefix, e.key]);
      continue;
    }
    const kindM = /\.(query|mutation)\s*\(/.exec(valueText);
    if (!kindM) continue; // 订阅/自定义/非过程条目不参与
    const kind = kindM[1];
    const chainText = valueText.slice(0, kindM.index);
    const { builder, forcedAuth, roleGuard } = chainAuthSignals(valueText, chainText);
    // 输入抽取：链上全部 .input(...)（v11 允许多次 input）
    let inputField = null;
    let inputScalar = false;
    let inputKind = null;
    for (const im of chainText.matchAll(/\.input\s*\(/g)) {
      const args = callArgsSpan(chainText, im.index + im[0].length - 1, 4000);
      if (args === null) continue;
      const picked = pickInputField(args);
      if (picked?.scalar && !inputScalar) {
        inputScalar = true;
        inputKind = picked.kind;
      } else if (picked?.field && !inputField) {
        inputField = picked.field;
        inputKind = picked.kind;
      }
    }
    out.push({
      procPath,
      method: kind === "mutation" ? "POST" : "GET",
      startLine: lineOf(content, e.valStart),
      index: e.valStart,
      text: valueText,
      trpc: {
        procPath,
        builder,
        kind,
        inputField,
        inputScalar,
        inputKind,
        addressable: inputScalar || !!inputField,
      },
      forcedAuth,
      roleGuard,
    });
  }
}

/**
 * 汇总 tRPC 路由区块。files 为 [{ path, content }]。
 * 返回 { sections, diag }——sections 与其它框架区块同构，style 固定 "trpc"。
 *
 * 组装顺序决定路径前缀：子路由（ordersRouter）被父路由按名引用时，只在父级的命名空间下展开
 * 一次（orders.byId）；若同时按自身声明再展开，会多出无前缀的伪过程（byId）。
 */
export function collectTrpcSections(files, projectRoot = null) {
  const diag = { trpcFiles: 0, trpcRouters: 0, trpcProcedures: 0, trpcPrefix: null, trpcRefsResolved: 0 };
  const routerFiles = (files ?? []).filter((f) => isTrpcRouterFile(f.content ?? ""));
  if (routerFiles.length === 0) return { sections: [], diag };
  const prefix = detectTrpcPrefix(files, projectRoot);
  diag.trpcPrefix = prefix;

  // 1) 具名路由注册表（export const postRouter = createTRPCRouter({…}），并记录每个声明锚点对应的变量名
  const registry = new Map();
  const fileInfos = [];
  for (const f of routerFiles) {
    const content = f.content ?? "";
    diag.trpcFiles += 1;
    const declByBrace = new Map();
    for (const m of content.matchAll(ROUTER_DECL)) {
      const braceOpen = m.index + m[0].length - 1;
      if (declByBrace.has(braceOpen)) continue;
      declByBrace.set(braceOpen, m[1]);
      if (!registry.has(m[1])) registry.set(m[1], { file: f, braceOpen, content });
    }
    const anchors = [];
    for (const m of content.matchAll(new RegExp(ROUTER_ANCHOR.source, "g"))) {
      const braceOpen = m.index + m[0].length - 1;
      anchors.push({ braceOpen, name: declByBrace.get(braceOpen) ?? null });
    }
    anchors.sort((a, b) => a.braceOpen - b.braceOpen);
    fileInfos.push({ file: f, content, anchors });
  }

  // 2) 被子路由按名引用的具名路由：只由父级展开，避免同一过程出现两种路径
  const referenced = new Set();
  for (const [name, r] of registry) {
    const bodyEnd = braceSpan(r.content, r.braceOpen);
    if (bodyEnd < 0) continue;
    for (const e of scanEntries(r.content, r.braceOpen + 1, bodyEnd)) {
      const v = r.content.slice(e.valStart, e.valEnd).trim();
      if (v !== name && registry.has(v)) referenced.add(v);
    }
  }

  const sections = [];
  const seenPath = new Set();
  const emit = (file, proc) => {
    const declaredPath = `${prefix}/${proc.procPath}`;
    if (seenPath.has(declaredPath)) return; // 同一路径只记一次（环引用与重复挂载的兜底）
    seenPath.add(declaredPath);
    diag.trpcProcedures += 1;
    sections.push({
      file: file.path,
      startLine: proc.startLine,
      method: proc.method,
      style: "trpc",
      declaredPath,
      text: proc.text,
      trpc: proc.trpc,
      forcedAuth: proc.forcedAuth || undefined,
      roleGuard: proc.roleGuard || undefined,
    });
  };

  const walked = new Set();
  const walking = new Set();
  const walkRouter = (content, braceOpen, prefixSegs, file, depth, isRef) => {
    if (depth > 6) return;
    const guard = prefixSegs.join(".");
    if (walking.has(guard)) return; // 环引用
    walking.add(guard);
    diag.trpcRouters += 1;
    if (isRef) diag.trpcRefsResolved += 1;
    const out = [];
    walkRouterBody(content, braceOpen, prefixSegs, out, (refName, refPrefix) => {
      const target = registry.get(refName);
      if (!target) return;
      walked.add(refName);
      walkRouter(target.content, target.braceOpen, refPrefix, target.file, depth + 1, true);
    });
    for (const proc of out) emit(file, proc);
    walking.delete(guard);
  };
  const walkNamed = (name, depth = 0) => {
    const t = registry.get(name);
    if (!t || walked.has(name)) return;
    walked.add(name);
    walkRouter(t.content, t.braceOpen, [], t.file, depth, false);
  };

  // 3) 逐文件展开根路由；匿名 router({...}) 就地展开，具名子路由交由父级按前缀展开
  for (const { file, content, anchors } of fileInfos) {
    let consumed = -1;
    for (const a of anchors) {
      if (a.braceOpen <= consumed) continue; // 嵌套调用由外层递归消费
      const bodyEnd = braceSpan(content, a.braceOpen);
      if (bodyEnd > 0) consumed = bodyEnd;
      if (a.name) {
        if (!referenced.has(a.name)) walkNamed(a.name);
        continue;
      }
      walkRouter(content, a.braceOpen, [], file, 0, false);
    }
  }
  // 兜底：仅被不可解析的父级（如别名路径/未纳入的入口文件）引用的具名路由，按无前缀形态保留
  for (const name of registry.keys()) walkNamed(name);

  return { sections, diag };
}
