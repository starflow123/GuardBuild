/**
 * 静态分析器：在目标项目中定位路由处理器，识别「按对象 ID 取资源但缺少归属校验」
 * 的可疑端点（对象级越权 / IDOR 的静态线索）。
 *
 * 分析只读取经 Host 脱敏后的内容；判定为启发式，最终以动态复现证据为准。
 */
import { detectSupabase } from "./supabase.mjs";
import { collectNextSections } from "./nextjs.mjs";
import { collectNestSections } from "./nestjs.mjs";
import { collectTrpcSections } from "./trpc.mjs";
import { collectGraphqlSections } from "./graphql.mjs";
import { collectPythonSections } from "./python.mjs";
import { buildImportGraph, graphToJSON, toRel as relToRoot } from "./depgraph.mjs";
import { crossFilePatchEnabled } from "./llm-patcher.mjs";
import {
  SINK,
  OWNER_GUARD,
  ROLE_GUARD,
  AUTH_GUARD,
  REJECT_UNAUTH,
  PUBLIC_PATH,
  OWNER_FILTER,
  FS_READ_SINK,
  XSS_REFLECTION,
  findTraversalSignal,
  findQueryParamSink,
  findSqlInjectionSignal,
  findCommandInjectionSignal,
  findSsrfSignal,
  findUploadSignal,
  callArgsSpan,
  braceSpan,
  findBodyOpen,
  escRe,
} from "./signals.mjs";

// 兼容既有测试/调用方：信号工具从 signals.mjs 统一导出后经此处再导出
export { braceSpan, findQueryParamSink } from "./signals.mjs";

// `.graphql/.gql` 为 SDL schema 文件：GraphQL 适配器的主要分析对象
const SOURCE_EXT = [".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".py", ".graphql", ".gql"];
const MAX_FILES = 200;
const MAX_FILE_BYTES = 128 * 1024;

// 编译/生成产物目录：同分时让位于真实源码
const OUTPUT_DIR = /(^|\/)(build|dist|out|coverage|\.next|\.nuxt)(\/|$)/;
// 依赖/虚拟环境/缓存目录：不是项目源码；宿主 fs.list 已跳过，此处防御性过滤第三方列举来源
const VENDOR_DIR = /(^|\/)(node_modules|\.git|\.venv|venv|site-packages|__pycache__|\.tox|\.nox|\.pytest_cache|\.mypy_cache|\.ruff_cache)(\/|$)/;

export function normalizePath(p) {
  return String(p).replace(/\\/g, "/");
}

function extOf(p) {
  const i = p.lastIndexOf(".");
  return i >= 0 ? p.slice(i).toLowerCase() : "";
}

export function scoreFile(rawPath) {
  const p = normalizePath(rawPath); // Windows 路径须先归一，否则 /src/ 加分与深度惩罚失效
  const lower = p.toLowerCase();
  let s = 0;
  if (/(route|router|app|server|api|controller|handler|schema|graphql|resolv|urls|views|endpoints|blueprint|resources|main)/.test(lower)) s += 10;
  // 路由/接口目录强于同深度的模型/配置文件；否则大项目里 MAX_FILES 会被 app/models 等占满
  if (/(^|\/)(api|routes?|routers?|controllers?|views|endpoints|handlers?|resolvers?|urls|graphql)(\/|\.|$)/.test(lower)) s += 8;
  if (lower.includes("/src/")) s += 5;
  if (lower.includes("index") || lower.includes("__init__")) s -= 3;
  if (lower.includes("test") || lower.includes("spec")) s -= 20;
  if (lower.includes("node_modules") || lower.includes(".git") || VENDOR_DIR.test(lower)) s -= 100;
  if (OUTPUT_DIR.test(lower)) s -= 15;
  s -= p.split("/").length; // 越浅越优先
  return s;
}

/** 从 fs.list 结果中筛出候选源文件（扩展名 + 大小过滤） */
export function filterSourceFiles(listing) {
  return listing.filter(
    (e) =>
      e.kind === "file" &&
      SOURCE_EXT.includes(extOf(e.path)) &&
      e.size > 0 &&
      e.size < MAX_FILE_BYTES &&
      !VENDOR_DIR.test(normalizePath(e.path))
  );
}

/** 从 fs.list 结果中选出待分析文件：源码扩展名 + 大小过滤，按评分取前 N */
export function selectSourceFiles(listing, { maxFiles = MAX_FILES } = {}) {
  return filterSourceFiles(listing)
    .map((e) => ({ ...e, score: scoreFile(e.path) }))
    .sort((a, b) => b.score - a.score)
    .slice(0, maxFiles);
}

// —— 路由锚点：express 风格 or 手写 if (method === "X") 风格 ——
const ANCHOR_EXPRESS = /^\s*(?:app|router|server|api)\s*\.\s*(get|post|put|patch|delete)\s*\(\s*["'`]([^"'`]+)["'`]/;
const ANCHOR_METHOD = /^\s*if\s*\(\s*method\s*===\s*["'`]([A-Za-z]+)["'`]/;

// —— 挂载级鉴权：app.use("/api/x", authRequired, router) / router.use(authenticate) ——
// 真实 Express 项目常把鉴权放在挂载点或文件顶部，路由文件正文中看不到守卫，
// 仅测区块文本会把「有认证」误判为 false，导致候选漏检。

// 认证中间件命名启发式（authRequired / authenticate / requireLogin / verifyToken / jwt…）
const AUTH_MW_NAME = /auth|token|guard|login|jwt|permission/i;

/** 按顶层逗号切分调用参数（忽略括号/引号内的逗号） */
function splitArgsTopLevel(s) {
  const out = [];
  let depth = 0;
  let cur = "";
  let quote = null;
  for (const ch of s) {
    if (quote) {
      cur += ch;
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") {
      quote = ch;
      cur += ch;
      continue;
    }
    if (ch === "(" || ch === "[" || ch === "{") depth += 1;
    else if (ch === ")" || ch === "]" || ch === "}") depth -= 1;
    else if (ch === "," && depth === 0) {
      out.push(cur.trim());
      cur = "";
      continue;
    }
    cur += ch;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

/** 收集 obj.method(...) 调用（括号配平切分参数）；methodPattern 为正则片段，如 "use" 或 "get|post|…" */
function collectMemberCalls(text, methodPattern) {
  const calls = [];
  const re = new RegExp(`\\b([A-Za-z_$][\\w$]*)\\s*\\.\\s*(${methodPattern})\\s*\\(`, "g");
  let m;
  while ((m = re.exec(text))) {
    const open = re.lastIndex - 1;
    let depth = 0;
    let quote = null;
    let end = -1;
    for (let i = open; i < text.length; i += 1) {
      const ch = text[i];
      if (quote) {
        if (ch === quote) quote = null;
        continue;
      }
      if (ch === '"' || ch === "'" || ch === "`") quote = ch;
      else if (ch === "(") depth += 1;
      else if (ch === ")") {
        depth -= 1;
        if (depth === 0) {
          end = i;
          break;
        }
      }
    }
    if (end > open) {
      calls.push({ obj: m[1], method: m[2], args: splitArgsTopLevel(text.slice(open + 1, end)), index: m.index });
    }
  }
  return calls;
}

const collectUseCalls = (text) => collectMemberCalls(text, "use");
const collectRouteCalls = (text) => collectMemberCalls(text, "get|post|put|patch|delete");

const isStringLit = (a) => /^["'`][^"'`]*["'`]$/.test(a);
const isBareIdent = (a) => /^[A-Za-z_$][\w$]*$/.test(a);
// 认证中间件引用：裸标识符或成员访问链（authenticate / authHandler.isAuthenticated），名称含认证语义
const isAuthMwRef = (a) =>
  /^[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*$/.test(a) && AUTH_MW_NAME.test(a);

/** IIFE require 挂载目标：require("./routes/app")() → "./routes/app"；非该形态返回 null */
function iifeRequireTarget(a) {
  const m = /^require\s*\(\s*["'](\.[^"']+)["']\s*\)/.exec(a);
  if (!m) return null;
  let i = m[0].length;
  while (i < a.length && /\s/.test(a[i])) i += 1;
  return a[i] === "(" ? m[1] : null;
}

/** 构建 局部标识符 → 相对模块路径 映射（const/let/var x = require('./x') 与 import x from './x'） */
function buildRequiresMap(content) {
  const requires = new Map();
  for (const m of content.matchAll(
    /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*["'](\.[^"']+)["']\s*\)/g
  )) {
    requires.set(m[1], m[2]);
  }
  for (const m of content.matchAll(/import\s+([A-Za-z_$][\w$]*)\s+from\s+["'](\.[^"']+)["']/g)) {
    requires.set(m[1], m[2]);
  }
  return requires;
}

/** 在已知文件集合中解析模块 spec 对应的真实文件路径（补扩展名 / index 形态） */
function resolveModuleFile(dir, spec, known) {
  for (const cand of resolveModuleCandidates(dir, spec)) {
    if (known.has(cand)) return cand;
  }
  return null;
}

function joinNormalize(dir, spec) {
  // 保留前导斜杠：Host 返回的真实路径带 \\?\ 扩展前缀（归一化后为 //?/…），
  // 若吞掉前缀，挂载级鉴权对任何绝对路径的解析都会失效。
  const joined = `${dir}/${spec}`;
  const lead = /^\/+/.exec(joined)?.[0] ?? "";
  const out = [];
  for (const p of joined.slice(lead.length).split("/")) {
    if (!p || p === ".") continue;
    if (p === "..") out.pop();
    else out.push(p);
  }
  return lead + out.join("/");
}

/** 拼接请求 URL：挂载前缀 + 路由路径（折叠重复斜杠、去尾部斜杠） */
function joinUrl(prefix, routePath) {
  if (!prefix) return routePath ?? null;
  if (!routePath) return String(prefix).replace(/\/+$/, "") || "/";
  const joined = `${prefix}/${routePath}`.replace(/\/{2,}/g, "/");
  return joined.length > 1 ? joined.replace(/\/+$/, "") : joined;
}

function resolveModuleCandidates(dir, spec) {
  const base = joinNormalize(dir, spec);
  const out = [base];
  for (const ext of [".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"]) out.push(base + ext);
  for (const ext of [".js", ".mjs", ".cjs", ".ts"]) out.push(`${base}/index${ext}`);
  return out;
}

/**
 * 跨文件识别路由文件的鉴权守卫：
 *  - 挂载级：app.use("/api/x", authRequired, router)，router 经 require/import 解析到具体文件
 *  - 文件级：router.use(authenticate)（无路径的全局中间件）
 * 返回 { mountGuarded, selfGuarded, mountPrefixes, diag }：
 *  - mountGuarded / selfGuarded 为归一化路径集合
 *  - mountPrefixes：目标文件 → 首个挂载点前缀（无论该挂载点是否带鉴权中间件）
 */
export function collectFileAuthGuards(files) {
  const known = new Set(files.map((f) => normalizePath(f.path)));
  const mountGuarded = new Set();
  const selfGuarded = new Set();
  const mountPrefixes = new Map();
  const diag = { mountsWithAuth: 0, resolvedModules: 0 };
  for (const f of files) {
    const filePath = normalizePath(f.path);
    const content = f.content ?? "";
    const requires = buildRequiresMap(content);
    const dir = filePath.slice(0, filePath.lastIndexOf("/"));
    for (const call of collectUseCalls(content)) {
      // tRPC 构建器链（protectedProcedure.use(isAuthed)）不是 Express 挂载：
      // 其鉴权在区块链上判定，不能据此把整个路由文件标为受保护（否则公开过程会被误判有认证）
      if (/procedure/i.test(call.obj)) continue;
      // router.use(authenticate)：无路径的全局认证中间件 → 本文件整体受保护
      if (call.args.length >= 1 && isBareIdent(call.args[0]) && AUTH_MW_NAME.test(call.args[0])) {
        selfGuarded.add(filePath);
        continue;
      }
      if (!isStringLit(call.args[0])) continue;
      const mountPath = call.args[0].slice(1, -1);
      const middlewares = call.args.slice(1);
      const hasAuth = middlewares.some(isAuthMwRef);
      if (hasAuth) diag.mountsWithAuth += 1;
      // 挂载目标：IIFE 形态（app.use("/app", require("./routes/app")())）优先；
      // 否则取最后一个 bare ident（router 变量）并跨文件解析，失败时回退同文件检查
      let mountTarget = null;
      for (const a of middlewares) {
        const spec = iifeRequireTarget(a);
        if (!spec) continue;
        mountTarget = resolveModuleFile(dir, spec, known);
        if (mountTarget) break;
      }
      let target = null;
      if (!mountTarget) {
        target = [...middlewares].reverse().find(isBareIdent) ?? null;
        if (target) {
          const spec = requires.get(target);
          if (spec) mountTarget = resolveModuleFile(dir, spec, known);
        }
      }
      if (mountTarget) {
        if (!mountPrefixes.has(mountTarget)) mountPrefixes.set(mountTarget, mountPath);
        if (hasAuth) {
          mountGuarded.add(mountTarget);
          diag.resolvedModules += 1;
        }
        continue;
      }
      // 同文件内定义的 router（const router = express.Router()）→ 保守视为整文件受保护
      if (target && new RegExp(`(?:const|let|var|function)\\s+${target}\\b`).test(content)) {
        if (!mountPrefixes.has(filePath)) mountPrefixes.set(filePath, mountPath);
        if (hasAuth) selfGuarded.add(filePath);
      }
    }
  }
  return { mountGuarded, selfGuarded, mountPrefixes, diag };
}

// —— 跨文件 handler 引用：router.get("/x", authMw, appHandler.x) 的实体在别的文件 ——

/** 提取导出函数体文本。支持：module.exports.X = function/箭头、exports.X = function、function X、module.exports = { X: function } */
export function extractExportedFunction(content, name) {
  if (!content || !name) return null;
  const n = escRe(name);
  const patterns = [
    new RegExp(`module\\.exports\\s*\\.\\s*${n}\\s*=\\s*(?:async\\s+)?function\\b`, "g"),
    new RegExp(`exports\\s*\\.\\s*${n}\\s*=\\s*(?:async\\s+)?function\\b`, "g"),
    new RegExp(`module\\.exports\\s*\\.\\s*${n}\\s*=\\s*(?:async\\s+)?(?:\\([^)]*\\)|[A-Za-z_$][\\w$]*)\\s*=>`, "g"),
    new RegExp(`(?:^|[\\n;])\\s*(?:async\\s+)?function\\s+${n}\\s*\\(`, "g"),
    new RegExp(`module\\.exports\\s*=\\s*\\{[\\s\\S]{0,2000}?\\b${n}\\s*:\\s*(?:async\\s+)?function\\b`, "g"),
  ];
  for (const re of patterns) {
    const m = re.exec(content);
    if (!m) continue;
    const open = findBodyOpen(content, m.index + m[0].length);
    if (open < 0) continue;
    const end = braceSpan(content, open);
    if (end < 0) continue;
    return { text: content.slice(m.index, end + 1), index: m.index };
  }
  return null;
}

/**
 * 跨文件 handler 引用解析：路由文件只声明路径/中间件/handler 引用，
 * 函数体在同项目另一文件（module.exports.x = function…）。把函数体转成「伪区块」
 * 参与候选检测：sink / 归属校验 / 查询参数都取自函数体文本。
 * 返回 { sections, diag }。
 */
export function collectHandlerSections(files, authGuards) {
  const known = new Set(files.map((f) => normalizePath(f.path)));
  const byPath = new Map(files.map((f) => [normalizePath(f.path), f]));
  const sections = [];
  const seen = new Set();
  const diag = { handlerRefs: 0, handlerResolved: 0, handlerMissed: 0 };
  for (const f of files) {
    const filePath = normalizePath(f.path);
    const content = f.content ?? "";
    const requires = buildRequiresMap(content);
    const dir = filePath.slice(0, filePath.lastIndexOf("/"));
    const routeGuarded = authGuards.mountGuarded.has(filePath) || authGuards.selfGuarded.has(filePath);
    for (const call of collectRouteCalls(content)) {
      if (!isStringLit(call.args[0])) continue;
      const middlewares = call.args.slice(1);
      const refMatch = /^([A-Za-z_$][\w$]*)\s*\.\s*([A-Za-z_$][\w$]*)$/.exec(middlewares[middlewares.length - 1] ?? "");
      if (!refMatch) continue;
      const [, ns, fn] = refMatch;
      const spec = requires.get(ns);
      if (!spec) continue;
      diag.handlerRefs += 1;
      const targetPath = resolveModuleFile(dir, spec, known);
      const targetFile = targetPath ? byPath.get(targetPath) : null;
      const exported = targetFile ? extractExportedFunction(targetFile.content ?? "", fn) : null;
      if (!exported) {
        diag.handlerMissed += 1;
        continue;
      }
      diag.handlerResolved += 1;
      const declaredPath = call.args[0].slice(1, -1);
      // 认证判定只看 handler 之前的中间件位；末位是 handler 引用本身，不参与
      const forcedAuth = routeGuarded || middlewares.slice(0, -1).some(isAuthMwRef);
      const key = `${targetPath}#${fn}#${call.method} ${declaredPath}`;
      if (seen.has(key)) continue;
      seen.add(key);
      sections.push({
        file: targetPath,
        startLine: (targetFile.content ?? "").slice(0, exported.index).split("\n").length,
        method: call.method.toUpperCase(),
        style: "express-handler",
        declaredPath,
        mountPrefixOverride: authGuards.mountPrefixes.get(filePath) ?? null,
        forcedAuth,
        text: exported.text,
      });
    }
  }
  return { sections, diag };
}

/** 区块的路由声明中是否含认证中间件引用（router.get("/x", authHandler.isAuthenticated, …)） */
function sectionRouteMwAuth(text) {
  for (const call of collectRouteCalls(text)) {
    if (!isStringLit(call.args[0])) continue;
    if (call.args.slice(1).some(isAuthMwRef)) return true;
  }
  return false;
}

export function translatePathRegex(regexLiteral) {
  // 把 /^\/api\/orders\/(\d+)$/ 这类正则字面量翻译成 /api/orders/:id 形态
  // 注意：只剥离开头/结尾的锚点，避免破坏 [^/] 这类字符类
  let s = regexLiteral.replace(/\\\//g, "/").replace(/^\^/, "").replace(/\$$/, "");
  // 数字/通配占位（捕获组或转义括号形式）：(\d+) \(\d+\) ([0-9]+) (\w+) ([^/]+) (?:[0-9]+)
  s = s.replace(/\\?\((?:\?:)?(?:\\d\+?|\[0-9\]\+?|\\w\+?|\[\^\/\]\+?)\\?\)/g, ":id");
  return s;
}

/** 将源文件切分为「handler 区块」 */
function sectionize(filePath, content) {
  const lines = content.split("\n");
  const anchors = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    let m = line.match(ANCHOR_EXPRESS);
    if (m) {
      anchors.push({ line: i, method: m[1].toUpperCase(), pathHint: m[2], style: "express" });
      continue;
    }
    m = line.match(ANCHOR_METHOD);
    if (m) {
      anchors.push({ line: i, method: m[1].toUpperCase(), pathHint: null, style: "method" });
    }
  }
  const sections = [];
  for (let a = 0; a < anchors.length; a++) {
    const start = anchors[a].line;
    const end = a + 1 < anchors.length ? anchors[a + 1].line : lines.length;
    // 向上把紧邻的 const XMatch = pathname.match(...) 行并入区块
    let from = start;
    while (from - 1 >= 0) {
      const prev = lines[from - 1].trim();
      if (!prev || /^(const|let)\s+\w*Match\w*\s*=/.test(prev) || /^\s*before/.test(prev)) {
        if (/^(const|let)\s+\w*Match\w*\s*=/.test(prev)) from -= 1;
        else break;
      } else {
        break;
      }
    }
    const text = lines.slice(from, end).join("\n");
    sections.push({
      file: filePath,
      startLine: from + 1,
      endLine: end,
      method: anchors[a].method,
      style: anchors[a].style,
      text,
    });
  }
  return sections;
}

function extractEndpoints(section) {
  const endpoints = [];
  if (section.style === "express") {
    const m = section.text.match(ANCHOR_EXPRESS);
    if (m) endpoints.push({ path: m[2] });
  } else {
    for (const m of section.text.matchAll(/pathname\s*===\s*["'`]([^"'`]+)["'`]/g)) {
      endpoints.push({ path: m[1] });
    }
    for (const m of section.text.matchAll(/pathname\s*\.\s*match\s*\(\s*\/(.+?)\/\s*\)/g)) {
      endpoints.push({ path: translatePathRegex(m[1]) });
    }
  }
  return endpoints;
}

function extractSinks(section) {
  const out = [];
  for (const m of section.text.matchAll(new RegExp(SINK.source, "g"))) {
    const rawReceiver = m[4]?.replace(/\s+/g, "");
    const knexFirst = m[8]?.replace(/\s+/g, "");
    out.push({
      call:
        m[1] ??
        m[2] ??
        (m[3] ? `${m[3]}.select-where` : null) ??
        (rawReceiver ? rawReceiver.replace(/\.prepare\([^;\n]*\)\./, ".prepare.") : null) ??
        m[5] ??
        (m[6] ? m[6].replace(/[\s(`]+$/, "") : null) ??
        (m[7] ? m[7].replace(/[\s(`]+$/, "") : null) ??
        (knexFirst ? `${/^[A-Za-z_$][\w$]*/.exec(knexFirst)?.[0] ?? "knex"}.first` : null),
      index: m.index,
    });
  }
  return out;
}

/** 从查询参数名推断资源：user_id → user / productId → product；无有效词根返回 null */
function resourceFromQueryParam(param) {
  if (!param) return null;
  const base = String(param).replace(/[_-]?id$/i, "");
  if (base.length < 3) return null;
  return singular(base.toLowerCase());
}

/** 从 Model.find({…}) 形态推断资源名：db.Product.find → product；排除工具对象名 */
const MODEL_UTIL = new Set(["db", "this", "self", "ctx", "req", "res", "module", "exports", "conn", "client", "collection", "store"]);
function resourceFromModel(text) {
  for (const m of text.matchAll(/(?:^|[^\w$])([A-Za-z_$][\w$]*)\s*\.\s*find[A-Za-z]*\s*\(/g)) {
    if (MODEL_UTIL.has(m[1].toLowerCase())) continue;
    // NestJS 等分层写法：ordersService.findOne → 剥去服务后缀再归约
    const name = m[1].replace(/(?:Service|Repository|Repo|Model|Client)$/, "").replace(/[_-]?id$/i, "");
    if (name.length < 3) continue;
    return singular(name.toLowerCase());
  }
  // Drizzle 链式取数：.select().from(ordersTable) → order（剥去 Table/Schema 后缀）
  const dr = /\.\s*select\s*\([^)]*\)\s*\.\s*from\s*\(\s*([A-Za-z_$][\w$]*)\s*\)/.exec(text);
  if (dr && !MODEL_UTIL.has(dr[1].toLowerCase())) {
    const name = dr[1].replace(/(?:Table|Schema)$/i, "").replace(/[_-]?id$/i, "");
    if (name.length >= 3) return singular(name.toLowerCase());
  }
  // Python 取数形态：db.query(Order) / Order.objects.get / get_object_or_404(Order) → order
  const pyModel =
    /\.\s*query\s*\(\s*([A-Z][A-Za-z0-9_]*)\s*\)/.exec(text) ??
    /\b([A-Z][A-Za-z0-9_]*)\s*\.\s*objects\s*\.\s*(?:get|filter)\s*\(/.exec(text) ??
    /\b([A-Z][A-Za-z0-9_]*)\s*\.\s*query\s*\.\s*(?:get|filter)/.exec(text) ??
    /\b(?:db|session)\s*\.\s*get\s*\(\s*([A-Z][A-Za-z0-9_]*)/.exec(text) ??
    /\bget_object_or_404\s*\(\s*([A-Z][A-Za-z0-9_]*)/.exec(text);
  if (pyModel) {
    const name = pyModel[1].replace(/Model$/, "").replace(/[_-]?id$/i, "");
    if (name.length >= 3) return singular(name.toLowerCase());
  }
  return null;
}

function extractRouteKeys(section) {
  const keys = [];
  for (const m of section.text.matchAll(/routeKey:\s*["'`]([\w.]+)["'`]/g)) keys.push(m[1]);
  return [...new Set(keys)];
}

function extractMatchVars(section) {
  const vars = [];
  for (const m of section.text.matchAll(/(?:const|let)\s+(\w*[Mm]atch\w*)\s*=/g)) vars.push(m[1]);
  return [...new Set(vars)];
}

export async function analyzeProject(ctx) {
  const { rpc, projectRoot } = ctx;
  const token = ctx.tokens.project;
  // 深度 6：覆盖 Next.js App Router 的深层路由文件（app/api/<res>/[id]/<action>/route.ts）
  const listing = await rpc.request("fs.list", { token, path: projectRoot, depth: 6 });
  const allCandidates = filterSourceFiles(listing.entries);
  const files = selectSourceFiles(listing.entries);

  const sections = [];
  const readFiles = [];
  const readContents = [];
  for (const f of files) {
    let res;
    try {
      res = await rpc.request("fs.read", { token, path: f.path, redact: true });
    } catch {
      continue;
    }
    readFiles.push({ path: f.path, size: res.size, redacted: res.redacted, redactions: res.redactions });
    readContents.push({ path: f.path, content: res.content });
    for (const s of sectionize(f.path, res.content)) sections.push(s);
  }

  // 依赖闭包：在已读过的那批文件上构图，零额外读取。编码代理的写集据此界定（S2-full）。
  // 只在跨文件补丁开启时构建——gate/CI 的确定性流程不需要它，也不该为它付出扫描成本。
  const depGraph = crossFilePatchEnabled(ctx)
    ? graphToJSON(
        buildImportGraph(
          readContents
            .map((f) => ({ rel: relToRoot(projectRoot, f.path), content: f.content }))
            .filter((f) => f.rel)
        )
      )
    : null;

  // 跨文件鉴权线索（挂载级 / 文件级中间件），补偿区块文本看不到的守卫
  const authGuards = collectFileAuthGuards(readContents);
  // 跨文件 handler 引用（router.get("/x", mw, appHandler.x)）→ 伪区块
  const handlerScan = collectHandlerSections(readContents, authGuards);
  // Next.js 适配器：app/**/route.ts 与 pages/api/** → 伪区块（style: "next-api"）
  const nextScan = collectNextSections(readContents, projectRoot);
  // NestJS 适配器：@Controller/@Get… 装饰器路由 → 伪区块（style: "nest"）
  const nestScan = collectNestSections(readContents);
  // tRPC 适配器：createTRPCRouter 路由树 → 伪区块（style: "trpc"，路径含挂载前缀与点连接过程名）
  const trpcScan = collectTrpcSections(readContents, projectRoot);
  // GraphQL 适配器：SDL schema + resolver/directive/shield 鉴权线索 → 伪区块（style: "graphql"，
  // declaredPath 为唯一 HTTP 端点，寻址信息在 s.graphql 而非 URL）
  const graphqlScan = collectGraphqlSections(readContents, projectRoot);
  // Python 适配器：FastAPI/Flask/Django(DRF) 路由 → 伪区块（style: "python"，
  // 路径已折叠路由前缀并归一化为 :param；取数/鉴权信号随区块携带）
  const pythonScan = collectPythonSections(readContents);

  const endpoints = [];
  const candidates = [];
  for (const s of [...sections, ...handlerScan.sections, ...nextScan.sections, ...nestScan.sections, ...trpcScan.sections, ...graphqlScan.sections, ...pythonScan.sections]) {
    const eps = extractEndpoints(s);
    const sinks = [...extractSinks(s), ...(s.sinkHints ?? [])];
    const routeKeys = s.routeKeys ?? extractRouteKeys(s);
    const normFile = normalizePath(s.file);
    const path = s.declaredPath ?? eps[0]?.path ?? null;
    const hasPathParam = /:[A-Za-z_]\w*/.test(path ?? "");
    // GraphQL 区块已带 declaredPath（完整端点），且 sink 判定走 s.graphql，不再做查询参数定位；
    // Python 区块的查询参数来自签名/request.args 等，由适配器直接携带
    const queryParam =
      s.queryParamHint ??
      (!hasPathParam && sinks.length > 0 && !s.graphql ? findQueryParamSink(s.text) : null);
    const strongAuth = AUTH_GUARD.test(s.text) || sectionRouteMwAuth(s.text) || s.forcedAuth === true;
    // 「未登录即拒」分支单独记一类来源：它证明端点确实要登录，但块内没有任何会话字段引用
    const rejectAuth = !strongAuth && REJECT_UNAUTH.test(s.text);
    const inlineAuth = strongAuth || rejectAuth;
    const mountAuth =
      !inlineAuth && (authGuards.mountGuarded.has(normFile) || authGuards.selfGuarded.has(normFile));
    const hasAuth = inlineAuth || mountAuth;
    const hasOwnerGuard = OWNER_GUARD.test(s.text) || s.ownerGuard === true;
    const hasRoleGuard = ROLE_GUARD.test(s.text) || s.roleGuard === true;
    const hasOwnerFilter = OWNER_FILTER.test(s.text) || s.ownerFilter === true;
    // 可寻址性：路径参数 / 查询参数 / tRPC 标量输入字段 / GraphQL 单标量 ID 参数——
    // 不可寻址的对象无法动态复现，不作越权候选
    const addressable = hasPathParam || !!queryParam || !!s.trpc?.addressable || !!s.graphql?.addressable;
    // 列表形态（归属过滤 + 无对象引用参数）：findFirst/单查族也常用于「取列表首条」，
    // 无可寻址参数时不可被动态寻址，抑制为噪声而非 IDOR 候选
    const listShaped = hasOwnerFilter && !addressable;
    const matchVars = extractMatchVars(s);
    // GraphQL 端点即完整 URL（detectGraphqlEndpoint 已含挂载前缀），不能再叠加 Express 挂载前缀
    const mountPrefix = s.style === "graphql" ? null : s.mountPrefixOverride ?? authGuards.mountPrefixes.get(normFile) ?? null;
    const fullPath = path ? joinUrl(mountPrefix, path) : null;

    const ep = {
      file: s.file,
      startLine: s.startLine,
      method: s.method,
      style: s.style ?? null,
      path,
      mountPrefix,
      fullPath,
      routeKeys,
      matchVars,
      hasAuth,
      authSource:
        s.forcedAuth === true
          ? "route"
          : strongAuth
            ? "inline"
            : rejectAuth
              ? "reject"
              : mountAuth
                ? "mount"
                : null,
      hasOwnerGuard,
      hasRoleGuard,
      hasOwnerFilter,
      sinkCalls: sinks.map((x) => x.call),
      trpc: s.trpc ?? null,
      graphql: s.graphql ?? null,
    };
    if (queryParam) ep.queryParam = queryParam;
    endpoints.push(ep);

    const resource =
      (s.graphql ? singular(String(s.graphql.resultType ?? "").toLowerCase()) : null) ||
      (resourceFromQueryParam(queryParam?.param) ?? resourceFromModel(s.text) ?? guessResource(fullPath, s.text));

    // 取数证据：传统代码看 sink 调用；GraphQL 看 SDL 里的单对象 ID 参数（无代码 sink 概念）
    const sinkish = sinks.length > 0 || !!s.graphql;

    // 可疑 IDOR：按 ID 取单体资源 + 有认证 + 无归属校验 + 无角色限制
    if (
      sinkish &&
      hasAuth &&
      !hasOwnerGuard &&
      !hasRoleGuard &&
      !listShaped &&
      ((!s.trpc && !s.graphql) || addressable)
    ) {
      candidates.push({ ...ep, kind: "idor-suspect", resource });
    } else if (
      // 可疑「无鉴权访问」：按 ID 取单体资源 + 无认证 + 可寻址（:param / 查询参数 / tRPC 输入字段 / GraphQL ID 参数）；
      // 登录/注册等预期公开端点不在此列
      sinkish &&
      !hasAuth &&
      !hasOwnerGuard &&
      !hasRoleGuard &&
      addressable &&
      !PUBLIC_PATH.test(path ?? "") &&
      !PUBLIC_PATH.test(fullPath ?? "")
    ) {
      candidates.push({ ...ep, kind: "no-auth-suspect", resource });
    }

    // 可疑「路径穿越」：文件读取 sink 的相邻语句链中出现请求输入（读取族，无修复策略）
    // GraphQL 区块的 text 含 resolver 体，可能恰好引用文件读取；穿越取证走 HTTP 路径参数，
    // 与 GraphQL 单端点模型不符，跳过（避免造出无法寻址的伪穿越用例）
    const traversal = s.graphql ? null : findTraversalSignal(s.text);
    if (traversal) {
      candidates.push({
        ...ep,
        kind: "traversal-suspect",
        resource: traversal.param ?? guessResource(fullPath ?? path, s.text),
        traversal,
      });
    }

    // 可疑「SQL 注入」：请求输入经模板/拼接进入 SQL 首参（参数化查询不入选）
    const sqli = s.graphql ? null : findSqlInjectionSignal(s.text);
    if (sqli && path) {
      candidates.push({
        ...ep,
        kind: "sqli-suspect",
        resource: guessResource(fullPath ?? path, s.text),
        sqli,
      });
    }

    // 可疑「命令注入」：请求输入进入 shell 执行入口（exec/os.system/subprocess）
    const cmdi = s.graphql ? null : findCommandInjectionSignal(s.text);
    if (cmdi && path) {
      candidates.push({
        ...ep,
        kind: "cmdi-suspect",
        resource: guessResource(fullPath ?? path, s.text),
        cmdi,
      });
    }

    // 可疑「反射型 XSS」：响应输出直接拼接请求输入（未转义）
    // 暂时禁用：动态 oracle 未实现，产出候选会误导。待 probe 加 XSS 反射验证后再开。
    // if (!s.graphql && XSS_REFLECTION.test(s.text)) {
    //   candidates.push({ ...ep, kind: "xss-suspect", resource: guessResource(fullPath ?? path, s.text) });
    // }

    // 可疑「SSRF」：请求输入直接作为 HTTP 客户端的 URL（本地 canary 回连复现）
    const ssrf = s.graphql ? null : findSsrfSignal(s.text);
    if (ssrf && path) {
      candidates.push({
        ...ep,
        kind: "ssrf-suspect",
        resource: ssrf.param ?? guessResource(fullPath ?? path, s.text),
        ssrf,
      });
    }

    // 可疑「文件上传」：服务端接收 multipart 文件；是否可上传主动内容由动态用例取证
    const upload = s.graphql ? null : findUploadSignal(s.text);
    if (upload && path && ep.method && ep.method !== "GET") {
      candidates.push({
        ...ep,
        kind: "upload-suspect",
        resource: upload.field ?? guessResource(fullPath ?? path, s.text),
        upload,
      });
    }
  }

  // Supabase / PostgREST 适配器：静态检测（失败不阻塞主流程，密钥值不进入返回值以外展示面）
  let supabase = null;
  try {
    supabase = await detectSupabase(ctx, { readContents });
  } catch {
    supabase = null;
  }

  const diagnostics = {
    totalEntries: listing.entries.length,
    candidateFiles: allCandidates.length,
    scannedFiles: readFiles.length,
    outputDirFiles: allCandidates.filter((e) => OUTPUT_DIR.test(normalizePath(e.path).toLowerCase()))
      .length,
    readFailures: files.length - readFiles.length,
    sections: sections.length,
    mountAuthFiles: authGuards.mountGuarded.size,
    selfAuthFiles: authGuards.selfGuarded.size,
    mountPrefixFiles: authGuards.mountPrefixes.size,
    handlerSections: handlerScan.sections.length,
    handlerRefsResolved: handlerScan.diag.handlerResolved,
    handlerRefsMissed: handlerScan.diag.handlerMissed,
    nextRouteFiles: nextScan.diag.nextRouteFiles,
    nextAppFiles: nextScan.diag.nextAppFiles,
    nextPagesFiles: nextScan.diag.nextPagesFiles,
    nextSections: nextScan.sections.length,
    nestFiles: nestScan.diag.nestFiles,
    nestControllers: nestScan.diag.nestControllers,
    nestHandlers: nestScan.diag.nestHandlers,
    nestGlobalPrefix: nestScan.diag.nestGlobalPrefix,
    trpcFiles: trpcScan.diag.trpcFiles,
    trpcRouters: trpcScan.diag.trpcRouters,
    trpcProcedures: trpcScan.diag.trpcProcedures,
    trpcPrefix: trpcScan.diag.trpcPrefix,
    trpcRefsResolved: trpcScan.diag.trpcRefsResolved,
    graphqlFiles: graphqlScan.diag.graphqlFiles,
    graphqlSdlBlocks: graphqlScan.diag.graphqlSdlBlocks,
    graphqlTypes: graphqlScan.diag.graphqlTypes,
    graphqlFields: graphqlScan.diag.graphqlFields,
    graphqlSections: graphqlScan.sections.length,
    graphqlEndpoint: graphqlScan.diag.graphqlEndpoint,
    graphqlAuthSource: graphqlScan.diag.graphqlAuthSource,
    graphqlLoginField: graphqlScan.diag.graphqlLoginField,
    pythonFiles: pythonScan.diag.pythonFiles,
    pythonFastapiFiles: pythonScan.diag.fastapiFiles,
    pythonFastapiRoutes: pythonScan.diag.fastapiRoutes,
    pythonFlaskFiles: pythonScan.diag.flaskFiles,
    pythonFlaskRoutes: pythonScan.diag.flaskRoutes,
    pythonDjangoFiles: pythonScan.diag.djangoFiles,
    pythonDjangoUrls: pythonScan.diag.djangoUrls,
    pythonDrfViewSets: pythonScan.diag.drfViewSets,
    pythonSections: pythonScan.sections.length,
    supabaseDetected: !!supabase,
    supabaseTables: supabase?.tables?.length ?? 0,
    supabaseProbeable: !!supabase?.probeable,
    supabaseServiceRoleLeak: !!supabase?.serviceRoleLeak,
  };

  // 标记适配器来源
  for (const ep of endpoints) ep.source = ep.source ?? "adapter";
  for (const c of candidates) c.source = c.source ?? "adapter";

  // ---- 合并外部路由线索：OpenAPI 文件 + guardbuild.json routes 手工声明 ----
  const externalWarnings = [];
  const externalEndpoints = [];

  if (ctx.targetConfig?.openapi) {
    try {
      const { loadOpenapiEndpoints } = await import("./openapi.mjs");
      const r = await loadOpenapiEndpoints(ctx, ctx.targetConfig.openapi);
      externalEndpoints.push(...r.endpoints);
      externalWarnings.push(...r.warnings);
    } catch (e) {
      externalWarnings.push(`OpenAPI 解析失败：${e.message}`);
    }
  }

  if (Array.isArray(ctx.targetConfig?.routes)) {
    for (const r of ctx.targetConfig.routes) {
      externalEndpoints.push({
        file: null,
        startLine: null,
        method: r.method,
        style: "routes",
        path: r.path,
        mountPrefix: null,
        fullPath: r.path,
        routeKeys: [r.path],
        matchVars: [],
        hasAuth: r.hasAuth,
        authSource: r.hasAuth ? "routes-declared" : null,
        hasOwnerGuard: false,
        hasRoleGuard: false,
        hasOwnerFilter: false,
        sinkCalls: [],
        trpc: null,
        graphql: null,
        source: "routes",
        resource: r.resource ?? guessResource(r.path, ""),
        ...(r.query ? { queryParam: { param: r.query, in: "query" } } : {}),
      });
    }
  }

  // LLM 侦察线索：只提供可寻址路由 + 可定位文件，作为动态探测目标；
  // 归属/鉴权判断仍由 probe 实际发请求验证，不因 LLM 断言而直接定罪。
  if (Array.isArray(ctx.targetConfig?.llmRoutes)) {
    for (const r of ctx.targetConfig.llmRoutes) {
      externalEndpoints.push({
        file: r.file ?? null,
        startLine: r.line ?? null,
        method: r.method,
        style: "llm-scout",
        path: r.path,
        mountPrefix: null,
        fullPath: r.path,
        routeKeys: [r.path],
        matchVars: [],
        hasAuth: r.hasAuth !== false,
        authSource: r.hasAuth !== false ? "llm-inferred" : null,
        hasOwnerGuard: false,
        hasRoleGuard: false,
        // 列表路由仅用于动态资源发现；归属过滤由实际响应验证，不据此判定漏洞
        hasOwnerFilter: r.list === true && r.hasOwnerFilter === true,
        sinkCalls: [],
        trpc: null,
        graphql: null,
        source: "llm-scout",
        resource: r.resource ?? guessResource(r.path, ""),
        ...(r.query ? { queryParam: { param: r.query, in: "query" } } : {}),
      });
    }
  }

  // 去重：按 method + fullPath，已有适配器结果优先
  const seen = new Set(endpoints.map((e) => `${e.method} ${e.fullPath}`));
  for (const ep of externalEndpoints) {
    const key = `${ep.method} ${ep.fullPath}`;
    if (seen.has(key)) continue;
    seen.add(key);
    endpoints.push(ep);
    // 外部线索没有代码 sink，直接按"带认证但未见归属校验"报候选；动态 probe 会实际验证
    const addressable = /:[A-Za-z_]\w*/.test(ep.path) || !!ep.queryParam;
    if (addressable) {
      candidates.push({ ...ep, kind: ep.hasAuth ? "idor-suspect" : "no-auth-suspect" });
    }
  }

  return {
    fileCount: files.length,
    readFiles,
    depGraph,
    sections,
    endpoints,
    candidates,
    diagnostics: {
      ...diagnostics,
      endpointsFromOpenapi: ctx.targetConfig?.openapi ? externalEndpoints.filter((e) => e.source === "openapi").length : 0,
      endpointsFromRoutes: Array.isArray(ctx.targetConfig?.routes) ? externalEndpoints.filter((e) => e.source === "routes").length : 0,
      endpointsFromLlm: Array.isArray(ctx.targetConfig?.llmRoutes) ? externalEndpoints.filter((e) => e.source === "llm-scout").length : 0,
      externalWarnings,
    },
    supabase,
    graphql: graphqlScan.endpoint ? { endpoint: graphqlScan.endpoint, login: graphqlScan.login } : null,
  };
}

function guessResource(pathHint, text) {
  const fromPath = pathHint?.match(/\/([a-z][a-z0-9_-]{2,})\s*(?:\/:|\/\(|$)/i);
  if (fromPath) return singular(fromPath[1]);
  const fromSink = text.match(/find(\w+?)ById/i);
  if (fromSink) return singular(fromSink[1].toLowerCase());
  return "resource";
}

function singular(word) {
  if (word.endsWith("ies")) return word.slice(0, -3) + "y";
  if (word.endsWith("ses")) return word.slice(0, -2);
  if (word.endsWith("s") && !word.endsWith("ss")) return word.slice(0, -1);
  return word;
}
