/**
 * 静态分析器：在目标项目中定位路由处理器，识别「按对象 ID 取资源但缺少归属校验」
 * 的可疑端点（对象级越权 / IDOR 的静态线索）。
 *
 * 分析只读取经 Host 脱敏后的内容；判定为启发式，最终以动态复现证据为准。
 */
import { detectSupabase } from "./supabase.mjs";

const SOURCE_EXT = [".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".py"];
const MAX_FILES = 64;
const MAX_FILE_BYTES = 128 * 1024;

// 编译/生成产物目录：同分时让位于真实源码
const OUTPUT_DIR = /(^|\/)(build|dist|out|coverage|\.next|\.nuxt)(\/|$)/;

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
  if (/(route|router|app|server|api|controller|handler)/.test(lower)) s += 10;
  if (lower.includes("/src/")) s += 5;
  if (lower.includes("index")) s -= 3;
  if (lower.includes("test") || lower.includes("spec")) s -= 20;
  if (lower.includes("node_modules") || lower.includes(".git")) s -= 100;
  if (OUTPUT_DIR.test(lower)) s -= 15;
  s -= p.split("/").length; // 越浅越优先
  return s;
}

/** 从 fs.list 结果中筛出候选源文件（扩展名 + 大小过滤） */
export function filterSourceFiles(listing) {
  return listing.filter(
    (e) => e.kind === "file" && SOURCE_EXT.includes(extOf(e.path)) && e.size > 0 && e.size < MAX_FILE_BYTES
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

// 资源获取 sink：按 ID 读取单个对象（ORM 单查族 + Sequelize/Mongo 的 Model.find({…}) 对象查询形态）
const SINK =
  /\b(find[A-Za-z]*ById|findById|findByPk|findOne|findUnique|getById|findOrderById|findByIdOrThrow)\s*\(|([A-Za-z_$][\w$]*\.find)\s*\(\s*\{/;

// 归属校验：出现 userId 与请求者的比较（=== / !== / == / !=）
const OWNER_GUARD =
  /(?:\.userId|\.ownerId|\.uid|\.authorId)\s*[!=]==?\s*[^,;\n]+|user\s*\.\s*id\s*[!=]==?\s*[^;,\n]*\.(?:userId|ownerId|uid)|(?:req|request|auth|ctx)\s*\.\s*user\s*[!=]==?/;

// 角色校验
const ROLE_GUARD = /role\s*[!=]==?\s*["'`]admin["'`]|isAdmin|hasRole\s*\(|requireRole|adminRequired|requireAdmin|ensureAdmin|adminGuard/i;

// 认证
const AUTH_GUARD = /authenticate\s*\(|requireAuth|requireLogin|ensureAuth|auth\s*\.\s*user|req\s*\.\s*user|getUser\s*\(/;

// 公开端点路径段（登录/注册等）：无鉴权属预期公开，不作为越权候选
const PUBLIC_PATH = /\/(?:login|logout|sign-?in|sign-?up|register|registration|auth|token|refresh|password|forgot|captcha)\b/i;

// 归属过滤（列表接口按归属过滤）：兼容 userId/user_id 与 where 变量赋值形态
const OWNER_FILTER =
  /filter\s*\(\s*\(?[^)]*\)?\s*=>[^)]*\.user_?[Ii][Dd]\s*[!=]==|where\s*:?\s*\{[^}]*\buser_?[Ii][Dd]\b|where\s*=[^;\n]*\buser_?[Ii][Dd]\b/;

// —— 路径穿越线索：文件读取 sink + 请求输入在同段代码内合流 ——
// sink 覆盖 fs.readFile / sendFile / createReadStream 等读取族（写/删类不在探测范围，避免破坏性操作）
const FS_READ_SINK =
  /\b(?:fs(?:\.promises)?\s*\.\s*)?(readFileSync|readFile|createReadStream|sendFileSync|sendFile|readdirSync|readdir|statSync|openSync|open)\s*\(/;
// 请求输入引用：req.query.x / req.params.x / req.body.x / 数组或字面量下标形态
const REQ_INPUT = /\breq\s*\.\s*(query|params|body)\b(?:\s*\.\s*([A-Za-z_$][\w$]*)|\[\s*["'`]([^"'`]+)["'`]\s*\])?/g;

/** 检测区块内路径穿越线索：返回离 sink 最近的请求输入 {source, param, sink} 或 null */
function findTraversalSignal(text) {
  const re = new RegExp(FS_READ_SINK.source, "g");
  let m;
  while ((m = re.exec(text))) {
    // 取 sink 调用前的窗口：覆盖「输入变量赋值 → 拼接 → 传参」的相邻语句链
    const from = Math.max(0, m.index - 400);
    const window = text.slice(from, m.index + 200);
    let input = null;
    for (const im of window.matchAll(REQ_INPUT)) input = im; // 保留最后一个（离 sink 最近）
    if (!input) continue;
    return {
      source: input[1],
      param: input[2] ?? input[3] ?? null,
      sink: m[1],
    };
  }
  return null;
}

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

/** 从开括号 openIdx（须为 {）找到配平闭括号位置；跳过字符串/模板/注释；未配平返回 -1 */
export function braceSpan(text, openIdx) {
  if (text[openIdx] !== "{") return -1;
  let depth = 0;
  let quote = null;
  for (let i = openIdx; i < text.length; i += 1) {
    const ch = text[i];
    if (quote) {
      if (ch === "\\") i += 1;
      else if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") {
      quote = ch;
      continue;
    }
    if (ch === "/" && text[i + 1] === "/") {
      const nl = text.indexOf("\n", i);
      if (nl < 0) break;
      i = nl;
      continue;
    }
    if (ch === "/" && text[i + 1] === "*") {
      const close = text.indexOf("*/", i + 2);
      if (close < 0) break;
      i = close + 1;
      continue;
    }
    if (ch === "{") depth += 1;
    else if (ch === "}") {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return -1;
}

/** 从 from 起找第一个「括号深度为 0」的 {（即函数体开括号），跳过参数列表与字符串；找不到返回 -1 */
function findBodyOpen(text, from) {
  let depth = 0;
  let quote = null;
  for (let i = from; i < text.length; i += 1) {
    const ch = text[i];
    if (quote) {
      if (ch === "\\") i += 1;
      else if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") quote = ch;
    else if (ch === "(" || ch === "[") depth += 1;
    else if (ch === ")" || ch === "]") depth -= 1;
    else if (ch === "{") {
      if (depth === 0) return i;
      depth += 1;
    } else if (ch === "}") depth -= 1;
    else if (ch === ";" && depth === 0) return -1;
  }
  return -1;
}

const RE_ESCAPE = /[.*+?^${}()|[\]\\]/g;
const escRe = (s) => s.replace(RE_ESCAPE, "\\$&");

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
    out.push({ call: m[1] ?? m[2], index: m.index });
  }
  return out;
}

/** 取调用实参文本（openIdx 处的 ( 起，括号配平到 )），窗口超过 cap 或未闭合返回 null */
function callArgsSpan(text, openIdx, cap = 300) {
  if (text[openIdx] !== "(") return null;
  let depth = 0;
  let quote = null;
  for (let i = openIdx; i < text.length && i - openIdx <= cap; i += 1) {
    const ch = text[i];
    if (quote) {
      if (ch === "\\") i += 1;
      else if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") quote = ch;
    else if (ch === "(") depth += 1;
    else if (ch === ")") {
      depth -= 1;
      if (depth === 0) return text.slice(openIdx + 1, i);
    }
  }
  return null;
}

/**
 * 查询参数形态的越权线索：sink 实参中出现 req.query.X。
 *  - direct：`find({ where: { id: req.query.id } })` —— 实参内直接引用
 *  - indirect：先 `const id = req.query.id` 赋值，变量再出现在实参内
 * 返回 { param, form } 或 null。
 */
export function findQueryParamSink(text) {
  const sinkRe = new RegExp(SINK.source, "g");
  let m;
  while ((m = sinkRe.exec(text))) {
    const openIdx = m.index + m[0].lastIndexOf("(");
    const argsText = callArgsSpan(text, openIdx);
    if (!argsText) continue;
    let direct = null;
    for (const im of argsText.matchAll(new RegExp(REQ_INPUT.source, "g"))) {
      if (im[1] === "query") direct = im;
    }
    if (direct) return { param: direct[2] ?? direct[3] ?? null, form: "direct" };
    const windowText = text.slice(Math.max(0, m.index - 400), m.index);
    for (const am of windowText.matchAll(/(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]{0,200})/g)) {
      const rhs = am[2];
      if (!/\breq\s*\.\s*query\b/.test(rhs)) continue;
      if (!new RegExp(`\\b${am[1]}\\b`).test(argsText)) continue;
      const pm = /req\s*\.\s*query\s*(?:\.\s*([A-Za-z_$][\w$]*)|\[\s*["'`]([^"'`]+)["'`]\s*\])/.exec(rhs);
      return { param: pm?.[1] ?? pm?.[2] ?? null, form: "indirect" };
    }
  }
  return null;
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
    const name = m[1].replace(/[_-]?id$/i, "");
    if (name.length < 3) continue;
    return singular(name.toLowerCase());
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
  const listing = await rpc.request("fs.list", { token, path: projectRoot, depth: 4 });
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

  // 跨文件鉴权线索（挂载级 / 文件级中间件），补偿区块文本看不到的守卫
  const authGuards = collectFileAuthGuards(readContents);
  // 跨文件 handler 引用（router.get("/x", mw, appHandler.x)）→ 伪区块
  const handlerScan = collectHandlerSections(readContents, authGuards);

  const endpoints = [];
  const candidates = [];
  for (const s of [...sections, ...handlerScan.sections]) {
    const eps = extractEndpoints(s);
    const sinks = extractSinks(s);
    const routeKeys = extractRouteKeys(s);
    const normFile = normalizePath(s.file);
    const path = s.declaredPath ?? eps[0]?.path ?? null;
    const hasPathParam = /:[A-Za-z_]\w*/.test(path ?? "");
    const queryParam = !hasPathParam && sinks.length > 0 ? findQueryParamSink(s.text) : null;
    const inlineAuth = AUTH_GUARD.test(s.text) || sectionRouteMwAuth(s.text) || s.forcedAuth === true;
    const mountAuth =
      !inlineAuth && (authGuards.mountGuarded.has(normFile) || authGuards.selfGuarded.has(normFile));
    const hasAuth = inlineAuth || mountAuth;
    const hasOwnerGuard = OWNER_GUARD.test(s.text);
    const hasRoleGuard = ROLE_GUARD.test(s.text);
    const hasOwnerFilter = OWNER_FILTER.test(s.text);
    const matchVars = extractMatchVars(s);
    const mountPrefix = s.mountPrefixOverride ?? authGuards.mountPrefixes.get(normFile) ?? null;
    const fullPath = path ? joinUrl(mountPrefix, path) : null;

    const ep = {
      file: s.file,
      startLine: s.startLine,
      method: s.method,
      path,
      mountPrefix,
      fullPath,
      routeKeys,
      matchVars,
      hasAuth,
      authSource: s.forcedAuth === true ? "route" : inlineAuth ? "inline" : mountAuth ? "mount" : null,
      hasOwnerGuard,
      hasRoleGuard,
      hasOwnerFilter,
      sinkCalls: sinks.map((x) => x.call),
    };
    if (queryParam) ep.queryParam = queryParam;
    endpoints.push(ep);

    const resource =
      resourceFromQueryParam(queryParam?.param) ?? resourceFromModel(s.text) ?? guessResource(fullPath, s.text);

    // 可疑 IDOR：按 ID 取单体资源 + 有认证 + 无归属校验 + 无角色限制
    if (sinks.length > 0 && hasAuth && !hasOwnerGuard && !hasRoleGuard) {
      candidates.push({ ...ep, kind: "idor-suspect", resource });
    } else if (
      // 可疑「无鉴权访问」：按 ID 取单体资源 + 无认证 + 路径含 :param 或查询参数标识符；
      // 登录/注册等预期公开端点不在此列
      sinks.length > 0 &&
      !hasAuth &&
      !hasOwnerGuard &&
      !hasRoleGuard &&
      (hasPathParam || queryParam) &&
      !PUBLIC_PATH.test(path ?? "") &&
      !PUBLIC_PATH.test(fullPath ?? "")
    ) {
      candidates.push({ ...ep, kind: "no-auth-suspect", resource });
    }

    // 可疑「路径穿越」：文件读取 sink 的相邻语句链中出现请求输入（读取族，无修复策略）
    const traversal = findTraversalSignal(s.text);
    if (traversal) {
      candidates.push({
        ...ep,
        kind: "traversal-suspect",
        resource: traversal.param ?? guessResource(fullPath ?? path, s.text),
        traversal,
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
    supabaseDetected: !!supabase,
    supabaseTables: supabase?.tables?.length ?? 0,
    supabaseProbeable: !!supabase?.probeable,
    supabaseServiceRoleLeak: !!supabase?.serviceRoleLeak,
  };

  return { fileCount: files.length, readFiles, sections, endpoints, candidates, diagnostics, supabase };
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
