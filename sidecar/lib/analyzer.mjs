/**
 * 静态分析器：在目标项目中定位路由处理器，识别「按对象 ID 取资源但缺少归属校验」
 * 的可疑端点（对象级越权 / IDOR 的静态线索）。
 *
 * 分析只读取经 Host 脱敏后的内容；判定为启发式，最终以动态复现证据为准。
 */

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

// 资源获取 sink：按 ID 读取单个对象
const SINK = /\b(find[A-Za-z]*ById|findById|findByPk|findOne|findUnique|getById|findOrderById|findByIdOrThrow)\s*\(/;

// 归属校验：出现 userId 与请求者的比较（=== / !== / == / !=）
const OWNER_GUARD =
  /(?:\.userId|\.ownerId|\.uid|\.authorId)\s*[!=]==?\s*[^,;\n]+|user\s*\.\s*id\s*[!=]==?\s*[^;,\n]*\.(?:userId|ownerId|uid)|(?:req|request|auth|ctx)\s*\.\s*user\s*[!=]==?/;

// 角色校验
const ROLE_GUARD = /role\s*[!=]==?\s*["'`]admin["'`]|isAdmin|hasRole\s*\(|requireRole/i;

// 认证
const AUTH_GUARD = /authenticate\s*\(|requireAuth|requireLogin|ensureAuth|auth\s*\.\s*user|req\s*\.\s*user|getUser\s*\(/;

// 归属过滤（列表接口按归属过滤）
const OWNER_FILTER = /filter\s*\(\s*\(?[^)]*\)?\s*=>[^)]*\.userId\s*[!=]==|where\s*:?\s*\{[^}]*userId/;

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
    out.push({ call: m[1], index: m.index });
  }
  return out;
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
  for (const f of files) {
    let res;
    try {
      res = await rpc.request("fs.read", { token, path: f.path, redact: true });
    } catch {
      continue;
    }
    readFiles.push({ path: f.path, size: res.size, redacted: res.redacted, redactions: res.redactions });
    for (const s of sectionize(f.path, res.content)) sections.push(s);
  }

  const endpoints = [];
  const candidates = [];
  for (const s of sections) {
    const eps = extractEndpoints(s);
    const sinks = extractSinks(s);
    const routeKeys = extractRouteKeys(s);
    const hasAuth = AUTH_GUARD.test(s.text);
    const hasOwnerGuard = OWNER_GUARD.test(s.text);
    const hasRoleGuard = ROLE_GUARD.test(s.text);
    const hasOwnerFilter = OWNER_FILTER.test(s.text);
    const matchVars = extractMatchVars(s);
    const path = eps[0]?.path ?? null;

    const ep = {
      file: s.file,
      startLine: s.startLine,
      method: s.method,
      path,
      routeKeys,
      matchVars,
      hasAuth,
      hasOwnerGuard,
      hasRoleGuard,
      hasOwnerFilter,
      sinkCalls: sinks.map((x) => x.call),
    };
    endpoints.push(ep);

    // 可疑 IDOR：按 ID 取单体资源 + 有认证 + 无归属校验 + 无角色限制
    if (sinks.length > 0 && hasAuth && !hasOwnerGuard && !hasRoleGuard) {
      candidates.push({
        ...ep,
        kind: "idor-suspect",
        resource: guessResource(path, s.text),
      });
    }
  }

  const diagnostics = {
    totalEntries: listing.entries.length,
    candidateFiles: allCandidates.length,
    scannedFiles: readFiles.length,
    outputDirFiles: allCandidates.filter((e) => OUTPUT_DIR.test(normalizePath(e.path).toLowerCase()))
      .length,
    readFailures: files.length - readFiles.length,
    sections: sections.length,
  };

  return { fileCount: files.length, readFiles, sections, endpoints, candidates, diagnostics };
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
