/**
 * Next.js 适配器：App Router（app/**\/route.ts 导出 GET/POST… 函数）与
 * Pages Router（pages/api/**，export default handler + req.method 分支）静态解析。
 *
 * 产出统一形态的「伪区块」（style: "next-api"）：真实 URL 路径 + HTTP 方法 + 处理器正文。
 * 由 analyzer 走同一套信号判定生成候选，动态复现复用 HTTP 泛化探测引擎——
 * 探测层只认「路径 + 方法 + 身份」，不关心服务端框架。
 *
 * 说明：route handler 的认证/归属写法（NextAuth / Clerk / Supabase SSR / 自研 JWT）
 * 差异大，暂不提供自动修复策略；探测到漏洞证据时按 vulnerable_unfixed 阻断并给出人工修复指引。
 */
import { braceSpan, findBodyOpen } from "./signals.mjs";

const HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

const norm = (p) => String(p).replace(/\\/g, "/");

/** 项目相对路径（无法判定时退回原路径） */
function projectRelative(p, projectRoot) {
  if (!projectRoot) return p;
  const root = norm(projectRoot).replace(/\/+$/, "") + "/";
  return p.startsWith(root) ? p.slice(root.length) : p;
}

/** 动态段翻译：[id] → :id；[...slug]/[[...slug]] → :slug；路由组 (group) → 空 */
function segmentToUrl(seg) {
  if (/^\(.*\)$/.test(seg)) return "";
  const opt = /^\[\[\.\.\.(.+)\]\]$/.exec(seg);
  if (opt) return `:${opt[1]}`;
  const rest = /^\[\.\.\.(.+)\]$/.exec(seg);
  if (rest) return `:${rest[1]}`;
  const dyn = /^\[(.+)\]$/.exec(seg);
  if (dyn) return `:${dyn[1]}`;
  return seg;
}

/**
 * 解析 Next.js 路由文件路径。
 * 返回 { kind: "app"|"pages", sub } 或 null（非路由文件）。
 *  - app：…/app/**\/route.(ts|tsx|js|jsx|mjs)
 *  - pages：…/pages/api/**
 */
export function parseNextRoute(rawPath, projectRoot = null) {
  const p = norm(rawPath);
  if (/(^|\/)\.next(\/|$)/.test(p)) return null; // 构建产物，跳过
  const rel = "/" + projectRelative(p, projectRoot).replace(/^\/+/, "");
  const appIdx = rel.lastIndexOf("/app/");
  if (appIdx >= 0) {
    const sub = rel.slice(appIdx + "/app/".length);
    const segs = sub.split("/");
    if (segs.some((s) => s.startsWith("_") || s.startsWith("."))) return null; // 私有目录/隐藏文件
    if (!/^route\.(ts|tsx|js|jsx|mjs)$/.test(segs[segs.length - 1])) return null;
    return { kind: "app", sub };
  }
  const pagesIdx = rel.lastIndexOf("/pages/api/");
  if (pagesIdx >= 0) {
    const sub = rel.slice(pagesIdx + "/pages/api/".length);
    return { kind: "pages", sub };
  }
  return null;
}

/** 路由文件的 URL 路径；非路由文件返回 null */
export function nextRouteUrl(rawPath, projectRoot = null) {
  const parsed = parseNextRoute(rawPath, projectRoot);
  if (!parsed) return null;
  if (parsed.kind === "app") {
    const segs = parsed.sub.split("/").slice(0, -1);
    if (segs.length === 0) return "/";
    return "/" + segs.map(segmentToUrl).filter(Boolean).join("/");
  }
  const segs = parsed.sub.split("/");
  const file = segs.pop();
  if (!/\.(ts|tsx|js|jsx|mjs)$/.test(file) || /\.d\.ts$/.test(file)) return null;
  if (segs.some((s) => s.startsWith("_") || s.startsWith("."))) return null; // _app/_middleware 等
  const name = file.replace(/\.(ts|tsx|js|jsx|mjs)$/, "");
  if (name.startsWith("_")) return null;
  const parts = [...segs, ...(name === "index" ? [] : [name])];
  return "/api" + (parts.length ? "/" + parts.map(segmentToUrl).join("/") : "");
}

const lineOf = (content, index) => content.slice(0, index).split("\n").length;

/**
 * App Router：提取 `export function GET(...)` / `export const GET = ...` 形态的方法处理器。
 * 返回 [{ method, index, startLine, text }]
 */
export function extractMethodHandlers(content) {
  const out = [];
  const seen = new Set();
  const methodAlt = HTTP_METHODS.join("|");
  const fnRe = new RegExp(`^[ \\t]*export\\s+(?:async\\s+)?function\\s+(${methodAlt})\\b`, "gm");
  const constRe = new RegExp(`^[ \\t]*export\\s+const\\s+(${methodAlt})\\s*=`, "gm");
  for (const re of [fnRe, constRe]) {
    for (const m of content.matchAll(re)) {
      const method = m[1];
      const bodyOpen = findBodyOpen(content, m.index + m[0].length);
      if (bodyOpen < 0) continue; // 表达式体（无 braces）暂不解析
      const end = braceSpan(content, bodyOpen);
      if (end < 0) continue;
      const key = `${method}@${m.index}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({
        method,
        index: m.index,
        startLine: lineOf(content, m.index),
        text: content.slice(m.index, end + 1),
      });
    }
  }
  return out.sort((a, b) => a.index - b.index);
}

/**
 * Pages Router：提取 `export default function/箭头` 与 `module.exports = function/箭头` 形态，
 * 方法从 `req.method === "X"` 分支收集（无分支按 GET 处理——单体资源默认读接口占多数）。
 * 返回 [{ method, index, startLine, text }]（一个处理器可产出多条，方法各异）
 */
export function extractDefaultHandler(content) {
  const patterns = [
    /^[ \t]*export\s+default\s+(?:async\s+)?function\s+[A-Za-z_$][\w$]*\s*(?=\()/m,
    /^[ \t]*export\s+default\s+(?:async\s+)?function\s*(?=\()/m,
    /^[ \t]*export\s+default\s+(?:async\s+)?\([^)]*\)\s*=>/m,
    /^[ \t]*module\.exports\s*=\s*(?:async\s+)?function\s+[A-Za-z_$][\w$]*\s*(?=\()/m,
    /^[ \t]*module\.exports\s*=\s*(?:async\s+)?function\s*(?=\()/m,
    /^[ \t]*module\.exports\s*=\s*(?:async\s+)?(?:function\s*)?\([^)]*\)\s*=>/m,
  ];
  for (const re of patterns) {
    const m = re.exec(content);
    if (!m) continue;
    const bodyOpen = findBodyOpen(content, m.index + m[0].length);
    if (bodyOpen < 0) continue;
    const end = braceSpan(content, bodyOpen);
    if (end < 0) continue;
    const text = content.slice(m.index, end + 1);
    const methods = new Set();
    for (const mm of text.matchAll(/req\s*\.\s*method\s*===\s*["'`]([A-Za-z]+)["'`]/g)) {
      methods.add(mm[1].toUpperCase());
    }
    const list = methods.size > 0 ? [...methods] : ["GET"];
    return list.map((method) => ({ method, index: m.index, startLine: lineOf(content, m.index), text }));
  }
  return [];
}

/**
 * 汇总 Next.js 路由区块。files 为 [{ path, content }]。
 * 返回 { sections, diag }——sections 与 express 区块同构，style 固定 "next-api"。
 */
export function collectNextSections(files, projectRoot = null) {
  const sections = [];
  const diag = { nextRouteFiles: 0, nextAppFiles: 0, nextPagesFiles: 0, nextHandlers: 0 };
  for (const f of files) {
    const parsed = parseNextRoute(f.path, projectRoot);
    if (!parsed) continue;
    const url = nextRouteUrl(f.path, projectRoot);
    if (!url) continue;
    diag.nextRouteFiles += 1;
    if (parsed.kind === "app") diag.nextAppFiles += 1;
    else diag.nextPagesFiles += 1;
    const content = f.content ?? "";
    const handlers = parsed.kind === "app" ? extractMethodHandlers(content) : extractDefaultHandler(content);
    for (const h of handlers) {
      diag.nextHandlers += 1;
      sections.push({
        file: f.path,
        startLine: h.startLine,
        method: h.method,
        style: "next-api",
        declaredPath: url,
        text: h.text,
      });
    }
  }
  return { sections, diag };
}
