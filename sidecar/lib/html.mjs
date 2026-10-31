/**
 * SSR / HTML 应用的资源发现与内容归属取证。
 *
 * 传统 SPA 靶场把列表做成 JSON 接口，越权取证只需比对 `userId` 字段。
 * 服务端渲染的应用没有这一层：列表是一页 HTML，详情也是一页 HTML，
 * 对象 ID 只出现在页面链接里，归属信息只出现在正文文本里。
 * 本模块只做三件纯函数的事：
 *  1. 判断响应是不是 HTML 页面；
 *  2. 从页面链接里抓出对象 ID（按候选路由模板匹配，不猜命名）；
 *  3. 把两页正文归一化成可比对的文本，并算出「只在本人页面出现」的片段。
 * 判定仍归 probe：这里不产生任何漏洞结论，只提供可核对的文本证据。
 */

// 详情链接里的 ID 段：允许字母数字、-、_、.，但不允许 / ? # ;（避免跨段匹配）
const ID_SEGMENT = "([^/?#;]+?)";

/** 响应是否为 HTML 页面（JSON 解析失败 + content-type 或正文形态像页面） */
export function looksHtml(res) {
  if (!res || typeof res.body !== "string" || res.body.length === 0) return false;
  if (res.json !== null && res.json !== undefined) return false;
  const ct = String(res.headers?.["content-type"] ?? "").toLowerCase();
  if (ct.includes("html")) return true;
  if (ct && !ct.includes("text")) return false;
  const head = res.body.slice(0, 2048).toLowerCase();
  return /<(?:!doctype\s+html|html|body|a\s|div|p\s|main|table)/.test(head);
}

function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * 路由模板 → 匹配实际链接的正则。
 * `/events/:id` → `^/events/([^/?#;]+?)$`；多段模板逐段捕获。
 * 只认路径段级参数，查询串与锚点在此剥离（它们不是对象寻址的主形态）。
 */
export function templateMatcher(template) {
  const clean = String(template ?? "").split("?")[0].split("#")[0].replace(/\/+$/, "");
  if (!clean || !/:[A-Za-z_]\w*/.test(clean)) return null;
  const source = escapeRe(clean).replace(/:[A-Za-z_]\w*/g, ID_SEGMENT);
  return { re: new RegExp(`^${source}$`), params: [...String(clean).matchAll(/:([A-Za-z_]\w*)/g)].map((m) => m[1]) };
}

/** 页面里出现的链接目标（href/src/action + 任意以 / 开头的带引号字符串，覆盖框架的路由 prop） */
export function pageLinks(html) {
  const text = String(html ?? "");
  const out = new Set();
  for (const m of text.matchAll(/(?:href|src|action|data-href|to|router-link|:to)\s*=\s*["']([^"']+)["']/gi)) {
    out.add(m[1]);
  }
  // 框架里链接常写成属性表达式（href="/x" 已被上面覆盖；这里补 JSX / 模板字符串形态）
  for (const m of text.matchAll(/["'`](\/[A-Za-z0-9_\-./:]+)["'`]/g)) out.add(m[1]);
  return [...out];
}

/**
 * 从页面链接里抓对象 ID：按候选路由模板逐条匹配，返回 [{ id, param, template, link }]。
 * 不做任何「看起来像 ID」的猜测——只有能填满某条真实候选路由的链接才算资源。
 * `link` 保留页面里那条链接的原始路径：读本人基线正文时按它请求，
 * 而不是按模板反拼（应用自己怎么写链接，就说明它认这个形态）。
 */
export function extractPageIds(html, templates) {
  const matchers = (templates ?? []).map((t) => ({ template: t, ...templateMatcher(t) })).filter((m) => m.re);
  if (matchers.length === 0) return [];
  const found = [];
  const seen = new Set();
  for (const link of pageLinks(html)) {
    const path = String(link).split("?")[0].split("#")[0];
    for (const m of matchers) {
      const hit = m.re.exec(path);
      if (!hit) continue;
      // 段级参数取最后一个捕获（/orgs/:orgId/members/:memberId 的主键是末段）
      const id = hit[hit.length - 1];
      const param = m.params[m.params.length - 1];
      if (!id) continue;
      const key = `${m.template}#${id}`;
      if (seen.has(key)) continue;
      seen.add(key);
      found.push({ id, param, template: m.template, link: path });
    }
  }
  return found;
}

/** 正文归一化：去脚本/样式/注释/标签，解常见实体，折叠空白。 */
export function pageText(html) {
  let s = String(html ?? "");
  s = s.replace(/<!--[\s\S]*?-->/g, " ");
  s = s.replace(/<(script|style|noscript|template)\b[^>]*>[\s\S]*?<\/\1>/gi, " ");
  s = s.replace(/<[^>]+>/g, " ");
  s = s
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'");
  return s.replace(/\s+/g, " ").trim();
}

// 片段取自正文：ASCII 词（订单号 / 单名 / 邮箱前缀等）+ 中日韩连续汉字的二元组。
// 汉字没有空格分词，只抓 ASCII 词会让中文页面的归属证据永远是空 —— 那等于整族页面无罪也无证。
const ASCII_TOKEN_RE = /[A-Za-z0-9][A-Za-z0-9_\-]{3,}/g;
const CJK_RUN_RE = /[\u3400-\u9fff]{2,}/g;

function tokensOf(text) {
  const out = new Set();
  const s = String(text ?? "");
  for (const m of s.matchAll(ASCII_TOKEN_RE)) out.add(m[0].toLowerCase());
  for (const m of s.matchAll(CJK_RUN_RE)) {
    const run = m[0];
    for (let i = 0; i + 2 <= run.length; i += 1) out.add(run.slice(i, i + 2));
  }
  return out;
}

/** 正文里的原始片段（保留大小写，供响应正文逐字比对）+ 其小写键（供对照集合比对） */
function rawTokens(text) {
  const out = [];
  const s = String(text ?? "");
  for (const m of s.matchAll(ASCII_TOKEN_RE)) out.push(m[0]);
  for (const m of s.matchAll(CJK_RUN_RE)) {
    const run = m[0];
    for (let i = 0; i + 2 <= run.length; i += 1) out.push(run.slice(i, i + 2));
  }
  return out;
}

/**
 * 「只在本人页面出现」的片段：candidate 正文里有、而所有对照页面里都没有的片段。
 * 少于 min 个就返回空——两页只差一两个通用词不构成归属证明，
 * 宁可不判（inconclusive）也不能把结构相似度当成越权证据。
 */
export function distinctiveMarkers(candidateText, controlTexts, { min = 3, limit = 12 } = {}) {
  const controls = new Set();
  for (const t of controlTexts ?? []) for (const tok of tokensOf(t)) controls.add(tok);
  const out = [];
  const seen = new Set();
  for (const tok of rawTokens(candidateText)) {
    const low = tok.toLowerCase();
    if (controls.has(low) || seen.has(low)) continue;
    seen.add(low);
    out.push(tok);
    if (out.length >= limit) break;
  }
  return out.length >= min ? out : [];
}

/** 攻击响应里命中了多少个归属片段（全部命中才算证据成立，避免部分巧合）。 */
export function markersInText(markers, text) {
  const body = String(text ?? "");
  const hit = (markers ?? []).filter((m) => body.includes(m));
  return { hit, all: hit.length === (markers?.length ?? 0) && hit.length > 0 };
}
