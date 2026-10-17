/**
 * GraphQL 适配器：SDL（.graphql/.gql 或 typeDefs 模板）+ resolver/指令/规则表信号
 * → 统一「伪区块」（style: "graphql"），供 analyzer 的候选循环与动态探测层消费。
 *
 * 与其它适配器的根本差异：GraphQL 只有一个 HTTP 端点（缺省 POST /graphql），
 * 「寻址」不在 URL 上而在查询文档的字段与参数里。因此本适配器产出的不是 URL 参数形态，
 * 而是可构造文档所需的结构化事实：根类型（Query/Mutation）、字段名、可寻址参数、
 * 返回类型及其可选标量集合（selection），线协议构造见 graphqlwire.mjs。
 *
 * 覆盖形态（vibecoding 主流写法）：
 *  - schema-first SDL：.graphql/.gql 文件、typeDefs/schema = gql`type Query {…}`、Python """…""" 内的 SDL
 *  - resolver 映射表：resolvers = { Query: { order: async (p, args, ctx) => {…} } }（鉴权/归属信号取函数体）
 *  - 装饰器 code-first：type-graphql / @nestjs/graphql 的 @Query/@Mutation 方法（@Authorized/@UseGuards/@Roles）
 *  - graphql-shield 规则表：shield({ Query: { order: isAuthenticated } })（含 "Query.*" 通配）
 *  - 字段指令：order(id: Int!): Order @auth / @hasRole(role: "ADMIN") / @skipAuth
 *
 * 鉴权判定优先级：字段显式 public 指令（@skipAuth/@public/@guest）> 字段 auth 指令 >
 * shield 规则 > resolver 体内的会话读取（ctx.user/req.user 等，走 signals 的统一正则）>
 * 服务端全局鉴权（applyMiddleware({middlewares:[auth…]}) / onRequest 含 auth 守卫）。
 *
 * v1 已知缺口（一律按「静态无候选 → 不建基线」诚实降级，不做猜测式报警）：
 *  - 返回**列表**且带 ID 参数的字段（如 ordersByUser(userId: ID!): [Order!]!）不作为读候选：
 *    现有证据判定按单体响应形状取证，列表形态需按归属逐条核验后才能定论（待后续专项）；
 *  - 无 SDL 的纯 code-first（Nexus / Schema Builder / type-graphql 无 schema 文件）：resolver 信号仍在，
 *    但字段参数与返回类型只能来自运行时 introspection；本适配器不用运行时 schema 造候选，
 *    introspection 仅用于端点确认与参数类型/选取集校验（见 probe.mjs 的 confirmGraphqlEndpoint）；
 *  - 别名根类型（schema { query: MyQuery }）、fragment/订阅（WS 协议）、路径穿越类文件读取形态不覆盖；
 *  - 无自动修复策略（GraphQL 鉴权分散在 middleware/shield/resolver 三层，锚点注入易破坏语义）→
 *    证据成立即 vulnerable_unfixed 阻断并给人工修复指引。
 */
import { AUTH_GUARD, OWNER_FILTER, OWNER_GUARD, ROLE_GUARD, braceSpan, findBodyOpen } from "./signals.mjs";
import { scanEntries } from "./trpc.mjs";

const norm = (p) => String(p).replace(/\\/g, "/");
const lineOf = (content, index) => content.slice(0, index).split("\n").length;

const SDL_EXT = [".graphql", ".gql"];
const SCALAR_TYPE = new Set(["Int", "Float", "String", "ID", "Boolean"]);
const MAX_SELECTION = 8;
const ROOTS = { Query: "query", Mutation: "mutation" };

// GraphQL 服务端/库来源标记：只有这类文件才参与解析，避免把普通对象字面量当作 resolver 表
const GQL_LIB =
  /@apollo|apollo-server|graphql-yoga|\bmercurius\b|fastify-gql|@nestjs\/graphql|type-graphql|\bnexus\b|graphql-shield|express-graphql|graphql-http|from\s+["']graphql["']|\bgql\b/i;
const GQL_SERVER =
  /\bnew\s+GraphQLServer\b|\bnew\s+ApolloServer\b|GraphQLModule|graphqlHTTP|createYoga|makeExecutableSchema|buildSchema|\bGraphQLView\b|GraphQLRouter|GraphQLSchema\b|@Query\s*\(|@Mutation\s*\(|typeDefs\s*[:=]/;
// SDL 特征：类型定义块（含 extend），用于判定一段文本是否为 schema
const SDL_HINT = /(^|\n)[ \t]*(?:extend[ \t]+)?(?:type|input|enum|interface|scalar)\s+[A-Za-z_]\w*/;

/** 文件是否与 GraphQL 相关（SDL 文件、含 SDL 模板的代码文件、含服务端接线/装饰器的文件） */
export function isGraphqlFile(file) {
  const p = norm(file?.path ?? "");
  const ext = p.slice(p.lastIndexOf(".")).toLowerCase();
  if (SDL_EXT.includes(ext)) return true;
  const content = file?.content ?? "";
  if (!content) return false;
  if (SDL_HINT.test(content) && /type\s+(Query|Mutation)\b/.test(content)) return true;
  return GQL_LIB.test(content) || GQL_SERVER.test(content);
}

/** 取文件中的 SDL 文本块：.graphql 全文 / `typeDefs = gql`…`模板 / Python """…""" */
export function extractSdlChunks(file) {
  const p = norm(file?.path ?? "");
  const content = file?.content ?? "";
  const ext = p.slice(p.lastIndexOf(".")).toLowerCase();
  if (!content) return [];
  if (SDL_EXT.includes(ext)) return [{ text: content, index: 0 }];
  const out = [];
  for (const m of content.matchAll(/`([^`]{40,}?)`/g)) {
    if (SDL_HINT.test(m[1])) out.push({ text: m[1], index: m.index });
  }
  for (const m of content.matchAll(/"""([\s\S]{40,}?)"""/g)) {
    if (SDL_HINT.test(m[1])) out.push({ text: m[1], index: m.index });
  }
  return out;
}

/** SDL 注释为 # 到行尾（字符串内的 # 罕见，按整词剥离处理不作保证） */
function stripComments(text) {
  return String(text)
    .split("\n")
    .map((l) => l.replace(/(^|\s)#.*$/, ""))
    .join("\n");
}

/** `[Order!]!` → {base:"Order", list:true, nonNull:true}（不支持嵌套二维列表） */
export function normalizeType(raw) {
  let s = String(raw ?? "").trim();
  const nonNull = s.endsWith("!");
  if (nonNull) s = s.slice(0, -1).trim();
  const list = s.startsWith("[") && s.endsWith("]");
  if (list) s = s.slice(1, -1).replace(/!$/, "").trim();
  return { base: s, list, nonNull, raw: String(raw ?? "").trim() };
}

/** 参数列表文本 → [{name, type}]（默认值 `= {…}` 丢弃） */
function parseArgDefs(text) {
  const out = [];
  for (const seg of splitTopLevel(text)) {
    const m = /^\s*([A-Za-z_]\w*)\s*:\s*([^=]+?)\s*(?:=[\s\S]*)?$/.exec(seg);
    if (!m) continue;
    out.push({ name: m[1], type: normalizeType(m[2]) });
  }
  return out;
}

/** 顶层逗号切分（跳过括号/方括号/花括号/引号内） */
function splitTopLevel(text) {
  const out = [];
  let depth = 0;
  let quote = null;
  let cur = "";
  for (const ch of String(text)) {
    if (quote) {
      cur += ch;
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      cur += ch;
      continue;
    }
    if (ch === "(" || ch === "[" || ch === "{") depth += 1;
    else if (ch === ")" || ch === "]" || ch === "}") depth -= 1;
    if (ch === "," && depth === 0) {
      out.push(cur);
      cur = "";
      continue;
    }
    cur += ch;
  }
  if (cur.trim()) out.push(cur);
  return out;
}

/** 从 openIdx 处的括号找到配平闭括号（跳过引号）；未配平返回 -1 */
function matchParen(text, openIdx) {
  let depth = 0;
  let quote = null;
  for (let i = openIdx; i < text.length; i += 1) {
    const ch = text[i];
    if (quote) {
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'") quote = ch;
    else if (ch === "(") depth += 1;
    else if (ch === ")") {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return -1;
}

/**
 * 类型正文 → 字段定义列表 [{name, args, type, directives, index}]。
 * 逐字段扫描：名称 →（可选参数括号）→ ":" → 类型 → 同行紧随的 @ 即指令（取到行尾）。
 * 同一行写多个字段（`type User { id: Int! email: String! }`）与跨行字段均可解析；
 * 无法识别的片段按字符跳过（enum 值、纯指令声明等）。
 */
function parseFieldDefs(body) {
  const out = [];
  let i = 0;
  while (i < body.length) {
    while (i < body.length && /[\s,]/.test(body[i])) i += 1;
    const nameM = /^[A-Za-z_]\w*/.exec(body.slice(i));
    if (!nameM) {
      i += 1;
      continue;
    }
    const start = i;
    let p = i + nameM[0].length;
    while (p < body.length && /\s/.test(body[p])) p += 1;
    let args = [];
    if (body[p] === "(") {
      const close = matchParen(body, p);
      if (close < 0) break;
      args = parseArgDefs(body.slice(p + 1, close));
      p = close + 1;
    }
    while (p < body.length && /\s/.test(body[p])) p += 1;
    if (body[p] !== ":") {
      const nl = body.indexOf("\n", p);
      i = nl < 0 ? body.length : nl + 1;
      continue;
    }
    p += 1;
    const typeM = /^\s*(\[[^\]]*\]\s*!?!?|[A-Za-z_]\w*\s*!?)/.exec(body.slice(p));
    if (!typeM) {
      const nl = body.indexOf("\n", p);
      i = nl < 0 ? body.length : nl + 1;
      continue;
    }
    p += typeM[0].length;
    let directives = "";
    const dirM = /^([ \t]*@[^\n]*)/.exec(body.slice(p));
    if (dirM) {
      directives = dirM[1].trim();
      p += dirM[1].length;
      const nl = body.indexOf("\n", p);
      i = nl < 0 ? body.length : nl + 1;
    } else {
      i = p;
    }
    out.push({ name: nameM[0], args, type: normalizeType(typeM[1]), directives, index: start });
  }
  return out;
}

const DEF_RE = /^[ \t]*(?:extend[ \t]+)?(type|input|interface|enum|scalar)[ \t]+([A-Za-z_]\w*)([^\n]*)/gm;

/**
 * 解析一段 SDL → { types: Map<name,{kind,fields}>, enums:Set, scalars:Set }。
 * 同名类型（extend type Query）由调用方合并。
 */
export function parseSdl(text) {
  const src = stripComments(text);
  const types = new Map();
  const enums = new Set();
  const scalars = new Set();
  let m;
  DEF_RE.lastIndex = 0;
  while ((m = DEF_RE.exec(src))) {
    const kind = m[1];
    const name = m[2];
    if (kind === "scalar") {
      scalars.add(name);
      continue;
    }
    const headEnd = m.index + m[0].length;
    const braceRel = m[0].indexOf("{");
    let braceIdx = braceRel >= 0 ? m.index + braceRel : -1;
    if (braceIdx < 0) {
      const gap = /^\s*/.exec(src.slice(headEnd));
      const cand = headEnd + gap[0].length;
      if (src[cand] === "{") braceIdx = cand;
    }
    if (braceIdx < 0) {
      types.set(name, { kind, fields: [], index: m.index });
      continue;
    }
    const end = braceSpan(src, braceIdx);
    const body = src.slice(braceIdx + 1, end > braceIdx ? end : src.length);
    if (kind === "enum") {
      // enums 收「枚举类型名」：选取集据此把 status: OrderStatus 这类字段当作标量叶子输出
      // （漏掉它会让取消/状态类证据在文档里没有对应字段，修复前后都无法判定）
      enums.add(name);
      types.set(name, { kind, fields: [], index: m.index });
      continue;
    }
    types.set(name, { kind, fields: parseFieldDefs(body), index: m.index, bodyIndex: braceIdx + 1 });
    DEF_RE.lastIndex = Math.max(DEF_RE.lastIndex, (end > braceIdx ? end : headEnd) + 1);
  }
  return { types, enums, scalars };
}

/** 合并多个 SDL 块（extend type Query / 分文件 schema） */
export function mergeSdl(chunks) {
  const types = new Map();
  const enums = new Set();
  const scalars = new Set(SCALAR_TYPE);
  const roots = []; // [{root, op, field, file, startLine}]
  for (const c of chunks) {
    const parsed = parseSdl(c.text);
    for (const [name, t] of parsed.types) {
      const cur = types.get(name) ?? { kind: t.kind, fields: [], file: c.file, index: t.index };
      for (const f of t.fields) {
        cur.fields.push({ ...f, file: c.file, startLine: lineOf(c.text, f.index) + (c.startLine ?? 1) - 1 });
      }
      types.set(name, cur);
    }
    for (const e of parsed.enums) enums.add(e);
    for (const s of parsed.scalars) scalars.add(s);
  }
  for (const [name, t] of types) {
    const op = ROOTS[name];
    if (!op || t.kind === "input") continue;
    for (const f of t.fields) roots.push({ root: name, op, field: f, file: f.file ?? t.file, startLine: f.startLine ?? 1 });
  }
  return { types, enums, scalars, roots };
}

/** 类型的可选标量字段（对象字段展开一层，供 login 之类返回 payload 的字段取 user{id…}） */
export function selectionFor(types, enums, scalars, typeName, depth = 0) {
  const t = types.get(typeName);
  if (!t) return [];
  const out = [];
  for (const f of t.fields) {
    if (f.name.startsWith("__")) continue;
    if (SCALAR_TYPE.has(f.type.base) || enums.has(f.type.base) || scalars.has(f.type.base)) {
      out.push(f.name);
      continue;
    }
    if (depth >= 1 || f.type.list) continue;
    const sub = selectionFor(types, enums, scalars, f.type.base, depth + 1);
    if (sub.length > 0) out.push(`${f.name} { ${sub.join(" ")} }`);
  }
  return out.slice(0, MAX_SELECTION);
}

// ID 形态参数名：id / orderId / orderID / user_id / uuid（纯后缀形态，避免 "paid"/"valid" 之类误判）
const ID_NAME = /^(?:id|[A-Za-z_$][\w$]*(?:Id|ID|_id|_ID|uuid|UUID))$/;
const NON_ID_NAME = /^(?:limit|offset|first|last|after|before|sort|order[_-]?(?:by)?|page|perPage|take|skip|search|query|filter|status)$/i;

/** 选出可寻址参数：标量 ID 参数，或 Prisma 式 input 对象（where/input: X 且内含唯一 ID 标量字段） */
export function pickAddressArg(args, types) {
  const scalars = [];
  for (const a of args ?? []) {
    const t = a.type;
    if (!t || t.list) continue;
    if (SCALAR_TYPE.has(t.base)) {
      if (ID_NAME.test(a.name) && !NON_ID_NAME.test(a.name)) scalars.push({ name: a.name, typeName: t.base, nonNull: t.nonNull });
      continue;
    }
    const it = types.get(t.base);
    if (it?.kind !== "input") continue;
    const inner = (it.fields ?? []).filter((f) => SCALAR_TYPE.has(f.type.base) && ID_NAME.test(f.name) && !NON_ID_NAME.test(f.name));
    if (inner.length === 1) {
      return {
        form: "input",
        name: a.name,
        inputType: t.base,
        field: inner[0].name,
        typeName: inner[0].type.base,
        nonNull: t.nonNull,
      };
    }
  }
  if (scalars.length === 0) return null;
  // 多个 ID 形态标量参数（如 senderId+receiverId）无法确定「对象主键」，不作候选
  if (scalars.length > 1) return null;
  return { form: "scalar", ...scalars[0] };
}

const DIR_AUTH = /(^|\s)@(auth|authenticated|requireAuth|requiresAuth|protected|private|isAuthenticated|guard|restricted|authorized|loginRequired|loggedIn)\b/i;
const DIR_ROLE = /(^|\s)@(hasRole|roles|role|admin|adminOnly|requireRole|permission|permissions|scope)\b/i;
const DIR_PUBLIC = /(^|\s)@(public|skipAuth|noAuth|guest|anon|anonymous|unauthenticated|isPublic|permit)\b/i;
const RULE_AUTH = /auth|guard|permission|protected|session|login|jwt|token|verified|user/i;
const RULE_ROLE = /admin|role|superuser|moderator|staff/i;
const RULE_PUBLIC = /^(?:permit|allow|public|always|true)$/i;

/** 解析器映射表 / 装饰器 / shield 规则 → 按 "Query.order" 归集的实现与规则文本 */
export function collectFieldImplementations(files) {
  const out = new Map();
  const slot = (key) => {
    if (!out.has(key)) out.set(key, { resolver: null, rule: null });
    return out.get(key);
  };
  for (const f of files) {
    const content = f?.content ?? "";
    if (!content) continue;
    const path = norm(f.path);

    // 1) resolver 映射表：Query: { order: async (…) => {…} }（含 Subscription 与自定义 root）
    for (const m of content.matchAll(/\b(Query|Mutation|Subscription)\s*:\s*\{/g)) {
      const open = m.index + m[0].length - 1;
      const end = braceSpan(content, open);
      if (end < 0) continue;
      for (const e of scanEntries(content, open + 1, end)) {
        if (!/^[A-Za-z_]\w*$/.test(e.key) || e.key.startsWith("__")) continue;
        const valueText = content.slice(e.valStart, e.valEnd).trim();
        const isImpl = /(?:^|[\s(])async\s|=>|\bfunction\b|\bresolve\s*:/.test(valueText);
        const isRef = /^\s*(?:[A-Za-z_$][\w$]*\s*\.\s*)*[A-Za-z_$][\w$]*\s*$/.test(valueText);
        const s = slot(`${m[1]}.${e.key}`);
        if (isImpl) s.resolver = { text: valueText, file: path, line: lineOf(content, e.valStart) };
        else if (isRef && !s.resolver) s.rule = valueText;
      }
    }

    // 2) shield 规则表：shield({ Query: { order: isAuthenticated }, Mutation: { "*": isAuthenticated } })
    for (const m of content.matchAll(/\bshield\s*\(\s*\{/g)) {
      const open = m.index + m[0].length - 1;
      const end = braceSpan(content, open);
      if (end < 0) continue;
      const body = content.slice(open + 1, end);
      for (const root of ["Query", "Mutation", "Subscription"]) {
        const rm = new RegExp(`\\b${root}\\s*:\\s*\\{`).exec(body);
        if (!rm) continue;
        const ro = rm.index + rm[0].length - 1;
        const re2 = braceSpan(body, ro);
        if (re2 < 0) continue;
        for (const e of scanEntries(body, ro + 1, re2)) {
          const s = slot(`${root}.${e.key}`);
          if (!s.rule) s.rule = body.slice(e.valStart, e.valEnd).trim();
        }
        for (const wc of body.slice(ro + 1, re2).matchAll(/["']\*["']\s*:\s*([A-Za-z_$][\w$]*)/g)) {
          const s = slot(`${root}.*`);
          if (!s.rule) s.rule = wc[1];
        }
      }
    }

    // 3) 装饰器 code-first：@Query(() => Order) / @Mutation("cancelOrder") + 方法体（前置 @Authorized/@UseGuards/@Roles）
    // 装饰器实参可能含嵌套括号（`() => Order` 是 NestJS GraphQL 的标准写法），必须按括号配平取右界
    const DECORATOR_RE = /@(Query|Mutation|Subscription)\s*\(/g;
    let dm;
    while ((dm = DECORATOR_RE.exec(content))) {
      const openParen = dm.index + dm[0].length - 1;
      const closeParen = matchParen(content, openParen);
      if (closeParen < 0) continue;
      const after = closeParen + 1;
      const sigM = /^[ \t\r\n]*(?:(?:public|private|protected|readonly|static|async)[ \t]+)*([A-Za-z_]\w*)[ \t]*(?:!\s*)?\(/.exec(content.slice(after));
      DECORATOR_RE.lastIndex = closeParen + 1;
      if (!sigM) continue;
      const declared = /^\s*["'`]([^"'`]+)["'`]/.exec(content.slice(openParen + 1, closeParen));
      const fieldName = declared ? declared[1] : sigM[1];
      const methodOpenParen = after + sigM[0].length - 1;
      const bodyOpen = findBodyOpen(content, methodOpenParen);
      const bodyEnd = bodyOpen >= 0 ? braceSpan(content, bodyOpen) : -1;
      const before = content.slice(Math.max(0, dm.index - 300), dm.index);
      const methodText = bodyEnd > bodyOpen ? content.slice(dm.index, bodyEnd + 1) : dm[0];
      const s = slot(`${dm[1]}.${fieldName}`);
      s.resolver = { text: `${before}\n${methodText}`, file: path, line: lineOf(content, dm.index), decorator: true };
    }
  }
  return out;
}

function normEndpointPath(raw, prefix = "") {
  const s = String(raw ?? "").replace(/\\/g, "/").trim();
  if (!s) return null;
  const withSlash = s.startsWith("/") ? s : `/${s}`;
  const joined = prefix ? `${prefix}${withSlash}`.replace(/\/{2,}/g, "/") : withSlash;
  return joined.length > 1 ? joined.replace(/\/+$/, "") : joined;
}

/**
 * 端点探测：接线里的显式 path > Next.js 路由文件位置 > 全局前缀拼接 > 缺省 /graphql。
 * 只取含 graphql 字样的路径形态，避免把 REST 挂载点当作 GraphQL 端点。
 */
export function detectGraphqlEndpoint(files, projectRoot = null) {
  const list = files ?? [];
  const contentOf = (f) => f?.content ?? "";
  const patterns = [
    /applyMiddleware\s*\(\s*\{[\s\S]{0,300}?\bpath\s*:\s*["'`]([^"'`]+)["'`]/,
    /GraphQLModule\.forRoot[\s\S]{0,800}?\bpath\s*:\s*["'`]([^"'`]+)["'`]/,
    /createYoga\s*\(\s*\{[\s\S]{0,300}?graphqlEndpoint\s*:\s*["'`]([^"'`]+)["'`]/,
    /\bregister\s*\(\s*(?:mercurius|fastifyGraphQl|graphql)\s*,\s*\{[\s\S]{0,300}?\bpath\s*:\s*["'`]([^"'`]+)["'`]/,
    /(?:app|server|router|fastify)\s*\.\s*use\s*\(\s*["'`]([^"'`]*graphql[^"'`]*)["'`]/i,
    /\bGraphQL\s*\([\s\S]{0,300}?route\s*=\s*["'`](\/[^"'`]*graphql[^"'`]*)["'`]/,
    /\bpath\s*\(\s*["'`]([^"'`]*graphql[^"'`]*)["'`]\s*,\s*GraphQL/,
    /\broute\s*=\s*["'`](\/[^"'`]*graphql[^"'`]*)["'`]/,
  ];
  for (const f of list) {
    const c = contentOf(f);
    for (const re of patterns) {
      const m = re.exec(c);
      if (!m) continue;
      const ep = normEndpointPath(m[1]);
      if (ep) return ep;
    }
  }
  // Next.js 形态：pages/api/graphql.ts / app/api/graphql/route.ts → 文件位置即 URL
  const root = String(projectRoot ?? "").replace(/[\\/]+$/, "");
  for (const f of list) {
    let rel = norm(f.path ?? "");
    if (root && rel.startsWith(norm(root))) rel = "/" + rel.slice(norm(root).length).replace(/^\/+/, "");
    const m = /(?:^|\/)(?:app|pages)\/(api(?:\/[^\[]*)?)\/graphql(?:\.[A-Za-z]+|\/route\.[A-Za-z]+)$/.exec(rel);
    // m[1] 是 api 前缀（不含 graphql 段）：端点 = 前缀 + /graphql
    if (m) return normEndpointPath("graphql", `/${m[1].replace(/^\/+|\/+$/g, "")}`);
  }
  // NestJS 全局前缀：GraphQLModule 存在时把 setGlobalPrefix 计入
  const hasNestGraphql = list.some((f) => /GraphQLModule/.test(contentOf(f)));
  if (hasNestGraphql) {
    for (const f of list) {
      const gp = /setGlobalPrefix\s*\(\s*["'`]([^"'`]+)["'`]/.exec(contentOf(f));
      if (gp) return normEndpointPath("graphql", `/${gp[1].replace(/^\/+|\/+$/g, "")}`);
    }
  }
  return "/graphql";
}

/** 服务端全局鉴权：middlewares/onRequest 里挂了名字含 auth/guard/shield 的钩子（挂载级，等价 Express 的 app.use 守卫） */
export function detectGraphqlMountAuth(files) {
  let auth = false;
  let role = false;
  let source = null;
  for (const f of files ?? []) {
    const c = f?.content ?? "";
    for (const m of c.matchAll(/\b(?:middlewares|onRequest|requestPipeline|guards)\s*:\s*(?:async\s*)?\[[^\]]{0,300}\]/g)) {
      if (/auth|guard|shield|permission|session|jwt|login/i.test(m[0])) {
        auth = true;
        source = source ?? `${norm(f.path)}`;
        if (/admin|role|permission/i.test(m[0])) role = true;
      }
    }
  }
  return { auth, role, source };
}

const LOGIN_FIELD = /^(?:login|signIn|signin|authenticate|loginWithPassword|authLogin)$/i;

/**
 * 汇总 GraphQL 区块。files 为 [{path, content}]。
 * 返回 { sections, endpoint, login, diag }；sections 与其它框架区块同构，style 固定 "graphql"。
 */
export function collectGraphqlSections(files, projectRoot = null) {
  const diag = {
    graphqlFiles: 0,
    graphqlSdlBlocks: 0,
    graphqlTypes: 0,
    graphqlFields: 0,
    graphqlEndpoint: null,
    graphqlAuthSource: null,
    graphqlLoginField: null,
  };
  const list = (files ?? []).filter((f) => isGraphqlFile(f));
  if (list.length === 0) return { sections: [], endpoint: null, login: null, diag };
  diag.graphqlFiles = list.length;

  const chunks = [];
  for (const f of list) {
    for (const c of extractSdlChunks(f)) {
      const rel = norm(f.path);
      chunks.push({ ...c, file: rel, startLine: lineOf(f.content ?? "", c.index) });
    }
  }
  diag.graphqlSdlBlocks = chunks.length;
  if (chunks.length === 0) return { sections: [], endpoint: null, login: null, diag };
  const { types, enums, scalars, roots } = mergeSdl(chunks);
  diag.graphqlTypes = types.size;
  diag.graphqlFields = roots.length;

  const endpoint = detectGraphqlEndpoint(list, projectRoot);
  diag.graphqlEndpoint = endpoint;
  const impls = collectFieldImplementations(list);
  const mount = detectGraphqlMountAuth(list);

  const sections = [];
  let login = null;
  for (const r of roots) {
    const field = r.field;
    if (field.name.startsWith("__")) continue;
    const impl = impls.get(`${r.root}.${field.name}`) ?? impls.get(`${r.root}.*`) ?? {};
    const resolverText = impl.resolver?.text ?? "";
    const ruleText = impl.rule ?? null;
    const rule = String(ruleText ?? "").trim();

    const resultType = field.type.base;
    const selection = selectionFor(types, enums, scalars, resultType);
    const arg = field.type.list ? null : pickAddressArg(field.args, types);
    // 可寻址 = 单一对象返回 + 有 ID 形态参数 + 返回类型可选出标量字段（内容证据需要 id）
    const addressable = !!arg && !field.type.list && selection.length > 0 && selection.includes("id");

    // 指令 / 规则 / resolver / 全局四层信号
    const dirPublic = DIR_PUBLIC.test(field.directives ?? "");
    const dirAuth = DIR_AUTH.test(field.directives ?? "");
    const dirRole = DIR_ROLE.test(field.directives ?? "");
    const rulePublic = rule ? RULE_PUBLIC.test(rule) : false;
    const ruleAuth = rule ? !rulePublic && RULE_AUTH.test(rule) : false;
    const ruleRole = rule ? RULE_ROLE.test(rule) : false;
    const forcedAuth = !dirPublic && !rulePublic && (dirAuth || ruleAuth || mount.auth || AUTH_GUARD.test(resolverText));
    const roleGuard = dirRole || ruleRole || mount.role;

    // text 供 analyzer 的统一信号正则使用（SINK/OWNER_*/AUTH_*），因此把 SDL 行与 resolver 体都并入
    const text = [
      `${r.root}.${field.name}: ${field.type.raw}${field.directives ? ` ${field.directives}` : ""}`,
      (field.args ?? []).map((a) => `${a.name}: ${a.type.raw}`).join(", "),
      resolverText,
      ruleText ?? "",
    ].join("\n");

    const section = {
      file: impl.resolver?.file ?? r.file,
      startLine: impl.resolver?.line ?? r.startLine,
      method: "POST", // GraphQL 传输层只有 POST（查询文档走请求体）
      style: "graphql",
      declaredPath: endpoint,
      text,
      graphql: {
        root: r.root,
        op: r.op,
        field: field.name,
        arg,
        resultType,
        list: field.type.list,
        selection,
        addressable,
        directives: (field.directives ?? "").trim() || null,
        rule: rule || null,
      },
      routeKeys: [`${r.root}.${field.name}`],
    };
    if (forcedAuth) section.forcedAuth = true;
    if (roleGuard) section.roleGuard = true;
    sections.push(section);

    if (r.op === "mutation" && LOGIN_FIELD.test(field.name) && !login) {
      const argNames = (field.args ?? []).map((a) => a.name);
      login = {
        path: endpoint,
        field: field.name,
        args: (field.args ?? []).map((a) => ({ name: a.name, typeName: a.type.base, list: a.type.list })),
        argNames,
        selection,
        resultType,
      };
      diag.graphqlLoginField = field.name;
    }
  }
  if (mount.auth) diag.graphqlAuthSource = mount.source ?? "global-middleware";

  return { sections, endpoint, login, diag };
}

// 归属/信号正则的再导出：适配器内部不直接使用，保留给测试与后续复用（避免各处重复 require signals）
export const GRAPHQL_SIGNALS = { AUTH_GUARD, OWNER_GUARD, OWNER_FILTER, ROLE_GUARD };
