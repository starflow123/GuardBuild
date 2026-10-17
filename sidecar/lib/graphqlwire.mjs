/**
 * GraphQL 动态探测层的线协议工具（纯函数，无 IO）。
 *
 * 协议对照 express-graphql / Apollo / graphql-yoga / mercurius 的 HTTP 形态：
 *  - 单一端点（缺省 POST /graphql），请求体 `{query, variables}`；查询与变更都走 POST
 *  - 成功信封 `{data: {字段名: …}}`；错误 `{errors: [{message, extensions: {code}}]}`
 *  - 拒绝语义两种流派：按 extensions.code 映射 HTTP 状态（UNAUTHENTICATED 401 / FORBIDDEN 403 /
 *    NOT_FOUND 404），或统一 HTTP 200 + errors（Apollo Server v4 形态）→ 后者必须由本模块识别，
 *    否则「越权被拒绝」在 HTTP 层不可判（见 probe.mjs 的 res.graphqlDenied）
 *  - 参数投放由 SDL 声明类型决定（Int!/Float! → 数值，其余含 ID → 字符串）；SDL 与运行时不符时
 *    由 introspection 校正，仍不确定则按 GRAPHQL_VALIDATION_FAILED 翻转一次（见 negotiateGraphqlCast）
 *
 * 文档构造只用静态分析给出的字段/参数/选取集（graphql.mjs），不使用运行时 schema 造候选：
 * 候选必须可追溯到源码位置，否则报告无法指认修复点。
 */

/** 静态分析是否给出 GraphQL 候选 */
export function isGraphqlCandidate(cand) {
  return !!(cand && cand.graphql);
}

/** 路径是否为 GraphQL 端点形态（用于识别契约里写的 GraphQL 登录路径） */
export function looksLikeGraphqlPath(path) {
  return /(^|\/)graphql(\?|\/|$)/i.test(String(path ?? ""));
}

/** 变量名必须是合法标识符（参数名里的 "-" 等替换为下划线） */
function safeVar(name) {
  const s = String(name ?? "").replace(/[^\w$]/g, "_");
  return s && !/^\d/.test(s) ? s : "id";
}

/** 按 SDL 声明类型投放参数值；flip 用于「SDL 与运行时类型不一致」时翻转 */
export function castArg(id, typeName, flip = false) {
  let wantNumber = typeName === "Int" || typeName === "Float";
  if (flip) wantNumber = !wantNumber;
  if (!wantNumber) return String(id);
  const n = Number(id);
  return Number.isFinite(n) ? n : String(id);
}

function selectionText(g) {
  const sel = (g?.selection ?? []).filter(Boolean).join(" ");
  return sel ? `{ ${sel} }` : "";
}

/**
 * 构造取数文档与变量。返回 {query, variables}，不可构造（无参数/无选取集）返回 null。
 * 两种参数形态：标量参数（order(id: Int!)）与 Prisma 式 input 对象（order(where: OrderWhereInput!)）。
 */
export function graphqlDocument(g, id, flip = false) {
  if (!g?.field || !g.arg) return null;
  const sel = selectionText(g);
  if (!sel) return null;
  const op = g.op === "mutation" ? "mutation" : "query";
  const arg = g.arg;
  if (arg.form === "input") {
    const v = safeVar(arg.name);
    return {
      query: `${op} GuardbuildProbe($${v}: ${arg.inputType}!) { ${g.field}(${arg.name}: $${v}) ${sel} }`,
      variables: { [v]: { [arg.field]: castArg(id, arg.typeName, flip) } },
      argName: arg.name,
      typeName: arg.inputType,
    };
  }
  const v = safeVar(arg.name);
  return {
    query: `${op} GuardbuildProbe($${v}: ${arg.typeName}!) { ${g.field}(${arg.name}: $${v}) ${sel} }`,
    variables: { [v]: castArg(id, arg.typeName, flip) },
    argName: arg.name,
    typeName: arg.typeName,
  };
}

/** 按候选 + 对象 ID 生成请求（path/body/method）。非 GraphQL 候选或不可构造返回 null */
export function graphqlRequest(cand, id, flip = false) {
  if (!isGraphqlCandidate(cand)) return null;
  const path = cand.fullPath ?? cand.path;
  const doc = graphqlDocument(cand.graphql, id, flip);
  if (!path || !doc) return null;
  return { method: "POST", path, body: JSON.stringify({ query: doc.query, variables: doc.variables }), graphql: true };
}

/** 无参数文档（列表/管理端字段、匿名探测用）：`query GuardbuildList { orders { … } }` */
export function graphqlPlainRequest(graphql, path, label = "GuardbuildList") {
  const sel = selectionText(graphql);
  if (!graphql?.field || !sel || !path) return null;
  const op = graphql.op === "mutation" ? "mutation" : "query";
  return {
    method: "POST",
    path,
    body: JSON.stringify({ query: `${op} ${label} { ${graphql.field} ${sel} }`, variables: {} }),
    graphql: true,
  };
}

/** 登录 mutation：变量取契约身份字段（email/username/password），选取集来自 SDL 登录返回类型 */
export function graphqlLoginRequest(login, values) {
  const declared = (login?.args ?? []).filter((a) => a && !a.list && values?.[a.name] !== undefined && values[a.name] !== "");
  if (!login?.field || declared.length === 0 || declared.length !== (login.args ?? []).filter((a) => !a.list).length) {
    return null;
  }
  const sel = selectionText(login);
  const vars = {};
  const decls = [];
  const args = [];
  for (const a of declared) {
    const v = safeVar(a.name);
    decls.push(`$${v}: ${a.typeName}!`);
    vars[v] = castArg(values[a.name], a.typeName);
    args.push(`${a.name}: $${v}`);
  }
  const query = `mutation GuardbuildLogin(${decls.join(", ")}) { ${login.field}(${args.join(", ")})${sel ? ` ${sel}` : ""} }`;
  return { method: "POST", path: login.path, body: JSON.stringify({ query, variables: vars }), graphql: true };
}

/** introspection 查询：根字段（含参数类型）+ 全部对象类型的标量字段，用于端点确认与类型/选取集校正 */
const TYPE_REF = "kind name ofType { kind name ofType { kind name ofType { name } } }";
export const INTROSPECTION_QUERY =
  `query GuardbuildIntrospect { __schema { queryType { name fields { name args { name type { ${TYPE_REF} } ` +
  `type { ${TYPE_REF} } } } } mutationType { name fields { name } } types { kind name fields { name type { ${TYPE_REF} } } } } }`;

export function introspectionRequest(path) {
  return { method: "POST", path, body: JSON.stringify({ query: INTROSPECTION_QUERY, variables: {} }), graphql: false };
}

function walkType(t, pred) {
  let n = t;
  while (n) {
    if (pred(n)) return n;
    n = n.ofType;
  }
  return null;
}
const baseNameOf = (t) => walkType(t, (x) => Boolean(x?.name))?.name ?? null;
const isListType = (t) => Boolean(walkType(t, (x) => x?.kind === "LIST"));
const isWrapperKind = (k) => k === "LIST" || k === "NON_NULL";

/** 解析 introspection 响应 → {fields:{"Query.order":{...}}, types:{Order:["id",…]}, queryType, mutationType} */
export function parseIntrospection(json) {
  const sch = json?.data?.__schema ?? json?.__schema ?? null;
  if (!sch || typeof sch !== "object") return null;
  const out = { fields: {}, types: {}, queryType: sch.queryType?.name ?? null, mutationType: sch.mutationType?.name ?? null };
  for (const [op, root] of [["query", sch.queryType], ["mutation", sch.mutationType]]) {
    for (const f of root?.fields ?? []) {
      if (!f?.name) continue;
      out.fields[`${root.name}.${f.name}`] = {
        op,
        returns: baseNameOf(f.type),
        list: isListType(f.type),
        args: (f.args ?? []).map((a) => ({ name: a.name, typeName: baseNameOf(a.type), list: isListType(a.type) })),
      };
    }
  }
  for (const t of sch.types ?? []) {
    if (!Array.isArray(t?.fields) || !t.name) continue;
    out.types[t.name] = t.fields
      .filter((f) => {
        const base = walkType(f.type, (x) => !isWrapperKind(x?.kind));
        return base && (base.kind === "SCALAR" || base.kind === "ENUM");
      })
      .map((f) => f.name);
  }
  return out;
}

/** GraphQL 成功信封（严格判定：顶层只有 data，或 data + errors） */
export function isGraphqlEnvelope(json) {
  if (!json || typeof json !== "object" || Array.isArray(json)) return false;
  const keys = Object.keys(json);
  if (!keys.includes("data")) return false;
  return keys.every((k) => k === "data" || k === "errors");
}

/** 解开 `{data:…}` 信封；非信封响应原样返回，保证 REST/tRPC 目标行为不变 */
export function unwrapGraphqlEnvelope(json) {
  return isGraphqlEnvelope(json) ? json.data : json;
}

export function graphqlErrorCodes(json) {
  const errs = json && typeof json === "object" ? json.errors : null;
  if (!Array.isArray(errs)) return [];
  return errs.map((e) => String(e?.extensions?.code ?? e?.code ?? "")).filter(Boolean);
}

// 拒绝语义码：认证/授权被拒。NOT_FOUND 不在列——「对象不存在」不是权限拒绝，不能据此判定攻击被阻断
const DENIAL_CODE =
  /^(?:UNAUTHENTICATED|UNAUTHORIZED|NOT_AUTHENTICATED|NOT_AUTHORIZED|FORBIDDEN|PERMISSION_DENIED|ACCESS_DENIED|NOT_ALLOWED|AUTH_REQUIRED|NO_TOKEN|INVALID_TOKEN|TOKEN_EXPIRED|NOT_AUTH)/i;
const DENIAL_TEXT =
  /not\s+(?:authenticated|authorized|logged\s?in)|unauthoriz|forbidden|permission\s+denied|access\s+denied|authentication\s+required|login\s+required|must\s+be\s+(?:logged\s?in|authenticated)|未登录|未认证|无权限|无权限/i;

/**
 * 响应是否为「GraphQL 层的访问拒绝」（HTTP 200 + errors 形态）。
 * 只在明确命中拒绝码/文案时为真：普通校验错误、对象不存在、服务端异常都不算被阻断，
 * 以免把「探测失败」粉饰成「修复生效」（gate 假放行是本项目的红线）。
 */
export function isGraphqlDenied(json) {
  const errs = json && typeof json === "object" ? json.errors : null;
  if (!Array.isArray(errs) || errs.length === 0) return false;
  return errs.some((e) => {
    const code = String(e?.extensions?.code ?? e?.code ?? "");
    if (DENIAL_CODE.test(code)) return true;
    return DENIAL_TEXT.test(String(e?.message ?? ""));
  });
}

/** 参数形态被拒（变量类型不符/文档不合法）：HTTP 400 或校验类错误码，用于类型翻转重试 */
export function graphqlShapeRejected(res) {
  if (!res) return false;
  if (res.status === 400) return true;
  const codes = graphqlErrorCodes(res.jsonRaw ?? res.json);
  return codes.some((c) => /^(?:GRAPHQL_VALIDATION_FAILED|VALIDATION_ERROR|GRAPHQL_PARSE_FAILED|BAD_REQUEST|PARSE_ERROR)$/i.test(c));
}
