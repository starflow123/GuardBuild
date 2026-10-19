/**
 * OpenAPI / Swagger 路由线索解析。
 *
 * 用途：目标项目是静态适配器认不出的框架（自研 MVC、Rails、Spring 等），
 * 但项目里有 openapi.json / swagger.json。本模块把它转成和 analyzer.mjs 适配器
 * 完全一致的 endpoint 结构，让 planner/probe 走同一通道。
 *
 * 安全边界：
 *  - OpenAPI 声明的 security 只填 hasAuth=true 并标 authSource="openapi-declared"，
 *    不盲信——动态 probe 仍会实际发请求验证；
 *  - 不读凭证、不发请求，只做 JSON 解析与路径归一化；
 *  - 路径参数 {id} → :id；in=query 参数 → queryParam；
 *  - 总数上限 200 条 path，超出截断并 warning。
 */
import { RPC_TO_HOST } from "../../shared/protocol.mjs";

export const MAX_OPENAPI_PATHS = 200;

const HTTP_METHODS = new Set(["get", "post", "put", "patch", "delete", "head", "options"]);

/** 把 OpenAPI 路径模板 /users/{id} 转成内部形态 /users/:id */
function toInternalPath(openApiPath) {
  return String(openApiPath ?? "").replace(/\{([^}]+)\}/g, ":$1");
}

/** 从 OpenAPI servers[0].url 推 basePath；失败返回 null */
function inferBasePath(doc) {
  const servers = Array.isArray(doc?.servers) ? doc.servers : [];
  for (const s of servers) {
    const url = typeof s?.url === "string" ? s.url : "";
    if (!url) continue;
    try {
      const u = new URL(url);
      if (u.pathname && u.pathname !== "/") return u.pathname.replace(/\/+$/, "");
    } catch {
      // 相对路径，取其 pathname 部分
      const m = /^([a-z]+:\/\/[^/]+)?(\/[^?#]*)?/i.exec(url);
      if (m && m[2] && m[2] !== "/") return m[2].replace(/\/+$/, "");
    }
  }
  return null;
}

/** 合并 basePath 与 path（折叠重复斜杠） */
function joinPath(basePath, path) {
  const b = String(basePath ?? "").replace(/\/+$/, "");
  const p = String(path ?? "/").replace(/^\/+/, "");
  const joined = b ? `${b}/${p}` : `/${p}`;
  return joined.replace(/\/{2,}/g, "/") || "/";
}

/** 从 operation.parameters 提取路径/查询参数线索 */
function extractParams(parameters) {
  const out = { pathParams: [], queryParams: [] };
  if (!Array.isArray(parameters)) return out;
  for (const p of parameters) {
    if (!p || typeof p !== "object") continue;
    if (p.in === "path") out.pathParams.push(String(p.name ?? ""));
    else if (p.in === "query") out.queryParams.push(String(p.name ?? ""));
  }
  return out;
}

/** 该 operation 是否声明了 security（顶层 security 作 fallback） */
function hasSecurity(doc, operation) {
  if (operation && Array.isArray(operation.security)) {
    // 空数组 = 显式放行；非空 = 声明需要鉴权
    return operation.security.length > 0;
  }
  return Array.isArray(doc?.security) && doc.security.length > 0;
}

/** 从路径猜资源名（/users/{id} → user） */
function guessResource(fullPath) {
  const m = String(fullPath ?? "").match(/\/([a-z][a-z0-9_-]{2,})(?:\/:|\/\{|$)/i);
  if (!m) return "resource";
  let word = m[1].toLowerCase();
  if (word.endsWith("ies")) word = word.slice(0, -3) + "y";
  else if (word.endsWith("ses")) word = word.slice(0, -2);
  else if (word.endsWith("s") && !word.endsWith("ss")) word = word.slice(0, -1);
  return word;
}

/**
 * 解析 OpenAPI 文档为内部 endpoint 数组。
 * @param {object} doc 已 JSON.parse 的 openapi/swagger 文档
 * @param {object} cfg guardbuild.json 里的 openapi 字段
 * @returns {{ endpoints: object[], warnings: string[] }}
 */
export function parseOpenapiDoc(doc, cfg = {}) {
  const warnings = [];
  const endpoints = [];
  if (!doc || typeof doc !== "object") {
    return { endpoints, warnings: ["OpenAPI 文档为空或不是对象"] };
  }
  const paths = doc.paths && typeof doc.paths === "object" ? doc.paths : null;
  if (!paths) {
    return { endpoints, warnings: ["OpenAPI 文档缺少 paths 字段"] };
  }

  const cfgBase = typeof cfg?.basePath === "string" && cfg.basePath.trim() ? cfg.basePath.trim() : null;
  const inferredBase = inferBasePath(doc);
  const basePath = cfgBase ?? inferredBase ?? "";

  const pathKeys = Object.keys(paths);
  if (pathKeys.length > MAX_OPENAPI_PATHS) {
    warnings.push(`OpenAPI 共 ${pathKeys.length} 条 path，超过上限 ${MAX_OPENAPI_PATHS}，仅解析前 ${MAX_OPENAPI_PATHS} 条`);
  }

  for (const rawPath of pathKeys.slice(0, MAX_OPENAPI_PATHS)) {
    const item = paths[rawPath];
    if (!item || typeof item !== "object") continue;
    // OpenAPI path item 可能直接是 operation，也可能是 {get: {...}, parameters: [...]}
    const opParameters = Array.isArray(item.parameters) ? item.parameters : [];
    for (const method of HTTP_METHODS) {
      const op = item[method];
      if (!op || typeof op !== "object") continue;

      const internalPath = toInternalPath(rawPath);
      const fullPath = joinPath(basePath, internalPath);
      const { pathParams, queryParams } = extractParams([...opParameters, ...(Array.isArray(op.parameters) ? op.parameters : [])]);

      const ep = {
        file: null,           // 外部线索无代码位置
        startLine: null,
        method: method.toUpperCase(),
        style: "openapi",
        path: internalPath,
        mountPrefix: basePath || null,
        fullPath,
        routeKeys: [fullPath],
        matchVars: [],
        hasAuth: hasSecurity(doc, op),
        authSource: hasSecurity(doc, op) ? "openapi-declared" : null,
        hasOwnerGuard: false,   // OpenAPI 不描述业务归属校验，统一按"未发现"处理，交给动态验证
        hasRoleGuard: false,
        hasOwnerFilter: false,
        sinkCalls: [],
        trpc: null,
        graphql: null,
        source: "openapi",
        resource: guessResource(fullPath),
      };
      // 查询参数线索：:param 形态优先于 query
      const hasPathParam = pathParams.length > 0 || /:[A-Za-z_]\w*/.test(internalPath);
      if (!hasPathParam && queryParams.length > 0) {
        ep.queryParam = { param: queryParams[0], in: "query" };
      }
      endpoints.push(ep);
    }
  }

  return { endpoints, warnings };
}

/**
 * 经 Host 读取并解析 openapi 文件。
 * @param {object} ctx 编排上下文（含 rpc / tokens / projectRoot）
 * @param {object} openapiCfg { file, basePath }
 */
export async function loadOpenapiEndpoints(ctx, openapiCfg) {
  const warnings = [];
  const file = typeof openapiCfg?.file === "string" ? openapiCfg.file.trim() : "";
  if (!file) return { endpoints: [], warnings: ["guardbuild.json openapi.file 为空"] };

  const base = String(ctx.projectRoot).replace(/[\\/]+$/, "");
  const abs = `${base}/${file.replace(/^\.[\\/]+/, "")}`;
  let content;
  try {
    const res = await ctx.rpc.request(
      RPC_TO_HOST.FS_READ,
      { token: ctx.tokens.project, path: abs, redact: false },
      { timeoutMs: 10_000 }
    );
    content = res?.content;
  } catch (e) {
    return { endpoints: [], warnings: [`读取 openapi 文件失败（${file}）：${e.message}`] };
  }
  if (typeof content !== "string" || !content.trim()) {
    return { endpoints: [], warnings: [`openapi 文件 ${file} 为空`] };
  }

  let doc;
  try {
    doc = JSON.parse(content);
  } catch (e) {
    return { endpoints: [], warnings: [`openapi 文件 ${file} 不是合法 JSON：${e.message}`] };
  }

  const { endpoints, warnings: parseWarnings } = parseOpenapiDoc(doc, openapiCfg);
  warnings.push(...parseWarnings);
  if (endpoints.length === 0) warnings.push("OpenAPI 文档未解析出任何 HTTP 端点");
  return { endpoints, warnings };
}
