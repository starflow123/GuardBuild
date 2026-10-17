/**
 * Python 适配器：FastAPI / Flask / Django（含 DRF ViewSet）路由静态解析。
 *
 * 产出统一形态的「伪区块」（style: "python"）：完整 URL（路由前缀 / Blueprint url_prefix /
 * Django include 前缀均已折叠）+ HTTP 方法 + 处理器正文。路径参数归一化为 `:param`，
 * 与 Express/NestJS 探测引擎的寻址约定一致——动态复现只认「路径 + 方法 + 身份」。
 *
 * 静态信号说明：
 *  - Python 的取数惯用法（Django `.objects.get`、SQLAlchemy `.query.filter().first()`、
 *    `get_object_or_404` 等）通过 sinkHints 并入统一候选判定；
 *  - 鉴权/角色/归属信号由本模块做 Python 语法定制（`Depends(get_current_user)`、
 *    `@login_required`、`permission_classes`、`if order.user_id != current_user.id`），
 *    以 forcedAuth / roleGuard / ownerGuard / ownerFilter 标记并入 analyzer。
 *
 * 修复策略：Python 的依赖注入/装饰器形态多元，v1 不提供自动修复；证据成立时按
 * vulnerable_unfixed 阻断并给出人工修复指引（与 NestJS/GraphQL 一致）。
 */
import { callArgsSpan } from "./signals.mjs";

const lineOf = (content, index) => content.slice(0, index).split("\n").length;
const normFile = (p) => String(p).replace(/\\/g, "/");

/** 按顶层逗号切分参数（忽略括号/方括号/引号内的逗号） */
function splitTopLevel(s) {
  const out = [];
  let depth = 0;
  let cur = "";
  let quote = null;
  for (let i = 0; i < s.length; i += 1) {
    const ch = s[i];
    if (quote) {
      cur += ch;
      if (ch === "\\") {
        if (i + 1 < s.length) cur += s[i + 1];
        i += 1;
      } else if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") {
      quote = ch;
      cur += ch;
      continue;
    }
    if (ch === "(" || ch === "[" || ch === "{") depth += 1;
    else if (ch === ")" || ch === "]" || ch === "}" ) depth -= 1;
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

/** 首个字符串字面量（普通或 r"…" 前缀） */
function firstStringLit(s) {
  const m = /(?:^|[^\w])(?:[rbuf]{0,2})["']([^"']*)["']/.exec(s ?? "");
  return m ? m[1] : null;
}

function joinUrl(...parts) {
  const segs = parts
    .filter((p) => p != null && String(p).trim() !== "")
    .map((p) => String(p).replace(/^\/+|\/+$/g, ""))
    .filter(Boolean);
  return segs.length ? "/" + segs.join("/") : "/";
}

/** FastAPI `{order_id}` / Flask & Django `<int:order_id>` → `:order_id` */
export function normalizePyPath(raw, style) {
  let p = String(raw ?? "").trim();
  if (!p) return null;
  if (!p.startsWith("/")) p = `/${p}`;
  if (style === "flask" || style === "django") {
    p = p.replace(/<(?:[A-Za-z_]\w*:)?([A-Za-z_]\w*)>/g, ":$1");
  } else {
    p = p.replace(/\{([A-Za-z_]\w*)(?::[^}]+)?\}/g, ":$1");
  }
  const joined = p.replace(/\/{2,}/g, "/");
  return joined.length > 1 ? joined.replace(/\/+$/, "") : joined;
}

/** 自 index 起（装饰器名/def 行）取到下一个顶格代码行，返回块尾偏移 */
function pythonBlockEnd(content, startIdx) {
  const lines = content.slice(startIdx).split("\n");
  let offset = startIdx;
  let started = false;
  let headerDone = false;
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    const lineStart = offset;
    offset += line.length + 1;
    if (!started) {
      if (/^\s*(?:async\s+)?def\s+|^\s*class\s+/.test(line)) {
        started = true;
        // 单行签名（def f(...):）直接进入函数体；多行签名要等收尾的 `):` 行
        headerDone = /:\s*(?:#.*)?$/.test(line);
      }
      continue;
    }
    if (!headerDone) {
      if (/:\s*(?:#.*)?$/.test(line)) headerDone = true;
      continue;
    }
    if (line.trim() === "" || /^\s/.test(line) || line.trimStart().startsWith("#")) continue;
    return lineStart - 1;
  }
  return content.length;
}

/** 装饰器/路由声明之后紧邻的函数定义 */
function findDefAfter(content, fromIdx) {
  const re = /^[ \t]*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(/gm;
  re.lastIndex = fromIdx;
  const m = re.exec(content);
  if (!m) return null;
  return { name: m[1], index: m.index, openIdx: m.index + m[0].length - 1 };
}

/** 从 class 行起取类体范围（含缩进方法），返回 { header, bases, start, end } */
function extractClass(content, name) {
  const re = new RegExp(`^[ \\t]*class\\s+${name}\\s*(?:\\(([^)]*)\\))?\\s*:`, "m");
  const m = re.exec(content);
  if (!m) return null;
  const start = m.index;
  const end = pythonBlockEnd(content, start);
  return { bases: m[1] ?? "", text: content.slice(start, end), start };
}

/** 类体内是否定义了某 HTTP 方法（def get/post/put/patch/delete） */
function classMethods(text) {
  const out = [];
  for (const m of text.matchAll(/^[ \t]+(?:async\s+)?def\s+(get|post|put|patch|delete|head|options)\s*\(/gm)) {
    out.push(m[1].toUpperCase());
  }
  return [...new Set(out)];
}

/** 模块 import 别名表：alias → 模块路径（相对 .views / 绝对 shop.views） */
export function parsePyImports(content) {
  const map = new Map();
  for (const m of content.matchAll(/^[ \t]*from\s+(\.*[\w.]*)\s+import\s+([^\n(]+)/gm)) {
    const base = m[1];
    for (const part of splitTopLevel(m[2])) {
      const pm = /^\s*([A-Za-z_]\w*)(?:\s+as\s+(\w+))?/.exec(part);
      if (!pm) continue;
      // 小写名字视为「子模块」（from . import views / from .routers import orders），
      // 大写或含下划线视为「模块内符号」（from .views import OrderViewSet / order_detail）
      const moduleLike = /^[a-z][a-z0-9]*$/.test(pm[1]);
      const mod = base === "." ? pm[1] : moduleLike ? `${base}.${pm[1]}` : base;
      map.set(pm[2] ?? pm[1], mod);
    }
  }
  for (const m of content.matchAll(/^[ \t]*import\s+([\w.]+)(?:\s+as\s+(\w+))?/gm)) {
    map.set(m[2] ?? m[1].split(".").pop(), m[1]);
  }
  return map;
}

/** 模块路径 → 项目内 .py 文件（支持相对 .routers.orders 与绝对 app.views） */
export function resolvePyModule(files, filePath, spec) {
  if (!spec) return null;
  const dir = filePath.slice(0, filePath.lastIndexOf("/"));
  let base;
  if (spec.startsWith(".")) {
    const up = /^\.+/.exec(spec)[0].length - 1;
    let d = dir;
    for (let i = 0; i < up; i += 1) d = d.slice(0, d.lastIndexOf("/"));
    const rest = spec.slice(up + 1).replace(/\./g, "/");
    base = rest ? `${d}/${rest}` : d;
  } else {
    base = spec.replace(/\./g, "/");
  }
  const cands = [`${base}.py`, `${base}/__init__.py`];
  for (const c of cands) {
    const hit = files.find((f) => {
      const p = normFile(f.path);
      return p === c || p.endsWith(`/${c}`);
    });
    if (hit) return normFile(hit.path);
  }
  return null;
}

// —— FastAPI ——

const FASTAPI_ROUTE =
  /^[ \t]*@([A-Za-z_]\w*)\.(get|post|put|patch|delete|head|options|api_route)\s*\(/gm;

const HTTP_ALIASES = { get: "GET", post: "POST", put: "PUT", patch: "PATCH", delete: "DELETE", head: "HEAD", options: "OPTIONS" };

function isDbDependency(expr) {
  return /\b(?:get_db|get_session|get_conn|db_session|session_maker|get_repository|Session)\b/.test(expr);
}

/** Depends()/Security() 调用是否属于鉴权依赖（排除数据库会话等基础设施依赖） */
function isAuthDependency(expr) {
  if (!expr) return false;
  if (isDbDependency(expr)) return false;
  return /auth|current_user|get_user|token|jwt|login|principal|permission|admin|role|guard/i.test(expr);
}

const AUTH_DECORATOR =
  /@[ \t]*(?:login_required|jwt_required|token_required|auth_required|requires_auth|permission_classes|authentication_classes|roles_required|admin_required|user_passes_test|permission_required)\b/;

/** Django/DRF 鉴权信号：装饰器/权限类/登录态判断（IsAuthenticatedOrReadOnly 对读请求等同公开） */
function pyAuthSignal(text, method = "GET") {
  if (/@(?:login_required|jwt_required|token_required|auth_required|requires_auth|roles_required|admin_required|user_passes_test|permission_required)\b/.test(text)) {
    return true;
  }
  const perm =
    /permission_classes\s*=\s*\[([^\]]*)\]/.exec(text)?.[1] ??
    /@permission_classes\s*\(([^)]*)\)/.exec(text)?.[1] ??
    "";
  if (perm) {
    if (/\bAllowAny\b/.test(perm)) return false;
    if (/IsAuthenticatedOrReadOnly\b/.test(perm)) return method !== "GET";
    if (/IsAuthenticated|IsAdminUser|DjangoModelPermissions/.test(perm)) return true;
  }
  if (/\bLoginRequiredMixin\b/.test(text)) return true;
  if (/request\.user\.is_authenticated|request\.auth\b/.test(text)) return true;
  return false;
}

function isScalarAnnotation(ann) {
  const s = String(ann ?? "").replace(/\s+/g, "");
  if (!s) return false;
  const core = s
    .replace(/^Optional\[/, "")
    .replace(/^Annotated\[/, "")
    .replace(/^Union\[/, "")
    .replace(/\]$/, "")
    .replace(/\|None$/, "");
  return /^(?:int|str|float|bool|UUID|Decimal|bytes)(?:$|,|\|)/.test(core);
}

/** FastAPI 函数签名：鉴权依赖、角色依赖、查询参数（含 Query(...) 与标量注解） */
function analyzeFastApiSignature(content, openIdx, pathParams) {
  const argsText = callArgsSpan(content, openIdx, 4000);
  if (argsText == null) return { auth: false, role: false, queryParam: null };
  const params = splitTopLevel(argsText);
  let auth = false;
  let role = false;
  let queryParam = null;
  for (const raw of params) {
    const p = raw.trim();
    if (!p || p === "*" || p.startsWith("**") || p.startsWith("*")) continue;
    const m = /^([A-Za-z_]\w*)\s*(?::\s*([\s\S]*?))?\s*(?:=\s*([\s\S]+))?$/.exec(p);
    if (!m) continue;
    const [, name, annotation, defExpr] = m;
    const dep = /\b(Depends|Security)\s*\(\s*([^)]*)\)/g;
    let dm;
    while ((dm = dep.exec(p))) {
      if (isAuthDependency(dm[2])) auth = true;
      if (/admin|role|permission|staff|superuser/i.test(dm[2])) role = true;
    }
    if (/\b(?:Request|Response|BackgroundTasks|WebSocket)\b/.test(annotation ?? "")) continue;
    if (/\b(?:Depends|Security)\s*\(/.test(p)) continue;
    if (pathParams.includes(name)) continue;
    if (/\bQuery\s*\(/.test(defExpr ?? "") || isScalarAnnotation(annotation)) {
      if (!queryParam) queryParam = name;
    }
  }
  return { auth, role, queryParam };
}

/** @router.get("/x", dependencies=[Depends(verify_token)]) 装饰器实参中的鉴权依赖 */
function decoratorDepsAuth(argsText) {
  let auth = false;
  let role = false;
  for (const m of argsText.matchAll(/\b(?:Depends|Security)\s*\(\s*([^)]*)\)/g)) {
    if (isAuthDependency(m[1])) auth = true;
    if (/admin|role|permission|staff|superuser/i.test(m[1])) role = true;
  }
  return { auth, role };
}

function collectFastApi(f, routers) {
  const filePath = normFile(f.path);
  const content = f.content ?? "";
  if (!/fastapi/i.test(content) && !/APIRouter\s*\(/.test(content)) return [];
  const sections = [];
  let m;
  FASTAPI_ROUTE.lastIndex = 0;
  while ((m = FASTAPI_ROUTE.exec(content))) {
    const openIdx = m.index + m[0].length - 1;
    const argsText = callArgsSpan(content, openIdx, 3000);
    if (argsText == null) continue;
    const declaredRaw = firstStringLit(argsText);
    if (!declaredRaw) continue;
    const methods =
      m[2] === "api_route"
        ? [...argsText.matchAll(/["']([A-Za-z]+)["']/g)]
            .map((x) => x[1].toUpperCase())
            .filter((x) => Object.values(HTTP_ALIASES).includes(x))
        : [HTTP_ALIASES[m[2]] ?? "GET"];
    const uniqMethods = methods.length ? [...new Set(methods)] : ["GET"];
    const def = findDefAfter(content, openIdx + argsText.length + 2);
    if (!def) continue;
    const bodyEnd = pythonBlockEnd(content, m.index);
    const text = content.slice(m.index, bodyEnd);
    const path = normalizePyPath(declaredRaw, "fastapi");
    const pathParams = [...path.matchAll(/:([A-Za-z_]\w*)/g)].map((x) => x[1]);
    const sig = analyzeFastApiSignature(content, def.openIdx, pathParams);
    const depSig = decoratorDepsAuth(argsText);
    const router = routers.get(`${filePath}#${m[1]}`);
    const prefix = router ? joinUrl(router.includePrefix, router.prefix) : "";
    const fullPath = joinUrl(prefix, path);
    const forcedAuth = sig.auth || depSig.auth || AUTH_DECORATOR.test(text);
    const roleGuard = sig.role || depSig.role || pyRoleGuard(text) || undefined;
    for (const method of uniqMethods) {
      sections.push({
        file: filePath,
        startLine: lineOf(content, m.index),
        method,
        style: "python",
        declaredPath: fullPath,
        text,
        forcedAuth,
        roleGuard: roleGuard || undefined,
        sinkHints: pySinkHints(text),
        queryParamHint: sig.queryParam ? { param: sig.queryParam, form: "signature" } : pyQueryParam(text),
        ownerGuard: pyOwnerGuard(text),
        ownerFilter: pyOwnerFilter(text),
      });
    }
  }
  return sections;
}

// —— Flask ——

const FLASK_ROUTE = /^[ \t]*@([A-Za-z_]\w*)\.(route|get|post|put|patch|delete)\s*\(/gm;

function collectFlask(f, blueprints) {
  const filePath = normFile(f.path);
  const content = f.content ?? "";
  if (!/flask/i.test(content)) return [];
  const sections = [];
  let m;
  FLASK_ROUTE.lastIndex = 0;
  while ((m = FLASK_ROUTE.exec(content))) {
    const openIdx = m.index + m[0].length - 1;
    const argsText = callArgsSpan(content, openIdx, 3000);
    if (argsText == null) continue;
    const declaredRaw = firstStringLit(argsText);
    if (!declaredRaw) continue;
    let methods;
    if (m[2] === "route") {
      const mm = /methods\s*=\s*\[([^\]]*)\]/.exec(argsText);
      methods = mm
        ? [...mm[1].matchAll(/["']([A-Za-z]+)["']/g)].map((x) => x[1].toUpperCase())
        : ["GET"];
    } else {
      methods = [HTTP_ALIASES[m[2]] ?? "GET"];
    }
    const def = findDefAfter(content, openIdx + argsText.length + 2);
    if (!def) continue;
    const bodyEnd = pythonBlockEnd(content, m.index);
    const text = content.slice(m.index, bodyEnd);
    const path = normalizePyPath(declaredRaw, "flask");
    const bp = blueprints.get(`${filePath}#${m[1]}`);
    const prefix = bp ? joinUrl(bp.includePrefix, bp.prefix) : "";
    const fullPath = joinUrl(prefix, path);
    for (const method of [...new Set(methods)]) {
      sections.push({
        file: filePath,
        startLine: lineOf(content, m.index),
        method,
        style: "python",
        declaredPath: fullPath,
        text,
        forcedAuth: AUTH_DECORATOR.test(text) || /\bcurrent_user\b|\bg\s*\.\s*user\b|\bverify_jwt_in_request\s*\(/.test(text),
        roleGuard: pyRoleGuard(text) || undefined,
        sinkHints: pySinkHints(text),
        queryParamHint: pyQueryParam(text),
        ownerGuard: pyOwnerGuard(text),
        ownerFilter: pyOwnerFilter(text),
      });
    }
  }
  return sections;
}

// —— Django（urls.py + 函数/类视图 + DRF ViewSet） ——

const DJANGO_PATH = /^[ \t]*(?:path|re_path)\s*\(/gm;

function djangoUrlToPath(raw) {
  let s = String(raw ?? "").trim();
  // re_path：^orders/(?P<pk>\d+)/$ → orders/:pk/
  const named = [...s.matchAll(/\(\?P<([A-Za-z_]\w*)>[^)]+\)/g)];
  if (named.length) {
    for (const n of named) s = s.replace(n[0], `:${n[1]}`);
    s = s.replace(/^\^/, "").replace(/\$$/, "").replace(/\\\//g, "/");
  }
  return normalizePyPath(s, "django");
}

function findPySymbol(files, filePath, alias, symbol) {
  const target = filePath ?? null;
  if (target) {
    const f = files.find((x) => normFile(x.path) === target);
    if (f) {
      const content = f.content ?? "";
      if (new RegExp(`^[ \\t]*def\\s+${symbol}\\s*\\(`, "m").test(content) || new RegExp(`^[ \\t]*class\\s+${symbol}\\b`, "m").test(content)) {
        return f;
      }
    }
  }
  // 回退：全局唯一符号
  const hits = files.filter((x) => {
    const c = x.content ?? "";
    return new RegExp(`^[ \\t]*(?:def\\s+${symbol}\\s*\\(|class\\s+${symbol}\\b)`, "m").test(c);
  });
  return hits.length === 1 ? hits[0] : null;
}

/** Django 视图引用 → { file, kind: "function"|"class", name } */
function resolveDjangoView(files, filePath, imports, ref) {
  const asView = /\.as_view\s*\(\s*\)/.test(ref);
  const base = ref.replace(/\.as_view\s*\(\s*\)/, "").trim();
  const dotted = /^([A-Za-z_]\w*)\.([A-Za-z_]\w*)$/.exec(base);
  const bare = /^([A-Za-z_]\w*)$/.exec(base);
  if (!dotted && !bare) return null;
  let targetFile = null;
  let name;
  if (dotted) {
    name = dotted[2];
    const spec = imports.get(dotted[1]);
    if (spec) targetFile = resolvePyModule(files, filePath, spec);
  } else {
    name = bare[1];
    const spec = imports.get(name);
    if (spec) targetFile = resolvePyModule(files, filePath, spec);
  }
  const f = findPySymbol(files, targetFile, targetFile ? null : name, name) ??
    (targetFile ? null : findPySymbol(files, null, name, name));
  if (!f) return null;
  const content = f.content ?? "";
  const isClass = new RegExp(`^[ \\t]*class\\s+${name}\\b`, "m").test(content);
  if (asView && !isClass) return null;
  return { file: normFile(f.path), kind: isClass ? "class" : "function", name };
}

function djangoViewSection(files, filePath, view, routePath, method, extra = {}) {
  const f = files.find((x) => normFile(x.path) === view.file);
  if (!f) return null;
  const content = f.content ?? "";
  let textStart;
  let text;
  let methodFinal = method;
  if (view.kind === "function") {
    const dm = new RegExp(`^[ \\t]*(?:async\\s+)?def\\s+${view.name}\\s*\\(`, "m").exec(content);
    if (!dm) return null;
    // 向上纳入紧邻装饰器行
    let start = dm.index;
    for (;;) {
      const prevLineStart = content.lastIndexOf("\n", start - 2) + 1;
      const prev = content.slice(prevLineStart, start).trim();
      if (/^@[A-Za-z_]\w*/.test(prev)) start = prevLineStart;
      else break;
    }
    textStart = start;
    text = content.slice(start, pythonBlockEnd(content, start));
    const apiViewMethods = /@api_view\s*\(\s*\[([^\]]*)\]/.exec(text);
    if (apiViewMethods) {
      const ms = [...apiViewMethods[1].matchAll(/["']([A-Za-z]+)["']/g)].map((x) => x[1].toUpperCase());
      methodFinal = method ?? (ms[0] ?? "GET");
    }
  } else {
    const cls = extractClass(content, view.name);
    if (!cls) return null;
    textStart = cls.start;
    text = cls.text;
  }
  const forcedAuth = pyAuthSignal(text, methodFinal);
  return {
    file: view.file,
    startLine: lineOf(content, textStart),
    method: methodFinal ?? "GET",
    style: "python",
    declaredPath: routePath,
    text,
    forcedAuth,
    roleGuard: pyRoleGuard(text) || undefined,
    sinkHints: pySinkHints(text),
    queryParamHint: pyQueryParam(text),
    ownerGuard: pyOwnerGuard(text),
    ownerFilter: pyOwnerFilter(text),
    ...extra,
  };
}

const DRF_ACTIONS = {
  ModelViewSet: [["GET", "retrieve"], ["PUT", "update"], ["PATCH", "partial_update"], ["DELETE", "destroy"]],
  ReadOnlyModelViewSet: [["GET", "retrieve"]],
};

function collectDjango(files) {
  const sections = [];
  const diag = { djangoFiles: 0, djangoUrls: 0, drfViewSets: 0 };
  const byPath = new Map(files.map((f) => [normFile(f.path), f]));
  // include 关系：path("api/", include("shop.urls")) → 目标文件累积前缀（支持多级 include）
  const edges = [];
  for (const f of files) {
    const content = f.content ?? "";
    if (!/include\s*\(/.test(content) || !/(?:urlpatterns|Router)/.test(content)) continue;
    const filePath = normFile(f.path);
    let m;
    DJANGO_PATH.lastIndex = 0;
    while ((m = DJANGO_PATH.exec(content))) {
      const open = m.index + m[0].length - 1;
      const args = callArgsSpan(content, open, 3000);
      if (args == null) continue;
      const parts = splitTopLevel(args);
      if (parts.length < 2) continue;
      const rawPath = firstStringLit(parts[0]);
      const inc = /\binclude\s*\(\s*([^)]*)\)/.exec(parts.slice(1).join(","));
      if (!inc) continue;
      const spec = firstStringLit(inc[1]);
      if (!spec) continue;
      const target = resolvePyModule(files, filePath, spec) ?? resolvePyModule(files, filePath, `.${spec.split(".").pop()}`);
      if (!target || !byPath.has(target)) continue;
      edges.push({ from: filePath, to: target, prefix: djangoUrlToPath(rawPath) });
    }
  }
  const prefixes = new Map();
  const targets = new Set(edges.map((e) => e.to));
  for (const f of files) {
    const filePath = normFile(f.path);
    if (/urlpatterns\s*=/.test(f.content ?? "") && !targets.has(filePath)) prefixes.set(filePath, "");
  }
  for (let pass = 0; pass < 8; pass += 1) {
    let changed = false;
    for (const e of edges) {
      if (!prefixes.has(e.from) || prefixes.has(e.to)) continue;
      prefixes.set(e.to, joinUrl(prefixes.get(e.from), e.prefix));
      changed = true;
    }
    if (!changed) break;
  }
  for (const f of files) {
    const filePath = normFile(f.path);
    const content = f.content ?? "";
    const isUrls = /urlpatterns\s*=|router\s*=\s*(?:Default|Simple)?Router\s*\(/.test(content);
    const isViews = /\bclass\s+\w+\s*\([^)]*(?:View|ViewSet|APIView)/.test(content) || /^[ \t]*def\s+\w+\s*\(\s*request\b/m.test(content);
    if (!isUrls && !isViews) continue;
    const prefix = prefixes.get(filePath) ?? "";
    const imports = parsePyImports(content);
    let matched = false;

    // ① urlpatterns：path/re_path → 视图
    if (/urlpatterns\s*=/.test(content)) {
      let m;
      DJANGO_PATH.lastIndex = 0;
      while ((m = DJANGO_PATH.exec(content))) {
        const open = m.index + m[0].length - 1;
        const args = callArgsSpan(content, open, 4000);
        if (args == null) continue;
        const parts = splitTopLevel(args);
        if (parts.length < 2) continue;
        if (/\binclude\s*\(/.test(parts[1])) continue; // include 已在上一轮处理
        const rawPath = firstStringLit(parts[0]);
        const view = resolveDjangoView(files, filePath, imports, parts[1]);
        if (!view) continue;
        const routePath = joinUrl(prefix, djangoUrlToPath(rawPath));
        const fView = files.find((x) => normFile(x.path) === view.file);
        if (!fView) continue;
        const viewContent = fView.content ?? "";
        let methods;
        if (view.kind === "class") {
          const cls = extractClass(viewContent, view.name);
          methods = cls ? classMethods(cls.text) : [];
          if (methods.length === 0) methods = ["GET"];
        } else {
          const dm = new RegExp(`^[ \\t]*(?:async\\s+)?def\\s+${view.name}\\s*\\([^)]*\\)`, "m").exec(viewContent);
          const apiViewMethods = dm
            ? /@api_view\s*\(\s*\[([^\]]*)\]/.exec(viewContent.slice(Math.max(0, dm.index - 500), dm.index + dm[0].length))
            : null;
          methods = apiViewMethods
            ? [...apiViewMethods[1].matchAll(/["']([A-Za-z]+)["']/g)].map((x) => x[1].toUpperCase())
            : ["GET"];
        }
        for (const method of methods) {
          const s = djangoViewSection(files, filePath, view, routePath, method);
          if (!s) continue;
          sections.push(s);
          matched = true;
          diag.djangoUrls += 1;
        }
      }
    }

    // ② DRF ViewSet：router.register(r"orders", OrderViewSet) + include(router.urls)
    const routers = [...content.matchAll(/([A-Za-z_]\w*)\s*=\s*(?:routers\.)?(?:Default|Simple)?Router\s*\(/g)].map((x) => x[1]);
    if (routers.length) {
      let routerPrefix = "";
      for (const m of content.matchAll(/\binclude\s*\(\s*([A-Za-z_]\w*)\.urls\s*\)/g)) {
        if (!routers.includes(m[1])) continue;
        // 同一文件内 path("api/", include(router.urls)) 的路径前缀
        const before = content.slice(Math.max(0, m.index - 400), m.index);
        const pathCall = /path\s*\(\s*(?:r)?["']([^"']*)["'][^)]*$/.exec(before);
        if (pathCall && !routerPrefix) routerPrefix = djangoUrlToPath(pathCall[1]);
      }
      for (const m of content.matchAll(/\.register\s*\(\s*(?:r)?["']([^"']+)["']\s*,\s*([A-Za-z_]\w*)/g)) {
        const regPrefix = m[1].replace(/^\/+|\/+$/g, "");
        const viewName = m[2];
        let viewFile = null;
        const spec = imports.get(viewName);
        if (spec) {
          const target = resolvePyModule(files, filePath, spec);
          if (target) viewFile = files.find((x) => normFile(x.path) === target) ?? null;
        }
        if (!viewFile) viewFile = findPySymbol(files, null, null, viewName);
        if (!viewFile) continue;
        const viewContent = viewFile.content ?? "";
        const cls = extractClass(viewContent, viewName);
        if (!cls) continue;
        const actions = [];
        for (const [setName, list] of Object.entries(DRF_ACTIONS)) {
          if (new RegExp(`\\b${setName}\\b`).test(cls.bases)) actions.push(...list);
        }
        if (actions.length === 0 && /ViewSet|GenericViewSet|ViewSetMixin|Mixin/.test(cls.bases)) {
          if (/RetrieveModelMixin/.test(cls.bases)) actions.push(["GET", "retrieve"]);
          if (/UpdateModelMixin/.test(cls.bases)) actions.push(["PUT", "update"], ["PATCH", "partial_update"]);
          if (/DestroyModelMixin/.test(cls.bases)) actions.push(["DELETE", "destroy"]);
        }
        if (actions.length === 0) continue;
        diag.drfViewSets += 1;
        const routePath = joinUrl(prefix, routerPrefix, regPrefix, ":pk");
        for (const [method] of actions) {
          const forcedAuth = pyAuthSignal(cls.text, method);
          sections.push({
            file: normFile(viewFile.path),
            startLine: lineOf(viewContent, cls.start),
            method,
            style: "python",
            declaredPath: routePath,
            text: cls.text,
            forcedAuth,
            roleGuard: pyRoleGuard(cls.text) || undefined,
            sinkHints: [{ call: "queryset.get", index: 0 }],
            ownerGuard: pyOwnerGuard(cls.text),
            ownerFilter: pyOwnerFilter(cls.text),
          });
          matched = true;
          diag.djangoUrls += 1;
        }
      }
    }
    if (matched) diag.djangoFiles += 1;
  }
  return { sections, diag };
}

// —— Python 信号（auth/role/owner/sink） ——

export function pySinkHints(text) {
  const hints = [];
  const add = (call) => {
    if (!hints.some((h) => h.call === call)) hints.push({ call, index: 0 });
  };
  if (/\.objects\s*\.\s*(?:get|filter|get_or_create)\s*\(/.test(text)) add("objects.get");
  if (/\bget_object_or_404\s*\(/.test(text)) add("get_object_or_404");
  if (/\.query\s*\.\s*(?:get|filter)\s*\(/.test(text)) add("query.filter");
  // 旧式 SQLAlchemy：session.query(Order).filter(...) / db.query(Order).get(...)
  if (/\.query\s*\([^)]*\)\s*\.\s*(?:get|filter|filter_by)\s*\(/.test(text)) add("query.filter");
  if (/\bsession\s*\.\s*(?:get|query)\s*\(/.test(text)) add("session.get");
  if (/\bdb\s*\.\s*(?:get|query)\s*\(/.test(text)) add("db.get");
  if (/\.filter_by\s*\(/.test(text)) add("filter_by");
  if (/\bselect\s*\([^)]*\)[\s\S]{0,300}?\.where\s*\(/.test(text)) add("select.where");
  if (/\.first\s*\(\s*\)/.test(text)) add("first");
  return hints;
}

export function pyOwnerGuard(text) {
  const lines = String(text ?? "").split("\n");
  for (const line of lines) {
    if (!/^\s*(?:if|elif|assert)\b/.test(line)) continue;
    if (!/(?:!=|==)/.test(line)) continue;
    const hasOwnerField = /\.(?:user_id|owner_id|author_id|user)\b/.test(line) || /\[["'](?:userId|user_id|ownerId|owner_id)["']\]/.test(line);
    const hasRequester = /\b(?:current_user|request\.user|g\.user|user|auth|principal)\b/.test(line);
    if (hasOwnerField && hasRequester) return true;
  }
  return false;
}

export function pyOwnerFilter(text) {
  const s = String(text ?? "");
  if (/\b(?:filter|filter_by|where)\s*\([^)]*(?:user_id|userId|owner_id|ownerId|user\s*==|user=)/i.test(s)) return true;
  if (/\bif\b[^\n]*(?:\.user_id|\.userId|\[["'](?:userId|user_id)["']\])[^\n]*(?:==|!=)[^\n]*(?:current_user|request\.user|g\.user|\buser\b)/.test(s)) return true;
  if (/get_queryset\s*\([^)]*\)[^:]*:[\s\S]{0,600}?(?:filter|filter_by)\s*\([^)]*(?:user|current_user|request\.user)/.test(s)) return true;
  return false;
}

export function pyRoleGuard(text) {
  const s = String(text ?? "");
  return /\bis_(?:admin|staff|superuser)\b|role\s*[!=]==?\s*["']admin["']|["'](?:role|roleName)["']\s*[!=]==?\s*["']admin["']|\b(?:roles_required|admin_required|require_admin|IsAdminUser|HasRole|DjangoModelPermissions)\b/i.test(s);
}

export function pyQueryParam(text) {
  const s = String(text ?? "");
  const m =
    /\brequest\s*\.\s*(?:args|GET|query_params)\s*\.\s*get\s*\(\s*["']([^"']+)["']/.exec(s) ??
    /\brequest\s*\.\s*(?:args|GET|query_params)\s*\[\s*["']([^"']+)["']\s*\]/.exec(s);
  return m ? { param: m[1], form: "request" } : null;
}

/** FastAPI APIRouter / Flask Blueprint 定义与跨文件 include 前缀解析 */
function collectRouterPrefixes(files) {
  const fastapi = new Map(); // `${file}#${var}` → { prefix, includePrefix }
  const flask = new Map();
  const pyFiles = files.filter((f) => normFile(f.path).toLowerCase().endsWith(".py"));
  for (const f of pyFiles) {
    const filePath = normFile(f.path);
    const content = f.content ?? "";
    for (const m of content.matchAll(/([A-Za-z_]\w*)\s*=\s*APIRouter\s*\(/g)) {
      const open = m.index + m[0].length - 1;
      const args = callArgsSpan(content, open, 2000) ?? "";
      const pm = /prefix\s*=\s*["']([^"']*)["']/.exec(args);
      fastapi.set(`${filePath}#${m[1]}`, { prefix: pm ? pm[1] : "", includePrefix: "" });
    }
    for (const m of content.matchAll(/([A-Za-z_]\w*)\s*=\s*Blueprint\s*\(/g)) {
      const open = m.index + m[0].length - 1;
      const args = callArgsSpan(content, open, 2000) ?? "";
      const pm = /url_prefix\s*=\s*["']([^"']*)["']/.exec(args);
      flask.set(`${filePath}#${m[1]}`, { prefix: pm ? pm[1] : "", includePrefix: "" });
    }
  }
  // include_router(mod.router, prefix="/v1") / register_blueprint(bp, url_prefix="/v1")
  const resolveTarget = (filePath, imports, expr, map) => {
    const dotted = /^([A-Za-z_]\w*)\.([A-Za-z_]\w*)$/.exec(expr);
    if (dotted) {
      const spec = imports.get(dotted[1]);
      const targetFile = resolvePyModule(pyFiles, filePath, spec);
      return targetFile ? `${targetFile}#${dotted[2]}` : null;
    }
    if (/^[A-Za-z_]\w*$/.test(expr)) {
      const local = `${filePath}#${expr}`;
      if (map.has(local)) return local;
      // from .orders import bp → bp 可能被记为「模块.符号」，回退到符号所在模块
      const spec = imports.get(expr);
      if (spec) {
        const target = resolvePyModule(pyFiles, filePath, spec);
        if (target) return `${target}#${expr}`;
        const dot = spec.lastIndexOf(".");
        if (dot > 0) {
          const parent = resolvePyModule(pyFiles, filePath, spec.slice(0, dot));
          if (parent) return `${parent}#${expr}`;
        }
      }
      return local;
    }
    return null;
  };
  for (const f of pyFiles) {
    const filePath = normFile(f.path);
    const content = f.content ?? "";
    const imports = parsePyImports(content);
    const apply = (re, map, prefixKey) => {
      let m;
      while ((m = re.exec(content))) {
        const open = m.index + m[0].length - 1;
        const args = callArgsSpan(content, open, 3000);
        if (args == null) continue;
        const parts = splitTopLevel(args);
        const key = resolveTarget(filePath, imports, parts[0] ?? "", map);
        if (!key || !map.has(key)) continue;
        const pm = new RegExp(`${prefixKey}\\s*=\\s*["']([^"']*)["']`).exec(args);
        if (pm && !map.get(key).includePrefix) map.get(key).includePrefix = pm[1];
      }
    };
    apply(/([A-Za-z_]\w*)\.include_router\s*\(/g, fastapi, "prefix");
    apply(/([A-Za-z_]\w*)\.register_blueprint\s*\(/g, flask, "url_prefix");
  }
  return { fastapi, flask };
}

/**
 * 汇总 Python 路由区块。files 为 [{ path, content }]。
 * 返回 { sections, diag }，sections 与 express 区块同构（style 固定 "python"）。
 */
export function collectPythonSections(files) {
  const diag = {
    pythonFiles: 0,
    fastapiFiles: 0,
    flaskFiles: 0,
    djangoFiles: 0,
    fastapiRoutes: 0,
    flaskRoutes: 0,
    djangoUrls: 0,
    drfViewSets: 0,
    sections: 0,
  };
  const routers = collectRouterPrefixes(files);
  const all = [];
  for (const f of files) {
    if (!normFile(f.path).toLowerCase().endsWith(".py")) continue;
    diag.pythonFiles += 1;
    const content = f.content ?? "";
    if (/fastapi/i.test(content) || /APIRouter\s*\(/.test(content)) {
      const secs = collectFastApi(f, routers.fastapi);
      if (secs.length) {
        diag.fastapiFiles += 1;
        diag.fastapiRoutes += secs.length;
        all.push(...secs);
      }
    }
    if (/flask/i.test(content) && /@[A-Za-z_]\w*\.(?:route|get|post|put|patch|delete)\s*\(/.test(content)) {
      const secs = collectFlask(f, routers.flask);
      if (secs.length) {
        diag.flaskFiles += 1;
        diag.flaskRoutes += secs.length;
        all.push(...secs);
      }
    }
  }
  const django = collectDjango(files);
  diag.djangoFiles = django.diag.djangoFiles;
  diag.djangoUrls = django.diag.djangoUrls;
  diag.drfViewSets = django.diag.drfViewSets;
  all.push(...django.sections);
  diag.sections = all.length;
  return { sections: all, diag };
}
