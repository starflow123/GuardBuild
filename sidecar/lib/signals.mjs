/**
 * 共享静态信号：路由/取数/鉴权/归属等启发式正则与文本定位工具。
 * 由 analyzer 主分析器与各框架适配器（nextjs 等）共用，保证判定口径一致。
 */

// 资源获取 sink：按 ID 读取单个对象。
//  - 单查族：findById/find…ById(OrThrow)（Mongoose/手写 helper）、findByPk（Sequelize）、
//    findUnique(OrThrow)/findFirst(OrThrow)（Prisma，含 Drizzle 关系式查询）、findOneBy/findOneOrFail（TypeORM）
//  - 对象查询形态：Model.find({…})（原生 Mongo 驱动）
//  - Drizzle 链式取数：db.select(…).from(表)(.中间链式调用)*.where((and()?)eq(…))
//    —— 以 eq( 收尾，便于 findQueryParamSink 从 where 实参中识别查询参数
//  - 裸 SQL 驱动/helper：dbGet(…) 等单行 helper、db.get(…)/pool.query(…)、
//    db.prepare(sql).get(…)（better-sqlite3）——vibecoding 项目常见的无 ORM 取数形态；
//    只收单行读取族（get/query），dbAll/all 等列表族不在此列，避免列表端点误报
//  - Prisma 原始查询：prisma.$queryRaw`…` / prisma.$queryRawUnsafe(…)
//  - Knex 单行取数：knex("t").where(…).first()；原始 SQL：db.raw(…)
export const SINK =
  /\b(find[A-Za-z]*ById(?:OrThrow)?|findByPk|findOneBy|findOneOrFail|findOne|findUnique(?:OrThrow)?|findFirst(?:OrThrow)?|getById)\s*\(|([A-Za-z_$][\w$]*\.find)\s*\(\s*\{|([A-Za-z_$][\w$]*)\s*\.\s*select\s*\([^)]*\)\s*\.\s*from\s*\([^)]*\)(?:\s*\.\s*[A-Za-z_$][\w$]*\s*\([^)]*\))*\s*\.\s*where\s*\(\s*(?:and\s*\(\s*)?eq\s*\(|((?:db|database|conn|connection|sqlite|pool|client|knex)\s*\.\s*(?:prepare\s*\([^;\n]*\)\s*\.\s*)?(?:get|query))\s*\(|((?:dbGet|dbOne|dbQuery|queryOne|getOne|fetchOne|fetchRow|getRow|selectOne))\s*\(|(\bprisma\s*\.\s*\$queryRaw(?:Unsafe)?\s*[(`])|((?:knex|db|trx|tx)\s*\.\s*raw\s*\()|((?:knex|db|trx|tx)\s*\(\s*[^)]*\s*\)(?:\s*\.\s*[A-Za-z_$][\w$]*\s*\([^)]*\))*\s*\.\s*first\s*\()/;

// 归属校验：出现 userId 与请求者的比较（=== / !== / == / !=）
export const OWNER_GUARD =
  /(?:\.userId|\.ownerId|\.uid|\.authorId)\s*[!=]==?\s*[^,;\n]+|user\s*\.\s*id\s*[!=]==?\s*[^;,\n]*\.(?:userId|ownerId|uid)|(?:req|request|auth|ctx)\s*\.\s*user\s*[!=]==?/;

// 角色校验（@Roles 为 NestJS 装饰器族）
export const ROLE_GUARD =
  /role\s*[!=]==?\s*["'`]admin["'`]|isAdmin|hasRole\s*\(|requireRole|adminRequired|requireAdmin|ensureAdmin|adminGuard|@Roles\s*\(/i;

// 认证：Express/手写中间件族 + Next.js/现代框架的会话获取族 + NestJS 守卫装饰器族 + tRPC/上下文会话族
// （getServerSession=NextAuth、auth()=Clerk、currentUser()=Clerk、getToken=NextAuth/Clerk、
//  @UseGuards(JwtAuthGuard)=NestJS、ctx.user/ctx.session/ctx.auth=tRPC 上下文族）
export const AUTH_GUARD =
  /authenticate\s*\(|requireAuth|requireLogin|ensureAuth|auth\s*\.\s*user|req\s*\.\s*user|\bctx\s*\.\s*(?:user|session|auth)\b|getUser\s*\(|getServerSession|getServerAuthSession|getToken\s*\(|currentUser\s*\(|getAuth\s*\(|\bauth\s*\(\s*\)|withAuth|isAuthenticated|requireUser|assertAuth|UseGuards\s*\(/;

// 公开端点路径段（登录/注册等）：无鉴权属预期公开，不作为越权候选
export const PUBLIC_PATH =
  /\/(?:login|logout|sign-?in|sign-?up|register|registration|auth|token|refresh|password|forgot|captcha)\b/i;

// 归属过滤（列表接口按归属过滤）：兼容 userId/user_id、where 赋值、Drizzle 的 eq(表.userId,…)
// 与 Supabase/PostgREST 的 eq("user_id",…) 归约形态
export const OWNER_FILTER =
  /filter\s*\(\s*\(?[^)]*\)?\s*=>[^)]*\.user_?[Ii][Dd]\s*[!=]==|where\s*:?\s*\{[^}]*\buser_?[Ii][Dd]\b|where\s*=[^;\n]*\buser_?[Ii][Dd]\b|eq\s*\(\s*[\w$]+\s*\.\s*user_?[Ii][Dd]\b|eq\s*\(\s*["'`]user_?[Ii][Dd]["'`]/;

// —— 路径穿越线索：文件读取 sink + 请求输入在同段代码内合流 ——
// sink 覆盖 fs.readFile / sendFile / createReadStream 等读取族（写/删类不在探测范围，避免破坏性操作）
export const FS_READ_SINK =
  /\b(?:fs(?:\.promises)?\s*\.\s*)?(readFileSync|readFile|createReadStream|sendFileSync|sendFile|readdirSync|readdir|statSync|openSync|open)\s*\(/;

// 请求输入引用：req.query.x / req.params.x / req.body.x / 数组或字面量下标形态
export const REQ_INPUT = /\breq\s*\.\s*(query|params|body)\b(?:\s*\.\s*([A-Za-z_$][\w$]*)|\[\s*["'`]([^"'`]+)["'`]\s*\])?/;

// —— XSS 反射线索：响应输出 sink 与请求输入在同段代码内合流，且未经转义 ——
// res.send / res.end / res.json / ctx.body / res.write 直接拼接 req 变量
export const XSS_REFLECTION =
  /\b(?:res|response|ctx)\s*\.\s*(?:send|end|write|json)\s*\(\s*[`'"][^`'"]*\$\{\s*req\s*\.\s*(?:query|params|body)|res\s*\.\s*(?:send|end)\s*\(\s*req\s*\.\s*(?:query|params|body)/;

// —— SSRF 线索：HTTP 客户端 sink 的参数直接来自请求输入 ——
// fetch(url) / axios.get(req.query.url) / http.get(req.params.url)
export const SSRF_SINK =
  /\b(?:fetch|axios\s*\.\s*get|axios\s*\.\s*post|http\s*\.\s*get|https\s*\.\s*get|request)\s*\(\s*[^)]*req\s*\.\s*(?:query|params|body)/;

// 现代框架的查询串读取：searchParams.get("x")（Next.js req.nextUrl / URL 解析形态）
export const SP_GET = /\bsearchParams\s*\.\s*get\s*\(\s*["'`]([^"'`]+)["'`]\s*\)/;

function reqInputRe() {
  return new RegExp(REQ_INPUT.source, "g");
}

function spGetRe() {
  return new RegExp(SP_GET.source, "g");
}

/** 检测区块内路径穿越线索：返回离 sink 最近的请求输入 {source, param, sink} 或 null */
export function findTraversalSignal(text) {
  const re = new RegExp(FS_READ_SINK.source, "g");
  const taintedVars = collectRequestVars(text);
  let m;
  while ((m = re.exec(text))) {
    // 取 sink 调用前的窗口：覆盖「输入变量赋值 → 拼接 → 传参」的相邻语句链
    const from = Math.max(0, m.index - 400);
    const window = text.slice(from, m.index + 200);
    let input = null;
    for (const im of window.matchAll(reqInputRe())) input = im; // 保留最后一个（离 sink 最近）
    if (!input) {
      let sp = null;
      for (const sm of window.matchAll(spGetRe())) sp = sm;
      if (sp) return { source: "searchParams", param: sp[1], sink: m[1] };
      // NestJS 装饰器参数绑定：@Query("file") file → 绑定变量出现在 sink 附近
      const qm = /@Query\s*\(\s*["'`]([^"'`]+)["'`]\s*\)\s*([A-Za-z_$][\w$]*)/.exec(window);
      if (qm) {
        const rest = window.slice(qm.index + qm[0].length);
        if (new RegExp(`\\b${qm[2]}\\b`).test(rest)) return { source: "query", param: qm[1], sink: m[1] };
      }
      // Python/JS 变量形态：sink 首参直接拼进已确认的请求可控变量
      // （如 open("./data/" + datestamp)，datestamp 来自 FastAPI 形参或 request.args）
      const openRel = m[0].lastIndexOf("(");
      const argsText = callArgsSpan(text, m.index + openRel, 400);
      if (argsText) {
        const first = firstArgText(argsText);
        for (const [name, info] of taintedVars) {
          if (new RegExp(`\\b${escRe(name)}\\b`).test(first)) {
            return { source: info.channel, param: info.param, sink: m[1] };
          }
        }
      }
      continue;
    }
    return {
      source: input[1],
      param: input[2] ?? input[3] ?? null,
      sink: m[1],
    };
  }
  return null;
}

/** 取调用实参文本（openIdx 处的 ( 起，括号配平到 )），窗口超过 cap 或未闭合返回 null */
export function callArgsSpan(text, openIdx, cap = 300) {
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
 * 查询参数形态的越权线索：sink 实参中出现 req.query.X 或 searchParams.get("x")。
 *  - direct：`find({ where: { id: req.query.id } })` —— 实参内直接引用
 *  - indirect：先 `const id = req.query.id / searchParams.get("id")` 赋值，变量再出现在实参内
 * 返回 { param, form } 或 null。
 */
export function findQueryParamSink(text) {
  const sinkRe = new RegExp(SINK.source, "g");
  let m;
  while ((m = sinkRe.exec(text))) {
    // Drizzle 链：扫描窗口取 where 的整体实参（and(eq(…), eq(…)) 内任一位置出现查询参数均可识别）；
    // 其余形态取 sink 调用自身的实参窗口
    let openIdx;
    if (m[3]) {
      const whereIdx = m[0].lastIndexOf("where");
      const parenRel = whereIdx < 0 ? -1 : m[0].indexOf("(", whereIdx);
      if (parenRel < 0) continue;
      openIdx = m.index + parenRel;
    } else {
      openIdx = m.index + m[0].lastIndexOf("(");
    }
    const argsText = callArgsSpan(text, openIdx);
    if (!argsText) continue;
    let direct = null;
    for (const im of argsText.matchAll(reqInputRe())) {
      if (im[1] === "query") direct = im;
    }
    if (direct) return { param: direct[2] ?? direct[3] ?? null, form: "direct" };
    const directSp = spGetRe().exec(argsText);
    if (directSp) return { param: directSp[1], form: "direct" };
    const windowText = text.slice(Math.max(0, m.index - 400), m.index);
    for (const am of windowText.matchAll(/(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]{0,200})/g)) {
      const rhs = am[2];
      if (!new RegExp(`\\b${am[1]}\\b`).test(argsText)) continue;
      const pm = /req\s*\.\s*query\s*(?:\.\s*([A-Za-z_$][\w$]*)|\[\s*["'`]([^"'`]+)["'`]\s*\])/.exec(rhs);
      if (pm) return { param: pm[1] ?? pm[2] ?? null, form: "indirect" };
      const sm = SP_GET.exec(rhs);
      if (sm) return { param: sm[1], form: "indirect" };
    }
    // NestJS 装饰器参数绑定：@Query("id") id → sink 实参引用该变量
    const qm = /@Query\s*\(\s*["'`]([^"'`]+)["'`]\s*\)\s*([A-Za-z_$][\w$]*)/.exec(windowText);
    if (qm && new RegExp(`\\b${qm[2]}\\b`).test(argsText)) return { param: qm[1], form: "indirect" };
  }
  return null;
}

// SQL 执行 sink：ORM 原始查询 / 驱动 query / SQLite helper / Python DB-API。
// 仅当请求输入以拼接或模板方式进入「第一个 SQL 实参」时才作为注入线索（参数化查询不在其列）。
export const SQL_SINK =
  /\b(?:dbAll|dbRun|dbGet|dbExec|dbQuery|dbExecute|rawQuery|queryRaw|executeRaw|knexRaw)\s*\(|\b(?:db|database|conn|connection|pool|client|knex|trx|tx|sequelize|prisma|stmt|statement|session|cursor|cur)\s*\.\s*(?:prepare\s*\([^;\n]*\)\s*\.\s*)?(?:all|run|get|each|exec|query|execute|executemany|raw|whereRaw|havingRaw|orderByRaw|\$queryRaw(?:Unsafe)?|\$executeRaw(?:Unsafe)?)\s*\(|\bquery\s*\.\s*(?:execute|executemany|exec|raw)\s*\(/;

// 命令执行 sink：Node child_process 与 Python os.system / subprocess 族。
// 只覆盖会把字符串交给 shell 的入口；execFile/spawn 的数组参数形态在检测时因首参不含输入而自然排除。
export const CMD_SINK =
  /\b(?:exec|execSync|execFile|execFileSync|spawn|spawnSync)\s*\(|\bos\s*\.\s*system\s*\(|\bsubprocess\s*\.\s*(?:run|call|check_output|check_call|Popen)\s*\(|\bchild_process\s*\.\s*(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(/;

/** 取首个顶层实参文本（跳过字符串/模板与嵌套括号） */
function firstArgText(argsText) {
  let depth = 0;
  let quote = null;
  for (let i = 0; i < argsText.length; i += 1) {
    const ch = argsText[i];
    if (quote) {
      if (ch === "\\") i += 1;
      else if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") quote = ch;
    else if (ch === "(" || ch === "[" || ch === "{") depth += 1;
    else if (ch === ")" || ch === "]" || ch === "}") depth -= 1;
    else if (ch === "," && depth === 0) return argsText.slice(0, i);
  }
  return argsText;
}

/** 按顶层逗号切分参数（忽略括号/方括号/花括号与字符串内的逗号） */
export function splitTopLevel(s) {
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

// Python 路由装饰器：@app.get("/x") / @router.post(...) / Flask 的 @bp.route(...)
const PY_ROUTE_DECORATOR =
  /@\s*[A-Za-z_]\w*(?:\.[A-Za-z_]\w+)*\s*\.\s*(?:get|post|put|patch|delete|head|options|api_route|route)\s*\(/;
// 非请求输入的注入型/框架型参数
const PY_NOT_INPUT = /\b(?:Request|Response|WebSocket|BackgroundTasks|Depends|Security|Body|Form|File|UploadFile)\b/;
// FastAPI 标量注解（其余大写注解按请求体模型处理）
const PY_SCALAR_ANN =
  /^(?:int|str|float|bool|bytes|UUID|Decimal|datetime|date|time|Optional\[\s*(?:int|str|float|bool|bytes|UUID|Decimal)\s*\]|List\[\s*(?:int|str|float|bool)\s*\])$/;

/**
 * Python 路由处理函数签名里的请求可控参数。
 * FastAPI 把「非依赖、非 Request 类」的参数当查询参数，最常见写法是没有注解的
 * `def handler(request: Request, code="1")`——只认 Query(...) 会整类漏掉。
 * 返回 [{ name, channel }]，channel 为 query（标量/未注解）或 body（模型注解）。
 */
export function pythonHandlerParams(text) {
  const s = String(text ?? "");
  const dec = PY_ROUTE_DECORATOR.exec(s);
  if (!dec) return [];
  const decArgs = callArgsSpan(s, dec.index + dec[0].length - 1, 600) ?? "";
  const pathLit = /["']([^"']*)["']/.exec(decArgs);
  const pathParams = new Set();
  if (pathLit) {
    for (const m of pathLit[1].matchAll(
      /\{([A-Za-z_]\w*)(?::[^}]*)?\}|<(?:(?:int|str|float|path|uuid)[^:>]*:)?([A-Za-z_]\w*)>/g
    )) {
      pathParams.add(m[1] ?? m[2]);
    }
  }
  // 装饰器之后的第一个 def 即路由处理器本体
  const rel = /(?:async\s+)?\bdef\s+[A-Za-z_]\w*\s*\(/.exec(s.slice(dec.index));
  if (!rel) return [];
  const openIdx = dec.index + rel.index + rel[0].length - 1;
  const argsText = callArgsSpan(s, openIdx, 4000);
  if (argsText == null) return [];
  const out = [];
  for (const raw of splitTopLevel(argsText)) {
    if (!raw || raw.startsWith("*")) continue;
    const m = /^([A-Za-z_]\w*)\s*(?::\s*([\s\S]*?))?\s*(?:=\s*([\s\S]+))?$/.exec(raw);
    if (!m) continue;
    const [, name, annotation, defExpr] = m;
    if (name === "self" || name === "cls" || pathParams.has(name)) continue;
    if (PY_NOT_INPUT.test(annotation ?? "") || PY_NOT_INPUT.test(defExpr ?? "")) continue;
    const ann = String(annotation ?? "").replace(/\s+/g, "");
    const channel = ann && !PY_SCALAR_ANN.test(ann) ? "body" : "query";
    out.push({ name, channel });
  }
  return out;
}

/** 直接请求输入：req.query.x / req.body.x / req.params.x / searchParams.get("x") / Python request.args */
function directInputIn(expr) {
  const m = /\breq\s*\.\s*(query|body|params)\s*(?:\.\s*([A-Za-z_$][\w$]*)|\[\s*["'`]([^"'`]+)["'`]\s*\])/.exec(expr);
  if (m) return { channel: m[1], param: m[2] ?? m[3] ?? null };
  const sp = /\bsearchParams\s*\.\s*get\s*\(\s*["'`]([^"'`]+)["'`]\s*\)/.exec(expr);
  if (sp) return { channel: "query", param: sp[1] };
  const py = /\brequest\s*\.\s*(args|form|json)\s*(?:\.\s*get\s*\(\s*["']([^"']+)["']\s*\)|\[\s*["']([^"']+)["']\s*\])/.exec(expr);
  if (py) return { channel: py[1] === "json" ? "body" : "query", param: py[2] ?? py[3] ?? null };
  return null;
}

/**
 * 收集请求可控变量并做轻量赋值传播：
 *  - const { query } = req.query / const host = req.body.host / searchParams.get / Nest @Query / Python request.args
 *  - const sql = `…${query}…` / const cmd = "ping " + host → 变量继承污点并标记 built（已参与字符串构造）
 */
function collectRequestVars(text) {
  const vars = new Map();
  const add = (name, channel, param, built = false) => {
    const n = String(name ?? "").trim();
    if (!/^[A-Za-z_$][\w$]*$/.test(n)) return;
    const prev = vars.get(n);
    if (prev && (prev.built || !built)) return;
    vars.set(n, { channel, param: param ?? n, built });
  };

  for (const m of text.matchAll(/(?:const|let|var)\s*\{([^}]+)\}\s*=\s*req\s*\.\s*(query|body|params)\b/g)) {
    for (const part of m[1].split(",")) {
      const raw = part.trim();
      if (!raw || raw.startsWith("...")) continue;
      const [lhsRaw, rhsRaw] = raw.split(":");
      const param = lhsRaw.trim().replace(/=.*$/, "").trim();
      const alias = (rhsRaw ?? lhsRaw).trim().replace(/=.*$/, "").trim();
      if (param && alias) add(alias, m[2], param);
    }
  }
  for (const m of text.matchAll(
    /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*req\s*\.\s*(query|body|params)\s*(?:\.\s*([A-Za-z_$][\w$]*)|\[\s*["'`]([^"'`]+)["'`]\s*\])/g
  )) {
    add(m[1], m[2], m[3] ?? m[4]);
  }
  for (const m of text.matchAll(
    /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*[^;\n]{0,160}?searchParams\s*\.\s*get\s*\(\s*["'`]([^"'`]+)["'`]\s*\)/g
  )) {
    add(m[1], "query", m[2]);
  }
  for (const m of text.matchAll(/@(Query|Body|Param)\s*\(\s*["'`]([^"'`]+)["'`]\s*\)\s*([A-Za-z_$][\w$]*)/g)) {
    add(m[3], m[1] === "Body" ? "body" : m[1] === "Param" ? "params" : "query", m[2]);
  }
  for (const m of text.matchAll(
    /([A-Za-z_]\w*)\s*=\s*request\s*\.\s*(args|form|json)\s*\.\s*get\s*\(\s*["']([^"']+)["']/g
  )) {
    add(m[1], m[2] === "json" ? "body" : "query", m[3]);
  }
  // Python 路由处理器签名参数（FastAPI 查询参数不写 request.args，直接是函数形参）
  for (const p of pythonHandlerParams(text)) {
    add(p.name, p.channel, p.name);
  }

  const propagate = (re) => {
    for (let pass = 0; pass < 3; pass += 1) {
      let changed = false;
      for (const m of text.matchAll(re)) {
        const name = m[1];
        if (vars.has(name)) continue;
        const rhs = m[2];
        let hit = null;
        for (const [v, info] of vars) {
          if (new RegExp(`\\b${escRe(v)}\\b`).test(rhs)) {
            hit = info;
            break;
          }
        }
        if (!hit) continue;
        // Python f-string 本身就是构造串（引号内再出现引号时无法用 [^"']* 界定），一律判为 built
        const built = /`[^`]*\$\{|\+\s*["'`]|["'`]\s*\+|\br?f["']|\.format\s*\(|%\s*\(/.test(rhs);
        vars.set(name, { ...hit, built: hit.built || built });
        changed = true;
      }
      if (!changed) break;
    }
  };
  propagate(/(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]{1,260})/g);
  propagate(/^[ \t]*([A-Za-z_]\w*)\s*=(?!=)\s*([^\n]{1,260})$/gm);
  return vars;
}

/** 首个实参是否由请求输入构造（模板插值 / f-string / 字符串拼接 / 已构造的变量） */
function constructedTaint(expr, vars) {
  const direct = directInputIn(expr);
  if (direct) return { ...direct, form: "direct" };
  for (const m of expr.matchAll(/\$\{([^{}]*)\}/g)) {
    for (const [name, info] of vars) {
      if (new RegExp(`\\b${escRe(name)}\\b`).test(m[1])) return { ...info, form: "interpolation" };
    }
  }
  for (const m of expr.matchAll(/\bf(["'])([^\n]*?)\1/gi)) {
    for (const im of m[2].matchAll(/\{([^{}]+)\}/g)) {
      for (const [name, info] of vars) {
        if (new RegExp(`\\b${escRe(name)}\\b`).test(im[1])) return { ...info, form: "f-string" };
      }
    }
  }
  for (const m of expr.matchAll(/(?:\+\s*([A-Za-z_$][\w$]*)|([A-Za-z_$][\w$]*)\s*\+)/g)) {
    const name = m[1] ?? m[2];
    if (vars.has(name)) return { ...vars.get(name), form: "concat" };
  }
  const whole = expr.trim().replace(/[,;]+$/, "");
  if (/^[A-Za-z_$][\w$]*$/.test(whole) && vars.get(whole)?.built) {
    return { ...vars.get(whole), form: "variable" };
  }
  return null;
}

function sinkName(raw, fallback) {
  const m = /([A-Za-z_$][\w$]*)\s*\(/.exec(raw);
  return m?.[1] ?? fallback;
}

/** SQL 注入线索：请求输入经模板/拼接进入 SQL sink 的首个实参 */
export function findSqlInjectionSignal(text) {
  const vars = collectRequestVars(text);
  for (const m of text.matchAll(new RegExp(SQL_SINK.source, "g"))) {
    const openRel = m[0].lastIndexOf("(");
    if (openRel < 0) continue;
    const argsText = callArgsSpan(text, m.index + openRel, 800);
    if (!argsText) continue;
    const hit = constructedTaint(firstArgText(argsText), vars);
    if (!hit) continue;
    return { source: hit.channel, param: hit.param, sink: sinkName(m[0], "sql"), form: hit.form };
  }
  // 注意：Prisma 的标签模板 $queryRaw`…${x}…` 会自动参数化，不构成 SQL 注入；
  // 仅 $queryRawUnsafe(...) 的拼接实参才会由上面的 sink 扫描命中。
  return null;
}

/** 命令注入线索：请求输入进入 exec/execSync/os.system/subprocess 的首个实参 */
export function findCommandInjectionSignal(text) {
  const vars = collectRequestVars(text);
  for (const m of text.matchAll(new RegExp(CMD_SINK.source, "g"))) {
    const raw = m[0];
    if (/^exec(?:Sync)?\s*\(/.test(raw)) {
      const before = text.slice(Math.max(0, m.index - 24), m.index);
      // re.exec / pattern.exec 等正则调用不是命令执行；child_process.exec 与解构后的 exec 保留
      if (/\.\s*$/.test(before) && !/(?:child_process|cp)\s*\.\s*$/i.test(before)) continue;
    }
    const openRel = raw.lastIndexOf("(");
    const argsText = callArgsSpan(text, m.index + openRel, 800);
    if (!argsText) continue;
    const first = firstArgText(argsText);
    const direct = directInputIn(first);
    if (direct) return { source: direct.channel, param: direct.param, sink: sinkName(raw, "exec"), form: "direct" };
    for (const [name, info] of vars) {
      if (new RegExp(`\\b${escRe(name)}\\b`).test(first)) {
        return { source: info.channel, param: info.param, sink: sinkName(raw, "exec"), form: "variable" };
      }
    }
  }
  return null;
}

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
export function findBodyOpen(text, from) {
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
export const escRe = (s) => s.replace(RE_ESCAPE, "\\$&");
