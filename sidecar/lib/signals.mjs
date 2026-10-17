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
export const SINK =
  /\b(find[A-Za-z]*ById(?:OrThrow)?|findByPk|findOneBy|findOneOrFail|findOne|findUnique(?:OrThrow)?|findFirst(?:OrThrow)?|getById)\s*\(|([A-Za-z_$][\w$]*\.find)\s*\(\s*\{|([A-Za-z_$][\w$]*)\s*\.\s*select\s*\([^)]*\)\s*\.\s*from\s*\([^)]*\)(?:\s*\.\s*[A-Za-z_$][\w$]*\s*\([^)]*\))*\s*\.\s*where\s*\(\s*(?:and\s*\(\s*)?eq\s*\(|((?:db|database|conn|connection|sqlite|pool|client|knex)\s*\.\s*(?:prepare\s*\([^;\n]*\)\s*\.\s*)?(?:get|query))\s*\(|((?:dbGet|dbOne|dbQuery|queryOne|getOne|fetchOne|fetchRow|getRow|selectOne))\s*\(/;

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
