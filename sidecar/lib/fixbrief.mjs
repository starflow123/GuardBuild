/**
 * 确定性修复简报：按证据/候选类型生成「风险 → 排查形态 → 修复方向 → 复现 → 复测」。
 * 不调用 LLM，不读源码；白盒只引用候选位置，黑盒只引用已复现证据。
 */

const FAMILY_BY_KIND = {
  "sqli-suspect": "sqli",
  "cmdi-suspect": "cmdi",
  "traversal-suspect": "traversal",
  "idor-suspect": "idor",
  "no-auth-suspect": "unauth",
  "supabase-table": "supabase_rls",
  "supabase-service-role-leak": "supabase_key",
};

export const KIND_LABELS = {
  "sqli-suspect": "SQL 注入静态线索",
  "cmdi-suspect": "命令注入静态线索",
  "traversal-suspect": "路径穿越静态线索",
  "idor-suspect": "对象级越权（IDOR）静态线索",
  "no-auth-suspect": "无鉴权静态线索",
  "supabase-table": "Supabase 表暴露",
  "supabase-service-role-leak": "Supabase service_role 密钥暴露",
};

const TEMPLATES = {
  sqli: {
    label: "SQL 注入",
    risk: "请求参数进入 SQL 文本，攻击者可改写条件/联合查询读取或篡改数据（本轮已用差分载荷复现）。",
    inspect: [
      "模板字符串、`+` 拼接、f-string、`%`/`.format()` 拼出的 SQL；`$queryRawUnsafe`、`db.raw`、`whereRaw`、`prepare()` 接字符串。",
      "ORM 的 raw 查询是否把请求值当 SQL 文本，而不是 bindings/replacements/占位符参数。",
      "排序字段、表名等无法参数化的位置是否直接取请求值。",
    ],
    fix: "改为参数化查询（占位符 + 绑定数组）；无法参数化的标识符改固定映射白名单；补一条注入载荷回归测试。",
  },
  cmdi: {
    label: "命令注入",
    risk: "请求参数进入 shell 命令拼接，攻击者可执行任意系统命令（本轮已用展开令牌复现）。",
    inspect: [
      "`child_process.exec/execSync`、`{ shell: true }` 的 `spawn`、`os.system`、`subprocess` 的 `shell=True`。",
      "命令字符串中是否包含请求值（host、filename、args 等）。",
      "是否用字符串拼接参数而不是参数数组。",
    ],
    fix: "改用 `execFile`/`spawn`（不启 shell）+ 参数数组；对主机名/路径等输入做格式白名单；补命令注入回归测试。",
  },
  traversal: {
    label: "路径穿越",
    risk: "请求参数被拼进文件路径，攻击者可读取工作目录外的文件（本轮已用 `../` 载荷复现）。",
    inspect: [
      "`fs.readFile/createReadStream/res.sendFile/sendFile` 的路径是否包含请求值。",
      "`path.join(root, userInput)` 后是否 `resolve` 并校验仍位于根目录内。",
      "是否只过滤 `..` 而漏掉 URL 编码、Windows 分隔符与绝对路径。",
    ],
    fix: "用固定根目录 + `path.resolve` 后做前缀校验；只允许白名单文件/`path.basename`；拒绝绝对路径与 `..`；补穿越载荷回归测试。",
  },
  idor: {
    label: "对象级越权（IDOR）",
    risk: "按客户端提供的对象 ID 取数但未校验归属，其他登录用户可读写不属于自己的对象（本轮已用跨身份请求复现）。",
    inspect: [
      "详情/更新/删除处理函数：是否只按 `id` 查询，未附加 `ownerId`/`tenantId`/`userId` 条件。",
      "列表端点：是否按当前身份过滤；管理端点：是否校验角色。",
      "查询参数形态（`?orderId=`）同样需要归属条件。",
    ],
    fix: "把当前身份作为查询条件的一部分（`WHERE id = ? AND owner_id = ?`）；管理操作单独校验角色；补跨用户回归用例。",
  },
  unauth: {
    label: "未认证访问",
    risk: "业务端点缺少认证守卫，匿名请求即可读取数据（本轮已用匿名请求复现）。",
    inspect: [
      "路由/控制器是否挂认证中间件；全局鉴权是否被白名单绕过。",
      "敏感路径段（user/order/file/admin 等）是否被标记为公开。",
      "反向代理或路由层是否提前放行。",
    ],
    fix: "路由挂认证中间件并默认拒绝；公开端点显式白名单；补匿名访问应返回 401/403 的回归用例。",
  },
  supabase_rls: {
    label: "Supabase 行级安全（RLS）缺失",
    risk: "anon key 匿名直连即可读取表数据，说明该表未启用 RLS 或策略过宽。",
    inspect: [
      "该表是否启用了 RLS（`ALTER TABLE ... ENABLE ROW LEVEL SECURITY`）。",
      "策略是否按 `auth.uid()` 限定行；是否存在 `USING (true)` 的过宽策略。",
      "前端是否直接查询了本应只由服务端访问的表。",
    ],
    fix: "启用 RLS 并按用户建策略；敏感表禁止客户端直连；修复后用同一 anon key 复测应返回空/403。",
  },
  supabase_key: {
    label: "Supabase service_role 密钥暴露",
    risk: "service_role 密钥出现在客户端可见位置，可绕过 RLS 读写全库。",
    inspect: [
      "前端环境变量/打包产物是否引用 `SERVICE_ROLE`；源码是否硬编码 `service_role` JWT。",
      "密钥是否被提交进仓库或写进公开配置。",
    ],
    fix: "立即在 Supabase 控制台轮换该密钥；service_role 只放服务端；移除客户端引用并排查历史泄露。",
  },
  sensitive_file: {
    label: "敏感文件暴露",
    risk: "敏感文件（环境变量、版本库元数据、备份/配置）可被未认证直接下载，泄露密钥与内部信息。",
    inspect: [
      "静态文件服务/反向代理的根目录是否覆盖了 `.env`、`.git/`、备份与配置文件。",
      "是否只靠前端路由隐藏路径，而服务端未拒绝 `.` 开头路径与 `.git`。",
      "泄露内容中是否含数据库口令、API key、部署凭据（如有，按已泄露处理）。",
    ],
    fix: "把敏感文件移出 web 根目录；服务器显式拒绝 dotfile 与 `.git` 路径；轮换已暴露的凭据；补未认证访问应返回 403/404 的用例。",
  },
  debug_surface: {
    label: "管理/调试面暴露",
    risk: "管理或调试端点未认证即可访问，可能泄露配置/环境变量，或提供危险操作入口。",
    inspect: [
      "`/actuator`、`/debug/pprof`、`/metrics`、`/admin` 等端点是否绑定公网且无认证。",
      "管理端口是否与业务端口分离；框架调试开关是否在生产环境开启。",
      "响应中是否包含环境变量、堆栈、依赖版本等敏感信息。",
    ],
    fix: "管理/调试端点绑定内网或加认证；生产环境关闭 actuator 敏感端点与调试开关；补未认证访问应返回 401/403 的用例。",
  },
  generic: {
    label: "安全问题",
    risk: "该端点存在已记录的安全风险，需结合证据定位。",
    inspect: ["按报告「实际」列定位失败的身份/参数组合，检查对应处理函数的认证、归属与输入处理。"],
    fix: "按最小改动修复认证/归属/输入处理后，复跑 gate 验证攻击不再复现。",
  },
};

export function detectFamily(finding) {
  const byKind = FAMILY_BY_KIND[finding?.kind];
  if (byKind) return byKind;
  const text = `${finding?.type ?? ""} ${finding?.reason ?? ""} ${finding?.detail ?? ""} ${finding?.impact ?? ""}`;
  if (/service[_ ]?role/i.test(text)) return "supabase_key";
  if (/敏感文件|敏感信息|\.env|\.git/i.test(text)) return "sensitive_file";
  if (/管理.{0,2}调试|调试面|actuator|pprof|debug\s*surface/i.test(text)) return "debug_surface";
  if (/SQL\s*注入/i.test(text)) return "sqli";
  if (/命令注入|command\s*injection/i.test(text)) return "cmdi";
  if (/穿越|traversal/i.test(text)) return "traversal";
  if (/RLS|Supabase|行级安全/i.test(text)) return "supabase_rls";
  // 「未认证」优先于「归属」：未认证读取的详情常附带归属类敏感字段说明
  if (/未认证|无鉴权|anonymous/i.test(text)) return "unauth";
  if (/跨用户|IDOR|越权|归属/i.test(text)) return "idor";
  return "generic";
}

function routeRegex(route) {
  const segs = String(route ?? "").split("?")[0].replace(/\/+$/, "").split("/");
  if (!segs.length || !route) return null;
  const pattern = segs
    .map((seg) => {
      if (/^:[\w]+$/.test(seg) || /^\{.+\}$/.test(seg) || seg === "*") return "[^/]+";
      return seg.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    })
    .join("/");
  return new RegExp(`^${pattern}/?$`, "i");
}

function matchEvidence(finding, evidence) {
  const candidates = [finding.path, finding.routePath].filter(Boolean);
  const matchers = candidates.map(routeRegex).filter(Boolean);
  if (!matchers.length) return null;
  const vulnerable = (evidence ?? []).filter((e) => e.verdict === "vulnerable" && e.endpoint);
  const hit = vulnerable.find((e) => matchers.some((m) => m.test(String(e.endpoint).split("?")[0])));
  if (!hit) return null;
  return hit.method && finding.method && hit.method !== finding.method
    ? vulnerable.find(
        (e) => e.method === finding.method && matchers.some((m) => m.test(String(e.endpoint).split("?")[0]))
      ) ?? hit
    : hit;
}

function displayPath(value) {
  return String(value ?? "").replace(/^\\\\\?\\/, "").replace(/\\/g, "/");
}

function concretePath(value) {
  return String(value ?? "")
    .split("?")[0]
    .replace(/:[\w]+/g, "1")
    .replace(/\{[^}]+\}/g, "1");
}

function buildReproduce(finding, ctx) {
  if (finding.curl) return finding.curl;
  if (ctx.family === "supabase_rls") {
    const table = String(finding.resource ?? finding.path ?? "").replace(/^table:/, "");
    const base = String(ctx.supabaseUrl ?? "<SUPABASE_URL>").replace(/\/+$/, "");
    return `curl "${base}/rest/v1/${table}?select=*" -H "apikey: <ANON_KEY>" -H "Authorization: Bearer <ANON_KEY>"`;
  }
  if (ctx.family === "supabase_key") {
    return `grep -rn "service_role\\|SERVICE_ROLE" "${displayPath(ctx.projectRoot) || "<项目目录>"}" -I`;
  }
  if (ctx.mode === "blackbox") return null;
  const hit = matchEvidence(finding, ctx.evidence);
  const base = ctx.baseUrl ?? "<目标URL>";
  if (hit) {
    const auth =
      hit.identity && hit.identity !== "(anonymous)" ? ` -H "Authorization: Bearer <${hit.identity}_token>"` : "";
    const rawBody = hit.request?.body;
    const body =
      rawBody == null
        ? ""
        : ` -H "Content-Type: application/json" -d '${typeof rawBody === "string" ? rawBody : JSON.stringify(rawBody)}'`;
    return `curl -X ${hit.method ?? "GET"}${auth}${body} '${base}${hit.endpoint}'`;
  }
  const path = concretePath(finding.routePath ?? finding.path);
  if (!path || /^(table|env|file):/.test(path)) return null;
  return `curl -X ${finding.method ?? "GET"} '${base}${path}'`;
}

function buildVerify(ctx) {
  const root = displayPath(ctx.projectRoot) || "<项目目录>";
  if (ctx.mode === "blackbox") {
    return `guardbuild-headless.exe --project "${root}" --url "${ctx.baseUrl ?? "<目标URL>"}" --gate --report <输出目录>`;
  }
  return `guardbuild-headless.exe --project "${root}" --gate --report <输出目录>`;
}

export function buildFixBrief(finding, ctx = {}) {
  const family = ctx.family ?? detectFamily(finding);
  const tpl = TEMPLATES[family] ?? TEMPLATES.generic;
  return {
    family,
    familyLabel: tpl.label,
    risk: tpl.risk,
    inspect: tpl.inspect,
    fix: tpl.fix,
    reproduce: buildReproduce(finding, { ...ctx, family }),
    verify: buildVerify(ctx),
    verifyExpectation: "修复后重跑应 exit 0（no_candidates / not_reproducible）；若仍 exit 1，按新证据继续修。",
  };
}

/** 把报告里的静态候选与黑盒发现统一转成修复简报。 */
export function buildFixBriefs(report) {
  const bb = report.blackbox;
  const mode = bb ? "blackbox" : "whitebox";
  const baseUrl = bb?.url ?? report.targets?.original?.url ?? null;
  const evidence = bb ? report.evidence?.blackbox ?? [] : report.evidence?.pre ?? [];
  const supabaseUrl = report.summary?.supabase?.url ?? report.supabase?.url ?? null;
  const findings = bb
    ? (bb.findings ?? []).map((f) => ({ ...f, source: "blackbox" }))
    : (report.summary?.findings ?? []).map((f) => ({ ...f, source: "static" }));
  const ctx = { mode, baseUrl, projectRoot: report.session?.projectRoot ?? null, evidence, supabaseUrl };
  return findings.map((f) => ({
    source: f.source,
    type: f.type ?? KIND_LABELS[f.kind] ?? f.kind ?? "安全发现",
    method: f.method ?? null,
    path: f.path ?? null,
    file: f.file ?? null,
    startLine: f.startLine ?? null,
    ...buildFixBrief(f, ctx),
  }));
}
