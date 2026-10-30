/**
 * 覆盖范围与终态措辞的唯一事实来源。
 *
 * 存在理由：`no_candidates` / `not_reproducible` 是 exit 0 的正常终态（工具正常工作，
 * 只是项目形态不在适配器覆盖内），但它们曾一度统一显示成「执行失败」，
 * 让使用者误判为崩溃。报告、事件流与 GUI 都从这里取文案，避免三处漂移。
 */

export const COVERAGE = {
  /** 已有「静态形状 + 攻击用例 + 交叉证明」四件套的漏洞类别 */
  kinds: [
    "对象级越权（IDOR：路径参数与查询参数两种形态）",
    "无鉴权读取与纵向越权",
    "路径穿越",
    "SQL 注入（数据库报错 / 布尔盲注双证据）",
    "命令注入（shell 展开令牌回显）",
    "SSRF（本机 canary 回连取证）",
    "文件上传（主动内容同源回读取证）",
    "JWT 伪造令牌（alg=none / 无效签名 / 源码密钥）",
    "业务逻辑跳步与并发双花（状态回读 / 并发副作用标识）",
    "CORS 配置错误（伪造 Origin + 允许凭证）",
    "CSRF（Cookie 会话下的跨站表单改写，仅 allowMutation）",
    "反射型 XSS（HTML 上下文无害 canary 反射）",
    "Supabase / PostgREST 数据暴露与 service_role 密钥泄露",
  ],
  /** 已实现的路由适配器形态 */
  stacks: [
    "Express 风格路由",
    "Next.js（App Router / Pages API）",
    "NestJS 装饰器路由",
    "tRPC 过程",
    "GraphQL（SDL 字段级）",
    "Supabase / PostgREST",
    "Python（FastAPI / Flask / Django + DRF）",
  ],
  /** 明确没有适配器的形态——命中即正常结束，不是错误 */
  unsupported: [
    "Java / Spring Boot（无静态适配器，启动器白名单也不含 java/mvn/gradle）",
    "Go / PHP / .NET / Ruby",
    "无 HTTP 接口的项目（纯脚本、CLI、离线工具）",
    "未识别的自定义路由注册形态（可用 guardbuild.json 的 routes / openapi 声明，或开启 llm.enabled 侦察）",
  ],
};

/** 给使用者看的一段话：覆盖了什么、没覆盖什么、以及「未命中」意味着什么 */
export function coverageSummary() {
  return [
    `已覆盖漏洞类别：${COVERAGE.kinds.join("；")}。`,
    `已覆盖框架形态：${COVERAGE.stacks.join("、")}。`,
    `暂无适配器：${COVERAGE.unsupported.join("；")}。`,
  ].join(" ");
}

/**
 * 终态措辞：code（会话错误码）→ 呈现方式。
 * kind 供 GUI 决定用红色错误还是中性提示；exitCode 与原 failSession 映射保持一致。
 */
const OUTCOME_PRESENTATION = {
  no_candidates: {
    outcome: "no_candidates",
    kind: "coverage",
    title: "已扫描但未发现可探测候选",
    stateLabel: "已扫描 · 无安全候选",
    hint: "已识别出 HTTP 路由，但没有命中任何「静态形状 + 攻击用例」组合（exit 0）：这是覆盖范围的边界，不是「系统安全」的证明。",
  },
  no_endpoints: {
    outcome: "inconclusive",
    kind: "inconclusive",
    title: "未识别到 HTTP 路由（无法证明）",
    stateLabel: "未识别路由 · 无法证明",
    hint: "引擎一条路由都没识别出来（exit 2）：既不能确认系统被覆盖，也不能据此判定安全。请在 guardbuild.json 用 routes / openapi.file / listEndpoint 声明接口，或开启接入侦察。",
  },
  attack_inconclusive: {
    outcome: "inconclusive",
    kind: "inconclusive",
    title: "证据不足（无法证明）",
    stateLabel: "攻击用例未跑全 · 无法证明",
    hint: "计划中的攻击用例因身份/资源/契约不足被跳过（exit 2）：本轮既没有复现漏洞，也没有把它们真正测到。补齐身份、可读资源与契约（listEndpoint / responses / routes[].params）后重跑。",
  },
  plan_incomplete: {
    outcome: "inconclusive",
    kind: "inconclusive",
    title: "候选端点无法构造探测请求（无法证明）",
    stateLabel: "无法构造探测请求 · 无法证明",
    hint: "已识别出候选，但没有一个能构造出可寻址请求（exit 2）：多段路径需要 routes[].params 给每个参数声明取值来源，否则引擎不会猜。补齐契约后重跑；本轮没有真正打到目标，不能据此判定安全。",
  },
  no_list_endpoint: {
    outcome: "inconclusive",
    kind: "inconclusive",
    title: "未定位到列表接口（无法证明）",
    stateLabel: "无列表接口 · 无法证明",
    hint: "静态、运行期实测（含自动发现）都没能确定按归属过滤的列表接口（exit 2）：既没复现漏洞，也没真正测到。请在 guardbuild.json 用 listEndpoint 显式声明列表端点（可带分页/过滤查询参数），或在 routes 里补充路由后重跑。",
  },
  param_binding_unverified: {
    outcome: "inconclusive",
    kind: "inconclusive",
    title: "多段路径参数取值来源未通过实测（无法证明）",
    stateLabel: "参数取值测不出 · 无法证明",
    hint: "已用本人列表里的真实对象实测过多段路径的参数绑定，响应里没有与参数对应的字段（exit 2）：引擎不会猜，本轮没有真正打到目标。请在 guardbuild.json 的 routes[].params 为每个参数声明取值来源（字段名或常量）后重跑。",
  },
  scout_routes_unverified: {
    outcome: "inconclusive",
    kind: "inconclusive",
    title: "模型给出的路由未通过运行期实测（无法证明）",
    stateLabel: "模型路由全部未命中 · 无法证明",
    hint: "静态分析没有候选，接入侦察给出的路由在真实运行实例上逐条打了一次、全部不成立（exit 2）：模型的断言没有变成覆盖，本轮不能判定安全。报告列出每条路由的实测状态码与不存在路径基线；请在 guardbuild.json 用 routes / openapi.file 声明真实接口，或让侦察的证据包含更多路由定义代码后重跑。",
  },
  static_routes_unverified: {
    outcome: "inconclusive",
    kind: "inconclusive",
    title: "静态推断的路由未通过运行期实测（无法证明）",
    stateLabel: "路由地址全部未命中 · 无法证明",
    hint: "本轮发出的每一个请求都落在「路由不存在」形态上（与不存在路径基线同形，exit 2）：静态从源码推断出的请求地址没有打到目标真实接口，覆盖没有建立，不能据此判定安全。最常见原因是挂载前缀与路由声明的对应关系判断有误，请在 guardbuild.json 用 routes / openapi.file 声明真实接口后重跑。",
  },
  no_attack_cases: {
    outcome: "inconclusive",
    kind: "inconclusive",
    title: "未能构造攻击用例（无法证明）",
    stateLabel: "无攻击用例 · 无法证明",
    hint: "登录与路由都正常，但一个攻击用例都没能构造出来（exit 2）：越权类用例需要「另一个身份名下真实存在的对象」，而本轮既没从列表接口读到资源，匿名 ID 探测也没找到可见对象——测试账号名下没有数据就会这样。这既不是执行失败也不是「无漏洞」：没有向目标发出越权请求，覆盖没有建立。请在 guardbuild.json 用 responses/listEndpoint 声明列表接口与主键/归属字段，或先在目标里给两个测试账号各造一条数据后重跑。",
  },
  attack_not_reproducible: {
    outcome: "not_reproducible",
    kind: "clean",
    title: "已测用例未复现（不等于安全）",
    stateLabel: "已测未复现 · 未证明安全",
    hint: "静态有候选，但本轮实际发出的攻击在运行实例上都没有复现（exit 0）。这只说明已测用例打不通（可能已有运行期防护），不构成「系统安全」的证明。",
  },
  no_patchable_candidates: {
    outcome: "vulnerable_unfixed",
    kind: "blocked",
    title: "漏洞证据成立，需人工修复",
    stateLabel: "证据成立 · 待人工修复",
    hint: "攻击已复现（exit 1 阻断门禁）：候选中没有可自动修复的端点，报告逐条给出修复指引。",
  },
  conflict: {
    outcome: "vulnerable_unfixed",
    kind: "blocked",
    title: "工作区已变化，补丁未写回",
    stateLabel: "补丁未写回 · 工作区已变化",
    hint: "Host 在写回预检（git apply --check）阶段拒绝，原文件未被修改：补丁生成基线与当前工作区代码不再一致。补丁仍保留在隔离 worktree，可重跑会话按最新代码重新生成，或自行合并 report.md 中的 Diff。",
  },
  login_form_rerendered: {
    outcome: "failed",
    kind: "failed",
    title: "登录未通过（目标把失败渲染成 200 表单）",
    stateLabel: "身份未建立 · 执行失败",
    hint: "登录接口返回 HTTP 200，但响应体仍是带密码输入框的登录页：凭据没有被接受，会话并未建立（exit 2）。这不是「已测未复现」——引擎不会拿未认证会话去跑越权用例，那只会得到全线被拒的假象。请核对 identities 是否为目标库中已存在且密码正确的账号，以及 login.bodyTemplate 的字段名。",
  },
  login_session_unverified: {
    outcome: "failed",
    kind: "failed",
    title: "会话未通过鉴权回读（身份不可信）",
    stateLabel: "身份未建立 · 执行失败",
    hint: "登录响应看似成功，但用该会话回读一个静态确认需要登录的只读接口时，响应与匿名请求同形（exit 2）：这个身份在目标上并没有认证。带着它跑越权只会全线被拒，进而被误判成「未复现」。请核对账号密码与目标库实际状态，或用 login.credentialPath 声明可判定的凭据字段。",
  },
  blackbox_login_failed: {
    outcome: "inconclusive",
    kind: "inconclusive",
    title: "黑盒身份族未执行（无法证明）",
    stateLabel: "身份探测未执行 · 无法证明",
    hint: "契约里配置了登录身份，但黑盒目标登录未成功（exit 2）：越权 / CSRF / 业务流这些依赖身份的探测族一条都没打，本轮只覆盖匿名面，不能当作「测过且干净」。请在 guardbuild.json 配好 login 与至少两个同角色测试账号后重跑。",
  },
  failed: {
    outcome: "failed",
    kind: "failed",
    title: "执行失败",
    stateLabel: "执行失败",
    hint: null,
  },
};

/**
 * 会话错误码 → 终态呈现。gate 的 verdict 与 exit code 语义：
 * vulnerable_unfixed→1、failed / inconclusive→2、其余→0。
 * inconclusive 与 failed 同为 2，但文案区分「没测到」与「跑挂了」。
 */
export function describeOutcome(code) {
  const pres = OUTCOME_PRESENTATION[code] ?? OUTCOME_PRESENTATION.failed;
  const exitCode =
    pres.outcome === "failed"
      ? 2
      : pres.outcome === "inconclusive"
        ? 2
        : pres.outcome === "vulnerable_unfixed"
          ? 1
          : 0;
  const severity = exitCode === 0 ? "warn" : "error";
  return { ...pres, exitCode, severity };
}
