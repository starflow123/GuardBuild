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
    title: "未命中当前覆盖范围",
    stateLabel: "未命中覆盖范围",
    hint: "引擎正常结束（exit 0）：项目形态不在当前适配器覆盖内，未产出可探测候选，并非执行失败。",
  },
  attack_not_reproducible: {
    outcome: "not_reproducible",
    kind: "clean",
    title: "未发现可复现漏洞",
    stateLabel: "未发现可复现漏洞",
    hint: "静态有候选，但攻击在真实运行实例上打不通（exit 0）：可能已有运行期防护，未建立漏洞基线。",
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
  failed: {
    outcome: "failed",
    kind: "failed",
    title: "执行失败",
    stateLabel: "执行失败",
    hint: null,
  },
};

/**
 * 会话错误码 → 终态呈现。gate 的 verdict 与 exit code 语义不变：
 * failed→2、vulnerable_unfixed→1、其余→0。
 */
export function describeOutcome(code) {
  const pres = OUTCOME_PRESENTATION[code === "no_candidates" ? "no_candidates" : code] ?? OUTCOME_PRESENTATION.failed;
  const exitCode = pres.outcome === "failed" ? 2 : pres.outcome === "vulnerable_unfixed" ? 1 : 0;
  const severity = pres.kind === "failed" || pres.kind === "blocked" ? "error" : "warn";
  return { ...pres, exitCode, severity };
}
