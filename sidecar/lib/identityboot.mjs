/**
 * 身份自举（S0，不依赖模型）：引擎在沙箱内用目标自己的公开注册接口建立测试身份，
 * 再按契约给它写入几条对象数据。
 *
 * 为什么要有这一层：跨归属攻击的成立条件是「两个不同归属、各自名下有真实数据的账号」。
 * 沙箱目标每次从空库启动，人手写 identities 只是把「账号不存在」换成「密码对不上」，
 * 而这两种情况过去都会退化成内建演示账号 → 全线被拒 → 报「未发现可复现漏洞」（假绿灯）。
 *
 * 这一层的边界（三条硬约束）：
 * 1. 只发请求、不判结论——注册/写数据成功与否按目标真实响应判定，会话真伪仍由
 *    probe 的登录回读（#175）把关；本模块绝不返回「已认证」这种断言。
 * 2. 口令由引擎随机生成，交给 Host 的 protected 保险库（只参与脱敏，不作为请求头凭证、
 *    不进 credential.list）；本模块不写日志、不落事件，调用方只能拿到状态码与形状。
 * 3. 准备失败必须显式失败——调用方拿 `unavailable`/`rejected` 一类结果时须回 inconclusive，
 *    禁止静默降级成匿名攻击。
 */
import { randomBytes } from "node:crypto";

/** 注册/建号路由的路径形状；只认末段或独立段，避免把 /api/sessions/register-device 之类误收 */
const SIGNUP_SEGMENT = /^(?:register|registration|signup|sign-up|sign_up|create-account|createuser|create-user|join)$/i;
/** 「建号」的近义动词段：users/create、accounts/new 这类 REST 形状，单段正则覆盖不到 */
const SIGNUP_CREATION_VERB = /^(?:create|add|new|insert|signups?|registrations?)$/i;
/** 明显不是建号的路径片段（找回密码/第三方登录/验证邮箱都不该被当注册打） */
const SIGNUP_EXCLUDE = /login|signin|logout|password|recover|reset|verify|activate|oauth|sso|token|refresh|2fa|otp|magic/i;

/** 模板占位符填充：`{name}`/`{username}`/`{email}`/`{password}`/`{canary}`，递归处理对象与数组 */
export function fillTemplate(value, values) {
  if (typeof value === "string") {
    return value.replace(/\{([A-Za-z_][\w]*)\}/g, (raw, k) =>
      Object.prototype.hasOwnProperty.call(values, k) && values[k] != null ? String(values[k]) : raw
    );
  }
  if (Array.isArray(value)) return value.map((v) => fillTemplate(v, values));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, fillTemplate(v, values)]));
  }
  return value;
}

/** 未被解析的占位符（用于把「契约字段名对不上」变成可执行的提示，而不是静默发出 `{password}`） */
export function unresolvedPlaceholders(value) {
  const found = new Set();
  const walk = (v) => {
    if (typeof v === "string") {
      for (const m of v.matchAll(/\{([A-Za-z_][\w]*)\}/g)) found.add(m[1]);
      return;
    }
    if (Array.isArray(v)) return v.forEach(walk);
    if (v && typeof v === "object") return Object.values(v).forEach(walk);
  };
  walk(value);
  return [...found];
}

const PWD_ALPHABET = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/**
 * 生成测试口令：长度 18、含大小写与数字、无易混字符（0/O/1/l/I）。
 * 目标常见的「至少 8 位、含字母和数字」校验能过，又不像 `alice123` 那样被当成弱口令扫描目标。
 */
export function generateTestPassword() {
  const bytes = randomBytes(16);
  let body = "";
  for (let i = 0; i < 14; i++) body += PWD_ALPHABET[bytes[i] % PWD_ALPHABET.length];
  // 固定补足一位大写与两位数字，避免「随机恰好没抽到」导致注册被校验拒掉；
  // 数字只取 2-9，否则「不含易混字符」这个承诺会被 0/1 打破。
  return `Gb${body}${2 + (bytes[14] % 8)}${2 + (bytes[15] % 8)}`;
}

/** 无害标记：写进种子数据，便于在报告里说明「这条对象是引擎造的」，也避免与真实数据混淆 */
export function generateCanary() {
  return `gbseed-${randomBytes(5).toString("hex")}`;
}

/**
 * 从静态分析结果里挑注册端点候选（确定性规则，不交给模型）：
 * POST + 末段命中建号形状 + 不含找回密码/第三方登录片段。
 */
export function signupCandidates(analysis) {
  const eps = Array.isArray(analysis?.endpoints) ? analysis.endpoints : [];
  const out = [];
  for (const e of eps) {
    if (String(e.method ?? "").toUpperCase() !== "POST") continue;
    const p = e.fullPath ?? e.path ?? "";
    if (typeof p !== "string" || !p.startsWith("/")) continue;
    if (SIGNUP_EXCLUDE.test(p)) continue;
    const segs = p.split("?")[0].split("/").filter(Boolean);
    const tail = segs.at(-1) ?? "";
    const parent = segs.at(-2) ?? "";
    // 末段是建号名词（/api/register），或「集合 + 创建动词」（/api/users/create、/accounts/new）
    const isSignup =
      segs.some((s) => SIGNUP_SEGMENT.test(s)) ||
      (SIGNUP_CREATION_VERB.test(tail) && /^(?:users?|accounts?|members?|signups?|registrations?)$/i.test(parent));
    if (!isSignup) continue;
    out.push({ path: p, file: e.file ?? null, startLine: e.startLine ?? null });
  }
  return out;
}

/**
 * 解析本轮用的注册端点：契约显式声明优先；未声明时只有「静态唯一候选」才敢用——
 * 多个候选意味着引擎在猜业务语义，宁可直接回 unavailable 让调用方显式失败。
 */
export function resolveRegisterEndpoint(registerCfg, analysis) {
  const declared = registerCfg?.path ?? null;
  if (declared) return { path: declared, source: "contract" };
  const cands = signupCandidates(analysis);
  if (cands.length === 1) return { path: cands[0].path, source: "static", file: cands[0].file };
  if (cands.length > 1) {
    return { path: null, source: "static-ambiguous", candidates: cands.map((c) => c.path) };
  }
  return { path: null, source: "none", candidates: [] };
}

/** 未声明 bodyTemplate 时按身份形状给一份最小注册体（不猜目标特有的业务必填字段） */
export function defaultRegisterBody(identity) {
  if (identity.fields) return { ...identity.fields };
  if (identity.username) return { username: identity.username, password: "{password}" };
  return { email: identity.email ?? "", password: "{password}" };
}

/** 组装注册请求体：契约模板优先，否则按身份形状；返回体与未解析占位符 */
export function registerBody(identity, registerCfg, values) {
  const template = registerCfg?.bodyTemplate ?? defaultRegisterBody(identity);
  const body = fillTemplate(template, values);
  const unresolved = unresolvedPlaceholders(body).filter((k) => !(k in values));
  return { body, unresolved };
}

/**
 * 注册响应分类（只按目标真实响应判定）：
 * created＝真建号；exists＝账号已在库里（可以是别的会话建的，随后仍要靠登录判定）；
 * rejected／not_found＝这一轮没能建立身份，调用方必须显式失败。
 */
export function classifyRegisterResponse(res) {
  const status = typeof res?.status === "number" ? res.status : 0;
  if (status >= 200 && status < 300) return { verdict: "created", status };
  if (status === 409) return { verdict: "exists", status };
  const text = typeof res?.body === "string" ? res.body.slice(0, 2000) : "";
  if ((status === 400 || status === 422) && /(alread|exist|taken|registered|in use)/i.test(text)) {
    return { verdict: "exists", status };
  }
  if (status === 404 || status === 405) return { verdict: "not_found", status };
  return { verdict: "rejected", status };
}

/**
 * 种子步骤体：`{canary}` 之外未解析的占位符说明契约写错了字段名，
 * 这类步骤整条跳过并如实回报，不能拿字面量 `{foo}` 去撞目标校验。
 */
export function seedBody(step, values) {
  if (!step?.bodyTemplate) return null;
  const body = fillTemplate(step.bodyTemplate, values);
  const unresolved = unresolvedPlaceholders(body).filter((k) => !(k in values));
  return { body, unresolved };
}

/** 写数据响应判定：状态码成功且响应不像被踢回登录页才算写进去；401/403＝身份不可信 */
export function classifySeedResponse(res) {
  const status = typeof res?.status === "number" ? res.status : 0;
  if (status === 401 || status === 403) return { verdict: "denied", status };
  if (status >= 200 && status < 300) return { verdict: "written", status };
  if (status === 404 || status === 405) return { verdict: "not_found", status };
  return { verdict: "rejected", status };
}
