/**
 * 动作表：执行器（真正发请求的写死程序）物理上能做到什么的唯一清单。
 *
 * 为什么单独有这一层：配方（一张填好的表）由模型起草。如果校验器只检查 JSON 形状，
 * 模型写出 `cookieJar: true` 这种执行器根本不认的字段时，引擎会**静悄悄忽略它**
 * （Host 侧 serde 没开 deny_unknown_fields，sidecar 也只是不读多余键）——
 * 于是「配方说打了、执行器没打」，又是一块假绿灯。所以这里做**拒收**而不是忽略：
 * 表外的动作/参数一律拒绝，并说明缺哪个动作（这就是能力请求单的输入）。
 *
 * 一条自我约束：表上每个动作都带 `anchor`（文件 + 该文件里必须存在的记号），
 * 单测逐条回读代码。删掉实现却忘了删表，测试就红——防止「表上写着能做、代码里已经做不到」。
 *
 * 红线：动作表本身、判据、写/删探测的默认开关——自动环不许写（见 docs/agent-attack-loop-plan.md 第六节）。
 */
import fs from "node:fs";
import path from "node:path";

export const RECIPE_VERSION = "gb-recipe-1";

/** 目标位置从哪来：探测计划里真实存在的槽位（planner.planView） */
export const SLOTS = [
  "loginPath",
  "resource",
  "readPath",
  "cancelPath",
  "unauthReadPath",
  "traversalPath",
  "sqliPath",
  "cmdiPath",
  "ssrfPath",
  "uploadPath",
  "jwtPath",
  "bizlogicPath",
  "listPath",
];
const SLOTS_ANCHOR = { file: "sidecar/lib/planner.mjs", token: "unauthReadPath:" };

/** Host 层允许的 HTTP 方法（CONNECT/TRACE 在 host.rs 里硬拒，写进表是为了明确拒收口径） */
export const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

/** 写/删探测的开关名：只有这两个，且配方只能声明依赖、不能翻默认值 */
export const GATE_NAMES = ["allowMutation", "allowDestructive"];

/**
 * 动作清单。`params` 是该动作能带的全部键——多一个就是表外。
 * 每条 anchor 都指向真正执行它的代码。
 */
export const ACTIONS = [
  {
    name: "request.anonymous",
    desc: "不带任何身份发起请求（匿名可达性取证）",
    params: ["method", "path", "query", "timeoutMs"],
    required: ["method", "path"],
    anchor: { file: "sidecar/lib/probe.mjs", token: "attack-anonymous-read" },
  },
  {
    name: "request.as",
    desc: "以保险库里的身份名发起请求；凭据由 Host 注入，配方永远看不到值",
    params: ["method", "path", "query", "identity", "timeoutMs"],
    required: ["method", "path", "identity"],
    anchor: { file: "src-tauri/src/core/host.rs", token: "identity_ref" },
  },
  {
    name: "request.body",
    desc: "带请求体（JSON / 表单 / 手工拼的 multipart），上限 256KB",
    params: ["method", "path", "body", "contentType", "timeoutMs"],
    required: ["method", "path"],
    anchor: { file: "src-tauri/src/core/host.rs", token: "256 * 1024" },
  },
  {
    name: "request.graphql",
    desc: "GraphQL 线协议：root.field + 变量，拒绝语义与错误体分开取证",
    params: ["method", "path", "operation", "variables", "identity"],
    required: ["path", "operation"],
    anchor: { file: "sidecar/lib/graphqlwire.mjs", token: "export function graphqlRequest" },
  },
  {
    name: "request.variant",
    desc: "同一攻击沿轴变形（对象写法 / 编码写法 / 通道），逐条独立判定",
    params: ["axis", "label", "requiresPreRepro"],
    required: ["axis"],
    anchor: { file: "sidecar/lib/probe.mjs", token: "requiresPreRepro" },
  },
  {
    name: "request.concurrent",
    desc: "并发扇出（双花类）：同一目标同一时刻打 N 次",
    params: ["method", "path", "identity", "fanout"],
    required: ["method", "path", "fanout"],
    anchor: { file: "sidecar/lib/probe.mjs", token: "attack-race" },
  },
  {
    name: "request.follow",
    desc: "跟随重定向：只跟同源、只跟 GET 或 307/308、最多 2 跳",
    params: ["max"],
    required: [],
    limits: { max: 2 },
    anchor: { file: "sidecar/lib/http-follow.mjs", token: "async function followRedirects" },
  },
  {
    name: "payload.inject",
    desc: "在已声明的参数上放注入载荷（SQL / 命令 / 布尔差量），报错与差量都算证据",
    params: ["method", "path", "query", "param", "payloadSet", "identity"],
    required: ["path", "param"],
    anchor: { file: "sidecar/lib/probe.mjs", token: "function injectionReq" },
  },
  {
    name: "fs.traverse",
    desc: "路径穿越：用无害 canary 文件是否存在来判定",
    params: ["method", "path", "param", "canary"],
    required: ["path", "param"],
    anchor: { file: "sidecar/lib/probe.mjs", token: "function traversalAttemptPath" },
  },
  {
    name: "net.canary",
    desc: "SSRF：只打本机回环上的 canary 服务，不外呼",
    params: ["method", "path", "param", "canaryHost"],
    required: ["path", "param"],
    anchor: { file: "sidecar/lib/probe.mjs", token: "attack-ssrf" },
  },
  {
    name: "upload.content",
    desc: "主动上传无害内容并同源回读",
    params: ["method", "path", "fieldName", "content", "identity"],
    required: ["path", "fieldName"],
    anchor: { file: "sidecar/lib/probe.mjs", token: "attack-upload" },
  },
  {
    name: "token.forge",
    desc: "伪造 JWT 后请求（alg=none / 错密钥），以放行与否取证",
    params: ["method", "path", "claims", "alg"],
    required: ["path", "claims"],
    anchor: { file: "sidecar/lib/probe.mjs", token: "attack-jwt-forge" },
  },
  {
    name: "state.skip",
    desc: "前置状态跳步：跳过中间状态直接打终态接口",
    params: ["method", "path", "identity", "from", "to"],
    required: ["path", "to"],
    anchor: { file: "sidecar/lib/probe.mjs", token: "attack-state-skip" },
  },
  {
    name: "readback.ownership",
    desc: "归属人复读：确认取到的内容确实是那个人的对象（交叉证明，不是看状态码）",
    params: ["uses", "field", "expect"],
    required: ["uses"],
    anchor: { file: "sidecar/lib/probe.mjs", token: "crossProof" },
  },
  {
    name: "gate.mutation",
    desc: "声明本步依赖写探测开关；开关默认关闭，配方无权翻",
    params: ["kind"],
    required: ["kind"],
    enums: { kind: GATE_NAMES },
    anchor: { file: "sidecar/main.mjs", token: "allowDestructive" },
  },
];

/**
 * 冻结判据：配方只能**引用名字**，不许内联判定逻辑。
 * 结论字段（漏洞 / 阻断 / 测不了）只能由已锚定的判卷代码落笔。
 */
export const VERDICT_RULES = [
  { name: "attack-repro", desc: "攻击是否真的复现（要求证据，不接受 200 即算穿）", anchor: { file: "sidecar/lib/probe.mjs", token: "function verifyAttack" } },
  { name: "cross-proof", desc: "内容归属交叉证明", anchor: { file: "sidecar/lib/probe.mjs", token: "crossProof" } },
  { name: "target-touched", desc: "攻击地址必须真的打到目标（全 404/405 不算测过）", anchor: { file: "sidecar/lib/probe.mjs", token: "assertTargetTouched" } },
  { name: "business-regress", desc: "合法业务在修复后必须仍可用", anchor: { file: "shared/protocol.mjs", token: "BUSINESS:" } },
  { name: "inconclusive", desc: "测不了就写测不了，不当安全结论", anchor: { file: "shared/protocol.mjs", token: "INCONCLUSIVE:" } },
];

/** 表外能力的常见写法：给出明确拒收理由，顺带说明该提能力请求单 */
export const KNOWN_IMPOSSIBLE = {
  cookieJar: "没有 Cookie 容器：会话凭据只能由 Host 保险库按身份名注入",
  headers: "白盒执行器不接受配方自带请求头：头由 httpJson 合成（黑盒的 Origin 类探测另有条道）",
  proxy: "无代理通道",
  clientCert: "无客户端证书 / TLS 自定义",
  stream: "无流式响应，响应体一次性读回",
  retry: "无自动重试（重试会让「第几次打到」不可重放）",
  websocket: "不支持 WebSocket / SSE",
  oob: "无带外信道（DNS / 反连），SSRF 只打本机 canary",
  follow: "重定向用 request.follow 声明，不在请求动作上挂任意 follow 标志",
  concurrency: "并发是 request.concurrent 的动作，不是请求参数",
  timeout: "超时用 timeoutMs（Host 侧夹在 1s–120s），不接受别的写法",
};

const ACTION_BY_NAME = new Map(ACTIONS.map((a) => [a.name, a]));
const RULE_BY_NAME = new Map(VERDICT_RULES.map((r) => [r.name, r]));

/** 身份必须是保险库条目名，不是凭据值——凭据值一旦写进配方就会跟着仓库外泄 */
const IDENTITY_RE = /^[a-z][a-z0-9_-]{0,31}$/;

function looksLikeCredential(v) {
  const s = String(v ?? "").replace(/\s/g, "");
  return /^bearer/i.test(s) || /^eyJ/.test(s) || /[A-Za-z0-9+/=]{32,}/.test(s) || s.includes("token=");
}

/** 名字相似度：用于「你是不是想用 X」——拒收要能指回表内最近的那个动作 */
export function closestActionName(name) {
  const parts = String(name ?? "").toLowerCase().split(/[._-]/).filter(Boolean);
  if (!parts.length) return null;
  const tail = parts[parts.length - 1];
  let best = null;
  let bestScore = 0;
  for (const a of ACTIONS) {
    const segs = a.name.toLowerCase().split(".");
    let score = 0;
    for (const p of parts) if (segs.includes(p)) score += 2;
    const last = segs[segs.length - 1];
    if (tail && (last.startsWith(tail) || tail.startsWith(last))) score += 1;
    if (score > bestScore) {
      bestScore = score;
      best = a.name;
    }
  }
  // 至少要有一段完全对得上才给建议：对不上的硬凑会把人引向另一条错动作
  return bestScore >= 2 ? best : null;
}

/**
 * 拒收项会把「给了什么」原样回显给人读。身份/请求体/载荷这些位置一旦填错，
 * 回显本身就是一次外泄（拒收文案会进事件流与报告），所以值一律先换掉再留长度。
 */
function safeGiven(key, value) {
  if (value == null) return null;
  const s = typeof value === "string" ? value : JSON.stringify(value);
  if (["identity", "body", "content", "claims", "token", "password"].includes(String(key))) {
    return `<已隐去 · ${String(value).length} 字符>`;
  }
  if (typeof value === "string" && looksLikeCredential(value)) return `<疑似凭据，已隐去 · ${value.length} 字符>`;
  return s?.length > 80 ? `${s.slice(0, 80)}…` : s;
}

const reject = (where, rule, given, detail) => ({ where, rule, given: safeGiven(where.split(".").pop(), given), ...detail });

/**
 * 校验一张配方。返回 `{ok, rejections}`；拒收项带「缺哪个动作」与最近已注册动作，
 * 以便下游把它变成能力请求单。
 *
 * 校验器的权限边界：它只否决，不给通过背书——`ok:true` 只表示「填表合法」，
 * 表示不了「这条配方打得中」。打不打得中由判卷器（第 6 项）拿考卷验。
 */
export function validateRecipe(recipe) {
  const out = [];
  const push = (where, rule, given, detail) => out.push(reject(where, rule, given, detail));
  if (!recipe || typeof recipe !== "object") {
    return { ok: false, rejections: [reject("<root>", "not_object", recipe, { why: "配方必须是一张表" })] };
  }
  if (recipe.version !== RECIPE_VERSION) {
    push("version", "bad_version", recipe.version, { why: `只认 ${RECIPE_VERSION}` });
  }
  if (typeof recipe.family !== "string" || !recipe.family.trim()) {
    push("family", "missing_family", recipe.family, { why: "必须声明攻击族，开关与判据都按族生效" });
  }
  if (!Array.isArray(recipe.steps) || recipe.steps.length === 0) {
    push("steps", "empty_steps", recipe.steps, { why: "至少要有一步" });
  }

  const seen = new Set();
  for (const [i, step] of (Array.isArray(recipe.steps) ? recipe.steps : []).entries()) {
    const where = `steps[${i}]${step?.id ? `#${step.id}` : ""}`;
    if (!step || typeof step !== "object") {
      push(where, "bad_step", step, { why: "每一步必须是对象" });
      continue;
    }
    if (typeof step.id !== "string" || !step.id.trim()) push(`${where}.id`, "missing_id", step.id, { why: "步骤要有 id，后续步骤与判据靠它引用" });
    else if (seen.has(step.id)) push(`${where}.id`, "duplicate_id", step.id, { why: "id 重复，引用会不确定" });
    else seen.add(step.id);

    const action = ACTION_BY_NAME.get(step.action);
    if (!action) {
      const known = KNOWN_IMPOSSIBLE[step.action];
      push(`${where}.action`, "action_out_of_table", step.action, {
        why: known ?? "动作表里没有这一项，执行器不会去做它",
        missingAction: step.action,
        nearest: closestActionName(step.action),
        needCapabilityRequest: !known,
      });
      continue;
    }
    if (step.uses != null && (step.uses === step.id || !seen.has(step.uses))) {
      push(`${where}.uses`, "bad_reference", step.uses, { why: "只能引用它之前的步骤 id" });
    }

    // 参数级表外：动作名对了但偷偷挂上执行器不认的键，同样拒收
    for (const key of Object.keys(step)) {
      if (["id", "action", "uses", "note"].includes(key)) continue;
      if (key === "gate") {
        // 声明依赖哪个开关是允许的（执行器按开关放行与否），但开关名必须真存在，值不许自造
        if (!GATE_NAMES.includes(String(step.gate))) {
          push(`${where}.gate`, "gate_unknown", step.gate, { why: `开关只有 ${GATE_NAMES.join("/")}` });
        }
        continue;
      }
      if (!action.params.includes(key)) {
        push(`${where}.${key}`, "param_out_of_table", key, {
          why: KNOWN_IMPOSSIBLE[key] ?? `${action.name} 不读这个键，写了也不会被执行`,
          missingAction: `${action.name}.${key}`,
          allowed: action.params,
        });
      }
    }
    for (const [key, allowed] of Object.entries(action.enums ?? {})) {
      if (step[key] != null && !allowed.includes(String(step[key]))) {
        push(`${where}.${key}`, "enum_value", step[key], { why: `${action.name} 的 ${key} 只能取 ${allowed.join("/")}` });
      }
    }
    for (const req of action.required) {
      if (step[req] == null) push(`${where}.${req}`, "missing_required", null, { why: `${action.name} 需要 ${req}` });
    }
    if (action.limits && step.max != null && Number(step.max) > action.limits.max) {
      push(`${where}.max`, "over_limit", step.max, { why: `${action.name} 最多 ${action.limits.max}，执行器就写死这么多` });
    }
    if (step.method != null) {
      const m = String(step.method).toUpperCase();
      if (m === "CONNECT" || m === "TRACE") push(`${where}.method`, "method_denied", step.method, { why: "Host 层硬拒 CONNECT/TRACE" });
      else if (!METHODS.includes(m)) push(`${where}.method`, "method_unknown", step.method, { why: `只认 ${METHODS.join("/")}` });
    }
    if (step.identity != null && !IDENTITY_RE.test(String(step.identity))) {
      push(`${where}.identity`, "bad_identity", step.identity, {
        why: looksLikeCredential(step.identity)
          ? "身份位只能填保险库里的名字，凭据值不许进配方（它是要进仓库的渠道）"
          : "身份名要匹配 /^[a-z][a-z0-9_-]{0,31}$/",
      });
    }
    for (const key of ["path", "operation", "canary"]) {
      const v = step[key];
      if (typeof v !== "string") continue;
      const slot = /^\{slot:([a-zA-Z]+)\}$/.exec(v.trim());
      if (slot && !SLOTS.includes(slot[1])) {
        push(`${where}.${key}`, "slot_unknown", slot[1], { why: `探测计划里没有这个槽位，可用的是 ${SLOTS.join("/")}` });
      }
      if (!slot && !v.startsWith("/") && key === "path") {
        push(`${where}.path`, "bad_path", v, { why: "路径必须是 / 开头或 {slot:x} 形式" });
      }
    }
  }

  const verdict = recipe.verdict;
  if (!verdict || typeof verdict !== "object") {
    push("verdict", "missing_verdict", verdict, { why: "必须引用一条已注册判据" });
  } else {
    if (!RULE_BY_NAME.has(verdict.rule)) {
      push("verdict.rule", "verdict_unknown", verdict.rule, { why: `判据只有这些：${VERDICT_RULES.map((r) => r.name).join("/")}` });
    }
    // 判据冻结：配方里出现内联判定，就是把「什么算打穿」的决定权交给了提议者
    for (const key of Object.keys(verdict)) {
      if (key === "rule") continue;
      push(`verdict.${key}`, "verdict_inline", key, { why: "判据不许内联：结论只能由判卷代码落笔，配方只能引用名字" });
    }
  }

  // 写/删探测的默认开关冻结：配方能声明依赖，不能自己翻
  for (const [k, v] of Object.entries(recipe)) {
    if (/^(allowMutation|allowDestructive|forceAllow|skipGate)$/.test(k)) {
      push(k, "gate_flip", v, { why: "写/删探测的默认开关是冻结项，配方无权打开；要开关请在 guardbuild.json 里由用户声明" });
    }
  }

  return { ok: out.length === 0, rejections: out };
}

export function formatRejections(result) {
  if (result.ok) return "填表合法：没有表外动作。但这只代表填表合法，不代表这条配方打得中——打不打得中由判卷器拿考卷验。";
  const lines = [`配方被拒收：${result.rejections.length} 处表外或冻结冲突`];
  for (const r of result.rejections) {
    const extra = r.missingAction
      ? ` → 缺的动作：${r.missingAction}${r.nearest ? `（表内最近的是 ${r.nearest}）` : ""}${r.needCapabilityRequest ? " → 应走能力请求单，不是改配方措辞绕过" : ""}`
      : "";
    lines.push(`- ${r.where}：${r.why ?? r.rule}${r.given != null ? `（给了 ${JSON.stringify(r.given)}）` : ""}${extra}`);
  }
  return lines.join("\n");
}

/**
 * 锚点自检：表上写的每条「能做」，代码里必须还找得到。
 * 实现被删掉而表没删 → 这里红，而不是等到真实项目上出现「表说打了、其实没打」。
 */
export function checkAnchors(repoRoot) {
  const entries = [
    ...ACTIONS.map((a) => [a.name, a.anchor]),
    ...VERDICT_RULES.map((r) => [r.name, r.anchor]),
    [`slots(${SLOTS.length})`, SLOTS_ANCHOR],
  ];
  const unresolved = [];
  for (const [name, anchor] of entries) {
    if (!anchor) continue;
    const file = path.join(repoRoot, anchor.file);
    let text = null;
    try {
      text = fs.readFileSync(file, "utf8");
    } catch {
      unresolved.push({ name, file: anchor.file, why: "文件不存在" });
      continue;
    }
    if (!text.includes(anchor.token)) unresolved.push({ name, file: anchor.file, why: `记号 ${anchor.token} 已不在该文件里` });
  }
  return { ok: unresolved.length === 0, checked: entries.length, unresolved };
}
