/**
 * LLM 编码代理（coding agent）：把「改代码」能力接回主流程，但只产出补丁意图。
 *
 * 信任模型（与侦察模块同一条边界）：
 *  - LLM 只能返回 {file, search, replace, reason}，不写文件、不执行命令、不批准补丁；
 *  - 真正的写入由 Host 在隔离 worktree 的真实字节上执行（fs.write，count=1），
 *    Sidecar 先在真实内容上校验锚点唯一、文件在候选范围内、改动规模受限；
 *  - 补丁生成后仍要跑「攻击用例失效 + 业务用例不回归」双重验收，通过才交人工审查；
 *  - 密钥只从进程环境 DEEPSEEK_API_KEY 读取，出站统一走 Host http.request。
 *
 * 因此 LLM 输出是不可信的：任何校验失败的补丁一律丢弃并记录原因，绝不猜测修补。
 */
import { RPC_TO_HOST } from "../../shared/protocol.mjs";
import { apiKey, chat, parseJson } from "./llm.mjs";

export const LLM_PATCH_VERSION = "llm-patch-v1";

const MAX_SNIPPET_CHARS = 24_000;
const MAX_PATCHES_PER_FILE = 4;
const MAX_SEARCH_LINES = 80;
const MAX_ADDED_LINES = 24;
const MAX_REPLACEMENT_CHARS = 4_000;
const MIN_SEARCH_CHARS = 4;
const MAX_LLM_FILES_PER_SESSION = 6;
const PATCH_TIMEOUT_MS = 90_000;
const REDACTION_MARKER = "***";

const SOURCE_EXT_RE = /\.(?:js|mjs|cjs|ts|tsx|jsx|py|go|rb|php|cs|java|kt|graphql|gql)$/i;
const FORBIDDEN_DIR_RE =
  /(?:^|\/)(?:node_modules|dist|build|out|coverage|\.git|\.next|\.nuxt|vendor|tests?|__tests__|e2e|fixtures?|public|static)(?:\/|$)/i;
const FORBIDDEN_FILE_RE =
  /(?:^|\/)(?:package(?:-lock)?\.json|pnpm-lock\.yaml|npm-shrinkwrap\.json|yarn\.lock\w*|bun\.lockb|composer\.json|gemfile\*?|go\.sum|cargo\.toml|guardbuild\.json|\.babelrc|webpack\.config\.[cm]?js|vite\.config\.[cm]?[jt]s|dockerfile.*|docker-compose\.ya?ml|compose\.ya?ml|\.?env\w*|.*\.(?:pem|key|p12|pfx|crt|sqlite3?|db|toml|ya?ml|ini|conf|sql))(?:$|\/)/i;
const TEST_FILE_RE = /(?:\.(?:test|spec)\.[cm]?[jt]sx?$|_test\.go$|test_[^/]+\.py$|\.robot$)/i;
// 补丁里新增这些调用意味着「修复」在做与本漏洞无关的事（起进程/执行任意代码）
const DANGEROUS_ADDITION_RE = /(?:\bchild_process\b|\brequire\s*\(\s*['"]child_process|\bimport\s+[\s\S]{0,40}child_process|\beval\s*\(|\bnew\s+Function\s*\(|\brm\s+-rf\b)/i;

function normRel(v) {
  return String(v ?? "").replace(/\\/g, "/").replace(/^\.\//, "").replace(/\/+/g, "/");
}

/** 只允许对「可定位到源码文件、非配置/依赖/测试/产物」的候选发起补丁请求 */
export function patchTargetAllowed(rel) {
  const r = normRel(rel);
  if (!r || r.includes("..") || r.startsWith("/") || /^[A-Za-z]:/.test(r)) {
    return { ok: false, reason: "路径越出项目范围或不是相对路径" };
  }
  if (FORBIDDEN_DIR_RE.test(r)) return { ok: false, reason: "位于依赖/产物/测试目录" };
  if (FORBIDDEN_FILE_RE.test(r)) return { ok: false, reason: "属于依赖清单、锁文件、配置或数据文件" };
  if (TEST_FILE_RE.test(r)) return { ok: false, reason: "属于测试文件" };
  if (!SOURCE_EXT_RE.test(r)) return { ok: false, reason: "不是可识别的源码文件" };
  return { ok: true, reason: null };
}

function countOccurrences(haystack, needle) {
  let count = 0;
  let from = 0;
  while (true) {
    const i = haystack.indexOf(needle, from);
    if (i === -1) break;
    count += 1;
    if (count > 2) break;
    from = i + needle.length;
  }
  return count;
}

function lineCount(text) {
  return String(text).split("\n").length;
}

function eolOf(text) {
  return text.includes("\r\n") ? "\r\n" : "\n";
}

/** 统一行尾，避免 LLM 返回的锚点因 CRLF/LF 差异与真实字节失配 */
function normalizeEol(text, content) {
  const eol = eolOf(content);
  const unified = String(text).replace(/\r\n/g, "\n");
  return eol === "\r\n" ? unified.replace(/\n/g, "\r\n") : unified;
}

/**
 * 严格校验 LLM 返回的补丁意图。只接受锚点在真实内容中恰好出现一次的补丁。
 * @returns {{ ops: Array<{find:string,replace:string,count:number}>, accepted: object[], rejected: object[] }}
 */
export function validatePatchOutput(raw, { rel, content, candidateKeys = [] } = {}) {
  const accepted = [];
  const rejected = [];
  const ops = [];
  const reject = (item, reason) => {
    rejected.push({
      file: normRel(item?.file ?? ""),
      candidate: typeof item?.candidate === "string" ? item.candidate.slice(0, 120) : null,
      reason,
    });
  };

  if (!raw || typeof raw !== "object" || !Array.isArray(raw.patches)) {
    return { ops: [], accepted, rejected: [{ file: "", candidate: null, reason: "输出缺少 patches 数组" }] };
  }
  if (raw.patches.length === 0) {
    return { ops: [], accepted, rejected: [{ file: normRel(rel), candidate: null, reason: "模型判定无法安全自动修复" }] };
  }

  const target = normRel(rel);
  const seen = new Set();
  for (const item of raw.patches) {
    if (accepted.length >= MAX_PATCHES_PER_FILE) {
      reject(item, `超过单文件补丁上限 ${MAX_PATCHES_PER_FILE}`);
      continue;
    }
    if (!item || typeof item !== "object") {
      reject(item, "补丁项不是对象");
      continue;
    }
    const fileRel = normRel(item.file);
    if (!fileRel) {
      reject(item, "缺少 file 字段");
      continue;
    }
    if (fileRel.toLowerCase() !== target.toLowerCase()) {
      reject(item, `补丁目标 ${fileRel} 越出本次候选文件 ${target}`);
      continue;
    }
    const allowed = patchTargetAllowed(target);
    if (!allowed.ok) {
      reject(item, `不允许修改该文件：${allowed.reason}`);
      continue;
    }
    if (typeof item.search !== "string" || typeof item.replace !== "string") {
      reject(item, "search/replace 必须是字符串");
      continue;
    }
    if (item.search.length < MIN_SEARCH_CHARS) {
      reject(item, `锚点过短（<${MIN_SEARCH_CHARS} 字符），可能被误匹配`);
      continue;
    }
    if (item.search.includes(REDACTION_MARKER) || item.replace.includes(REDACTION_MARKER)) {
      reject(item, "锚点含脱敏掩码，说明原文有敏感串已被遮蔽，无法定位真实字节");
      continue;
    }
    const cand = typeof item.candidate === "string" ? item.candidate.trim() : "";
    if (cand && candidateKeys.length && !candidateKeys.some((k) => k.toLowerCase() === cand.toLowerCase())) {
      reject(item, `candidate ${cand} 不在本次待修复清单中`);
      continue;
    }
    if (DANGEROUS_ADDITION_RE.test(item.replace)) {
      reject(item, "补丁新增子进程/动态执行等与漏洞修复无关的危险调用");
      continue;
    }
    if (normalizeEol(item.search, content) === normalizeEol(item.replace, content)) {
      reject(item, "search 与 replace 相同（空操作）");
      continue;
    }
    const find = normalizeEol(item.search, content);
    const replace = normalizeEol(item.replace, content);
    if (seen.has(find)) {
      reject(item, "锚点重复（同一位置已被更早的补丁占用）");
      continue;
    }
    const hits = countOccurrences(content, find);
    if (hits === 0) {
      reject(item, "锚点未在文件真实内容中出现（模型改写了原文或存在未提交差异）");
      continue;
    }
    if (hits > 1) {
      reject(item, "锚点在文件中出现多次，无法唯一定位");
      continue;
    }
    const searchLines = lineCount(find);
    const added = lineCount(replace) - searchLines;
    if (searchLines > MAX_SEARCH_LINES) {
      reject(item, `锚点跨 ${searchLines} 行，超过 ${MAX_SEARCH_LINES} 行上限`);
      continue;
    }
    if (added > MAX_ADDED_LINES) {
      reject(item, `新增 ${added} 行，超过 ${MAX_ADDED_LINES} 行上限（要求最小改动）`);
      continue;
    }
    if (replace.length > MAX_REPLACEMENT_CHARS) {
      reject(item, `补丁体 ${replace.length} 字符，超过 ${MAX_REPLACEMENT_CHARS} 上限`);
      continue;
    }
    // 锚点之间不得重叠（否则第二条会在已被改写的内容上失配）
    if (ops.some((o) => find.includes(o.find) || o.find.includes(find))) {
      reject(item, "锚点与更早的补丁重叠");
      continue;
    }
    seen.add(find);
    ops.push({ find, replace, count: 1 });
    accepted.push({
      candidate: cand || null,
      reason: typeof item.reason === "string" ? item.reason.slice(0, 300) : null,
      addedLines: added,
    });
  }

  return { ops, accepted, rejected };
}

function describeCandidates(candidates) {
  return candidates.map((c) => {
    const guard = [
      c.hasAuth === false ? "缺少认证" : "已有认证",
      c.hasOwnerGuard ? "已有归属校验" : "缺少归属校验",
      c.hasRoleGuard ? "已有角色校验" : "未见角色校验",
    ].join("，");
    return {
      candidate: `${c.method} ${c.fullPath ?? c.path}`,
      kind: c.kind ?? null,
      resource: c.resource ?? null,
      style: c.style ?? null,
      line: c.startLine ?? null,
      signal: guard,
    };
  });
}

function patternMatches(pattern, actual) {
  const a = String(pattern ?? "").split("?")[0].split("/").filter(Boolean);
  const b = String(actual ?? "").split("?")[0].split("/").filter(Boolean);
  if (a.length !== b.length) return false;
  return a.every((seg, i) => seg.startsWith(":") || seg === b[i]);
}

function evidenceFor(candidates, evidence) {
  const out = [];
  for (const e of evidence ?? []) {
    if (e.phase && e.phase !== "pre") continue;
    const hit = candidates.some(
      (c) =>
        String(c.method).toUpperCase() === String(e.method).toUpperCase() &&
        patternMatches(c.fullPath ?? c.path, e.endpoint)
    );
    if (!hit) continue;
    out.push({
      case: e.name ?? e.caseId ?? null,
      verdict: e.verdict,
      actual: e.actual ?? null,
      status: e.response?.status ?? null,
      impact: e.impact ?? null,
    });
    if (out.length >= 6) break;
  }
  return out;
}

const SYSTEM_PROMPT = `你是资深应用安全工程师，为「已通过动态复现证明存在」的越权/注入类漏洞生成最小修复补丁意图。

严格要求：
1. 你只能返回补丁意图，格式为 JSON 对象：{"patches":[{"file":"相对路径","search":"文件中逐字连续原文","replace":"替换后的文本","candidate":"METHOD /path","reason":"一句话说明"}]}
2. search 必须逐字复制所提供源码中真实存在的连续片段（含缩进与标点），并在该文件中唯一出现；不要改写、不要省略、不要加行号。
3. replace 是最小改动：只加入权限/归属校验或参数化处理，保持原有功能与响应契约，不重构、不调整格式、不新增依赖、不改动其它逻辑。
4. 不得改动依赖清单、锁文件、配置、环境变量、测试或数据文件；只改所提供的那一个源码文件。
5. 无法在单文件内安全修复时，返回 {"patches":[]} 并在 note 字段说明原因，不要勉强编造补丁。
6. 不要输出代码之外的解释文字，不要输出 markdown 代码块以外的内容。`;

/** 构造提示词：只喂脱敏后的源码片段、已固化证据与上一轮失败反馈 */
export function buildPatchPrompt({ rel, candidates, evidence, snippet, note = null, feedback = null }) {
  const body = {
    file: normRel(rel),
    candidates: describeCandidates(candidates),
    reproduced_evidence: evidenceFor(candidates, evidence),
    note:
      note ??
      (feedback
        ? "上一轮补丁未通过双重验收。previous_attempt 里带有失败用例、修复后实例的真实日志尾部与上一轮 diff，请据此判断补丁的运行时后果，再重新生成最小补丁：攻击必须被拒绝（401/403/空结果），业务基线必须保持原有 2xx 与响应契约。"
        : "修复必须让上述攻击用例被拒绝（401/403/空结果），同时合法用户的正常请求仍返回 2xx。"),
    source_lines: snippet,
  };
  if (feedback) body.previous_attempt = feedback;
  return JSON.stringify(body, null, 1);
}

/** 是否启用 LLM 编码代理：需要 API 密钥 + 契约显式开启（或环境变量强制） */
export function patchEnabled(ctx) {
  if (!apiKey()) return false;
  const cfg = ctx?.llmConfig ?? null;
  if (cfg?.patch === false) return false;
  if (cfg?.patch === true) return true;
  return process.env.GUARDBUILD_LLM_PATCH === "1";
}

/** 取脱敏源码文本（提示词用）；真实锚点校验走调用方传入的 redact:false 内容 */
async function readRedactedSnippet(ctx, file, readRedacted) {
  let text;
  try {
    if (typeof readRedacted === "function") text = String(await readRedacted());
    else {
      const read = await ctx.rpc.request(
        RPC_TO_HOST.FS_READ,
        { token: ctx.tokens.project, path: file },
        { timeoutMs: 30_000 }
      );
      text = String(read?.content ?? "");
    }
  } catch (e) {
    throw new Error(`读取脱敏源码失败：${e.message}`);
  }
  if (text.length > MAX_SNIPPET_CHARS) {
    return { snippet: `${text.slice(0, MAX_SNIPPET_CHARS)}\n/* …(截断，共 ${text.length} 字符)… */`, truncated: true };
  }
  return { snippet: text, truncated: false };
}

/**
 * 为一个文件的候选请求补丁意图。
 * @returns {Promise<{ops:object[], accepted:object[], rejected:object[], model:string|null, usage:object|null, failure:string|null}>}
 */
export async function requestPatchIntent(
  ctx,
  { file, rel, content, candidates, evidence, model = null, getToken, chatImpl = chat, maxFiles = MAX_LLM_FILES_PER_SESSION, readRedacted = null, feedback = null } = {}
) {
  const empty = { ops: [], accepted: [], rejected: [], model: model ?? null, usage: null, failure: null };
  if (!Array.isArray(candidates) || candidates.length === 0) return empty;

  const allowed = patchTargetAllowed(rel);
  if (!allowed.ok) {
    return { ...empty, rejected: [{ file: normRel(rel), candidate: null, reason: `不允许修改：${allowed.reason}` }] };
  }

  ctx._llmPatchFiles = ctx._llmPatchFiles ?? new Set();
  if (ctx._llmPatchFiles.size >= maxFiles && !ctx._llmPatchFiles.has(normRel(rel))) {
    return { ...empty, failure: `已达本次会话 LLM 补丁文件上限（${maxFiles} 个），该文件转人工修复` };
  }

  let snippet;
  try {
    snippet = await readRedactedSnippet(ctx, file, readRedacted);
  } catch (e) {
    return { ...empty, failure: e.message };
  }

  const candidateKeys = describeCandidates(candidates).map((c) => c.candidate);
  const userPrompt = buildPatchPrompt({
    rel,
    candidates,
    evidence,
    snippet: snippet.snippet,
    feedback,
  });

  let res;
  try {
    res = await chatImpl(ctx, {
      systemPrompt: SYSTEM_PROMPT,
      userPrompt,
      getToken,
      model,
      timeoutMs: PATCH_TIMEOUT_MS,
      maxTokens: 1200,
      purpose: "发送补丁意图（编码代理）",
    });
  } catch (e) {
    return { ...empty, failure: `LLM 请求失败：${e?.message ?? e}` };
  }

  let raw;
  try {
    raw = parseJson(res.content);
  } catch (e) {
    return { ...empty, model: res?.model ?? model, failure: `LLM 输出非法 JSON：${e?.message ?? e}` };
  }

  const validated = validatePatchOutput(raw, { rel, content, candidateKeys });
  ctx._llmPatchFiles.add(normRel(rel));

  return {
    ...validated,
    model: res?.model ?? model ?? null,
    usage: res?.usage ?? null,
    truncatedSnippet: !!snippet.truncated,
    note: typeof raw.note === "string" ? raw.note.slice(0, 300) : null,
    failure: validated.ops.length === 0 ? validated.rejected[0]?.reason ?? "模型未给出可用补丁" : null,
  };
}
