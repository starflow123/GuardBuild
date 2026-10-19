/**
 * DeepSeek API 客户端（可选，接入侦察专用）。
 *
 * 安全边界：
 *  - 密钥只从进程环境 DEEPSEEK_API_KEY 读取，绝不写入 guardbuild.json / 仓库 / 证据库；
 *  - 出站统一走 Host 的 http.request + net.egress 作用域，Sidecar 不直连外网；
 *  - 默认关闭，只有 guardbuild.json 的 llm.enabled=true 或 GUARDBUILD_LLM_SCOUT=1 才调用；
 *  - 超时/非 2xx/非法 JSON 一律抛错，由调用方回落到确定性流程。
 */
import { RPC_TO_HOST } from "../../shared/protocol.mjs";

const DEFAULT_BASE = "https://api.deepseek.com/v1";
const DEFAULT_MODEL = "deepseek-chat";
export const DEFAULT_TIMEOUT_MS = 60_000;
export const MAX_PROMPT_CHARS = 60_000;

export class LlmError extends Error {
  constructor(message, { code = "llm_failed", hint = null, details = null } = {}) {
    super(message);
    this.code = code;
    this.hint = hint;
    this.details = details;
  }
}

export function apiKey() {
  const key = process.env.DEEPSEEK_API_KEY;
  return typeof key === "string" && key.trim() ? key.trim() : null;
}

export function isEnabled() {
  return !!apiKey();
}

export function baseUrl() {
  return (process.env.DEEPSEEK_BASE_URL ?? DEFAULT_BASE).replace(/\/+$/, "");
}

export function defaultModel() {
  return process.env.DEEPSEEK_MODEL?.trim() || DEFAULT_MODEL;
}

export function chatEndpoint() {
  return new URL(`${baseUrl()}/chat/completions`);
}

function isLoopback(host) {
  return host === "127.0.0.1" || host === "localhost" || host === "::1" || host === "[::1]";
}

/**
 * 经 Host 调用 DeepSeek chat completions。
 * @param {object} ctx 会话上下文（需 ctx.rpc.request）
 * @param {object} opts
 * @param {string} opts.systemPrompt
 * @param {string} opts.userPrompt
 * @param {(url: string, reason: string) => Promise<string>} opts.getToken 返回 net.egress/net.probe 令牌
 * @param {string} [opts.model]
 * @param {number} [opts.timeoutMs]
 * @param {number} [opts.maxTokens]
 */
export async function chat(
  ctx,
  {
    systemPrompt,
    userPrompt,
    getToken,
    model = null,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    maxTokens = 1500,
  } = {}
) {
  const key = apiKey();
  if (!key) {
    throw new LlmError("未配置 DEEPSEEK_API_KEY，LLM 接入侦察不可用", {
      code: "llm_not_configured",
      hint: "启动 GuardBuild 前设置环境变量 DEEPSEEK_API_KEY（只放环境变量，不要写进 guardbuild.json）",
    });
  }
  if (!ctx?.rpc?.request) throw new LlmError("缺少 Host RPC 上下文，拒绝直连外网", { code: "llm_no_rpc" });
  if (typeof getToken !== "function") throw new LlmError("缺少网络作用域令牌提供方", { code: "llm_no_token" });

  const promptChars = String(systemPrompt ?? "").length + String(userPrompt ?? "").length;
  if (promptChars > MAX_PROMPT_CHARS) {
    throw new LlmError(`侦察提示词过大（${promptChars} 字符 > ${MAX_PROMPT_CHARS}）`, {
      code: "llm_prompt_too_large",
    });
  }

  const url = chatEndpoint();
  if (url.protocol !== "https:" && !isLoopback(url.hostname)) {
    throw new LlmError("DeepSeek 端点必须是 https（或本机回环测试服务）", { code: "llm_insecure_endpoint" });
  }
  const token = await getToken(url.toString(), "向 DeepSeek 发送接入侦察请求");
  const body = JSON.stringify({
    model: model || defaultModel(),
    messages: [
      { role: "system", content: String(systemPrompt ?? "") },
      { role: "user", content: String(userPrompt ?? "") },
    ],
    temperature: 0.1,
    max_tokens: maxTokens,
    stream: false,
    response_format: { type: "json_object" },
  });

  let res;
  try {
    res = await ctx.rpc.request(
      RPC_TO_HOST.HTTP_REQUEST,
      {
        token,
        method: "POST",
        url: url.toString(),
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${key}`,
        },
        body,
        // 响应仍走 Host 脱敏：即使模型回显了源码片段里的敏感串也不会进入 Sidecar 日志
        redact: true,
        timeoutMs,
      },
      { timeoutMs: timeoutMs + 10_000 }
    );
  } catch (e) {
    throw new LlmError(`DeepSeek 请求失败：${e.message}`, { code: "llm_request_failed" });
  }

  if (!res || typeof res.status !== "number") {
    throw new LlmError("Host 返回了非法 HTTP 响应", { code: "llm_bad_response" });
  }
  if (res.status < 200 || res.status >= 300) {
    const snippet = String(res.body ?? "").slice(0, 300);
    throw new LlmError(`DeepSeek API 返回 HTTP ${res.status}`, {
      code: "llm_http_error",
      hint: snippet || null,
      details: { status: res.status },
    });
  }

  let json;
  try {
    json = JSON.parse(res.body);
  } catch (e) {
    throw new LlmError(`DeepSeek 响应不是合法 JSON：${e.message}`, { code: "llm_bad_json" });
  }
  const content = json?.choices?.[0]?.message?.content ?? "";
  if (typeof content !== "string" || !content.trim()) {
    throw new LlmError("DeepSeek 返回空内容", { code: "llm_empty" });
  }
  return {
    content,
    json,
    model: model || defaultModel(),
    usage: json?.usage ?? null,
  };
}

/** 把 LLM 文本解析为对象；失败抛错，不猜测。 */
export function parseJson(content) {
  const text = String(content ?? "").trim();
  const fenced = /^```(?:json)?\s*([\s\S]*?)\s*```$/m.exec(text);
  const body = fenced ? fenced[1] : text;
  let parsed;
  try {
    parsed = JSON.parse(body);
  } catch (e) {
    throw new LlmError(`DeepSeek 返回非合法 JSON：${e.message}`, { code: "llm_bad_json" });
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new LlmError("DeepSeek 返回的 JSON 顶层必须是对象", { code: "llm_bad_shape" });
  }
  return parsed;
}
