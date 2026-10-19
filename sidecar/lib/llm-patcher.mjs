/**
 * LLM 补丁生成器（coding agent）：对模板修不了的漏洞，调 DeepSeek 读代码上下文生成补丁。
 *
 * 安全边界：
 *  - 只产出 diff 文本，不直接写文件；人 review 后由 patcher.mjs 写入
 *  - 无 DEEPSEEK_API_KEY 时自动降级，不假装修复成功
 *  - 输出经过 schema 校验，格式不对就拒绝
 */
import { RPC_TO_HOST } from "../../shared/protocol.mjs";

const DEEPSEEK_URL = "https://api.deepseek.com/v1/chat/completions";

/** 构造发给 LLM 的提示词 */
function buildPrompt(findings, fileContents) {
  return `你是一个安全工程师。以下是扫描发现的漏洞和相关源码。请为每个漏洞生成最小修复补丁。

漏洞列表：
${findings.map((f, i) => `${i + 1}. [${f.type}] ${f.method} ${f.path}\n   ${f.detail}`).join("\n")}

相关源码：
${fileContents.map((fc) => `--- ${fc.path} ---\n${fc.content}`).join("\n\n")}

要求：
1. 每个补丁给出 file_path、search（要替换的原文）、replace（修复后代码）
2. 最小改动，不重构
3. 不新增依赖
4. 输出 JSON 数组格式，不要多余文字`;
}

/** 调用 DeepSeek API */
async function callDeepSeek(prompt, apiKey) {
  if (!apiKey) throw new Error("DEEPSEEK_API_KEY 未配置");
  const res = await fetch(DEEPSEEK_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model: "deepseek-chat",
      messages: [{ role: "user", content: prompt }],
      temperature: 0.1,
      response_format: { type: "json_object" },
    }),
  });
  if (!res.ok) throw new Error(`DeepSeek API ${res.status}: ${await res.text()}`);
  const data = await res.json();
  return data.choices?.[0]?.message?.content ?? "";
}

/** 解析 LLM 返回的 JSON 补丁 */
function parsePatches(raw) {
  try {
    const parsed = JSON.parse(raw);
    const arr = Array.isArray(parsed) ? parsed : parsed.patches ?? [];
    return arr
      .filter((p) => p.file_path && p.search && p.replace)
      .map((p) => ({
        file: p.file_path,
        search: p.search,
        replace: p.replace,
        reason: p.reason ?? "",
      }));
  } catch (e) {
    throw new Error(`LLM 返回格式非法：${e.message}`);
  }
}

/**
 * 为漏洞列表生成 LLM 补丁。
 * @param {object} ctx 会话上下文
 * @param {Array} findings 漏洞列表（来自黑盒或白盒扫描）
 * @param {object} opts { apiKey, files: [{path, content}] }
 * @returns { patches, degraded }
 */
export async function generateLlmPatch(ctx, findings, opts = {}) {
  const apiKey = opts.apiKey ?? process.env.DEEPSEEK_API_KEY;

  // 无 key → 降级
  if (!apiKey) {
    ctx.emit?.({
      kind: "warning",
      severity: "warn",
      message: "[LLM-Patcher] 未配置 DEEPSEEK_API_KEY，跳过 AI 修复，仅保留模板补丁",
    });
    return { patches: [], degraded: true };
  }

  // 读相关文件
  const files = opts.files ?? [];
  if (files.length === 0) {
    ctx.emit?.({
      kind: "warning",
      severity: "warn",
      message: "[LLM-Patcher] 未提供源码文件，无法生成补丁",
    });
    return { patches: [], degraded: true };
  }

  const prompt = buildPrompt(findings, files);
  ctx.emit?.({
    kind: "info",
    severity: "info",
    message: `[LLM-Patcher] 调用 DeepSeek 生成补丁（${findings.length} 个漏洞，${files.length} 个文件）`,
  });

  try {
    const raw = await callDeepSeek(prompt, apiKey);
    const patches = parsePatches(raw);
    ctx.emit?.({
      kind: "info",
      severity: "info",
      message: `[LLM-Patcher] 生成 ${patches.length} 个补丁，待人工 review`,
    });
    return { patches, degraded: false };
  } catch (e) {
    ctx.emit?.({
      kind: "warning",
      severity: "warn",
      message: `[LLM-Patcher] AI 修复失败：${e.message}，回落到模板修复`,
    });
    return { patches: [], degraded: true };
  }
}
