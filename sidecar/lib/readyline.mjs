/**
 * 目标就绪行解析：真实项目常输出带 ANSI 色码的人类可读行
 * （如 "info: \x1b[36mServer listening on port \x1b[1m3000\x1b[22m\x1b[39m"），
 * 这里先 strip ANSI，再按形状依次提取端口。
 */
const ANSI_RE = /\u001b\[[0-9;?]*[A-Za-z]/g;

export function stripAnsi(s) {
  return String(s ?? "").replace(ANSI_RE, "");
}

/** 依次尝试：行内 JSON 的 port 字段 → host:port → 「端口 NNNN」/ "port NNNN" 文本回退 */
export function parsePortFromLine(rawLine) {
  const line = stripAnsi(rawLine);
  if (!line) return null;

  const jsonStart = line.indexOf("{");
  if (jsonStart >= 0) {
    try {
      const p = Number(JSON.parse(line.slice(jsonStart)).port);
      if (Number.isInteger(p) && p > 0) return p;
    } catch {
      /* 非 JSON 行，继续按文本模式解析 */
    }
  }

  let m = line.match(/(?:127\.0\.0\.1|localhost|0\.0\.0\.0)[:=](\d{2,5})/i);
  if (m) return Number(m[1]);

  // 中文项目常见形状：服务器运行在端口 3000 / 监听端口：8080 / 端口号为 4123
  m = line.match(/端口(?:号)?\s*(?:[:：]|为|是)?\s*(\d{2,5})/);
  if (m) return Number(m[1]);

  m = line.match(/\bport\b[^\d]{0,12}(\d{2,5})\b/i);
  if (m) return Number(m[1]);

  // "Listening on 3000" / "Server running at 8080"（无 port 字样）
  m = line.match(/\b(?:listen(?:ing)?|running|serv(?:ing|ed)|started)\b[^\d]{0,24}(\d{2,5})\b/i);
  if (m) return Number(m[1]);

  return null;
}
