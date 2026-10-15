/**
 * 目标就绪行解析：真实项目常输出带 ANSI 色码的人类可读行
 * （如 "info: \x1b[36mServer listening on port \x1b[1m3000\x1b[22m\x1b[39m"），
 * 这里先 strip ANSI，再按形状依次提取端口。
 */
const ANSI_RE = /\u001b\[[0-9;?]*[A-Za-z]/g;

export function stripAnsi(s) {
  return String(s ?? "").replace(ANSI_RE, "");
}

/** 依次尝试：行内 JSON 的 port 字段 → host:port → "port NNNN" 文本回退 */
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

  m = line.match(/\bport\b[^\d]{0,12}(\d{2,5})\b/i);
  if (m) return Number(m[1]);

  return null;
}
