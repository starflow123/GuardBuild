// 共享 HTTP 辅助：响应写出、请求体读取、路径参数规整（真实项目常见的「先规整再取数」写法）

export function json(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(payload),
  });
  res.end(payload);
}

export function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      if (!raw) return resolve({});
      try {
        resolve(JSON.parse(raw));
      } catch {
        resolve({});
      }
    });
  });
}

export function normalizeId(raw) {
  const parsed = parseInt(String(raw), 10);
  return Number.isNaN(parsed) ? -1 : parsed;
}
