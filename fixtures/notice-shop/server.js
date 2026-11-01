import http from "node:http";
import { handleRequest } from "./src/app.js";

/**
 * Node 的 IncomingMessage 没有 req.body。路由块要写成真实的 `const { column } = req.body;` 形态，
 * 所以在这层先把请求体读完并挂上去（JSON 与表单两种编码），handleRequest 只负责分发。
 */
function readRaw(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", () => resolve(""));
  });
}

function parseBody(raw, contentType) {
  if (!raw) return {};
  if (String(contentType).includes("application/x-www-form-urlencoded")) {
    return Object.fromEntries(new URLSearchParams(raw));
  }
  try {
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

const server = http.createServer((req, res) => {
  readRaw(req).then((raw) => {
    req.body = parseBody(raw, req.headers["content-type"]);
    return handleRequest(req, res);
  });
});

const port = Number(process.env.PORT || 0);
server.listen(port, "127.0.0.1", () => {
  const actual = server.address().port;
  console.log(`NoticeShop 已就绪: http://127.0.0.1:${actual}`);
  console.log(`GB_LISTEN ${JSON.stringify({ port: actual })}`);
});
