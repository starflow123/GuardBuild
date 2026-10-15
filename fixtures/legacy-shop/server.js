import http from "node:http";
import { handleRequest } from "./src/app.js";

const port = Number(process.env.PORT || 0);

const server = http.createServer((req, res) => {
  handleRequest(req, res).catch((err) => {
    console.error("unhandled:", err);
    res.writeHead(500, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "internal error" }));
  });
});

server.listen(port, "127.0.0.1", () => {
  const actual = server.address().port;
  // 模拟真实项目的人类可读就绪行：仅 ANSI 色码，无 JSON 握手、无 host:port 形态
  const cyan = "\u001b[36m";
  const bold = "\u001b[1m";
  const unbold = "\u001b[22m";
  const reset = "\u001b[39m";
  console.log(`info: ${cyan}LegacyShop server listening on port ${bold}${actual}${unbold}${reset}`);
});
