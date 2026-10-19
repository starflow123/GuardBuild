import http from "node:http";
import { handleRequest } from "./lib/app.mjs";

const port = Number(process.env.PORT || 0);

const server = http.createServer((req, res) => {
  handleRequest(req, res).catch((err) => {
    console.error("unhandled:", err);
    res.writeHead(500, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "internal error" }));
  });
});

server.listen(port, "127.0.0.1", () => {
  console.log(`LLMShop listening on port ${server.address().port}`);
});
