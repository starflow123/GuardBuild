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
  console.log(`SSRFShop 已就绪: http://127.0.0.1:${actual}`);
  console.log(`GB_LISTEN ${JSON.stringify({ port: actual })}`);
});
