import { createServer } from "./src/express-lite.js";
import { router } from "./src/app.js";

const server = createServer(router);
const port = Number(process.env.PORT || 0);
server.listen(port, "127.0.0.1", () => {
  const actual = server.address().port;
  console.log(`LedgerShop 已就绪: http://127.0.0.1:${actual}`);
  console.log(`GB_LISTEN ${JSON.stringify({ port: actual })}`);
});
