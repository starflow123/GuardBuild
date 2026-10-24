import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { RPC_TO_HOST } from "../../shared/protocol.mjs";
import { analyzeProject } from "../lib/analyzer.mjs";
import { buildProbePlan } from "../lib/planner.mjs";
import { buildCases } from "../lib/probe.mjs";
import { findUploadSignal } from "../lib/signals.mjs";

function listen(handler) {
  return new Promise((resolve) => {
    const server = createServer(handler);
    server.listen(0, "127.0.0.1", () => {
      const port = server.address().port;
      resolve({ server, url: `http://127.0.0.1:${port}` });
    });
  });
}

function stubCtx() {
  return {
    tokens: { net: "net-token" },
    loginConfig: null,
    rpc: {
      request: async (method, params) => {
        if (method !== RPC_TO_HOST.HTTP_REQUEST) throw new Error(`不应调用 ${method}`);
        const res = await fetch(params.url, {
          method: params.method,
          headers: params.headers,
          body: params.body,
        });
        return {
          status: res.status,
          statusText: res.statusText,
          body: await res.text(),
          headers: Object.fromEntries(res.headers),
        };
      },
    },
  };
}

test("findUploadSignal: 识别服务端上传入口并收集字段名与防护信号", () => {
  assert.equal(findUploadSignal('router.post("/avatar", upload.single("avatar"), handler);').field, "avatar");
  assert.equal(findUploadSignal("const files = req.files;").field, null);
  assert.equal(findUploadSignal("async def upload(file: UploadFile = File(...)): ...").field, "file");
  assert.ok(findUploadSignal("const form = await request.formData();"));

  const guarded = findUploadSignal(
    'const upload = multer({ fileFilter, limits: { fileSize: 1024 } });\nif (!/\\.(png|jpe?g)$/.test(name)) reject();'
  );
  assert.ok(guarded.validations.includes("文件过滤（fileFilter）"));
  assert.ok(guarded.validations.includes("大小限制"));
  assert.ok(guarded.validations.includes("扩展名白名单"));

  assert.equal(findUploadSignal("const body = await readJson(req);"), null, "普通 JSON 请求不应命中");
  assert.equal(findUploadSignal("const form = new FormData();"), null, "客户端构造 FormData 不应命中");
});

test("analyzeProject + buildProbePlan: 上传候选进入探测计划", async () => {
  const R = "\\\\?\\D:\\upload";
  const source = [
    "export async function handleRequest(req, res) {",
    '  if (method === "POST" && pathname === "/api/avatar") {',
    "    if (!auth) return json(res, 401, { error: '未登录' });",
    "    const uploaded = req.files ?? (await parseMultipart(req));",
    "    const file = uploaded[0];",
    "    files.set(file.filename, file);",
    '    return json(res, 201, { url: `/uploads/${file.filename}` });',
    "  }",
    "}",
  ].join("\n");
  const ctx = {
    projectRoot: R,
    tokens: { project: "tok" },
    rpc: {
      request: async (method, params) => {
        if (method === "fs.list") return { entries: [{ path: `${R}\\server.js`, kind: "file", size: 400 }] };
        if (method === "fs.read") return { content: source, size: 400, redacted: false, redactions: [] };
        throw new Error(`不应调用 ${method}`);
      },
    },
  };
  const a = await analyzeProject(ctx);
  const cand = a.candidates.find((c) => c.kind === "upload-suspect");
  assert.ok(cand, "req.files 应产生 upload-suspect 候选");
  assert.equal(cand.fullPath, "/api/avatar");
  assert.equal(cand.method, "POST");
  assert.ok(cand.upload);

  const plan = buildProbePlan(a);
  assert.equal(plan.uploadCandidate?.fullPath, "/api/avatar");
  assert.equal(plan.uploadCandidates.length, 1);
});

test("buildCases: 主动内容上传并同源回读即判 vulnerable，类型校验后判 blocked", async () => {
  let hardened = false;
  const stored = new Map();
  const server = await listen((req, res) => {
    const url = new URL(req.url, "http://127.0.0.1");
    if (req.method === "POST" && url.pathname === "/api/avatar") {
      const chunks = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", () => {
        if (hardened) {
          res.writeHead(415, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: "不支持的文件类型" }));
          return;
        }
        const raw = Buffer.concat(chunks).toString("utf8");
        const name = /filename="([^"]+)"/i.exec(raw)?.[1] ?? "upload.bin";
        const type = /content-type:\s*([^\r\n]+)/i.exec(raw)?.[1]?.trim() ?? "application/octet-stream";
        const content = raw.slice(raw.indexOf("\r\n\r\n") + 4, raw.lastIndexOf("\r\n--"));
        stored.set(name, { type, content });
        res.writeHead(201, { "content-type": "application/json" });
        res.end(JSON.stringify({ url: `/uploads/${encodeURIComponent(name)}` }));
      });
      return;
    }
    if (req.method === "GET" && url.pathname.startsWith("/uploads/")) {
      const name = decodeURIComponent(url.pathname.slice("/uploads/".length));
      const hit = stored.get(name);
      if (!hit) {
        res.writeHead(404).end();
        return;
      }
      res.writeHead(200, { "content-type": hit.type });
      res.end(hit.content);
      return;
    }
    res.writeHead(404).end();
  });

  try {
    const cand = {
      path: "/api/avatar",
      fullPath: "/api/avatar",
      method: "POST",
      upload: { field: "avatar", validations: [], sink: "req.files" },
      routeKeys: ["avatar.post"],
    };
    const cases = buildCases(
      { plan: { uploadCandidates: [cand] }, targetConfig: null },
      { attacker: { name: "alice", user: { id: 1 } }, victim: { name: "bob", user: { id: 2 } } }
    );
    assert.equal(cases.length, 1);
    const kase = cases[0];
    assert.equal(kase.id, "attack-upload");
    assert.equal(kase.unfixable, true);
    assert.equal(kase.method, "POST");
    assert.equal(kase.identity, "alice");

    const ctx = stubCtx();
    const out = await kase.send(ctx, server.url);
    const proof = out.res._uploadProof;
    assert.equal(proof.accepted, true);
    assert.equal(proof.markerMatched, true, "同源回读应包含上传令牌");
    assert.equal(proof.contentType, "text/html");
    assert.equal(proof.activeType, true);
    assert.equal(proof.exploitable, true);
    const verdict = kase.verify(out.res, "pre");
    assert.equal(verdict.verdict, "vulnerable");
    assert.match(verdict.actual, /同源 .* 以 text\/html 回读上传内容/);
    assert.ok(kase.crossProof(out.res)?.note.includes("主动内容"));
    assert.ok(kase.impact(out.res).includes("XSS"));

    hardened = true;
    const blocked = await kase.send(ctx, server.url);
    assert.equal(blocked.res._uploadProof.accepted, false);
    assert.equal(kase.verify(blocked.res, "pre").verdict, "blocked");
    assert.equal(kase.crossProof(blocked.res), null);
  } finally {
    await new Promise((r) => server.server.close(r));
  }
});
