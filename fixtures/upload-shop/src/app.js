import { randomUUID } from "node:crypto";
import path from "node:path";

/*
 * UploadShop：复刻「头像上传」常见的无限制文件上传形态。
 * POST /api/avatar 接收任意文件，按原始文件名与 Content-Type 存下，
 * 再通过 GET /uploads/<name> 以相同类型回读——HTML/SVG 会被同源渲染。
 * GB_UPLOAD_HARDENED=1 时只允许 PNG/JPEG（扩展名 + 声明类型 + 魔数），
 * 随机重命名并以附件 + nosniff 回读，用于验证修复后的行为（静态候选仍在）。
 */

const HARDENED = process.env.GB_UPLOAD_HARDENED === "1";

const USERS = [
  { id: 1, username: "alice", password: "alice123", role: "user" },
  { id: 2, username: "bob", password: "bob123", role: "user" },
  { id: 3, username: "admin", password: "admin123", role: "admin" },
];
const sessions = new Map();
const files = new Map();

function json(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(payload),
  });
  res.end(payload);
}

function readJson(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}"));
      } catch {
        resolve({});
      }
    });
  });
}

/** 零依赖 multipart 解析：只处理本靶场需要的单文件/多文件表单 */
function parseMultipart(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const raw = Buffer.concat(chunks);
      const contentType = req.headers["content-type"] ?? "";
      const match = /boundary=(?:"([^"]+)"|([^;]+))/i.exec(contentType);
      if (!match) return resolve([]);
      const marker = `--${String(match[1] ?? match[2]).trim()}`;
      const text = raw.toString("utf8");
      const parts = [];
      let pos = text.indexOf(marker);
      while (pos >= 0) {
        const start = pos + marker.length;
        if (text.startsWith("--", start)) break;
        const headEnd = text.indexOf("\r\n\r\n", start);
        if (headEnd < 0) break;
        const next = text.indexOf(`\r\n${marker}`, headEnd + 4);
        if (next < 0) break;
        const head = text.slice(start + 2, headEnd);
        const content = text.slice(headEnd + 4, next);
        parts.push({
          field: /name="([^"]*)"/i.exec(head)?.[1] ?? null,
          filename: /filename="([^"]*)"/i.exec(head)?.[1] ?? null,
          contentType: /content-type:\s*([^\r\n]+)/i.exec(head)?.[1]?.trim() ?? "application/octet-stream",
          bytes: Buffer.from(content, "utf8"),
        });
        pos = next + 2;
      }
      resolve(parts);
    });
  });
}

function login(username, password) {
  const user = USERS.find((u) => u.username === username && u.password === password);
  if (!user) return null;
  const token = randomUUID();
  sessions.set(token, user);
  return { token, user: { id: user.id, username: user.username, role: user.role } };
}

function authenticate(req) {
  const header = req.headers.authorization ?? "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  return sessions.get(token) ?? null;
}

function isPng(buf) {
  return (
    buf.length > 8 &&
    buf[0] === 0x89 &&
    buf[1] === 0x50 &&
    buf[2] === 0x4e &&
    buf[3] === 0x47 &&
    buf[4] === 0x0d &&
    buf[5] === 0x0a &&
    buf[6] === 0x1a &&
    buf[7] === 0x0a
  );
}

function isJpeg(buf) {
  return buf.length > 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff;
}

export async function handleRequest(req, res) {
  const url = new URL(req.url, "http://127.0.0.1");
  const pathname = url.pathname;
  const method = req.method.toUpperCase();
  const auth = authenticate(req);

  if (method === "GET" && pathname === "/api/health") {
    return json(res, 200, { ok: true, service: "upload-shop" });
  }

  if (method === "POST" && pathname === "/api/login") {
    const body = await readJson(req);
    const result = login(body.username, body.password);
    if (!result) return json(res, 401, { error: "用户名或密码错误" });
    return json(res, 200, { token: result.token, user: result.user });
  }

  if (method === "POST" && pathname === "/api/avatar") {
    if (!auth) return json(res, 401, { error: "未登录" });
    const uploaded = req.files ?? (await parseMultipart(req));
    const file = Array.isArray(uploaded) ? uploaded[0] : null;
    if (!file || !file.filename) return json(res, 400, { error: "缺少文件字段" });

    if (HARDENED) {
      const ext = path.extname(file.filename).toLowerCase();
      const declared = String(file.contentType ?? "").toLowerCase();
      const allowedExt = new Set([".png", ".jpg", ".jpeg"]);
      const allowedType = new Set(["image/png", "image/jpeg"]);
      const magicOk = ext === ".png" ? isPng(file.bytes) : isJpeg(file.bytes);
      if (!allowedExt.has(ext) || !allowedType.has(declared) || !magicOk) {
        return json(res, 415, { error: "不支持的文件类型" });
      }
      const stored = `${randomUUID()}${ext === ".jpeg" ? ".jpg" : ext}`;
      files.set(stored, { contentType: declared, bytes: file.bytes, attachment: true });
      return json(res, 201, { url: `/uploads/${stored}`, name: stored });
    }

    const stored = file.filename;
    files.set(stored, {
      contentType: file.contentType || "application/octet-stream",
      bytes: file.bytes,
      attachment: false,
    });
    return json(res, 201, { url: `/uploads/${encodeURIComponent(stored)}`, name: stored });
  }

  if (method === "GET" && pathname.startsWith("/uploads/")) {
    let name;
    try {
      name = decodeURIComponent(pathname.slice("/uploads/".length));
    } catch {
      return json(res, 400, { error: "非法文件名" });
    }
    const stored = files.get(name);
    if (!stored) return json(res, 404, { error: "文件不存在" });
    const headers = {
      "Content-Type": stored.contentType,
      "Content-Length": stored.bytes.length,
    };
    if (stored.attachment) {
      headers["Content-Disposition"] = `attachment; filename="${name}"`;
      headers["X-Content-Type-Options"] = "nosniff";
    }
    res.writeHead(200, headers);
    return res.end(stored.bytes);
  }

  return json(res, 404, { error: "not found", path: pathname });
}
