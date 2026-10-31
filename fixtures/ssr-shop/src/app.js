/*
 * SSRShop：服务端渲染的笔记本站，全站没有任何 JSON 接口。
 *  列表是一页 HTML，详情也是一页 HTML：对象 ID 只出现在 <a href> 里，
 *  归属信息只出现在正文文本里（响应体里没有 userId 字段可比对）。
 *  /notes/:id 只校验「有没有登录」，不校验「这条笔记是不是你的」——
 *  任何登录用户改一下地址栏就能读到别人的笔记正文。
 *
 * 两种「修复」形态分别验证两条判据：
 *  1) GB_SSR_HARDENED=1：归属校验走 src/access.js 的 helper（路由块内看不见比较），
 *     静态候选仍在，结论由实测给出 → 跨用户读取被 403 挡住 = 未复现。
 *  2) e2e 第 ③ 轮把 `note.userId !== auth.id` 直接写进路由块：
 *     静态识别为「已加归属校验」→ 该端点不再作为越权候选。
 */

import { canReadNote } from "./access.js";

const HARDENED = process.env.GB_SSR_HARDENED === "1";

const USERS = [
  { id: 1, email: "alice@ssr.shop", password: "alice123", name: "周慕云", role: "user" },
  { id: 2, email: "bob@ssr.shop", password: "bob123", name: "韩雪", role: "user" },
];

const NOTES = [
  { id: 101, userId: 1, code: "A-1013", title: "机械键盘团购", courier: "SF1029384756", remark: "周五前发货" },
  { id: 102, userId: 1, code: "A-1024", title: "显示器比价", courier: "SF1029388811", remark: "等促销再买" },
  { id: 201, userId: 2, code: "B-2087", title: "耳机退货", courier: "YT8837462211", remark: "走顺丰到付" },
];

const SESSIONS = new Map();
let seq = 0;

const NAV = `<nav><a href="/">首页</a><a href="/my">我的笔记</a><a href="/login">登录</a></nav>`;
const LOGIN_FORM = `<form method="post" action="/login"><input name="email"><input type="password" name="password"><button type="submit">登录</button></form>`;

function render(res, status, title, main, headers = {}) {
  const html = `<!doctype html><html lang="zh"><head><meta charset="utf-8"><title>${title}</title></head><body>${NAV}<main>${main}</main></body></html>`;
  res.writeHead(status, {
    "Content-Type": "text/html; charset=utf-8",
    "Content-Length": Buffer.byteLength(html),
    ...headers,
  });
  res.end(html);
}

function redirect(res, location, headers = {}) {
  res.writeHead(302, { Location: location, "Content-Type": "text/plain; charset=utf-8", ...headers });
  res.end("redirecting");
}

function notesOf(user) {
  return NOTES.filter((n) => n.userId === user.id);
}

function listMain(user) {
  const items = notesOf(user)
    .map((n) => `<li><a href="/notes/${n.id}">${n.title}</a></li>`)
    .join("");
  return `<h1>${user.name} 的笔记本</h1><ul>${items}</ul>`;
}

function noteMain(n) {
  const owner = USERS.find((u) => u.id === n.userId);
  return `<h1>${n.title}</h1><p>单号 ${n.code}</p><p>收件人 ${owner.name}</p><p>快递单号 ${n.courier}</p><p>备注 ${n.remark}</p><p><a href="/my">回到我的笔记</a></p>`;
}

function findNoteById(id) {
  return NOTES.find((n) => n.id === id) ?? null;
}

function readForm(req) {
  return new Promise((resolve) => {
    let raw = "";
    req.on("data", (c) => {
      raw += c;
    });
    req.on("end", () => resolve(new URLSearchParams(raw)));
  });
}

function sidOf(req) {
  return /sid=([^;]+)/.exec(String(req.headers.cookie ?? ""))?.[1] ?? null;
}

function authenticate(req) {
  const sid = sidOf(req);
  return sid ? (SESSIONS.get(sid) ?? null) : null;
}

export async function handleRequest(req, res) {
  const url = new URL(req.url, "http://127.0.0.1");
  const pathname = url.pathname;
  const method = req.method.toUpperCase();
  const auth = authenticate(req);

  if (method === "GET" && pathname === "/") {
    const main = auth
      ? `<h1>欢迎回来，${auth.name}</h1><h2>最近笔记</h2><ul>${notesOf(auth)
          .map((n) => `<li><a href="/notes/${n.id}">${n.title}</a></li>`)
          .join("")}</ul>`
      : `<h1>笔记本</h1><p>登录后即可查看自己的笔记。</p>${LOGIN_FORM}`;
    return render(res, 200, "首页", main);
  }

  if (method === "POST" && pathname === "/login") {
    const form = await readForm(req);
    const user = USERS.find((u) => u.email === form.get("email") && u.password === form.get("password"));
    if (!user) return render(res, 401, "登录", `<p>邮箱或密码不正确。</p>${LOGIN_FORM}`);
    const sid = `s${++seq}`;
    SESSIONS.set(sid, user);
    return redirect(res, "/my", { "Set-Cookie": `sid=${sid}; Path=/` });
  }

  if (method === "GET" && pathname === "/login") {
    return render(res, 200, "登录", `<h1>登录</h1>${LOGIN_FORM}`);
  }

  if (method === "GET" && pathname === "/my") {
    if (!auth) return redirect(res, "/login");
    return render(res, 200, "我的笔记", listMain(auth));
  }

  const noteMatch = pathname.match(/^\/notes\/(\d+)$/);
  if (method === "GET" && noteMatch) {
    if (!auth) return redirect(res, "/login");
    const note = findNoteById(Number(noteMatch[1]));
    if (!note) return render(res, 404, "未找到", "<p>该笔记不存在</p>");
    // 只验登录，不验归属：任何会话都能翻开别人的笔记（helper 形态的加固见 src/access.js）
    if (HARDENED && !canReadNote(auth, note)) return render(res, 403, "禁止访问", "<p>无权查看该笔记</p>");
    return render(res, 200, `${note.title} - 我的笔记`, noteMain(note));
  }

  return render(res, 404, "未找到", "<p>该页面不存在</p>");
}
