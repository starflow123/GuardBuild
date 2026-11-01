/*
 * NoticeShop：内部公告与报表系统（第 8 项补齐用的第二个 SQL 注入白盒靶子）。
 *
 * 与 ledger-shop 的形状差别是这一张存在的全部理由（同一族的两张考卷不能只换框架名）：
 *  - 路由写法：if (method === "POST" && pathname === "…") 的手写分发，不是 Express 风格注册；
 *  - 注入通道：请求体（POST + JSON），不是查询参数；
 *  - 拼接形态：字符串加号拼接，不是模板插值；
 *  - 取数入口：dbAll(…) 自由函数，不是 db.all(…) 方法；
 *  - 会话形态：表单登录 + Set-Cookie，不是 Bearer 令牌。
 *
 * 埋的漏洞：POST /api/reports/query 把报表标题检索词直接拼进 SQL 文本。
 */

import { authenticate, login } from "./auth.js";
import { reports } from "./data.js";
import { dbAll } from "./sql.js";

const NAV = `<nav><a href="/reports">我的报表</a><a href="/query">报表检索</a></nav>`;
const LOGIN_FORM = `<form method="post" action="/api/session"><input name="username"><input type="password" name="password"><button type="submit">登录</button></form>`;

function json(res, status, body, headers = {}) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(payload),
    ...headers,
  });
  res.end(payload);
}

function render(res, status, title, main, headers = {}) {
  const html = `<!doctype html><html lang="zh"><head><meta charset="utf-8"><title>${title}</title></head><body>${NAV}<main>${main}</main></body></html>`;
  res.writeHead(status, {
    "Content-Type": "text/html; charset=utf-8",
    "Content-Length": Buffer.byteLength(html),
    ...headers,
  });
  res.end(html);
}

export async function handleRequest(req, res) {
  const url = new URL(req.url, "http://127.0.0.1");
  const pathname = url.pathname;
  const method = req.method.toUpperCase();
  const user = authenticate(req);

  if (method === "POST" && pathname === "/api/session") {
    const session = login(req.body.username ?? "", req.body.password ?? "");
    if (!session) return render(res, 401, "登录", `<p>用户名或密码不正确。</p>${LOGIN_FORM}`);
    // 会话凭据只走 Set-Cookie；响应体回本人对象（不含口令），供客户端渲染用户名下报表
    return json(
      res,
      200,
      { user: { id: session.user.id, username: session.user.username, name: session.user.name, role: session.user.role } },
      { "Set-Cookie": `sid=${session.sid}; Path=/; HttpOnly` }
    );
  }

  if (method === "GET" && pathname === "/reports") {
    if (!user) return render(res, 200, "登录", `<h1>登录</h1>${LOGIN_FORM}`);
    const mine = reports.filter((r) => r.ownerId === user.id);
    return render(
      res,
      200,
      "我的报表",
      `<h1>${user.name} 的报表</h1><ul>${mine.map((r) => `<li>${r.title}｜${r.body}</li>`).join("")}</ul>`
    );
  }

  if (method === "GET" && pathname === "/api/reports") {
    if (!user) return json(res, 401, { error: "请先登录" });
    return json(res, 200, { reports: reports.filter((r) => r.ownerId === user.id) });
  }

  if (method === "POST" && pathname === "/api/reports/query") {
    if (!user) return json(res, 401, { error: "请先登录" });
    const { column } = req.body;
    try {
      // 漏洞就在这行：检索词以字符串拼接进入 SQL 文本，没有任何参数绑定
      const rows = dbAll("SELECT * FROM reports WHERE title LIKE '%" + column + "%'");
      return json(res, 200, { reports: rows });
    } catch (err) {
      // 排查期把数据库报错原文回写出去，报错型注入的证据即来自这里
      return json(res, 500, { error: err.message });
    }
  }

  return json(res, 404, { error: "接口不存在" });
}
