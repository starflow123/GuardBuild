/**
 * OddSelfBootShop：换场景靶场（#182/#183/#184 验收）。
 *
 * 它与 selfboot-shop 的差别就是「确定性词表打不中」这四处，专门用来证明兜底层不是摆设：
 *   1. 建号接口叫 POST /api/huiyuan/add，请求体字段是 mail/pwd/nick ——
 *      注册词表认不出这个形状，引擎的默认注册体（email/password）也会被它 422 拒掉；
 *   2. 往名下写对象的接口叫 POST /api/xiadan，字段是 mingcheng ——
 *      契约里没有 register.seed，端点与字段名都只能由引擎观测出来（写入后本人列表回读得到标记）；
 *   3. POST /api/feedback 同样回 201，但什么都不落到调用方名下 —— 这是给复读归因闸门准备的陷阱：
 *      只看状态码就会把它当成「造数据成功」，越权用例于是建立在一个不存在的前提上；
 *   4. POST /api/mima/reset 长得像个写接口，但引擎的策略线禁止往它发建号体（撞找回密码＝改别人口令），
 *      它根本不会出现在给模型的候选菜单里。
 *
 *   GB_ODD_BOOT=0        关注册接口（405）：省略口令又建不了号＝测不了
 *   GB_ODD_HARDENED=1    单体端点加归属校验：自举成功 → 已测未复现
 *   GB_ODD_LEAKY_LIST=1  列表不按归属过滤：写入都成功但归不了属，引擎拒绝把它当名下对象
 *
 * 零依赖：与 selfboot-shop 同一微型分发形态（body 由分发器挂到 req.body，等价 body-parser），
 * 取数走 Model.find({ … })，否则 analyzer 认不出「按 ID 取单体」，靶场会在登录之前就收摊。
 */
const BOOT_ALLOWED = process.env.GB_ODD_BOOT !== "0";
const HARDENED = process.env.GB_ODD_HARDENED === "1";
const LEAKY_LIST = process.env.GB_ODD_LEAKY_LIST === "1";

/** 空库：账号只能由目标自己的注册接口产生 */
const USERS = [];
const ORDERS = [];
const FEEDBACK = [];

let seq = 0;
const SESSIONS = new Map();

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

function currentUser(req) {
  const header = req.headers.authorization ?? "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  return SESSIONS.get(token) ?? null;
}

const ROUTES = [];
const app = {
  get: (path, handler) => ROUTES.push({ method: "GET", path, handler }),
  post: (path, handler) => ROUTES.push({ method: "POST", path, handler }),
};

const db = {
  user: {
    find(where) {
      return USERS.find((u) => Object.entries(where).every(([k, v]) => String(u[k]) === String(v))) ?? null;
    },
    has(where) {
      return db.user.find(where) !== null;
    },
  },
  order: {
    find(where) {
      return ORDERS.find((o) => Object.entries(where).every(([k, v]) => String(o[k]) === String(v))) ?? null;
    },
    create(data) {
      ORDERS.push(data);
      return data;
    },
    listFor(userId) {
      return ORDERS.filter((o) => o.userId === userId);
    },
  },
};

// 归属校验走 helper：加固前后静态候选都保留，由动态攻击证明修复，
// 而不是让引擎在源码里读到字段比较就停止探测。
function owns(user, order) {
  return order.userId === user.id;
}

/** 会员开户：路径与字段名都是异形命名，注册词表与引擎默认注册体都打不中 */
app.post("/api/huiyuan/add", async (req, res) => {
  if (!BOOT_ALLOWED) return json(res, 405, { error: "开户通道已关闭" });
  const mail = typeof req.body.mail === "string" ? req.body.mail.trim().toLowerCase() : "";
  const pwd = typeof req.body.pwd === "string" ? req.body.pwd : "";
  if (!mail || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(mail)) {
    return json(res, 422, { error: "mail 必填且需为合法邮箱" });
  }
  if (pwd.length < 8) return json(res, 422, { error: "pwd 至少 8 位" });
  if (db.user.has({ email: mail })) return json(res, 409, { error: "mail already registered" });
  const user = { id: ++seq, email: mail, username: req.body.nick ?? mail.split("@")[0], password: pwd, role: "user" };
  USERS.push(user);
  return json(res, 201, { id: user.id, mail: user.email });
});

app.post("/api/huiyuan/login", async (req, res) => {
  const user = db.user.find({
    email: String(req.body.mail ?? "").toLowerCase(),
    password: String(req.body.pwd ?? ""),
  });
  if (!user) return json(res, 401, { error: "账号或密码不正确" });
  const token = `tok-${user.id}-${++seq}`;
  SESSIONS.set(token, user);
  return json(res, 200, { token, user: { id: user.id, mail: user.email, role: user.role } });
});

/** 找回密码：引擎策略线禁止对它发建号体，因此它绝不进候选菜单 */
app.post("/api/mima/reset", async (req, res) => {
  if (!db.user.has({ email: String(req.body.mail ?? "").toLowerCase() })) return json(res, 404, { error: "账号不存在" });
  return json(res, 400, { error: "需短信验证码，沙箱内不可用" });
});

/** 无参数、只读、需登录 —— #175 的会话真实性回读探针就用它 */
app.get("/api/huiyuan/me", async (req, res) => {
  const auth = currentUser(req);
  if (!auth) return json(res, 401, { error: "未登录" });
  return json(res, 200, { id: auth.id, mail: auth.email, role: auth.role });
});

app.get("/api/orders", async (req, res) => {
  const auth = currentUser(req);
  if (!auth) return json(res, 401, { error: "未登录" });
  // LEAKY_LIST：列表不分归属 —— 此时「这条对象落在谁名下」无从证明
  return json(res, 200, { orders: LEAKY_LIST ? ORDERS : db.order.listFor(auth.id) });
});

/** 下单：路径与字段名都不走 REST 惯例，契约里也没有 register.seed，只能由观测发现 */
app.post("/api/xiadan", async (req, res) => {
  const auth = currentUser(req);
  if (!auth) return json(res, 401, { error: "未登录" });
  const order = db.order.create({
    id: ORDERS.length + 1,
    userId: auth.id,
    title: typeof req.body.mingcheng === "string" ? req.body.mingcheng : "",
    status: "stored",
  });
  return json(res, 201, order);
});

/** 反馈：回 201 但什么都不落在调用方名下 —— 复读归因闸门必须把它判掉 */
app.post("/api/feedback", async (req, res) => {
  const auth = currentUser(req);
  if (!auth) return json(res, 401, { error: "未登录" });
  FEEDBACK.push({
    id: FEEDBACK.length + 1,
    userId: auth.id,
    content: typeof req.body.neirong === "string" ? req.body.neirong : "",
  });
  return json(res, 201, { ok: true });
});

app.get("/api/orders/:id", async (req, res) => {
  const auth = currentUser(req);
  if (!auth) return json(res, 401, { error: "未登录" });
  const order = db.order.find({ id: Number(req.params.id) });
  if (!order) return json(res, 404, { error: "订单不存在" });
  if (HARDENED && !owns(auth, order)) return json(res, 403, { error: "无权查看该订单" });
  return json(res, 200, { id: order.id, userId: order.userId, title: order.title, status: order.status });
});

function pathToRegExp(path) {
  const source = path
    .split("/")
    .map((seg) => (seg.startsWith(":") ? `([^/]+)` : seg.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")))
    .join("/");
  const names = path.split("/").filter((s) => s.startsWith(":")).map((s) => s.slice(1));
  return { pattern: new RegExp(`^${source}$`), names };
}

const COMPILED = ROUTES.map((r) => ({ ...r, ...pathToRegExp(r.path) }));

export async function handleRequest(req, res) {
  const url = new URL(req.url, "http://127.0.0.1");
  req.query = Object.fromEntries(url.searchParams);
  for (const route of COMPILED) {
    if (route.method !== req.method) continue;
    const m = route.pattern.exec(url.pathname);
    if (!m) continue;
    req.params = {};
    route.path
      .split("/")
      .filter((s) => s.startsWith(":"))
      .forEach((s, i) => {
        req.params[s.slice(1)] = decodeURIComponent(m[i + 1]);
      });
    req.body = req.method === "GET" ? {} : await readJson(req);
    await route.handler(req, res);
    return;
  }
  json(res, 404, { error: "not found" });
}
