/**
 * SelfBootShop：空库靶场（#179 身份与测试数据自举）。
 *
 * 库里一个账号都没有 —— 只有走 /api/register 才能拿到身份。这正是沙箱目标的真实处境：
 * 每次从空库启动，人手写的 identities 只是把「账号不存在」换成「密码对不上」。
 * 引擎必须用目标自己的注册接口建号、用 register.seed 给每个账号写名下对象，
 * 然后才谈得上跨归属攻击；任一环不成立就显式失败，绝不退回匿名探测再报「未发现漏洞」。
 *
 *   GB_SELFB_BOOT=0        关注册接口（405）：验证「省略口令 + 目标不接受注册」＝测不了（exit 2）
 *   GB_SELFB_SEED_DENIED=1 写入接口对已登录身份回 403：验证 seed 失败＝测不了（exit 2）
 *   GB_SELFB_HARDENED=1    单体端点加归属校验：验证自举之后的 exit 0（已测未复现）
 *
 * 零依赖：app 只是一个注册表 + 运行期正则分发。
 */
const BOOT_ALLOWED = process.env.GB_SELFB_BOOT !== "0";
const SEED_DENIED = process.env.GB_SELFB_SEED_DENIED === "1";
const HARDENED = process.env.GB_SELFB_HARDENED === "1";

/** 空库：账号只能由目标自己的注册接口产生 */
const USERS = [];
const ORDERS = [];

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

// 微型数据层：取数走 Model.find({ … }) 形态（与 shape-shop 同一口径），
// 否则 analyzer 认不出「按 ID 取单体」，靶场会在登录之前就以 no_candidates 收摊。
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

// 归属校验走 helper：路由块内不出现字段比较，加固前后静态候选都保留，
// 由动态攻击证明修复（not_reproducible），而不是让引擎在源码里读到比较就停止探测。
function owns(user, order) {
  return order.userId === user.id;
}

app.post("/api/register", async (req, res) => {
  if (!BOOT_ALLOWED) return json(res, 405, { error: "registration is closed" });
  const body = await readJson(req);
  const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
  const password = typeof body.password === "string" ? body.password : "";
  if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
    return json(res, 422, { error: "email 必填且需为合法邮箱" });
  }
  if (password.length < 8) return json(res, 422, { error: "password 至少 8 位" });
  if (db.user.has({ email })) return json(res, 409, { error: "email already registered" });
  const user = { id: ++seq, email, username: body.username ?? email.split("@")[0], password, role: "user" };
  USERS.push(user);
  return json(res, 201, { id: user.id, email: user.email });
});

app.post("/api/login", async (req, res) => {
  const body = await readJson(req);
  const user = db.user.find({
    email: String(body.email ?? "").toLowerCase(),
    password: String(body.password ?? ""),
  });
  if (!user) return json(res, 401, { error: "用户名或密码错误" });
  const token = `tok-${user.id}-${++seq}`;
  SESSIONS.set(token, user);
  return json(res, 200, { token, user: { id: user.id, email: user.email, role: user.role } });
});

/** 无参数、只读、需登录 —— #175 的会话真实性回读探针就用它 */
app.get("/api/profile", async (req, res) => {
  const auth = currentUser(req);
  if (!auth) return json(res, 401, { error: "未登录" });
  return json(res, 200, { id: auth.id, email: auth.email, role: auth.role });
});

app.get("/api/orders", async (req, res) => {
  const auth = currentUser(req);
  if (!auth) return json(res, 401, { error: "未登录" });
  return json(res, 200, { orders: db.order.listFor(auth.id) });
});

app.post("/api/orders", async (req, res) => {
  const auth = currentUser(req);
  if (!auth) return json(res, 401, { error: "未登录" });
  if (SEED_DENIED) return json(res, 403, { error: "forbidden" });
  const body = await readJson(req);
  const order = db.order.create({
    id: ORDERS.length + 1,
    userId: auth.id,
    title: typeof body.title === "string" ? body.title : "",
    status: "stored",
  });
  return json(res, 201, order);
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
    await route.handler(req, res);
    return;
  }
  json(res, 404, { error: "not found" });
}
