/**
 * ShapeShop：路由用静态可见的 app.get("/…/:param") 形态（analyzer 的 express 适配器能找到），
 * 但响应形状全部偏离默认启发式 —— 专门验证 P2 资源契约自动发现：
 * guardbuild.json 不写 responses / listEndpoint / routes[].params，契约必须由引擎
 * 用两个真实身份对拉实测得出。零依赖：app 只是一个注册表 + 运行期正则分发。
 *   - 列表在 data.results.batchList 三层嵌套，page/pageSize 缺一就 400；
 *   - 主键 batch_id、归属 keeper_id / tenant_code，都不在引擎默认回退名单里；
 *   - 单体响应包在 { meta, record } 里；
 *   - 两段路径 /api/tenants/:tenant_code/batches/:batch_id，对象里带同名字段。
 * GB_SHAPE_HARDENED=1：单体端点加归属校验（验证 exit 0）。
 * GB_SHAPE_NO_TENANT=1：列表元素剥掉 tenant_code 字段（验证绑定实测失败时如实拒绝、不猜）。
 */
const HARDENED = process.env.GB_SHAPE_HARDENED === "1";
const NO_TENANT = process.env.GB_SHAPE_NO_TENANT === "1";

const USERS = [
  { id: 1, username: "alice", password: "alice123", role: "user" },
  { id: 2, username: "bob", password: "bob123", role: "user" },
];

const BATCHES = [
  { batch_id: 3001, keeper_id: 1, tenant_code: "T-A7", sku: "SKU-A1", status: "stored" },
  { batch_id: 3002, keeper_id: 1, tenant_code: "T-A7", sku: "SKU-A2", status: "stored" },
  { batch_id: 4001, keeper_id: 2, tenant_code: "T-B3", sku: "SKU-B1", status: "stored" },
];

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

function publicBatch(b) {
  const item = {
    batch_id: b.batch_id,
    keeper_id: b.keeper_id,
    tenant_code: b.tenant_code,
    sku: b.sku,
    status: b.status,
  };
  if (NO_TENANT) delete item.tenant_code;
  return item;
}

const ROUTES = [];
const app = {
  get: (path, handler) => ROUTES.push({ method: "GET", path, handler }),
  post: (path, handler) => ROUTES.push({ method: "POST", path, handler }),
};

// 微型 ORM：让取数形态贴近真实项目（db.batch.find({ ... })）
const db = {
  batch: {
    find(where) {
      return BATCHES.find((b) => Object.entries(where).every(([k, v]) => String(b[k]) === String(v))) ?? null;
    },
  },
};

app.post("/api/login", async (req, res) => {
  const body = await readJson(req);
  const user = USERS.find((u) => u.username === body.username && u.password === body.password);
  if (!user) return json(res, 401, { error: "用户名或密码错误" });
  const token = `tok-${user.username}-${++seq}`;
  SESSIONS.set(token, user);
  return json(res, 200, { token, user: { id: user.id, username: user.username, role: user.role } });
});

app.get("/api/warehouse/batches", async (req, res) => {
  const auth = currentUser(req);
  if (!auth) return json(res, 401, { error: "未登录" });
  const page = Number(req.query.page);
  const pageSize = Number(req.query.pageSize);
  if (!Number.isFinite(page) || !Number.isFinite(pageSize) || page < 1 || pageSize < 1) {
    return json(res, 400, { error: "page 与 pageSize 为必填正整数" });
  }
  const mine = BATCHES.filter((b) => b.keeper_id === auth.id).map(publicBatch);
  return json(res, 200, {
    data: {
      paging: { page, pageSize, total: mine.length },
      results: { batchList: mine.slice((page - 1) * pageSize, page * pageSize) },
    },
  });
});

// GB_SHAPE_SINGLE_BEGIN（e2e 场景会把这一段从源码里删掉，只留两段路径路由）
app.get("/api/warehouse/batches/:batch_id", async (req, res) => {
  const auth = currentUser(req);
  if (!auth) return json(res, 401, { error: "未登录" });
  const batch = db.batch.find({ batch_id: Number(req.params.batch_id) });
  if (!batch) return json(res, 404, { error: "批次不存在" });
  if (HARDENED && batch.keeper_id !== auth.id) return json(res, 404, { error: "批次不存在" });
  return json(res, 200, { meta: { requestId: `req-${++seq}` }, record: publicBatch(batch) });
});
// GB_SHAPE_SINGLE_END

app.get("/api/tenants/:tenant_code/batches/:batch_id", async (req, res) => {
  const auth = currentUser(req);
  if (!auth) return json(res, 401, { error: "未登录" });
  const batch = db.batch.find({
    batch_id: Number(req.params.batch_id),
    tenant_code: req.params.tenant_code,
  });
  if (!batch) return json(res, 404, { error: "批次不存在" });
  if (HARDENED && batch.keeper_id !== auth.id) return json(res, 404, { error: "批次不存在" });
  return json(res, 200, { meta: { requestId: `req-${++seq}` }, record: publicBatch(batch) });
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
