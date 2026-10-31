/**
 * 配方化试点的等价性快照（M1-5 / M1-5b）。
 *
 * 纯等价重构的证据不能只靠「测试还是绿的」——既有单测只断言它们关心的那几项，
 * 搬家时掉了某个字段（比如变体的 requiresPreRepro、GraphQL 的 method）它们不会响。
 * 所以这里在改代码**之前**把该族在若干计划形状下的全部产出字段固化成快照，
 * 包括 verify/crossProof/impact/contract 判据闭包的**源码文本**：
 * 判据是冻结项，改动它必须是一次刻意的重快照，而不是重构的副作用。
 *
 * 快照里的 path/method/name 等由 buildCases 现算，形状输入是本仓库自建的计划对象，
 * 不发任何请求、不含任何凭据。
 *
 * 用法：
 *   node scripts/recipe-snapshot.mjs --family <idor-read|sqli-injection|path-traversal> --write benchmarks/<族>-golden.json   # 重快照（刻意）
 *   单测 sidecar/tests/recipe-*.test.mjs 读同一份快照做逐条 deep-equal
 */
import { buildCases } from "../sidecar/lib/probe.mjs";
import { writeFileSync } from "node:fs";

// 三个线协议形状 + 多候选 + 无对照对象 + 身份缺失兜底
const readCand = { fullPath: "/api/orders/:id", routeKeys: ["orders.get"], resource: "order" };
const queryCand = {
  fullPath: "/app/modifyproduct",
  queryParam: { param: "id" },
  method: "GET",
  routeKeys: ["product.get"],
  resource: "product",
};
const gqlCand = {
  fullPath: "/graphql",
  method: "POST",
  routeKeys: ["Query.order"],
  resource: "order",
  graphql: { root: "Query", field: "order", argName: "id", argType: "ID!", entityPath: "data.order", ownerField: "userId" },
};

const targets = (extra = {}) => ({
  attacker: { name: "alice", user: { id: 1 } },
  victim: { name: "bob", user: { id: 2 } },
  admin: null,
  readTarget: { id: 11 },
  ownReadTarget: { id: 14 },
  victimOwnTarget: { id: 12 },
  attackerOwnIds: new Set(["14"]),
  victimItems: [{ id: 11 }, { id: 12 }, { id: 13 }],
  ...extra,
});

export const IDOR_SHAPES = {
  "rest-path-param": {
    plan: { resource: "order", readCandidate: readCand, listEndpoint: { path: "/api/orders", routeKey: "orders.list" } },
    targets: targets(),
  },
  "rest-query-param": {
    plan: { resource: "product", readCandidate: queryCand, listEndpoint: { path: "/app/products", routeKey: "product.list" } },
    targets: targets({ readTarget: { id: 7 }, ownReadTarget: { id: 9 }, victimOwnTarget: { id: 8 }, attackerOwnIds: new Set(["9"]), victimItems: [{ id: 7 }, { id: 8 }] }),
  },
  graphql: {
    plan: {
      resource: "order",
      readCandidate: gqlCand,
      listEndpoint: { path: "/graphql", routeKey: "Query.orders", graphql: { root: "Query", field: "orders", entityPath: "data.orders" } },
    },
    targets: targets(),
  },
  "multi-candidates": {
    plan: {
      resource: "order",
      readCandidate: readCand,
      readCandidates: [readCand, queryCand],
      listEndpoint: { path: "/api/orders", routeKey: "orders.list" },
    },
    targets: targets(),
  },
  "no-victim-items": {
    plan: { resource: "order", readCandidate: readCand },
    targets: targets({ victimItems: undefined }),
  },
  "missing-targets": {
    plan: { resource: "order", readCandidate: readCand },
    targets: { attacker: { name: "alice" }, victim: { name: "bob" }, readTarget: null },
  },
};

/** 只取越权读一族（攻击基线 + 同源变体 + 本人可见断言），其余族留给后续里程碑 */
const FAMILY_ID_PREFIXES = ["attack-read-foreign", "business-read-own"];

/**
 * SQL 注入族（M1-5b 第二族）：注入通道三种（query / body / params）各一份，
 * 外加「计划没声明参数名」（走执行器默认 q）、多候选、候选缺 injection 声明、
 * attacker 缺席（身份兜底走 victim）。
 */
const sqliQuery = { fullPath: "/api/products", routeKeys: ["product.list"], sqli: { source: "query", param: "keyword" } };
const sqliBody = { fullPath: "/api/login", method: "POST", routeKeys: ["auth.login"], sqli: { source: "body", param: "username" } };
const sqliParams = { fullPath: "/api/items/:id", routeKeys: ["item.get"], sqli: { source: "params", param: "id" } };
const sqliNoParam = { fullPath: "/api/search", routeKeys: ["search.get"], sqli: { source: "query" } };

export const SQLI_SHAPES = {
  query: { plan: { sqliCandidate: sqliQuery }, targets: { attacker: { name: "alice", user: { id: 1 } }, victim: { name: "bob", user: { id: 2 } }, admin: null } },
  body: { plan: { sqliCandidate: sqliBody }, targets: { attacker: { name: "alice", user: { id: 1 } }, victim: { name: "bob", user: { id: 2 } }, admin: null } },
  params: { plan: { sqliCandidate: sqliParams }, targets: { attacker: { name: "alice", user: { id: 1 } }, victim: { name: "bob", user: { id: 2 } }, admin: null } },
  "no-param-name": { plan: { sqliCandidate: sqliNoParam }, targets: { attacker: { name: "alice", user: { id: 1 } }, victim: { name: "bob", user: { id: 2 } }, admin: null } },
  "multi-candidates": {
    plan: { sqliCandidate: sqliQuery, sqliCandidates: [sqliQuery, sqliBody, sqliParams] },
    targets: { attacker: { name: "alice", user: { id: 1 } }, victim: { name: "bob", user: { id: 2 } }, admin: null },
  },
  "no-injection": { plan: { sqliCandidate: { fullPath: "/api/plain", routeKeys: ["plain.get"] } }, targets: { attacker: { name: "alice", user: { id: 1 } }, victim: { name: "bob", user: { id: 2 } }, admin: null } },
  "attacker-missing": { plan: { sqliCandidate: sqliQuery }, targets: { attacker: null, victim: { name: "bob", user: { id: 2 } }, admin: null } },
};

/**
 * 路径穿越族（M1-5b 第三族）：query 形态 / params 形态 / 计划没给参数名（执行器默认 file），
 * 多候选，以及没有路由的候选（跳过）。穿越用例与身份无关，targets 只给一份固定值。
 */
const travQuery = { fullPath: "/api/download", routeKeys: ["files.get"], traversal: { param: "name" } };
const travParams = { fullPath: "/static/:name", routeKeys: ["static.get"], traversal: { source: "params", param: "name" } };
const travNoParam = { fullPath: "/api/read", routeKeys: ["read.get"], traversal: {} };

export const TRAVERSAL_SHAPES = {
  query: { plan: { traversalCandidate: travQuery }, targets: { attacker: { name: "alice", user: { id: 1 } }, victim: { name: "bob", user: { id: 2 } }, admin: null } },
  params: { plan: { traversalCandidate: travParams }, targets: { attacker: { name: "alice", user: { id: 1 } }, victim: { name: "bob", user: { id: 2 } }, admin: null } },
  "no-param-name": { plan: { traversalCandidate: travNoParam }, targets: { attacker: { name: "alice", user: { id: 1 } }, victim: { name: "bob", user: { id: 2 } }, admin: null } },
  "multi-candidates": {
    plan: { traversalCandidate: travQuery, traversalCandidates: [travQuery, travParams, travNoParam] },
    targets: { attacker: { name: "alice", user: { id: 1 } }, victim: { name: "bob", user: { id: 2 } }, admin: null },
  },
  "no-route": { plan: { traversalCandidate: { routeKeys: ["files.get"], traversal: { param: "name" } } }, targets: { attacker: { name: "alice", user: { id: 1 } }, victim: { name: "bob", user: { id: 2 } }, admin: null } },
  "no-identity": { plan: { traversalCandidate: travQuery }, targets: { attacker: null, victim: null, admin: null } },
};

/** 按族取快照：判据闭包按源码文本入快照，冻结项被顺手改动要在这里显形 */
function snapshotFamily(shapes, prefixes) {
  const out = {};
  for (const [name, { plan, targets: t }] of Object.entries(shapes)) {
    const cases = buildCases({ plan, targetConfig: null }, t);
    out[name] = cases
      .filter((c) => prefixes.some((p) => String(c.id).startsWith(p)))
      .map((c) => {
        const o = {};
        for (const [k, v] of Object.entries(c)) {
          o[k] = typeof v === "function" ? `fn:${v.toString()}` : v instanceof Set ? [...v].sort() : v;
        }
        return o;
      });
  }
  return out;
}

export function snapshotIdorRead() {
  return snapshotFamily(IDOR_SHAPES, FAMILY_ID_PREFIXES);
}

export function snapshotSqliInjection() {
  return snapshotFamily(SQLI_SHAPES, ["attack-sql-injection"]);
}

export function snapshotPathTraversal() {
  return snapshotFamily(TRAVERSAL_SHAPES, ["attack-path-traversal"]);
}

export const SNAPSHOT_FAMILIES = {
  "idor-read": { shapes: IDOR_SHAPES, prefixes: FAMILY_ID_PREFIXES },
  "sqli-injection": { shapes: SQLI_SHAPES, prefixes: ["attack-sql-injection"] },
  "path-traversal": { shapes: TRAVERSAL_SHAPES, prefixes: ["attack-path-traversal"] },
};

const argv = process.argv.slice(2);
const familyAt = argv.indexOf("--family");
const family = familyAt >= 0 ? argv[familyAt + 1] : "idor-read";
if (argv[0] === "--write" || argv.includes("--write")) {
  const writeAt = argv.indexOf("--write");
  const dest = argv[writeAt + 1];
  if (!dest) {
    console.error("用法：node scripts/recipe-snapshot.mjs --family <idor-read|sqli-injection|path-traversal> --write <输出文件>");
    process.exit(2);
  }
  const spec = SNAPSHOT_FAMILIES[family];
  if (!spec) {
    console.error(`没有这一族的快照形状：${family}（可用：${Object.keys(SNAPSHOT_FAMILIES).join("/")}）`);
    process.exit(2);
  }
  const snap = snapshotFamily(spec.shapes, spec.prefixes);
  writeFileSync(dest, `${JSON.stringify(snap, null, 2)}\n`);
  console.log(`已写入 ${dest}（族：${family}）`);
  console.log("形状条数：", Object.entries(snap).map(([k, v]) => `${k}=${v.length}`).join(" "));
}
