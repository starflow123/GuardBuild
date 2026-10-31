/**
 * 配方化试点的等价性快照（M1-5）。
 *
 * 纯等价重构的证据不能只靠「测试还是绿的」——既有单测只断言它们关心的那几项，
 * 搬家时掉了某个字段（比如变体的 requiresPreRepro、GraphQL 的 method）它们不会响。
 * 所以这里在改代码**之前**把越权读一族在 6 种计划形状下的全部产出字段固化成快照，
 * 包括 verify/crossProof/impact/contract 判据闭包的**源码文本**：
 * 判据是冻结项，改动它必须是一次刻意的重快照，而不是重构的副作用。
 *
 * 快照里的 path/method/name 等由 buildCases 现算，形状输入是本仓库自建的计划对象，
 * 不发任何请求、不含任何凭据。
 *
 * 用法：
 *   node scripts/recipe-snapshot.mjs --write benchmarks/idor-read-golden.json   # 重快照（刻意）
 *   单测 sidecar/tests/recipe-idor-read.test.mjs 读同一份快照做逐条 deep-equal
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

export function snapshotIdorRead() {
  const out = {};
  for (const [name, { plan, targets: t }] of Object.entries(IDOR_SHAPES)) {
    const cases = buildCases({ plan, targetConfig: null }, t);
    out[name] = cases
      .filter((c) => FAMILY_ID_PREFIXES.some((p) => String(c.id).startsWith(p)))
      .map((c) => {
        const o = {};
        for (const [k, v] of Object.entries(c)) {
          // 判据闭包按源码文本入快照：冻结项被顺手改动要在这里显形
          o[k] = typeof v === "function" ? `fn:${v.toString()}` : v instanceof Set ? [...v].sort() : v;
        }
        return o;
      });
  }
  return out;
}

const argv = process.argv.slice(2);
if (argv[0] === "--write") {
  const dest = argv[1];
  if (!dest) {
    console.error("用法：node scripts/recipe-snapshot.mjs --write <输出文件>");
    process.exit(2);
  }
  const snap = snapshotIdorRead();
  writeFileSync(dest, `${JSON.stringify(snap, null, 2)}\n`);
  console.log(`已写入 ${dest}`);
  console.log("形状条数：", Object.entries(snap).map(([k, v]) => `${k}=${v.length}`).join(" "));
}
