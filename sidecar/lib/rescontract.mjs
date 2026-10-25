/**
 * 资源契约自动发现（静态瓶颈第 5 项）。
 *
 * 此前「列表数组在哪一层、要不要分页参数、主键叫什么、归属字段叫什么、多段路径参数从哪取值」
 * 全部只能靠人工写进 guardbuild.json；没写就退化成 no_list_endpoint / plan_incomplete，
 * 或者更糟——extractListItems 只看一层、ownerOf 只认五个命名，取到错对象还当成证据。
 *
 * 这里按同一条四层规则补自动发现：**引擎枚举假设（可加模型补充），一律用真实请求实测**。
 * 判定信号全部来自响应内容本身，不来自模型：
 *   1. 数组路径 —— 逐层枚举响应里「元素是对象」的数组，谁的取值能构成两个身份互斥的 id 集合，谁才是列表；
 *   2. 分页参数 —— 只有「不带参数回 4xx/空、带上白名单分页参数后两侧都有数据」才认定该端点要分页；
 *   3. id / 归属字段 —— id 取「两个身份列表互斥」的那个字段；归属字段取「同一身份内恒定、两个身份之间不同」的那个；
 *   4. 单体字段与多段参数 —— 用本人列表里真实存在的对象回读一次，响应里含同一主键值的对象才是实体；
 *      路径参数只能从同一对象的已有字段取值（取不到就判不可寻址，绝不猜）。
 *
 * 验证结果绑定「被测代码内容 + commit」落盘；重放仍要重新实测一次（缓存只当线索，不当结论）。
 */

import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, readdirSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

export const CONTRACT_VERSION = "rescontract-v1";

/** 一轮自动发现的请求预算：槽位 × 分页假设 × 两身份，必须可预期 */
export const MAX_CONTRACT_REQUESTS = 40;
/** 参与实测的列表槽位上限 */
export const MAX_LIST_SLOTS = 4;
/** 单个响应内参与实测的数组路径上限 */
export const MAX_ARRAY_PATHS = 5;
/** 单个数组内参与实测的候选主键字段上限 */
export const MAX_ID_FIELDS = 3;
/** 分页假设上限 */
export const MAX_PAGINATION_TRIES = 8;
/** 多段路径参数候选槽位上限 */
export const MAX_BINDING_SLOTS = 4;

/** 分页参名白名单：只发这些键，避免把模型给的任意键拼进查询串 */
const PAGINATION_KEYS = new Set([
  "page",
  "pageNum",
  "pageNumber",
  "pageIndex",
  "limit",
  "size",
  "count",
  "per_page",
  "perPage",
  "pagesize",
  "page_size",
  "offset",
]);

/** 确定性别名：常见分页组合，按「不带 / 带 page+limit / 带 offset+limit」的顺序试 */
export const PAGINATION_HYPOTHESES = [
  null,
  { page: "1", limit: "100" },
  { page: "1", size: "100" },
  { page: "1", pageSize: "100" },
  { offset: "0", limit: "100" },
  { pageNumber: "1", pageSize: "100" },
  { page: "1", per_page: "100" },
  { limit: "100" },
];

const ID_LIKE_RE = /(?:^|[_A-Za-z0-9])id$/;

function isPlainObject(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

export function getByPath(obj, path) {
  let node = obj;
  for (const key of String(path).split(".")) {
    if (node == null || typeof node !== "object") return undefined;
    node = node[key];
  }
  return node;
}

/** 响应里「元素为对象」的数组路径，按层级由浅到深 */
export function arrayPaths(json, { maxDepth = 4, maxResults = MAX_ARRAY_PATHS } = {}) {
  const out = [];
  const walk = (node, prefix, depth) => {
    if (out.length >= maxResults || depth > maxDepth) return;
    if (Array.isArray(node)) {
      const items = node.filter(isPlainObject);
      if (items.length > 0) out.push({ path: prefix, count: node.length, keys: commonKeys(items) });
      return;
    }
    if (!isPlainObject(node)) return;
    for (const [key, value] of Object.entries(node)) {
      const p = prefix ? `${prefix}.${key}` : key;
      if (Array.isArray(value)) {
        const items = value.filter(isPlainObject);
        if (items.length > 0) {
          if (out.length < maxResults) out.push({ path: p, count: value.length, keys: commonKeys(items) });
        }
      } else if (isPlainObject(value)) {
        walk(value, p, depth + 1);
      }
    }
  };
  walk(json, "", 1);
  return out;
}

/** 响应里「值为对象」的字段路径（用于从 { meta, record } 这类包装里认实体） */
export function objectPaths(json, { maxDepth = 3, maxResults = MAX_ARRAY_PATHS } = {}) {
  const out = [];
  const walk = (node, prefix, depth) => {
    if (out.length >= maxResults || depth > maxDepth) return;
    if (!isPlainObject(node)) return;
    for (const [key, value] of Object.entries(node)) {
      const p = prefix ? `${prefix}.${key}` : key;
      if (isPlainObject(value)) {
        if (out.length < maxResults) out.push({ path: p, keys: Object.keys(value) });
        walk(value, p, depth + 1);
      }
    }
  };
  walk(json, "", 1);
  return out;
}

function commonKeys(items) {
  if (items.length === 0) return [];
  return Object.keys(items[0]).filter((k) => items.every((o) => o[k] !== undefined));
}

/** 候选主键字段：优先就叫 id，其次 xxx_id / xxxId；只取实际存在的字段 */
export function idFieldCandidates(keys) {
  const list = Array.isArray(keys) ? keys : [];
  const scalars = list.filter((k) => /id$/i.test(k) || k === "uuid" || k === "key" || k === "code");
  const ordered = ["id", "uuid", "key"].filter((k) => scalars.includes(k));
  for (const k of scalars) if (!ordered.includes(k)) ordered.push(k);
  return ordered.slice(0, MAX_ID_FIELDS);
}

function idSet(items, field) {
  const set = new Set();
  for (const o of items) {
    const v = o?.[field];
    if (v === undefined || v === null) return null;
    set.add(String(v));
  }
  return set;
}

/** 两个 id 集合的关系：disjoint（互斥）/ identical（同一批）/ partial（部分重叠）/ unusable（取不到值） */
export function compareIdSets(a, b) {
  if (!a || !b || a.size === 0 || b.size === 0) return "unusable";
  let overlap = 0;
  for (const v of a) if (b.has(v)) overlap += 1;
  if (overlap === 0) return "disjoint";
  if (a.size === b.size && overlap === a.size) return "identical";
  return "partial";
}

/**
 * 归属字段：在同一身份的列表里恒定、在两个身份之间不同。
 * 这是「这份列表确实按调用者过滤」的第二个独立信号，不依赖字段命名。
 */
export function ownerContrastFields(itemsA, itemsB, exclude = []) {
  const skip = new Set(exclude);
  const keys = commonKeys(itemsA).filter((k) => commonKeys(itemsB).includes(k) && !skip.has(k));
  const constOf = (items, key) => {
    if (items.length === 0) return null;
    const first = String(items[0]?.[key]);
    if (first === "undefined" || first === "null" || first === "") return null;
    return items.every((o) => String(o?.[key]) === first) ? first : null;
  };
  const out = [];
  for (const key of keys) {
    const a = constOf(itemsA, key);
    const b = constOf(itemsB, key);
    if (a != null && b != null && a !== b) out.push(key);
  }
  return out;
}

const normKey = (k) => String(k).replace(/[_-]/g, "").toLowerCase();

/**
 * 多段路径参数取值：只允许从同一资源对象里已存在的字段取（:orgId ← org_id/orgId）。
 * 取不到就返回 null —— 没有真实来源的参数不填，不猜。
 */
export function bindingsFromItem(item, paramNames) {
  if (!isPlainObject(item)) return null;
  const keys = Object.keys(item);
  const bindings = {};
  for (const raw of paramNames) {
    const name = String(raw);
    const hit = keys.find((k) => normKey(k) === normKey(name)) ?? keys.find((k) => normKey(k) === normKey(`${name}id`));
    if (!hit) return null;
    if (item[hit] === undefined || item[hit] === null) return null;
    bindings[name] = { from: "field", field: hit, source: "live-derived" };
  }
  return Object.keys(bindings).length > 0 ? bindings : null;
}

/**
 * 校验模型提出的契约补充假设：只能落在「已实测响应里真实存在」的路径与字段上。
 * 模型的作用是在引擎枚举不到时补线索（例如数组在字符串化的 JSON 里、分页键叫自造名），
 * 任何在样本响应里对不上的假设都拒掉。
 */
export function validateExtras(raw, sampleJson) {
  const rejected = [];
  const extras = { arrayPaths: [], idFields: [], pagination: [] };
  if (!isPlainObject(raw)) return { extras, rejected: ["模型未返回可解析的契约对象"] };

  const seenPaths = arrayPaths(sampleJson, { maxDepth: 5, maxResults: 20 });
  const allKeys = new Set(seenPaths.flatMap((p) => p.keys));
  for (const p of Array.isArray(raw.arrayPaths) ? raw.arrayPaths : raw.arrayPath ? [raw.arrayPath] : []) {
    const key = String(p ?? "").trim();
    if (!/^[A-Za-z0-9_.]{1,80}$/.test(key)) {
      rejected.push(`列表路径「${key}」不是允许的键路径`);
      continue;
    }
    const node = getByPath(sampleJson, key);
    if (!Array.isArray(node) || node.filter(isPlainObject).length === 0) {
      rejected.push(`列表路径「${key}」在实测响应里取不到对象数组`);
      continue;
    }
    if (!extras.arrayPaths.includes(key)) extras.arrayPaths.push(key);
  }
  for (const f of Array.isArray(raw.idFields) ? raw.idFields : raw.idField ? [raw.idField] : []) {
    const key = String(f ?? "").trim();
    if (!/^[A-Za-z0-9_]{1,40}$/.test(key) || !allKeys.has(key)) {
      rejected.push(`主键字段「${key}」不在实测响应的对象字段里`);
      continue;
    }
    if (!extras.idFields.includes(key)) extras.idFields.push(key);
  }
  const proposed = Array.isArray(raw.pagination) ? raw.pagination : raw.pagination ? [raw.pagination] : [];
  for (const q of proposed) {
    if (!isPlainObject(q)) {
      rejected.push("分页假设不是键值对象");
      continue;
    }
    const entries = Object.entries(q);
    if (entries.length === 0 || entries.length > 3) {
      rejected.push(`分页假设键数越界（${entries.length}）`);
      continue;
    }
    const clean = {};
    let bad = null;
    for (const [k, v] of entries) {
      if (!PAGINATION_KEYS.has(k)) {
        bad = k;
        break;
      }
      const n = Number(v);
      if (!Number.isFinite(n) || n < 0 || n > 5000) {
        bad = k;
        break;
      }
      clean[k] = String(n);
    }
    if (bad) {
      rejected.push(`分页参数「${bad}」不在白名单或取值非法`);
      continue;
    }
    const sig = entries.map(([k]) => k).sort().join("+");
    if (!extras.pagination.some((e) => Object.keys(e).sort().join("+") === sig)) extras.pagination.push(clean);
  }
  return { extras, rejected };
}

function statusOf(res) {
  return Number(res?.status ?? res?.statusCode ?? 0);
}

function isDenied(res) {
  if (res?.error) return false;
  const s = statusOf(res);
  if (s === 401 || s === 403) return true;
  // 2xx 却只回错误体（不少框架用 200 + {error} 表达未登录）：这个槽位给不出资源
  const json = res?.json;
  return s >= 200 && s < 300 && isPlainObject(json) && json.error != null && json.data == null;
}

/**
 * 实测列表契约：逐个槽位 × 分页假设 × 数组路径 × 候选主键，两个真实身份对拉。
 * @param {object} opts
 * @param {(req:{method:string,path:string,query:object|null,identity:string}) => Promise<object>} opts.request
 * @param {Array<{key:string,method?:string,path:string,params?:string[],extraQuery?:object}>} opts.slots
 * @param {string[]} opts.identities 已登录的两个普通用户身份名
 * @param {object|null} [opts.extras] validateExtras 通过后的模型补充假设
 * @param {number} [opts.budget]
 */
export async function discoverListContract(opts) {
  const { request, slots = [], identities, extras = null, budget = MAX_CONTRACT_REQUESTS } = opts;
  const [nameA, nameB] = identities ?? [];
  const tried = [];
  let used = 0;
  let exhausted = false;

  const send = async ({ method, path, query, identity }) => {
    if (used >= budget) {
      exhausted = true;
      return null;
    }
    used += 1;
    try {
      return await request({ method, path, query, identity });
    } catch (e) {
      return { error: e?.message ?? String(e) };
    }
  };

  for (const slot of slots.slice(0, MAX_LIST_SLOTS)) {
    const slotKey = slot.key ?? `${slot.method ?? "GET"} ${slot.path}`;
    const hypotheses = [...PAGINATION_HYPOTHESES.slice(0, MAX_PAGINATION_TRIES)];
    for (const q of extras?.pagination ?? []) if (!hypotheses.includes(q)) hypotheses.push(q);

    for (const query of hypotheses) {
      if (used >= budget) break;
      const merged = { ...(slot.extraQuery ?? {}), ...(query ?? {}) };
      const resA = await send({
        method: slot.method ?? "GET",
        path: slot.path,
        query: Object.keys(merged).length > 0 ? merged : null,
        identity: nameA,
      });
      if (!resA) {
        tried.push({ slot: slotKey, query, outcome: "budget" });
        return finish(null);
      }
      if (resA.error) {
        tried.push({ slot: slotKey, query, outcome: "request_failed", detail: resA.error });
        break;
      }
      const s = statusOf(resA);
      if (s === 404 || s === 405) {
        tried.push({ slot: slotKey, query, outcome: "slot_absent", status: s });
        break;
      }
      if (isDenied(resA)) {
        tried.push({ slot: slotKey, query, outcome: "denied", status: s || null });
        break;
      }
      if (s !== 0 && s >= 400) {
        tried.push({ slot: slotKey, query, outcome: "bad_request", status: s });
        continue;
      }
      const paths = arrayPaths(resA.json);
      for (const p of extras?.arrayPaths ?? []) if (!paths.some((x) => x.path === p)) paths.push({ path: p, keys: [] });
      if (paths.length === 0) {
        tried.push({ slot: slotKey, query, outcome: "no_object_array" });
        continue;
      }
      const resB = await send({
        method: slot.method ?? "GET",
        path: slot.path,
        query: Object.keys(merged).length > 0 ? merged : null,
        identity: nameB,
      });
      if (!resB || resB.error || isDenied(resB) || statusOf(resB) >= 400) {
        tried.push({ slot: slotKey, query, outcome: "second_identity_unusable" });
        break;
      }
      for (const arrPath of paths.slice(0, MAX_ARRAY_PATHS)) {
        const itemsA = getByPath(resA.json, arrPath.path);
        const itemsB = getByPath(resB.json, arrPath.path);
        if (!Array.isArray(itemsA) || !Array.isArray(itemsB)) {
          tried.push({ slot: slotKey, query, arrayPath: arrPath.path, outcome: "path_not_array" });
          continue;
        }
        if (itemsA.filter(isPlainObject).length === 0 || itemsB.filter(isPlainObject).length === 0) {
          tried.push({ slot: slotKey, query, arrayPath: arrPath.path, outcome: "empty_list" });
          continue;
        }
        const cleanA = itemsA.filter(isPlainObject);
        const cleanB = itemsB.filter(isPlainObject);
        const candidates = [...idFieldCandidates(arrPath.keys), ...(extras?.idFields ?? [])].filter(
          (v, i, arr) => arr.indexOf(v) === i
        );
        if (candidates.length === 0) {
          tried.push({ slot: slotKey, query, arrayPath: arrPath.path, outcome: "no_id_field" });
          continue;
        }
        let matched = null;
        for (const field of candidates.slice(0, MAX_ID_FIELDS + 1)) {
          const rel = compareIdSets(idSet(cleanA, field), idSet(cleanB, field));
          if (rel === "disjoint") {
            matched = field;
            break;
          }
          tried.push({ slot: slotKey, query, arrayPath: arrPath.path, idField: field, outcome: `ids_${rel}` });
        }
        if (!matched) continue;
        const ownerFields = ownerContrastFields(cleanA, cleanB, [matched]);
        return finish({
          slotKey,
          slot,
          listPath: arrPath.path,
          listQuery: Object.keys(merged).length > 0 ? merged : null,
          idField: matched,
          ownerField: ownerFields[0] ?? null,
          ownerCandidates: ownerFields,
          counts: { a: cleanA.length, b: cleanB.length },
          needsPagination: query != null,
          sampleKeys: commonKeys(cleanA).slice(0, 12),
          itemsA: cleanA,
          itemsB: cleanB,
        });
      }
    }
  }

  function finish(contract) {
    return {
      contract,
      tried,
      requestsUsed: used,
      budgetExhausted: exhausted && contract == null,
    };
  }
  return finish(null);
}

/**
 * 实测单体契约：用本人列表里的真实对象回读一次自己的端点，
 * 响应里「含同一主键值」的对象才是实体（{ meta, record } 这种包装靠这一步认出来）。
 */
export async function discoverEntityContract(opts) {
  const { request, slot, identity, idField, idValue, ownerField, budget = 4 } = opts;
  const path = slot?.path ?? null;
  if (!path) return { entityPath: null, reason: "no_path", requestsUsed: 0, status: null };
  let used = 0;
  const send = async () => {
    if (used >= budget) return null;
    used += 1;
    try {
      return await request({ method: slot.method ?? "GET", path, query: slot.query ?? null, identity });
    } catch (e) {
      return { error: e?.message ?? String(e) };
    }
  };
  const res = await send();
  if (!res || res.error || statusOf(res) >= 400 || isDenied(res)) {
    return { entityPath: null, reason: res?.error ? "request_failed" : "unusable", requestsUsed: used, status: statusOf(res) || null };
  }
  const paths = objectPaths(res.json);
  const matches = (obj) => String(obj?.[idField]) === String(idValue);
  for (const p of ["", ...paths.map((x) => x.path)]) {
    const node = p === "" ? res.json : getByPath(res.json, p);
    if (!isPlainObject(node)) continue;
    if (!matches(node)) continue;
    if (ownerField && node[ownerField] === undefined) continue;
    return { entityPath: p || null, reason: null, requestsUsed: used, status: statusOf(res) };
  }
  return { entityPath: null, reason: "no_object_carries_id", requestsUsed: used, status: statusOf(res) };
}

/** 响应里（根层或一层包装内）是否读回了预期的那个对象 */
function carriesId(json, idField, expectedId) {
  if (!isPlainObject(json) || idField == null) return false;
  if (String(json[idField] ?? "") === String(expectedId)) return true;
  for (const v of Object.values(json)) {
    if (isPlainObject(v) && String(v[idField] ?? "") === String(expectedId)) return true;
  }
  return false;
}

/**
 * 实测多段路径参数绑定：用归属本人的对象填参数发一次真实请求，
 * 只有「2xx 且响应里读回同一主键」才算这条路由可寻址。
 */
export async function discoverBindings(opts) {
  const { request, slots = [], itemsByIdentity, idField, budget = 8 } = opts;
  const out = [];
  let used = 0;
  for (const slot of slots.slice(0, MAX_BINDING_SLOTS)) {
    const paramNames = slot.params ?? [];
    if (paramNames.length < 2) continue;
    const entry = itemsByIdentity?.[slot.identity];
    if (!entry?.item) {
      out.push({ key: slot.key ?? slot.path, outcome: "no_own_item", bindings: null });
      continue;
    }
    const bindings = bindingsFromItem(entry.item, paramNames);
    if (!bindings) {
      out.push({ key: slot.key ?? slot.path, outcome: "unbound_param", bindings: null });
      continue;
    }
    if (used >= budget) {
      out.push({ key: slot.key ?? slot.path, outcome: "budget", bindings: null });
      continue;
    }
    used += 1;
    const filled = slot.path.replace(/:([A-Za-z_]\w*)/g, (_m, name) => {
      const b = bindings[name];
      const v = b ? entry.item[b.field] : undefined;
      return encodeURIComponent(String(v ?? ""));
    });
    let res = null;
    try {
      res = await request({ method: slot.method ?? "GET", path: filled, query: slot.query ?? null, identity: slot.identity });
    } catch (e) {
      res = { error: e?.message ?? String(e) };
    }
    const status = statusOf(res);
    const expectedId = entry.item[idField];
    const ok =
      !!res &&
      !res.error &&
      status >= 200 &&
      status < 300 &&
      !isDenied(res) &&
      carriesId(res.json, idField, expectedId);
    // 同一次回读顺带推出实体包装路径（{ meta, record } 之类）：
    // 单体端点可能不是静态计划里的候选（如只有多段路由的项目），没有这里就取错对象
    let entityPath = null;
    if (ok) {
      const paths = objectPaths(res.json);
      for (const p of ["", ...paths.map((x) => x.path)]) {
        const node = p === "" ? res.json : getByPath(res.json, p);
        if (!isPlainObject(node)) continue;
        if (String(node[idField] ?? "") !== String(expectedId)) continue;
        entityPath = p || null;
        break;
      }
    }
    out.push({
      key: slot.key ?? slot.path,
      outcome: !res || res.error ? "request_failed" : ok ? "verified" : status === 404 ? "not_found" : "rejected",
      bindings: ok ? bindings : null,
      status: status || null,
      path: filled,
      entityPath,
    });
  }
  return { results: out, requestsUsed: used };
}

/* ------------------------------- 缓存 ------------------------------- */

const CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const CACHE_MAX = 20;

export function contractFingerprint({ commit = null, slots = [], identities = [], resourceName = null, declared = {} }) {
  const parts = [
    CONTRACT_VERSION,
    commit ?? "no-commit",
    resourceName ?? "",
    [...identities].sort().join(","),
    slots
      .map((s) => `${s.method ?? "GET"} ${s.path} ${JSON.stringify(s.extraQuery ?? null)}`)
      .sort()
      .join("|"),
    JSON.stringify(declared ?? {}),
  ];
  return createHash("sha256").update(parts.join("\0")).digest("hex").slice(0, 32);
}

/**
 * 缓存里只存「实测出来的字段位置」，绝不存响应体本身：
 * 列表元素可能含用户数据，落盘到 GUARDBUILD_DATA_DIR 等于把目标数据抄一份到证据目录。
 */
export function contractForCache(contract) {
  if (!contract) return null;
  const { itemsA, itemsB, slot, ...rest } = contract;
  return {
    ...rest,
    slot: slot ? { method: slot.method ?? "GET", path: slot.path } : null,
    sampleKeys: (contract.sampleKeys ?? []).slice(0, 12),
  };
}

function cacheRootDir() {
  const base = process.env.GUARDBUILD_DATA_DIR;
  return typeof base === "string" && base.trim() ? base.trim() : null;
}

function projectCacheId(root) {
  const p = String(root ?? "").replace(/\\/g, "/").replace(/\/+$/, "");
  return createHash("sha256").update(process.platform === "win32" ? p.toLowerCase() : p).digest("hex").slice(0, 16);
}

function cacheFile(ctx, key) {
  const base = cacheRootDir();
  if (!base) return null;
  return join(base, "rescontract", projectCacheId(ctx?.projectRoot), `${key}.json`);
}

export function writeContractCache(ctx, key, payload) {
  const file = cacheFile(ctx, key);
  if (!file) return null;
  const tmp = `${file}.${process.pid}.tmp`;
  try {
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(tmp, JSON.stringify({ version: CONTRACT_VERSION, savedAt: Date.now(), ...payload }), "utf8");
    renameSync(tmp, file);
    prune(dirname(file));
    return file;
  } catch {
    try {
      rmSync(tmp, { force: true });
    } catch {
      /* ignore */
    }
    return null;
  }
}

export function readContractCache(ctx, key) {
  const file = cacheFile(ctx, key);
  if (!file) return null;
  try {
    const data = JSON.parse(readFileSync(file, "utf8"));
    if (data?.version !== CONTRACT_VERSION) return null;
    if (Date.now() - Number(data.savedAt ?? 0) > CACHE_TTL_MS) return null;
    return data;
  } catch {
    return null;
  }
}

function prune(dir) {
  try {
    const files = readdirSync(dir)
      .filter((n) => n.endsWith(".json"))
      .map((n) => ({ name: n, mtime: statSync(join(dir, n)).mtimeMs }))
      .sort((a, b) => b.mtime - a.mtime);
    for (const f of files.slice(CACHE_MAX)) rmSync(join(dir, f.name), { force: true });
  } catch {
    /* 缓存清理失败不影响主流程 */
  }
}

/** 从 .git 里取当前 commit（只读）；取不到返回 null，缓存键回落到纯内容指纹 */
export async function readCommitFromGit(readText) {
  try {
    const head = String((await readText(".git/HEAD")) ?? "").trim();
    if (!head) return null;
    const match = /^ref:\s*(\S+)/m.exec(head);
    if (!match) return /^[0-9a-f]{7,40}$/.test(head) ? head : null;
    const ref = match[1];
    const direct = String((await readText(`.git/${ref}`)) ?? "").trim();
    if (/^[0-9a-f]{7,40}$/.test(direct)) return direct;
    const packed = String((await readText(".git/packed-refs")) ?? "");
    for (const line of packed.split(/\r?\n/)) {
      const [shaValue, name] = line.trim().split(/\s+/);
      if (name === ref && /^[0-9a-f]{7,40}$/.test(shaValue ?? "")) return shaValue;
    }
    return null;
  } catch {
    return null;
  }
}
