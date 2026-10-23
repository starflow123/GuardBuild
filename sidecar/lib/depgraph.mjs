/**
 * 依赖闭包：给编码代理算出「允许写哪些文件」的有限集合。
 *
 * 为什么不能放开成「全仓库任意改」：补丁归因链要求 `candidate → 定位文件 → 补丁 → 该候选的用例翻转`
 * 可追溯。写集无限时，报告里的 verified 就退化成「总体变好了」，那正是最危险的假修复。
 *
 * 集合由三类构成（角色名进风险画像，人工 review 能看出这条补丁为什么动了共享文件）：
 *  - candidate：候选定位到的源码文件（S2-lite 之前的全部权限）
 *  - forward  ：候选文件 import 到的仓库内模块（取数层、共享 helper 在这一层）
 *  - reverse  ：直接 import 候选文件的模块（Nest 的 app.module.ts、Express 的 app.js 在这一层，
 *               挂守卫/中间件的正确修法必然落在这里，只有正向闭包时这两类栈仍修不了）
 *
 * bare specifier（`express`、`@prisma/client`）不入图：那是依赖产物，属于不可碰清单。
 * 图在 analyzer 已经读过的那批文件上构建，零额外读取。
 */

const JS_IMPORT_RES = [
  /require\(\s*["'`](\.[^"'`]+)["'`]\s*\)/g,
  /(?:import|export)\s+(?:[\w{}\s,*$]+\s+)?from\s+["'`](\.[^"'`]+)["'`]/g,
  // 副作用导入（import "./routes";）：挂守卫的启动文件常用这种写法，漏了它反向闭包就不成立
  /\bimport\s+["'`](\.[^"'`]+)["'`]/g,
  /\bimport\s*\(\s*["'`](\.[^"'`]+)["'`]\s*\)/g,
];
// Python 相对导入：from ..db import get_conn / from .services.auth import guard
const PY_IMPORT_RE = /^\s*from\s+(\.+)([\w.]*)\s+import\s/gm;

const RESOLVE_EXT = ["", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".py"];

import { relative, sep } from "node:path";

/** Host 返回的绝对路径在 Windows 上带 `\\?\` 扩展前缀，去掉后才是可比较的字面路径 */
function plain(v) {
  return String(v)
    .replace(/\\/g, "/")
    .replace(/^\/\/\?\//, "")
    .replace(/\/+$/, "");
}

/**
 * 仓库相对路径。Host 的 `\\?\` 扩展形态与契约里的普通形态可能同时出现，
 * 因此先按前缀剥离，再退回 node:path（不同根时 relative 会吐出越界路径，须判掉）。
 */
export function toRel(root, p) {
  if (!root || !p) return null;
  const r = plain(root);
  const a = plain(p);
  if (!r || !a) return null;
  const rl = r.toLowerCase();
  if (a.toLowerCase() === rl) return "";
  if (a.toLowerCase().startsWith(`${rl}/`)) return a.slice(r.length + 1);
  const rel = relative(String(root), String(p)).split(sep).join("/");
  if (!rel || rel.startsWith("..") || /^[A-Za-z]:/.test(rel) || rel.startsWith("//?/")) return null;
  return rel;
}

/** 抽出该文件引用到的仓库内相对模块说明符 */
export function extractRelativeImports(content) {
  const specs = [];
  for (const re of JS_IMPORT_RES) {
    re.lastIndex = 0;
    for (const m of String(content).matchAll(re)) specs.push(m[1]);
  }
  PY_IMPORT_RE.lastIndex = 0;
  for (const m of String(content).matchAll(PY_IMPORT_RE)) {
    const dots = m[1].length; // 一个点=当前包，两个点=上一级
    const tail = m[2] ? m[2].split(".").join("/") : "";
    const base = dots === 1 ? "." : `..${"/..".repeat(dots - 2)}`;
    specs.push(`${base}${tail ? `/${tail}` : ""}`);
  }
  return [...new Set(specs)];
}

/** 把 `./x`、`../y/z` 解析成图里真实存在的文件（补扩展名与 index 形态） */
export function resolveSpec(fromRel, spec, known) {
  const dir = fromRel.includes("/") ? fromRel.slice(0, fromRel.lastIndexOf("/")) : "";
  const joined = `${dir}/${spec}`
    .split("/")
    .filter(Boolean)
    .reduce((out, seg) => {
      if (seg === ".") return out;
      if (seg === "..") out.pop();
      else out.push(seg);
      return out;
    }, [])
    .join("/");
  if (!joined) return null;
  for (const ext of RESOLVE_EXT) {
    if (known.has(`${joined}${ext}`)) return `${joined}${ext}`;
  }
  for (const ext of RESOLVE_EXT.slice(1)) {
    if (known.has(`${joined}/index${ext}`)) return `${joined}/index${ext}`;
  }
  return null;
}

/**
 * @param files [{rel, content}] —— analyzer 已读过的源码（rel 为仓库相对路径）
 * @returns {{nodes: Map<string,{out:Set<string>,in:Set<string>}>, unresolved: number}}
 */
export function buildImportGraph(files) {
  const known = new Set(files.map((f) => f.rel).filter(Boolean));
  const nodes = new Map();
  const touch = (rel) => {
    if (!nodes.has(rel)) nodes.set(rel, { out: new Set(), in: new Set() });
    return nodes.get(rel);
  };
  for (const f of files) {
    if (!f.rel) continue;
    touch(f.rel);
  }
  let unresolved = 0;
  for (const f of files) {
    if (!f.rel) continue;
    for (const spec of extractRelativeImports(f.content)) {
      const target = resolveSpec(f.rel, spec, known);
      if (!target) {
        unresolved += 1;
        continue;
      }
      const from = touch(f.rel);
      const to = touch(target);
      if (from === to) continue; // 自引用不参与闭包
      from.out.add(target);
      to.in.add(f.rel);
    }
  }
  return { nodes, unresolved };
}

/** 闭包展开的规模上限：越界即按广度截断，宁可少给权限也不给无限范围 */
export const CLOSURE_CAPS = { forwardDepth: 2, forwardFiles: 6, reverseDepth: 1, reverseFiles: 4 };

function bfs(nodes, seeds, dir, maxDepth, maxFiles) {
  const found = new Map();
  const queue = seeds.map((s) => [s, 0]);
  const seen = new Set(seeds);
  while (queue.length) {
    const [rel, depth] = queue.shift();
    if (depth >= maxDepth) continue;
    const node = nodes.get(rel);
    if (!node) continue;
    for (const next of node[dir]) {
      if (seen.has(next) || seeds.includes(next)) continue;
      seen.add(next);
      if (found.size >= maxFiles) continue;
      found.set(next, depth + 1);
      queue.push([next, depth + 1]);
    }
  }
  return found;
}

/**
 * 计算某个候选文件的写集。
 * @returns {{roles: Map<string,"candidate"|"forward"|"reverse">, rolesLower: Map<string,string>, newFileDirs: string[]}}
 */
export function expandWriteSet({ nodes, seeds, caps = CLOSURE_CAPS, enabled = true }) {
  const roles = new Map();
  for (const s of seeds) roles.set(s, "candidate");
  if (!enabled || !nodes || nodes.size === 0) return wrap(roles, nodes);
  for (const rel of bfs(nodes, seeds, "out", caps.forwardDepth, caps.forwardFiles).keys()) {
    if (!roles.has(rel)) roles.set(rel, "forward");
  }
  for (const rel of bfs(nodes, seeds, "in", caps.reverseDepth, caps.reverseFiles).keys()) {
    if (!roles.has(rel)) roles.set(rel, "reverse");
  }
  return wrap(roles, nodes);
}

function wrap(roles, nodes) {
  // 新建文件只能落在已有源码目录里：防止在仓库任意角落造文件
  const dirs = new Set();
  for (const rel of nodes?.keys?.() ?? []) {
    const i = rel.lastIndexOf("/");
    if (i > 0) dirs.add(rel.slice(0, i));
  }
  for (const rel of roles.keys()) {
    const i = rel.lastIndexOf("/");
    if (i > 0) dirs.add(rel.slice(0, i));
  }
  const rolesLower = new Map();
  for (const [rel, role] of roles) rolesLower.set(rel.toLowerCase(), role);
  return { roles, rolesLower, newFileDirs: [...dirs].sort() };
}

/** 共享度：一个文件被多少处 import（入度），进风险画像作为影响面指标 */
export function inDegree(nodes, rel) {
  return nodes?.get(rel)?.in?.size ?? 0;
}

/** 图要放进 analysis（可 JSON 化），Map/Set 无法序列化，落盘前折成数组 */
export function graphToJSON({ nodes, unresolved }) {
  return {
    nodes: [...nodes.entries()].map(([rel, n]) => ({ rel, out: [...n.out], in: [...n.in] })),
    unresolved,
  };
}

export function reviveGraph(json) {
  const nodes = new Map();
  for (const n of json?.nodes ?? []) {
    if (!n?.rel) continue;
    nodes.set(n.rel, { out: new Set(n.out ?? []), in: new Set(n.in ?? []) });
  }
  return nodes;
}

/**
 * 新建文件的目录约束：只能落在「已经有源码文件的目录」里。
 * @param rel 归一后的仓库相对路径
 * @param dirs expandWriteSet 返回的 newFileDirs
 */
export function createDirAllowed(rel, dirs) {
  const i = rel.lastIndexOf("/");
  if (i <= 0) return { ok: false, dir: "", reason: "新建文件必须位于项目内的某个源码目录下（需要父目录路径）" };
  const dir = rel.slice(0, i);
  if ((dirs ?? []).includes(dir)) return { ok: true, dir, reason: null };
  return { ok: false, dir, reason: `父目录 ${dir}/ 没有已扫描到的源码文件，不允许在此新建文件` };
}
