/*
 * 只覆盖本靶子用到的语句形状：SELECT * FROM <表> [WHERE <条件> [OR <条件> …]]
 *   条件：<列> LIKE '<模式>'  |  <字面量> = <字面量>
 *   -- 之后视为行注释丢弃；引号不成对就当语法错误抛出（报错型注入的证据从这里出来）。
 *
 * 与「命中载荷原文就返回全部行」的写法区别要说清：那样测不出拼接是否真的改变了 SQL 语义，
 * 判卷器拿到的绿灯也就是假的，所以这里按 SQL 语义求值。
 */

import { tables } from "./data.js";

export class SqlError extends Error {
  constructor(message) {
    super(message);
    this.name = "SqlError";
  }
}

function whereOf(sql) {
  const i = sql.indexOf("--");
  const text = (i >= 0 ? sql.slice(0, i) : sql).trim().replace(/;+$/, "");
  const m = /^SELECT \* FROM ([A-Za-z_]\w*)(?:\s+WHERE\s+([\s\S]*))?$/i.exec(text);
  if (!m) throw new SqlError(`SQLITE_ERROR: malformed statement near "${text.slice(0, 40)}"`);
  return { table: m[1].toLowerCase(), where: m[2] ?? null };
}

/** 按顶层 OR 分隔：单引号内部出现的 OR 必须整体留在字面量里 */
function orClauses(where) {
  const parts = [];
  let cur = "";
  let quoted = false;
  for (let i = 0; i < where.length; i += 1) {
    const ch = where[i];
    if (ch === "'") {
      quoted = !quoted;
      cur += ch;
      continue;
    }
    if (!quoted && /^\s+OR\s+/i.test(where.slice(i))) {
      const skip = /^\s+OR\s+/i.exec(where.slice(i))[0].length;
      parts.push(cur.trim());
      cur = "";
      i += skip - 1;
      continue;
    }
    cur += ch;
  }
  parts.push(cur.trim());
  return parts.filter(Boolean);
}

function clauseTrue(clause, row) {
  const like = /^([A-Za-z_]\w*)\s+LIKE\s+'([^']*)'$/i.exec(clause);
  if (like) {
    if (!(like[1] in row)) throw new SqlError(`SQLITE_ERROR: no such column: ${like[1]}`);
    const re = new RegExp(`^${like[2].replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/%/g, "[\\s\\S]*")}$`, "i");
    return re.test(String(row[like[1]] ?? ""));
  }
  const eq = /^'?([\w\s-]*'?)\s*=\s*'?([\w\s-]*)'?$/i.exec(clause);
  if (eq) return eq[1].replace(/^'|'$/g, "") === eq[2].replace(/^'|'$/g, "");
  throw new SqlError(`SQLITE_ERROR: unrecognized token: "${clause}"`);
}

/** 执行一条 SELECT，返回行数组（与真实驱动的 all() 同形） */
export function dbAll(sqlText) {
  const { table, where } = whereOf(String(sqlText));
  const rows = tables[table];
  if (!rows) throw new SqlError(`SQLITE_ERROR: no such table: ${table}`);
  if (!where) return rows.slice();
  if (((where.match(/'/g) ?? []).length) % 2 !== 0) {
    throw new SqlError(`SQLITE_ERROR: unrecognized token: "${where.trim().slice(0, 40)}" (unterminated string)`);
  }
  return rows.filter((row) => orClauses(where).some((c) => clauseTrue(c, row)));
}
