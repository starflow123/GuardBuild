/*
 * 极简 SQL 求值器：只覆盖本靶子用到的语句形状——
 *   SELECT * FROM <表> [WHERE <条件> [OR <条件> …]]
 *   条件： <列> LIKE '<模式>'  |  <字面量> = <字面量>
 *   -- 之后按行注释丢弃；引号不成对则抛数据库报错原文。
 *
 * 为什么要真的解析，而不是 `if (输入 === "' OR 1=1--") return 全部行`：
 * 注入用例的判据是「拼进 SQL 文本的用户输入，按 SQL 语义改变了结果集」。
 * 靶子配合载荷就测不出真实拼接的行为差异，判卷器拿到的证据也就是假的。
 */

export class SqlError extends Error {
  constructor(message) {
    super(message);
    this.name = "SqlError";
  }
}

function stripLineComment(sql) {
  const i = sql.indexOf("--");
  return i >= 0 ? sql.slice(0, i) : sql;
}

/** 按顶层 OR 分隔（单引号内不分隔：`'... OR ...'` 必须整体留在字面量里） */
function splitOr(text) {
  const parts = [];
  let current = "";
  let inQuote = false;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (ch === "'") {
      inQuote = !inQuote;
      current += ch;
      continue;
    }
    if (!inQuote) {
      const m = /^\s+OR\s+/i.exec(text.slice(i));
      if (m) {
        parts.push(current.trim());
        current = "";
        i += m[0].length - 1;
        continue;
      }
    }
    current += ch;
  }
  parts.push(current.trim());
  return parts;
}

function evalCondition(cond, row) {
  const like = /^([A-Za-z_]\w*)\s+LIKE\s+'([^']*)'$/i.exec(cond);
  if (like) {
    const column = like[1];
    const pattern = like[2];
    if (!(column in row)) throw new SqlError(`SQLITE_ERROR: no such column: ${column}`);
    const re = new RegExp(`^${pattern.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/%/g, "[\\s\\S]*")}$`, "i");
    return re.test(String(row[column] ?? ""));
  }
  const eq = /^'?([\w\s-]*'?)\s*=\s*'?([\w\s-]*)'?$/i.exec(cond);
  if (eq) return eq[1].replace(/^'|'$/g, "") === eq[2].replace(/^'|'$/g, "");
  throw new SqlError(`SQLITE_ERROR: unrecognized token: "${cond}"`);
}

function evalWhere(where, row) {
  const quotes = (where.match(/'/g) ?? []).length;
  if (quotes % 2 !== 0) {
    throw new SqlError(`SQLITE_ERROR: unrecognized token: "${where.trim().slice(0, 40)}" (unterminated string)`);
  }
  return splitOr(where).some((cond) => cond && evalCondition(cond, row));
}

export function createDb(tables) {
  function all(sqlText) {
    const sql = stripLineComment(String(sqlText)).trim().replace(/;+$/, "");
    const parsed = /^SELECT \* FROM ([A-Za-z_]\w*)(?:\s+WHERE\s+([\s\S]*))?$/i.exec(sql);
    if (!parsed) throw new SqlError(`SQLITE_ERROR: malformed statement near "${sql.slice(0, 40)}"`);
    const rows = tables[parsed[1].toLowerCase()];
    if (!rows) throw new SqlError(`SQLITE_ERROR: no such table: ${parsed[1]}`);
    if (!parsed[2]) return rows.slice();
    return rows.filter((row) => evalWhere(parsed[2], row));
  }
  return { all };
}
