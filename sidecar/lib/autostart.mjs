/**
 * 启动方式自动探测：guardbuild.json 缺失/未声明 start 时，从项目文件推断
 * 「怎么启动 / 端口怎么注入 / 什么时候算就绪」。
 *
 * 全部规则确定性、无网络：只看 package.json 脚本、锁文件、Procfile、
 * Python 入口（manage.py / FastAPI / Flask）与常见 Node 入口文件。
 * 探测结果始终使用 ${GB_PORT} 槽位注入端口（Vite 等不读 PORT 的脚本用命令行 --port），
 * 并配合 GENERIC_READY_PATTERN 匹配主流框架的监听日志；不打印日志的服务
 * 由 main.mjs 通过回环 HTTP 主动探活兜底。
 *
 * 另有 diagnoseStartFailure：把目标进程常见的启动失败翻译成可操作建议。
 */
import { RPC_TO_HOST } from "../../shared/protocol.mjs";

/** 端口槽位：targetconfig 也导出同一常量（此处定义以避免模块循环依赖） */
export const PORT_SLOT = "${GB_PORT}";

/** 主流框架/HTTP 服务监听日志的通用就绪模式（Rust regex 语法子集，编译失败会回落为子串匹配）。 */
export const GENERIC_READY_PATTERN =
  "(?i)https?://(?:localhost|127\\.0\\.0\\.1|0\\.0\\.0\\.0|\\[::1?\\]):\\d{2,5}" +
  "|(?:listen(?:ing)?|running|serv(?:ing|ed)|started|ready|监听|启动|运行|端口)[^\\n]{0,80}" +
  "(?:port|端口|localhost|127\\.0\\.0\\.1|0\\.0\\.0\\.0|\\[::1?\\])[^\\n]{0,40}\\d{2,5}" +
  "|\\bport\\b[^\\d\\n]{0,16}\\d{2,5}" +
  "|\\b(?:listen(?:ing)?|running|serv(?:ing|ed))\\b[^\\d\\n]{0,24}\\d{2,5}\\b" +
  "|nest application successfully started";

export const AUTO_READY_TIMEOUT_MS = 30_000;

/** Host proc.spawn 白名单（src-tauri/src/core/token.rs），自动探测只会生成这些启动器 */
export const ALLOWED_LAUNCHERS = new Set([
  "node", "npm", "npx", "python", "python3", "py", "uvicorn", "gunicorn", "hypercorn",
  "flask", "fastapi", "uv",
]);

const NODE_ENTRY_NAMES = [
  "server.js", "app.js", "index.js", "main.js",
  "server.mjs", "app.mjs", "index.mjs",
  "src/server.js", "src/app.js", "src/index.js", "src/main.js",
];

const PY_ENTRY_NAMES = ["main.py", "app.py", "server.py", "api.py", "run.py"];

const LOCKFILES = {
  "package-lock.json": "npm",
  "npm-shrinkwrap.json": "npm",
  "pnpm-lock.yaml": "pnpm",
  "yarn.lock": "yarn",
  "bun.lockb": "bun",
};

function slashes(p) {
  return String(p ?? "").replace(/\\/g, "/");
}

function stripLongPrefix(p) {
  return slashes(p).replace(/^\/\/\?\/?/, "");
}

/** 相对 projectRoot 的 POSIX 路径；不在根内返回 null */
export function relativeTo(root, p) {
  const r = stripLongPrefix(root).replace(/\/+$/, "");
  const x = stripLongPrefix(p);
  if (!r || !x) return null;
  if (x.toLowerCase() === r.toLowerCase()) return ".";
  if (x.toLowerCase().startsWith(`${r.toLowerCase()}/`)) return x.slice(r.length + 1);
  return null;
}

function parentOf(rel) {
  const i = rel.lastIndexOf("/");
  return i < 0 ? "." : rel.slice(0, i);
}

function baseOf(rel) {
  return rel.slice(rel.lastIndexOf("/") + 1);
}

function depthOf(rel) {
  return rel === "." ? 0 : rel.split("/").length;
}

function joinRel(dirRel, name) {
  return dirRel && dirRel !== "." ? `${dirRel}/${name}` : name;
}

async function listDir(ctx, abs, depth) {
  const res = await ctx.rpc.request(
    RPC_TO_HOST.FS_LIST,
    { token: ctx.tokens.project, path: abs, depth },
    { timeoutMs: 30_000 }
  );
  return Array.isArray(res?.entries) ? res.entries : [];
}

async function readText(ctx, abs) {
  const res = await ctx.rpc.request(
    RPC_TO_HOST.FS_READ,
    { token: ctx.tokens.project, path: abs, redact: false },
    { timeoutMs: 20_000 }
  );
  return typeof res?.content === "string" ? res.content : "";
}

async function exists(ctx, abs) {
  try {
    await ctx.rpc.request(RPC_TO_HOST.FS_STAT, { token: ctx.tokens.project, path: abs }, { timeoutMs: 10_000 });
    return true;
  } catch {
    return false;
  }
}

function filesFromEntries(root, entries, relDir = ".") {
  const m = new Map();
  for (const e of entries) {
    if (e.kind !== "file" && e.kind !== "symlink" && e.kind !== "dir") continue;
    const rel = relativeTo(root, e.path);
    if (!rel || parentOf(rel) !== relDir) continue;
    m.set(baseOf(rel).toLowerCase(), { ...e, rel });
  }
  return m;
}

function scoreDir(relDir) {
  if (relDir === ".") return 0;
  const parts = relDir.split("/");
  const last = parts[parts.length - 1].toLowerCase();
  if (parts.length === 1) {
    return /^(backend|server|api|service|services|app)$/.test(last) ? 1 : 4;
  }
  if (/^(backend|server|api|service|services)$/.test(last)) return 2;
  if (/^(apps|packages)$/.test(parts[0].toLowerCase())) return 3;
  return 5;
}

function rankDirs(rels) {
  return [...new Set(rels)].sort((a, b) => scoreDir(a) - scoreDir(b) || a.localeCompare(b));
}

/** Procfile：只接受 web 行且命令在 Host 白名单内；$PORT 替换为 ${GB_PORT} 槽位 */
export function parseProcfile(text) {
  for (const raw of String(text ?? "").split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const m = line.match(/^web:\s*(.+)$/i);
    if (!m) continue;
    const tokens = tokenize(m[1]);
    if (!tokens.length) continue;
    const cmd = tokens[0];
    const base = slashes(cmd).split("/").pop().replace(/\.(cmd|exe|bat)$/i, "").toLowerCase();
    if (!ALLOWED_LAUNCHERS.has(base)) return null;
    const args = tokens.slice(1).map((t) => t.replace(/\$\{?PORT\}?/g, PORT_SLOT));
    return {
      start: {
        cmd,
        args,
        env: { PORT: PORT_SLOT },
        cwd: null,
        readyPattern: GENERIC_READY_PATTERN,
        readyTimeoutMs: AUTO_READY_TIMEOUT_MS,
      },
      origin: "Procfile web 行",
    };
  }
  return null;
}

function tokenize(s) {
  const out = [];
  let cur = "";
  let quote = null;
  for (const ch of String(s)) {
    if (quote) {
      if (ch === quote) quote = null;
      else cur += ch;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
    } else if (/\s/.test(ch)) {
      if (cur) {
        out.push(cur);
        cur = "";
      }
    } else {
      cur += ch;
    }
  }
  if (cur) out.push(cur);
  return out;
}

function noteLockfile(pkg, files, info) {
  if (info._pmNoted) return;
  const declared =
    typeof pkg?.packageManager === "string" ? pkg.packageManager.split("@")[0].toLowerCase() : null;
  const lock = Object.keys(LOCKFILES).find((name) => files.has(name));
  const pm = declared ?? (lock ? LOCKFILES[lock] : null);
  if (!pm || pm === "npm") return;
  info._pmNoted = true;
  info.warnings.push(
    `检测到 ${pm} 包管理（${declared ? "packageManager 字段" : lock}）；GuardBuild 进程白名单不含 ${pm}，` +
      `将用 npm 执行 package.json 脚本（需依赖已安装；安装依赖请在 guardbuild.json 的 prepare 中使用受支持的命令）`
  );
}

function noteMissingDeps(files, info) {
  if (files.has("node_modules")) return;
  info.warnings.push(
    "未发现 node_modules：动态复现要求依赖已安装。可在 guardbuild.json 的 prepare 中加入安装步骤（如 npm install）后重试"
  );
}

function scriptStartArgs(scriptName, command) {
  const args = ["run", scriptName];
  const cmd = String(command ?? "");
  if (/\bvite\b/i.test(cmd) && !/--port\b/i.test(cmd)) {
    args.push("--", "--port", PORT_SLOT, "--host", "127.0.0.1");
  }
  return args;
}

/** 从 package.json 推断启动方式；目录内无可用脚本/入口时返回 null */
async function inferPackageStart(ctx, dirAbs, dirRel, files, info) {
  const ent = files.get("package.json");
  if (!ent) return null;
  let pkg;
  try {
    pkg = JSON.parse(await readText(ctx, ent.path));
  } catch (e) {
    info.warnings.push(`${joinRel(dirRel, "package.json")} 解析失败：${e.message}`);
    return null;
  }
  if (!pkg || typeof pkg !== "object") return null;

  noteLockfile(pkg, files, info);
  noteMissingDeps(files, info);

  const scripts = pkg.scripts && typeof pkg.scripts === "object" ? pkg.scripts : {};
  const runnable = Object.keys(scripts).filter((k) => typeof scripts[k] === "string" && scripts[k].trim());
  const preferred = ["start", "dev", "serve", "preview"].filter((k) => runnable.includes(k));
  const extra = runnable.filter((k) => !preferred.includes(k) && /^(start|dev|serve)/i.test(k));
  const order = [...preferred, ...extra];

  if (order.length > 0) {
    let chosen = order[0];
    if (
      chosen === "start" &&
      /\bnext\s+start\b/i.test(scripts.start) &&
      !(await exists(ctx, `${dirAbs}/.next/BUILD_ID`)) &&
      runnable.includes("dev")
    ) {
      chosen = "dev";
      info.warnings.push("检测到 Next.js 的 start 脚本但缺少 .next 构建产物，已改用 dev 脚本；生产启动需先在 prepare 中构建");
    }
    for (const other of order) {
      if (other === chosen) continue;
      info.alternatives.push(`package.json scripts.${other}（npm run ${other}）`);
      if (info.alternatives.length >= 5) break;
    }
    const command = scripts[chosen];
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(command.trim())) {
      info.warnings.push(
        `脚本 ${chosen} 含 POSIX 环境变量前缀（${command.split(/\s+/)[0]}），Windows 下 npm 可能无法执行；建议改用 cross-env 或在 guardbuild.json 的 start.env 中声明`
      );
    }
    return {
      start: {
        cmd: "npm",
        args: scriptStartArgs(chosen, command),
        env: { PORT: PORT_SLOT },
        cwd: dirRel === "." ? null : dirRel,
        readyPattern: GENERIC_READY_PATTERN,
        readyTimeoutMs: AUTO_READY_TIMEOUT_MS,
      },
      origin: `package.json scripts.${chosen}`,
    };
  }

  const candidates = [];
  if (typeof pkg.main === "string" && pkg.main.trim()) candidates.push(slashes(pkg.main.trim()).replace(/^\.\//, ""));
  candidates.push(...NODE_ENTRY_NAMES);
  for (const rel of candidates) {
    const simple = !rel.includes("/");
    const found = simple ? files.has(rel.toLowerCase()) : await exists(ctx, `${dirAbs}/${rel}`);
    if (!found) continue;
    return {
      start: {
        cmd: "node",
        args: [rel],
        env: { PORT: PORT_SLOT },
        cwd: dirRel === "." ? null : dirRel,
        readyPattern: GENERIC_READY_PATTERN,
        readyTimeoutMs: AUTO_READY_TIMEOUT_MS,
      },
      origin: rel === pkg.main ? `package.json main（${rel}）` : `入口文件 ${rel}`,
    };
  }
  info.warnings.push(
    `${joinRel(dirRel, "package.json")} 没有可运行的 start/dev 脚本，也未找到 server.js/index.js 等入口；请在契约中声明 start`
  );
  return null;
}

async function venvPython(ctx, dirAbs, root) {
  const candidates = [
    `${dirAbs}/.venv/Scripts/python.exe`,
    `${dirAbs}/venv/Scripts/python.exe`,
    `${dirAbs}/.venv/bin/python`,
    `${dirAbs}/venv/bin/python`,
  ];
  if (dirAbs !== root) {
    candidates.push(`${root}/.venv/Scripts/python.exe`, `${root}/venv/Scripts/python.exe`);
  }
  for (const p of candidates) {
    if (await exists(ctx, p)) return p;
  }
  return "python";
}

/** 从 Python 入口文件推断启动方式（manage.py / FastAPI / Flask / __main__） */
async function inferPythonStart(ctx, root, dirAbs, dirRel, files, info) {
  const hasPythonFile = files.has("manage.py") || PY_ENTRY_NAMES.some((n) => files.has(n));
  if (!hasPythonFile) return null;
  const py = await venvPython(ctx, dirAbs, root);
  const cwd = dirRel === "." ? null : dirRel;
  const base = {
    env: { PORT: PORT_SLOT },
    cwd,
    readyPattern: GENERIC_READY_PATTERN,
    readyTimeoutMs: AUTO_READY_TIMEOUT_MS,
  };

  if (files.has("manage.py")) {
    return {
      start: { cmd: py, args: ["manage.py", "runserver", `127.0.0.1:${PORT_SLOT}`, "--noreload"], ...base },
      origin: "manage.py（Django）",
    };
  }

  for (const name of PY_ENTRY_NAMES) {
    const ent = files.get(name);
    if (!ent) continue;
    let text;
    try {
      text = await readText(ctx, ent.path);
    } catch {
      continue;
    }
    const module = name.replace(/\.py$/i, "");
    const uvicornRun = text.match(/uvicorn\s*\.\s*run\s*\(\s*["']([\w.]+):(\w+)["']/);
    const fastapi = text.match(/([A-Za-z_]\w*)\s*=\s*FastAPI\s*\(/);
    const flask = text.match(/([A-Za-z_]\w*)\s*=\s*Flask\s*\(/);

    if (uvicornRun) {
      return {
        start: {
          cmd: py,
          args: ["-m", "uvicorn", `${uvicornRun[1]}:${uvicornRun[2]}`, "--host", "127.0.0.1", "--port", PORT_SLOT],
          ...base,
        },
        origin: `${name} 的 uvicorn.run`,
      };
    }
    if (fastapi) {
      return {
        start: {
          cmd: py,
          args: ["-m", "uvicorn", `${module}:${fastapi[1]}`, "--host", "127.0.0.1", "--port", PORT_SLOT],
          ...base,
        },
        origin: `${name}（FastAPI ${fastapi[1]}）`,
      };
    }
    if (flask) {
      return {
        start: {
          cmd: py,
          args: ["-m", "flask", "--app", `${module}:${flask[1]}`, "run", "--host", "127.0.0.1", "--port", PORT_SLOT],
          ...base,
        },
        origin: `${name}（Flask ${flask[1]}）`,
      };
    }
    if (/if\s+__name__\s*==\s*["']__main__["']/.test(text)) {
      return { start: { cmd: py, args: [name], ...base }, origin: `${name}（__main__ 入口）` };
    }
  }
  return null;
}

/**
 * 探测目标项目的启动方式。
 * 返回 { start, origin, alternatives, warnings, checked }；start 为 null 表示无法确定。
 */
export async function detectStartConfig(ctx) {
  const root = slashes(ctx.projectRoot).replace(/\/+$/, "");
  const info = { warnings: [], alternatives: [], checked: [] };
  if (!root) return { start: null, ...info };

  let rootEntries;
  try {
    rootEntries = await listDir(ctx, root, 1);
  } catch (e) {
    info.warnings.push(`无法列举项目根目录：${e.message}`);
    return { start: null, ...info };
  }
  info.checked.push("根目录文件");
  const rootFiles = filesFromEntries(root, rootEntries);

  if (rootFiles.has("procfile")) {
    try {
      const cand = parseProcfile(await readText(ctx, rootFiles.get("procfile").path));
      if (cand) return { ...cand, ...info };
      info.warnings.push("Procfile 的 web 行不在受支持的启动命令白名单内，已继续探测");
    } catch (e) {
      info.warnings.push(`读取 Procfile 失败：${e.message}`);
    }
  }

  const rootPkg = await inferPackageStart(ctx, root, ".", rootFiles, info);
  if (rootPkg) return { ...rootPkg, ...info };

  const rootPy = await inferPythonStart(ctx, root, root, ".", rootFiles, info);
  if (rootPy) return { ...rootPy, ...info };

  // 根目录没有可用入口：一次性列举到 3 层，寻找 backend/、server/、apps/api/ 等子目录
  info.checked.push("子目录");
  let deep = [];
  try {
    deep = await listDir(ctx, root, 3);
  } catch (e) {
    info.warnings.push(`无法列举子目录：${e.message}`);
  }

  const dirFiles = new Map();
  for (const e of deep.length ? deep : rootEntries) {
    if (e.kind !== "file" && e.kind !== "symlink") continue;
    const rel = relativeTo(root, e.path);
    if (!rel) continue;
    const dir = parentOf(rel);
    if (!dirFiles.has(dir)) dirFiles.set(dir, new Map());
    dirFiles.get(dir).set(baseOf(rel).toLowerCase(), { ...e, rel });
  }

  const pkgDirs = rankDirs(
    [...dirFiles.entries()]
      .filter(([rel, files]) => rel !== "." && files.has("package.json") && depthOf(rel) <= 2)
      .map(([rel]) => rel)
  );
  for (const dirRel of pkgDirs.slice(0, 4)) {
    const cand = await inferPackageStart(ctx, `${root}/${dirRel}`, dirRel, dirFiles.get(dirRel), info);
    if (cand) return { ...cand, ...info };
  }

  const pyDirs = rankDirs(
    [...dirFiles.entries()]
      .filter(
        ([rel, files]) =>
          rel !== "." &&
          depthOf(rel) <= 2 &&
          (files.has("manage.py") || PY_ENTRY_NAMES.some((n) => files.has(n)))
      )
      .map(([rel]) => rel)
  );
  for (const dirRel of pyDirs.slice(0, 4)) {
    const cand = await inferPythonStart(ctx, root, `${root}/${dirRel}`, dirRel, dirFiles.get(dirRel), info);
    if (cand) return { ...cand, ...info };
  }

  if (rootFiles.has("docker-compose.yml") || rootFiles.has("compose.yaml") || rootFiles.has("dockerfile")) {
    info.warnings.push(
      "检测到 Docker 配置，但 GuardBuild 不能经 docker 启动目标；请先在容器中启动依赖服务，并在 guardbuild.json 中声明 start"
    );
  }
  return { start: null, ...info };
}

const DIAGNOSTICS = [
  {
    code: "next_no_build",
    re: /could not find a production build|no production build/i,
    hint:
      "Next.js 的 start 需要先构建：请在 guardbuild.json 的 prepare 中加入 npm run build，或改用 dev 脚本",
  },
  {
    code: "port_in_use",
    re: /EADDRINUSE|address already in use|端口[^\n]{0,12}(?:占用|使用中)|Port \d+ is (?:already )?in use/i,
    hint:
      "端口已被占用。请先关闭残留进程；若应用忽略 PORT 环境变量而写死端口，请在 guardbuild.json 的 start.args 中显式传入 ${GB_PORT}",
  },
  {
    code: "missing_env",
    re:
      /missing (?:required )?environment variable|environment variable [`'"]?([A-Z0-9_]+)[`'"]? (?:is )?(?:not set|missing)|(?:DATABASE_URL|JWT_SECRET|SESSION_SECRET|API_KEY)[^\n]{0,40}(?:not set|missing|undefined|未设置)|缺少环境变量/i,
    hint:
      "缺少环境变量。Host 只透传白名单变量与 start.env，请把数据库连接串/密钥等写进 guardbuild.json 的 start.env（不要把本机 .env 直接暴露给被测进程）",
  },
  {
    code: "dependency_unreachable",
    re: /ECONNREFUSED|connection refused|Can't reach database server|P1001/i,
    hint:
      "目标进程依赖的数据库/缓存等服务未启动或地址不对。请先启动依赖服务，并在 guardbuild.json 的 start.env 中配置连接串",
  },
  {
    code: "db_not_initialized",
    re:
      /SQLITE_CANTOPEN|unable to open database file|no such table|relation [`"'][^`"']+[`"'] does not exist|Unknown database|database [^\n]{0,20}does not exist|P2021|P1003/i,
    hint:
      "数据库未初始化或未迁移。请先在 guardbuild.json 的 prepare 中执行迁移/种子脚本（或手动初始化数据库）后重试",
  },
  {
    code: "django_migrations",
    re: /You have \d+ unapplied migration|django\.db\.utils\.OperationalError/i,
    hint: "Django 数据库未迁移：请先执行 python manage.py migrate（可写入 guardbuild.json 的 prepare）",
  },
  {
    code: "command_not_found",
    re:
      /is not recognized as an internal or external command|command not found|不是内部或外部命令|spawn [^\n]* ENOENT|ENOENT[^\n]*spawn/i,
    hint:
      "启动命令不存在或不在 PATH 中。自动探测只会使用 node/npm/python 等白名单命令；Windows 上若 python 不存在，可在契约中改用 py",
  },
  {
    code: "python_missing_dependency",
    re: /ModuleNotFoundError: No module named [`'"]([^`'"]+)['"`]/i,
    hint:
      "缺少 Python 依赖。请激活项目虚拟环境或安装依赖（如 pip install -r requirements.txt），也可在 guardbuild.json 的 prepare 中声明",
  },
  {
    code: "missing_dependency",
    re: /Cannot find module [`'"]([^`'"]+)[`'"]|Cannot find package [`'"]([^`'"]+)[`'"]|ERR_MODULE_NOT_FOUND|MODULE_NOT_FOUND/,
    hint:
      "缺少 Node 依赖。请先在目标项目安装依赖（npm install），或在 guardbuild.json 的 prepare 中加入安装步骤后重试",
  },
  {
    code: "script_missing",
    re: /Missing script: [`'"]?([\w:-]+)/i,
    hint: "package.json 中没有该脚本：请把 guardbuild.json 的 start.args 改成实际存在的脚本名",
  },
  {
    code: "bind_address",
    re: /EADDRNOTAVAIL|cannot assign requested address/i,
    hint: "监听地址不可用：请检查 start.args 中的 host（本机复现建议使用 127.0.0.1）",
  },
  {
    code: "permission_denied",
    re: /EACCES|permission denied/i,
    hint: "文件/端口权限不足：请检查项目目录权限，或改用非特权端口（GuardBuild 会分配空闲端口）",
  },
  {
    code: "syntax_error",
    re:
      /SyntaxError|Unexpected token|Unexpected identifier|Cannot use import statement outside a module|ERR_REQUIRE_ESM/i,
    hint:
      "源码或构建产物存在语法/模块格式错误：请先修复代码或补充构建（prepare）步骤；CommonJS/ESM 混用需调整 package.json type 或入口",
  },
];

function tailLines(lines, n = 12) {
  return lines.slice(Math.max(0, lines.length - n));
}

/** 按诊断规则表全量扫描日志，返回每条命中（供修复循环回喂编码代理复用启动诊断知识） */
export function matchDiagnostics(lines, { limit = 4 } = {}) {
  const text = (Array.isArray(lines) ? lines : []).map((l) => String(l ?? "")).join("\n");
  const hits = [];
  for (const d of DIAGNOSTICS) {
    const m = text.match(d.re);
    if (!m) continue;
    hits.push({ code: d.code, hint: d.hint, matched: String(m[0]).slice(0, 200) });
    if (hits.length >= limit) break;
  }
  return hits;
}

/** 把启动失败日志翻译成可操作诊断；无日志时按退出状态给出通用建议 */
export function diagnoseStartFailure({ output = [], exitCode = null, start = null } = {}) {
  const lines = (Array.isArray(output) ? output : []).map((l) => String(l ?? ""));
  const text = lines.join("\n");
  for (const d of DIAGNOSTICS) {
    const m = text.match(d.re);
    if (!m) continue;
    return { code: d.code, exitCode, hint: d.hint, matched: m[0].slice(0, 200), excerpt: tailLines(lines) };
  }
  if (Number.isInteger(exitCode)) {
    return {
      code: "early_exit",
      exitCode,
      hint: `目标进程启动后立即退出（退出码 ${exitCode}），且未输出可识别的错误。请先在项目目录手动运行启动命令确认；如缺依赖或环境变量，请补充 prepare / start.env`,
      excerpt: tailLines(lines),
    };
  }
  const cmd = start ? `${start.cmd} ${(start.args ?? []).join(" ")}`.trim() : "启动命令";
  return {
    code: "no_ready_output",
    exitCode,
    hint: `进程未在超时内输出可识别的就绪行（${cmd}）。若服务不打印监听日志，GuardBuild 已尝试 HTTP 探活；也可在 guardbuild.json 中把 start.readyPattern 设为实际输出`,
    excerpt: tailLines(lines),
  };
}
