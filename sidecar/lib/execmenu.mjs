/**
 * 启动代理（S3-full）的动作菜单：命令行由引擎从仓库自身声明里拼装，模型只能报编号。
 *
 * 为什么不让模型直接给命令：proc.spawn 的 Host 白名单只约束启动器名字（node/npm/python/uv…），
 * 参数是任意的。模型给一句 `npm run <不存在的脚本>` 只是失败，给一句 `node evil.js` 就是任意代码执行。
 * 因此这里把可选动作收敛成封闭集合（安装 / 构建类脚本 / 已声明的启动候选 / 只读查看 / 放弃），
 * 模型报编号，引擎按编号取自己生成的那条——模型附带的 cmd/args 一律丢弃。
 *
 * 菜单的来源全部是引擎已经读过或允许读的仓库清单文件；脚本内容只作为观察信息，不参与拼装。
 * 裸 `node <任意文件>` 不进菜单：收益不划算，那是真正的任意代码执行。
 */

/** 安装类：只有存在清单时才生成，且命令行固定 */
const NPM_LOCKFILES = ["package-lock.json", "npm-shrinkwrap.json"];
/** 构建/准备类脚本名的白名单（必须同时出现在 package.json 的 scripts 里） */
const ALLOWED_SCRIPT_RE =
  /^(build|prebuild|postbuild|build:main|prepare|preinstall|install|postinstall|setup|bootstrap|codegen|codegen:all|generate|prisma:generate|prisma:migrate|db:push|db:migrate|migrate)$/;
const SCRIPT_NAME_SAFE = /^[A-Za-z0-9][A-Za-z0-9_:./-]{0,39}$/;

export const MAX_MENU_ACTIONS = 12;
/** 只读动作允许的路径形状（相对项目根；拒绝越界、绝对路径与密钥类文件） */
const READ_FORBIDDEN_RE = /(^|\/)(\.env(\.|$)|\.git\/|node_modules\/|secrets?(\/|$)|.*\.(pem|key|p12|kdbx)$)/i;

const normRel = (v) =>
  String(v ?? "")
    .replace(/\\/g, "/")
    .replace(/^\.\//, "")
    .replace(/\/+/g, "/");

/** 只读动作的路径守卫：合法返回归一路径，非法返回 null */
export function safeReadPath(raw) {
  const rel = normRel(raw);
  if (!rel || rel.length > 200) return null;
  if (rel.startsWith("/") || /^[A-Za-z]:/.test(rel)) return null;
  if (rel.split("/").some((s) => s === ".." || s === "")) return null;
  if (READ_FORBIDDEN_RE.test(rel)) return null;
  return rel;
}

function parseJsonLoose(text) {
  try {
    return JSON.parse(String(text));
  } catch {
    return null;
  }
}

/**
 * 生成封闭动作集。
 * @param {object} facts
 * @param {Array<{rel:string, content:string}>} facts.manifests 引擎读到的清单文件（缺内容视为不存在）
 * @param {Array<object>} [facts.starts] 引擎已有的启动候选（cmd/args/cwd 由引擎持有）
 * @param {string} [facts.reason] 本轮为什么需要代理介入（诊断码/失败摘要），只进观察不进菜单
 */
export function buildActionMenu({ manifests = [], starts = [] } = {}) {
  const have = new Map();
  for (const m of manifests) {
    const rel = normRel(m?.rel);
    if (rel) have.set(rel, typeof m.content === "string" ? m.content : null);
  }
  const actions = [];
  const push = (a) => {
    if (actions.length >= MAX_MENU_ACTIONS) return;
    if (actions.some((x) => x.shape === a.shape)) return; // 同一形状只留一条
    actions.push({ ...a, id: actions.length + 1 });
  };

  const pkgText = have.get("package.json");
  if (have.has("package.json")) {
    const lock = NPM_LOCKFILES.find((f) => have.has(f));
    if (lock) {
      push({
        kind: "exec",
        cmd: "npm",
        args: ["ci"],
        cwd: ".",
        reason: `存在 ${lock}，用 npm ci 按锁文件安装（与人工准备步骤同一动作面）`,
        source: lock,
        shape: "npm ci",
      });
    } else {
      push({
        kind: "exec",
        cmd: "npm",
        args: ["install"],
        cwd: ".",
        reason: "package.json 存在但没有 npm 锁文件，用 npm install 安装依赖",
        source: "package.json",
        shape: "npm install",
      });
    }
    const scripts = pkgText && parseJsonLoose(pkgText)?.scripts;
    if (scripts && typeof scripts === "object" && !Array.isArray(scripts)) {
      for (const name of Object.keys(scripts).sort()) {
        if (!SCRIPT_NAME_SAFE.test(name) || !ALLOWED_SCRIPT_RE.test(name)) continue;
        const body = String(scripts[name] ?? "").slice(0, 160);
        push({
          kind: "exec",
          cmd: "npm",
          args: ["run", name],
          cwd: ".",
          reason: `package.json 已声明脚本 ${name}`,
          source: "package.json",
          shape: `npm run ${name}`,
          scriptBody: body,
        });
      }
    }
  }

  if (have.has("requirements.txt")) {
    push({
      kind: "exec",
      cmd: "python",
      args: ["-m", "pip", "install", "-r", "requirements.txt"],
      cwd: ".",
      reason: "requirements.txt 存在，按清单安装 Python 依赖",
      source: "requirements.txt",
      shape: "python -m pip install -r requirements.txt",
    });
  }
  if (have.has("uv.lock") && have.has("pyproject.toml")) {
    push({
      kind: "exec",
      cmd: "uv",
      args: ["sync"],
      cwd: ".",
      reason: "uv.lock + pyproject.toml：用 uv sync 还原环境",
      source: "uv.lock",
      shape: "uv sync",
    });
  }

  // 保留引擎原样的 start 对象字段（readyPattern/readyTimeoutMs/env…），tryStart 要用它真实拉起
  const startEntries = (starts ?? [])
    .filter((s) => s && typeof s.cmd === "string" && Array.isArray(s.args))
    .slice(0, 8)
    .map((s, i) => ({
      ...s,
      id: i + 1,
      kind: "start",
      cmd: s.cmd,
      args: s.args.map(String),
      cwd: s.cwd ?? null,
      shape: [s.cmd, ...s.args.map(String)].filter(Boolean).join(" "),
      source: s.source ?? "engine",
    }));

  return {
    actions,
    actionsById: new Map(actions.map((a) => [a.id, a])),
    starts: startEntries,
    startsById: new Map(startEntries.map((s) => [s.id, s])),
  };
}

export const ACTIONS = ["exec", "start", "read", "list", "giveup"];

/**
 * 校验模型的一步选择。只认编号，不认模型给的命令行。
 * @returns {{ok:true, step:object, ignored:string[]}|{ok:false, reason:string}}
 */
export function validateActionChoice(raw, menu) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return { ok: false, reason: "选择必须是 JSON 对象" };
  }
  const action = String(raw.action ?? "").toLowerCase();
  if (!ACTIONS.includes(action)) {
    return { ok: false, reason: `动作 ${action || "（空）"} 不在允许列表（${ACTIONS.join("/")}）` };
  }
  // 模型想自己拼命令行时常见的键，一律丢弃并留痕
  const ignored = ["cmd", "command", "args", "shell", "script", "url"].filter((k) => raw[k] !== undefined);

  if (action === "giveup") {
    return { ok: true, ignored, step: { action, note: String(raw.note ?? "").slice(0, 300) } };
  }
  if (action === "read" || action === "list") {
    const rel = safeReadPath(raw.path);
    if (!rel) return { ok: false, reason: `路径 ${String(raw.path ?? "").slice(0, 80)} 不在只读允许范围（相对项目根、排除 .env/node_modules/.git/密钥文件）` };
    return { ok: true, ignored, step: { action, path: rel } };
  }
  if (action === "exec") {
    const id = Number(raw.id);
    const entry = Number.isInteger(id) ? menu.actionsById.get(id) : null;
    if (!entry) {
      const valid = menu.actions.map((a) => a.id).join(", ") || "无";
      return { ok: false, reason: `动作编号 ${String(raw.id ?? "（空）")} 不在菜单内（可用编号：${valid}）` };
    }
    return { ok: true, ignored, step: { action, entry } };
  }
  const id = Number(raw.candidate);
  const entry = Number.isInteger(id) ? menu.startsById.get(id) : null;
  if (!entry) {
    const valid = menu.starts.map((s) => s.id).join(", ") || "无";
    return { ok: false, reason: `启动候选编号 ${String(raw.candidate ?? "（空）")} 不在引擎候选内（可用编号：${valid}）` };
  }
  return { ok: true, ignored, step: { action, entry } };
}

/** 给提示词用的菜单视图：只有编号、形状与理由，模型看不到也不需要参数细节 */
export function renderMenuForPrompt(menu) {
  return {
    exec: menu.actions.map((a) => ({ id: a.id, run: a.shape, why: a.reason, script: a.scriptBody ?? null })),
    start: menu.starts.map((s) => ({ id: s.id, run: s.shape, why: `引擎已登记的启动候选（${s.source}）` })),
    note: "exec/start 只能报编号；read/list 只能报项目根内的相对路径且不含 .env、node_modules、.git、密钥文件；认为无法继续就报 giveup。",
  };
}
