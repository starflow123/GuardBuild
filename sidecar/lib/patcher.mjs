/**
 * 补丁生成器：在隔离的 Git worktree 中生成「最小权限修复补丁」。
 *
 * 安全设计：
 *  1. worktree 由 Host 从 HEAD 创建（--detach），不触碰原工作区未提交改动；
 *  2. 模型/编排层只产出「定向替换意图」（find/replace 锚点），由 Host 在真实字节上执行；
 *     锚点未匹配时 Host 返回 Conflict，补丁生成诚实失败，不猜测内容；
 *  3. 补丁以 git diff 捕获并计算 patch_hash，后续写回与该哈希绑定；
 *  4. LLM 编码代理（可选）同样只产出 file+search+replace 意图，且先经严格校验
 *     （锚点唯一、目标文件受限、改动规模受限），写入后仍须双重验收。
 */
import { relative, sep } from "node:path";
import { RPC_TO_HOST, SEVERITY, shortId } from "../../shared/protocol.mjs";
import { FIX_STRATEGIES, candKey } from "./planner.mjs";
import { crossFilePatchEnabled, makeReadTools, patchEnabled, requestPatchIntent } from "./llm-patcher.mjs";
import { expandWriteSet, inDegree, reviveGraph } from "./depgraph.mjs";

/** 确定性模板策略覆盖的候选（仅 IDOR：有明确的归属校验插入位） */
const TEMPLATE_KINDS = new Set(["idor-suspect"]);
/** LLM 编码代理额外覆盖的候选类别 */
const LLM_KINDS = new Set(["idor-suspect", "no-auth-suspect", "traversal-suspect", "sqli-suspect", "cmdi-suspect"]);

const normRelPath = (v) => String(v ?? "").replace(/\\/g, "/").replace(/^\.\//, "").replace(/\/+/g, "/");

/**
 * 补丁风险画像：人工审查先看「改动范围有多大、动的是不是共享文件」，再看 diff。
 * 角色来自写集（候选文件 / 正向依赖 / 反向引用者 / 新建），入度来自依赖图——
 * 入度越高说明这个文件被越多处 import，改它的影响面越大。
 */
export function buildScope({ crossFile = false, depNodes = null, filePatches = [], changedFiles = [], rejected = [] }) {
  const meta = new Map();
  for (const f of filePatches) {
    const rel = normRelPath(f?.file);
    if (!rel) continue;
    const prev = meta.get(rel);
    if (!prev) {
      meta.set(rel, {
        role: f.role ?? "candidate",
        created: f.created === true,
        crossFileOnly: f.crossFileOnly === true,
      });
    } else {
      if (f.created === true) prev.created = true;
      if (f.role && f.role !== "candidate") prev.role = f.role;
    }
  }
  const delta = new Map();
  // changedFiles 来自 Host 的 git.diff 响应（外部边界）：形状异常时画像不得炸掉补丁链路
  for (const c of Array.isArray(changedFiles) ? changedFiles : []) {
    const rel = normRelPath(c?.path ?? c?.file);
    if (rel) delta.set(rel, { insertions: c.insertions ?? 0, deletions: c.deletions ?? 0 });
  }
  const files = [...new Set([...meta.keys(), ...delta.keys()])].map((rel) => ({
    file: rel,
    role: meta.get(rel)?.role ?? "candidate",
    created: meta.get(rel)?.created === true,
    // 候选文件本身没被改动、修复全在依赖闭包里：画像要说明「漏洞文件为什么没动」
    untouched: meta.get(rel)?.crossFileOnly === true,
    insertions: delta.get(rel)?.insertions ?? 0,
    deletions: delta.get(rel)?.deletions ?? 0,
    inDegree: depNodes ? inDegree(depNodes, rel) : null,
  }));
  const shared = files.filter((f) => (f.inDegree ?? 0) >= 2);
  return {
    crossFile: !!crossFile,
    files,
    candidateFiles: files.filter((f) => f.role === "candidate").map((f) => f.file),
    closureFiles: files.filter((f) => f.role === "forward" || f.role === "reverse").map((f) => f.file),
    newFiles: files.filter((f) => f.created).map((f) => f.file),
    sharedFiles: shared.map((f) => ({ file: f.file, inDegree: f.inDegree })),
    rejectedCount: (rejected ?? []).length,
  };
}

export class PatchError extends Error {
  constructor(message, { code = "patch_failed", hint = null, details = null } = {}) {
    super(message);
    this.code = code;
    this.hint = hint;
    this.details = details;
  }
}

/**
 * 为静态分析得到的候选端点生成修复补丁。
 * 返回 { worktree, patch: {id, hash, diff, files, strategies}, filePatches, skipped, llm }
 */
export async function createPatch(ctx, { feedback = null } = {}) {
  const useLlm = patchEnabled(ctx);
  const allCandidates = ctx.analysis?.candidates ?? [];
  const patchableKinds = useLlm ? LLM_KINDS : TEMPLATE_KINDS;
  const candidates = allCandidates.filter((c) => patchableKinds.has(c.kind));
  if (candidates.length === 0) {
    // 到达此处说明攻击已复现（stageReproduce 已通过），但候选中没有可自动修复的
    // IDOR 端点（如仅无鉴权/注入/穿越证据）——不得退化为「无漏洞」放行
    throw new PatchError("攻击证据已建立，但没有可自动修复的候选端点", {
      code: "no_patchable_candidates",
      hint: useLlm
        ? "确定性模板覆盖「带认证但缺归属校验」的 IDOR；编码代理可尝试注入/穿越/无鉴权类，但候选需定位到源码文件（外部路由线索与 Supabase 数据策略不在代码层修复范围）"
        : "自动修复仅覆盖「带认证但缺归属校验」的 IDOR 场景；SQL/命令注入、SSRF、文件上传、无鉴权与路径穿越类需按证据中的攻击用例人工修复后重跑 gate",
    });
  }

  // 0. 预检：隔离修复依赖 git 仓库与至少一次提交基线
  let repoState = null;
  try {
    repoState = await ctx.rpc.request(
      RPC_TO_HOST.GIT_STATUS,
      { token: ctx.tokens.worktree, dir: ctx.projectRoot },
      { timeoutMs: 15_000 }
    );
  } catch {
    /* 探测失败不阻断（交由 worktree.add 报错兜底） */
  }
  if (repoState && repoState.isRepo === false) {
    throw new PatchError("目标项目不是 Git 仓库，无法创建隔离 worktree", {
      code: "not_a_git_repo",
      hint: "隔离修复依赖 git：请在目标项目根执行 `git init && git add -A && git commit -m baseline` 后重试（未提交的文件不会进入隔离副本）",
      details: { projectRoot: ctx.projectRoot },
    });
  }

  // 1. 创建隔离 worktree
  const name = `fix-${Date.now().toString(36)}`;
  let wtRes;
  try {
    wtRes = await ctx.rpc.request(
      RPC_TO_HOST.GIT_WORKTREE_ADD,
      { token: ctx.tokens.worktree, name },
      { timeoutMs: 90_000 }
    );
  } catch (e) {
    const msg = String(e?.message ?? e);
    if (msg.includes("不是 Git 仓库")) {
      throw new PatchError("目标项目不是 Git 仓库，无法创建隔离 worktree", {
        code: "not_a_git_repo",
        hint: "隔离修复依赖 git：请在目标项目根执行 `git init && git add -A && git commit -m baseline` 后重试",
        details: { projectRoot: ctx.projectRoot, hostError: msg },
      });
    }
    if (msg.includes("尚无提交")) {
      throw new PatchError("Git 仓库尚无提交基线（HEAD 不存在），无法创建隔离 worktree", {
        code: "no_baseline_commit",
        hint: "请在目标项目执行 `git add -A && git commit -m baseline` 建立基线提交后重试",
        details: { projectRoot: ctx.projectRoot, hostError: msg },
      });
    }
    throw e;
  }
  const worktree = wtRes.path;
  // 供终态清理使用：补丁生成中途失败时 view.patch 尚未建立，也不能泄漏 worktree
  ctx._worktree = worktree;
  const wtRoot = worktree.replace(/[\\/]+$/, "");

  // 1.5 链接依赖目录（顶层与一级子目录的 node_modules，如 monorepo 的 backend/、client/；
  //     失败不致命，交由契约 prepare 兜底）
  const rootClean = ctx.projectRoot.replace(/[\\/]+$/, "");
  let nmDirs = [`${rootClean}/node_modules`];
  try {
    const listing = await ctx.rpc.request(
      RPC_TO_HOST.FS_LIST,
      { token: ctx.tokens.project, path: ctx.projectRoot, depth: 2 },
      { timeoutMs: 30_000 }
    );
    // 连接点/symlink 形式的 node_modules 报为 symlink，同样纳入（FS_LINK_DIR 会校验目录有效性）
    const found = (listing.entries ?? []).filter(
      (e) => (e.kind === "dir" || e.kind === "symlink") && e.name === "node_modules"
    );
    if (found.length > 0) nmDirs = found.map((e) => e.path);
  } catch {
    /* 目录列表失败时回退为仅链接顶层 node_modules */
  }
  const linked = [];
  const linkFailures = [];
  for (const srcNm of nmDirs) {
    const rel = relative(rootClean, srcNm).split(sep).join("/");
    if (!rel || rel.startsWith("..")) continue;
    try {
      await ctx.rpc.request(
        RPC_TO_HOST.FS_LINK_DIR,
        { token: ctx.tokens.worktree, readToken: ctx.tokens.project, src: srcNm, dst: `${wtRoot}/${rel}` },
        { timeoutMs: 60_000 }
      );
      linked.push(rel);
    } catch (e) {
      linkFailures.push({ rel, reason: e.message });
    }
  }
  if (linked.length > 0) {
    ctx.emit({
      kind: "patch",
      severity: SEVERITY.INFO,
      message: `已将 ${linked.length} 个依赖目录链接到隔离工作区（${linked.join("、")}），复用依赖安装`,
      data: { linked, failures: linkFailures },
    });
  } else {
    ctx.emit({
      kind: "patch",
      severity: SEVERITY.WARN,
      message: `未能链接依赖目录（${linkFailures.map((f) => f.rel).join("、") || "未发现 node_modules"}），依赖将由 prepare 步骤处理`,
      data: { failures: linkFailures },
    });
  }

  // 2. 按文件分组候选，逐一生成定向替换。
  //    外部线索（OpenAPI / guardbuild.json routes）来源的候选没有代码文件位置，
  //    无法生成定向补丁——证据已在 probe 阶段固化，此处只记录跳过原因。
  const byFile = new Map();
  const externalSkipped = [];
  for (const c of candidates) {
    if (!c.file || c.source === "openapi" || c.source === "routes" || c.source === "llm-scout") {
      externalSkipped.push({
        method: c.method,
        path: c.fullPath ?? c.path,
        source: c.source ?? "unknown",
        reason:
          c.source === "llm-scout"
            ? "候选来自 LLM 接入侦察（仅用于定位动态探测目标），不参与自动改码"
            : "候选来自外部路由线索（OpenAPI/手工声明），无代码文件位置，跳过自动补丁",
      });
      continue;
    }
    const arr = byFile.get(c.file) ?? [];
    arr.push(c);
    byFile.set(c.file, arr);
  }
  if (externalSkipped.length > 0) {
    ctx.emit({
      kind: "patch",
      severity: SEVERITY.WARN,
      message: `${externalSkipped.length} 个候选来自外部/LLM 路由线索，无法生成自动补丁（需人工修复）`,
      data: { skipped: externalSkipped },
    });
  }
  if (byFile.size === 0) {
    throw new PatchError("攻击证据已建立，但候选均无代码位置可定位（全部来自 OpenAPI/手工路由线索）", {
      code: "no_patchable_candidates",
      hint: "自动补丁需要静态分析定位到具体文件行号；请在目标项目里找到对应 handler 手动加归属校验，或提供带代码路径的 routes 线索（LLM 侦察线索只用于定位探测目标，不参与自动改码）",
    });
  }

  const filePatches = [];
  const skipped = [];
  const createdFiles = [];
  // 跨文件写集（S2-full）：图由 analyzer 在已读文件上构建，只有开启该能力时才存在
  const depNodes = useLlm && crossFilePatchEnabled(ctx) ? reviveGraph(ctx.analysis?.depGraph) : null;
  const crossFileEnabled = !!depNodes && depNodes.size > 0;
  const llmStats = {
    enabled: useLlm,
    requestedFiles: [],
    appliedFiles: [],
    appliedOps: 0,
    rejected: [],
    failures: [],
    model: null,
    usage: [],
    toolRounds: 0,
    toolCalls: [],
    crossFile: crossFileEnabled,
    crossFileFiles: [],
    createdFiles,
  };
  // 只读自查工具绑定在隔离 worktree 上：模型能读到的范围永远不包括原工作区
  const llmTools = useLlm ? makeReadTools(ctx, wtRoot) : null;
  const toolRounds = ctx.llmConfig?.patchToolRounds;
  for (const [file, cands] of byFile) {
    const rel = relative(ctx.projectRoot, file).split(sep).join("/");
    const wtPath = `${wtRoot}/${rel}`;
    // 写集：候选文件 + 正向闭包（取数层/helper）+ 反向闭包（挂载守卫的启动文件）
    const writeSet = crossFileEnabled
      ? { enabled: true, ...expandWriteSet({ nodes: depNodes, seeds: [rel], enabled: true }) }
      : null;
    // 归一化到写集内的规范相对路径：不在写集（或越界）一律返回 null，绝不拼成 worktree 路径
    const canonOf = (r) => {
      const norm = normRelPath(r);
      if (!norm || norm.includes("..")) return null;
      if (!writeSet?.rolesLower?.has(norm.toLowerCase())) return null;
      return norm;
    };

    // 未跟踪文件诊断：worktree 从 HEAD 检出，未提交的文件不在其中
    try {
      await ctx.rpc.request(RPC_TO_HOST.FS_STAT, { token: ctx.tokens.worktree, path: wtPath }, { timeoutMs: 15_000 });
    } catch {
      skipped.push({
        file,
        reason: `worktree 中不存在 ${rel}（文件未纳入 git 提交）`,
        hint: "在目标项目执行 git add && git commit 后重新运行",
      });
      ctx.emit({
        kind: "patch",
        severity: SEVERITY.WARN,
        message: `跳过补丁目标 ${rel}：该文件未提交到 git，隔离 worktree（基于 HEAD 检出）中不存在`,
        data: { file: rel },
      });
      continue;
    }

    let read;
    try {
      // redact:false —— 锚点必须取自真实字节（Host 在真实文件上执行替换）；
      // 脱敏会使含敏感字样的锚点失配（anchor_conflict）或把掩码写进补丁
      read = await ctx.rpc.request(
        RPC_TO_HOST.FS_READ,
        { token: ctx.tokens.project, path: file, redact: false },
        { timeoutMs: 30_000 }
      );
    } catch (e) {
      skipped.push({ file, reason: `读取失败: ${e.message}` });
      continue;
    }
    const content = read.content;

    // 1) 确定性模板补丁（仅覆盖有明确归属校验插入位的 IDOR 形态）
    const templateOps = [];
    const used = [];
    const unapplied = [];
    for (const cand of cands) {
      const key = `${cand.method} ${cand.path}`;
      if (!TEMPLATE_KINDS.has(cand.kind)) {
        unapplied.push(cand);
        continue;
      }
      let applied = false;
      let lastErr = null;
      for (const strat of FIX_STRATEGIES) {
        // 风格门控：候选代码形态与策略不匹配时不得强行套用（如把 Express 的 req.user.id
        // 守卫注入 Next.js route handler）。无 style 字段的候选保持既有全试行为。
        if (cand.style && !strat.styles.includes(cand.style)) continue;
        try {
          const candOps = strat.builder(content, cand);
          templateOps.push(...candOps);
          used.push({ candidate: key, candidateKey: candKey(cand), strategy: strat.name });
          applied = true;
          break;
        } catch (e) {
          lastErr = e;
        }
      }
      if (applied) continue;
      unapplied.push(cand);
      skipped.push({ file, candidate: key, reason: lastErr?.message ?? "无匹配策略" });
    }

    const writeSum = { appliedOps: 0, beforeSha256: null, sha256: null, wrote: false };
    const extraWrites = [];
    const flushWrite = async (patchOps, reason) => {
      if (patchOps.length === 0) return;
      let write;
      try {
        write = await ctx.rpc.request(
          RPC_TO_HOST.FS_WRITE,
          { token: ctx.tokens.worktree, path: wtPath, ops: patchOps, reason },
          { timeoutMs: 30_000 }
        );
      } catch (e) {
        throw new PatchError(`锚点替换在隔离副本中执行失败：${e.message}`, {
          code: "anchor_conflict",
          hint: "源文件与提交版本存在差异（可能含未提交改动），锚点无法匹配",
          details: { file, worktreePath: wtPath },
        });
      }
      writeSum.appliedOps += write.appliedOps ?? 0;
      writeSum.beforeSha256 = writeSum.beforeSha256 ?? write.beforeSha256;
      writeSum.sha256 = write.sha256;
      writeSum.wrote = true;
    };

    /**
     * 写集内其它文件的落盘。与候选文件不同：单个附属文件写失败不能拖垮整批补丁
     * （锚点已在真实字节上校验过，此处失败多为权限/IO 问题），记录原因后继续。
     */
    const flushExtra = async (fileRel, patchOps, role, reason) => {
      if (patchOps.length === 0) return;
      try {
        const write = await ctx.rpc.request(
          RPC_TO_HOST.FS_WRITE,
          { token: ctx.tokens.worktree, path: `${wtRoot}/${fileRel}`, ops: patchOps, reason },
          { timeoutMs: 30_000 }
        );
        extraWrites.push({
          file: fileRel,
          role,
          appliedOps: write.appliedOps ?? patchOps.length,
          beforeSha256: write.beforeSha256,
          sha256: write.sha256,
          created: false,
        });
      } catch (e) {
        llmStats.rejected.push({ file: fileRel, candidate: null, reason: `写入隔离副本失败：${e.message}` });
      }
    };

    /** 新建文件：只接受「当前不存在」的目标，且必须使用带 allow_create 的令牌 */
    const flushCreate = async (item, reason) => {
      const fileRel = canonOf(item.file) ?? normRelPath(item.file);
      const path = `${wtRoot}/${fileRel}`;
      try {
        await ctx.rpc.request(RPC_TO_HOST.FS_STAT, { token: ctx.tokens.worktree, path }, { timeoutMs: 15_000 });
        llmStats.rejected.push({ file: fileRel, candidate: null, reason: "新建目标在隔离副本中已存在，拒绝整文件覆盖" });
        return;
      } catch {
        /* 不存在正是新建的前提 */
      }
      if (!ctx.tokens.worktreeCreate) {
        llmStats.rejected.push({ file: fileRel, candidate: null, reason: "未签发 allow_create 作用域，无法新建文件" });
        return;
      }
      try {
        const write = await ctx.rpc.request(
          RPC_TO_HOST.FS_WRITE,
          { token: ctx.tokens.worktreeCreate, path, content: item.content, reason },
          { timeoutMs: 30_000 }
        );
        if (write.created !== true) {
          llmStats.rejected.push({ file: fileRel, candidate: null, reason: "Host 判定该写入不是新建，已丢弃" });
          return;
        }
        extraWrites.push({
          file: fileRel,
          role: "new",
          appliedOps: 1,
          beforeSha256: null,
          sha256: write.sha256,
          created: true,
        });
        createdFiles.push(fileRel);
      } catch (e) {
        llmStats.rejected.push({ file: fileRel, candidate: null, reason: `新建文件写入失败：${e.message}` });
      }
    };

    await flushWrite(templateOps, `修复越权：${cands.map((c) => `${c.method} ${c.path}`).join("、")}`);

    // 2) LLM 编码代理回落：模板覆盖不到的候选。锚点在「隔离副本当前字节」上校验，
    //    既避免与已写入的模板补丁错位，也比工作区字节更贴近 Host 实际修改的对象。
    if (useLlm && unapplied.length > 0 && typeof ctx.llmGetToken === "function") {
      const keyOf = (c) => `${c.method} ${c.fullPath ?? c.path}`.toLowerCase();
      const attempted = unapplied.map((c) => `${c.method} ${c.path}`);
      llmStats.requestedFiles.push({ file: rel, candidates: attempted });

      let wtBytes = null;
      try {
        // redact:false：校验锚点必须用真实字节
        const cur = await ctx.rpc.request(
          RPC_TO_HOST.FS_READ,
          { token: ctx.tokens.worktree, path: wtPath, redact: false },
          { timeoutMs: 30_000 }
        );
        wtBytes = cur.content;
      } catch (e) {
        llmStats.failures.push({ file: rel, reason: `读取隔离副本失败：${e.message}` });
      }

      if (wtBytes != null) {
        const llmRes = await requestPatchIntent(ctx, {
          file,
          rel,
          content: wtBytes,
          candidates: unapplied,
          evidence: ctx.view?.evidence ?? [],
          model: ctx.llmConfig?.model ?? null,
          getToken: ctx.llmGetToken,
          maxFiles: ctx.llmConfig?.patchMaxFiles,
          feedback,
          tools: llmTools,
          maxToolRounds: toolRounds,
          writeSet,
          // 跨文件锚点用隔离副本的真实字节校验；只取写集内、模型实际点名的文件
          fetchContents: async (rels) => {
            const out = new Map();
            for (const r of rels) {
              const canon = canonOf(r);
              if (!canon) continue;
              try {
                const res = await ctx.rpc.request(
                  RPC_TO_HOST.FS_READ,
                  { token: ctx.tokens.worktree, path: `${wtRoot}/${canon}`, redact: false },
                  { timeoutMs: 30_000 }
                );
                out.set(r, res.content);
              } catch {
                /* 读不到即不放进 map，由校验层给出「未取得真实内容」的拒绝原因 */
              }
            }
            return out;
          },
          // 提示词只喂脱敏后的源码，真实锚点校验走上面的 wtBytes
          readRedacted: async () => {
            const r = await ctx.rpc.request(
              RPC_TO_HOST.FS_READ,
              { token: ctx.tokens.worktree, path: wtPath },
              { timeoutMs: 30_000 }
            );
            return r.content;
          },
        });
        if (llmRes.model) llmStats.model = llmRes.model;
        if (llmRes.usage) llmStats.usage.push({ file: rel, ...llmRes.usage });
        for (const r of llmRes.rejected) llmStats.rejected.push({ file: rel, ...r });
        llmStats.toolRounds = Math.max(llmStats.toolRounds, llmRes.toolRounds ?? 0);
        for (const t of llmRes.toolCalls ?? []) llmStats.toolCalls.push({ file: rel, ...t });

        const covered = new Set(llmRes.accepted.map((a) => String(a.candidate ?? "").toLowerCase()));
        const fileOps = Object.entries(llmRes.byFile ?? {});
        const creations = llmRes.creations ?? [];
        const anyProduced = fileOps.length > 0 || creations.length > 0;
        if (anyProduced) {
          const reason = `LLM 编码代理修复：${llmRes.accepted.map((a) => a.candidate ?? "-").join("、")}`;
          let opsApplied = 0;
          for (const [fileRel, list] of fileOps) {
            const canon = fileRel === rel ? rel : (canonOf(fileRel) ?? fileRel);
            opsApplied += list.length;
            if (canon === rel) await flushWrite(list, reason);
            else {
              const role = writeSet?.rolesLower?.get(canon.toLowerCase()) ?? "forward";
              await flushExtra(canon, list, role, `${reason}（跨文件·${role}）`);
              llmStats.crossFileFiles.push({ from: rel, to: canon, role, ops: list.length });
            }
          }
          for (const c of creations) {
            await flushCreate(c, `${reason}（新建守卫文件）`);
          }
          const createdNow = creations.filter((c) =>
            extraWrites.some((w) => w.created && w.file === normRelPath(c.file))
          ).length;
          llmStats.appliedOps += opsApplied + createdNow;
          llmStats.appliedFiles.push({
            file: rel,
            ops: llmRes.ops.length,
            crossFileOps: opsApplied - llmRes.ops.length,
            created: createdNow,
          });
          for (const a of llmRes.accepted) {
            const claimed = cands.find(
              (c) => keyOf(c) === String(a.candidate ?? attempted[0]).toLowerCase()
            );
            used.push({
              candidate: a.candidate ?? attempted[0],
              candidateKey: claimed ? candKey(claimed) : null,
              strategy: "llm-coding-agent",
              reason: a.reason ?? null,
              addedLines: a.addedLines ?? null,
              file: a.file ?? rel,
              role: a.role ?? "candidate",
            });
          }
          ctx.emit({
            kind: "patch",
            severity: SEVERITY.INFO,
            message:
              `LLM 编码代理为 ${rel} 产出 ${opsApplied} 个补丁意图` +
              (creations.length ? `、新建 ${creations.length} 个文件` : "") +
              (opsApplied > llmRes.ops.length ? "（含依赖闭包内其它文件）" : "") +
              "（锚点校验通过，已写入隔离副本）",
            data: {
              file: rel,
              candidates: llmRes.accepted.map((a) => a.candidate),
              reasons: llmRes.accepted.map((a) => a.reason),
              touched: fileOps.map(([f, list]) => ({ file: f, ops: list.length })),
              created: creations.map((c) => c.file),
              rejected: llmRes.rejected.length,
              model: llmRes.model,
            },
          });
        }

        for (const c of unapplied) {
          const key = `${c.method} ${c.path}`;
          if (covered.has(key.toLowerCase()) || covered.has(keyOf(c))) continue;
          const reason =
            llmRes.failure ?? llmRes.rejected[0]?.reason ?? "编码代理未对该端点产出经校验的补丁";
          const existing = skipped.find((s) => s.file === file && s.candidate === key);
          if (existing) existing.llm = reason;
          else skipped.push({ file, candidate: key, reason });
        }

        if (!anyProduced) {
          const reason = llmRes.failure ?? llmRes.rejected[0]?.reason ?? "编码代理未产出可用补丁";
          llmStats.failures.push({ file: rel, reason });
          ctx.emit({
            kind: "patch",
            severity: SEVERITY.WARN,
            message: `LLM 编码代理未产出 ${rel} 的可用补丁：${reason}（这些端点转人工修复）`,
            data: { file: rel, candidates: attempted, rejected: llmRes.rejected },
          });
        }
      }
    }

    if (!writeSum.wrote && extraWrites.length === 0) continue;

    if (writeSum.wrote) {
      filePatches.push({
        file: rel,
        appliedOps: writeSum.appliedOps,
        beforeSha256: writeSum.beforeSha256,
        sha256: writeSum.sha256,
        fixes: used,
      });
    } else {
      // 候选文件本身未被改动、修复全部落在依赖闭包内：仍要保留归因，否则该候选的
      // 验收翻转会被判成「补丁没点名」，报告也看不出修法在哪个文件
      filePatches.push({
        file: rel,
        appliedOps: 0,
        beforeSha256: null,
        sha256: null,
        fixes: used,
        crossFileOnly: true,
      });
    }
    for (const w of extraWrites) {
      filePatches.push({
        file: w.file,
        role: w.role,
        created: w.created,
        appliedOps: w.appliedOps,
        beforeSha256: w.beforeSha256,
        sha256: w.sha256,
        fixes: [],
        fromCandidate: rel,
      });
    }
  }

  if (filePatches.length === 0) {
    // 跳过原因分两类：候选带策略可用却被环境阻断（文件未提交/读取失败）→ 执行问题（exit 2）；
    // 其余（无策略匹配该代码形态）→ 漏洞证据成立但无可自动修复候选（vulnerable_unfixed，exit 1）
    const untracked = skipped.filter((s) => s.reason?.includes("未纳入 git 提交"));
    if (!skipped.some((s) => s.candidate)) {
      throw new PatchError("未能为任何候选生成补丁锚点", {
        code: "no_patch_applied",
        hint:
          untracked.length > 0
            ? `${untracked.length} 个候选文件未提交到 git（worktree 基于 HEAD 检出）；请先 git add/commit 后重试`
            : "锚点定位失败，可查看跳过原因",
        details: { skipped },
      });
    }
    throw new PatchError("攻击证据已建立，但候选端点均无可自动修复的代码形态", {
      code: "no_patchable_candidates",
      hint: useLlm
        ? `确定性模板与 LLM 编码代理（已启用）都未能产出经校验的补丁；编码代理只在锚点唯一、目标为源码文件且改动规模受限时才提交补丁意图，拒绝原因见 details.skipped 与报告中的 llmPatch`
        : "自动修复仅覆盖可识别归属校验位的 IDOR 形态；注入/穿越/SSRF/上传/无鉴权类需对照证据人工修复后重跑 gate（或在 guardbuild.json 开启 llm.enabled/llm.patch 让编码代理尝试）",
      details: { skipped, llmPatch: useLlm ? llmStats : null },
    });
  }

  // 3. 捕获 diff 与哈希。新建文件默认是未跟踪的，git diff 看不见——先按逐条清单
  //    登记 intent-to-add（仅允许发生在隔离 worktree），它们才会进入补丁与回滚
  const diffRes = await ctx.rpc.request(
    RPC_TO_HOST.GIT_DIFF,
    { token: ctx.tokens.worktree, dir: worktree, ...(createdFiles.length ? { intentAdd: [...new Set(createdFiles)] } : {}) },
    { timeoutMs: 30_000 }
  );
  if (!diffRes.diff || !diffRes.diff.trim()) {
    throw new PatchError("补丁生成后 diff 为空，请检查替换是否实际生效", { code: "empty_diff" });
  }

  const strategies = [...new Set(filePatches.flatMap((f) => f.fixes.map((x) => x.strategy)))];
  const usedLlm = strategies.includes("llm-coding-agent");
  const patch = {
    id: shortId("patch"),
    sessionId: ctx.sessionId,
    worktree,
    strategy: strategies.join(",") || "none",
    diff: diffRes.diff,
    files: diffRes.files,
    patchHash: diffRes.patchHash,
    status: "pending_review",
    createdAt: Date.now(),
  };
  ctx.db.insertPatch(patch);

  const lineCount = patch.diff.split("\n").filter((l) => l.startsWith("+") || l.startsWith("-")).length;
  const registered = diffRes.registeredNewFiles ?? [];
  const unregistered = [...new Set(createdFiles)].filter((f) => !registered.includes(f));
  ctx.emit({
    kind: "patch",
    severity: SEVERITY.SUCCESS,
    message:
      `已在隔离 worktree 生成最小补丁（${new Set(filePatches.map((f) => f.file)).size} 个文件 / ${lineCount} 行变更` +
      `${registered.length ? `，含新建 ${registered.length} 个文件` : ""}；策略 ${patch.strategy}）` +
      `${usedLlm ? "，含 LLM 编码代理产出的补丁意图，等待双重验收" : "，等待 Diff 审查与授权"}`,
    data: {
      patchHash: patch.patchHash,
      worktree,
      files: filePatches.map((f) => f.file),
      createdFiles: registered,
      crossFile: llmStats.crossFileFiles,
      skipped,
      strategy: patch.strategy,
      llmApplied: llmStats.appliedOps,
    },
  });
  if (unregistered.length > 0) {
    ctx.emit({
      kind: "patch",
      severity: SEVERITY.WARN,
      message: `${unregistered.length} 个新建文件未能登记进补丁（${unregistered.join("、")}），写回时不会带上它们`,
      data: { unregistered },
    });
  }

  return {
    worktree,
    patch: { id: patch.id, hash: patch.patchHash, diff: patch.diff, files: patch.files, status: patch.status },
    filePatches,
    // 本次在写集内新建的文件（已登记进补丁），报告与 GUI 据此说明「为什么多了个文件」
    createdFiles: registered,
    // 补丁实际点名的候选（candKey 形态），验收归因据此判定「这条候选的翻转算不算补丁带来的」
    claimedKeys: [
      ...new Set(filePatches.flatMap((f) => f.fixes.map((x) => x.candidateKey).filter(Boolean))),
    ],
    skipped,
    usedLlm,
    llm: llmStats,
    scope: buildScope({
      crossFile: crossFileEnabled,
      depNodes,
      filePatches,
      changedFiles: patch.files,
      rejected: llmStats.rejected,
    }),
  };
}

/** 写回工作区（需 Host 签发的 workspace.write 令牌，且与 patchHash 绑定） */
export async function writebackPatch(ctx, { token, patchHash, worktree, diff }) {
  const res = await ctx.rpc.request(
    RPC_TO_HOST.GIT_WRITEBACK,
    { token, worktree, patch: diff, patchHash },
    { timeoutMs: 60_000 }
  );
  ctx.db.updatePatchStatus(ctx.sessionId, patchHash, "written_back");
  ctx.db.insertApproval({
    id: shortId("ap"),
    sessionId: ctx.sessionId,
    action: "workspace.write",
    subject: worktree,
    patchHash,
    approvedAt: Date.now(),
    via: "user-diff-approval",
  });
  return res;
}

/** 回滚（需 Host 签发的 workspace.rollback 令牌，且与 backupId 绑定） */
export async function rollbackWorkspace(ctx, { token, backupId }) {
  const res = await ctx.rpc.request(RPC_TO_HOST.GIT_ROLLBACK, { token, backupId }, { timeoutMs: 60_000 });
  ctx.db.insertApproval({
    id: shortId("ap"),
    sessionId: ctx.sessionId,
    action: "workspace.rollback",
    subject: backupId,
    patchHash: null,
    approvedAt: Date.now(),
    via: "user-rollback",
  });
  const patch = ctx.view?.patch;
  if (patch?.hash) ctx.db.updatePatchStatus(ctx.sessionId, patch.hash, "rolled_back");
  return res;
}
