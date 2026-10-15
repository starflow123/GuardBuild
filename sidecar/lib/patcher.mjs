/**
 * 补丁生成器：在隔离的 Git worktree 中生成「最小权限修复补丁」。
 *
 * 安全设计：
 *  1. worktree 由 Host 从 HEAD 创建（--detach），不触碰原工作区未提交改动；
 *  2. 模型/编排层只产出「定向替换意图」（find/replace 锚点），由 Host 在真实字节上执行；
 *     锚点未匹配时 Host 返回 Conflict，补丁生成诚实失败，不猜测内容；
 *  3. 补丁以 git diff 捕获并计算 patch_hash，后续写回与该哈希绑定。
 */
import { relative, sep } from "node:path";
import { RPC_TO_HOST, SEVERITY, shortId } from "../../shared/protocol.mjs";
import { FIX_STRATEGIES } from "./planner.mjs";

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
 * 返回 { worktree, patch: {id, hash, diff, files, strategies}, filePatches, skipped }
 */
export async function createPatch(ctx) {
  const candidates = (ctx.analysis?.candidates ?? []).filter((c) => c.kind === "idor-suspect");
  if (candidates.length === 0) {
    // 到达此处说明攻击已复现（stageReproduce 已通过），但候选中没有可自动修复的
    // IDOR 端点（如仅无鉴权/纵向越权证据）——不得退化为「无漏洞」放行
    throw new PatchError("攻击证据已建立，但没有可自动修复的对象级越权候选端点", {
      code: "no_patchable_candidates",
      hint: "自动修复仅覆盖「带认证但缺归属校验」的 IDOR 场景；请对照证据中的攻击用例人工修复该端点后重跑 gate",
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
  const wtRoot = worktree.replace(/[\\/]+$/, "");

  // 1.5 链接依赖目录（避免在 worktree 中重复安装；失败不致命，交由契约 prepare 兜底）
  try {
    const srcNm = `${ctx.projectRoot.replace(/[\\/]+$/, "")}/node_modules`;
    await ctx.rpc.request(RPC_TO_HOST.FS_STAT, { token: ctx.tokens.project, path: srcNm }, { timeoutMs: 15_000 });
    await ctx.rpc.request(
      RPC_TO_HOST.FS_LINK_DIR,
      { token: ctx.tokens.worktree, readToken: ctx.tokens.project, src: srcNm, dst: `${wtRoot}/node_modules` },
      { timeoutMs: 60_000 }
    );
    ctx.emit({
      kind: "patch",
      severity: SEVERITY.INFO,
      message: "已将 node_modules 链接到隔离工作区（复用依赖安装）",
      data: { src: srcNm, dst: `${wtRoot}/node_modules` },
    });
  } catch (e) {
    ctx.emit({
      kind: "patch",
      severity: SEVERITY.WARN,
      message: `未能链接 node_modules（${e.message}），依赖将由 prepare 步骤处理`,
      data: {},
    });
  }

  // 2. 按文件分组候选，逐一生成定向替换
  const byFile = new Map();
  for (const c of candidates) {
    const arr = byFile.get(c.file) ?? [];
    arr.push(c);
    byFile.set(c.file, arr);
  }

  const filePatches = [];
  const skipped = [];
  for (const [file, cands] of byFile) {
    const rel = relative(ctx.projectRoot, file).split(sep).join("/");
    const wtPath = `${wtRoot}/${rel}`;

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

    const ops = [];
    const used = [];
    for (const cand of cands) {
      let applied = false;
      let lastErr = null;
      for (const strat of FIX_STRATEGIES) {
        try {
          const candOps = strat.builder(content, cand);
          ops.push(...candOps);
          used.push({ candidate: `${cand.method} ${cand.path}`, strategy: strat.name });
          applied = true;
          break;
        } catch (e) {
          lastErr = e;
        }
      }
      if (!applied) {
        skipped.push({ file, candidate: `${cand.method} ${cand.path}`, reason: lastErr?.message ?? "无匹配策略" });
      }
    }
    if (ops.length === 0) continue;

    let write;
    try {
      write = await ctx.rpc.request(
        RPC_TO_HOST.FS_WRITE,
        {
          token: ctx.tokens.worktree,
          path: wtPath,
          ops,
          reason: `修复对象级越权：${cands.map((c) => `${c.method} ${c.path}`).join("、")}`,
        },
        { timeoutMs: 30_000 }
      );
    } catch (e) {
      throw new PatchError(`锚点替换在隔离副本中执行失败：${e.message}`, {
        code: "anchor_conflict",
        hint: "源文件与提交版本存在差异（可能含未提交改动），锚点无法匹配",
        details: { file, worktreePath: wtPath },
      });
    }
    filePatches.push({
      file: rel,
      appliedOps: write.appliedOps,
      beforeSha256: write.beforeSha256,
      sha256: write.sha256,
      fixes: used,
    });
  }

  if (filePatches.length === 0) {
    const untracked = skipped.filter((s) => s.reason?.includes("未纳入 git 提交"));
    throw new PatchError("未能为任何候选生成补丁锚点", {
      code: "no_patch_applied",
      hint:
        untracked.length > 0
          ? `${untracked.length} 个候选文件未提交到 git（worktree 基于 HEAD 检出）；请先 git add/commit 后重试`
          : "锚点定位失败，可查看跳过原因",
      details: { skipped },
    });
  }

  // 3. 捕获 diff 与哈希
  const diffRes = await ctx.rpc.request(
    RPC_TO_HOST.GIT_DIFF,
    { token: ctx.tokens.worktree, dir: worktree },
    { timeoutMs: 30_000 }
  );
  if (!diffRes.diff || !diffRes.diff.trim()) {
    throw new PatchError("补丁生成后 diff 为空，请检查替换是否实际生效", { code: "empty_diff" });
  }

  const patch = {
    id: shortId("patch"),
    sessionId: ctx.sessionId,
    worktree,
    strategy: filePatches.flatMap((f) => f.fixes.map((x) => x.strategy)).join(",") || "none",
    diff: diffRes.diff,
    files: diffRes.files,
    patchHash: diffRes.patchHash,
    status: "pending_review",
    createdAt: Date.now(),
  };
  ctx.db.insertPatch(patch);

  const lineCount = patch.diff.split("\n").filter((l) => l.startsWith("+") || l.startsWith("-")).length;
  ctx.emit({
    kind: "patch",
    severity: SEVERITY.SUCCESS,
    message: `已在隔离 worktree 生成最小补丁（${filePatches.length} 个文件 / ${lineCount} 行变更），等待 Diff 审查与授权`,
    data: {
      patchHash: patch.patchHash,
      worktree,
      files: filePatches.map((f) => f.file),
      skipped,
    },
  });

  return {
    worktree,
    patch: { id: patch.id, hash: patch.patchHash, diff: patch.diff, files: patch.files, status: patch.status },
    filePatches,
    skipped,
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
