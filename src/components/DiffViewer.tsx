import type { ViewPatch, ViewPatchScope } from "../bridge";

const ROLE_LABEL: Record<string, string> = {
  candidate: "漏洞文件",
  forward: "正向依赖",
  reverse: "反向引用",
  new: "新建",
};

function describeFile(f: NonNullable<ViewPatchScope["files"]>[number]): string {
  const bits = [ROLE_LABEL[f.role ?? "candidate"] ?? f.role];
  if (f.created) bits.push("新建");
  if (f.untouched) bits.push("本次未改动");
  if (f.insertions || f.deletions) bits.push(`+${f.insertions ?? 0}/-${f.deletions ?? 0}`);
  if (typeof f.inDegree === "number" && f.inDegree > 0) bits.push(`被 ${f.inDegree} 处引用`);
  return `${f.file}（${bits.filter(Boolean).join("·")}）`;
}

function PatchScopePanel({ scope }: { scope: ViewPatchScope }) {
  const files = scope.files ?? [];
  if (files.length === 0) return null;
  return (
    <div className="patch-meta" style={{ borderBottom: "1px solid var(--line-soft)" }}>
      <span className="muted small">
        改动范围：{files.map(describeFile).join("；")}
        {scope.crossFile
          ? "——跨文件写权限由 llm.patchCrossFile 开启，写入严格限于候选的依赖闭包写集与已扫描源码目录"
          : null}
      </span>
      {scope.sharedFiles?.length ? (
        <span className="muted small" style={{ display: "block" }}>
          共享文件影响面：{scope.sharedFiles.map((s) => `${s.file} 被 ${s.inDegree ?? "?"} 处 import`).join("；")}
          （入度越高越要确认其它调用方不受影响）
        </span>
      ) : null}
      {scope.rejectedCount ? (
        <span className="muted small" style={{ display: "block" }}>
          另有 {scope.rejectedCount} 条补丁意图在校验层被拒（越界 / 锚点歧义 / 规模超限），未写入任何文件
        </span>
      ) : null}
    </div>
  );
}

function lineClass(line: string): string {
  if (line.startsWith("+++") || line.startsWith("---") || line.startsWith("diff --git") || line.startsWith("index "))
    return "meta";
  if (line.startsWith("@@")) return "hunk";
  if (line.startsWith("+")) return "add";
  if (line.startsWith("-")) return "del";
  return "";
}

export function DiffViewer({
  patch,
  canApprove,
  onApprove,
}: {
  patch: ViewPatch | null;
  canApprove: boolean;
  onApprove: () => void;
}) {
  if (!patch) {
    return <div className="empty">尚未生成补丁。修复阶段会在隔离 Git worktree 中生成最小权限补丁并展示 Diff。</div>;
  }
  const lines = patch.diff.split("\n");
  return (
    <div className="panel" style={{ minHeight: 0, flex: 1 }}>
      <div className="patch-meta">
        <span>
          补丁哈希 <b className="mono">{patch.hash.slice(0, 16)}…</b>
        </span>
        <span>
          变更 <b>{patch.lineCount}</b> 行 / <b>{patch.files?.length ?? 0}</b> 个文件
        </span>
        <span>
          隔离目录 <b className="mono">{patch.worktree}</b>
        </span>
        <span>
          状态{" "}
          <b>
            {patch.status === "pending_review"
              ? "待审查"
              : patch.status === "written_back"
                ? "已写回"
                : patch.status === "rolled_back"
                  ? "已回滚"
                  : patch.status}
          </b>
        </span>
        <span className="grow" />
        {canApprove && (
          <button className="btn primary" onClick={onApprove}>
            批准 Diff · 启动隔离验收
          </button>
        )}
      </div>
      {patch.fixes && patch.fixes.length > 0 && (
        <div className="patch-meta" style={{ borderBottom: "1px solid var(--line-soft)" }}>
          <span className="muted small">
            修复策略：{patch.fixes.map((f) => `${f.file}（${f.fixes.map((x) => x.strategy).join("/")}，${f.appliedOps} 处替换）`).join("；")}
          </span>
        </div>
      )}
      {patch.scope ? <PatchScopePanel scope={patch.scope} /> : null}
      {patch.llm?.enabled && (
        <div className="patch-meta" style={{ borderBottom: "1px solid var(--line-soft)" }}>
          <span className="muted small">
            LLM 编码代理（{patch.llm.model ?? "未知模型"}）：请求 {patch.llm.requestedFiles?.length ?? 0} 个文件 · 采纳
            {patch.llm.appliedOps ?? 0} 处补丁意图 · 校验拒绝 {patch.llm.rejected?.length ?? 0} 条
            {patch.autoVerify ? " · 已自动执行双重验收，通过后再由您审查写回" : ""}
            {patch.llm.toolRounds
              ? ` · 只读自查 ${patch.llm.toolRounds} 轮（读取 worktree 内源码，写入范围未变）`
              : null}
          </span>
          {(patch.llm.rejected?.length ?? 0) > 0 && (
            <span className="muted small" style={{ display: "block" }}>
              拒绝原因：
              {patch.llm.rejected!.slice(0, 4).map((r) => `${r.file}（${r.reason}）`).join("；")}
            </span>
          )}
        </div>
      )}
      {patch.fixLoop && patch.fixLoop.rounds.length > 0 && (
        <div className="patch-meta" style={{ borderBottom: "1px solid var(--line-soft)" }}>
          <span className="muted small">
            修复循环：{patch.fixLoop.attempts} 轮（重试上限 {patch.fixLoop.maxRounds}）
            {patch.fixLoop.resolvedRound ? `，第 ${patch.fixLoop.resolvedRound} 轮通过` : "，未收敛"}
            {patch.fixLoop.rounds
              .map((r) =>
                r.pass
                  ? ` · 第 ${r.round} 轮通过`
                  : ` · 第 ${r.round} 轮未通过（攻击回归 ${r.verdict?.attackRegressed ?? "?"}、业务回归 ${r.verdict?.businessRegressed ?? "?"}）`
              )
              .join("")}
          </span>
        </div>
      )}
      {patch.skipped && patch.skipped.length > 0 && (
        <div className="patch-meta" style={{ borderBottom: "1px solid var(--line-soft)" }}>
          <span className="small" style={{ color: "#f7dc9b" }}>
            跳过：{patch.skipped.map((s) => `${s.candidate ?? s.file}（${s.reason}）`).join("；")}
          </span>
        </div>
      )}
      <div className="diff" style={{ flex: 1 }}>
        {lines.map((l, i) => (
          <div key={i} className={`diff-line ${lineClass(l)}`}>
            {l || " "}
          </div>
        ))}
      </div>
    </div>
  );
}
