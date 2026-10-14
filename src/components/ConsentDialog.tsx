import type { ConsentRequest } from "../../shared/protocol";

const SCOPE_DESC: Record<string, string> = {
  "project.read": "读取所选项目目录（只读，敏感信息自动脱敏）",
  "worktree.write": "在隔离的 Git worktree 中生成修复补丁",
  "proc.spawn": "启动目标项目进程与 Node 运行时（仅限项目目录内）",
  "net.probe": "向本机回环地址（127.0.0.1）发送诊断探测请求",
  "workspace.write": "将批准的补丁写回原工作区",
  "workspace.rollback": "回滚写回操作，恢复原工作区文件",
};

export function ConsentDialog({
  consent,
  onResolve,
}: {
  consent: ConsentRequest | null;
  onResolve: (approved: boolean) => void;
}) {
  if (!consent) return null;
  const kind = consent.scope?.kind ?? "unknown";
  return (
    <div className="overlay">
      <div className="dialog">
        <div className="dialog-head">
          <span style={{ color: "var(--accent)" }}>⛨</span> 权限申请
        </div>
        <div className="dialog-body">
          <div>
            编排层请求获得作用域授权，授权后由 Rust Host 签发限时令牌：
          </div>
          <div className="scope-line">
            {kind}
            <div className="small muted" style={{ marginTop: 4, fontFamily: "inherit" }}>
              {SCOPE_DESC[kind] ?? ""}
            </div>
          </div>
          <div>
            <span className="muted">申请理由：</span>
            {consent.reason || "（未提供）"}
          </div>
          <div className="small muted">
            令牌只在你批准后签发、限时有效；所有受控操作都会记录在事件流与证据库中。
          </div>
        </div>
        <div className="dialog-foot">
          <button className="btn" onClick={() => onResolve(false)}>
            拒绝
          </button>
          <button className="btn primary" onClick={() => onResolve(true)}>
            批准授权
          </button>
        </div>
      </div>
    </div>
  );
}
