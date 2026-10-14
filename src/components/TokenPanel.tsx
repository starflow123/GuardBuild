import type { View } from "../bridge";

const VIA_LABEL: Record<string, string> = {
  "user-selected-project": "用户选择目录（自动）",
  auto: "自动",
  "auto-consent": "测试模式自动同意",
  "user-consent": "用户批准",
  "user-diff-approval": "用户批准 Diff 后签发",
  "user-rollback": "用户触发回滚",
};

function remain(expiresAt: number): string {
  const ms = expiresAt - Date.now();
  if (ms <= 0) return "已过期";
  const min = Math.floor(ms / 60000);
  if (min < 60) return `${min} 分钟后过期`;
  return `${Math.floor(min / 60)} 小时后过期`;
}

export function TokenPanel({ view }: { view: View | null }) {
  const tokens = view?.tokens ?? [];
  const authorized = view?.writebackAuthorized;
  return (
    <div className="panel">
      <div className="panel-title">
        作用域令牌
        <span className="count">{tokens.length}</span>
      </div>
      <div className="panel-body" style={{ padding: "6px 13px" }}>
        {tokens.length === 0 && <div className="small muted" style={{ padding: "8px 0" }}>暂无已签发令牌</div>}
        {tokens.map((t) => (
          <div key={t.id} className="token-row">
            {t.scopes.map((s, i) => (
              <span key={i} className="scope">
                {s}
              </span>
            ))}
            <span className="via">
              <span>{VIA_LABEL[t.via] ?? t.via}</span>
              <span>{remain(t.expiresAt)}</span>
            </span>
          </div>
        ))}
        <div className="token-row">
          <span className="via">
            <span>写回授权</span>
            <span>
              {authorized ? (
                <span style={{ color: "var(--ok)" }}>已批准（与补丁哈希绑定）</span>
              ) : (
                <span className="badge-user-only">仅用户可批准</span>
              )}
            </span>
          </span>
        </div>
      </div>
    </div>
  );
}
