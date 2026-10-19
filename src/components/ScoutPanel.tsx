import type { View } from "../bridge";

function cacheLabel(llm: NonNullable<View["llm"]>): string {
  if (!llm.cached) return "本次调用";
  const source = llm.cacheSource === "disk" ? "磁盘缓存" : "内存缓存";
  if (!llm.cachedAt) return source;
  return `${source} · ${new Date(llm.cachedAt).toLocaleString()}`;
}

export function ScoutPanel({ view }: { view: View | null }) {
  const llm = view?.llm;
  if (!llm?.used) return null;
  const applied = llm.applied ?? { start: false, login: false, routes: 0 };
  const verified = llm.verified ?? { start: false, login: false };
  const warnings = llm.warnings ?? [];
  const verifiedAll = verified.start && verified.login;

  return (
    <div className="panel">
      <div className="panel-title">
        接入侦察
        <span className="count">{verifiedAll ? "已验证" : llm.cached ? "缓存" : "待验证"}</span>
      </div>
      <div className="panel-body" style={{ padding: "8px 13px" }}>
        <div className="scout-kv">
          <span className="k">模型</span>
          <span className="v">{llm.model ?? "未知"}</span>
          <span className="k">启动</span>
          <span className="v">
            {applied.start ? "已应用" : "未应用"} · {verified.start ? "实际启动已验证" : "未验证"}
          </span>
          <span className="k">登录</span>
          <span className="v">
            {applied.login ? "已应用" : "未应用"} · {verified.login ? "实际登录已验证" : "未验证"}
          </span>
          <span className="k">路由</span>
          <span className="v">{llm.routes ?? 0} 条（仅用于探测，不自动改码）</span>
          <span className="k">来源</span>
          <span className="v">{cacheLabel(llm)}</span>
          {llm.usage?.total_tokens != null && (
            <>
              <span className="k">Token</span>
              <span className="v">{llm.usage.total_tokens}</span>
            </>
          )}
        </div>
        {(warnings.length > 0 || llm.rejectedStart) && (
          <div className="scout-warn">
            {llm.rejectedStart && <div>· 启动契约未通过实际验证，已回退到确定性启动方式</div>}
            {warnings.slice(0, 3).map((w, i) => (
              <div key={i}>· {w}</div>
            ))}
            {warnings.length > 3 && <div>· 其余 {warnings.length - 3} 条见事件日志</div>}
          </div>
        )}
      </div>
    </div>
  );
}
