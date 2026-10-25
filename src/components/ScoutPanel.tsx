import type { View } from "../bridge";

function cacheLabel(llm: NonNullable<View["llm"]>): string {
  if (!llm.cached) return "本次调用";
  const source = llm.cacheSource === "disk" ? "磁盘缓存" : "内存缓存";
  if (!llm.cachedAt) return source;
  return `${source} · ${new Date(llm.cachedAt).toLocaleString()}`;
}

const ROUTE_DROP_TEXT: Record<string, string> = {
  not_found: "目标上没有这条路由",
  method_not_allowed: "方法不被允许",
  no_probe_id: "没有可填充的真实资源 id，无法验证",
  request_failed: "复核请求失败",
  budget: "复核请求预算用尽",
};

export function ScoutPanel({ view }: { view: View | null }) {
  const llm = view?.llm;
  if (!llm?.used) return null;
  const applied = llm.applied ?? { start: false, login: false, routes: 0 };
  const verified = llm.verified ?? { start: false, login: false };
  const warnings = llm.warnings ?? [];
  const attempts = llm.startAttempts ?? [];
  const rv = llm.routeVerification ?? null;
  const dropped = rv?.dropped ?? [];
  const okAttempt = attempts.find((a) => a.ok);
  const failed = attempts.filter((a) => !a.ok && !a.skipped).length;
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
            {okAttempt?.index != null && okAttempt.index > 1
              ? ` · 第 ${okAttempt.index}/${okAttempt.total ?? attempts.length} 个候选可用`
              : null}
            {!verified.start && failed > 0 ? ` · ${failed} 个候选启动失败` : null}
          </span>
          <span className="k">登录</span>
          <span className="v">
            {applied.login ? "已应用" : "未应用"} · {verified.login ? "实际登录已验证" : "未验证"}
          </span>
          <span className="k">路由</span>
          <span className="v">
            {llm.routes ?? 0} 条（仅用于定位探测，不自动改码）
            {rv
              ? ` · 实测送检 ${rv.checked}，命中 ${rv.kept}，丢弃 ${dropped.length}（复核请求 ${rv.requestsUsed ?? 0} 个）`
              : " · 尚未运行期实测"}
          </span>
          <span className="k">来源</span>
          <span className="v">{cacheLabel(llm)}</span>
          {llm.usage?.total_tokens != null && (
            <>
              <span className="k">Token</span>
              <span className="v">{llm.usage.total_tokens}</span>
            </>
          )}
        </div>
        {attempts.length > 1 && (
          <div className="scout-warn">
            {attempts.map((a) => (
              <div key={`${a.index}-${a.cmd}-${(a.args ?? []).join(" ")}`}>
                · 启动候选 {a.index}/{a.total} {a.cmd} {(a.args ?? []).join(" ")}：
                {a.skipped ? "跳过（预算不足）" : a.ok ? "已就绪" : `失败${a.diagnosisCode ? `（${a.diagnosisCode}）` : ""}`}
              </div>
            ))}
          </div>
        )}
        {rv && (
          <div className="scout-warn">
            {(rv.detail ?? []).map((d) => (
              <div key={d.key}>
                · {d.method ?? "GET"} {d.declaredPath ?? d.key}：实测 {d.status ?? "—"}
                {d.auth === "open"
                  ? " · 匿名即可取数（无鉴权确认）"
                  : d.auth === "protected"
                    ? " · 匿名被拒（需登录确认）"
                    : " · 鉴权未定性"}
                {d.ownerFilter === false
                  ? " · 两身份列表一致（未按归属过滤）"
                  : d.ownerFilter === true
                    ? " · 两身份列表互斥（归属过滤生效）"
                    : null}
              </div>
            ))}
            {dropped.map((d) => (
              <div key={d.key}>
                · {d.key}：已丢弃 —— {ROUTE_DROP_TEXT[d.reason ?? ""] ?? d.reason ?? "实测未通过"}
              </div>
            ))}
          </div>
        )}
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
