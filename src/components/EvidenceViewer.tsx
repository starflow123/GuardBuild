import type { EvidenceItem } from "../bridge";

const VERDICT_LABEL: Record<string, string> = {
  vulnerable: "漏洞可利用",
  blocked: "攻击已阻断",
  passed: "业务正常",
  regressed: "出现回归",
  inconclusive: "无法判定",
};

const PHASE_LABEL: Record<string, string> = {
  pre: "修复前 · 漏洞复现",
  post: "修复后 · 隔离实例验收",
  post_writeback: "写回后 · 实际工作区复核",
};

function decisionBadge(decision?: string) {
  const cls = decision === "allow" ? "allow" : decision === "deny" ? "deny" : "no-check";
  return <span className={`decision-badge ${cls}`}>{decision ?? "无记录"}</span>;
}

function EvidenceCard({ e }: { e: EvidenceItem }) {
  return (
    <div className="ev-card">
      <div className="ev-card-head">
        <span className={`ev-method ${e.method === "POST" ? "post" : ""}`}>{e.method}</span>
        <span className="name">{e.name}</span>
        <span className={`verdict ${e.verdict}`}>{VERDICT_LABEL[e.verdict] ?? e.verdict}</span>
      </div>
      <div className="ev-kv">
        <span className="k">请求</span>
        <span className="v mono">
          {e.method} {e.endpoint} <span className="muted">· 身份 {e.identity}</span>
        </span>
        <span className="k">预期</span>
        <span className="v">{e.expectation}</span>
        <span className="k">实际</span>
        <span className="v">{e.actual}</span>
        {e.impact && (
          <>
            <span className="k">影响</span>
            <span className="v" style={{ color: "#ffce8a" }}>
              {e.impact}
            </span>
          </>
        )}
        <span className="k">HTTP</span>
        <span className="v mono">
          {e.response.status} {e.response.statusText ?? ""}
          {e.response.redacted && <span className="tag" style={{ marginLeft: 8 }}>响应已脱敏</span>}
        </span>
      </div>

      <details className="ev-section">
        <summary>▸ 权限判断决策（服务端实际执行的授权检查）</summary>
        <div style={{ padding: "4px 11px 10px" }}>
          {e.decision ? (
            <div className="decision-line">
              {decisionBadge(e.decision.decision)}
              <span className="muted small">routeKey: {e.decision.routeKey}</span>
              {(e.decision.checks ?? []).map((c, i) => (
                <span key={i} className="check-tag">
                  {c}
                </span>
              ))}
              {e.decision.resourceOwner && (
                <span className="muted small">
                  资源归属 {e.decision.resourceOwner} / 请求者 {e.decision.requesterId ?? "-"}
                </span>
              )}
              {e.decision.note && <span className="small muted">{e.decision.note}</span>}
            </div>
          ) : (
            <span className="small muted">该用例未关联到服务端决策记录</span>
          )}
        </div>
      </details>

      <details className="ev-section">
        <summary>▸ 请求（凭证以保险库引用显示，不含明文）</summary>
        <pre className="ev-code">
          {`${e.request.url}\n` +
            Object.entries(e.request.headers ?? {})
              .map(([k, v]) => `${k}: ${v}`)
              .join("\n") +
            (e.request.body ? `\n\n${e.request.body}` : "")}
        </pre>
      </details>

      <details className="ev-section" open={e.verdict === "vulnerable"}>
        <summary>▸ 响应</summary>
        <pre className="ev-code">{e.response.body || "（空响应体）"}</pre>
      </details>
    </div>
  );
}

export function EvidenceViewer({
  evidence,
  filter,
  onFilter,
}: {
  evidence: EvidenceItem[];
  filter: string;
  onFilter: (f: string) => void;
}) {
  const phases = ["pre", "post", "post_writeback"].filter((p) => evidence.some((e) => e.phase === p));
  const shown = filter === "all" ? evidence : evidence.filter((e) => e.phase === filter);

  if (evidence.length === 0) {
    return <div className="empty">尚无证据。动态复现阶段会自动构造「身份 × 对象归属」请求矩阵并落库。</div>;
  }

  return (
    <div>
      <div style={{ display: "flex", gap: 6, marginBottom: 10, flexWrap: "wrap" }}>
        <button className={`btn small ${filter === "all" ? "primary" : ""}`} onClick={() => onFilter("all")}>
          全部（{evidence.length}）
        </button>
        {phases.map((p) => (
          <button key={p} className={`btn small ${filter === p ? "primary" : ""}`} onClick={() => onFilter(p)}>
            {PHASE_LABEL[p] ?? p}（{evidence.filter((e) => e.phase === p).length}）
          </button>
        ))}
      </div>
      {phases
        .filter((p) => filter === "all" || filter === p)
        .map((p) => (
          <div key={p} className="ev-group">
            <div className="ev-group-head">
              <span>{PHASE_LABEL[p] ?? p}</span>
              <span className="muted small">
                {shown.filter((e) => e.phase === p).filter((e) => e.category === "attack").length} 条攻击用例 ·{" "}
                {shown.filter((e) => e.phase === p).filter((e) => e.category === "business").length} 条业务用例
              </span>
            </div>
            {shown.filter((e) => e.phase === p).map((e) => (
              <EvidenceCard key={e.id} e={e} />
            ))}
          </div>
        ))}
    </div>
  );
}
