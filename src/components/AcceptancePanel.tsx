import type { AcceptanceView, EvidenceItem, View } from "../bridge";

const CATEGORY_LABEL: Record<string, string> = { attack: "攻击用例", business: "业务用例" };

function CaseRows({ evidence }: { evidence: EvidenceItem[] }) {
  return (
    <div>
      {evidence.map((e) => {
        const pass = e.category === "attack" ? e.verdict === "blocked" : e.verdict === "passed";
        return (
          <div key={e.id} className="case-row">
            <span className="icon" style={{ color: pass ? "var(--ok)" : "var(--err)" }}>
              {pass ? "✓" : "✗"}
            </span>
            <div>
              <div className="title">
                <span className="muted small">[{CATEGORY_LABEL[e.category] ?? e.category}]</span> {e.name}
              </div>
              <div className="detail">{e.actual}</div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

export function AcceptancePanel({
  view,
  canWriteback,
  onWriteback,
}: {
  view: View | null;
  canWriteback: boolean;
  onWriteback: () => void;
}) {
  const acc: AcceptanceView | null | undefined = view?.acceptance;
  const postEvidence = (view?.evidence ?? []).filter((e) => e.phase === "post" || e.phase === "post_writeback");

  if (!acc) {
    return (
      <div className="empty">
        尚未执行双重验收。
        <br />
        修复验收会同时检查「原攻击被阻断」与「本人/合法管理操作保持可用」。
      </div>
    );
  }

  const recheck = acc.writebackRecheck;
  return (
    <div>
      <div className="accept-grid">
        <div className={`accept-card attack ${acc.attackBlocked >= acc.attackTotal ? "ok" : ""}`}>
          <div className="desc">原攻击被阻断（修复前可利用的攻击用例）</div>
          <div className="num">
            {acc.attackBlocked}
            <span style={{ fontSize: 15, color: "var(--muted)" }}> / {acc.attackTotal}</span>
          </div>
          <div className="desc">越权读取 / 越权取消等攻击请求应被拒绝</div>
        </div>
        <div className="accept-card business">
          <div className="desc">业务功能保持可用（本人对象与合法管理操作）</div>
          <div className="num">
            {acc.businessPassed}
            <span style={{ fontSize: 15, color: "var(--muted)" }}> / {acc.businessTotal}</span>
          </div>
          <div className="desc">防一刀切封禁：归属过滤、管理员通道、状态机规则</div>
        </div>
      </div>

      <div className={`accept-verdict ${acc.pass ? "pass" : "fail"}`}>
        {acc.pass
          ? "双重验收通过：攻击已阻断且业务无回归，可授权写回工作区"
          : "双重验收未通过：存在未阻断攻击或业务回归，禁止写回"}
      </div>

      {recheck && (
        <div className={`accept-verdict ${recheck.pass ? "pass" : "fail"}`} style={{ marginTop: 0 }}>
          写回后复核（实际工作区）：攻击阻断 {recheck.attackBlocked}/{recheck.attackTotal} · 业务保持{" "}
          {recheck.businessPassed}/{recheck.businessTotal}
          {recheck.pass ? "" : " —— 建议回滚"}
        </div>
      )}

      {canWriteback && (
        <div style={{ display: "flex", justifyContent: "center", padding: "4px 0 14px" }}>
          <button className="btn primary" onClick={onWriteback}>
            授权写回工作区（将备份原文件并支持回滚）
          </button>
        </div>
      )}

      <div className="panel" style={{ margin: "0 13px 13px" }}>
        <div className="panel-title">验收用例明细</div>
        {postEvidence.length > 0 ? <CaseRows evidence={postEvidence} /> : <div className="empty">暂无用例记录</div>}
      </div>
    </div>
  );
}
