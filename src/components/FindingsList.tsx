import type { FindingItem } from "../bridge";

const RESOURCE_LABEL: Record<string, string> = {
  order: "订单",
  user: "用户",
  account: "账户",
  payment: "支付单",
  invoice: "发票",
  file: "文件",
};

export function FindingsList({ findings }: { findings: FindingItem[] }) {
  if (!findings || findings.length === 0) {
    return <div className="empty">尚未发现候选端点（静态分析完成后显示）</div>;
  }
  return (
    <div>
      {findings.map((f) => (
        <div key={f.id} className="finding-card">
          <div className="head">
            <span className={`ev-method ${f.method === "POST" ? "post" : ""}`}>{f.method}</span>
            <span className="path">{f.path}</span>
            <span className="tag warn">对象级越权候选</span>
            <span className="grow" />
            <span className="tag">{f.liveVerified ? "路由实测已确认" : "待运行期实测"}</span>
            <span className="tag">{RESOURCE_LABEL[f.resource] ?? f.resource}</span>
          </div>
          <div className="row small muted">
            <span className="loc">
              {f.file}:{f.startLine}
            </span>
            {f.sinkCalls?.length > 0 && <span className="mono">sink: {f.sinkCalls.join(", ")}()</span>}
          </div>
          <div className="reason">{f.reason}——将以动态复现证据确认，再由隔离补丁修复。</div>
        </div>
      ))}
    </div>
  );
}
