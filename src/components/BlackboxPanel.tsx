import type { BlackboxView } from "../bridge";

const GRADE_LABEL: Record<string, string> = {
  strong: "决策轨迹",
  "cross-proven": "内容归属",
  "http-only": "仅 HTTP",
};

export function BlackboxPanel({ blackbox }: { blackbox: BlackboxView }) {
  const findings = blackbox.findings ?? [];
  const unreachable = blackbox.reachable === false;
  return (
    <div>
      <div className="panel" style={{ marginBottom: 10 }}>
        <div className="panel-title">
          黑盒扫描概况
          <span className="count">
            {unreachable ? "不可达" : blackbox.outcome === "vulnerable_unfixed" ? "发现漏洞" : "无漏洞证据"}
          </span>
        </div>
        <div className="panel-body small" style={{ padding: "8px 13px" }}>
          <div className="mono">{blackbox.url}</div>
          <div className="muted">
            路由 {blackbox.routeCount ?? 0} 条
            {blackbox.openapiFound ? `（含 OpenAPI 模板 ${blackbox.openapiRouteCount ?? 0} 条）` : "（目录探测）"}
            {" · "}证据 {blackbox.evidenceCount ?? 0} 条
            {" · "}登录{" "}
            {blackbox.login?.ok
              ? `成功（${blackbox.login.path}；${(blackbox.login.identities ?? []).map((i) => i.name).join("、")}）`
              : "失败或未配置"}
            {" · "}写操作探测{" "}
            {blackbox.allowMutation ? (blackbox.allowDestructive ? "已开启（含 DELETE）" : "已开启（不含 DELETE）") : "关闭"}
          </div>
          {blackbox.coverage?.length ? (
            <div className="muted" style={{ marginTop: 5 }}>
              本轮攻击面：{blackbox.coverage.join("、")}
            </div>
          ) : null}
          {unreachable && <div style={{ color: "var(--warn)", marginTop: 5 }}>目标不可达，未执行任何攻击探测。</div>}
          <div className="muted" style={{ marginTop: 5 }}>
            黑盒模式只对运行中的目标发起外部 HTTP 请求，不读源码、不启动目标、不生成补丁。
          </div>
        </div>
      </div>

      {findings.length === 0 ? (
        <div className="empty">
          {unreachable ? "目标不可达，无探测结果。" : "本次已探测攻击面未发现可复现漏洞（不代表无漏洞）。"}
        </div>
      ) : (
        findings.map((f, i) => (
          <div key={`${f.path}-${i}`} className="finding-card">
            <div className="head">
              <span className={`ev-method ${f.method === "POST" || f.method === "PUT" ? "post" : ""}`}>{f.method}</span>
              <span className="path">{f.path}</span>
              <span className="tag warn">黑盒可复现</span>
              <span className="grow" />
              <span className="tag">{GRADE_LABEL[f.evidenceGrade] ?? f.evidenceGrade ?? "—"}</span>
            </div>
            <div className="reason">{f.detail}</div>
            {f.curl && (
              <details style={{ marginTop: 6 }}>
                <summary className="small muted">复现命令</summary>
                <pre className="mono small" style={{ whiteSpace: "pre-wrap", margin: "6px 0 0" }}>
                  {f.curl}
                </pre>
              </details>
            )}
          </div>
        ))
      )}
    </div>
  );
}
