import type { BootstrapView, View } from "../bridge";

const OUTCOME_LABEL: Record<string, string> = {
  started: "已拉起（实跑就绪）",
  budget_exhausted: "预算用尽，仍未就绪",
  gave_up: "代理主动收手",
  llm_unavailable: "LLM 不可用",
  agent_error: "代理执行出错",
  not_started: "未拉起",
};

export function BootstrapPanel({ view }: { view: View | null }) {
  const b: BootstrapView | null | undefined = view?.bootstrap;
  if (!b) return null;
  const actions = b.actions ?? [];
  const started = b.outcome === "started";

  return (
    <div className="panel">
      <div className="panel-title">
        启动代理
        <span className="count">{OUTCOME_LABEL[b.outcome ?? ""] ?? b.outcome ?? "—"}</span>
      </div>
      <div className="panel-body" style={{ padding: "8px 13px" }}>
        <div className="scout-kv">
          <span className="k">触发</span>
          <span className="v">{b.reason ?? "—"}</span>
          <span className="k">模型</span>
          <span className="v">{b.model ?? "未知"}</span>
          <span className="k">步数</span>
          <span className="v">
            {b.stepsUsed ?? 0}/{b.maxSteps ?? "—"}
            {b.rejected ? ` · ${b.rejected} 次选择被拒` : ""}
          </span>
          <span className="k">动作菜单</span>
          <span className="v">
            安装/构建 {b.menuSize ?? 0} 条 · 启动候选 {b.startCandidateSize ?? 0} 条
          </span>
          <span className="k">预算</span>
          <span className="v">
            {b.durationMs != null ? `已用 ${Math.round(b.durationMs / 1000)}s` : "—"}
            {b.remainingMs != null ? ` · 剩 ${Math.round(b.remainingMs / 1000)}s` : ""}
          </span>
          {b.url && (
            <>
              <span className="k">就绪地址</span>
              <span className="v">{b.url}</span>
            </>
          )}
          {b.start?.cmd && (
            <>
              <span className="k">生效契约</span>
              <span className="v">
                {b.start.cmd} {(b.start.args ?? []).join(" ")}
              </span>
            </>
          )}
        </div>
        {actions.length > 0 && (
          <div className="scout-warn">
            {actions.map((a, i) => (
              <div key={`${a.step}-${a.action}-${i}`}>
                · 第 {a.step ?? "?"} 步 {a.action} {a.subject ?? ""}：{a.ok ? "成功" : "未成功"}
                {a.exitCode != null ? `（退出码 ${a.exitCode}）` : ""}
                {a.note ? ` — ${a.note}` : ""}
              </div>
            ))}
          </div>
        )}
        {b.budgetStop && <div className="scout-warn">· 预算停止：{b.budgetStop}</div>}
        {b.error && <div className="scout-warn">· 代理错误：{b.error}</div>}
        <div className="muted small" style={{ marginTop: 6 }}>
          {started
            ? "动作全部来自引擎生成的菜单（模型只报编号，命令行由引擎按仓库清单拼装）；「已拉起」以真实就绪判定为准，不是模型自评。"
            : "代理未把项目拉起来：已回落到确定性启动契约；本环节只处理接入障碍，不参与漏洞判定与修复。"}
        </div>
      </div>
    </div>
  );
}
