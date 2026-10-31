import type { ExplorationView, View } from "../bridge";

const OUTCOME_LABEL: Record<string, string> = {
  stopped: "已自行收手",
  budget_exhausted: "预算用尽，超限即停",
  no_targets: "没有可试打的端点，未启动",
  not_run: "未启动",
  llm_unavailable: "LLM 不可用",
  agent_error: "代理执行出错",
};

export function ExplorationPanel({ view }: { view: View | null }) {
  const e: ExplorationView | null | undefined = view?.exploration;
  if (!e) return null;
  const trace = e.trace ?? [];
  const budget = e.budget ?? {};
  const draft = e.draft ?? null;

  return (
    <div className="panel">
      <div className="panel-title">
        探索区（自主试打）
        <span className="count">{OUTCOME_LABEL[e.outcome ?? ""] ?? e.outcome ?? "—"}</span>
      </div>
      <div className="panel-body" style={{ padding: "8px 13px" }}>
        <div className="scout-kv">
          <span className="k">模型</span>
          <span className="v">{e.model ?? "未知"}</span>
          <span className="k">实发请求</span>
          <span className="v">
            {e.requestsUsed ?? 0}/{budget.maxRequests ?? "—"}
          </span>
          <span className="k">询问轮数</span>
          <span className="v">
            {e.rounds ?? 0}/{budget.maxRounds ?? "—"}
            {e.rejectedChoices?.length ? ` · ${e.rejectedChoices.length} 次选择被拒` : ""}
          </span>
          <span className="k">菜单</span>
          <span className="v">
            动作 {(e.menu?.actions ?? []).length} 项 · 端点 {e.menu?.targets ?? 0} 个 · 身份 {e.menu?.roles ?? 0} 个 · 对象{" "}
            {e.menu?.resources ?? 0} 个
          </span>
          <span className="k">用时</span>
          <span className="v">{e.durationMs != null ? `${Math.round(e.durationMs / 1000)}s` : "—"}</span>
        </div>
        {trace.length > 0 && (
          <div className="scout-warn">
            {trace.map((t, i) => (
              <div key={`${t.seq ?? i}`}>
                · 第 {t.seq ?? i + 1} 次 {t.action} {t.role ? `（${t.role}）` : ""} {t.method ?? ""} {t.path ?? ""}：
                {t.ok ? `状态码 ${t.status ?? "—"}，回读 ${t.bytes ?? 0} 字节` : `未送达（${t.error ?? "无响应"}）`}
              </div>
            ))}
          </div>
        )}
        {e.ignoredFields && e.ignoredFields.length > 0 && (
          <div className="scout-warn">· 模型夹带的表外字段已丢弃，只按编号执行：{e.ignoredFields.join("、")}</div>
        )}
        {(e.rejectedChoices ?? []).map((r, i) => (
          <div className="scout-warn" key={`rej-${r.round}-${i}`}>
            · 第 {r.round ?? "?"} 轮拒收：{r.why ?? ""}
          </div>
        ))}
        {e.budgetStop && <div className="scout-warn">· 超限即停：{e.budgetStop}</div>}
        {e.error && <div className="scout-warn">· 代理错误：{e.error}</div>}
        {draft && (
          <div className="scout-kv" style={{ marginTop: 6 }}>
            <span className="k">配方草稿</span>
            <span className="v">
              族名 {draft.family ?? "—"}（{draft.familyDeclared ? "模型声明" : "引擎占位"}）· {draft.steps ?? 0} 步 ·{" "}
              {draft.tableOk ? "已过动作表校验" : "被动作表拒收"} · 判据 {draft.verdictRule ?? "—"}（引擎写死）
            </span>
          </div>
        )}
        <div className="muted small" style={{ marginTop: 6 }}>
          {draft
            ? "草稿未注册、未进判定链：过表校验只代表填表合法，打得中要判卷器拿考卷验（第 6 项）。状态码来自真实响应，不是模型自述。"
            : "探索流量不进证据库、不参与判卷；这一路只回答「怎么打」，产出的是配方草稿。"}
          {e.artifact ? ` 草稿位置：${e.artifact}` : ""}
        </div>
      </div>
    </div>
  );
}
