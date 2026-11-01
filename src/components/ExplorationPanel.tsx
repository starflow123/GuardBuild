import type { DualView, ExplorationView, View } from "../bridge";

const OUTCOME_LABEL: Record<string, string> = {
  stopped: "已自行收手",
  budget_exhausted: "预算用尽，超限即停",
  no_targets: "没有可试打的端点，未启动",
  not_run: "未启动",
  llm_unavailable: "LLM 不可用",
  agent_error: "代理执行出错",
};

const BASIS_LABEL: Record<string, string> = {
  generic_shapes: "照通用打法形状（不看靶子正文）",
  target_response: "照靶子真实响应形状",
};

/** 第 14/15 项的双路块：两路各自的事实 + 引擎按事实落的结论（没有「通过」这一格） */
function DualBlock({ d }: { d: DualView }) {
  const cmp = d.comparison ?? null;
  return (
    <div className="scout-warn" style={{ marginBottom: 6 }}>
      <div>
        · 两路提议者：
        {(d.proposals ?? [])
          .map((p) => `${p.id ?? "?"}（${BASIS_LABEL[p.basis ?? ""] ?? p.basis ?? "—"}，实发 ${p.requestsUsed ?? 0} 次，草稿 ${p.draft?.steps ?? 0} 步${p.draft?.tableOk ? "·过表" : p.draft ? "·被拒" : "·无"}）`)
          .join(" ｜ ")}
      </div>
      <div>
        · 独立性对账：菜单{d.menusIdentical ? "一致" : "不一致（差异不可归因）"} · 提示词隔离
        {d.isolation?.ok ? `通过（比对 ${d.isolation.checked ?? 0} 条独有文本行）` : "失败（出现跨路文本）"} · 草稿
        {d.draftsDiffer ? "确有差异" : "无差异（B 是 A 换皮）"} · 合计 {d.totals?.requestsUsed ?? 0} 次实发 /{" "}
        {d.totals?.modelCalls ?? 0} 次模型调用
      </div>
      {(d.isolation?.leaked ?? []).slice(0, 3).map((l, i) => (
        <div key={`leak-${i}`}>
          · 泄露：{l.from} → {l.to}（{l.kind ?? "private_text"}）{l.token ? `：${l.token}` : ""}
        </div>
      ))}
      {(d.diff?.divergences ?? []).slice(0, 3).map((t, i) => (
        <div key={`div-${i}`}>· 结构差异：{t}</div>
      ))}
      <div>
        · 对比结论：<b>{cmp?.decisionLabel ?? "—"}</b>（结论由引擎按事实落笔，对比代理只有降级权，没有「通过」字段写权限）
      </div>
      {(cmp?.reasons ?? []).slice(0, 3).map((r, i) => (
        <div key={`why-${i}`}>· 原因：{r}</div>
      ))}
      {cmp?.model?.ok && (cmp.model.divergences ?? []).length > 0 && <div>· 模型补充的分歧说明：{cmp.model.divergences!.slice(0, 3).join("；")}</div>}
      {cmp?.model?.ok === false && cmp.model?.rejected && <div>· 模型意见被拒：{cmp.model.rejected}</div>}
      <div>· 上面列出的是其中一路的实发序列；每一路各自独立跑，各自留一份草稿（成绩各记各的，不许共享）。</div>
    </div>
  );
}

export function ExplorationPanel({ view }: { view: View | null }) {
  const e: ExplorationView | null | undefined = view?.exploration;
  if (!e) return null;
  const d: DualView | null | undefined = e.dual;
  const trace = e.trace ?? [];
  const budget = e.budget ?? {};
  const draft = e.draft ?? null;

  return (
    <div className="panel">
      <div className="panel-title">
        {d ? "探索区（双路独立提案 → 对比分析）" : "探索区（自主试打）"}
        <span className="count">{OUTCOME_LABEL[e.outcome ?? ""] ?? e.outcome ?? "—"}</span>
      </div>
      <div className="panel-body" style={{ padding: "8px 13px" }}>
        {d && <DualBlock d={d} />}
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
