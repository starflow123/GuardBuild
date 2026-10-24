import type { BlackboxView } from "../bridge";

const GRADE_LABEL: Record<string, string> = {
  strong: "决策轨迹",
  "cross-proven": "内容归属",
  "http-only": "仅 HTTP",
};

const PLAN_FALLBACK_LABEL: Record<string, string> = {
  no_unprobed_routes: "没有预算外路由",
  llm_unavailable: "模型不可用",
  planner_error: "调用出错",
  bad_json: "返回不是合法 JSON",
  choice_rejected: "所选编号不在菜单内",
};

export function BlackboxPanel({ blackbox }: { blackbox: BlackboxView }) {
  const findings = blackbox.findings ?? [];
  const unreachable = blackbox.reachable === false;
  const plan = blackbox.attackPlan ?? null;
  const probeCap = blackbox.probeCap ?? plan?.probeCap ?? null;
  const budgetTruncated = !plan && probeCap != null && (blackbox.routeCount ?? 0) > probeCap;
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
          {budgetTruncated && (
            <div style={{ color: "var(--warn)", marginTop: 5 }}>
              路由 {blackbox.routeCount} 条、每类探测预算 {probeCap} 条：预算外的路由本轮未被打。可用
              blackbox.attackPlan=true 或 GUARDBUILD_LLM_ATTACKPLAN=1 让规划代理按线索重排预算（仅交互模式，gate
              不启用）。
            </div>
          )}
          {unreachable && <div style={{ color: "var(--warn)", marginTop: 5 }}>目标不可达，未执行任何攻击探测。</div>}
          <div className="muted" style={{ marginTop: 5 }}>
            黑盒模式只对运行中的目标发起外部 HTTP 请求，不读源码、不启动目标、不生成补丁。
          </div>
        </div>
      </div>

      {plan && (
        <div className="panel" style={{ marginBottom: 10 }}>
          <div className="panel-title">
            攻击规划代理
            <span className="count">只分配探测预算</span>
          </div>
          <div className="panel-body small" style={{ padding: "8px 13px" }}>
            <div className="scout-kv">
              <span className="k">模型</span>
              <span className="v">{plan.model ?? "未调用"}</span>
              <span className="k">调用</span>
              <span className="v">
                {plan.llmCalls} 次 · 每类探测预算 {plan.probeCap ?? probeCap ?? "—"} 条
              </span>
              <span className="k">提进预算</span>
              <span className="v">
                {plan.appliedPicks.length
                  ? plan.appliedPicks.map((p) => `#${p.id} ${p.method} ${p.path}`).join("、")
                  : "无（按引擎原序探测）"}
              </span>
              {plan.ignoredFields.length > 0 && (
                <>
                  <span className="k">丢弃字段</span>
                  <span className="v" style={{ color: "var(--warn)" }}>
                    {plan.ignoredFields.join("、")}（模型只能报编号）
                  </span>
                </>
              )}
            </div>
            {plan.rounds.length > 0 && (
              <div className="scout-warn">
                {plan.rounds.map((r) => (
                  <div key={r.round}>
                    · 第 {r.round} 轮：{r.asked ? "已询问" : "未询问"} · 待排 {r.menuSize} 条（已覆盖{" "}
                    {r.coveredCount}）
                    {r.picks.length ? ` · 选中 ${r.picks.map((p) => `#${p.id} ${p.path}`).join("、")}` : " · 未挑选"}
                    {r.invalid.length ? ` · 非法编号 ${r.invalid.length} 个` : ""}
                    {r.fallback ? ` · 回退：${PLAN_FALLBACK_LABEL[r.fallback] ?? r.fallback}` : ""}
                    {r.rejected ? ` · 拒绝原因：${r.rejected}` : ""}
                  </div>
                ))}
              </div>
            )}
            <div className="muted" style={{ marginTop: 6 }}>
              模型只从路由菜单里挑编号，载荷、请求头与判据全部由引擎生成；模型原文与疑似请求字段（payload/headers/method
              等）不入视图、事件与报告。是否漏洞只由实测证据决定。默认关闭，gate 模式结构性禁用。
            </div>
          </div>
        </div>
      )}

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
