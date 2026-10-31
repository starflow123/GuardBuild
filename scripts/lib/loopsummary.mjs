/**
 * 闭环产物摘要：把失败账本与「不许回退」的结果渲染成报告段落 + 控制台行。
 * 四个基准脚本共用，避免每套各写一份口径（口径不一致就没法跨套件比对）。
 */
import { CATEGORIES, summarizeLedger } from "../../sidecar/lib/failureledger.mjs";

export function loopSection({ loop }) {
  const lines = [];
  const ledger = loop?.ledger;
  const reg = loop?.regression;
  lines.push("## 失败账本与回退检查");
  lines.push("");
  if (ledger) {
    const sum = summarizeLedger(ledger.entries);
    const cells = Object.entries(CATEGORIES)
      .map(([key, label]) => `${label} ${sum[key].open} 在办/${sum[key].occurrences} 次`)
      .join(" · ");
    lines.push(`- 本轮记账：新增 ${ledger.added} 条 · 复现 ${ledger.updated} 条 · 关闭 ${ledger.resolved} 条 · 在办合计 ${ledger.open}`);
    lines.push(`- 五类现状：${cells}`);
    lines.push(`- 账本：\`${loop.ledgerPath}\`（进仓库，逐条附脱敏后的原始请求与响应摘录）`);
  }
  if (reg) {
    lines.push(`- ${formatGateLine(reg)}`);
    for (const k of (reg.regressions ?? []).slice(0, 20)) lines.push(`  - 回退：${k}`);
  }
  lines.push("");
  lines.push("- 「测不了」与「起不来」不是「没漏洞」：这两类只说明这一轮没证明任何事，不得读成结论安全。");
  lines.push("");
  return lines;
}

export function formatGateLine(reg) {
  if (reg.reason === "refuse_rebaseline") return `绿名单重建被拒：${reg.reason} —— 这一轮并非全绿，先修好再用 --rebaseline`;
  const head = `不许回退：绿名单 ${reg.baselineKeys} 键（上一份 ${reg.previousKeys ?? 0}），回退 ${reg.regressions.length} 条`;
  if (reg.regressions.length) return `${head} → 整轮否决（不看平均）`;
  const up = reg.improvements?.length ? `，新覆盖 ${reg.improvements.length} 条` : "";
  return `${head}${up}`;
}

export function consoleLoopLines(loop) {
  const out = [];
  if (loop?.ledger) {
    out.push(`[LOOP] 失败账本：新增 ${loop.ledger.added} · 复现 ${loop.ledger.updated} · 关闭 ${loop.ledger.resolved} · 在办 ${loop.ledger.open}`);
  }
  if (loop?.regression) out.push(`[LOOP] ${formatGateLine(loop.regression)}`);
  return out;
}
