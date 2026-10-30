/**
 * 「绿灯必须有测量支撑」的结构性判据。
 *
 * 为什么需要：真实项目的结论方向（exit 0/1/2）事先不可预测，所以基准不能靠「期望某个出口」
 * 来防假绿灯——2026-10-30 那轮唯一的 exit 0 恰恰是被双前缀架空后给出的（3 条攻击用例全打
 * /api/api/*，目标自有兜底 404 被记成「攻击被阻断 → 未复现」）。这里判的不是漏洞有没有，
 * 而是这一轮有没有真的打到目标、身份有没有真的建立。
 */

/** 连续重复的路径段（/api/api/x）——挂载前缀被重复拼接的指纹；参数段（:id/{id}）不参与 */
export function doubledSegments(endpoint) {
  const segs = String(endpoint ?? "")
    .split("?")[0]
    .split("#")[0]
    .split("/")
    .filter(Boolean);
  const hits = [];
  for (let i = 1; i < segs.length; i++) {
    if (segs[i] === segs[i - 1] && !/^[:{_]/.test(segs[i])) hits.push(segs[i]);
  }
  return [...new Set(hits)];
}

export function allEvidence(report) {
  const ev = report?.evidence ?? {};
  return [...(ev.pre ?? []), ...(ev.post ?? []), ...(ev.postWriteback ?? [])];
}

/**
 * @param report  report.json 解析结果
 * @param contract 该项目的 guardbuild.json（可为 null）
 * @param minFindings 静态候选下限（真实项目为 0 通常是适配器漏检）
 * @returns 问题清单 [{ rule, text }]，空数组代表结构上站得住
 */
export function auditWhiteboxRun({ report, contract = null, minFindings = 1 }) {
  const issues = [];
  if (!report || typeof report !== "object") {
    return [{ rule: "R0", text: "未产出报告，本轮没有任何可核对的测量结果" }];
  }
  const ev = allEvidence(report);
  const attack = ev.filter((e) => e.category === "attack");
  const exit = report.verdict?.exitCode ?? null;

  if (report.blackbox) {
    issues.push({ rule: "R1", text: "白盒层却产出黑盒报告（没有走 --gate --project 链路）" });
  }
  if (!report.summary?.start) {
    issues.push({ rule: "R1", text: "报告缺 summary.start，本轮没有按启动契约真实拉起目标" });
  }

  const doubled = [...new Set(ev.flatMap((e) => doubledSegments(e.endpoint).map((d) => `${d} @ ${e.endpoint}`)))];
  if (doubled.length) {
    issues.push({ rule: "R2", text: `攻击地址出现连续重复路径段（挂载前缀重复拼接）：${doubled.join("；")}` });
  }

  if (report.error?.code === "git_error") {
    issues.push({ rule: "R4", text: `worktree 创建失败（白盒专属：Windows 长路径 / 仓库状态）：${report.error.message ?? ""}`.slice(0, 300) });
  }

  if (exit === 0) {
    if (attack.length === 0) {
      issues.push({ rule: "R3", text: "exit 0（已测未复现）但没有一条攻击用例被执行——绿灯无测量支撑" });
    } else {
      const missing = attack.filter((e) => e.response?.status === 404 || e.response?.status === 405);
      if (missing.length === attack.length) {
        issues.push({
          rule: "R3",
          text: `exit 0，但 ${attack.length} 条攻击用例全部 ${missing[0].response.status}（目标根本没有这些地址）——「未复现」来自打错地址，不是防护生效`,
        });
      } else if (missing.length > attack.length / 2) {
        issues.push({ rule: "R3", text: `exit 0，但过半攻击用例（${missing.length}/${attack.length}）落到 404/405，绿灯可疑` });
      }
    }
    const configured = (contract?.identities ?? []).length;
    const loggedIn = report.summary?.identities?.loggedIn?.length ?? 0;
    if (configured >= 2 && loggedIn < 2) {
      issues.push({
        rule: "R3",
        text: `exit 0，但契约声明 ${configured} 个身份、本轮只建立 ${loggedIn} 个会话——跨用户越权用例实际是拿匿名身份打的`,
      });
    }
  }

  if ((report.summary?.findingCount ?? 0) < minFindings) {
    issues.push({
      rule: "R5",
      text: `静态候选 ${report.summary?.findingCount ?? 0} 条 < 下限 ${minFindings} 条（错误码 ${report.error?.code ?? "无"}）——真实项目里这通常是适配器漏检，不是项目干净`,
    });
  }

  return issues;
}
