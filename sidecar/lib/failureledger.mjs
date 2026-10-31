/**
 * 失败账本：把一轮基准里「不符合标注」的结果按五类归档，累积进仓库，供复盘与调优使用。
 *
 * 为什么需要：此前每条失败只活在 .benchmark 目录下的 benchmark-report.md（不进仓库、下一轮被覆盖），
 * 「这一步为什么没打中」每次都要人重看日志。账本把它变成可查询的历史数据。
 *
 * 两条设计约束：
 * 1. 每条记录附原始请求与响应摘录（脱敏后）——「引擎错了」还是「标注本身错了」要能被下游自己判，
 *    而不是只留一个红叉，让人或模型照着一个可能写错的答案去学。
 * 2. 凭据一律不落账本：账本是要进 git 的新渠道，摘录先过 redactSecrets。
 */
import fs from "node:fs";

export const LEDGER_VERSION = "gb-failure-ledger-1";

/** 五类失败：判据见 classifyRun，不许随意增类（下游按类别统计会漂移） */
export const CATEGORIES = {
  missed: "打不中",
  false_positive: "误报",
  not_ready: "起不来",
  inconclusive: "测不了",
  broken_run: "超时崩溃",
};

/** 这一轮压根没打到目标：启动、端口、容器、目标不可达 */
export const NOT_READY_CODES = new Set([
  "target_not_ready",
  "target_spawn_failed",
  "prepare_failed",
  "port_alloc_failed",
  "port_parse_failed",
  "blackbox_unreachable",
  "blackbox_bad_url",
  "blackbox_insecure_url",
  "docker_config_invalid",
  "no_worktree_target",
]);

/** 打到了但证明不了任何事：身份/资源/计划缺失，或引擎自己判「测不了」 */
export const INCONCLUSIVE_CODES = new Set([
  "no_endpoints",
  "attack_inconclusive",
  "plan_incomplete",
  "no_list_endpoint",
  "param_binding_unverified",
  "scout_routes_unverified",
  "static_routes_unverified",
  "no_attack_cases",
  "blackbox_login_failed",
  "identity_bootstrap_unavailable",
  "identity_bootstrap_failed",
  "identity_seed_failed",
  "second_identity_unusable",
]);

const INCONCLUSIVE_OUTCOMES = new Set(["inconclusive", "no_endpoints", "attack_inconclusive", "plan_incomplete"]);
const SECRET_KEY_RE =
  /"(password|passwd|token|accessToken|refreshToken|authorization|cookie|secret|api[_-]?key|apikey|service_role_key|anon_key)"\s*:\s*"[^"]*"/gi;

/** 摘掉凭据值，保留字段名——读的人能看出「这里本来有一个凭据」，但拿不到值 */
export function redactSecrets(text) {
  return String(text ?? "")
    .replace(SECRET_KEY_RE, (m, key) => `"${key}":"***redacted***"`)
    .replace(/((?:Set-Cookie|Cookie):\s*)[^;\r\n]*/gi, "$1***redacted***")
    .replace(/Bearer\s+(?![$<[*])[A-Za-z0-9._~+/-]{12,}=*/gi, "Bearer ***redacted***");
}

function truncate(text, max = 600) {
  const s = redactSecrets(text);
  return s.length > max ? `${s.slice(0, max)}…（截断，原文 ${s.length} 字）` : s;
}

export function fingerprint(record) {
  return `${record.suite}/${record.target}/${record.caseKey}/${record.category}`;
}

/** 按用例编号找证据：黑盒在 evidence.blackbox，白盒在 pre/post/postWriteback；同源变体折叠回基名 */
function pickEvidence(report, caseId) {
  const ev = report?.evidence ?? {};
  const pool = [...(ev.blackbox ?? []), ...(ev.pre ?? []), ...(ev.post ?? []), ...(ev.postWriteback ?? [])];
  const exact = pool.find((e) => e.caseId === caseId);
  if (exact) return exact;
  return pool.find((e) => {
    const id = String(e.caseId ?? "");
    const tail = id.slice(caseId.length);
    return id.startsWith(caseId) && /^-(?:obj|enc|chan)\d+$/.test(tail);
  });
}

function evidenceExcerpt(entry) {
  if (!entry) return null;
  const req = entry.request ?? {};
  const res = entry.response ?? {};
  return {
    verdict: entry.verdict ?? null,
    phase: entry.phase ?? null,
    method: entry.method ?? req.method ?? null,
    endpoint: entry.endpoint ?? null,
    identity: entry.identity ?? null,
    evidenceGrade: entry.evidenceGrade ?? null,
    requestUrl: truncate(req.url ?? null, 300),
    responseStatus: res.status ?? null,
    responseBody: truncate(res.body ?? null),
    actual: truncate(entry.actual ?? null, 300),
    expectation: truncate(entry.expectation ?? null, 300),
    decision: truncate(entry.decision ?? null, 300),
    redacted: res.redacted ?? false,
  };
}

/**
 * 把一条靶场结果拆成失败记录。
 * @param {object} p.suite whitebox | blackbox | realworld | indie
 * @param {object} p.target 语料里这条靶场的声明
 * @param {object} p.result 该基准脚本 evaluate() 的返回值
 * @param {object} [p.report] report.json 解析结果（用于取证据摘录）
 * @param {object} [p.gate] GB_GATE 那一行的解析结果
 * @param {boolean} [p.result.startupFailed] 扫描没开始就失败（工作区/靶场进程），归「起不来」
 */
export function classifyRun({ suite, target, result, report = null, gate = null }) {
  const records = [];
  const base = {
    suite,
    target: target.id,
    exit: { actual: result?.exit?.actual ?? null, expected: result?.exit?.expected ?? null },
    outcome: { actual: result?.outcome?.actual ?? null, expected: result?.outcome?.expected ?? null },
    durationMs: result?.durationMs ?? null,
  };
  const push = (caseKey, category, cause, detail, entry) =>
    records.push({
      ...base,
      caseKey,
      category,
      cause,
      // detail 常常带目标进程的输出尾部（启动日志、stderr），凭据就是从这里漏进账本的，
      // 所以它和响应体走同一道脱敏：账本是要进 git 的渠道。
      detail: detail == null ? null : truncate(String(detail), 400),
      evidence: evidenceExcerpt(entry ?? null),
      corpus: {
        expectedExit: target.expectedExit ?? target.expectedExits ?? null,
        expectedCases: target.expectedVulnerableCases ?? target.expectedVulnerable ?? null,
        forbidden: target.forbiddenVulnerable ?? null,
      },
    });

  const code = report?.error?.code ?? gate?.error?.code ?? null;
  const actualOutcome = result?.outcome?.actual ?? report?.verdict?.outcome ?? null;
  const timedOut = !!result?.exit?.timedOut;
  const spawnError = result?.exit?.error ?? null;

  // 基准脚本在扫描真正开始之前就抛了（工作区没建好 / 靶场进程没起来）：
  // 这一轮根本没打到目标，归「起不来」而不是「跑挂了」，否则账本会把环境问题记成引擎缺陷。
  if (result?.startupFailed) {
    push(
      "-",
      "not_ready",
      result.startupCause ?? "startup_failed",
      `靶场没起来，扫描未开始：${spawnError ?? result.skipReason ?? "未知原因"}`,
      null
    );
    return records;
  }

  if (timedOut || spawnError || (!report && !result?.reportPath)) {
    push(
      "-",
      "broken_run",
      timedOut ? "timeout" : spawnError ? "process_error" : "no_report",
      timedOut ? "本轮超时被杀" : spawnError ? `进程错误：${spawnError}` : "未产出 report.json，本轮没有可核对的测量结果",
      null
    );
    return records;
  }

  if (NOT_READY_CODES.has(code)) {
    push("-", "not_ready", code, `目标没起来或不可达（${code}）`, null);
    return records;
  }

  if (INCONCLUSIVE_CODES.has(code) || INCONCLUSIVE_OUTCOMES.has(actualOutcome)) {
    push("-", "inconclusive", code ?? actualOutcome, `这一轮没能证明任何事（${code ?? actualOutcome}）`, null);
  }

  const dyn = result?.dynamic;
  const cases = result?.cases;
  for (const item of dyn?.missed ?? cases?.missed ?? []) {
    const caseKey = typeof item === "string" ? item : (item?.caseId ?? String(item));
    const entry = pickEvidence(report, caseKey);
    const verdict = entry?.verdict ?? null;
    if (!entry) {
      push(caseKey, "missed", "case_not_generated", "标注要求的用例根本没生成（候选缺失或计划被跳过）", null);
    } else if (verdict === "inconclusive") {
      push(caseKey, "inconclusive", "case_inconclusive", `打了但证据不足以判定：${entry?.actual ?? "—"}`, entry);
    } else if (verdict === "blocked") {
      push(caseKey, "missed", "blocked_by_target", `目标拒了这一发：${entry?.actual ?? "—"}`, entry);
    } else {
      push(caseKey, "missed", "attempted_not_vulnerable", `打了但没打中：${entry?.actual ?? verdict ?? "—"}`, entry);
    }
  }

  for (const item of dyn?.falsePositives ?? cases?.falsePositives ?? []) {
    const caseKey = typeof item === "string" ? item : (item?.caseId ?? String(item));
    const entry = pickEvidence(report, caseKey);
    const why = (cases?.forbiddenHits ?? []).includes(caseKey) ? "forbidden_rule" : "unannotated";
    push(caseKey, "false_positive", why, `报了标注之外或明令禁止的用例：${entry?.actual ?? "—"}`, entry);
  }

  if (result?.exit && result.exit.ok === false && records.length === 0) {
    const vulnerable = actualOutcome === "vulnerable_unfixed" || actualOutcome === "vulnerable";
    const cleanish = ["not_reproducible", "no_candidates", "no_findings"].includes(actualOutcome);
    const inferred = vulnerable ? "false_positive" : cleanish ? "missed" : "broken_run";
    push("-", inferred, "exit_mismatch", `退出码 ${result.exit.actual ?? "—"}，期望 ${result.exit.expected}`, null);
  }

  // 静态漏报只作诊断附注：GuardBuild 以动态复现裁决，静态没认出不算失败
  for (const s of result?.static?.missed ?? []) {
    push(
      `${s.kind}:${s.path ?? (s.routeKeys ?? []).join(",")}`,
      "missed",
      "static_candidate_missing",
      `静态没认出这个候选：${s.kind} ${s.method ?? ""} ${s.path ?? ""}`.trim(),
      null
    );
  }

  return records;
}

/** 本轮哪些键是绿的：通过靶场的靶场级键 + 任何轮次里命中的用例，供「不许回退」比对 */
export function greenKeysOf({ suite, results }) {
  const keys = [];
  for (const r of results ?? []) {
    if (!r) continue;
    if (r.pass) keys.push(`${suite}/${r.id}`);
    for (const rule of r?.dynamic?.matched ?? r?.cases?.matched ?? []) {
      keys.push(`${suite}/${r.id}#${typeof rule === "string" ? rule : (rule?.caseId ?? rule)}`);
    }
  }
  return [...new Set(keys)];
}

export function readLedger(filePath) {
  if (!fs.existsSync(filePath)) return [];
  return fs
    .readFileSync(filePath, "utf8")
    .split("\n")
    .filter((l) => l.trim())
    .map((l) => {
      try {
        return JSON.parse(l);
      } catch {
        return null;
      }
    })
    .filter(Boolean);
}

/**
 * 追加/更新账本。
 * @param {boolean} partial 局部跑（--only）时不许把没覆盖到的条目判成已解决
 * @param {boolean} cleanRun 只有全绿的完整轮次才允许关闭旧条目
 * @param {string} [resolveSuite] 只关闭这个套件的旧条目
 */
export function appendLedger({
  filePath,
  records,
  gitHead = null,
  now = new Date().toISOString(),
  partial = false,
  cleanRun = false,
  resolveSuite = null,
}) {
  const entries = readLedger(filePath);
  const index = new Map(entries.map((e) => [e.fingerprint, e]));
  const seen = new Set();
  let added = 0;
  let updated = 0;

  for (const rec of records) {
    const fp = fingerprint(rec);
    seen.add(fp);
    const prev = index.get(fp);
    const merged = {
      ...rec,
      fingerprint: fp,
      status: "open",
      firstSeen: prev?.firstSeen ?? now,
      firstSeenIn: prev?.firstSeenIn ?? gitHead,
      lastSeen: now,
      lastSeenIn: gitHead,
      occurrences: (prev?.occurrences ?? 0) + 1,
    };
    index.set(fp, merged);
    if (prev) updated += 1;
    else {
      entries.push(merged);
      added += 1;
    }
  }

  let resolved = 0;
  const suiteScope = resolveSuite ?? records[0]?.suite ?? null;
  const out = entries.map((e) => {
    const cur = index.get(e.fingerprint) ?? e;
    const inScope = !partial && cleanRun && (!suiteScope || cur.suite === suiteScope);
    if (inScope && cur.status === "open" && !seen.has(cur.fingerprint)) {
      resolved += 1;
      return { ...cur, status: "resolved", resolvedAt: now, resolvedIn: gitHead };
    }
    return cur;
  });

  if (filePath && (added || updated || resolved)) {
    const dir = filePath.replace(/[\\/][^\\/]*$/, "");
    if (dir && dir !== filePath && !fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(filePath, `${out.map((e) => JSON.stringify(e)).join("\n")}\n`);
  }
  return { added, updated, resolved, entries: out, open: out.filter((e) => e.status === "open").length };
}

export function summarizeLedger(entries) {
  const byCategory = {};
  for (const [key, label] of Object.entries(CATEGORIES)) byCategory[key] = { label, open: 0, resolved: 0, occurrences: 0 };
  for (const e of entries) {
    const slot = byCategory[e.category];
    if (!slot) continue;
    slot[e.status === "open" ? "open" : "resolved"] += 1;
    slot.occurrences += e.occurrences ?? 1;
  }
  return byCategory;
}
